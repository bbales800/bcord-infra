// ============================================================================
// auth/cookie_auth.hpp — Cookie-based authentication handlers
// ============================================================================
#pragma once
#include <string>
#include <optional>
#include <boost/beast/http.hpp>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx.h>
#include <argon2.h>
#include "jwt_utils_cookie.hpp"

namespace http = boost::beast::http;

// External DB connection string
extern const std::string PG_CONN;

// ---------------------------------------------------------------------------
// User structure
// ---------------------------------------------------------------------------
struct UserRow {
    int id{};
    std::string username;
    std::string email;
    std::string password_hash;
    bool is_verified{false};
};

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------
inline std::optional<UserRow> db_get_user_by_username(pqxx::work& txn, const std::string& username) {
    auto r = txn.exec_params("SELECT id, username, email, password_hash, verified FROM users WHERE username=$1", username);
    if (r.empty()) return std::nullopt;
    UserRow u;
    u.id = r[0]["id"].as<int>();
    u.username = r[0]["username"].c_str();
    u.email = r[0]["email"].c_str();
    u.password_hash = r[0]["password_hash"].c_str();
    u.is_verified = r[0]["verified"].as<bool>();
    return u;
}

// ---------------------------------------------------------------------------
// Argon2id password verification
// ---------------------------------------------------------------------------
inline bool argon2id_verify_ok(const std::string& encoded, const std::string& password) {
    int rc = argon2id_verify(encoded.c_str(), password.data(), password.size());
    return rc == ARGON2_OK;
}

// ---------------------------------------------------------------------------
// Cookie-based auth middleware
// ---------------------------------------------------------------------------
inline bool attach_user_from_cookies(
    const http::request<http::string_body>& req,
    http::response<http::string_body>& res,
    std::string& out_user_id
) {
    using http::field;

    const auto cookies_hdr = req[field::cookie];
    if (cookies_hdr.empty()) {
        res.result(http::status::unauthorized);
        res.body() = R"({"error":"unauthenticated"})";
        res.prepare_payload();
        return false;
    }

    auto cookies = parse_cookie_header(std::string{cookies_hdr});
    
    // Try access token first
    auto accIt = cookies.find("bc_access");
    if (accIt != cookies.end()) {
        try {
            auto dec = verify_access_jwt(accIt->second);
            if (dec.valid) {
                out_user_id = dec.subject;
                return true;
            }
        } catch (...) {
            // Access expired or invalid — fall through to try refresh
        }
    }

    // Try refresh token
    auto rtIt = cookies.find("bc_refresh");
    if (rtIt != cookies.end()) {
        try {
            auto dec = verify_refresh_jwt(rtIt->second);
            if (!dec.valid) {
                res.result(http::status::unauthorized);
                res.body() = R"({"error":"session expired"})";
                res.prepare_payload();
                return false;
            }

            auto sub = dec.subject;
            auto jti = dec.jti;
            
            if (!validate_refresh_jti(jti, sub)) {
                // Revoked/invalid
                res.result(http::status::unauthorized);
                res.body() = R"({"error":"session expired"})";
                res.set(field::set_cookie, "bc_access=; Max-Age=0; Path=/; Secure; SameSite=Lax");
                res.insert(field::set_cookie, "bc_refresh=; Max-Age=0; Path=/; Secure; SameSite=Lax");
                res.prepare_payload();
                return false;
            }

            // Rotate refresh token
            revoke_refresh_jti(jti);
            auto newJti = random_hex();
            auto newRef = sign_refresh_jwt(sub, newJti);
            store_refresh_jti(newJti, sub);
            auto newAcc = sign_access_jwt(sub);

            auto access_ttl = std::chrono::seconds{ std::stoi(env_or("BCORD_JWT_ACCESS_TTL","900")) };
            auto refresh_ttl = std::chrono::seconds{ std::stoi(env_or("BCORD_JWT_REFRESH_TTL","2592000")) };

            res.set(field::set_cookie, cookie_kv("bc_access", newAcc, access_ttl));
            res.insert(field::set_cookie, cookie_kv("bc_refresh", newRef, refresh_ttl));
            
            out_user_id = sub;
            return true;
        } catch (...) {
            res.result(http::status::unauthorized);
            res.body() = R"({"error":"invalid refresh"})";
            res.prepare_payload();
            return false;
        }
    }

    res.result(http::status::unauthorized);
    res.body() = R"({"error":"unauthenticated"})";
    res.prepare_payload();
    return false;
}

// ---------------------------------------------------------------------------
// Login handler with cookies
// ---------------------------------------------------------------------------
inline void handle_login_cookie(
    const http::request<http::string_body>& req,
    http::response<http::string_body>& res
) {
    try {
        auto j = nlohmann::json::parse(req.body());
        std::string username = j.value("username", "");
        std::string password = j.value("password", "");

        if (username.empty() || password.empty()) {
            res.result(http::status::unauthorized);
            res.body() = R"({"error":"missing username or password"})";
            res.prepare_payload();
            return;
        }

        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);
        
        auto user_opt = db_get_user_by_username(txn, username);
        if (!user_opt) {
            res.result(http::status::unauthorized);
            res.body() = R"({"error":"invalid credentials"})";
            res.prepare_payload();
            return;
        }

        auto& user = *user_opt;
        if (!argon2id_verify_ok(user.password_hash, password)) {
            res.result(http::status::unauthorized);
            res.body() = R"({"error":"invalid credentials"})";
            res.prepare_payload();
            return;
        }

        // Issue cookies
        std::string uid = std::to_string(user.id);
        std::string access = sign_access_jwt(uid);
        std::string jti = random_hex();
        std::string refresh = sign_refresh_jwt(uid, jti);
        store_refresh_jti(jti, uid);

        auto access_ttl = std::chrono::seconds{ std::stoi(env_or("BCORD_JWT_ACCESS_TTL","900")) };
        auto refresh_ttl = std::chrono::seconds{ std::stoi(env_or("BCORD_JWT_REFRESH_TTL","2592000")) };

        res.result(http::status::ok);
        res.set(http::field::server, "bcord-backend");
        res.set(http::field::content_type, "application/json");
        res.set(http::field::cache_control, "no-store");
        res.set(http::field::set_cookie, cookie_kv("bc_access", access, access_ttl));
        res.insert(http::field::set_cookie, cookie_kv("bc_refresh", refresh, refresh_ttl));

        // Optional CSRF double-submit cookie
        std::string csrf = random_hex(32);
        res.insert(http::field::set_cookie, "bc_csrf=" + csrf + "; Max-Age=2592000; Path=/; Secure; SameSite=Lax");

        nlohmann::json resp = {
            {"ok", true},
            {"user", {
                {"id", user.id},
                {"username", user.username},
                {"verified", user.is_verified}
            }}
        };
        res.body() = resp.dump();
        res.prepare_payload();

    } catch (const std::exception& e) {
        res.result(http::status::internal_server_error);
        res.body() = std::string(R"({"error":"login failed: )") + e.what() + "\"}";
        res.prepare_payload();
    }
}

// ---------------------------------------------------------------------------
// Refresh handler
// ---------------------------------------------------------------------------
inline void handle_refresh_cookie(
    const http::request<http::string_body>& req,
    http::response<http::string_body>& res
) {
    const auto cookie = req[http::field::cookie];
    if (cookie.empty()) {
        res.result(http::status::unauthorized);
        res.body() = R"({"error":"missing cookies"})";
        res.prepare_payload();
        return;
    }

    auto cookies = parse_cookie_header(std::string{cookie});
    auto it = cookies.find("bc_refresh");
    if (it == cookies.end()) {
        res.result(http::status::unauthorized);
        res.body() = R"({"error":"no refresh token"})";
        res.prepare_payload();
        return;
    }

    try {
        auto decoded = verify_refresh_jwt(it->second);
        if (!decoded.valid) {
            res.result(http::status::unauthorized);
            res.body() = R"({"error":"invalid refresh"})";
            res.prepare_payload();
            return;
        }

        auto sub = decoded.subject;
        auto jti = decoded.jti;

        if (!validate_refresh_jti(jti, sub)) {
            res.result(http::status::unauthorized);
            res.body() = R"({"error":"refresh revoked or invalid"})";
            res.prepare_payload();
            return;
        }

        // Rotate refresh
        revoke_refresh_jti(jti);
        auto newJti = random_hex();
        auto newRef = sign_refresh_jwt(sub, newJti);
        store_refresh_jti(newJti, sub);
        auto newAccess = sign_access_jwt(sub);

        auto access_ttl = std::chrono::seconds{ std::stoi(env_or("BCORD_JWT_ACCESS_TTL","900")) };
        auto refresh_ttl = std::chrono::seconds{ std::stoi(env_or("BCORD_JWT_REFRESH_TTL","2592000")) };

        res.result(http::status::no_content);
        res.set(http::field::set_cookie, cookie_kv("bc_access", newAccess, access_ttl));
        res.insert(http::field::set_cookie, cookie_kv("bc_refresh", newRef, refresh_ttl));
        res.prepare();

    } catch (const std::exception& e) {
        res.result(http::status::unauthorized);
        res.body() = R"({"error":"invalid refresh"})";
        res.prepare_payload();
    }
}

// ---------------------------------------------------------------------------
// Logout handler
// ---------------------------------------------------------------------------
inline void handle_logout_cookie(
    const http::request<http::string_body>& req,
    http::response<http::string_body>& res
) {
    const auto cookie = req[http::field::cookie];
    if (!cookie.empty()) {
        auto cookies = parse_cookie_header(std::string{cookie});
        if (auto it = cookies.find("bc_refresh"); it != cookies.end()) {
            try {
                auto dec = verify_refresh_jwt(it->second);
                if (dec.valid && !dec.jti.empty()) {
                    revoke_refresh_jti(dec.jti);
                }
            } catch (...) {}
        }
    }

    // Expire cookies
    res.result(http::status::no_content);
    res.set(http::field::set_cookie, "bc_access=; Max-Age=0; Path=/; Secure; SameSite=Lax");
    res.insert(http::field::set_cookie, "bc_refresh=; Max-Age=0; Path=/; Secure; SameSite=Lax");
    res.insert(http::field::set_cookie, "bc_csrf=; Max-Age=0; Path=/; Secure; SameSite=Lax");
    res.prepare();
}
