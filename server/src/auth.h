#pragma once

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>

#include <argon2.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include "jwt_utils.h"
#include "metrics.h"
#include "session.h"

// PG connection shared with main.cpp
extern const std::string PG_CONN;

struct UserRow {
    int id{};
    std::string username;
    std::string email;
    std::string password_hash;
    bool is_verified{false};
};

using HandlerResponse = std::pair<std::string, int>;

// -----------------------------------------------------------------------------
// Utility helpers
// -----------------------------------------------------------------------------
static HandlerResponse json_error(int code, const std::string &msg) {
    nlohmann::json j = {{"status", "error"}, {"message", msg}};
    return {j.dump(), code};
}

static HandlerResponse json_ok(const nlohmann::json &payload, int code = 200) {
    nlohmann::json j = payload;
    if (!j.contains("status")) {
        j["status"] = "ok";
    }
    return {j.dump(), code};
}

static std::string_view trim_view(std::string_view input) {
    while (!input.empty() && std::isspace(static_cast<unsigned char>(input.front()))) {
        input.remove_prefix(1);
    }
    while (!input.empty() && std::isspace(static_cast<unsigned char>(input.back()))) {
        input.remove_suffix(1);
    }
    return input;
}

static std::optional<std::string> extract_cookie_value(const std::string &cookie_header,
                                                       const std::string &name) {
    if (cookie_header.empty()) {
        return std::nullopt;
    }

    const std::string needle = name + "=";
    std::string_view view{cookie_header};
    size_t pos = 0;
    while (pos < view.size()) {
        size_t next = view.find(';', pos);
        std::string_view token = next == std::string::npos ? view.substr(pos)
                                                           : view.substr(pos, next - pos);
        token = trim_view(token);
        if (token.compare(0, needle.size(), needle) == 0) {
            std::string value(token.substr(needle.size()));
            return value;
        }
        if (next == std::string::npos) {
            break;
        }
        pos = next + 1;
    }
    return std::nullopt;
}

struct RefreshTokenLookup {
    std::optional<std::string> token;
    bool json_provided{false};
    bool cookie_provided{false};
    bool json_parse_failed{false};
    std::string json_error_msg;
};

static RefreshTokenLookup resolve_refresh_token(const std::string &body_json,
                                                const std::string &cookie_header) {
    RefreshTokenLookup out;

    if (!body_json.empty()) {
        try {
            auto j = nlohmann::json::parse(body_json);
            if (j.contains("refresh_token")) {
                out.json_provided = true;
                if (j["refresh_token"].is_string()) {
                    out.token = j["refresh_token"].get<std::string>();
                }
            }
        } catch (const std::exception &e) {
            out.json_parse_failed = true;
            out.json_error_msg = e.what();
        }
    }

    auto cookie_value = extract_cookie_value(cookie_header, "BCORD_REFRESH");
    if (cookie_value) {
        out.cookie_provided = true;
        if (!out.token || out.token->empty()) {
            out.token = *cookie_value;
        }
    }

    return out;
}

// -----------------------------------------------------------------------------
// DB helpers
// -----------------------------------------------------------------------------
static std::optional<UserRow> db_get_user_by_username(pqxx::work &txn,
                                                      const std::string &username) {
    auto r = txn.exec_params(
        "SELECT id, username, email, password_hash, verified FROM users WHERE username=$1",
        username);
    if (r.empty()) return std::nullopt;
    UserRow u;
    u.id = r[0]["id"].as<int>();
    u.username = r[0]["username"].c_str();
    u.email = r[0]["email"].c_str();
    u.password_hash = r[0]["password_hash"].c_str();
    u.is_verified = r[0]["verified"].as<bool>();
    return u;
}

static std::optional<UserRow> db_get_user_by_email(pqxx::work &txn,
                                                   const std::string &email) {
    auto r = txn.exec_params(
        "SELECT id, username, email, password_hash, verified FROM users WHERE email=$1",
        email);
    if (r.empty()) return std::nullopt;
    UserRow u;
    u.id = r[0]["id"].as<int>();
    u.username = r[0]["username"].c_str();
    u.email = r[0]["email"].c_str();
    u.password_hash = r[0]["password_hash"].c_str();
    u.is_verified = r[0]["verified"].as<bool>();
    return u;
}

static int db_create_user(pqxx::work &txn, const std::string &username,
                          const std::string &email, const std::string &password_hash) {
    auto r = txn.exec_params(
        "INSERT INTO users (username,email,password_hash,verified) "
        "VALUES ($1,$2,$3,false) RETURNING id",
        username, email, password_hash);
    return r[0]["id"].as<int>();
}

// -----------------------------------------------------------------------------
// Argon2id helpers
// -----------------------------------------------------------------------------
static std::string argon2id_hash(const std::string &password) {
    const uint32_t t_cost = 3;
    const uint32_t m_cost = 1 << 15;
    const uint32_t parallelism = 1;
    const size_t salt_len = 16;
    const size_t hash_len = 32;

    std::array<uint8_t, salt_len> salt{};
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> d(0, 255);
    for (auto &b : salt) b = static_cast<uint8_t>(d(gen));

    char encoded[256]{0};
    int rc = argon2id_hash_encoded(t_cost, m_cost, parallelism, password.data(),
                                   password.size(), salt.data(), salt_len, hash_len,
                                   encoded, sizeof(encoded));
    if (rc != ARGON2_OK) {
        throw std::runtime_error(std::string("argon2id_hash_encoded failed: ") +
                                 argon2_error_message(rc));
    }
    return std::string(encoded);
}

static bool argon2id_verify_ok(const std::string &encoded, const std::string &password) {
    int rc = argon2id_verify(encoded.c_str(), password.data(), password.size());
    return rc == ARGON2_OK;
}

// -----------------------------------------------------------------------------
// Registration
// -----------------------------------------------------------------------------
static HandlerResponse handle_register(const std::string &body_json) {
    try {
        auto j = nlohmann::json::parse(body_json);
        std::string username = j.value("username", "");
        std::string email = j.value("email", "");
        std::string password = j.value("password", "");
        std::string captcha = j.value("captcha_text", "");
        (void)captcha; // currently validated upstream

        if (username.size() < 3 || password.size() < 6 || email.find('@') == std::string::npos) {
            Metrics::instance().auth_register_failure_total++;
            return json_error(400, "invalid input");
        }

        std::string phash = argon2id_hash(password);

        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);

        if (db_get_user_by_username(txn, username)) {
            Metrics::instance().auth_register_failure_total++;
            return json_error(409, "username already exists");
        }
        if (db_get_user_by_email(txn, email)) {
            Metrics::instance().auth_register_failure_total++;
            return json_error(409, "email already exists");
        }

        (void)db_create_user(txn, username, email, phash);
        txn.commit();

        Metrics::instance().auth_register_success_total++;
        return json_ok({{"message", "account created (verify email next)"}}, 201);
    } catch (const nlohmann::json::exception &e) {
        Metrics::instance().auth_register_failure_total++;
        return json_error(400, std::string("invalid JSON payload: ") + e.what());
    } catch (const std::exception &e) {
        Metrics::instance().auth_register_failure_total++;
        return json_error(500, std::string("register failed: ") + e.what());
    }
}

// -----------------------------------------------------------------------------
// Login
// -----------------------------------------------------------------------------
static HandlerResponse handle_login(const std::string &body_json) {
    try {
        auto j = nlohmann::json::parse(body_json);
        std::string user = j.value("username", "");
        std::string pass = j.value("password", "");

        if (user.empty() || pass.empty()) {
            Metrics::instance().auth_login_failure_total++;
            return json_error(400, "missing username or password");
        }

        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);
        auto row = txn.exec_params("SELECT id, password_hash, verified FROM users WHERE username=$1", user);
        if (row.empty()) {
            Metrics::instance().auth_login_failure_total++;
            return json_error(401, "invalid username or password");
        }

        std::string hash = row[0]["password_hash"].c_str();
        bool verified = row[0]["verified"].as<bool>();

        if (!argon2id_verify_ok(hash, pass)) {
            Metrics::instance().auth_login_failure_total++;
            return json_error(401, "invalid username or password");
        }

        std::string token = generate_jwt(user);
        std::string refresh = generate_refresh_token();

        auto refresh_exp = std::chrono::system_clock::now() + std::chrono::hours(8);
        std::time_t refresh_exp_t = std::chrono::system_clock::to_time_t(refresh_exp);

        store_refresh_token(txn, row[0]["id"].as<int>(), refresh, refresh_exp_t);
        txn.commit();

        Metrics::instance().auth_login_success_total++;

        nlohmann::json resp = {
            {"message", "login ok"},
            {"token", token},
            {"refresh_token", refresh},
            {"user", user},
            {"verified", verified}
        };

        return json_ok(resp);
    } catch (const nlohmann::json::exception &e) {
        Metrics::instance().auth_login_failure_total++;
        return json_error(400, std::string("invalid JSON payload: ") + e.what());
    } catch (const std::exception &e) {
        Metrics::instance().auth_login_failure_total++;
        return json_error(500, std::string("login failed: ") + e.what());
    }
}

// -----------------------------------------------------------------------------
// Refresh token exchange
// -----------------------------------------------------------------------------
static HandlerResponse handle_refresh(const std::string &body_json,
                                      const std::string &cookie_header) {
    auto lookup = resolve_refresh_token(body_json, cookie_header);

    if (lookup.json_parse_failed && (!lookup.token || lookup.token->empty())) {
        Metrics::instance().auth_refresh_failure_total++;
        return json_error(400, std::string("invalid JSON payload: ") + lookup.json_error_msg);
    }

    if (!lookup.token || lookup.token->empty()) {
        Metrics::instance().auth_refresh_failure_total++;
        if (lookup.json_provided || lookup.cookie_provided) {
            return json_error(400, "refresh token missing");
        }
        return json_error(400, "refresh token not provided");
    }

    try {
        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);
        int user_id = 0;
        if (!validate_refresh_token(txn, *lookup.token, user_id)) {
            Metrics::instance().auth_refresh_failure_total++;
            return json_error(401, "invalid or expired refresh token");
        }

        auto r = txn.exec_params("SELECT username FROM users WHERE id=$1", user_id);
        if (r.empty()) {
            Metrics::instance().auth_refresh_failure_total++;
            return json_error(404, "user not found");
        }

        std::string username = r[0]["username"].c_str();
        std::string token = generate_jwt(username);
        txn.commit();

        Metrics::instance().auth_refresh_success_total++;
        return json_ok({{"access_token", token}});
    } catch (const std::exception &e) {
        Metrics::instance().auth_refresh_failure_total++;
        return json_error(500, std::string("refresh failed: ") + e.what());
    }
}

// -----------------------------------------------------------------------------
// Logout handler (refresh token revocation)
// -----------------------------------------------------------------------------
static HandlerResponse handle_logout(const std::string &body_json,
                                     const std::string &cookie_header) {
    auto lookup = resolve_refresh_token(body_json, cookie_header);

    if (lookup.json_parse_failed && (!lookup.token || lookup.token->empty())) {
        return json_error(400, std::string("invalid JSON payload: ") + lookup.json_error_msg);
    }

    if (!lookup.token || lookup.token->empty()) {
        Metrics::instance().auth_logout_total++;
        return json_ok({{"message", "no refresh token supplied"}});
    }

    try {
        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);
        revoke_refresh_token(txn, *lookup.token);
        txn.commit();

        Metrics::instance().auth_logout_total++;
        return json_ok({{"message", "logged out"}});
    } catch (const std::exception &e) {
        return json_error(500, std::string("logout failed: ") + e.what());
    }
}

