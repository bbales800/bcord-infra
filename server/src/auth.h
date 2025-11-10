#pragma once
#include <string>
#include <optional>
#include <pqxx/pqxx>
#include <nlohmann/json.hpp>
#include <argon2.h>
#include "session.h"
#include "metrics.h"
#include <random>
#include <sstream>
#include "jwt_utils.h"

// PG connection shared with main.cpp
extern const std::string PG_CONN;

struct UserRow {
    int id{};
    std::string username;
    std::string email;
    std::string password_hash;
    bool is_verified{false};
};

// --- DB helpers
std::optional<UserRow> db_get_user_by_username(pqxx::work& txn, const std::string& username) {
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

std::optional<UserRow> db_get_user_by_email(pqxx::work& txn, const std::string& email) {
    auto r = txn.exec_params("SELECT id, username, email, password_hash, verified FROM users WHERE email=$1", email);
    if (r.empty()) return std::nullopt;
    UserRow u;
    u.id = r[0]["id"].as<int>();
    u.username = r[0]["username"].c_str();
    u.email = r[0]["email"].c_str();
    u.password_hash = r[0]["password_hash"].c_str();
    u.is_verified = r[0]["verified"].as<bool>();
    return u;
}

int db_create_user(pqxx::work& txn, const std::string& username, const std::string& email, const std::string& password_hash) {
    auto r = txn.exec_params(
        "INSERT INTO users (username,email,password_hash,verified) "
        "VALUES ($1,$2,$3,false) RETURNING id",
        username, email, password_hash
    );
    return r[0]["id"].as<int>();
}

// --- Argon2id helpers
std::string argon2id_hash(const std::string& password) {
    const uint32_t t_cost = 3;
    const uint32_t m_cost = 1 << 15;
    const uint32_t parallelism = 1;
    const size_t salt_len = 16;
    const size_t hash_len = 32;

    std::array<uint8_t, salt_len> salt{};
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> d(0, 255);
    for (auto& b : salt) b = static_cast<uint8_t>(d(gen));

    char encoded[256]{0};
    int rc = argon2id_hash_encoded(
        t_cost, m_cost, parallelism,
        password.data(), password.size(),
        salt.data(), salt_len,
        hash_len, encoded, sizeof(encoded)
    );
    if (rc != ARGON2_OK) {
        throw std::runtime_error(std::string("argon2id_hash_encoded failed: ") + argon2_error_message(rc));
    }
    return std::string(encoded);
}

bool argon2id_verify_ok(const std::string& encoded, const std::string& password) {
    int rc = argon2id_verify(encoded.c_str(), password.data(), password.size());
    return rc == ARGON2_OK;
}

// --- Helper JSON responses
static std::pair<std::string,int> json_error(int code, const std::string& msg) {
    nlohmann::json j = {{"status","error"},{"message",msg}};
    return { j.dump(), code };
}
static std::pair<std::string,int> json_ok(const nlohmann::json &payload) {
    nlohmann::json j = payload;
    if (!j.contains("status")) j["status"]="ok";
    return { j.dump(), 200 };
}

// --- Registration
std::pair<std::string,int> handle_register(const std::string& body_json) {
    try {
        auto j = nlohmann::json::parse(body_json);
        std::string username = j.value("username", "");
        std::string email    = j.value("email", "");
        std::string password = j.value("password", "");
        std::string captcha  = j.value("captcha_text", "");

        if (username.size() < 3 || password.size() < 6 || email.find('@') == std::string::npos) {
            Metrics::instance().auth_register_failure_total++;
            return json_error(400, "invalid input");
        }

        // Hash password
        std::string phash = argon2id_hash(password);

        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);
        if (db_get_user_by_username(txn, username).has_value()) {
            Metrics::instance().auth_register_failure_total++;
            return json_error(409, "username already exists");
        }
        if (db_get_user_by_email(txn, email).has_value()) {
            Metrics::instance().auth_register_failure_total++;
            return json_error(409, "email already exists");
        }

        (void)db_create_user(txn, username, email, phash);
        txn.commit();

        // ✅ Increment success metric
        Metrics::instance().auth_register_success_total++;

        return json_ok({{"message","account created (verify email next)"}});
    } catch (const std::exception& e) {
        // ✅ Increment failure metric
        Metrics::instance().auth_register_failure_total++;
        return json_error(400, std::string("register failed: ") + e.what());
    }
}

// --- Login
std::pair<std::string,int> handle_login(const std::string& body_json) {
    try {
        auto j = nlohmann::json::parse(body_json);
        std::string user = j.value("username", "");
        std::string pass = j.value("password", "");

        if (user.empty() || pass.empty())
            throw std::runtime_error("missing username or password");

        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);
        auto r = txn.exec_params("SELECT id, password_hash, verified FROM users WHERE username=$1", user);
        if (r.empty())
            throw std::runtime_error("user not found");

        std::string hash = r[0]["password_hash"].c_str();
        bool verified = r[0]["verified"].as<bool>();

        if (!argon2id_verify_ok(hash, pass))
            throw std::runtime_error("invalid password");

        // ✅ Generate JWT + refresh token
        std::string token = generate_jwt(user);
        std::string refresh = generate_refresh_token();

        // 8-hour refresh expiry
        auto refresh_exp = std::chrono::system_clock::now() + std::chrono::hours(8);
        std::time_t refresh_exp_t = std::chrono::system_clock::to_time_t(refresh_exp);

        store_refresh_token(txn, r[0]["id"].as<int>(), refresh, refresh_exp_t);
        txn.commit();

        // ✅ Increment success metric
        Metrics::instance().auth_login_success_total++;

        nlohmann::json resp = {
            {"status", "ok"},
            {"message", "login ok"},
            {"token", token},
            {"refresh_token", refresh},
            {"user", user},
            {"verified", verified}
        };

        return {resp.dump(), 1};

    } catch (const std::exception &e) {
        // ✅ Increment failure metric
        Metrics::instance().auth_login_failure_total++;
        
        nlohmann::json err = {
            {"status", "error"},
            {"message", e.what()}
        };
        return {err.dump(), 0};
    }
}

// ---------------------------------------------------------------------------
// handle_refresh — exchange refresh token for new JWT
// ---------------------------------------------------------------------------
std::pair<std::string,int> handle_refresh(const std::string &body_json) {
    try {
        auto j = nlohmann::json::parse(body_json);
        std::string refresh = j.value("refresh_token", "");
        if (refresh.empty()) throw std::runtime_error("missing refresh_token");

        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);
        int user_id = 0;
        if (!validate_refresh_token(txn, refresh, user_id))
            throw std::runtime_error("invalid or expired refresh token");

        auto r = txn.exec_params("SELECT username FROM users WHERE id=$1", user_id);
        if (r.empty()) throw std::runtime_error("user not found");

        std::string username = r[0]["username"].c_str();
        std::string token = generate_jwt(username);

        // ✅ Increment success metric
        Metrics::instance().auth_refresh_success_total++;

        nlohmann::json resp = {
            {"status","ok"},
            {"access_token", token}
        };
        return {resp.dump(), 1};
    } catch (const std::exception &e) {
        // ✅ Increment failure metric
        Metrics::instance().auth_refresh_failure_total++;
        
        nlohmann::json err = {{"status","error"},{"message",e.what()}};
        return {err.dump(), 0};
    }
}

// ---------------------------------------------------------------------------
// handle_logout — revoke refresh token
// ---------------------------------------------------------------------------
std::pair<std::string,int> handle_logout(const std::string &body_json) {
    try {
        auto j = nlohmann::json::parse(body_json);
        std::string refresh = j.value("refresh_token", "");
        if (refresh.empty()) throw std::runtime_error("missing refresh_token");

        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);
        revoke_refresh_token(txn, refresh);
        txn.commit();

        // ✅ Increment logout metric
        Metrics::instance().auth_logout_total++;

        nlohmann::json resp = {{"status","ok"},{"message","logged out"}};
        return {resp.dump(), 1};
    } catch (const std::exception &e) {
        nlohmann::json err = {{"status","error"},{"message",e.what()}};
        return {err.dump(), 0};
    }
}
