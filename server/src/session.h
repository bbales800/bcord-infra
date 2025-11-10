#pragma once
#include <string>
#include <ctime>
#include <pqxx/pqxx>
#include <nlohmann/json.hpp>
#include <random>
#include "jwt_utils.h"

// --- Session table helpers ---
inline std::string generate_refresh_token() {
    static const char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);
    std::string token(64, ' ');
    for (auto &c : token) c = charset[dist(rng)];
    return token;
}

inline void store_refresh_token(pqxx::work &txn, int user_id,
                                const std::string &token, time_t expires_at) {
    txn.exec_params(
        R"(INSERT INTO sessions (user_id, refresh_token, expires_at)
           VALUES ($1, $2, to_timestamp($3))
           ON CONFLICT (refresh_token) DO NOTHING)",
        user_id, token, expires_at);
}

inline bool validate_refresh_token(pqxx::work &txn,
                                   const std::string &token, int &user_id_out) {
    auto r = txn.exec_params(
        "SELECT user_id, expires_at FROM sessions WHERE refresh_token=$1", token);
    if (r.empty()) return false;
    std::string exp_str = r[0]["expires_at"].c_str();
    std::tm tm{};
    std::istringstream ss(exp_str);
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    time_t exp_t = std::mktime(&tm);
    if (std::time(nullptr) > exp_t) return false;
    user_id_out = r[0]["user_id"].as<int>();
    return true;
}

inline void revoke_refresh_token(pqxx::work &txn, const std::string &token) {
    txn.exec_params("DELETE FROM sessions WHERE refresh_token=$1", token);
}
