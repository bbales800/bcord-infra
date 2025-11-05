#pragma once
#include <string>
#include <chrono>
#include <nlohmann/json.hpp>
#include <openssl/hmac.h>
#include <openssl/sha.h>

// ---------------------------------------------------------------------------
// Secret key (change for production)
// ---------------------------------------------------------------------------
const std::string JWT_SECRET = "super_secret_key_change_me";
// ---------------------------------------------------------------------------
// Base64 URL-safe encoder (JWT-safe, no padding)
// ---------------------------------------------------------------------------
static std::string base64_url_encode(const unsigned char* data, size_t len) {
    static const char* chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    int val = 0, valb = -6;
    for (size_t i = 0; i < len; ++i) {
        val = (val << 8) + data[i];
        valb += 8;
        while (valb >= 0) {
            out.push_back(chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    return out;
}
// ---------------------------------------------------------------------------
// Generate a signed JWT using HS256
// ---------------------------------------------------------------------------
static std::string generate_jwt(const std::string& username) {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto exp = now + hours(1);

    nlohmann::json header = {{"alg", "HS256"}, {"typ", "JWT"}};
    nlohmann::json payload = {
        {"sub", username},
        {"iat", duration_cast<seconds>(now.time_since_epoch()).count()},
        {"exp", duration_cast<seconds>(exp.time_since_epoch()).count()}
    };

    std::string header_str = header.dump();
    std::string payload_str = payload.dump();

    std::string header_enc = base64_url_encode(
        reinterpret_cast<const unsigned char*>(header_str.data()), header_str.size());
    std::string payload_enc = base64_url_encode(
        reinterpret_cast<const unsigned char*>(payload_str.data()), payload_str.size());

    std::string message = header_enc + "." + payload_enc;

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), JWT_SECRET.data(), JWT_SECRET.size(),
         reinterpret_cast<const unsigned char*>(message.data()), message.size(),
         hash, &len);

    std::string signature = base64_url_encode(hash, len);
    return message + "." + signature;
}
// ---------------------------------------------------------------------------
// Verify JWT (signature + expiration)
// ---------------------------------------------------------------------------
static bool verify_jwt(const std::string& token) {
    size_t p1 = token.find('.');
    size_t p2 = token.find('.', p1 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos) return false;

    std::string message = token.substr(0, p2);
    std::string sig = token.substr(p2 + 1);

    // recompute HMAC signature
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), JWT_SECRET.data(), JWT_SECRET.size(),
         reinterpret_cast<const unsigned char*>(message.data()), message.size(),
         hash, &len);

    std::string expected = base64_url_encode(hash, len);
    if (expected != sig) return false;

    // check exp claim (decode payload)
    std::string payload_enc = token.substr(p1 + 1, p2 - p1 - 1);
    std::string payload_json; // naive base64 decode (payload is JSON)
    for (char c : payload_enc)
        if (isalnum(c) || c == '{' || c == '}' || c == '"' || c == ':' || c == ',')
            payload_json.push_back(c);

    try {
        auto payload = nlohmann::json::parse(payload_json, nullptr, false);
        if (!payload.is_object()) return false;
        long exp = payload.value("exp", 0L);
        long now = std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
        return now <= exp;
    } catch (...) {
        return false;
    }
}

