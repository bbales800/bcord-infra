// ============================================================================
// auth/jwt_utils_cookie.hpp — Cookie-based JWT with Redis refresh tokens
// ============================================================================
#pragma once
#include <string>
#include <chrono>
#include <unordered_map>
#include <sstream>
#include <random>
#include <cstdlib>
#include <algorithm>
#include <cctype>
#include <nlohmann/json.hpp>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sw/redis++/redis++.h>
#include "jwt_decode.hpp"

// ---------------------------------------------------------------------------
// Environment helpers
// ---------------------------------------------------------------------------
inline std::string env_or(const char* key, const std::string& def = {}) {
    const char* v = std::getenv(key);
    return v ? std::string{v} : def;
}

inline std::string trim(std::string s) {
    auto is_space = [](unsigned char c){ return std::isspace(c); };
    s.erase(s.begin(), std::find_if_not(s.begin(), s.end(), is_space));
    s.erase(std::find_if_not(s.rbegin(), s.rend(), is_space).base(), s.end());
    return s;
}

// ---------------------------------------------------------------------------
// Cookie parser
// ---------------------------------------------------------------------------
inline std::unordered_map<std::string,std::string> parse_cookie_header(const std::string& cookie_header) {
    std::unordered_map<std::string,std::string> m;
    std::ostringstream ss;
    for (size_t i=0; i<cookie_header.size(); ++i) {
        if (cookie_header[i] == ';') {
            std::string kv = trim(ss.str());
            auto p = kv.find('=');
            if (p != std::string::npos) m[trim(kv.substr(0,p))] = kv.substr(p+1);
            ss.str(std::string{}); ss.clear();
        } else {
            ss << cookie_header[i];
        }
    }
    if (!ss.str().empty()) {
        auto kv = trim(ss.str());
        auto p = kv.find('=');
        if (p != std::string::npos) m[trim(kv.substr(0,p))] = kv.substr(p+1);
    }
    return m;
}

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
// Random hex generator
// ---------------------------------------------------------------------------
inline std::string random_hex(size_t n=32) {
    static const char* HEX="0123456789abcdef";
    std::random_device rd; 
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    std::string s; 
    s.reserve(n);
    while (s.size() < n) {
        auto v = dist(gen);
        for (int i=0; i<16 && s.size()<n; i++) {
            s.push_back(HEX[(v >> (i*4)) & 0xF]);
        }
    }
    return s;
}

// ---------------------------------------------------------------------------
// JWT signing (HS256)
// ---------------------------------------------------------------------------
inline std::string sign_access_jwt(const std::string& user_id) {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto exp = now + seconds{ std::stoi( env_or("BCORD_JWT_ACCESS_TTL","900") ) };
    
    auto secret = env_or("BCORD_JWT_ACCESS_SECRET", "super_secret_key_change_me");

    nlohmann::json header = {{"alg", "HS256"}, {"typ", "JWT"}};
    nlohmann::json payload = {
        {"iss", "bcord"},
        {"aud", "bcord"},
        {"sub", user_id},
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
    HMAC(EVP_sha256(), secret.data(), secret.size(),
         reinterpret_cast<const unsigned char*>(message.data()), message.size(),
         hash, &len);

    std::string signature = base64_url_encode(hash, len);
    return message + "." + signature;
}

inline std::string sign_refresh_jwt(const std::string& user_id, const std::string& jti) {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto exp = now + seconds{ std::stoi( env_or("BCORD_JWT_REFRESH_TTL","2592000") ) };
    
    auto secret = env_or("BCORD_JWT_REFRESH_SECRET", "another_secret_key_change_me");

    nlohmann::json header = {{"alg", "HS256"}, {"typ", "JWT"}};
    nlohmann::json payload = {
        {"iss", "bcord"},
        {"aud", "bcord"},
        {"sub", user_id},
        {"jti", jti},
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
    HMAC(EVP_sha256(), secret.data(), secret.size(),
         reinterpret_cast<const unsigned char*>(message.data()), message.size(),
         hash, &len);

    std::string signature = base64_url_encode(hash, len);
    return message + "." + signature;
}

// ---------------------------------------------------------------------------
// JWT verification with proper decoding
// ---------------------------------------------------------------------------
struct DecodedJWT {
    std::string subject;
    std::string jti;
    long exp{0};
    bool valid{false};
};

inline DecodedJWT verify_jwt_internal(const std::string& token, const std::string& secret) {
    DecodedJWT result;
    try {
        size_t p1 = token.find('.');
        size_t p2 = token.find('.', p1 + 1);
        if (p1 == std::string::npos || p2 == std::string::npos) return result;

        std::string message = token.substr(0, p2);
        std::string sig = token.substr(p2 + 1);

        // Verify signature
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        HMAC(EVP_sha256(), secret.data(), secret.size(),
             reinterpret_cast<const unsigned char*>(message.data()), message.size(),
             hash, &len);

        std::string expected = base64_url_encode(hash, len);
        if (expected != sig) return result;

        // Decode payload
        std::string payload_enc = token.substr(p1 + 1, p2 - p1 - 1);
        std::string payload_json = base64_url_decode(payload_enc);
        
        auto payload = nlohmann::json::parse(payload_json);
        
        // Check expiration
        if (payload.contains("exp")) {
            result.exp = payload["exp"].get<long>();
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            if (now > result.exp) return result; // Expired
        }
        
        // Extract claims
        if (payload.contains("sub")) {
            result.subject = payload["sub"].get<std::string>();
        }
        if (payload.contains("jti")) {
            result.jti = payload["jti"].get<std::string>();
        }
        
        result.valid = true;
        
    } catch (...) {
        result.valid = false;
    }
    return result;
}

inline DecodedJWT verify_access_jwt(const std::string& token) {
    auto secret = env_or("BCORD_JWT_ACCESS_SECRET", "super_secret_key_change_me");
    return verify_jwt_internal(token, secret);
}

inline DecodedJWT verify_refresh_jwt(const std::string& token) {
    auto secret = env_or("BCORD_JWT_REFRESH_SECRET", "another_secret_key_change_me");
    return verify_jwt_internal(token, secret);
}

// ---------------------------------------------------------------------------
// Cookie string builder
// ---------------------------------------------------------------------------
inline std::string cookie_kv(std::string name, std::string value, std::chrono::seconds ttl) {
    std::ostringstream o;
    auto maxAge = ttl.count();
    auto domain = env_or("BCORD_COOKIE_DOMAIN", "");
    bool secure = (env_or("BCORD_COOKIE_SECURE","true") != "false");
    
    o << name << '=' << value
      << "; Max-Age=" << maxAge
      << "; Path=/"
      << "; HttpOnly";
    
    if (secure) o << "; Secure";
    o << "; SameSite=Lax";
    
    if (!domain.empty()) {
        o << "; Domain=" << domain;
    }
    
    return o.str();
}

// ---------------------------------------------------------------------------
// Redis refresh token storage
// ---------------------------------------------------------------------------
extern std::unique_ptr<sw::redis::Redis> redisClient;

inline void store_refresh_jti(const std::string& jti, const std::string& user_id) {
    if (!redisClient) return;
    long ttl = std::stol( env_or("BCORD_JWT_REFRESH_TTL","2592000") );
    redisClient->setex("rt:" + jti, ttl, user_id);
}

inline bool validate_refresh_jti(const std::string& jti, const std::string& user_id) {
    if (!redisClient) return false;
    auto v = redisClient->get("rt:" + jti);
    return v && *v == user_id;
}

inline void revoke_refresh_jti(const std::string& jti) {
    if (!redisClient) return;
    redisClient->del("rt:" + jti);
}
