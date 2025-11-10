#pragma once
#include <string>
#include <chrono>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <ctime>

// ============================================================================
// JWT Utilities — BCord Secure Edition (HS256, 1-hour expiry)
// ============================================================================

// ---------------------------------------------------------------------------
// Secret key (⚠️ Replace for production!)
// ---------------------------------------------------------------------------
const std::string JWT_SECRET = "super_secret_key_change_me";

// ---------------------------------------------------------------------------
// Base64 URL-safe encoder (JWT-safe, no padding)
// ---------------------------------------------------------------------------
inline std::string base64url_encode(const unsigned char *data, size_t len) {
    static const char *chars =
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
    if (valb > -6)
        out.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    return out;
}

// ---------------------------------------------------------------------------
// Base64 URL-safe decoder
// ---------------------------------------------------------------------------
inline std::string base64url_decode(const std::string &input) {
    std::string s = input;
    std::replace(s.begin(), s.end(), '-', '+');
    std::replace(s.begin(), s.end(), '_', '/');
    while (s.size() % 4)
        s.push_back('=');

    std::string out;
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new_mem_buf(s.data(), s.size());
    bio = BIO_push(b64, bio);

    char buffer[256];
    int len;
    while ((len = BIO_read(bio, buffer, sizeof(buffer))) > 0)
        out.append(buffer, len);

    BIO_free_all(bio);
    return out;
}

// ---------------------------------------------------------------------------
// Generate a signed JWT using HS256
// ---------------------------------------------------------------------------
inline std::string generate_jwt(const std::string &username) {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto exp = now + hours(1);

    nlohmann::json header = {{"alg", "HS256"}, {"typ", "JWT"}};
    nlohmann::json payload = {
        {"sub", username},
        {"iat", duration_cast<seconds>(now.time_since_epoch()).count()},
        {"exp", duration_cast<seconds>(exp.time_since_epoch()).count()}};

    std::string header_str = header.dump();
    std::string payload_str = payload.dump();

    std::string header_enc = base64url_encode(
        reinterpret_cast<const unsigned char *>(header_str.data()),
        header_str.size());
    std::string payload_enc = base64url_encode(
        reinterpret_cast<const unsigned char *>(payload_str.data()),
        payload_str.size());

    std::string message = header_enc + "." + payload_enc;

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), JWT_SECRET.data(), JWT_SECRET.size(),
         reinterpret_cast<const unsigned char *>(message.data()), message.size(),
         hash, &len);

    std::string signature = base64url_encode(hash, len);
    return message + "." + signature;
}

// ---------------------------------------------------------------------------
// Verify JWT (signature + expiration)
// ---------------------------------------------------------------------------
inline bool verify_jwt(const std::string &token) {
    size_t dot1 = token.find('.');
    size_t dot2 = token.find('.', dot1 + 1);
    if (dot1 == std::string::npos || dot2 == std::string::npos)
        return false;

    std::string header_b64  = token.substr(0, dot1);
    std::string payload_b64 = token.substr(dot1 + 1, dot2 - dot1 - 1);
    std::string sig_b64     = token.substr(dot2 + 1);

    // ✅ Recreate HMAC signature using the same algorithm as generate_jwt()
    std::string signing_input = header_b64 + "." + payload_b64;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), JWT_SECRET.data(), JWT_SECRET.size(),
         reinterpret_cast<const unsigned char *>(signing_input.data()),
         signing_input.size(), hash, &len);
    std::string expected_b64 = base64url_encode(hash, len);

    // Normalize (remove padding '=')
    auto normalize = [](std::string s) {
        s.erase(std::remove(s.begin(), s.end(), '='), s.end());
        return s;
    };

    if (normalize(expected_b64) != normalize(sig_b64))
        return false;

    // ✅ Decode payload and verify exp claim
    std::string decoded_payload = base64url_decode(payload_b64);
    auto j = nlohmann::json::parse(decoded_payload, nullptr, false);
    if (!j.is_object() || !j.contains("exp"))
        return false;

    std::time_t now = std::time(nullptr);
    if (now > j["exp"].get<std::time_t>())
        return false;

    return true;
}
