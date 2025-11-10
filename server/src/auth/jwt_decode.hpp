// ============================================================================
// auth/jwt_decode.hpp — Proper JWT base64 decoding and verification
// ============================================================================
#pragma once
#include <string>
#include <stdexcept>
#include <vector>

// ---------------------------------------------------------------------------
// Base64 URL-safe decoder
// ---------------------------------------------------------------------------
inline std::string base64_url_decode(const std::string& input) {
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;
    
    std::string out;
    std::vector<int> vec(input.size());
    int i = 0;
    for (char c : input) {
        if (T[c] != -1) vec[i++] = T[c];
    }
    
    int val = 0, valb = -8;
    for (int j = 0; j < i; j++) {
        val = (val << 6) + vec[j];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}
