// ============================================================================
// BCord Backend — HTTP + WebSocket + Postgres + Redis + JWT Auth
// ============================================================================

#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <memory>
#include <chrono>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <regex>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <pqxx/pqxx>
#include <sw/redis++/redis++.h>
#include <openssl/sha.h>
#include "jwt_utils.h"
#include "metrics.h"
#include "auth.h"
#include <algorithm>
#include <cctype>

namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
using tcp = net::ip::tcp;

std::mutex cout_mutex;

const std::string PG_CONN = "dbname=bcord user=bcord password=change_me host=bcord-postgres";
static const std::string REDIS_URI = "tcp://bcord-redis:6379";

static void log(const std::string &msg) {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "[" << std::time(nullptr) << "] " << msg << std::endl;
}

static void init_database() {
    try {
        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);
        txn.commit();
        log("✅ PostgreSQL table check complete");
    } catch (std::exception &e) {
        log(std::string("❌ PostgreSQL init error: ") + e.what());
    }
}

// ---------------------------------------------------------------------------
// Cookie utilities
// ---------------------------------------------------------------------------
static std::string get_cookie(const http::request<http::string_body>& req,
                              const std::string& name) {
    auto it = req.find(http::field::cookie);
    if (it == req.end()) return {};
    std::string cookies = std::string(it->value());
    std::regex kv_re("(^|;\\s*)" + name + "=([^;]+)");
    std::smatch m;
    if (std::regex_search(cookies, m, kv_re) && m.size() >= 3) {
        return m[2].str();
    }
    return {};
}

// ---------------------------------------------------------------------------
// Helper to decode JWT and extract subject (username)
// ---------------------------------------------------------------------------
static std::string decode_jwt_subject(const std::string& token) {
    size_t p1 = token.find('.');
    size_t p2 = token.find('.', p1 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos) {
        throw std::runtime_error("malformed token");
    }

    // Extract base64-encoded payload (between first and second dot)
    std::string payload_enc = token.substr(p1 + 1, p2 - p1 - 1);
    
    // Properly decode the base64url-encoded payload
    std::string payload_json = base64url_decode(payload_enc);

    try {
        auto payload = nlohmann::json::parse(payload_json, nullptr, false);
        if (!payload.is_object()) {
            throw std::runtime_error("invalid payload");
        }
        
        // Extract the "sub" (subject) claim which contains the username
        if (payload.contains("sub")) {
            return payload["sub"].get<std::string>();
        }
        
        throw std::runtime_error("missing subject claim");
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("token decode error: ") + e.what());
    }
}

// ---------------------------------------------------------------------------
// Auth middleware - returns username on success
// ---------------------------------------------------------------------------
static std::string authenticate_request(const http::request<http::string_body> &req) {
    // Prefer Authorization: Bearer ...
    auto it = req.find(http::field::authorization);
    std::string token;

    if (it != req.end()) {
        std::string auth(it->value().data(), it->value().size());
        if (auth.rfind("Bearer ", 0) != 0)
            throw std::runtime_error("invalid scheme");
        token = auth.substr(7);
    } else {
        // Fallback to cookie-based auth
        token = get_cookie(req, "BCORD_ACCESS");
        if (token.empty())
            throw std::runtime_error("missing Authorization header");
    }

    if (!verify_jwt(token))
        throw std::runtime_error("invalid or expired token");

    return decode_jwt_subject(token);
}


// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------
template <class Stream>
static void handle_request(http::request<http::string_body> &req, Stream &stream) {
    http::response<http::string_body> res{http::status::ok, req.version()};
    const std::string target = std::string(req.target());
    const auto method = req.method();
    log("HTTP request: " + target + " method=" + std::string(req.method_string()));
    
    std::string cookie_header;
    if (auto it = req.find(http::field::cookie); it != req.end()) {
        cookie_header = std::string(it->value());
    }

    if (target == "/api/health" && method == http::verb::get) {
        res.set(http::field::content_type, "application/json");
        res.body() = R"({"status":"healthy"})";
    }
    else if ((target == "/metrics") && method == http::verb::get) {
        // ✅ Use Metrics singleton to generate Prometheus text format
        res.set(http::field::content_type, "text/plain; version=0.0.4");
        res.body() = Metrics::instance().to_prometheus_text();
    }
    else if (target == "/api/auth/register" && method == http::verb::post) {
        auto [body, status_code] = handle_register(req.body());
        res.result(static_cast<http::status>(status_code));
        res.set(http::field::content_type, "application/json");
        res.body() = body;
    }
    else if (target == "/api/auth/login" && method == http::verb::post) {
        auto [body, status_code] = handle_login(req.body());
        res.result(static_cast<http::status>(status_code));
        res.set(http::field::content_type, "application/json");
        res.body() = body;
        try {
            const bool success = status_code >= 200 && status_code < 300;
            if (success) {
                auto json = nlohmann::json::parse(body);
                if (json.contains("token")) {
                    std::string access = json["token"].get<std::string>();
                    res.set(http::field::set_cookie,
                        "BCORD_ACCESS=" + access +
                        "; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=900");
                }
                if (json.contains("refresh_token")) {
                    std::string refresh = json["refresh_token"].get<std::string>();
                    res.insert(http::field::set_cookie,
                        "BCORD_REFRESH=" + refresh +
                        "; Path=/api/auth; Secure; HttpOnly; SameSite=Strict; Max-Age=604800");
                }
            }
        } catch (...) {
            // If parsing failed, we still return the JSON body as-is.
        }

    }
    // 2c) Refresh & Logout
    else if ((target == "/api/auth/refresh") && method == http::verb::post) {
        log("[AUTH] /api/auth/refresh");
        res.set(http::field::content_type, "application/json");

        auto [resp_body, status_code] = handle_refresh(req.body(), cookie_header);
        res.result(static_cast<http::status>(status_code));
        res.body() = resp_body;
        try {
            const bool success = status_code >= 200 && status_code < 300;
            if (success) {
                auto json = nlohmann::json::parse(resp_body);
                if (json.contains("access_token")) {
                    std::string access = json["access_token"].get<std::string>();
                    res.set(http::field::set_cookie,
                        "BCORD_ACCESS=" + access +
                        "; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=900");
                }
            }
        } catch (...) {}

    }
    else if ((target == "/api/auth/logout") && method == http::verb::post) {
        log("[AUTH] /api/auth/logout");
        res.set(http::field::content_type, "application/json");
        auto [body, status_code] = handle_logout(req.body(), cookie_header);
        res.result(static_cast<http::status>(status_code));
        res.body() = body;
        if (status_code >= 200 && status_code < 300) {
            res.set(http::field::set_cookie,
                "BCORD_ACCESS=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0");
            res.insert(http::field::set_cookie,
                "BCORD_REFRESH=; Path=/api/auth; Secure; HttpOnly; SameSite=Strict; Max-Age=0");
        }
    }
    else if (target == "/api/profile" && method == http::verb::get) {
        try {
            auto auth = authenticate_request(req);   // existing JWT verify
            res.set(http::field::content_type, "application/json");
            res.body() = R"({"status":"ok","user":")" + auth + R"("})";
        } catch (const std::exception &e) {
            res.result(http::status::unauthorized);
            res.body() = R"({"status":"error","message":")" + std::string(e.what()) + "\"}";
        }
    }

    // -----------------------------------------------------------------------
    // 🧩 CAPTCHA proxy (frontend preview support)
    // -----------------------------------------------------------------------
    else if ((target == "/captcha") && method == http::verb::post) {
        log("[CAPTCHA] Proxy request to OpenCaptcha");

        // Forward request to internal OpenCaptcha container
        CURL *curl = curl_easy_init();
        if (!curl) {
            res.result(http::status::internal_server_error);
            res.set(http::field::content_type, "text/plain");
            res.body() = "curl init failed";
        } else {
            std::string response;
            std::string url = "http://opencaptcha:8080/captcha";

            // --- headers: OpenCaptcha expects JSON, we also accept jpeg back
            struct curl_slist *hdrs = nullptr;
            hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
            hdrs = curl_slist_append(hdrs, "Accept: image/jpeg");

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req.body().c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(req.body().size()));

            // capture binary jpeg safely
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                +[](void *ptr, size_t sz, size_t nm, void *userdata) -> size_t {
                    auto *out = static_cast<std::string*>(userdata);
                    out->append(static_cast<char*>(ptr), sz * nm);
                    return sz * nm;
                });
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
            curl_easy_setopt(curl, CURLOPT_USERAGENT, "bcord-backend/1.0");

            CURLcode rc = curl_easy_perform(curl);
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

            curl_slist_free_all(hdrs);
            curl_easy_cleanup(curl);

            if (rc == CURLE_OK && http_code == 200) {
                res.result(http::status::ok);
                res.set(http::field::content_type, "image/jpeg");
                res.body() = std::move(response);
            } else {
                std::ostringstream oss;
                oss << "captcha backend error (curl=" << rc << ", http=" << http_code << ")";
                res.result(http::status::bad_gateway);
                res.set(http::field::content_type, "text/plain");
                res.body() = oss.str();
            }
        }
    }
    else {
        res.result(http::status::not_found);
        res.set(http::field::content_type, "application/json");
        res.body() = R"({"status":"error","message":"Not Found"})";
    }

    res.prepare_payload();
    http::write(stream, res);
}  // ✅ closes handle_request()


// ---------------------------------------------------------------------------
// Session Dispatcher
// ---------------------------------------------------------------------------
static void do_session(tcp::socket socket) {
    try {
        beast::flat_buffer buffer;
        http::request<http::string_body> req;
        http::read(socket, buffer, req);
        handle_request(req, socket);
    } catch (const std::exception &e) {
        log(std::string("[Session] Error: ") + e.what());
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    log("🚀 BCord backend starting...");
    init_database();
    try {
        net::io_context ioc{1};
        tcp::acceptor acceptor(ioc, {net::ip::make_address("0.0.0.0"), 9000});
        log("✅ Port 9000 bound successfully");
        for (;;) {
            tcp::socket socket(ioc);
            acceptor.accept(socket);
            std::thread(&do_session, std::move(socket)).detach();
        }
    } catch (const std::exception &e) {
        log(std::string("[Fatal] ") + e.what());
        return 1;
    }
}
