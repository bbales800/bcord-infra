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
#include "auth.h"

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
// Auth middleware
// ---------------------------------------------------------------------------
static std::string authenticate_request(const http::request<http::string_body> &req) {
    auto it = req.find(http::field::authorization);
    if (it == req.end()) throw std::runtime_error("missing Authorization header");

    std::string auth(it->value().data(), it->value().size());
    if (auth.rfind("Bearer ", 0) != 0)
        throw std::runtime_error("invalid scheme");

    std::string token = auth.substr(7);
    if (!verify_jwt(token))
        throw std::runtime_error("invalid or expired token");

    return "ok";
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

    if (target == "/api/health" && method == http::verb::get) {
        res.set(http::field::content_type, "application/json");
        res.body() = R"({"status":"healthy"})";
    }
    else if (target == "/api/auth/register" && method == http::verb::post) {
        auto [body, ok] = handle_register(req.body());
        res.result(ok ? http::status::ok : http::status::bad_request);
        res.set(http::field::content_type, "application/json");
        res.body() = body;
    }
    else if (target == "/api/auth/login" && method == http::verb::post) {
        auto [body, ok] = handle_login(req.body());
        res.result(ok ? http::status::ok : http::status::unauthorized);
        res.set(http::field::content_type, "application/json");
        res.body() = body;
    }
    else if (target == "/api/profile" && method == http::verb::get) {
        try {
            authenticate_request(req);
            res.set(http::field::content_type, "application/json");
            res.body() = R"({"status":"ok","message":"profile validated"})";
        } catch (const std::exception &e) {
            res.result(http::status::unauthorized);
            res.body() = std::string(R"({"status":"error","message":")") + e.what() + "\"}";
        }
    }
    else {
        res.result(http::status::not_found);
        res.set(http::field::content_type, "application/json");
        res.body() = R"({"status":"error","message":"Not Found"})";
    }

    res.prepare_payload();
    http::write(stream, res);
}

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

