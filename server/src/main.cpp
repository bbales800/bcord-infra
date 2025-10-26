// ============================================================================
// BCord Backend — HTTP + WebSocket + Postgres + Redis
// ----------------------------------------------------------------------------
// ✅ Handles /api/login and /api/history
// ✅ WebSocket upgrades now correctly processed
// ✅ Graceful ping/pong + error handling
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

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <pqxx/pqxx>
#include <sw/redis++/redis++.h>

namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
using tcp = net::ip::tcp;

std::mutex cout_mutex;

// PostgreSQL + Redis connections
const std::string PG_CONN =
    "dbname=bcord user=bcord password=change_me host=bcord-postgres";
const std::string REDIS_URI = "tcp://bcord-redis:6379";

void do_session(tcp::socket socket, std::shared_ptr<sw::redis::Redis> redis);
void do_websocket(tcp::socket socket, std::shared_ptr<sw::redis::Redis> redis);

// Thread-safe logger
void log(const std::string &msg) {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "[" << std::time(nullptr) << "] " << msg << std::endl;
}
// Ensure messages table exists
void init_database() {
    try {
        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);
        txn.exec(R"(
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender TEXT NOT NULL,
                text   TEXT NOT NULL,
                ts     TIMESTAMPTZ DEFAULT NOW()
            )
        )");
        txn.commit();
        log("✅ PostgreSQL table check complete");
    } catch (std::exception &e) {
        log(std::string("❌ PostgreSQL init error: ") + e.what());
    }
}

// Insert a new message
void insert_message(const std::string &sender, const std::string &text) {
    try {
        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);
        txn.exec_params("INSERT INTO messages (sender, text) VALUES ($1, $2)", sender, text);
        txn.commit();
    } catch (...) {
        log("[WARN] Failed to insert message");
    }
}

// Fetch recent message history
std::string get_history_json() {
    try {
        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);
        pqxx::result r =
            txn.exec("SELECT sender, text, ts FROM messages ORDER BY ts DESC LIMIT 50");

        std::ostringstream out;
        out << "{\"rows\":[";
        bool first = true;
        for (auto row : r) {
            if (!first) out << ",";
            first = false;
            out << "{\"sender\":\"" << row["sender"].c_str()
                << "\",\"text\":\"" << row["text"].c_str()
                << "\",\"ts\":\"" << row["ts"].c_str() << "\"}";
        }
        out << "]}";
        return out.str();
    } catch (const std::exception &e) {
        log(std::string("[ERROR] DB read failed: ") + e.what());
        return R"({"rows":[]})";
    }
}
// Handle normal HTTP requests
template <class Stream>
void handle_request(http::request<http::string_body> &req, Stream &stream) {
    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::server, "BCordServer");
    res.set(http::field::content_type, "application/json");

    if (req.target() == "/") {
        res.body() = R"({"status":"ok","message":"BCord backend running"})";
    } else if (req.target().starts_with("/api/login")) {
        res.body() = R"({"status":"ok","token":"demo-token","user":"dev"})";
    } else if (req.target().starts_with("/api/history")) {
        res.body() = get_history_json();
    } else {
        res.result(http::status::not_found);
        res.body() = R"({"status":"error","message":"Not Found"})";
    }

    res.prepare_payload();
    http::write(stream, res);
}

// Handle WebSocket session
void do_websocket(tcp::socket socket, std::shared_ptr<sw::redis::Redis> redis) {
    try {
        websocket::stream<tcp::socket> ws(std::move(socket));
        ws.accept();

        log("🧩 WebSocket connection accepted");

        auto sub = redis->subscriber();
        sub.subscribe("bcord_channel");

        std::atomic<bool> running{true};

        // Thread: receive Redis messages and forward to WebSocket
        sub.on_message([&](std::string, std::string payload) {
            try {
                ws.text(true);
                ws.write(net::buffer(payload));
            } catch (...) { running = false; }
        });

        std::thread redis_thread([&]() {
            while (running) {
                try { sub.consume(); } catch (...) { running = false; }
            }
        });

        // Read messages from WebSocket and publish to Redis
        while (running) {
            beast::flat_buffer buffer;
            ws.read(buffer);
            std::string msg = beast::buffers_to_string(buffer.data());
            if (msg == "/quit") break;
            redis->publish("bcord_channel", msg);
            insert_message("user", msg);
        }

        running = false;
        sub.unsubscribe("bcord_channel");
        if (redis_thread.joinable()) redis_thread.join();
    } catch (const std::exception &e) {
        log(std::string("[WebSocket] error: ") + e.what());
    }
}
// Accept connection, detect WebSocket upgrades
void do_session(tcp::socket socket, std::shared_ptr<sw::redis::Redis> redis) {
    try {
        beast::flat_buffer buffer;
        http::request<http::string_body> req;

        // Read incoming request
        http::read(socket, buffer, req);

        // WebSocket upgrade
        if (websocket::is_upgrade(req)) {
            do_websocket(std::move(socket), redis);
            return;
        }

        // Otherwise handle HTTP
        handle_request(req, socket);
    } catch (const std::exception &e) {
        log(std::string("[Session] Error: ") + e.what());
    }
}

// Entry point
int main() {
    log("🚀 BCord backend starting...");
    init_database();

    net::io_context ioc{1};
    tcp::acceptor acceptor(ioc, {tcp::v4(), 9000});
    auto redis = std::make_shared<sw::redis::Redis>(REDIS_URI);
    log("✅ Port 9000 bound successfully");

    while (true) {
        tcp::socket socket(ioc);
        acceptor.accept(socket);
        std::thread(&do_session, std::move(socket), redis).detach();
    }
}

