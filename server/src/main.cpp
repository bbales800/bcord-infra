// ============================================================================
// BCord Backend — HTTP + WebSocket + Postgres + Redis
// ----------------------------------------------------------------------------
// ✅ Handles /api/login, /api/history, /api/ready
// ✅ WebSocket upgrades (Boost.Beast) with accept(req) for proxy compatibility
// ✅ Structured JSON messages with {user, channel, text}
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

#include <nlohmann/json.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <pqxx/pqxx>
#include <sw/redis++/redis++.h>

namespace net       = boost::asio;
namespace beast     = boost::beast;
namespace http      = beast::http;
namespace websocket = beast::websocket;
using tcp           = net::ip::tcp;

std::mutex cout_mutex;
const std::string PG_CONN   = "dbname=bcord user=bcord password=change_me host=bcord-postgres";
const std::string REDIS_URI = "tcp://bcord-redis:6379";
void log(const std::string &msg) {
    std::lock_guard<std::mutex> lock(cout_mutex);
    std::cout << "[" << std::time(nullptr) << "] " << msg << std::endl;
}

void init_database() {
    try {
        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);
        txn.exec(R"(
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender TEXT NOT NULL,
                channel TEXT DEFAULT 'general',
                text TEXT NOT NULL,
                ts TIMESTAMPTZ DEFAULT NOW()
            )
        )");
        txn.commit();
        log("✅ PostgreSQL table check complete");
    } catch (std::exception &e) {
        log(std::string("❌ PostgreSQL init error: ") + e.what());
    }
}

void insert_message(const std::string &sender, const std::string &channel, const std::string &text) {
    try {
        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);
        txn.exec_params("INSERT INTO messages (sender, channel, text) VALUES ($1, $2, $3)", sender, channel, text);
        txn.commit();
    } catch (...) {
        log("[WARN] Failed to insert message");
    }
}

std::string get_history_json(const std::string &channel) {
    try {
        pqxx::connection c(PG_CONN);
        pqxx::work txn(c);
        pqxx::result r = txn.exec_params(
            "SELECT sender, text, ts FROM messages WHERE channel=$1 ORDER BY ts DESC LIMIT 50",
            channel);

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
static std::string qs_get(const std::string &target, const std::string &key, const std::string &def="") {
    auto pos = target.find('?');
    if (pos == std::string::npos) return def;
    auto qs = target.substr(pos + 1);
    std::string needle = key + "=";
    pos = qs.find(needle);
    if (pos == std::string::npos) return def;
    pos += needle.size();
    auto end = qs.find('&', pos);
    auto val = (end == std::string::npos) ? qs.substr(pos) : qs.substr(pos, end - pos);
    for (size_t i = 0; i + 2 < val.size(); ++i)
        if (val[i] == '%' && val[i+1] == '2' && val[i+2] == '0') val.replace(i, 3, " ");
    return val;
}

template <class Stream>
void handle_request(http::request<http::string_body> &req, Stream &stream) {
    http::response<http::string_body> res{http::status::ok, req.version()};
    res.set(http::field::server, "BCordServer");
    res.set(http::field::content_type, "application/json");

    const std::string target = std::string(req.target());
    log("HTTP request: " + target);

    if (target == "/") {
        res.body() = R"({"status":"ok","message":"BCord backend running"})";
    } else if (target.rfind("/api/login", 0) == 0) {
        res.body() = R"({"status":"ok","token":"demo-token","user":"dev"})";
    } else if (target.rfind("/api/history", 0) == 0) {
        const auto channel = qs_get(target, "channel", "general");
        res.body() = get_history_json(channel);
    } else if (target == "/api/ready") {
        nlohmann::json j = {{"ready", true}, {"db", true}, {"redis_sub", true}};
        res.body() = j.dump();
    } else {
        res.result(http::status::not_found);
        res.body() = R"({"status":"error","message":"Not Found"})";
    }

    res.prepare_payload();
    http::write(stream, res);
}
void do_websocket(tcp::socket socket,
                  http::request<http::string_body> req,
                  std::shared_ptr<sw::redis::Redis> redis) {
    try {
        websocket::stream<beast::tcp_stream> ws(std::move(socket));
        beast::get_lowest_layer(ws).expires_never();
        ws.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        ws.set_option(websocket::stream_base::decorator(
            [](websocket::response_type &res) {
                res.set(http::field::server, "BCordServer WebSocket");
            }));

        ws.accept(req);
        log("🛰️  WebSocket accepted: " + std::string(req.target()));

        auto sub = redis->subscriber();
        sub.subscribe("bcord_channel");

        std::atomic<bool> running{true};
        sub.on_message([&](std::string, std::string payload) {
            try { ws.text(true); ws.write(net::buffer(payload)); }
            catch (...) { running = false; }
        });

        std::thread redis_thread([&]() {
            while (running) { try { sub.consume(); } catch (...) { running = false; } }
        });

        while (running) {
            beast::flat_buffer buffer;
            beast::error_code ec;
            ws.read(buffer, ec);
            if (ec == websocket::error::closed) break;
            if (ec) { running = false; break; }

            std::string msg = beast::buffers_to_string(buffer.data());
            std::string user = "unknown", channel = "general", text = msg;

            try {
                auto j = nlohmann::json::parse(msg);
                if (j.contains("user")) user = j["user"].get<std::string>();
                if (j.contains("channel")) channel = j["channel"].get<std::string>();
                if (j.contains("text")) text = j["text"].get<std::string>();
            } catch (...) {}

            // Ignore ping messages and empty payloads
            if (text == "/quit" || text.empty() || text.find("\"op\":\"ping\"") != std::string::npos)
                continue;

            // Broadcast valid messages
            nlohmann::json out = {
                {"user", user},
                {"channel", channel},
                {"text", text},
                {"ts", std::time(nullptr)}
            };
            redis->publish("bcord_channel", out.dump());
            insert_message(user, channel, text);

        }

        running = false;
        try { sub.unsubscribe("bcord_channel"); } catch (...) {}
        if (redis_thread.joinable()) redis_thread.join();
        ws.close(websocket::close_code::normal);
        log("🔌 WebSocket closed cleanly");
    } catch (const std::exception &e) {
        log(std::string("[WebSocket] Error: ") + e.what());
    }
}
void do_session(tcp::socket socket, std::shared_ptr<sw::redis::Redis> redis) {
    try {
        beast::flat_buffer buffer;
        http::request<http::string_body> req;
        http::read(socket, buffer, req);

        const std::string target = std::string(req.target());
        const bool wants_ws = websocket::is_upgrade(req);
        log("Session: target=" + target + (wants_ws ? " [upgrade]" : " [http]"));

        if (wants_ws) {
            do_websocket(std::move(socket), std::move(req), redis);
            return;
        }
        handle_request(req, socket);
    } catch (const std::exception &e) {
        log(std::string("[Session] Error: ") + e.what());
    }
}

int main() {
    log("🚀 BCord backend starting...");
    init_database();

    try {
        net::io_context ioc{1};
        tcp::acceptor acceptor(ioc, {net::ip::make_address("0.0.0.0"), 9000});
        auto redis = std::make_shared<sw::redis::Redis>(REDIS_URI);
        log("✅ Port 9000 bound successfully");

        for (;;) {
            tcp::socket socket(ioc);
            acceptor.accept(socket);
            std::thread(&do_session, std::move(socket), redis).detach();
        }
    } catch (const std::exception &e) {
        log(std::string("[Fatal] BCord server error: ") + e.what());
        return 1;
    }
}

