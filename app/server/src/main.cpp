// app/server/src/main.cpp

#include <cstdlib>
#include <string>
#include <iostream>
#include <thread>
#include <initializer_list>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

#include <pqxx/pqxx>

namespace beast = boost::beast;
namespace http  = beast::http;
namespace net   = boost::asio;
namespace websocket = beast::websocket;
using     tcp   = net::ip::tcp;

// ---------- helpers ----------
static std::string get_env(const char* k, const char* dflt) {
    const char* v = std::getenv(k);
    return (v && *v) ? std::string(v) : std::string(dflt);
}

static inline bool is_any(const std::string& t, std::initializer_list<const char*> opts) {
    for (auto* s : opts) if (t == s) return true;
    return false;
}

static void write_response(http::response<http::string_body>& res,
                           http::status code,
                           const std::string& ctype,
                           std::string_view body,
                           bool head)
{
    res.result(code);
    res.set(http::field::content_type, ctype);
    if (head) {
        res.content_length(body.size());
    } else {
        res.body() = std::string(body);
        res.prepare_payload();
    }
}

// ---------- websocket echo ----------
static void do_ws_echo(tcp::socket sock,
                       http::request<http::string_body>&& req)
{
    try {
        websocket::stream<tcp::socket> ws{std::move(sock)};
        ws.accept(req); // complete WS handshake

        beast::flat_buffer buf;
        for (;;) {
            ws.read(buf);                 // read a message
            ws.text(ws.got_text());       // echo respecting text/binary mode
            ws.write(buf.data());         // write it back
            buf.consume(buf.size());      // clear buffer
        }
    } catch (const std::exception& e) {
        std::cerr << "[ws] " << e.what() << "\n";
    }
}

// ---------- HTTP session ----------
static void handle_session(tcp::socket sock) {
    try {
        beast::flat_buffer buffer;
        http::request<http::string_body> req;
        http::read(sock, buffer, req);

        const bool is_get  = (req.method() == http::verb::get);
        const bool is_head = (req.method() == http::verb::head);
        std::string target = std::string(req.target());

        // WebSocket upgrade first (on /ws or /api/ws)
        if (websocket::is_upgrade(req) &&
            (target == "/ws" || target == "/api/ws"))
        {
            return do_ws_echo(std::move(sock), std::move(req));
        }

        http::response<http::string_body> res;
        res.version(req.version());
        res.keep_alive(false);

        // /api/version
        if ((is_get || is_head) && target == "/api/version") {
            const std::string ver = get_env("APP_VERSION", "1.0.0");
            std::string body = std::string("{\"version\":\"") + ver + "\"}";
            write_response(res, http::status::ok, "application/json; charset=utf-8", body, is_head);
        }
        // /api/info
        else if ((is_get || is_head) && target == "/api/info") {
            const std::string app = get_env("APP_NAME", "BCord");
            const std::string ver = get_env("APP_VERSION", "1.0.0");
            const std::string bt  = get_env("BUILD_TIME", "unknown");
            std::string body = std::string("{\"name\":\"") + app + "\",\"version\":\"" + ver +
                               "\",\"build_time\":\"" + bt + "\"}";
            write_response(res, http::status::ok, "application/json; charset=utf-8", body, is_head);
        }
        // /api/dbtime (query server time via Postgres)
        else if (is_get && target == "/api/dbtime") {
            try {
                std::string conn = "host=" + get_env("PGHOST","postgres") +
                                   " port=" + get_env("PGPORT","5432") +
                                   " dbname=" + get_env("PGDATABASE","bcord") +
                                   " user=" + get_env("PGUSER","bcord") +
                                   " password=" + get_env("PGPASSWORD","change_me");
                pqxx::connection c(conn);
                pqxx::work w(c);
                auto r = w.exec1("SELECT now()");
                std::string ts = r[0].c_str();
                std::string body = std::string("{\"db_time\":\"") + ts + "\"}";
                write_response(res, http::status::ok, "application/json; charset=utf-8", body, false);
            } catch (const std::exception& e) {
                std::string err = std::string("{\"error\":\"") + e.what() + "\"}";
                write_response(res, http::status::internal_server_error, "application/json; charset=utf-8", err, false);
            }
        }
        // /health and /api/health
        else if ((is_get || is_head) && is_any(target, {"/health", "/api/health"})) {
            write_response(res, http::status::ok, "text/plain; charset=utf-8", "ok", is_head);
        }
        // landing for / and /api/
        else if ((is_get || is_head) && is_any(target, {"/", "/api/"})) {
            static constexpr const char* HTML =
                R"(<!doctype html><title>BCord backend</title><h1>BCord backend running</h1>)";
            write_response(res, http::status::ok, "text/html; charset=utf-8", HTML, is_head);
        }
        else {
            write_response(res, http::status::not_found, "text/plain; charset=utf-8", "not found", is_head);
        }

        http::write(sock, res);
        beast::error_code ec;
        sock.shutdown(tcp::socket::shutdown_send, ec);
    } catch (std::exception const& e) {
        std::cerr << "[session] " << e.what() << "\n";
    }
}

// ---------- main ----------
int main() {
    try {
        std::string bind_addr = get_env("BIND_ADDR", "0.0.0.0");
        unsigned short port   = static_cast<unsigned short>(std::stoi(get_env("PORT", "9000")));

        net::io_context ioc{1};
        tcp::endpoint ep{ net::ip::make_address(bind_addr), port };
        tcp::acceptor acc{ioc, ep};
        std::cout << "[start] listening on " << bind_addr << ":" << port << std::endl;

        for (;;) {
            tcp::socket sock{ioc};
            acc.accept(sock);
            std::thread(&handle_session, std::move(sock)).detach();
        }
    } catch (std::exception const& e) {
        std::cerr << "[fatal] " << e.what() << "\n";
        return 1;
    }
}

