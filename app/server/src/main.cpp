#include <cstdlib>
#include <string>
#include <iostream>
#include <thread>
#include <boost/asio.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/core.hpp>

namespace beast = boost::beast;
namespace http  = beast::http;
namespace net   = boost::asio;
using     tcp   = net::ip::tcp;

std::string get_env(const char* k, const char* dflt) {
    const char* v = std::getenv(k);
    return (v && *v) ? std::string(v) : std::string(dflt);
}

static inline bool is_any(const std::string& t, std::initializer_list<const char*> opts) {
    for (auto* s : opts) if (t == s) return true;
    return false;
}

void handle_session(tcp::socket sock) {
    try {
        beast::flat_buffer buffer;
        http::request<http::string_body> req;
        http::read(sock, buffer, req);

        const bool is_get  = (req.method() == http::verb::get);
        const bool is_head = (req.method() == http::verb::head);
        std::string target = std::string(req.target());

        http::response<http::string_body> res;
        res.version(req.version());
        res.keep_alive(false);

        auto respond_text = [&](http::status code, std::string_view body){
            res.result(code);
            res.set(http::field::content_type, "text/plain; charset=utf-8");
            if (is_head) {
                res.content_length(body.size());
            } else {
                res.body() = std::string(body);
                res.prepare_payload();
            }
        };

        auto respond_html = [&](http::status code, std::string_view body){
            res.result(code);
            res.set(http::field::content_type, "text/html; charset=utf-8");
            if (is_head) {
                res.content_length(body.size());
            } else {
                res.body() = std::string(body);
                res.prepare_payload();
            }
        };

        if ((is_get || is_head) && is_any(target, {"/health", "/api/health"})) {
            respond_text(http::status::ok, "ok");
        } else if ((is_get || is_head) && is_any(target, {"/", "/api/"})) {
            respond_html(http::status::ok, "<!doctype html><title>BCord backend</title><h1>BCord backend running</h1>");
        } else {
            respond_text(http::status::not_found, "not found");
        }

        http::write(sock, res);
        beast::error_code ec;
        sock.shutdown(tcp::socket::shutdown_send, ec);
    } catch (std::exception const& e) {
        std::cerr << "[session] " << e.what() << "\n";
    }
}

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

