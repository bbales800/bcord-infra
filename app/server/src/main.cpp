// ============================================================================
// BCord Backend: single-file Boost.Beast HTTP+WebSocket server
// (HEAVILY COMMENTED DEV BUILD)
// Additions in this step:
//   • HTTP abuse controls:
//       - Per-IP token bucket for ALL HTTP routes (20 burst, 10 req/sec).
//         Returns HTTP 429 when exceeded.
//       - 10s socket recv timeout before we read the HTTP request (slowloris).
//   • Uses proxy forwarding headers when present (X-Forwarded-For, X-Real-IP,
//     Forwarded) with string-based lookup for compatibility with older Boost.
//     Falls back to the socket IP when none are set.
// Everything else (WS auth+ACLs, history pagination, soft delete/edit, dev
// signing endpoints, exact-path routing) is unchanged.
// ============================================================================

#include <cstdlib>
#include <string>
#include <string_view>
#include <iostream>
#include <thread>
#include <initializer_list>
#include <sstream>
#include <map>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <random>
#include <csignal>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

#include <pqxx/pqxx>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#ifdef __linux__
#include <sys/socket.h>
#include <sys/time.h>
#endif

namespace beast = boost::beast;
namespace http  = beast::http;
namespace net   = boost::asio;
namespace websocket = beast::websocket;
using     tcp   = net::ip::tcp;

// --------------------------- Small helpers ----------------------------------

static std::string get_env(const char* k, const char* dflt) {
    const char* v = std::getenv(k);
    return (v && *v) ? std::string(v) : std::string(dflt);
}

static inline bool is_any(const std::string& t, std::initializer_list<const char*> opts) {
    for (auto* s : opts) if (t == s) return true;
    return false;
}

static bool env_truthy(const std::string& v) {
    if (v.empty()) return false;
    std::string low;
    low.reserve(v.size());
    for (unsigned char c : v) low.push_back(static_cast<char>(std::tolower(c)));
    return low == "1" || low == "true" || low == "yes" || low == "on";
}

static void write_response(http::response<http::string_body>& res,
                           http::status code,
                           const std::string& ctype,
                           std::string_view body,
                           bool head)
{
    res.result(code);
    res.set(http::field::content_type, ctype);
    if (head) res.content_length(body.size());
    else { res.body() = std::string(body); res.prepare_payload(); }
}

// Trim ASCII whitespace from both ends of a string (in-place)
static inline void trim_inplace(std::string& s) {
    auto issp = [](unsigned char c){ return c==' ' || c=='\t' || c=='\r' || c=='\n'; };
    std::size_t b = 0;
    std::size_t e = s.size();
    while (b < e && issp(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && issp(static_cast<unsigned char>(s[e-1]))) --e;
    if (b == 0 && e == s.size()) return;
    s = s.substr(b, e - b);
}

// Extract exact path (without querystring) for **exact** routing
static std::string path_of(const std::string& target) {
    auto qpos = target.find('?');
    return qpos == std::string::npos ? target : target.substr(0, qpos);
}

// TCP/Redis diagnostics (for /api/diag)
static bool tcp_connect_ok(const std::string& host, const std::string& port) {
    try {
        net::io_context ioc;
        tcp::resolver r{ioc};
        auto results = r.resolve(host, port);
        tcp::socket s{ioc};
        beast::error_code ec;
        net::connect(s, results, ec);
        return !ec;
    } catch (...) { return false; }
}
static bool redis_ping_ok(const std::string& host, const std::string& port, std::string& raw_reply) {
    try {
        net::io_context ioc;
        tcp::resolver r{ioc};
        auto results = r.resolve(host, port);
        tcp::socket s{ioc};
        net::connect(s, results);
        const std::string ping = "*1\r\n$4\r\nPING\r\n";
        net::write(s, net::buffer(ping));
        char buf[128]{};
        beast::error_code ec;
        std::size_t n = s.read_some(net::buffer(buf), ec);
        if (ec && ec != net::error::eof) return false;
        raw_reply.assign(buf, buf + n);
        return raw_reply.find("+PONG") != std::string::npos;
    } catch (...) { return false; }
}

static bool redis_publish(const std::string& host,
                          const std::string& port,
                          const std::string& chan,
                          const std::string& payload)
{
    try {
        net::io_context ioc;
        tcp::resolver resolver{ioc};
        auto endpoints = resolver.resolve(host, port);
        tcp::socket socket{ioc};
        net::connect(socket, endpoints);

        std::string frame;
        frame.reserve(64 + chan.size() + payload.size());
        frame.append("*3\r\n");
        frame.append("$7\r\nPUBLISH\r\n");
        frame.append("$").append(std::to_string(chan.size())).append("\r\n");
        frame.append(chan).append("\r\n");
        frame.append("$").append(std::to_string(payload.size())).append("\r\n");
        frame.append(payload).append("\r\n");

        net::write(socket, net::buffer(frame));
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[redis-publish] " << e.what() << "\n";
        return false;
    } catch (...) {
        std::cerr << "[redis-publish] unknown error\n";
        return false;
    }
}

static bool json_extract_string(const std::string& json,
                                const std::string& key,
                                std::string& out)
{
    std::string needle;
    needle.reserve(key.size() + 2);
    needle.push_back('"');
    needle.append(key);
    needle.push_back('"');

    std::size_t pos = json.find(needle);
    if (pos == std::string::npos) return false;
    pos += needle.size();
    pos = json.find(':', pos);
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) ++pos;
    if (pos >= json.size() || json[pos] != '"') return false;
    ++pos;

    std::string result;
    result.reserve(64);
    while (pos < json.size()) {
        char ch = json[pos++];
        if (ch == '\\') {
            if (pos >= json.size()) return false;
            char esc = json[pos++];
            switch (esc) {
                case '"': result.push_back('"'); break;
                case '\\': result.push_back('\\'); break;
                case '/': result.push_back('/'); break;
                case 'b': result.push_back('\b'); break;
                case 'f': result.push_back('\f'); break;
                case 'n': result.push_back('\n'); break;
                case 'r': result.push_back('\r'); break;
                case 't': result.push_back('\t'); break;
                case 'u': {
                    if (pos + 4 > json.size()) return false;
                    unsigned code = 0;
                    for (int i = 0; i < 4; ++i) {
                        char h = json[pos++];
                        code <<= 4;
                        if (h >= '0' && h <= '9') code |= static_cast<unsigned>(h - '0');
                        else if (h >= 'a' && h <= 'f') code |= 10u + static_cast<unsigned>(h - 'a');
                        else if (h >= 'A' && h <= 'F') code |= 10u + static_cast<unsigned>(h - 'A');
                        else return false;
                    }
                    if (code <= 0x7F) {
                        result.push_back(static_cast<char>(code));
                    } else if (code <= 0x7FF) {
                        result.push_back(static_cast<char>(0xC0 | ((code >> 6) & 0x1F)));
                        result.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                    } else {
                        result.push_back(static_cast<char>(0xE0 | ((code >> 12) & 0x0F)));
                        result.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                        result.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                    }
                    break;
                }
                default:
                    return false;
            }
        } else if (ch == '"') {
            out = std::move(result);
            return true;
        } else {
            result.push_back(ch);
        }
    }
    return false;
}

// URL decoding for QS (handles '+' and %HH)
static std::string url_decode(std::string_view in) {
    std::string out; out.reserve(in.size());
    auto hex = [](char ch)->int{
        if (ch>='0'&&ch<='9') return ch-'0';
        if (ch>='a'&&ch<='f') return 10+(ch-'a');
        if (ch>='A'&&ch<='F') return 10+(ch-'A');
        return -1;
    };
    for (size_t i=0;i<in.size();++i) {
        unsigned char c = (unsigned char)in[i];
        if (c == '+') { out.push_back(' '); continue; }
        if (c == '%' && i+2 < in.size()) {
            int a=hex(in[i+1]), b=hex(in[i+2]);
            if (a>=0 && b>=0) { out.push_back(char((a<<4)|b)); i+=2; continue; }
        }
        out.push_back((char)c);
    }
    return out;
}
static std::map<std::string,std::string> parse_qs(const std::string& target) {
    std::map<std::string,std::string> out;
    auto qpos = target.find('?');
    if (qpos == std::string::npos) return out;
    std::string qs = target.substr(qpos + 1);
    std::stringstream ss(qs);
    std::string kv;
    while (std::getline(ss, kv, '&')) {
        auto eq = kv.find('=');
        if (eq == std::string::npos) continue;
        std::string key = url_decode(std::string_view(kv).substr(0, eq));
        std::string val = url_decode(std::string_view(kv).substr(eq + 1));
        out[key] = val;
    }
    return out;
}

static std::string json_escape(std::string_view s) {
    std::string out; out.reserve(s.size()+16);
    for (unsigned char c : s) {
        switch (c) {
            case '\"': out+="\\\""; break; case '\\': out+="\\\\"; break;
            case '\b': out+="\\b";  break; case '\f': out+="\\f";  break;
            case '\n': out+="\\n";  break; case '\r': out+="\\r";  break;
            case '\t': out+="\\t";  break;
            default:
                if (c < 0x20) { char buf[7]; std::snprintf(buf,sizeof(buf),"\\u%04X",c); out+=buf; }
                else out+=char(c);
        }
    }
    return out;
}
static std::string trim_soft(const std::string& s) {
    size_t i=0,j=s.size();
    while (i<j && (unsigned char)s[i] <= 0x20) ++i;
    while (j>i && (unsigned char)s[j-1] <= 0x20) --j;
    return s.substr(i, j-i);
}

static std::string to_hex_lower(const unsigned char* data, unsigned len) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (unsigned i = 0; i < len; ++i) {
        out[2 * i]     = hex[(data[i] >> 4) & 0x0F];
        out[2 * i + 1] = hex[data[i] & 0x0F];
    }
    return out;
}

static std::string sha256_hex(std::string_view data) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (!EVP_Digest(reinterpret_cast<const unsigned char*>(data.data()), data.size(),
                    digest, &len, EVP_sha256(), nullptr)) {
        return {};
    }
    return to_hex_lower(digest, len);
}

static std::string hmac_sha256_bin(const std::string& key, std::string_view msg) {
    unsigned int len = 0;
    unsigned char mac[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
         mac, &len);
    return std::string(reinterpret_cast<const char*>(mac), reinterpret_cast<const char*>(mac) + len);
}

// HMAC-SHA256 → lowercase hex
static std::string hmac_sha256_hex(const std::string& key, const std::string& msg) {
    std::string mac = hmac_sha256_bin(key, msg);
    return to_hex_lower(reinterpret_cast<const unsigned char*>(mac.data()), static_cast<unsigned>(mac.size()));
}

static std::string aws_uri_encode(std::string_view s, bool encode_slash) {
    auto is_unreserved = [](unsigned char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
    };
    std::string out;
    out.reserve(s.size() * 3);
    char buf[4];
    for (unsigned char c : s) {
        if (is_unreserved(c) || (c == '/' && !encode_slash)) {
            out.push_back(static_cast<char>(c));
        } else {
            std::snprintf(buf, sizeof(buf), "%02X", c);
            out.push_back('%');
            out.push_back(buf[0]);
            out.push_back(buf[1]);
        }
    }
    return out;
}

static std::tm gmtime_utc(std::time_t t) {
    std::tm out{};
#if defined(_WIN32)
    gmtime_s(&out, &t);
#else
    gmtime_r(&t, &out);
#endif
    return out;
}

static std::string safe_filename(std::string_view name) {
    std::string out;
    out.reserve(name.size());
    for (unsigned char c : name) {
        if (c < 0x20) continue; // strip control chars
        if (c == ' ') {
            out.push_back('-');
            continue;
        }
        unsigned char lower = static_cast<unsigned char>(std::tolower(c));
        if ((lower >= 'a' && lower <= 'z') || (lower >= '0' && lower <= '9') ||
            lower == '.' || lower == '_' || lower == '-') {
            out.push_back(static_cast<char>(lower));
        } else {
            out.push_back('_');
        }
    }
    if (out.empty()) out = "file";
    return out;
}

static std::string uuid4() {
    static thread_local std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 255);
    unsigned char bytes[16];
    for (auto& b : bytes) b = static_cast<unsigned char>(dist(rng));
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0F) | 0x40);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3F) | 0x80);
    char buf[37];
    std::snprintf(buf, sizeof(buf),
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  bytes[0], bytes[1], bytes[2], bytes[3],
                  bytes[4], bytes[5],
                  bytes[6], bytes[7],
                  bytes[8], bytes[9],
                  bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return std::string(buf);
}

static std::string attachment_object_key(const std::string& channel, std::string_view filename) {
    std::string chan = safe_filename(channel);
    if (chan.empty()) chan = "channel";
    std::time_t now = std::time(nullptr);
    std::tm tm = gmtime_utc(now);
    char yymm[7];
    std::strftime(yymm, sizeof(yymm), "%Y%m", &tm);
    std::string key = "attachments/";
    key += chan;
    key.push_back('/');
    key.append(yymm);
    key.push_back('/');
    key += uuid4();
    key += "__";
    key += safe_filename(filename);
    return key;
}

struct S3Config {
    std::string endpoint;
    std::string bucket;
    std::string region;
    std::string access_key;
    std::string secret_key;
    std::string public_base_url;
    bool use_ssl{true};
    bool virtual_hosted{true};
    int default_ttl{600};
    bool configured{false};

    bool is_configured() const { return configured; }
};

static S3Config load_s3_config() {
    S3Config cfg;
    cfg.endpoint = get_env("S3_ENDPOINT", "");
    cfg.bucket = get_env("S3_BUCKET", "");
    cfg.region = get_env("S3_REGION", "");
    cfg.access_key = get_env("S3_ACCESS_KEY", "");
    cfg.secret_key = get_env("S3_SECRET_KEY", "");
    cfg.public_base_url = get_env("S3_PUBLIC_BASE_URL", "");
    cfg.use_ssl = env_truthy(get_env("S3_USE_SSL", "1"));
    cfg.virtual_hosted = env_truthy(get_env("S3_VIRTUAL_HOSTED", "1"));
    try {
        int ttl = std::stoi(get_env("S3_PRESIGN_TTL_SECONDS", "600"));
        if (ttl > 0) cfg.default_ttl = ttl;
    } catch (...) {
        cfg.default_ttl = 600;
    }
    if (!cfg.public_base_url.empty() && cfg.public_base_url.back() == '/') {
        cfg.public_base_url.pop_back();
    }
    cfg.configured = !cfg.endpoint.empty() && !cfg.bucket.empty() && !cfg.region.empty() &&
                     !cfg.access_key.empty() && !cfg.secret_key.empty();
    return cfg;
}

static const S3Config g_s3_config = load_s3_config();

static bool is_valid_attachment_key(const std::string& key) {
    if (key.empty()) return false;
    if (key.size() >= 1024) return false;
    if (key.rfind("attachments/", 0) != 0) return false;
    return true;
}

static std::string s3_object_url(const S3Config& cfg, const std::string& key) {
    if (!is_valid_attachment_key(key)) return {};
    if (!cfg.public_base_url.empty()) {
        return cfg.public_base_url + "/" + key;
    }
    if (!cfg.is_configured()) return {};

    std::time_t now = std::time(nullptr);
    std::tm tm = gmtime_utc(now);
    char date_stamp[9];
    char amz_date[17];
    std::strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", &tm);
    std::strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", &tm);
    return s3_presign_url(cfg, "GET", key, 86400, amz_date, date_stamp);
}

static std::string s3_presign_url(const S3Config& cfg,
                                  const std::string& method,
                                  const std::string& key,
                                  int ttl,
                                  const std::string& amz_date,
                                  const std::string& date_stamp)
{
    if (!cfg.is_configured() || ttl <= 0) return {};
    std::string host = cfg.virtual_hosted ? (cfg.bucket + "." + cfg.endpoint) : cfg.endpoint;
    std::string path = cfg.virtual_hosted ? ("/" + key) : ("/" + cfg.bucket + "/" + key);
    std::string canonical_uri = aws_uri_encode(path, false);

    std::string credential_scope = date_stamp + "/" + cfg.region + "/s3/aws4_request";
    std::string credential = cfg.access_key + "/" + credential_scope;

    std::vector<std::pair<std::string, std::string>> params;
    params.emplace_back("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
    params.emplace_back("X-Amz-Credential", credential);
    params.emplace_back("X-Amz-Date", amz_date);
    params.emplace_back("X-Amz-Expires", std::to_string(ttl));
    params.emplace_back("X-Amz-SignedHeaders", "host");

    std::vector<std::pair<std::string, std::string>> encoded;
    encoded.reserve(params.size());
    for (auto& p : params) {
        encoded.emplace_back(aws_uri_encode(p.first, true), aws_uri_encode(p.second, true));
    }
    std::sort(encoded.begin(), encoded.end(), [](const auto& a, const auto& b) {
        if (a.first == b.first) return a.second < b.second;
        return a.first < b.first;
    });

    std::string canonical_query;
    for (std::size_t i = 0; i < encoded.size(); ++i) {
        if (i > 0) canonical_query.push_back('&');
        canonical_query += encoded[i].first;
        canonical_query.push_back('=');
        canonical_query += encoded[i].second;
    }

    std::string canonical_request = method;
    canonical_request.push_back('\n');
    canonical_request += canonical_uri;
    canonical_request.push_back('\n');
    canonical_request += canonical_query;
    canonical_request.push_back('\n');
    canonical_request += "host:";
    canonical_request += host;
    canonical_request.append("\n\n");
    canonical_request += "host\nUNSIGNED-PAYLOAD";

    std::string hashed_canonical = sha256_hex(canonical_request);
    if (hashed_canonical.empty()) return {};
    std::string string_to_sign = std::string("AWS4-HMAC-SHA256\n") +
                                 amz_date + "\n" +
                                 credential_scope + "\n" +
                                 hashed_canonical;

    std::string k_secret = "AWS4" + cfg.secret_key;
    std::string k_date = hmac_sha256_bin(k_secret, date_stamp);
    std::string k_region = hmac_sha256_bin(k_date, cfg.region);
    std::string k_service = hmac_sha256_bin(k_region, "s3");
    std::string k_signing = hmac_sha256_bin(k_service, "aws4_request");
    std::string signature_bin = hmac_sha256_bin(k_signing, string_to_sign);
    if (signature_bin.empty()) return {};
    std::string signature = to_hex_lower(reinterpret_cast<const unsigned char*>(signature_bin.data()),
                                         static_cast<unsigned>(signature_bin.size()));

    std::string final_query = canonical_query + "&X-Amz-Signature=" + signature;
    std::string scheme = cfg.use_ssl ? "https" : "http";
    return scheme + "://" + host + canonical_uri + "?" + final_query;
}

static bool hex_ci_equal(const std::string& a, const std::string& b) {
    if (a.size()!=b.size()) return false;
    unsigned char diff=0;
    for (size_t i=0;i<a.size();++i){
        unsigned char ca=(unsigned char)std::tolower((unsigned char)a[i]);
        unsigned char cb=(unsigned char)std::tolower((unsigned char)b[i]);
        diff |= (ca ^ cb);
    }
    return diff==0;
}

static long long ensure_channel_id(pqxx::connection& conn, const std::string& name) {
    pqxx::work w(conn);
    auto row = w.exec_params1(
        "INSERT INTO channels(name) VALUES ($1) "
        "ON CONFLICT (name) DO UPDATE SET name=EXCLUDED.name RETURNING id",
        name);
    w.commit();
    return row[0].as<long long>();
}

// ------------------------- Auth & admin signatures --------------------------

static bool verify_token(const std::string& secret,
                         const std::string& user,
                         const std::string& channel,
                         const std::string& ts_str,
                         const std::string& token_hex)
{
    if (secret.empty()) return true; // dev fallback
    if (user.empty() || channel.empty() || ts_str.empty() || token_hex.empty()) return false;
    std::uint64_t ts=0; try{ ts=std::stoull(ts_str);}catch(...){return false;}
    std::uint64_t now_s = (std::uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if ((now_s>ts?now_s-ts:ts-now_s) > 300) return false;
    std::string expect = hmac_sha256_hex(secret, user + "|" + channel + "|" + ts_str);
    return hex_ci_equal(expect, token_hex);
}

// canonical: op|arg1|arg2|...|ts ; legacy (edit only): edit|id|user|ts|body
static bool verify_op_sig(const std::string& secret,
                          const std::string& op,
                          const std::vector<std::string>& args,
                          const std::string& ts_str,
                          const std::string& sig_hex)
{
    if (secret.empty() || op.empty() || ts_str.empty() || sig_hex.empty()) return false;
    std::uint64_t ts=0; try{ ts=std::stoull(ts_str);}catch(...){return false;}
    std::uint64_t now_s = (std::uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if ((now_s>ts?now_s-ts:ts-now_s) > 300) return false;

    std::ostringstream oss; oss<<op; for (auto& a: args) oss<<'|'<<a; oss<<'|'<<ts_str;
    std::string mac_can = hmac_sha256_hex(secret, oss.str());
    if (hex_ci_equal(mac_can, sig_hex)) return true;

    if (op=="edit" && args.size()==3) {
        std::string msg_leg = std::string("edit|") + args[0] + "|" + args[1] + "|" + ts_str + "|" + args[2];
        std::string mac_leg = hmac_sha256_hex(secret, msg_leg);
        if (hex_ci_equal(mac_leg, sig_hex)) return true;
    }
    return false;
}
static bool verify_admin_sig(const std::string& secret,
                             const std::string& user,
                             const std::string& channel,
                             const std::string& role,
                             const std::string& ts_str,
                             const std::string& sig_hex)
{
    return verify_op_sig(secret, "add_member", {user, channel, role}, ts_str, sig_hex);
}

// ------------------------- WS fan-out registry ------------------------------

struct WsSession {
    explicit WsSession(tcp::socket&& s) : ws(std::move(s)) {}
    websocket::stream<tcp::socket> ws;
    std::mutex write_mtx;
};
static std::unordered_map<std::string, std::vector<std::weak_ptr<WsSession>>> g_channels;
static std::mutex g_channels_mtx;

static std::atomic<bool> g_redis_sub_connected{false};
static std::atomic<std::int64_t> g_redis_sub_last_ok{0};
static std::atomic<bool> g_draining{false};
static std::atomic<std::int64_t> g_draining_since{0};
static int parse_drain_close_after() {
    try {
        int v = std::stoi(get_env("DRAIN_CLOSE_AFTER_SECONDS", "20"));
        return v < 0 ? 0 : v;
    } catch (...) {
        return 20;
    }
}
static const int g_drain_close_after = parse_drain_close_after();
static const std::string g_instance_id = get_env("INSTANCE_ID", "");

static void broadcast_channel_locally(const std::string& channel,
                                      const std::string& payload,
                                      const WsSession* skip = nullptr)
{
    std::vector<std::shared_ptr<WsSession>> peers;
    {
        std::lock_guard<std::mutex> lk(g_channels_mtx);
        auto it = g_channels.find(channel);
        if (it != g_channels.end()) {
            auto& vec = it->second;
            std::vector<std::weak_ptr<WsSession>> keep;
            keep.reserve(vec.size());
            for (auto& wp : vec) {
                if (auto sp = wp.lock()) {
                    peers.push_back(sp);
                    keep.push_back(sp);
                }
            }
            vec.swap(keep);
        }
    }

    for (auto& p : peers) {
        if (skip && p.get() == skip) continue;
        std::lock_guard<std::mutex> wl(p->write_mtx);
        beast::error_code wec;
        p->ws.text(true);
        p->ws.write(net::buffer(payload), wec);
    }
}

static std::uint64_t steady_now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

static std::int64_t unix_now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static void handle_shutdown_signal(int) {
    bool was_draining = g_draining.exchange(true, std::memory_order_relaxed);
    std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    if (now < 0) now = 0;
    std::int64_t expected = 0;
    std::int64_t since = now;
    if (!g_draining_since.compare_exchange_strong(expected, now, std::memory_order_relaxed)) {
        since = g_draining_since.load(std::memory_order_relaxed);
    }
    if (!was_draining) {
        std::cout << "[drain] draining since " << since << std::endl;
    }
}

static bool resp_read_line(const std::string& buf, std::size_t& pos, std::string& line) {
    auto end = buf.find("\r\n", pos);
    if (end == std::string::npos) return false;
    line.assign(buf, pos, end - pos);
    pos = end + 2;
    return true;
}

static bool resp_parse_long(const std::string& text, long long& value) {
    try {
        value = std::stoll(text);
        return true;
    } catch (...) {
        return false;
    }
}

static bool resp_try_parse(const std::string& buf,
                           std::size_t& consumed,
                           std::vector<std::string>& array_out,
                           std::string& simple_out)
{
    array_out.clear();
    simple_out.clear();
    consumed = 0;
    if (buf.empty()) return false;

    char prefix = buf[0];
    if (prefix == '+' || prefix == '-') {
        std::size_t pos = 1;
        std::string line;
        if (!resp_read_line(buf, pos, line)) return false;
        simple_out = (prefix == '-') ? std::string("-") + line : line;
        consumed = pos;
        return true;
    }

    if (prefix != '*') return false;

    std::size_t pos = 1;
    std::string count_line;
    if (!resp_read_line(buf, pos, count_line)) return false;
    long long count = 0;
    if (!resp_parse_long(count_line, count) || count < 0) return false;

    array_out.reserve(static_cast<std::size_t>(count));
    for (long long i = 0; i < count; ++i) {
        if (pos >= buf.size()) return false;
        char type = buf[pos++];
        if (type == '$') {
            std::string len_line;
            if (!resp_read_line(buf, pos, len_line)) return false;
            long long len = 0;
            if (!resp_parse_long(len_line, len)) return false;
            if (len < 0) {
                array_out.emplace_back();
                continue;
            }
            if (pos + static_cast<std::size_t>(len) + 2 > buf.size()) return false;
            array_out.emplace_back(buf.substr(pos, static_cast<std::size_t>(len)));
            pos += static_cast<std::size_t>(len);
            if (pos + 2 > buf.size()) return false;
            if (buf[pos] != '\r' || buf[pos + 1] != '\n') return false;
            pos += 2;
        } else if (type == ':') {
            std::string int_line;
            if (!resp_read_line(buf, pos, int_line)) return false;
            array_out.emplace_back(int_line);
        } else if (type == '+') {
            std::string simple_line;
            if (!resp_read_line(buf, pos, simple_line)) return false;
            array_out.emplace_back(simple_line);
        } else {
            return false;
        }
    }

    consumed = pos;
    return true;
}

static void redis_subscriber_loop() {
    const std::string host = get_env("REDIS_HOST", "redis");
    const std::string port = get_env("REDIS_PORT", "6379");
    const std::string pattern = "bcord:*";

    for (;;) {
        try {
            net::io_context ioc;
            tcp::resolver resolver{ioc};
            auto endpoints = resolver.resolve(host, port);
            tcp::socket socket{ioc};
            net::connect(socket, endpoints);
            std::cout << "[redis-sub] reconnected" << std::endl;
            socket.non_blocking(true);

            std::string cmd;
            cmd.reserve(64 + pattern.size());
            cmd.append("*2\r\n");
            cmd.append("$10\r\nPSUBSCRIBE\r\n");
            cmd.append("$");
            cmd.append(std::to_string(pattern.size()));
            cmd.append("\r\n");
            cmd.append(pattern);
            cmd.append("\r\n");

            {
                static bool logged_frame = false;
                if (!logged_frame) {
                    std::ostringstream hex;
                    hex << "[redis-sub] sending PSUBSCRIBE len=" << cmd.size() << " hex=";
                    hex << std::hex << std::setfill('0');
                    std::size_t limit = std::min<std::size_t>(cmd.size(), 64);
                    for (std::size_t i = 0; i < limit; ++i) {
                        hex << std::setw(2) << static_cast<unsigned>(static_cast<unsigned char>(cmd[i]));
                        if (i + 1 < limit) hex << ' ';
                    }
                    std::cout << hex.str() << std::dec << std::endl;
                    logged_frame = true;
                }
            }

            net::write(socket, net::buffer(cmd));

            std::string buffer;
            bool subscribed = false;
            auto last_ping = std::chrono::steady_clock::now();

            for (;;) {
                beast::error_code ec;
                char temp[4096];
                std::size_t n = socket.read_some(net::buffer(temp), ec);
                if (!ec) {
                    buffer.append(temp, n);
                    while (!buffer.empty()) {
                        std::size_t consumed = 0;
                        std::vector<std::string> parts;
                        std::string simple;
                        if (!resp_try_parse(buffer, consumed, parts, simple)) break;
                        buffer.erase(0, consumed);

                        if (!simple.empty()) {
                            if (simple == "PONG") {
                                g_redis_sub_last_ok.store(unix_now_seconds(), std::memory_order_relaxed);
                            } else if (!simple.empty() && simple[0] == '-') {
                                std::cerr << "[redis-sub] " << simple << "\n";
                            }
                            continue;
                        }

                        if (parts.empty()) continue;
                        std::string kind = parts[0];
                        std::transform(kind.begin(), kind.end(), kind.begin(), [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
                        if (kind == "psubscribe" && parts.size() >= 3) {
                            g_redis_sub_connected.store(true, std::memory_order_relaxed);
                            g_redis_sub_last_ok.store(unix_now_seconds(), std::memory_order_relaxed);
                            if (!subscribed) {
                                std::cout << "[redis-sub] subscribed to " << pattern << std::endl;
                                subscribed = true;
                            }
                        } else if (kind == "pmessage" && parts.size() >= 4) {
                            g_redis_sub_last_ok.store(unix_now_seconds(), std::memory_order_relaxed);
                            const std::string& incoming_channel = parts[2];
                            const std::string& payload = parts[3];

                            std::string json_channel;
                            std::string json_body;
                            std::string json_src;
                            bool have_body = json_extract_string(payload, "body", json_body);
                            if (!have_body || json_body.empty()) continue;
                            if (!json_extract_string(payload, "channel", json_channel)) {
                                json_channel = incoming_channel;
                            }
                            if (!json_extract_string(payload, "src", json_src)) {
                                json_src.clear();
                                if (!json_body.empty() && json_body.front() == '{') {
                                    std::string inner_src;
                                    if (json_extract_string(json_body, "src", inner_src)) {
                                        json_src = std::move(inner_src);
                                    }
                                }
                            }
                            if (!g_instance_id.empty() && !json_src.empty() && json_src == g_instance_id) {
                                continue;
                            }

                            broadcast_channel_locally(json_channel, json_body);
                        }
                    }
                } else if (ec == net::error::would_block || ec == net::error::try_again) {
                    // no data ready
                } else {
                    g_redis_sub_connected.store(false, std::memory_order_relaxed);
                    throw beast::system_error{ec};
                }

                auto now_tp = std::chrono::steady_clock::now();
                if (subscribed && now_tp - last_ping >= std::chrono::seconds(5)) {
                    const std::string ping = "*1\r\n$4\r\nPING\r\n";
                    net::write(socket, net::buffer(ping));
                    last_ping = now_tp;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        } catch (const std::exception& e) {
            std::cerr << "[redis-sub] " << e.what() << "\n";
        } catch (...) {
            std::cerr << "[redis-sub] unknown error\n";
        }

        g_redis_sub_connected.store(false, std::memory_order_relaxed);
        g_redis_sub_last_ok.store(0, std::memory_order_relaxed);
        std::cout << "[redis-sub] disconnected, will retry" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

static void presence_touch(const std::string& conn_str, long long chan_id, const std::string& user) {
    if (chan_id <= 0) return;
    try {
        pqxx::connection c(conn_str); pqxx::work w(c);
        w.exec_params(
            "INSERT INTO presence(channel_id, user_name, last_seen) "
            "VALUES ($1,$2, now()) "
            "ON CONFLICT (channel_id, user_name) DO UPDATE SET last_seen = EXCLUDED.last_seen",
            chan_id, user);
        w.commit();
    } catch (const std::exception& e) { std::cerr<<"[presence] "<<e.what()<<"\n"; }
}

// ------------------------- HTTP abuse controls ------------------------------

// Token bucket per client key (IP). We use X-Forwarded-For when present to avoid
// rate-limiting the Caddy proxy IP.
struct Bucket {
    double tokens;
    std::chrono::steady_clock::time_point last;
    Bucket(double t, std::chrono::steady_clock::time_point tp) : tokens(t), last(tp) {}
    Bucket() : tokens(0.0), last(std::chrono::steady_clock::now()) {}
};

static std::unordered_map<std::string, Bucket> g_http_rl;
static std::mutex g_http_rl_mtx;

// Single place to configure HTTP RL.
// capacity = max burst; refill = tokens added per second.
static constexpr double HTTP_RL_CAPACITY = 20.0;    // allow short bursts
static constexpr double HTTP_RL_REFILL   = 10.0;    // ~10 req/sec sustained

static bool http_rate_ok(const std::string& key) {
    using clock = std::chrono::steady_clock;
    auto now = clock::now();
    std::lock_guard<std::mutex> lk(g_http_rl_mtx);
    auto it = g_http_rl.find(key);
    if (it == g_http_rl.end()) {
        g_http_rl.emplace(key, Bucket(HTTP_RL_CAPACITY, now));
        return true;
    }

    auto& b = it->second;
    // Refill
    std::chrono::duration<double> dt = now - b.last;
    b.last = now;
    b.tokens = std::min(HTTP_RL_CAPACITY, b.tokens + dt.count() * HTTP_RL_REFILL);
    if (b.tokens < 1.0) return false;
    b.tokens -= 1.0;
    return true;
}

// Extract client IP key for RL: prefer header; else socket remote IP.
static std::string client_ip_key(const http::request<http::string_body>& req, tcp::socket& sock) {
    // 1) X-Forwarded-For: take first token
    if (auto it = req.find("X-Forwarded-For"); it != req.end()) {
        auto value = it->value();
        std::string s(value.data(), value.size());
        auto comma = s.find(',');
        if (comma != std::string::npos) s = s.substr(0, comma);
        trim_inplace(s);
        if (!s.empty()) return s;
    }
    // 2) X-Real-IP
    if (auto it = req.find("X-Real-IP"); it != req.end()) {
        auto value = it->value();
        std::string s(value.data(), value.size());
        trim_inplace(s);
        if (!s.empty()) return s;
    }
    // 3) Forwarded: for=<ip>
    if (auto it = req.find("Forwarded"); it != req.end()) {
        auto value = it->value();
        std::string v(value.data(), value.size());
        auto pos = v.find("for=");
        if (pos != std::string::npos) {
            pos += 4;
            bool quoted = (pos < v.size() && (v[pos] == '\"' || v[pos] == '\''));
            if (quoted) ++pos;
            std::size_t end = pos;
            while (end < v.size() && v[end] != ';' && v[end] != ',' && (!quoted || v[end] != '\"')) ++end;
            std::string s = v.substr(pos, end - pos);
            if (!s.empty() && s.front() == '[' && s.back() == ']') {
                s = s.substr(1, s.size() - 2);
            }
            trim_inplace(s);
            if (!s.empty()) return s;
        }
    }
    // 4) Fallback to socket remote IP
    beast::error_code ec;
    auto ep = sock.remote_endpoint(ec);
    if (!ec) return ep.address().to_string();
    return "unknown";
}

// Slowloris guard: set SO_RCVTIMEO (Linux) for header read
static void set_recv_timeout(tcp::socket& sock, int seconds) {
#ifdef __linux__
    timeval tv{}; tv.tv_sec = seconds; tv.tv_usec = 0;
    ::setsockopt(sock.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#else
    (void)sock; (void)seconds;
#endif
}

// ------------------------- WS session core ----------------------------------

static void do_ws_echo(tcp::socket sock, http::request<http::string_body>&& req)
{
    auto self = std::make_shared<WsSession>(std::move(sock));
    try {
        self->ws.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        self->ws.read_message_max(8192);
        self->ws.set_option(websocket::stream_base::decorator(
            [](websocket::response_type& res){ res.set(http::field::server, "BCord-WS"); }
        ));
        self->ws.accept(req);

        const std::string target = std::string(req.target());
        auto qs = parse_qs(target);
        std::string channel = qs.count("channel") ? qs["channel"] : "general";
        std::string user    = qs.count("user")    ? qs["user"]    : "anon";
        std::string ts_str  = qs.count("ts")      ? qs["ts"]      : "";
        std::uint64_t time_left=0;
        if (!ts_str.empty()) {
            try{
                std::uint64_t ts=std::stoull(ts_str);
                std::uint64_t now_s=(std::uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                if (ts + 300ULL > now_s) time_left = (ts + 300ULL) - now_s;
            }catch(...){}
        }

        const std::string conn = "host=" + get_env("PGHOST","postgres") +
                                 " port=" + get_env("PGPORT","5432") +
                                 " dbname=" + get_env("PGDATABASE","bcord") +
                                 " user=" + get_env("PGUSER","bcord") +
                                 " password=" + get_env("PGPASSWORD","change_me");
        std::unique_ptr<pqxx::connection> db;
        try { db = std::make_unique<pqxx::connection>(conn); } catch (...) { db.reset(); }

        long long chan_id=-1;
        if (db) { try { chan_id = ensure_channel_id(*db, channel); } catch (...) { chan_id=-1; } }

        { std::lock_guard<std::mutex> lk(g_channels_mtx); g_channels[channel].push_back(self); }

        presence_touch(conn, chan_id, user);
        std::atomic<bool> hb_run{true};
        std::thread hb([&]{ using namespace std::chrono_literals;
            while(hb_run.load()){ std::this_thread::sleep_for(15s); presence_touch(conn, chan_id, user); }});

        std::atomic<bool> tok_timer_run{true};
        std::thread tok_timer;
        if (time_left>0) {
            tok_timer = std::thread([self,time_left,&tok_timer_run]{
                try{
                    std::this_thread::sleep_for(std::chrono::seconds(time_left));
                    if(!tok_timer_run.load()) return;
                    websocket::close_reason cr; cr.code=(websocket::close_code)1008; cr.reason="token expired";
                    std::lock_guard<std::mutex> wl(self->write_mtx);
                    beast::error_code ec; self->ws.close(cr, ec);
                }catch(...){}
            });
        }

        std::atomic<bool> drain_timer_run{true};
        std::thread drain_timer([self,&drain_timer_run]{
            using namespace std::chrono_literals;
            try {
                while (drain_timer_run.load(std::memory_order_relaxed)) {
                    if (!g_draining.load(std::memory_order_relaxed)) {
                        std::this_thread::sleep_for(1s);
                        continue;
                    }

                    std::int64_t since = g_draining_since.load(std::memory_order_relaxed);
                    if (since <= 0) {
                        std::this_thread::sleep_for(1s);
                        continue;
                    }

                    std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
                    if (now < 0) now = 0;
                    std::int64_t deadline = since + static_cast<std::int64_t>(g_drain_close_after);
                    std::int64_t left = deadline - now;

                    if (left > 0) {
                        auto sleep_for = std::chrono::seconds(left > 1 ? 1 : left);
                        std::this_thread::sleep_for(sleep_for);
                        continue;
                    }

                    if (!g_draining.load(std::memory_order_relaxed)) {
                        continue;
                    }

                    websocket::close_reason cr;
                    cr.code = (websocket::close_code)1001;
                    cr.reason = "server draining";
                    {
                        std::lock_guard<std::mutex> wl(self->write_mtx);
                        beast::error_code ec;
                        self->ws.close(cr, ec);
                    }
                    std::cout << "[drain] session closed (1001)" << std::endl;
                    break;
                }
            } catch (...) {}
        });

        const double capacity=30.0, refill_per_sec=3.0;
        double tokens=capacity; auto last_refill=std::chrono::steady_clock::now();
        auto consume_token=[&]()->bool{
            auto now=std::chrono::steady_clock::now();
            std::chrono::duration<double> dt=now-last_refill; last_refill=now;
            tokens = std::min(capacity, tokens + dt.count()*refill_per_sec);
            if(tokens<1.0) return false; tokens-=1.0; return true;
        };
        const size_t MAX_MSG_BYTES=4096;

        beast::flat_buffer buf;
        for(;;){
            beast::error_code ec; self->ws.read(buf, ec);
            if (ec==websocket::error::closed) break;
            if (ec) throw beast::system_error{ec};
            std::string msg = beast::buffers_to_string(buf.data());
            buf.consume(buf.size());

            if (msg.size()>MAX_MSG_BYTES) { websocket::close_reason cr; cr.code=(websocket::close_code)1009; cr.reason="message > 4096 bytes"; self->ws.close(cr); break; }
            if (!consume_token()) { websocket::close_reason cr; cr.code=(websocket::close_code)1008; cr.reason="rate limit: >30 msgs/10s"; self->ws.close(cr); break; }

            presence_touch(conn, chan_id, user);

            std::string to_store = trim_soft(msg);
            if (!to_store.empty() && db && chan_id>0) {
                try {
                    pqxx::work w(*db);
                    w.exec_params("INSERT INTO messages(channel_id,sender,body) VALUES ($1,$2,$3)", chan_id, user, to_store);
                    w.commit();

                    const std::string redis_host = get_env("REDIS_HOST", "redis");
                    const std::string redis_port = get_env("REDIS_PORT", "6379");
                    const std::string payload = std::string("{\"channel\":\"") + json_escape(channel) +
                        "\",\"sender\":\"" + json_escape(user) +
                        "\",\"body\":\"" + json_escape(to_store) +
                        "\",\"ts\":" + std::to_string(std::time(nullptr)) + "}";
                    redis_publish(redis_host, redis_port, "bcord:" + channel, payload);
                }
                catch (const std::exception& e) { std::cerr<<"[ws-store] "<<e.what()<<"\n"; }
            }

            { std::lock_guard<std::mutex> wl(self->write_mtx);
              self->ws.text(self->ws.got_text()); self->ws.write(net::buffer(msg)); }
            broadcast_channel_locally(channel, msg, self.get());
        }

        hb_run.store(false); if (hb.joinable()) hb.join();
        tok_timer_run.store(false); if (tok_timer.joinable()) tok_timer.join();
        drain_timer_run.store(false); if (drain_timer.joinable()) drain_timer.join();

        { std::lock_guard<std::mutex> lk(g_channels_mtx);
          auto &vec=g_channels[channel];
          vec.erase(std::remove_if(vec.begin(),vec.end(),
                   [&](const std::weak_ptr<WsSession>& wp){ auto sp=wp.lock(); return !sp || sp.get()==self.get(); }),
                   vec.end()); }

        presence_touch(conn, chan_id, user);
    } catch (const std::exception& e) { std::cerr<<"[ws] "<<e.what()<<"\n"; }
}

// ---------------------------- HTTP router -----------------------------------

static void handle_session(tcp::socket sock) {
    try {
        // Slowloris guard: if client doesn't deliver a request in 10s, the OS read will fail.
        set_recv_timeout(sock, 10);

        beast::flat_buffer buffer;
        http::request<http::string_body> req;
        http::read(sock, buffer, req);

        const bool is_get  = (req.method()==http::verb::get);
        const bool is_head = (req.method()==http::verb::head);
        const bool is_opts = (req.method()==http::verb::options);

        std::string target = std::string(req.target());
        std::string path   = path_of(target);   // <— exact path (no querystring)

        // Per-IP HTTP rate-limit (after we read the headers so we can use XFF).
        // One request per connection in this server, which simplifies RL.
        {
            std::string ip = client_ip_key(req, sock);
            if (!http_rate_ok(ip)) {
                http::response<http::string_body> r;
                r.version(req.version());
                r.keep_alive(false);
                write_response(r, http::status::too_many_requests, "application/json; charset=utf-8",
                               R"({"error":"rate limited","hint":"try again shortly"})", false);
                http::write(sock, r);
                beast::error_code ec; sock.shutdown(tcp::socket::shutdown_send, ec);
                return;
            }
        }

        // --- WS auth + ACLs BEFORE upgrade ---
        if (websocket::is_upgrade(req) &&
            (path == "/ws" || path == "/api/ws"))
        {
            if (g_draining.load(std::memory_order_relaxed)) {
                http::response<http::string_body> r; r.version(req.version()); r.keep_alive(false);
                write_response(r, http::status::service_unavailable, "application/json; charset=utf-8",
                               R"({"error":"server draining"})", false);
                http::write(sock, r); beast::error_code ec; sock.shutdown(tcp::socket::shutdown_send, ec); return;
            }
            const std::string ws_secret=get_env("WS_SECRET","");
            auto qs=parse_qs(target);
            std::string channel = qs.count("channel")?qs["channel"]:"";
            std::string user    = qs.count("user")?qs["user"]:"";
            std::string ts      = qs.count("ts")?qs["ts"]:"";
            std::string token   = qs.count("token")?qs["token"]:"";

            if(!verify_token(ws_secret,user,channel,ts,token)){
                http::response<http::string_body> r; r.version(req.version()); r.keep_alive(false);
                write_response(r, http::status::unauthorized, "application/json; charset=utf-8",
                               "{\"error\":\"invalid or missing token\"}", false);
                http::write(sock, r); beast::error_code ec; sock.shutdown(tcp::socket::shutdown_send, ec); return;
            }
            if (channel!="general") {
                const std::string conn = "host=" + get_env("PGHOST","postgres") +
                                         " port=" + get_env("PGPORT","5432") +
                                         " dbname=" + get_env("PGDATABASE","bcord") +
                                         " user=" + get_env("PGUSER","bcord") +
                                         " password=" + get_env("PGPASSWORD","change_me");
                bool allowed=false;
                try{
                    pqxx::connection c(conn); pqxx::work w(c);
                    auto r=w.exec_params("SELECT id FROM channels WHERE name=$1", channel);
                    if(!r.empty()){
                        long long cid=r[0][0].as<long long>();
                        auto r2=w.exec_params("SELECT 1 FROM channel_members WHERE channel_id=$1 AND user_name=$2 LIMIT 1", cid, user);
                        allowed=!r2.empty();
                    }
                    w.commit();
                }catch(...){allowed=false;}
                if(!allowed){
                    http::response<http::string_body> r; r.version(req.version()); r.keep_alive(false);
                    write_response(r, http::status::forbidden, "application/json; charset=utf-8",
                                   "{\"error\":\"forbidden: not a member of channel\"}", false);
                    http::write(sock, r); beast::error_code ec; sock.shutdown(tcp::socket::shutdown_send, ec); return;
                }
            }
            return do_ws_echo(std::move(sock), std::move(req));
        }

        http::response<http::string_body> res; res.version(req.version()); res.keep_alive(false);

        // --- CORS preflight ---
        if (is_opts && (path.rfind("/api/",0)==0 || path=="/ws" || path=="/api/ws")) {
            res.set(http::field::access_control_allow_origin, "*");
            res.set(http::field::access_control_allow_methods, "GET,HEAD,OPTIONS");
            res.set(http::field::access_control_allow_headers, "Content-Type");
            write_response(res, http::status::no_content, "text/plain; charset=utf-8", "", true);
        }
        // --- Basic info ---
        else if ((is_get||is_head) && path=="/api/version") {
            write_response(res, http::status::ok, "application/json; charset=utf-8",
                           std::string("{\"version\":\"")+get_env("APP_VERSION","1.0.0")+"\"}", is_head);
        }
        else if ((is_get||is_head) && path=="/api/info") {
            std::string app=get_env("APP_NAME","BCord"), ver=get_env("APP_VERSION","1.0.0"), bt=get_env("BUILD_TIME","unknown");
            write_response(res, http::status::ok, "application/json; charset=utf-8",
                           std::string("{\"name\":\"")+app+"\",\"version\":\""+ver+"\",\"build_time\":\""+bt+"\"}", is_head);
        }
        else if ((is_get||is_head) && path=="/api/dbtime") {
            try{
                std::string conn="host="+get_env("PGHOST","postgres")+" port="+get_env("PGPORT","5432")+
                                 " dbname="+get_env("PGDATABASE","bcord")+" user="+get_env("PGUSER","bcord")+
                                 " password="+get_env("PGPASSWORD","change_me");
                pqxx::connection c(conn); pqxx::work w(c); auto r=w.exec1("SELECT now()");
                write_response(res, http::status::ok, "application/json; charset=utf-8",
                               std::string("{\"db_time\":\"")+std::string(r[0].c_str())+"\"}", is_head);
            }catch(const std::exception& e){
                write_response(res, http::status::internal_server_error, "application/json; charset=utf-8",
                               std::string("{\"error\":\"")+json_escape(e.what())+"\"}", is_head);
            }
        }
        else if ((is_get||is_head) && path=="/api/diag") {
            const std::string pg_host=get_env("PGHOST","postgres"), pg_port=get_env("PGPORT","5432"),
                              rd_host=get_env("REDIS_HOST","redis"), rd_port=get_env("REDIS_PORT","6379");
            bool pg_tcp=tcp_connect_ok(pg_host,pg_port), pg_query=false;
            try{
                std::string conn="host="+pg_host+" port="+pg_port+
                                 " dbname="+get_env("PGDATABASE","bcord")+" user="+get_env("PGUSER","bcord")+
                                 " password="+get_env("PGPASSWORD","change_me");
                pqxx::connection c(conn); pqxx::work w(c); (void)w.exec1("SELECT 1"); pg_query=true;
            }catch(...){ pg_query=false; }
            std::string redis_reply; bool redis_tcp=tcp_connect_ok(rd_host,rd_port), redis_ping=redis_ping_ok(rd_host,rd_port,redis_reply);
            std::ostringstream js; js<<"{\"postgres\":{\"tcp\":"<<(pg_tcp?"true":"false")<<",\"query\":"<<(pg_query?"true":"false")
                 <<"},\"redis\":{\"tcp\":"<<(redis_tcp?"true":"false")<<",\"ping\":"<<(redis_ping?"true":"false")<<"}}";
            write_response(res, http::status::ok, "application/json; charset=utf-8", js.str(), is_head);
        }
        else if ((is_get||is_head) && path=="/api/attachments/presign") {
            if(get_env("ENABLE_DEV_TOKEN","0")!="1"){
                write_response(res, http::status::not_found, "application/json; charset=utf-8", R"({"error":"not enabled"})", is_head);
            }else if(!g_s3_config.is_configured()){
                write_response(res, http::status::service_unavailable, "application/json; charset=utf-8", R"({"error":"s3 not configured"})", is_head);
            }else{
                auto qs=parse_qs(target);
                auto it_chan=qs.find("channel");
                auto it_file=qs.find("filename");
                if(it_chan==qs.end() || it_file==qs.end()){
                    write_response(res, http::status::bad_request, "application/json; charset=utf-8", R"({"error":"missing channel or filename"})", is_head);
                }else{
                    std::string channel=trim_soft(it_chan->second);
                    std::string filename=trim_soft(it_file->second);
                    if(channel.empty() || filename.empty()){
                        write_response(res, http::status::bad_request, "application/json; charset=utf-8", R"({"error":"channel and filename required"})", is_head);
                    }else{
                        std::string content_type;
                        if(auto it_ct=qs.find("content_type"); it_ct!=qs.end()){
                            content_type=trim_soft(it_ct->second);
                        }
                        int ttl=g_s3_config.default_ttl;
                        std::string ttl_error;
                        if(auto it_ttl=qs.find("ttl"); it_ttl!=qs.end()){
                            std::string ttl_str=trim_soft(it_ttl->second);
                            if(!ttl_str.empty()){
                                try{
                                    int req_ttl=std::stoi(ttl_str);
                                    if(req_ttl<=0){
                                        ttl_error = R"({"error":"ttl must be positive"})";
                                    }else{
                                        ttl=std::min(req_ttl, g_s3_config.default_ttl);
                                    }
                                }catch(...){
                                    ttl_error = R"({"error":"invalid ttl"})";
                                }
                            }
                        }

                        if(!ttl_error.empty()){
                            write_response(res, http::status::bad_request, "application/json; charset=utf-8", ttl_error, is_head);
                        }else{
                            std::time_t now = std::time(nullptr);
                            std::tm tm = gmtime_utc(now);
                            char date_stamp[9];
                            char amz_date[17];
                            std::strftime(date_stamp, sizeof(date_stamp), "%Y%m%d", &tm);
                            std::strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", &tm);
                            std::string key = attachment_object_key(channel, filename);
                            std::string put_url = s3_presign_url(g_s3_config, "PUT", key, ttl, amz_date, date_stamp);
                            if(put_url.empty()){
                                write_response(res, http::status::internal_server_error, "application/json; charset=utf-8", R"({"error":"presign failed"})", is_head);
                            }else{
                                int short_ttl = std::min(60, std::max(1, g_s3_config.default_ttl));
                                short_ttl = std::min(short_ttl, ttl);
                                if (short_ttl <= 0) short_ttl = 60;
                                std::string get_url;
                                std::string public_url;
                                if(!g_s3_config.public_base_url.empty()){
                                    public_url = g_s3_config.public_base_url + "/" + key;
                                }else{
                                    get_url = s3_presign_url(g_s3_config, "GET", key, short_ttl, amz_date, date_stamp);
                                }

                                std::ostringstream js;
                                js<<"{\"method\":\"PUT\",\"url\":\""<<json_escape(put_url)
                                  <<"\",\"expires_in\":"<<ttl;
                                if(!content_type.empty()){
                                    js<<",\"headers\":{\"Content-Type\":\""<<json_escape(content_type)<<"\"}";
                                }
                                js<<",\"key\":\""<<json_escape(key)<<"\"";
                                if(!public_url.empty()){
                                    js<<",\"public_url\":\""<<json_escape(public_url)<<"\"";
                                }else if(!get_url.empty()){
                                    js<<",\"get_url\":\""<<json_escape(get_url)<<"\"";
                                }
                                js<<"}";

                                res.set(http::field::access_control_allow_origin, "*");
                                write_response(res, http::status::ok, "application/json; charset=utf-8", js.str(), is_head);
                            }
                        }
                    }
                }
            }
        }
        else if ((is_get||is_head) && path=="/api/attachments/confirm") {
            if(get_env("ENABLE_DEV_TOKEN","0")!="1"){
                write_response(res, http::status::not_found, "application/json; charset=utf-8", R"({"error":"not enabled"})", is_head);
            } else {
                auto qs=parse_qs(target);
                auto it_chan=qs.find("channel");
                auto it_user=qs.find("user");
                auto it_key =qs.find("key");
                if(it_chan==qs.end() || it_user==qs.end() || it_key==qs.end()){
                    write_response(res, http::status::bad_request, "application/json; charset=utf-8", R"({"error":"missing channel|user|key"})", is_head);
                } else {
                    std::string channel = trim_soft(it_chan->second);
                    std::string user    = trim_soft(it_user->second);
                    std::string key     = trim_soft(it_key->second);
                    if(channel.empty() || user.empty() || key.empty()){
                        write_response(res, http::status::bad_request, "application/json; charset=utf-8", R"({"error":"channel,user,key required"})", is_head);
                    } else if(!is_valid_attachment_key(key)){
                        write_response(res, http::status::bad_request, "application/json; charset=utf-8", R"({"error":"invalid key"})", is_head);
                    } else if(g_s3_config.public_base_url.empty() && !g_s3_config.is_configured()){
                        write_response(res, http::status::service_unavailable, "application/json; charset=utf-8", R"({"error":"s3 not configured"})", is_head);
                    } else {
                        std::string url = s3_object_url(g_s3_config, key);
                        if(url.empty()){
                            write_response(res, http::status::internal_server_error, "application/json; charset=utf-8", R"({"error":"url build failed"})", is_head);
                        } else {
                            try{
                                std::string conn="host="+get_env("PGHOST","postgres")+" port="+get_env("PGPORT","5432")+
                                                 " dbname="+get_env("PGDATABASE","bcord")+" user="+get_env("PGUSER","bcord")+
                                                 " password="+get_env("PGPASSWORD","change_me");
                                pqxx::connection c(conn);
                                long long chan_id = ensure_channel_id(c, channel);
                                {
                                    pqxx::work w(c);
                                    w.exec_params("INSERT INTO messages(channel_id,sender,body) VALUES ($1,$2,$3)", chan_id, user, url);
                                    w.commit();
                                }
                                std::ostringstream js;
                                js<<"{\"ok\":true,\"url\":\""<<json_escape(url)<<"\",\"key\":\""<<json_escape(key)<<"\"}";
                                res.set(http::field::access_control_allow_origin, "*");
                                write_response(res, http::status::ok, "application/json; charset=utf-8", js.str(), is_head);
                            }catch(const std::exception& e){
                                write_response(res, http::status::internal_server_error, "application/json; charset=utf-8", std::string("{\"error\":\"")+json_escape(e.what())+"\"}", is_head);
                            }catch(...){
                                write_response(res, http::status::internal_server_error, "application/json; charset=utf-8", R"({"error":"unknown"})", is_head);
                            }
                        }
                    }
                }
            }
        }
        
        // --- History (pagination + soft-delete) ---
        else if ((is_get||is_head) && path=="/api/history") {
            auto qs=parse_qs(target);
            std::string channel=qs.count("channel")?qs["channel"]:"general";
            int limit=50; if(qs.count("limit")){ try{ limit=std::stoi(qs["limit"]); }catch(...){} }
            if(limit<1)limit=1; if(limit>200)limit=200;
            long long before_id=-1, since_id=-1;
            if(qs.count("before_id")){ try{ before_id=std::stoll(qs["before_id"]); }catch(...){} }
            if(qs.count("since_id")) { try{ since_id =std::stoll(qs["since_id"]);  }catch(...){} }
            bool include_deleted = (qs.count("include_deleted") && (qs["include_deleted"]=="1"||qs["include_deleted"]=="true"));

            try{
                std::string conn="host="+get_env("PGHOST","postgres")+" port="+get_env("PGPORT","5432")+
                                 " dbname="+get_env("PGDATABASE","bcord")+" user="+get_env("PGUSER","bcord")+
                                 " password="+get_env("PGPASSWORD","change_me");
                pqxx::connection c(conn); pqxx::work w(c);
                std::string delf = include_deleted? "" : " AND m.deleted_at IS NULL ";
                pqxx::result rows;
                if(before_id>0){
                    rows=w.exec_params(("SELECT m.id,m.sender,m.body,m.created_at, m.deleted_at IS NOT NULL AS deleted, m.edited_at IS NOT NULL AS edited "
                                        "FROM messages m JOIN channels c ON c.id=m.channel_id "
                                        "WHERE c.name=$1 AND m.id<$2 "+delf+" ORDER BY m.id DESC LIMIT $3"),
                                       channel,before_id,limit);
                }else if(since_id>0){
                    rows=w.exec_params(("SELECT m.id,m.sender,m.body,m.created_at, m.deleted_at IS NOT NULL AS deleted, m.edited_at IS NOT NULL AS edited "
                                        "FROM messages m JOIN channels c ON c.id=m.channel_id "
                                        "WHERE c.name=$1 AND m.id>$2 "+delf+" ORDER BY m.id ASC  LIMIT $3"),
                                       channel,since_id,limit);
                }else{
                    rows=w.exec_params(("SELECT m.id,m.sender,m.body,m.created_at, m.deleted_at IS NOT NULL AS deleted, m.edited_at IS NOT NULL AS edited "
                                        "FROM messages m JOIN channels c ON c.id=m.channel_id "
                                        "WHERE c.name=$1 "+delf+" ORDER BY m.id DESC LIMIT $2"),
                                       channel,limit);
                }
                std::ostringstream js; js<<"[";
                bool first=true;
                for(auto const& r: rows){
                    if(!first) js<<","; first=false;
                    std::string sender=r[1].c_str(), body=r[2].c_str();
                    bool deleted=r[4].as<bool>(), edited=r[5].as<bool>();
                    if(deleted && !include_deleted) continue;
                    if(deleted) body.clear();
                    js<<"{\"id\":"<<r[0].as<long long>()<<",\"sender\":\""<<json_escape(sender)
                      <<"\",\"body\":\""<<json_escape(body)<<"\",\"created_at\":\""<<r[3].c_str()
                      <<"\",\"deleted\":"<<(deleted?"true":"false")<<",\"edited\":"<<(edited?"true":"false")<<"}";
                }
                js<<"]";
                write_response(res, http::status::ok, "application/json; charset=utf-8", js.str(), is_head);
            }catch(const std::exception& e){
                write_response(res, http::status::internal_server_error, "application/json; charset=utf-8",
                               std::string("{\"error\":\"")+json_escape(e.what())+"\"}", is_head);
            }
        }

        // --- Presence snapshot ---
        else if ((is_get||is_head) && path=="/api/presence") {
            auto qs=parse_qs(target); std::string channel=qs.count("channel")?qs["channel"]:"general";
            try{
                std::string conn="host="+get_env("PGHOST","postgres")+" port="+get_env("PGPORT","5432")+
                                 " dbname="+get_env("PGDATABASE","bcord")+" user="+get_env("PGUSER","bcord")+
                                 " password="+get_env("PGPASSWORD","change_me");
                pqxx::connection c(conn); pqxx::work w(c);
                auto rows=w.exec_params("SELECT p.user_name,p.last_seen,(p.last_seen >= now()-interval '30 seconds') AS online "
                                        "FROM presence p JOIN channels c ON c.id=p.channel_id "
                                        "WHERE c.name=$1 AND p.last_seen>now()-interval '5 minutes' ORDER BY p.user_name", channel);
                std::ostringstream js; js<<"[";
                bool first=true; for(auto const& r: rows){
                    if(!first) js<<","; first=false;
                    js<<"{\"user\":\""<<json_escape(r[0].c_str())<<"\",\"last_seen\":\""<<r[1].c_str()
                      <<"\",\"online\":"<<(r[2].as<bool>()?"true":"false")<<"}";
                }
                js<<"]";
                write_response(res, http::status::ok, "application/json; charset=utf-8", js.str(), is_head);
            }catch(const std::exception& e){
                write_response(res, http::status::internal_server_error, "application/json; charset=utf-8",
                               std::string("{\"error\":\"")+json_escape(e.what())+"\"}", is_head);
            }
        }

        // --- DEV: mint {token, ts} for WS ---
        else if ((is_get||is_head) && path=="/api/login") {
            if(get_env("ENABLE_DEV_TOKEN","0")!="1"){
                write_response(res, http::status::not_found, "application/json; charset=utf-8", R"({"error":"not enabled"})", is_head);
            }else{
                auto qs=parse_qs(target); auto it_user=qs.find("user"), it_chan=qs.find("channel");
                if(it_user==qs.end() || it_chan==qs.end()){
                    write_response(res, http::status::bad_request, "application/json; charset=utf-8", R"({"error":"missing user or channel"})", is_head);
                }else{
                    const std::string secret=get_env("WS_SECRET","");
                    if(secret.empty()){
                        write_response(res, http::status::internal_server_error, "application/json; charset=utf-8", R"({"error":"WS_SECRET not set"})", is_head);
                    }else{
                        std::uint64_t now_s=(std::uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
                        std::string ts=std::to_string(now_s);
                        std::string token=hmac_sha256_hex(secret, it_user->second+"|"+it_chan->second+"|"+ts);
                        std::ostringstream js; js<<"{\"token\":\""<<token<<"\",\"ts\":"<<ts<<"}";
                        write_response(res, http::status::ok, "application/json; charset=utf-8", js.str(), is_head);
                    }
                }
            }
        }

        // --- DEV: sign message ops (delete/edit) ---
        else if ((is_get||is_head) && path=="/api/adminsig_msg") {
            if(get_env("ENABLE_DEV_TOKEN","0")!="1"){
                write_response(res, http::status::not_found, "application/json; charset=utf-8", R"({"error":"not enabled"})", is_head);
            }else{
                auto qs=parse_qs(target);
                std::string op   = qs.count("op")  ? qs["op"]  : "";
                std::string id   = qs.count("id")  ? qs["id"]  : "";
                std::string user = qs.count("user")? qs["user"]: "";
                std::string body = qs.count("body")? qs["body"]: "";
                if (op.empty()||id.empty()||user.empty()||(op=="edit"&&body.empty())){
                    write_response(res, http::status::bad_request, "application/json; charset=utf-8", R"({"error":"missing op|id|user[|body]"})", is_head);
                } else if (op!="delete" && op!="edit"){
                    write_response(res, http::status::bad_request, "application/json; charset=utf-8", R"({"error":"op must be delete or edit"})", is_head);
                } else {
                    const std::string secret=get_env("WS_SECRET","");
                    if(secret.empty()){
                        write_response(res, http::status::internal_server_error, "application/json; charset=utf-8", R"({"error":"WS_SECRET not set"})", is_head);
                    } else {
                        std::uint64_t now_s=(std::uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
                        std::string ts=std::to_string(now_s);
                        std::string sig = (op=="delete")
                            ? hmac_sha256_hex(secret, "delete|"+id+"|"+user+"|"+ts)
                            : hmac_sha256_hex(secret, "edit|"+id+"|"+user+"|"+body+"|"+ts);
                        std::ostringstream js; js<<"{\"sig\":\""<<sig<<"\",\"ts\":"<<ts<<"}";
                        write_response(res, http::status::ok, "application/json; charset=utf-8", js.str(), is_head);
                    }
                }
            }
        }

        // --- DEV: verify provided signature (debug helper) ---
        else if ((is_get||is_head) && path=="/api/adminsig_verify") {
            if(get_env("ENABLE_DEV_TOKEN","0")!="1"){
                write_response(res, http::status::not_found, "application/json; charset=utf-8", R"({"error":"not enabled"})", is_head);
            }else{
                auto qs=parse_qs(target);
                std::string op   = qs.count("op")  ? qs["op"]  : "";
                std::string id   = qs.count("id")  ? qs["id"]  : "";
                std::string user = qs.count("user")? qs["user"]: "";
                std::string body = qs.count("body")? qs["body"]: "";
                std::string ts   = qs.count("ts")  ? qs["ts"]  : "";
                std::string sig  = qs.count("sig") ? qs["sig"] : "";
                const std::string secret=get_env("WS_SECRET","");
                if(secret.empty()){
                    write_response(res, http::status::internal_server_error, "application/json; charset=utf-8", R"({"error":"WS_SECRET not set"})", is_head);
                } else if (op.empty()||id.empty()||user.empty()||ts.empty()||sig.empty()){
                    write_response(res, http::status::bad_request, "application/json; charset=utf-8", R"({"error":"missing op|id|user|ts|sig"})", is_head);
                } else {
                    std::string msg_can = (op=="edit")
                        ? "edit|"+id+"|"+user+"|"+body+"|"+ts
                        : "delete|"+id+"|"+user+"|"+ts;
                    std::string mac_can = hmac_sha256_hex(secret, msg_can);
                    std::string msg_leg, mac_leg;
                    if (op=="edit") {
                        msg_leg = "edit|"+id+"|"+user+"|"+ts+"|"+body;
                        mac_leg = hmac_sha256_hex(secret, msg_leg);
                    }
                    bool ok = hex_ci_equal(mac_can, sig) || (!msg_leg.empty() && hex_ci_equal(mac_leg, sig));
                    std::ostringstream js;
                    js<<"{\"ok\":"<<(ok?"true":"false")<<",\"expected\":{\"canonical\":\""<<mac_can<<"\"";
                    if(!msg_leg.empty()) js<<",\"legacy\":\""<<mac_leg<<"\"";
                    js<<"},\"message\":{\"canonical\":\""<<json_escape(msg_can)<<"\"";
                    if(!msg_leg.empty()) js<<",\"legacy\":\""<<json_escape(msg_leg)<<"\"}}";
                    write_response(res, http::status::ok, "application/json; charset=utf-8", js.str(), is_head);
                }
            }
        }

        // --- DEV: sign add_member (exact path to avoid shadowing) ---
        else if ((is_get||is_head) && path=="/api/adminsig") {
            if(get_env("ENABLE_DEV_TOKEN","0")!="1"){
                write_response(res, http::status::not_found, "application/json; charset=utf-8", R"({"error":"not enabled"})", is_head);
            }else{
                auto qs=parse_qs(target);
                auto it_user=qs.find("user"), it_chan=qs.find("channel"), it_role=qs.find("role");
                std::string role=(it_role==qs.end()||it_role->second.empty())?"owner":it_role->second;
                if(it_user==qs.end() || it_chan==qs.end()){
                    write_response(res, http::status::bad_request, "application/json; charset=utf-8", R"({"error":"missing user or channel"})", is_head);
                }else{
                    const std::string secret=get_env("WS_SECRET","");
                    if(secret.empty()){
                        write_response(res, http::status::internal_server_error, "application/json; charset=utf-8", R"({"error":"WS_SECRET not set"})", is_head);
                    }else{
                        std::uint64_t now_s=(std::uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count();
                        std::string ts=std::to_string(now_s);
                        std::string sig=hmac_sha256_hex(secret, "add_member|"+it_user->second+"|"+it_chan->second+"|"+role+"|"+ts);
                        std::ostringstream js; js<<"{\"sig\":\""<<sig<<"\",\"ts\":"<<ts<<"}";
                        write_response(res, http::status::ok, "application/json; charset=utf-8", js.str(), is_head);
                    }
                }
            }
        }

        // --- Signed add_member ---
        else if ((is_get||is_head) && path=="/api/channels/add_member") {
            auto qs=parse_qs(target);
            auto it_user=qs.find("user"), it_chan=qs.find("channel"), it_role=qs.find("role"),
                 it_ts=qs.find("ts"), it_sig=qs.find("sig");
            std::string role=(it_role==qs.end()||it_role->second.empty())?"member":it_role->second;
            if(it_user==qs.end()||it_chan==qs.end()||it_ts==qs.end()||it_sig==qs.end()){
                write_response(res, http::status::bad_request, "application/json; charset=utf-8", R"({"error":"missing user|channel|ts|sig"})", is_head);
            }else{
                const std::string secret=get_env("WS_SECRET","");
                if(!verify_admin_sig(secret, it_user->second, it_chan->second, role, it_ts->second, it_sig->second)){
                    write_response(res, http::status::unauthorized, "application/json; charset=utf-8", R"({"error":"invalid admin signature"})", is_head);
                }else{
                    try{
                        std::string conn="host="+get_env("PGHOST","postgres")+" port="+get_env("PGPORT","5432")+
                                         " dbname="+get_env("PGDATABASE","bcord")+" user="+get_env("PGUSER","bcord")+
                                         " password="+get_env("PGPASSWORD","change_me");
                        pqxx::connection c(conn); pqxx::work w(c);
                        auto row=w.exec_params1("INSERT INTO channels(name) VALUES ($1) ON CONFLICT (name) DO UPDATE SET name=EXCLUDED.name RETURNING id", it_chan->second);
                        long long cid=row[0].as<long long>();
                        w.exec_params("INSERT INTO channel_members(channel_id,user_name,role) VALUES ($1,$2,$3) "
                                      "ON CONFLICT (channel_id,user_name) DO UPDATE SET role=EXCLUDED.role, added_at=now()",
                                      cid, it_user->second, role);
                        w.commit();
                        std::ostringstream js; js<<"{\"ok\":true,\"channel_id\":"<<cid<<",\"user\":\""<<json_escape(it_user->second)<<"\",\"role\":\""<<json_escape(role)<<"\"}";
                        write_response(res, http::status::ok, "application/json; charset=utf-8", js.str(), is_head);
                    }catch(const std::exception& e){
                        write_response(res, http::status::internal_server_error, "application/json; charset=utf-8",
                                       std::string("{\"error\":\"")+json_escape(e.what())+"\"}", is_head);
                    }
                }
            }
        }

        // --- Signed delete ---
        else if ((is_get||is_head) && path=="/api/messages/delete") {
            auto qs=parse_qs(target);
            std::string id=qs.count("id")?qs["id"]:"", user=qs.count("user")?qs["user"]:"", ts=qs.count("ts")?qs["ts"]:"", sig=qs.count("sig")?qs["sig"]:"";
            const std::string secret=get_env("WS_SECRET","");
            if(!verify_op_sig(secret, "delete", {id,user}, ts, sig)){
                write_response(res, http::status::unauthorized, "application/json; charset=utf-8", R"({"error":"invalid signature"})", is_head);
            }else{
                try{
                    std::string conn="host="+get_env("PGHOST","postgres")+" port="+get_env("PGPORT","5432")+
                                     " dbname="+get_env("PGDATABASE","bcord")+" user="+get_env("PGUSER","bcord")+
                                     " password="+get_env("PGPASSWORD","change_me");
                    pqxx::connection c(conn); pqxx::work w(c);
                    auto r=w.exec_params("UPDATE messages SET deleted_at=now(), deleted_by=$2 WHERE id=$1 RETURNING id", id, user);
                    if(r.empty()) write_response(res, http::status::not_found, "application/json; charset=utf-8", R"({"error":"message not found"})", is_head);
                    else          write_response(res, http::status::ok,       "application/json; charset=utf-8", R"({"ok":true})", is_head);
                    w.commit();
                }catch(const std::exception& e){
                    write_response(res, http::status::internal_server_error, "application/json; charset=utf-8",
                                   std::string("{\"error\":\"")+json_escape(e.what())+"\"}", is_head);
                }
            }
        }

        // --- Signed edit ---
        else if ((is_get||is_head) && path=="/api/messages/edit") {
            auto qs=parse_qs(target);
            std::string id=qs.count("id")?qs["id"]:"", user=qs.count("user")?qs["user"]:"", body=qs.count("body")?qs["body"]:"", ts=qs.count("ts")?qs["ts"]:"", sig=qs.count("sig")?qs["sig"]:"";
            const std::string secret=get_env("WS_SECRET","");
            if(body.empty() || !verify_op_sig(secret, "edit", {id,user,body}, ts, sig)){
                write_response(res, http::status::unauthorized, "application/json; charset=utf-8", R"({"error":"invalid signature or empty body"})", is_head);
            }else{
                try{
                    std::string conn="host="+get_env("PGHOST","postgres")+" port="+get_env("PGPORT","5432")+
                                     " dbname="+get_env("PGDATABASE","bcord")+" user="+get_env("PGUSER","bcord")+
                                     " password="+get_env("PGPASSWORD","change_me");
                    pqxx::connection c(conn); pqxx::work w(c);
                    auto r=w.exec_params("UPDATE messages SET body=$2, edited_at=now(), edited_by=$3 WHERE id=$1 AND deleted_at IS NULL RETURNING id",
                                         id, body, user);
                    if(r.empty()) write_response(res, http::status::not_found, "application/json; charset=utf-8", R"({"error":"message not found or already deleted"})", is_head);
                    else          write_response(res, http::status::ok,       "application/json; charset=utf-8", R"({"ok":true})", is_head);
                    w.commit();
                }catch(const std::exception& e){
                    write_response(res, http::status::internal_server_error, "application/json; charset=utf-8",
                                   std::string("{\"error\":\"")+json_escape(e.what())+"\"}", is_head);
                }
            }
        }

        // --- Readiness & health ---
        else if ((is_get||is_head) && path=="/api/ready") {
            if (g_draining.load(std::memory_order_relaxed)) {
                write_response(res,
                               http::status::service_unavailable,
                               "application/json; charset=utf-8",
                               R"({"ready":false,"draining":true})",
                               is_head);
            } else {
                bool db_ok = false;
                try {
                    std::string conn = "host=" + get_env("PGHOST","postgres") +
                                       " port=" + get_env("PGPORT","5432") +
                                       " dbname=" + get_env("PGDATABASE","bcord") +
                                       " user=" + get_env("PGUSER","bcord") +
                                       " password=" + get_env("PGPASSWORD","change_me");
                    pqxx::connection c(conn);
                    pqxx::work w(c);
                    (void)w.exec1("SELECT 1");
                    db_ok = true;
                } catch (...) {
                    db_ok = false;
                }

                bool redis_conn = g_redis_sub_connected.load(std::memory_order_relaxed);
                std::int64_t last = g_redis_sub_last_ok.load(std::memory_order_relaxed);
                std::int64_t now_s = unix_now_seconds();
                bool redis_fresh = false;
                if (redis_conn && last > 0 && now_s >= last) {
                    redis_fresh = (now_s - last) <= 300;
                }
                if (redis_conn && !redis_fresh) {
                    const std::string redis_host = get_env("REDIS_HOST", "redis");
                    const std::string redis_port = get_env("REDIS_PORT", "6379");
                    std::string raw_reply;
                    if (redis_ping_ok(redis_host, redis_port, raw_reply)) {
                        redis_fresh = true;
                        std::int64_t refreshed = unix_now_seconds();
                        g_redis_sub_last_ok.store(refreshed, std::memory_order_relaxed);
                        now_s = refreshed;
                    }
                }
                bool redis_ok = redis_conn && redis_fresh;
                bool ready = db_ok && redis_ok;

                std::ostringstream js;
                js << "{\"ready\":" << (ready?"true":"false")
                   << ",\"db\":" << (db_ok?"true":"false")
                   << ",\"redis_sub\":" << (redis_ok?"true":"false")
                   << "}";

                write_response(res,
                               ready ? http::status::ok : http::status::service_unavailable,
                               "application/json; charset=utf-8",
                               js.str(),
                               is_head);
            }
        }
        else if ((is_get||is_head) && (path=="/health" || path=="/api/health")) {
            write_response(res, http::status::ok, "text/plain; charset=utf-8", "ok", is_head);
        }
        else if ((is_get||is_head) && (path=="/" || path=="/api/")) {
            static constexpr const char* HTML="<!doctype html><title>BCord backend</title><h1>BCord backend running</h1>";
            write_response(res, http::status::ok, "text/html; charset=utf-8", HTML, is_head);
        }
        else {
            write_response(res, http::status::not_found, "text/plain; charset=utf-8", "not found", is_head);
        }

        http::write(sock, res);
        beast::error_code ec; sock.shutdown(tcp::socket::shutdown_send, ec);
    } catch(const std::exception& e) { std::cerr<<"[session] "<<e.what()<<"\n"; }
}

// ---------------------------- main() ----------------------------------------

int main() {
    try{
        std::string bind_addr=get_env("BIND_ADDR","0.0.0.0");
        unsigned short port=(unsigned short)std::stoi(get_env("PORT","9000"));
        std::signal(SIGTERM, handle_shutdown_signal);
        std::signal(SIGINT, handle_shutdown_signal);
        std::cout << "[redis-sub] thread starting" << std::endl;
        std::thread(redis_subscriber_loop).detach();
        net::io_context ioc{1};
        tcp::acceptor acc{ioc, {net::ip::make_address(bind_addr), port}};
        std::cout<<"[start] listening on "<<bind_addr<<":"<<port<<std::endl;
        for(;;){ tcp::socket sock{ioc}; acc.accept(sock); std::thread(&handle_session, std::move(sock)).detach(); }
    }catch(const std::exception& e){ std::cerr<<"[fatal] "<<e.what()<<"\n"; return 1; }
}

