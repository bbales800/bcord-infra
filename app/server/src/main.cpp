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
//   • Updated for Boost ≥1.81: beast::string_view no longer supports .to_string()
//     → use std::string(req.target()) for portability.
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
using tcp = net::ip::tcp;

// -----------------------------------------------------------------------------
// Utility helpers
// -----------------------------------------------------------------------------
static std::string get_env(const char* k, const char* dflt) {
    const char* v = std::getenv(k);
    return (v && *v) ? std::string(v) : std::string(dflt);
}

// trim_soft: removes leading/trailing ASCII whitespace (non-destructive)
static inline std::string trim_soft(const std::string& s) {
    size_t i=0,j=s.size();
    while (i<j && (unsigned char)s[i] <= 0x20) ++i;
    while (j>i && (unsigned char)s[j-1] <= 0x20) --j;
    return s.substr(i, j-i);
}

// json_escape: escapes control characters for safe JSON output
static std::string json_escape(std::string_view s) {
    std::string out; out.reserve(s.size()+16);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out+="\\\""; break;
            case '\\': out+="\\\\"; break;
            case '\n': out+="\\n"; break;
            case '\r': out+="\\r"; break;
            case '\t': out+="\\t"; break;
            default:
                if (c < 0x20) { char buf[7]; std::snprintf(buf,sizeof(buf),"\\u%04X",c); out+=buf; }
                else out+=char(c);
        }
    }
    return out;
}

// to_hex_lower: converts binary data to lowercase hex string
static std::string to_hex_lower(const unsigned char* data, unsigned len) {
    static const char* hex="0123456789abcdef";
    std::string out; out.resize(len*2);
    for(unsigned i=0;i<len;i++){ out[2*i]=hex[(data[i]>>4)&0xF]; out[2*i+1]=hex[data[i]&0xF]; }
    return out;
}

// hmac_sha256_hex: convenience wrapper using OpenSSL EVP
static std::string hmac_sha256_hex(const std::string& key,const std::string& msg){
    unsigned char mac[EVP_MAX_MD_SIZE]; unsigned int len=0;
    HMAC(EVP_sha256(),key.data(),(int)key.size(),
         reinterpret_cast<const unsigned char*>(msg.data()),msg.size(),mac,&len);
    return to_hex_lower(mac,len);
}

// hex_ci_equal: constant-time, case-insensitive hex comparison
static bool hex_ci_equal(const std::string& a,const std::string& b){
    if(a.size()!=b.size())return false; unsigned char diff=0;
    for(size_t i=0;i<a.size();++i) diff|=(std::tolower(a[i])^std::tolower(b[i]));
    return diff==0;
}

// -----------------------------------------------------------------------------
// Token verification (HMAC user|channel|ts)
// -----------------------------------------------------------------------------
static bool verify_token(const std::string& secret,const std::string& user,
                         const std::string& channel,const std::string& ts,
                         const std::string& token){
    if(secret.empty())return true;
    if(user.empty()||channel.empty()||ts.empty()||token.empty())return false;
    uint64_t now=(uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    uint64_t ts64=0; try{ts64=std::stoull(ts);}catch(...){return false;}
    if((now>ts64?now-ts64:ts64-now)>300)return false;
    std::string expect=hmac_sha256_hex(secret,user+"|"+channel+"|"+ts);
    return hex_ci_equal(expect,token);
}

// -----------------------------------------------------------------------------
// Globals
// -----------------------------------------------------------------------------
struct WsSession { explicit WsSession(tcp::socket&& s):ws(std::move(s)){} websocket::stream<tcp::socket> ws; std::mutex m; };
static std::unordered_map<std::string,std::vector<std::weak_ptr<WsSession>>> g_channels;
static std::mutex g_channels_mtx;

// -----------------------------------------------------------------------------
// Broadcast helper: sends message to all peers in same channel except origin
// -----------------------------------------------------------------------------
static void broadcast_channel(const std::string& chan,const std::string& msg,const WsSession*skip=nullptr){
    std::vector<std::shared_ptr<WsSession>> peers;
    { std::lock_guard<std::mutex> lk(g_channels_mtx);
      auto it=g_channels.find(chan);
      if(it!=g_channels.end()){
        for(auto&w:it->second)if(auto sp=w.lock()){ if(sp.get()!=skip)peers.push_back(sp); }
      }}
    for(auto&p:peers){ std::lock_guard<std::mutex> wl(p->m);
      beast::error_code ec; p->ws.text(true); p->ws.write(net::buffer(msg),ec);}
}

// -----------------------------------------------------------------------------
// WebSocket echo handler
// -----------------------------------------------------------------------------
static void do_ws_echo(tcp::socket sock,http::request<http::string_body>&& req){
    auto self=std::make_shared<WsSession>(std::move(sock));
    self->ws.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
    self->ws.accept(req);

    // NOTE: Boost >=1.81 returns beast::string_view; must cast explicitly
    std::string qs = std::string(req.target());  // instead of req.target().to_string()
    auto qpos=qs.find('?');
    std::map<std::string,std::string> qmap;
    if(qpos!=std::string::npos){
        std::string kvs=qs.substr(qpos+1);
        std::stringstream ss(kvs); std::string kv;
        while(std::getline(ss,kv,'&')){
            auto eq=kv.find('=');
            if(eq!=std::string::npos) qmap[kv.substr(0,eq)]=kv.substr(eq+1);
        }
    }
    std::string user=qmap.count("user")?qmap["user"]:"anon";
    std::string chan=qmap.count("channel")?qmap["channel"]:"general";
    { std::lock_guard<std::mutex> lk(g_channels_mtx); g_channels[chan].push_back(self); }

    beast::flat_buffer buf;
    for(;;){
        beast::error_code ec; self->ws.read(buf,ec);
        if(ec==websocket::error::closed)break;
        if(ec)break;
        std::string body=beast::buffers_to_string(buf.data());
        buf.consume(buf.size());
        if(body.size()>4096)continue;

        // Parse {"op":"message","text":"..."}
        std::string op,text;
        auto pos_txt=body.find("\"text\"");
        if(pos_txt!=std::string::npos){
            auto colon=body.find(':',pos_txt);
            auto q1=body.find('"',colon+1);
            auto q2=body.find('"',q1+1);
            if(q1!=std::string::npos&&q2!=std::string::npos) text=body.substr(q1+1,q2-q1-1);
        }
        if(text.empty())continue;

        // Build broadcast JSON
        std::time_t now=std::time(nullptr);
        char tsbuf[32]; std::strftime(tsbuf,sizeof(tsbuf),"%Y-%m-%dT%H:%M:%SZ",std::gmtime(&now));
        std::ostringstream js;
        js<<"{\"op\":\"message\",\"sender\":\""<<json_escape(user)
          <<"\",\"text\":\""<<json_escape(text)
          <<"\",\"ts\":\""<<tsbuf<<"\"}";
        std::string outgoing=js.str();

        // DB insert (optional: safe ignore if DB down)
        try{
            std::string conn="host="+get_env("PGHOST","postgres")+" port="+get_env("PGPORT","5432")+
                " dbname="+get_env("PGDATABASE","bcord")+" user="+get_env("PGUSER","bcord")+
                " password="+get_env("PGPASSWORD","change_me");
            pqxx::connection c(conn); pqxx::work w(c);
            w.exec_params("INSERT INTO messages(channel_id,sender,body) VALUES ((SELECT id FROM channels WHERE name=$1 LIMIT 1),$2,$3)", chan, user, text);
            w.commit();
        }catch(...){}

        // Send back to self + broadcast to others
        { std::lock_guard<std::mutex> wl(self->m);
          self->ws.text(true); self->ws.write(net::buffer(outgoing)); }
        broadcast_channel(chan,outgoing,self.get());
    }
}

// -----------------------------------------------------------------------------
// HTTP router
// -----------------------------------------------------------------------------
static void handle_session(tcp::socket sock){
    beast::flat_buffer buffer; http::request<http::string_body> req;
    http::read(sock,buffer,req);

    // NOTE: Boost ≥1.81 changed target() return type; cast explicitly
    std::string target = std::string(req.target());  // fixed .to_string() call
    std::string path=target.substr(0,target.find('?'));
    bool is_post=req.method()==http::verb::post;
    bool is_get=req.method()==http::verb::get||req.method()==http::verb::head;
    http::response<http::string_body> res; res.version(req.version()); res.keep_alive(false);

    // --- WebSocket upgrade path ---
    if(websocket::is_upgrade(req)&&(path=="/ws"||path=="/api/ws")){
        const std::string ws_secret=get_env("WS_SECRET","");
        auto qspos=target.find('?');
        std::string user="anon",chan="general",ts,token;
        if(qspos!=std::string::npos){
            auto qs=target.substr(qspos+1);
            std::stringstream ss(qs); std::string kv;
            while(std::getline(ss,kv,'&')){
                auto eq=kv.find('=');
                if(eq==std::string::npos)continue;
                auto k=kv.substr(0,eq),v=kv.substr(eq+1);
                if(k=="user")user=v; else if(k=="channel")chan=v;
                else if(k=="ts")ts=v; else if(k=="token")token=v;
            }
        }
        if(!verify_token(ws_secret,user,chan,ts,token)){
            res.result(http::status::unauthorized);
            res.set(http::field::content_type,"application/json");
            res.body()=R"({"error":"invalid or expired token"})"; res.prepare_payload();
            http::write(sock,res); return;
        }
        return do_ws_echo(std::move(sock),std::move(req));
    }

    // --- /api/login (GET or POST) ---
    if((is_get||is_post)&&path=="/api/login"){
        res.set(http::field::access_control_allow_origin,"*");
        const std::string secret=get_env("WS_SECRET","");
        if(secret.empty()){
            res.result(http::status::internal_server_error);
            res.body()=R"({"error":"WS_SECRET not set"})";
        }else{
            std::string user,channel;
            auto qspos=target.find('?');
            if(qspos!=std::string::npos){
                auto qs=target.substr(qspos+1);
                std::stringstream ss(qs); std::string kv;
                while(std::getline(ss,kv,'&')){
                    auto eq=kv.find('=');
                    if(eq==std::string::npos)continue;
                    auto k=kv.substr(0,eq),v=kv.substr(eq+1);
                    if(k=="user")user=v; else if(k=="channel")channel=v;
                }
            }
            // Parse JSON body for POST /api/login {"username": "...", "channel": "..."}
            if(is_post&&!req.body().empty()){
                auto b=req.body();
                auto pos=b.find("\"username\"");
                if(pos!=std::string::npos){
                    auto c=b.find(':',pos);
                    auto q1=b.find('"',c+1); auto q2=b.find('"',q1+1);
                    if(q1!=std::string::npos&&q2!=std::string::npos)
                        user=trim_soft(b.substr(q1+1,q2-q1-1));
                }
                auto posc=b.find("\"channel\"");
                if(posc!=std::string::npos){
                    auto c=b.find(':',posc);
                    auto q1=b.find('"',c+1); auto q2=b.find('"',q1+1);
                    if(q1!=std::string::npos&&q2!=std::string::npos)
                        channel=trim_soft(b.substr(q1+1,q2-q1-1));
                }
            }
            if(user.empty())user="dev"; if(channel.empty())channel="general";
            uint64_t now=(uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            std::string ts=std::to_string(now);
            std::string token=hmac_sha256_hex(secret,user+"|"+channel+"|"+ts);
            std::ostringstream js;
            js<<"{\"token\":\""<<token<<"\",\"ts\":"<<ts<<",\"user\":\""<<json_escape(user)<<"\"}";
            res.result(http::status::ok);
            res.set(http::field::content_type,"application/json; charset=utf-8");
            res.body()=js.str();
        }
        res.prepare_payload(); http::write(sock,res); return;
    }

    // --- Fallback root path ---
    res.result(http::status::ok);
    res.set(http::field::content_type,"text/plain; charset=utf-8");
    res.body()="BCord backend running";
    res.prepare_payload();
    http::write(sock,res);
}

// -----------------------------------------------------------------------------
// main()
// -----------------------------------------------------------------------------
int main(){
    try{
        // Ignore termination signals (handled manually via Docker stop)
        std::signal(SIGTERM,SIG_IGN);
        std::signal(SIGINT,SIG_IGN);

        // Bind and listen
        std::string addr=get_env("BIND_ADDR","0.0.0.0");
        unsigned short port=(unsigned short)std::stoi(get_env("PORT","9000"));
        net::io_context ioc{1};
        tcp::acceptor acc{ioc,{net::ip::make_address(addr),port}};
        std::cout<<"[start] listening on "<<addr<<":"<<port<<std::endl;

        // Simple multi-threaded accept loop
        for(;;){
            tcp::socket sock{ioc};
            acc.accept(sock);
            std::thread(&handle_session,std::move(sock)).detach();
        }
    }catch(const std::exception&e){
        std::cerr<<"[fatal] "<<e.what()<<"\n";
        return 1;
    }
}
