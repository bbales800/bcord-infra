// ============================================================================
// BCord Backend — Boost.Beast HTTP + WebSocket Server (Stable + JSON Ready)
// ----------------------------------------------------------------------------
// • /api/login → issues HMAC(user|channel|ts) token + CORS
// • /api/history → returns channel messages in JSON
// • /ws → real-time chat broadcast + DB insert
// • Compatible with Boost 1.83 (Ubuntu 24.04) and Caddy reverse proxy
// ============================================================================

#include <cstdlib>
#include <string>
#include <string_view>
#include <iostream>
#include <thread>
#include <sstream>
#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <random>
#include <csignal>
#include <cctype>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <pqxx/pqxx>
#include <openssl/hmac.h>
#include <openssl/evp.h>

namespace beast = boost::beast;
namespace http  = beast::http;
namespace net   = boost::asio;
namespace websocket = beast::websocket;
using tcp = net::ip::tcp;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------
static std::string get_env(const char* k,const char* d){
    const char* v=getenv(k); return (v&&*v)?v:d;
}
static inline std::string trim_soft(const std::string& s){
    size_t i=0,j=s.size(); while(i<j&&(unsigned char)s[i]<=0x20)++i;
    while(j>i&&(unsigned char)s[j-1]<=0x20)--j; return s.substr(i,j-i);
}
static std::string json_escape(std::string_view s){
    std::string o; o.reserve(s.size()+16);
    for(unsigned char c:s){
        switch(c){ case '"':o+="\\\"";break;case '\\':o+="\\\\";break;
        case '\n':o+="\\n";break;case '\r':o+="\\r";break;case '\t':o+="\\t";break;
        default: if(c<0x20){char b[7];std::snprintf(b,sizeof(b),"\\u%04X",c);o+=b;}else o+=c;}
    } return o;
}
static std::string to_hex_lower(const unsigned char* d,unsigned n){
    static const char* h="0123456789abcdef"; std::string o; o.resize(n*2);
    for(unsigned i=0;i<n;i++){o[2*i]=h[(d[i]>>4)&0xF];o[2*i+1]=h[d[i]&0xF];}
    return o;
}
static std::string hmac_sha256_hex(const std::string& key,const std::string& msg){
    unsigned char mac[EVP_MAX_MD_SIZE]; unsigned len=0;
    HMAC(EVP_sha256(),key.data(),(int)key.size(),
         reinterpret_cast<const unsigned char*>(msg.data()),msg.size(),mac,&len);
    return to_hex_lower(mac,len);
}
static bool hex_ci_equal(const std::string&a,const std::string&b){
    if(a.size()!=b.size())return false; unsigned char diff=0;
    for(size_t i=0;i<a.size();++i)diff|=(std::tolower(a[i])^std::tolower(b[i]));
    return diff==0;
}
static bool verify_token(const std::string&sec,const std::string&user,const std::string&chan,
                         const std::string&ts,const std::string&tok){
    if(sec.empty())return true;
    if(user.empty()||chan.empty()||ts.empty()||tok.empty())return false;
    uint64_t now=std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    uint64_t t64=0; try{t64=std::stoull(ts);}catch(...){return false;}
    if((now>t64?now-t64:t64-now)>300)return false;
    return hex_ci_equal(hmac_sha256_hex(sec,user+"|"+chan+"|"+ts),tok);
}

// -----------------------------------------------------------------------------
// WebSocket session + broadcast state
// -----------------------------------------------------------------------------
struct WsSession{ explicit WsSession(tcp::socket&&s):ws(std::move(s)){} websocket::stream<tcp::socket> ws; std::mutex m; };
static std::unordered_map<std::string,std::vector<std::weak_ptr<WsSession>>> G;
static std::mutex Gmtx;

static void fanout(const std::string&ch,const std::string&msg,const WsSession*skip=nullptr){
    std::vector<std::shared_ptr<WsSession>> peers;
    {std::lock_guard<std::mutex>lk(Gmtx);
     auto it=G.find(ch);
     if(it!=G.end())for(auto&w:it->second)if(auto sp=w.lock())if(sp.get()!=skip)peers.push_back(sp);}
    for(auto&p:peers){std::lock_guard<std::mutex>wl(p->m);
        beast::error_code ec; p->ws.text(true); p->ws.write(net::buffer(msg),ec);}
}

// -----------------------------------------------------------------------------
// WebSocket loop
// -----------------------------------------------------------------------------
static void ws_loop(tcp::socket sock,http::request<http::string_body>&&req){
    auto self=std::make_shared<WsSession>(std::move(sock));
    self->ws.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
    self->ws.accept(req);

    std::string t=std::string(req.target());
    auto qpos=t.find('?'); std::map<std::string,std::string> q;
    if(qpos!=std::string::npos){
        std::stringstream ss(t.substr(qpos+1)); std::string kv;
        while(std::getline(ss,kv,'&')){
            auto e=kv.find('='); if(e!=std::string::npos)
                q[kv.substr(0,e)]=kv.substr(e+1);
        }
    }
    std::string user=q.count("user")?q["user"]:"anon";
    std::string chan=q.count("channel")?q["channel"]:"general";

    {std::lock_guard<std::mutex>lk(Gmtx); G[chan].push_back(self);}

    beast::flat_buffer buf;
    for(;;){
        beast::error_code ec; self->ws.read(buf,ec);
        if(ec==websocket::error::closed)break; if(ec)break;
        std::string msg=beast::buffers_to_string(buf.data()); buf.consume(buf.size());
        if(msg.size()>4096)continue;

        // extract "text"
        auto p=msg.find("\"text\""); if(p==std::string::npos)continue;
        auto c=msg.find(':',p); auto q1=msg.find('"',c+1); auto q2=msg.find('"',q1+1);
        if(q1==std::string::npos||q2==std::string::npos)continue;
        std::string text=msg.substr(q1+1,q2-q1-1);

        time_t now=time(nullptr); char ts[32];
        strftime(ts,sizeof(ts),"%Y-%m-%dT%H:%M:%SZ",gmtime(&now));

        try{
            std::string conn="host="+get_env("PGHOST","postgres")+" port="+get_env("PGPORT","5432")+
                             " dbname="+get_env("PGDATABASE","bcord")+" user="+get_env("PGUSER","bcord")+
                             " password="+get_env("PGPASSWORD","change_me");
            pqxx::connection cdb(conn); pqxx::work w(cdb);
            w.exec_params("INSERT INTO messages(channel_id,sender,body)"
                          " VALUES((SELECT id FROM channels WHERE name=$1 LIMIT 1),$2,$3)",
                          chan,user,text);
            w.commit();
        }catch(...){}

        std::ostringstream js;
        js<<"{\"op\":\"message\",\"sender\":\""<<json_escape(user)
          <<"\",\"text\":\""<<json_escape(text)
          <<"\",\"ts\":\""<<ts<<"\"}";
        std::string out=js.str();

        {std::lock_guard<std::mutex>wl(self->m);
         self->ws.text(true); self->ws.write(net::buffer(out));}
        fanout(chan,out,self.get());
    }
}

// -----------------------------------------------------------------------------
// HTTP handler
// -----------------------------------------------------------------------------
static void serve_http(tcp::socket sock){
    beast::flat_buffer buffer; http::request<http::string_body> req;
    http::read(sock,buffer,req);

    std::string target=std::string(req.target());
    std::string path=target.substr(0,target.find('?'));
    bool is_get=req.method()==http::verb::get;
    bool is_post=req.method()==http::verb::post;

    http::response<http::string_body> res; res.version(req.version()); res.keep_alive(false);

    // --- WebSocket upgrade
    if(websocket::is_upgrade(req)&&(path=="/ws"||path=="/api/ws"))
        return ws_loop(std::move(sock),std::move(req));

    // --- /api/login
    if((is_get||is_post)&&path=="/api/login"){
        res.set(http::field::access_control_allow_origin,"*");
        const std::string secret=get_env("WS_SECRET","");
        if(secret.empty()){
            res.result(http::status::internal_server_error);
            res.set(http::field::content_type,"application/json");
            res.body()=R"({"error":"WS_SECRET not set"})";
            res.prepare_payload(); http::write(sock,res); return;
        }
        std::string user,channel;
        auto qpos=target.find('?');
        if(qpos!=std::string::npos){
            std::stringstream ss(target.substr(qpos+1)); std::string kv;
            while(std::getline(ss,kv,'&')){
                auto e=kv.find('='); if(e==std::string::npos)continue;
                auto k=kv.substr(0,e),v=kv.substr(e+1);
                if(k=="user")user=v; else if(k=="channel")channel=v;
            }
        }
        if(is_post&&!req.body().empty()){
            auto b=req.body(); auto pu=b.find("\"username\"");
            if(pu!=std::string::npos){auto c=b.find(':',pu);
                auto q1=b.find('"',c+1); auto q2=b.find('"',q1+1);
                if(q1!=std::string::npos&&q2!=std::string::npos)
                    user=trim_soft(b.substr(q1+1,q2-q1-1));}
            auto pc=b.find("\"channel\"");
            if(pc!=std::string::npos){auto c=b.find(':',pc);
                auto q1=b.find('"',c+1); auto q2=b.find('"',q1+1);
                if(q1!=std::string::npos&&q2!=std::string::npos)
                    channel=trim_soft(b.substr(q1+1,q2-q1-1));}
        }
        if(user.empty())user="dev"; if(channel.empty())channel="general";
        uint64_t now=std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        std::string ts=std::to_string(now);
        std::string tok=hmac_sha256_hex(secret,user+"|"+channel+"|"+ts);
        std::ostringstream js;
        js<<"{\"token\":\""<<tok<<"\",\"ts\":"<<ts<<",\"user\":\""<<json_escape(user)<<"\"}";
        res.result(http::status::ok);
        res.set(http::field::content_type,"application/json");
        res.body()=js.str(); res.prepare_payload(); http::write(sock,res); return;
    }

    // --- /api/history
    // --- /api/history
if(is_get && path == "/api/history") {
    res.set(http::field::access_control_allow_origin,"*");
    std::string channel = "general";
    auto qpos = target.find('?');
    if(qpos != std::string::npos){
        std::stringstream ss(target.substr(qpos+1));
        std::string kv;
        while(std::getline(ss,kv,'&')){
            auto e = kv.find('=');
            if(e != std::string::npos && kv.substr(0,e) == "channel")
                channel = kv.substr(e+1);
        }
    }

    try{
        std::string conn = "host="+get_env("PGHOST","postgres")+" port="+get_env("PGPORT","5432")+
                           " dbname="+get_env("PGDATABASE","bcord")+" user="+get_env("PGUSER","bcord")+
                           " password="+get_env("PGPASSWORD","change_me");
        pqxx::connection cdb(conn);
        pqxx::work w(cdb);
        auto r = w.exec_params(
            "SELECT sender, body, to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') "
            "FROM messages m JOIN channels c ON m.channel_id = c.id "
            "WHERE c.name=$1 ORDER BY m.created_at DESC LIMIT 50",
            channel);

        std::ostringstream js;
        js << "{\"rows\":[";
        bool first = true;
        for(auto const& row : r){
            if(!first) js << ",";
            first = false;
            js << "{\"sender\":\"" << json_escape(row[0].c_str())
               << "\",\"text\":\"" << json_escape(row[1].c_str())
               << "\",\"ts\":\"" << row[2].c_str() << "\"}";
        }
        js << "]}";

        res.result(http::status::ok);
        res.set(http::field::content_type, "application/json");
        res.body() = js.str();
        res.prepare_payload();
        http::write(sock, res);
        return;
    }
    catch(const std::exception& e){
        res.result(http::status::internal_server_error);
        res.set(http::field::content_type, "application/json");
        res.body() = "{\"error\":\"" + std::string(e.what()) + "\"}";
        res.prepare_payload();
        http::write(sock, res);
        return;
    }
}


    // --- fallback root (JSON safe)
    res.result(http::status::ok);
    res.set(http::field::content_type,"application/json");
    res.body()=R"({"status":"ok","message":"BCord backend running"})";
    res.prepare_payload(); http::write(sock,res);
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------
int main(){
    try{
        std::string bind=get_env("BIND_ADDR","0.0.0.0");
        unsigned short port=(unsigned short)std::stoi(get_env("PORT","9000"));
        net::io_context ioc{1};
        tcp::acceptor acc{ioc,{net::ip::make_address(bind),port}};
        std::cout<<"[start] listening on "<<bind<<":"<<port<<std::endl;
        for(;;){tcp::socket s{ioc}; acc.accept(s);
            std::thread(serve_http,std::move(s)).detach();}
    }catch(const std::exception&e){
        std::cerr<<"[fatal] "<<e.what()<<std::endl; return 1;
    }
}

