#pragma once
#include <atomic>
#include <string>
#include <sstream>

// Singleton Metrics class for Prometheus-style counters
class Metrics {
public:
    // Singleton access
    static Metrics& instance() {
        static Metrics m;
        return m;
    }

    // Auth metrics counters
    std::atomic<uint64_t> auth_login_success_total{0};
    std::atomic<uint64_t> auth_login_failure_total{0};
    std::atomic<uint64_t> auth_refresh_success_total{0};
    std::atomic<uint64_t> auth_refresh_failure_total{0};
    std::atomic<uint64_t> auth_logout_total{0};
    std::atomic<uint64_t> auth_register_success_total{0};
    std::atomic<uint64_t> auth_register_failure_total{0};

    // Generate Prometheus text format
    std::string to_prometheus_text() const {
        std::ostringstream oss;
        
        oss << "# HELP bcord_up Backend health indicator\n"
            << "# TYPE bcord_up gauge\n"
            << "bcord_up 1\n\n";
        
        oss << "# HELP auth_login_success_total Total successful login attempts\n"
            << "# TYPE auth_login_success_total counter\n"
            << "auth_login_success_total " << auth_login_success_total.load() << "\n\n";
        
        oss << "# HELP auth_login_failure_total Total failed login attempts\n"
            << "# TYPE auth_login_failure_total counter\n"
            << "auth_login_failure_total " << auth_login_failure_total.load() << "\n\n";
        
        oss << "# HELP auth_refresh_success_total Total successful token refreshes\n"
            << "# TYPE auth_refresh_success_total counter\n"
            << "auth_refresh_success_total " << auth_refresh_success_total.load() << "\n\n";
        
        oss << "# HELP auth_refresh_failure_total Total failed token refreshes\n"
            << "# TYPE auth_refresh_failure_total counter\n"
            << "auth_refresh_failure_total " << auth_refresh_failure_total.load() << "\n\n";
        
        oss << "# HELP auth_logout_total Total logout requests\n"
            << "# TYPE auth_logout_total counter\n"
            << "auth_logout_total " << auth_logout_total.load() << "\n\n";
        
        oss << "# HELP auth_register_success_total Total successful registrations\n"
            << "# TYPE auth_register_success_total counter\n"
            << "auth_register_success_total " << auth_register_success_total.load() << "\n\n";
        
        oss << "# HELP auth_register_failure_total Total failed registrations\n"
            << "# TYPE auth_register_failure_total counter\n"
            << "auth_register_failure_total " << auth_register_failure_total.load() << "\n";
        
        return oss.str();
    }

private:
    Metrics() = default;
    Metrics(const Metrics&) = delete;
    Metrics& operator=(const Metrics&) = delete;
};
