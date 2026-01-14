// Lightweight proxy-backed port scanner for TCP port 25565 (default).
// Each worker is pinned to a unique proxy. Supports SOCKS5 or HTTP CONNECT proxies.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <functional>
#include <iostream>
#include <mutex>
#include <optional>
#include <random>
#include <numeric>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>
#include <deque>

#include <cstring>
#include <cerrno>
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <commctrl.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
using socket_t = SOCKET;
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#endif

namespace {

constexpr const char* kDefaultStartIp = "40.0.0.0";
constexpr const char* kDefaultEndIp = "255.255.255.255";
constexpr int kDefaultPort = 25565;
constexpr const char* kResultsFile = "minecraft_servers.txt";

struct Options {
    std::string start_ip;
    std::string end_ip;
    std::vector<std::string> targets;
    std::string target_file;
    int port = kDefaultPort;
    int workers = 32;
    double timeout_sec = 3.0;
    double duration_sec = -1.0;  // negative = unlimited
    double ping_timeout_sec = 1.0;
    std::string proxies_file = "mullvadproxyips.txt";
    int proxy_port = 1080;
    std::string proxy_type = "socks5";
    bool shuffle_targets = true;
    bool verbose = false;
};

struct Result {
    std::string target_ip;
    std::string proxy_ip;
    double elapsed_sec;
    std::string mc_status;
};

struct StatSnapshot {
    uint64_t scanned = 0;
    double scanned_rate = 0.0;
    uint64_t replies = 0;
    double replies_rate = 0.0;
    uint64_t opens = 0;
};

struct ScanCallbacks {
    // For GUI/CLI logging. Functions may be empty.
    std::function<void(const std::string&)> on_ping_lifecycle;  // worker starts ping, ping timeouts/failures
    std::function<void(const std::string&)> on_ping_success;    // ping replies and port check start
    std::function<void(const std::string&)> on_open;            // open port found
    std::function<void(const std::string&)> on_info;            // general info (start/finish)
    std::function<void(const std::string&)> on_verbose;         // optional verbose failures
    std::function<void(const Result&)> on_result;               // structured result callback
    std::function<void(const StatSnapshot&)> on_stats;          // stats update (aggregated)
};

void emit_log(const std::function<void(const std::string&)>& fn, const std::string& msg) {
    if (fn) fn(msg);
}

void emit_result(const std::function<void(const Result&)>& fn, const Result& r) {
    if (fn) fn(r);
}

void emit_stats(const std::function<void(const StatSnapshot&)>& fn, const StatSnapshot& s) {
    if (fn) fn(s);
}

std::string trim_copy(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

struct TargetSet {
    bool has_range = false;
    uint32_t range_start = 0;
    uint32_t range_end = 0;
    uint64_t range_count = 0;
    uint64_t perm_stride = 1;
    uint64_t perm_offset = 0;
    std::vector<std::string> list_targets;  // explicit list/file
};

std::string usage() {
    std::ostringstream out;
    out << "Usage: scanner [options]\n"
        << "  --start-ip IP          Starting IPv4 address (default: " << kDefaultStartIp << ")\n"
        << "  --end-ip IP            Ending IPv4 address (default: " << kDefaultEndIp << ")\n"
        << "  --targets IP ...       Explicit target IPs\n"
        << "  --target-file PATH     File with one IP per line\n"
        << "  --port N               Target TCP port (default: " << kDefaultPort << ")\n"
        << "  --workers N            Worker threads (default: 32)\n"
        << "  --ping-timeout SEC     Ping timeout seconds (default: 1.0)\n"
        << "  --timeout SEC          Socket timeout seconds (default: 3.0)\n"
        << "  --duration SEC         Optional max runtime seconds\n"
        << "  --proxies-file PATH    Proxy list file (default: mullvadproxyips.txt)\n"
        << "  --proxy-port N         Proxy port (default: 1080)\n"
        << "  --proxy-type TYPE      socks5 or http (default: socks5)\n"
        << "  --shuffle-targets      Shuffle targets before scanning\n"
        << "  --verbose              Log failures/timeouts\n"
        << "  --help                 Show this help\n";
    return out.str();
}

bool starts_with_dash(const std::string& s) {
    return s.rfind("--", 0) == 0;
}

std::optional<Options> parse_args(int argc, char** argv) {
    Options opts;
    int i = 1;
    auto need_val = [&](const char* flag) -> std::optional<std::string> {
        if (i + 1 >= argc) {
            std::cerr << "Missing value for " << flag << "\n";
            return std::nullopt;
        }
        return argv[++i];
    };
    for (; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            std::cout << usage();
            return std::nullopt;
        } else if (arg == "--start-ip") {
            auto v = need_val("--start-ip");
            if (!v) return std::nullopt;
            opts.start_ip = *v;
        } else if (arg == "--end-ip") {
            auto v = need_val("--end-ip");
            if (!v) return std::nullopt;
            opts.end_ip = *v;
        } else if (arg == "--targets") {
            while (i + 1 < argc && !starts_with_dash(argv[i + 1])) {
                opts.targets.emplace_back(argv[++i]);
            }
        } else if (arg == "--target-file") {
            auto v = need_val("--target-file");
            if (!v) return std::nullopt;
            opts.target_file = *v;
        } else if (arg == "--port") {
            auto v = need_val("--port");
            if (!v) return std::nullopt;
            opts.port = std::stoi(*v);
        } else if (arg == "--workers") {
            auto v = need_val("--workers");
            if (!v) return std::nullopt;
            opts.workers = std::stoi(*v);
        } else if (arg == "--timeout") {
            auto v = need_val("--timeout");
            if (!v) return std::nullopt;
            opts.timeout_sec = std::stod(*v);
        } else if (arg == "--ping-timeout") {
            auto v = need_val("--ping-timeout");
            if (!v) return std::nullopt;
            opts.ping_timeout_sec = std::stod(*v);
        } else if (arg == "--duration") {
            auto v = need_val("--duration");
            if (!v) return std::nullopt;
            opts.duration_sec = std::stod(*v);
        } else if (arg == "--proxies-file") {
            auto v = need_val("--proxies-file");
            if (!v) return std::nullopt;
            opts.proxies_file = *v;
        } else if (arg == "--proxy-port") {
            auto v = need_val("--proxy-port");
            if (!v) return std::nullopt;
            opts.proxy_port = std::stoi(*v);
        } else if (arg == "--proxy-type") {
            auto v = need_val("--proxy-type");
            if (!v) return std::nullopt;
            opts.proxy_type = *v;
            if (opts.proxy_type != "socks5" && opts.proxy_type != "http") {
                std::cerr << "proxy-type must be socks5 or http\n";
                return std::nullopt;
            }
        } else if (arg == "--shuffle-targets") {
            opts.shuffle_targets = true;
        } else if (arg == "--verbose") {
            opts.verbose = true;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            return std::nullopt;
        }
    }
    return opts;
}

std::vector<std::string> load_lines(const std::string& path) {
    std::ifstream file(path);
    std::vector<std::string> lines;
    if (!file.is_open()) {
        return lines;
    }
    std::string line;
    while (std::getline(file, line)) {
        line = trim_copy(line);
        if (!line.empty() && line[0] != '#') lines.push_back(line);
    }
    return lines;
}

bool parse_ipv4(const std::string& ip, uint32_t& out) {
    in_addr addr{};
    int rc = inet_pton(AF_INET, ip.c_str(), &addr);
    if (rc != 1) {
        return false;
    }
    out = ntohl(addr.s_addr);
    return true;
}

std::string ipv4_to_string(uint32_t ip) {
    in_addr out_addr{};
    out_addr.s_addr = htonl(ip);
    return std::string(inet_ntoa(out_addr));
}

bool expand_range(const std::string& start_ip, const std::string& end_ip, std::vector<std::string>& out, std::string& err) {
    uint32_t start, end;
    if (!parse_ipv4(start_ip, start)) {
        err = "Invalid start IP";
        return false;
    }
    if (!parse_ipv4(end_ip, end)) {
        err = "Invalid end IP";
        return false;
    }
    if (end < start) {
        err = "End IP must be greater than or equal to start IP";
        return false;
    }
    uint64_t count = static_cast<uint64_t>(end) - static_cast<uint64_t>(start) + 1;
    out.reserve(static_cast<size_t>(count));
    for (uint32_t ip = start; ip <= end; ++ip) {
        out.emplace_back(ipv4_to_string(ip));
        if (ip == 0xFFFFFFFFu) break;  // prevent overflow, though capped above
    }
    return true;
}

TargetSet collect_targets(const Options& opts, std::string& err) {
    TargetSet tset;
    bool has_list_targets = !opts.targets.empty() || !opts.target_file.empty();
    std::string start_ip = opts.start_ip;
    std::string end_ip = opts.end_ip;
    if (start_ip.empty() && end_ip.empty() && !has_list_targets) {
        start_ip = kDefaultStartIp;
        end_ip = kDefaultEndIp;
    }
    if (!start_ip.empty() || !end_ip.empty()) {
        if (start_ip.empty() || end_ip.empty()) {
            err = "Both --start-ip and --end-ip are required together";
            return {};
        }
        uint32_t start, end;
        if (!parse_ipv4(start_ip, start)) {
            err = "Invalid start IP";
            return {};
        }
        if (!parse_ipv4(end_ip, end)) {
            err = "Invalid end IP";
            return {};
        }
        if (end < start) {
            err = "End IP must be greater than or equal to start IP";
            return {};
        }
        tset.has_range = true;
        tset.range_start = start;
        tset.range_end = end;
        tset.range_count = static_cast<uint64_t>(end) - static_cast<uint64_t>(start) + 1;

        // Generate a permutation step and offset for randomized iteration without storing all IPs.
        std::mt19937_64 rng(static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count()));
        std::uniform_int_distribution<uint64_t> offset_dist(0, tset.range_count - 1);
        tset.perm_offset = offset_dist(rng);

        // Choose a stride coprime with range_count (odd often suffices when count is power of two).
        std::uniform_int_distribution<uint64_t> stride_dist(1, tset.range_count - 1);
        uint64_t stride = 0;
        for (int attempts = 0; attempts < 128; ++attempts) {
            uint64_t candidate = stride_dist(rng);
            if (std::gcd(candidate, tset.range_count) == 1) {
                stride = candidate;
                break;
            }
        }
        if (stride == 0) {
            // Fallback: use 1 (no permutation) if we somehow failed to find a coprime.
            stride = 1;
        }
        tset.perm_stride = stride;
    }

    tset.list_targets.insert(tset.list_targets.end(), opts.targets.begin(), opts.targets.end());
    if (!opts.target_file.empty()) {
        auto more = load_lines(opts.target_file);
        tset.list_targets.insert(tset.list_targets.end(), more.begin(), more.end());
    }
    if (!tset.list_targets.empty()) {
        // Deduplicate explicit/file targets.
        std::unordered_set<std::string> seen;
        std::vector<std::string> deduped;
        deduped.reserve(tset.list_targets.size());
        for (const auto& ip : tset.list_targets) {
            if (seen.insert(ip).second) {
                deduped.push_back(ip);
            }
        }
        tset.list_targets.swap(deduped);
    }

    if (!tset.has_range && tset.list_targets.empty()) {
        err = "No targets provided. Use --start-ip/--end-ip, --targets, or --target-file.";
        return {};
    }
    return tset;
}

bool set_blocking(socket_t s, bool blocking) {
#ifdef _WIN32
    u_long mode = blocking ? 0 : 1;
    return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) return false;
    if (!blocking)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;
    return fcntl(s, F_SETFL, flags) == 0;
#endif
}

void set_socket_timeouts(socket_t s, int timeout_ms) {
#ifdef _WIN32
    DWORD tv = static_cast<DWORD>(timeout_ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

void close_socket(socket_t s) {
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

std::optional<socket_t> connect_with_timeout(const std::string& host, int port, int timeout_ms) {
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    struct addrinfo* res = nullptr;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0) {
        return std::nullopt;
    }
    std::optional<socket_t> sock_opt;
    for (auto* rp = res; rp != nullptr; rp = rp->ai_next) {
        socket_t s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        set_blocking(s, false);
        int ret = connect(s, rp->ai_addr, static_cast<int>(rp->ai_addrlen));
        if (ret == 0) {
            set_blocking(s, true);
            set_socket_timeouts(s, timeout_ms);
            sock_opt = s;
            break;
        }
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
#else
        int err = errno;
        if (err == EINPROGRESS) {
#endif
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(s, &wfds);
            struct timeval tv;
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            int sel = select(static_cast<int>(s + 1), nullptr, &wfds, nullptr, &tv);
            if (sel > 0) {
                int so_error = 0;
                socklen_t len = sizeof(so_error);
                getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_error), &len);
                if (so_error == 0) {
                    set_blocking(s, true);
                    set_socket_timeouts(s, timeout_ms);
                    sock_opt = s;
                    break;
                }
            }
        }
        close_socket(s);
    }
    freeaddrinfo(res);
    return sock_opt;
}

bool send_all(socket_t s, const std::vector<uint8_t>& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        int n = send(s, reinterpret_cast<const char*>(data.data() + sent), static_cast<int>(data.size() - sent), 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool send_all(socket_t s, const std::string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        int n = send(s, data.data() + sent, static_cast<int>(data.size() - sent), 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool recv_exact(socket_t s, uint8_t* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        int n = recv(s, reinterpret_cast<char*>(buf + got), static_cast<int>(len - got), 0);
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }
    return true;
}

bool socks5_connect(socket_t s, const std::string& target_ip, int target_port) {
    std::vector<uint8_t> hello{0x05, 0x01, 0x00};
    if (!send_all(s, hello)) return false;
    uint8_t resp[2];
    if (!recv_exact(s, resp, 2)) return false;
    if (resp[0] != 0x05 || resp[1] != 0x00) return false;

    in_addr addr{};
    if (inet_pton(AF_INET, target_ip.c_str(), &addr) != 1) return false;
    uint8_t req[10];
    req[0] = 0x05;  // version
    req[1] = 0x01;  // connect
    req[2] = 0x00;  // reserved
    req[3] = 0x01;  // IPv4
    std::memcpy(req + 4, &addr.s_addr, 4);
    req[8] = static_cast<uint8_t>((target_port >> 8) & 0xFF);
    req[9] = static_cast<uint8_t>(target_port & 0xFF);
    if (!send_all(s, std::vector<uint8_t>(req, req + 10))) return false;
    uint8_t rep[10];
    if (!recv_exact(s, rep, 10)) return false;
    if (rep[1] != 0x00) return false;
    return true;
}

bool http_connect(socket_t s, const std::string& target_ip, int target_port) {
    std::ostringstream req;
    req << "CONNECT " << target_ip << ":" << target_port << " HTTP/1.1\r\n"
        << "Host: " << target_ip << ":" << target_port << "\r\n\r\n";
    if (!send_all(s, req.str())) return false;
    std::string resp;
    char buf[512];
    while (resp.find("\r\n\r\n") == std::string::npos && resp.size() < 4096) {
        int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        resp.append(buf, buf + n);
    }
    auto first_line_end = resp.find("\r\n");
    if (first_line_end == std::string::npos) return false;
    std::string status_line = resp.substr(0, first_line_end);
    std::istringstream iss(status_line);
    std::string http_version, status_code;
    iss >> http_version >> status_code;
    if (status_code != "200") return false;
    return true;
}

bool attempt_connect(
    const std::string& proxy_ip,
    int proxy_port,
    const std::string& target_ip,
    int target_port,
    const std::string& proxy_type,
    int timeout_ms,
    std::string& error_out) {
    auto sock_opt = connect_with_timeout(proxy_ip, proxy_port, timeout_ms);
    if (!sock_opt) {
        error_out = "connect to proxy failed";
        return false;
    }
    socket_t s = *sock_opt;
    bool ok = false;
    if (proxy_type == "socks5") {
        ok = socks5_connect(s, target_ip, target_port);
        if (!ok) error_out = "SOCKS5 connect failed";
    } else {
        ok = http_connect(s, target_ip, target_port);
        if (!ok) error_out = "HTTP CONNECT failed";
    }
    close_socket(s);
    return ok;
}

bool ping_host(const std::string& ip, int timeout_ms) {
#ifdef _WIN32
    std::ostringstream cmd;
    cmd << "ping -n 1 -w " << timeout_ms << " " << ip << " >nul 2>&1";
#else
    // timeout_ms to seconds (rounded up)
    int timeout_s = (timeout_ms + 999) / 1000;
    if (timeout_s <= 0) timeout_s = 1;
    std::ostringstream cmd;
    cmd << "ping -c 1 -W " << timeout_s << " " << ip << " >/dev/null 2>&1";
#endif
    int rc = std::system(cmd.str().c_str());
    return rc == 0;
}

bool command_available(const std::string& cmd) {
#ifdef _WIN32
    std::string test = "cmd /c " + cmd + " --version >nul 2>&1";
#else
    std::string test = cmd + " --version >/dev/null 2>&1";
#endif
    return std::system(test.c_str()) == 0;
}

std::string python_command() {
    if (const char* env = std::getenv("PYTHON_CMD")) {
        return env;
    }
#ifdef _WIN32
    for (const char* cand : {"python", "python3", "py -3", "py"}) {
        if (command_available(cand)) return cand;
    }
    return "python";
#else
    for (const char* cand : {"python3", "python"}) {
        if (command_available(cand)) return cand;
    }
    return "python3";
#endif
}

std::string mcstatus_script_path() {
    if (const char* env = std::getenv("MCSTATUS_SCRIPT")) {
        return env;
    }
    return "mcstatus_probe.py";
}

bool check_minecraft_server_via_python(
    const std::string& ip,
    int port,
    std::string& message_out,
    std::string& error_out,
    std::vector<std::string>* logs_out = nullptr) {
    const double timeout_sec = 3.0;
    auto quote_if_path = [](std::string v) {
        bool has_space = v.find_first_of(" \t") != std::string::npos;
        bool has_sep = v.find('\\') != std::string::npos || v.find('/') != std::string::npos;
        bool quoted = v.find('"') != std::string::npos;
        if (has_sep && has_space && !quoted) v = "\"" + v + "\"";
        return v;
    };
    std::string py_cmd = quote_if_path(python_command());
    std::string script = quote_if_path(mcstatus_script_path());
    std::ostringstream cmd;
    cmd << py_cmd << " " << script
        << " --ip \"" << ip << "\" --port " << port
        << " --timeout " << timeout_sec
        << " 2>&1";
#ifdef _WIN32
    FILE* pipe = _popen(cmd.str().c_str(), "r");
#else
    FILE* pipe = popen(cmd.str().c_str(), "r");
#endif
    if (!pipe) {
        error_out = "failed to start mcstatus helper";
        return false;
    }
    std::string output;
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output.append(buffer);
    }
#ifdef _WIN32
    int rc = _pclose(pipe);
#else
    int rc = pclose(pipe);
#endif
    std::string main_line;
    {
        std::istringstream iss(output);
        std::string line;
        while (std::getline(iss, line)) {
            line = trim_copy(line);
            if (line.empty()) continue;
            if (line.rfind("LOG:", 0) == 0) {
                if (logs_out) logs_out->push_back(trim_copy(line.substr(4)));
                continue;
            }
            main_line = line;
        }
    }
    output = trim_copy(main_line);
    if (rc == 0 && !output.empty()) {
        message_out = output;
        return true;
    }
    if (rc == 2 || output.rfind("NONMC:", 0) == 0) {
        error_out = "NONMC";
        return false;
    }
    if (rc == 3 || output.rfind("MC-TIMEOUT", 0) == 0) {
        error_out = output.empty() ? "MC-TIMEOUT" : output;
        return false;
    }
    if (rc != 0 || output.empty()) {
        error_out = output.empty() ? "mcstatus helper returned no output" : output;
#ifdef _WIN32
        if (error_out.find("not recognized") != std::string::npos) {
            error_out += " (install Python or set PYTHON_CMD)";
        }
#endif
        return false;
    }
    message_out = output;
    return true;
}

void write_results_to_file(const std::vector<Result>& results, const Options& opts, const std::string& path = kResultsFile) {
    std::ofstream out(path, std::ios::trunc);
    if (!out.is_open()) return;
    for (const auto& r : results) {
        out << (r.mc_status.empty() ? (r.target_ip + ":" + std::to_string(opts.port)) : r.mc_status) << "\n";
    }
}

class StatTracker {
public:
    void set_callback(std::function<void(const StatSnapshot&)> cb) { callback_ = std::move(cb); }

    void record_scanned() { record_event(EventType::Scanned); }
    void record_reply() { record_event(EventType::Reply); }
    void record_open() { opens_.fetch_add(1, std::memory_order_relaxed); maybe_emit(true); }

private:
    enum class EventType { Scanned, Reply };

    void record_event(EventType type) {
        auto now = std::chrono::steady_clock::now();
        if (type == EventType::Scanned) {
            scanned_.fetch_add(1, std::memory_order_relaxed);
        } else {
            replies_.fetch_add(1, std::memory_order_relaxed);
        }
        {
            std::lock_guard<std::mutex> lock(mu_);
            auto& dq = (type == EventType::Scanned) ? scanned_times_ : reply_times_;
            dq.push_back(now);
            prune_locked(now, dq);
        }
        maybe_emit(false);
    }

    void prune_locked(std::chrono::steady_clock::time_point now, std::deque<std::chrono::steady_clock::time_point>& dq) {
        auto cutoff = now - std::chrono::seconds(60);
        while (!dq.empty() && dq.front() < cutoff) {
            dq.pop_front();
        }
    }

    void maybe_emit(bool force) {
        if (!callback_) return;
        auto now = std::chrono::steady_clock::now();
        bool do_emit = force;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (!force && now - last_emit_ < std::chrono::milliseconds(500)) {
                return;
            }
            last_emit_ = now;
        }
        StatSnapshot snap = snapshot(now);
        emit_stats(callback_, snap);
    }

    StatSnapshot snapshot(std::chrono::steady_clock::time_point now) {
        StatSnapshot snap;
        snap.scanned = scanned_.load(std::memory_order_relaxed);
        snap.replies = replies_.load(std::memory_order_relaxed);
        snap.opens = opens_.load(std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(mu_);
        prune_locked(now, scanned_times_);
        prune_locked(now, reply_times_);
        double window = 60.0;
        snap.scanned_rate = scanned_times_.empty() ? 0.0 : scanned_times_.size() / window;
        snap.replies_rate = reply_times_.empty() ? 0.0 : reply_times_.size() / window;
        return snap;
    }

    std::atomic<uint64_t> scanned_{0};
    std::atomic<uint64_t> replies_{0};
    std::atomic<uint64_t> opens_{0};
    std::deque<std::chrono::steady_clock::time_point> scanned_times_;
    std::deque<std::chrono::steady_clock::time_point> reply_times_;
    std::chrono::steady_clock::time_point last_emit_{};
    std::mutex mu_;
    std::function<void(const StatSnapshot&)> callback_;
};

void worker_loop(
    size_t worker_id,
    const std::string& proxy_ip,
    const Options& opts,
    const TargetSet& targets,
    uint64_t total_targets,
    std::atomic<uint64_t>& next_index,
    std::atomic<bool>& stop_flag,
    std::optional<std::chrono::steady_clock::time_point> stop_at,
    std::mutex& results_mutex,
    std::vector<Result>& results,
    const ScanCallbacks& callbacks,
    StatTracker& stats) {
    const int timeout_ms = static_cast<int>(opts.timeout_sec * 1000);
    const int ping_timeout_ms = static_cast<int>(opts.ping_timeout_sec * 1000);
    while (true) {
        if (stop_flag.load()) break;
        if (stop_at && std::chrono::steady_clock::now() >= *stop_at) {
            stop_flag.store(true);
            break;
        }
        uint64_t idx = next_index.fetch_add(1);
        if (idx >= total_targets) break;
        std::string target;
        if (targets.has_range && idx < targets.range_count) {
            uint64_t perm_idx = (idx * targets.perm_stride + targets.perm_offset) % targets.range_count;
            uint32_t ip_val = targets.range_start + static_cast<uint32_t>(perm_idx);
            target = ipv4_to_string(ip_val);
        } else {
            uint64_t list_idx = idx - targets.range_count;
            if (list_idx < targets.list_targets.size()) {
                target = targets.list_targets[static_cast<size_t>(list_idx)];
            } else {
                continue;
            }
        }
        stats.record_scanned();
        // Ping check first.
        emit_log(callbacks.on_ping_lifecycle, "[WORKER " + std::to_string(worker_id) + "] pinging " + target);
        auto ping_start = std::chrono::steady_clock::now();
        bool ping_ok = ping_host(target, ping_timeout_ms);
        double ping_elapsed = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - ping_start).count();
        if (ping_ok) {
            stats.record_reply();
            std::ostringstream ping_msg;
            ping_msg << "[RECV-PING] " << target << " (" << std::fixed << std::setprecision(1) << ping_elapsed << " ms)";
            emit_log(callbacks.on_ping_success, ping_msg.str());
            std::ostringstream check_msg;
            check_msg << "[CHECK] worker " << worker_id << " testing " << target << ":" << opts.port;
            emit_log(callbacks.on_ping_success, check_msg.str());
        } else {
            std::ostringstream fail_msg;
            fail_msg << "[FAIL-PING] " << target << " (>" << ping_timeout_ms << " ms)";
            emit_log(callbacks.on_ping_lifecycle, fail_msg.str());
            continue;
        }

        std::string error;
        auto start = std::chrono::steady_clock::now();
        bool ok = attempt_connect(proxy_ip, opts.proxy_port, target, opts.port, opts.proxy_type, timeout_ms, error);
        double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        if (ok) {
            std::string mc_message;
            std::string mc_error;
            std::vector<std::string> py_logs;
            bool mc_ok = check_minecraft_server_via_python(target, opts.port, mc_message, mc_error, &py_logs);
            for (const auto& log_line : py_logs) {
                emit_log(callbacks.on_open, "LOG: " + log_line);
            }
            if (mc_ok) {
                std::ostringstream mc_log;
                mc_log << "[MC] " << mc_message << " via " << proxy_ip << ":" << opts.proxy_port
                       << " (" << opts.proxy_type << ", port check " << std::fixed << std::setprecision(2) << elapsed << "s)";
                stats.record_open();
                Result r{target, proxy_ip, elapsed, mc_message};
                {
                    std::lock_guard<std::mutex> lock(results_mutex);
                    results.push_back(r);
                }
                emit_result(callbacks.on_result, r);
            } else {
                std::ostringstream msg;
                bool non_mc = mc_error.empty() || mc_error.rfind("NONMC", 0) == 0;
                if (non_mc) {
                    msg << "[OPEN NON-MC] " << target << ":" << opts.port << " via " << proxy_ip << ":" << opts.proxy_port
                        << " (" << opts.proxy_type << ") -> " << (mc_error.empty() ? "not a Minecraft server" : mc_error);
                    emit_log(callbacks.on_open, msg.str());
                } else if (opts.verbose) {
                    msg << "[MC-ERROR] " << target << ":" << opts.port << " via " << proxy_ip << ":" << opts.proxy_port
                        << " (" << opts.proxy_type << ") -> " << mc_error;
                    emit_log(callbacks.on_verbose, msg.str());
                }
            }
        } else if (opts.verbose) {
            std::ostringstream fail_msg;
            fail_msg << "[FAIL] " << target << ":" << opts.port << " via " << proxy_ip << ":" << opts.proxy_port
                     << " (" << opts.proxy_type << ") -> " << error;
            emit_log(callbacks.on_verbose, fail_msg.str());
        }
    }
}

bool run_scan(const Options& opts_in, const ScanCallbacks& callbacks, std::atomic<bool>& stop_flag, std::vector<Result>& results_out) {
    Options opts = opts_in;
    stop_flag.store(false);
    StatTracker stats;
    stats.set_callback(callbacks.on_stats);
    if (opts.workers < 1) {
        emit_log(callbacks.on_info, "Invalid config: --workers must be >= 1.");
        return false;
    }
    auto proxies = load_lines(opts.proxies_file);
    if (proxies.empty()) {
        emit_log(callbacks.on_info, "No proxies loaded from " + opts.proxies_file);
        return false;
    }
    std::string target_err;
    auto targets = collect_targets(opts, target_err);
    if (!targets.has_range && targets.list_targets.empty()) {
        emit_log(callbacks.on_info, target_err.empty() ? "No targets provided." : target_err);
        return false;
    }
    if (opts.shuffle_targets && !targets.list_targets.empty()) {
        std::mt19937 rng(static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::shuffle(targets.list_targets.begin(), targets.list_targets.end(), rng);
    }

    size_t worker_count = static_cast<size_t>(opts.workers);
    if (worker_count > proxies.size()) {
        std::ostringstream warn;
        warn << "Requested " << worker_count << " workers but only " << proxies.size()
             << " proxies available; using " << proxies.size() << " workers instead.";
        emit_log(callbacks.on_info, warn.str());
        worker_count = proxies.size();
    }
    if (worker_count == 0) {
        emit_log(callbacks.on_info, "No workers can be started (no proxies?).");
        return false;
    }

    uint64_t total_targets = targets.range_count + static_cast<uint64_t>(targets.list_targets.size());
    std::ostringstream start_msg;
    start_msg << "Scanning " << total_targets << " target(s) on port " << opts.port << " with " << worker_count
              << " workers via " << opts.proxy_type << " proxies (timeout=" << opts.timeout_sec
              << "s, duration=" << (opts.duration_sec < 0 ? std::string("unlimited") : std::to_string(opts.duration_sec))
              << ", ping-timeout=" << opts.ping_timeout_sec << "s).";
    emit_log(callbacks.on_info, start_msg.str());

    std::optional<std::chrono::steady_clock::time_point> stop_at;
    if (opts.duration_sec > 0) {
        stop_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(static_cast<int64_t>(opts.duration_sec * 1000));
    }

    std::atomic<uint64_t> next_index{0};
    std::mutex results_mutex;
    results_out.clear();
    results_out.reserve(64);
    std::vector<std::thread> threads;
    threads.reserve(worker_count);
    for (size_t i = 0; i < worker_count; ++i) {
        threads.emplace_back(worker_loop, i, proxies[i], std::cref(opts), std::cref(targets), total_targets,
                             std::ref(next_index), std::ref(stop_flag), stop_at, std::ref(results_mutex),
                             std::ref(results_out), std::cref(callbacks), std::ref(stats));
    }
    for (auto& t : threads) {
        t.join();
    }

    std::ostringstream done_msg;
    done_msg << "Scan finished. Minecraft servers found: " << results_out.size();
    emit_log(callbacks.on_info, done_msg.str());
    return true;
}

#ifdef _WIN32
struct WinsockInit {
    WinsockInit() {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    }
    ~WinsockInit() { WSACleanup(); }
};
#endif

int run_console(int argc, char** argv) {
#ifdef _WIN32
    WinsockInit winsock_guard;
#endif
    auto opts_opt = parse_args(argc, argv);
    if (!opts_opt.has_value()) {
        return 0;
    }
    Options opts = *opts_opt;

    std::mutex cout_mutex;
    ScanCallbacks callbacks;
    callbacks.on_ping_lifecycle = [&](const std::string& msg) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << msg << "\n";
    };
    callbacks.on_ping_success = callbacks.on_ping_lifecycle;
    callbacks.on_open = callbacks.on_ping_lifecycle;
    callbacks.on_verbose = [&](const std::string& msg) {
        if (opts.verbose) {
            std::lock_guard<std::mutex> lock(cout_mutex);
            std::cout << msg << "\n";
        }
    };
    callbacks.on_info = [&](const std::string& msg) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cout << msg << "\n";
    };

    std::atomic<bool> stop_flag{false};
    std::vector<Result> results;
    bool ok = run_scan(opts, callbacks, stop_flag, results);
    write_results_to_file(results, opts);

    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        if (!results.empty()) {
            std::cout << "Minecraft servers:\n";
            for (const auto& r : results) {
                std::string line = r.mc_status.empty() ? (r.target_ip + ":" + std::to_string(opts.port)) : r.mc_status;
                std::cout << " - " << line << " via " << r.proxy_ip << ":" << opts.proxy_port
                          << " (port check " << std::fixed << std::setprecision(2) << r.elapsed_sec << "s)\n";
            }
        }
    }
    return ok ? 0 : 1;
}

#ifdef _WIN32

enum ControlId {
    IDC_BTN_START = 2001,
    IDC_BTN_STOP,
    IDC_EDIT_WORKERS,
    IDC_EDIT_START_IP,
    IDC_EDIT_END_IP,
    IDC_EDIT_PORT,
    IDC_EDIT_PING_TIMEOUT,
    IDC_LOG_ACTIVITY,
    IDC_LOG_SUCCESS,
    IDC_LABEL_START_IP,
    IDC_LABEL_END_IP,
    IDC_LABEL_PORT,
    IDC_LABEL_WORKERS,
    IDC_LABEL_PING,
    IDC_LABEL_LOG1,
    IDC_LABEL_LOG2,
    IDC_LABEL_SCANNED,
    IDC_VALUE_SCANNED,
    IDC_LABEL_SCAN_RATE,
    IDC_VALUE_SCAN_RATE,
    IDC_LABEL_REPLIES,
    IDC_VALUE_REPLIES,
    IDC_LABEL_REPLY_RATE,
    IDC_VALUE_REPLY_RATE,
    IDC_LABEL_OPENS,
    IDC_VALUE_OPENS,
    IDC_CHECK_VERBOSE
};

constexpr UINT WM_LOG_PING = WM_APP + 1;
constexpr UINT WM_LOG_RECV = WM_APP + 2;
constexpr UINT WM_LOG_OPEN = WM_APP + 3;
constexpr UINT WM_LOG_SUCCESS = WM_APP + 4;
constexpr UINT WM_SCAN_DONE = WM_APP + 5;
constexpr UINT WM_STATS = WM_APP + 6;

struct GuiState {
    HWND hwnd = nullptr;
    HWND start_btn = nullptr;
    HWND stop_btn = nullptr;
    HWND workers_edit = nullptr;
    HWND start_ip_edit = nullptr;
    HWND end_ip_edit = nullptr;
    HWND port_edit = nullptr;
    HWND ping_timeout_edit = nullptr;
    HWND verbose_check = nullptr;
    HWND stats_scanned = nullptr;
    HWND stats_scan_rate = nullptr;
    HWND stats_replies = nullptr;
    HWND stats_reply_rate = nullptr;
    HWND stats_opens = nullptr;
    HWND log_activity = nullptr;
    HWND log_success = nullptr;
    HFONT font = nullptr;
    std::thread scan_thread;
    std::atomic<bool> stop_flag{false};
    bool running = false;
    bool verbose = false;
};

GuiState g_gui;

void append_line(HWND control, const std::string& text) {
    if (!control) return;
    std::string line = text;
    if (line.empty() || line.back() != '\n') {
        line += "\r\n";
    }
    const int max_chars = 15000;
    const int trim_to = 12000;

    int len_before = GetWindowTextLengthA(control);
    SendMessageA(control, EM_SETSEL, len_before, len_before);
    SendMessageA(control, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(line.c_str()));

    int len_after = GetWindowTextLengthA(control);
    if (len_after > max_chars) {
        int remove_count = len_after - trim_to;
        if (remove_count > 0) {
            SendMessageA(control, EM_SETSEL, 0, remove_count);
            SendMessageA(control, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(""));
            int new_len = GetWindowTextLengthA(control);
            SendMessageA(control, EM_SETSEL, new_len, new_len);
        }
    }
}

void clear_log(HWND control) {
    if (control) {
        SetWindowTextA(control, "");
    }
}

std::string read_text(HWND control) {
    if (!control) return {};
    int len = GetWindowTextLengthA(control);
    std::string buffer(static_cast<size_t>(len) + 1, '\0');
    if (len > 0) {
        GetWindowTextA(control, buffer.data(), len + 1);
    }
    buffer.resize(static_cast<size_t>(len));
    return buffer;
}

void set_control_font(HWND control, HFONT font) {
    if (control && font) {
        SendMessage(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    }
}

void post_log(HWND hwnd, UINT msg, const std::string& text) {
    if (!IsWindow(hwnd)) return;
    auto payload = new std::string(text);
    PostMessage(hwnd, msg, 0, reinterpret_cast<LPARAM>(payload));
}

void layout_controls(int width, int height) {
    const int margin = 12;
    const int label_w = 110;
    const int edit_w = 190;
    const int row_h = 22;
    const int row_gap = 10;

    int y = margin;
    MoveWindow(GetDlgItem(g_gui.hwnd, IDC_LABEL_START_IP), margin, y, label_w, row_h, TRUE);
    MoveWindow(g_gui.start_ip_edit, margin + label_w + 6, y, edit_w, row_h + 2, TRUE);
    MoveWindow(GetDlgItem(g_gui.hwnd, IDC_LABEL_WORKERS), margin + label_w + edit_w + 24, y, label_w, row_h, TRUE);
    MoveWindow(g_gui.workers_edit, margin + label_w + edit_w + label_w + 30, y, 70, row_h + 2, TRUE);

    y += row_h + row_gap;
    MoveWindow(GetDlgItem(g_gui.hwnd, IDC_LABEL_END_IP), margin, y, label_w, row_h, TRUE);
    MoveWindow(g_gui.end_ip_edit, margin + label_w + 6, y, edit_w, row_h + 2, TRUE);
    MoveWindow(GetDlgItem(g_gui.hwnd, IDC_LABEL_PING), margin + label_w + edit_w + 24, y, label_w, row_h, TRUE);
    MoveWindow(g_gui.ping_timeout_edit, margin + label_w + edit_w + label_w + 30, y, 70, row_h + 2, TRUE);

    y += row_h + row_gap;
    MoveWindow(GetDlgItem(g_gui.hwnd, IDC_LABEL_PORT), margin, y, label_w, row_h, TRUE);
    MoveWindow(g_gui.port_edit, margin + label_w + 6, y, 90, row_h + 2, TRUE);
    MoveWindow(g_gui.verbose_check, margin + label_w + edit_w + 24, y, 220, row_h + 4, TRUE);

    MoveWindow(g_gui.start_btn, width - margin - 90, margin, 80, row_h + 6, TRUE);
    MoveWindow(g_gui.stop_btn, width - margin - 90, margin + row_h + row_gap, 80, row_h + 6, TRUE);

    // Stats row
    int stats_y = y + row_h + row_gap;
    int x = margin;
    const int label_small_w = 90;
    const int value_w = 90;
    auto place_stat = [&](int label_id, int value_id) {
        MoveWindow(GetDlgItem(g_gui.hwnd, label_id), x, stats_y, label_small_w, row_h, TRUE);
        MoveWindow(GetDlgItem(g_gui.hwnd, value_id), x + label_small_w + 4, stats_y, value_w, row_h, TRUE);
        x += label_small_w + value_w + 14;
    };
    place_stat(IDC_LABEL_SCANNED, IDC_VALUE_SCANNED);
    place_stat(IDC_LABEL_SCAN_RATE, IDC_VALUE_SCAN_RATE);
    place_stat(IDC_LABEL_REPLIES, IDC_VALUE_REPLIES);
    place_stat(IDC_LABEL_REPLY_RATE, IDC_VALUE_REPLY_RATE);
    place_stat(IDC_LABEL_OPENS, IDC_VALUE_OPENS);

    int inputs_bottom = stats_y + row_h;
    int log_top = inputs_bottom + margin;  // add breathing room under stats
    int available_height = height - log_top - margin;
    int spacing = 16;
    int log_height = available_height;
    int min_log_height = 200;
    if (log_height < min_log_height) log_height = min_log_height;
    int log_width = (width - margin * 2 - spacing) / 2;
    int col2_x = margin + log_width + spacing;

    MoveWindow(g_gui.log_activity, margin, log_top, log_width, log_height, TRUE);

    MoveWindow(g_gui.log_success, col2_x, log_top, log_width, log_height, TRUE);
}

void update_stats_ui(const StatSnapshot& snap) {
    auto set_val = [](HWND h, const std::string& s) {
        if (h) SetWindowTextA(h, s.c_str());
    };
    set_val(g_gui.stats_scanned, std::to_string(snap.scanned));
    {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << snap.scanned_rate;
        set_val(g_gui.stats_scan_rate, ss.str());
    }
    set_val(g_gui.stats_replies, std::to_string(snap.replies));
    {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2) << snap.replies_rate;
        set_val(g_gui.stats_reply_rate, ss.str());
    }
    set_val(g_gui.stats_opens, std::to_string(snap.opens));
}

void create_controls(HWND hwnd) {
    g_gui.hwnd = hwnd;
    g_gui.font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    CreateWindowExA(0, "STATIC", "Start IP", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                    reinterpret_cast<HMENU>(IDC_LABEL_START_IP), nullptr, nullptr);
    CreateWindowExA(0, "STATIC", "End IP", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                    reinterpret_cast<HMENU>(IDC_LABEL_END_IP), nullptr, nullptr);
    CreateWindowExA(0, "STATIC", "Port", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                    reinterpret_cast<HMENU>(IDC_LABEL_PORT), nullptr, nullptr);
    CreateWindowExA(0, "STATIC", "Workers", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                    reinterpret_cast<HMENU>(IDC_LABEL_WORKERS), nullptr, nullptr);
    CreateWindowExA(0, "STATIC", "Ping timeout (ms)", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                    reinterpret_cast<HMENU>(IDC_LABEL_PING), nullptr, nullptr);

    g_gui.start_ip_edit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", kDefaultStartIp, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_LEFT | ES_AUTOHSCROLL,
                                          0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_EDIT_START_IP), nullptr, nullptr);
    g_gui.end_ip_edit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", kDefaultEndIp, WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_LEFT | ES_AUTOHSCROLL,
                                        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_EDIT_END_IP), nullptr, nullptr);
    g_gui.port_edit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", std::to_string(kDefaultPort).c_str(),
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_LEFT | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd,
                                      reinterpret_cast<HMENU>(IDC_EDIT_PORT), nullptr, nullptr);
    g_gui.workers_edit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "32", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_LEFT | ES_AUTOHSCROLL,
                                         0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_EDIT_WORKERS), nullptr, nullptr);
    g_gui.ping_timeout_edit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "1000", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_LEFT | ES_AUTOHSCROLL,
                                              0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_EDIT_PING_TIMEOUT), nullptr, nullptr);

    g_gui.verbose_check = CreateWindowExA(0, "BUTTON", "Verbose (ping lifecycle)", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
                                          0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_CHECK_VERBOSE), nullptr, nullptr);

    g_gui.start_btn = CreateWindowExA(0, "BUTTON", "Start", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                      0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BTN_START), nullptr, nullptr);
    g_gui.stop_btn = CreateWindowExA(0, "BUTTON", "Stop", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                                     0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(IDC_BTN_STOP), nullptr, nullptr);
    EnableWindow(g_gui.stop_btn, FALSE);

    CreateWindowExA(0, "STATIC", "IPs scanned:", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                    reinterpret_cast<HMENU>(IDC_LABEL_SCANNED), nullptr, nullptr);
    g_gui.stats_scanned = CreateWindowExA(0, "STATIC", "0", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                          reinterpret_cast<HMENU>(IDC_VALUE_SCANNED), nullptr, nullptr);
    CreateWindowExA(0, "STATIC", "IPs/s (60s):", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                    reinterpret_cast<HMENU>(IDC_LABEL_SCAN_RATE), nullptr, nullptr);
    g_gui.stats_scan_rate = CreateWindowExA(0, "STATIC", "0.0", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                            reinterpret_cast<HMENU>(IDC_VALUE_SCAN_RATE), nullptr, nullptr);
    CreateWindowExA(0, "STATIC", "Replies:", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                    reinterpret_cast<HMENU>(IDC_LABEL_REPLIES), nullptr, nullptr);
    g_gui.stats_replies = CreateWindowExA(0, "STATIC", "0", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                          reinterpret_cast<HMENU>(IDC_VALUE_REPLIES), nullptr, nullptr);
    CreateWindowExA(0, "STATIC", "Replies/s (60s):", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                    reinterpret_cast<HMENU>(IDC_LABEL_REPLY_RATE), nullptr, nullptr);
    g_gui.stats_reply_rate = CreateWindowExA(0, "STATIC", "0.0", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                             reinterpret_cast<HMENU>(IDC_VALUE_REPLY_RATE), nullptr, nullptr);
    CreateWindowExA(0, "STATIC", "MC servers:", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                    reinterpret_cast<HMENU>(IDC_LABEL_OPENS), nullptr, nullptr);
    g_gui.stats_opens = CreateWindowExA(0, "STATIC", "0", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                        reinterpret_cast<HMENU>(IDC_VALUE_OPENS), nullptr, nullptr);

    auto log_style = WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_BORDER;
    g_gui.log_activity = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", log_style, 0, 0, 0, 0, hwnd,
                                         reinterpret_cast<HMENU>(IDC_LOG_ACTIVITY), nullptr, nullptr);
    g_gui.log_success = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", log_style, 0, 0, 0, 0, hwnd,
                                         reinterpret_cast<HMENU>(IDC_LOG_SUCCESS), nullptr, nullptr);

    for (HWND h : {g_gui.start_ip_edit, g_gui.end_ip_edit, g_gui.port_edit, g_gui.workers_edit, g_gui.ping_timeout_edit,
                   g_gui.verbose_check, g_gui.start_btn, g_gui.stop_btn, g_gui.log_activity, g_gui.log_success,
                   GetDlgItem(hwnd, IDC_LABEL_START_IP), GetDlgItem(hwnd, IDC_LABEL_END_IP), GetDlgItem(hwnd, IDC_LABEL_PORT),
                   GetDlgItem(hwnd, IDC_LABEL_WORKERS), GetDlgItem(hwnd, IDC_LABEL_PING), GetDlgItem(hwnd, IDC_LABEL_SCANNED),
                   GetDlgItem(hwnd, IDC_LABEL_SCAN_RATE), GetDlgItem(hwnd, IDC_LABEL_REPLIES), GetDlgItem(hwnd, IDC_LABEL_REPLY_RATE),
                   GetDlgItem(hwnd, IDC_LABEL_OPENS), g_gui.stats_scanned, g_gui.stats_scan_rate, g_gui.stats_replies,
                   g_gui.stats_reply_rate, g_gui.stats_opens}) {
        set_control_font(h, g_gui.font);
    }

    RECT rc{};
    GetClientRect(hwnd, &rc);
    layout_controls(rc.right - rc.left, rc.bottom - rc.top);
}

void set_inputs_enabled(bool enabled) {
    EnableWindow(g_gui.start_ip_edit, enabled);
    EnableWindow(g_gui.end_ip_edit, enabled);
    EnableWindow(g_gui.port_edit, enabled);
    EnableWindow(g_gui.workers_edit, enabled);
    EnableWindow(g_gui.ping_timeout_edit, enabled);
    EnableWindow(g_gui.verbose_check, enabled);
}

void handle_stop(bool silent) {
    if (!g_gui.running) return;
    g_gui.stop_flag.store(true);
    if (!silent) {
        append_line(g_gui.log_activity, "Stop requested...");
    }
}

void handle_start() {
    if (g_gui.running) return;

    std::string start_ip = trim_copy(read_text(g_gui.start_ip_edit));
    std::string end_ip = trim_copy(read_text(g_gui.end_ip_edit));
    if (start_ip.empty()) start_ip = kDefaultStartIp;
    if (end_ip.empty()) end_ip = kDefaultEndIp;

    auto parse_int = [](const std::string& text, int fallback, int min_val) {
        try {
            return std::max(min_val, std::stoi(trim_copy(text)));
        } catch (...) {
            return fallback;
        }
    };
    int workers = parse_int(read_text(g_gui.workers_edit), 32, 1);
    int ping_ms = parse_int(read_text(g_gui.ping_timeout_edit), 1000, 100);
    int port_val = parse_int(read_text(g_gui.port_edit), kDefaultPort, 1);
    g_gui.verbose = (SendMessage(g_gui.verbose_check, BM_GETCHECK, 0, 0) == BST_CHECKED);

    clear_log(g_gui.log_activity);
    clear_log(g_gui.log_success);
    update_stats_ui(StatSnapshot{});

    Options opts;
    opts.start_ip = start_ip;
    opts.end_ip = end_ip;
    opts.port = port_val;
    opts.workers = workers;
    opts.ping_timeout_sec = ping_ms / 1000.0;
    opts.verbose = g_gui.verbose;

    g_gui.stop_flag.store(false);
    g_gui.running = true;
    set_inputs_enabled(false);
    EnableWindow(g_gui.start_btn, FALSE);
    EnableWindow(g_gui.stop_btn, TRUE);

    append_line(g_gui.log_activity, "Starting scan...");

    ScanCallbacks callbacks;
    callbacks.on_ping_lifecycle = [&](const std::string& msg) {
        if (g_gui.verbose) {
            post_log(g_gui.hwnd, WM_LOG_PING, msg);
        }
    };
    callbacks.on_ping_success = [&](const std::string& msg) { post_log(g_gui.hwnd, WM_LOG_RECV, msg); };
    callbacks.on_open = [&](const std::string& msg) {
        if (msg.rfind("[OPEN NON-MC]", 0) == 0 || msg.rfind("LOG:", 0) == 0) {
            post_log(g_gui.hwnd, WM_LOG_SUCCESS, msg);
        }
    };
    callbacks.on_info = [&](const std::string& msg) { post_log(g_gui.hwnd, WM_LOG_PING, msg); };
    callbacks.on_verbose = [&](const std::string& msg) { post_log(g_gui.hwnd, WM_LOG_PING, msg); };
    const int port = opts.port;
    const int proxy_port = opts.proxy_port;
    callbacks.on_result = [port, proxy_port](const Result& r) {
        std::ostringstream ss;
        std::string mc_line = r.mc_status.empty() ? (r.target_ip + ":" + std::to_string(port)) : r.mc_status;
        ss << "[MC] " << mc_line << " via proxy " << r.proxy_ip << ":" << proxy_port
           << " (port check " << std::fixed << std::setprecision(2) << r.elapsed_sec << "s)";
        post_log(g_gui.hwnd, WM_LOG_SUCCESS, ss.str());
    };
    callbacks.on_stats = [&](const StatSnapshot& snap) {
        auto payload = new StatSnapshot(snap);
        PostMessage(g_gui.hwnd, WM_STATS, 0, reinterpret_cast<LPARAM>(payload));
    };

    g_gui.scan_thread = std::thread([opts, callbacks]() mutable {
        std::vector<Result> results;
        bool ok = run_scan(opts, callbacks, g_gui.stop_flag, results);
        write_results_to_file(results, opts);
        if (IsWindow(g_gui.hwnd)) {
            LPARAM stopped = g_gui.stop_flag.load() ? 1 : 0;
            PostMessage(g_gui.hwnd, WM_SCAN_DONE, ok ? 1 : 0, stopped);
        }
    });
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            create_controls(hwnd);
            return 0;
        case WM_SIZE:
            layout_controls(static_cast<int>(LOWORD(lParam)), static_cast<int>(HIWORD(lParam)));
            return 0;
        case WM_COMMAND: {
            int id = LOWORD(wParam);
            if (id == IDC_BTN_START) {
                handle_start();
                return 0;
            }
            if (id == IDC_BTN_STOP) {
                handle_stop(false);
                return 0;
            }
            break;
        }
        case WM_LOG_PING:
            if (auto* s = reinterpret_cast<std::string*>(lParam)) {
                append_line(g_gui.log_activity, *s);
                delete s;
            }
            return 0;
        case WM_LOG_RECV:
            if (auto* s = reinterpret_cast<std::string*>(lParam)) {
                append_line(g_gui.log_activity, *s);
                delete s;
            }
            return 0;
        case WM_LOG_OPEN:
            if (auto* s = reinterpret_cast<std::string*>(lParam)) {
                append_line(g_gui.log_success, *s);
                delete s;
            }
            return 0;
        case WM_LOG_SUCCESS:
            if (auto* s = reinterpret_cast<std::string*>(lParam)) {
                append_line(g_gui.log_success, *s);
                delete s;
            }
            return 0;
        case WM_SCAN_DONE:
            if (g_gui.scan_thread.joinable()) {
                g_gui.scan_thread.join();
            }
            g_gui.running = false;
            EnableWindow(g_gui.start_btn, TRUE);
            EnableWindow(g_gui.stop_btn, FALSE);
            set_inputs_enabled(true);
            if (wParam == 0) {
                append_line(g_gui.log_activity, "Scan ended early or failed.");
            } else if (lParam != 0) {
                append_line(g_gui.log_activity, "Scan stopped by user.");
            } else {
                append_line(g_gui.log_activity, "Scan completed.");
            }
            return 0;
        case WM_STATS:
            if (auto* s = reinterpret_cast<StatSnapshot*>(lParam)) {
                update_stats_ui(*s);
                delete s;
            }
            return 0;
        case WM_CLOSE:
            handle_stop(true);
            if (g_gui.scan_thread.joinable()) {
                g_gui.scan_thread.join();
            }
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int run_gui() {
    WinsockInit winsock_guard;
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASSEXA wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "ScannerGuiWindow";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    if (!RegisterClassExA(&wc)) {
        MessageBoxA(nullptr, "Failed to register window class.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    int width = 1050;
    int height = 800;
    HWND hwnd = CreateWindowExA(0, wc.lpszClassName, "Proxy-backed Scanner", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                                CW_USEDEFAULT, CW_USEDEFAULT, width, height, nullptr, nullptr, wc.hInstance, nullptr);
    if (!hwnd) {
        MessageBoxA(nullptr, "Failed to create window.", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return static_cast<int>(msg.wParam);
}

#else

int run_gui() {
    std::cerr << "GUI mode is only available on Windows builds.\n";
    return 1;
}

#endif

}  // namespace

int main(int argc, char** argv) {
#ifdef _WIN32
    bool launch_gui = (argc == 1);
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--gui") {
            launch_gui = true;
            break;
        }
    }
    if (launch_gui) {
        return run_gui();
    }
#endif
    return run_console(argc, argv);
}
