/* pnscan_core.cpp - C++ DLL implementation of a threaded port/banner/SSL scanner 


    Author      : Gregory King
    Date        : 03/22/25

*/
/*
// for use in c#
public static class PnScanNative
{
    [DllImport("pnscan_core.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool startScan(
        [MarshalAs(UnmanagedType.LPStr)] string ipStart,
        [MarshalAs(UnmanagedType.LPStr)] string ipEnd,
        int portStart,
        int portEnd,
        [MarshalAs(UnmanagedType.Bool)] bool useSSL);

    [DllImport("pnscan_core.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void stopScan();

    [DllImport("pnscan_core.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void setMaxThreads(int count);

    [DllImport("pnscan_core.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void setScanMode(int mode);

    [DllImport("pnscan_core.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void setConnectTimeoutMs(int ms);

    [DllImport("pnscan_core.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void setSendData(
        [MarshalAs(UnmanagedType.LPStr)] string raw,
        int len);

    [DllImport("pnscan_core.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void setBannerMatch(
        [MarshalAs(UnmanagedType.LPStr)] string pattern);

    [DllImport("pnscan_core.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern bool isScanning();

    [DllImport("pnscan_core.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr getLog();

    [DllImport("pnscan_core.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void clearLog();

    public static string GetLog()
    {
        IntPtr ptr = getLog();
        return Marshal.PtrToStringAnsi(ptr);
    }
}
*/
#define _CRT_SECURE_NO_WARNINGS
#define MAX_SOCKETS 128

#include "pnscan_core.h"
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <sstream>
#include <iostream>
#include <map>
#include <queue>
#include <set>
#include <condition_variable>
#include <cstring>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <chrono>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

using namespace boost::asio;
using namespace boost::asio::ip;
using namespace std;

// global state
static std::atomic<bool> running{ false };
static std::atomic<int> threadCount{ 32 };
static std::atomic<int> scanMode{ SCAN_PORT_ONLY };
static std::atomic<int> timeoutMs{ 3000 };
static BannerCallback callback = nullptr;

static std::string matchString;
static std::string sendData;
static std::string logBuffer;
static std::mutex logMutex;

// Semaphore replacement for C++14
class Semaphore {
public:
    explicit Semaphore(int count) : count_(count) {}
    void acquire() {
        std::unique_lock<std::mutex> lock(mtx_);
        cv_.wait(lock, [&]{ return count_ > 0; });
        --count_;
    }
    void release() {
        std::unique_lock<std::mutex> lock(mtx_);
        ++count_;
        cv_.notify_one();
    }
private:
    std::mutex mtx_;
    std::condition_variable cv_;
    int count_;
};

Semaphore socketLimiter(MAX_SOCKETS);

// helper: log
void appendLog(const std::string& msg) {
    std::lock_guard<std::mutex> lock(logMutex);
    logBuffer += msg + "\n";
}

const char* getLog() {
    std::lock_guard<std::mutex> lock(logMutex);
    return logBuffer.c_str();
}

void clearLog() {
    std::lock_guard<std::mutex> lock(logMutex);
    logBuffer.clear();
}

void setMaxThreads(int count) { threadCount = count; }
void setScanMode(int mode) { scanMode = mode; }
void setConnectTimeoutMs(int ms) { timeoutMs = ms; }
void setSendData(const char* raw, int len) { sendData = std::string(raw, len); }
void setBannerMatch(const char* pattern) {
    matchString.clear();
    for (size_t i = 0; i < strlen(pattern); ++i) {
        if (pattern[i] == '\\' && i + 1 < strlen(pattern)) {
            switch (pattern[i + 1]) {
            case 'r': matchString += '\r'; break;
            case 'n': matchString += '\n'; break;
            case 't': matchString += '\t'; break;
            default: matchString += pattern[i + 1]; break;
            }
            ++i;
        }
        else {
            matchString += pattern[i];
        }
    }
}

void setBannerCallback(BannerCallback cb) { callback = cb; }

bool isScanning() { return running.load(); }

unsigned int ipToInt(const std::string& ip) {
    unsigned int a, b, c, d;
    sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
    return (a << 24) | (b << 16) | (c << 8) | d;
}

std::string intToIp(unsigned int ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
        std::to_string((ip >> 16) & 0xFF) + "." +
        std::to_string((ip >> 8) & 0xFF) + "." +
        std::to_string(ip & 0xFF);
}

void scanWorker(std::queue<std::pair<std::string, int>>& targets, std::mutex& qMutex, bool useSSL) {
    io_context ctx;
    ssl::context sslCtx(ssl::context::sslv23);
    sslCtx.set_default_verify_paths();

    while (running) {
        std::pair<std::string, int> target;
        {
            std::lock_guard<std::mutex> lock(qMutex);
            if (targets.empty()) break;
            target = targets.front();
            targets.pop();
        }

        socketLimiter.acquire();
        try {
            tcp::endpoint endpoint(make_address(target.first), target.second);
            std::string banner;

            if (useSSL) {
                ssl::stream<tcp::socket> stream(ctx, sslCtx);
                stream.lowest_layer().connect(endpoint);
                stream.handshake(ssl::stream_base::client);

                if (!sendData.empty()) write(stream, buffer(sendData));
                char buf[1024] = { 0 };
                size_t len = stream.read_some(buffer(buf));
                banner.assign(buf, len);
            }
            else {
                tcp::socket sock(ctx);
                sock.open(tcp::v4());
                sock.non_blocking(false);

                // --- Set socket timeouts using setsockopt ---
                int ms = timeoutMs.load();
#ifdef _WIN32
                DWORD timeout = static_cast<DWORD>(ms);
                setsockopt(sock.native_handle(), SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
                setsockopt(sock.native_handle(), SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
                struct timeval tv;
                tv.tv_sec = ms / 1000;
                tv.tv_usec = (ms % 1000) * 1000;
                setsockopt(sock.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                setsockopt(sock.native_handle(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
                // --- End setsockopt ---

                sock.connect(endpoint);

                if (!sendData.empty()) write(sock, buffer(sendData));
                char buf[1024] = { 0 };
                size_t len = sock.read_some(buffer(buf));
                banner.assign(buf, len);
            }

            if (!matchString.empty() && banner == matchString && callback) {
                callback(target.first.c_str(), target.second, banner.c_str());
                appendLog("Match: " + target.first + ":" + std::to_string(target.second));
            }
            else if (matchString.empty()) {
                appendLog("Open: " + target.first + ":" + std::to_string(target.second));
            }
        }
        catch (...) {
            // ignore errors
        }
        socketLimiter.release();
    }
}

bool startScan(const char* ipStart, const char* ipEnd, int portStart, int portEnd, bool useSSL) {
    if (running) return false;
    running = true;
    std::queue<std::pair<std::string, int>> targets;
    std::mutex qMutex;

    unsigned int ip1 = ipToInt(ipStart);
    unsigned int ip2 = ipToInt(ipEnd);
    for (unsigned int ip = ip1; ip <= ip2; ++ip) {
        for (int port = portStart; port <= portEnd; ++port) {
            targets.push({ intToIp(ip), port });
        }
    }

    std::vector<std::thread> workers;
    for (int i = 0; i < threadCount; ++i) {
        workers.emplace_back(scanWorker, std::ref(targets), std::ref(qMutex), useSSL);
    }

    for (auto& t : workers) t.join();

    running = false;
    return true;
}

void stopScan() {
    running = false;
    appendLog("stopScan() called");
}
