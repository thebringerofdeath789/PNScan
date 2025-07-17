/* pnscan_core.h - Exported DLL header for pnscan-style scanner with SSL and banner callback support */

#pragma once

#define OPENSSL_STATIC
#define OPENSSL_USE_STATIC_LIBS

#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

    // scan modes
    enum ScanMode {
        SCAN_PORT_ONLY = 0,     // only check if port is open
        SCAN_BANNER = 1,        // TCP banner scan
        SCAN_SSL_BANNER = 2     // SSL/TLS banner scan
    };

    // callback prototype
    typedef void(__stdcall* BannerCallback)(const char* ip, int port, const char* banner);

    // scan control
    DLL_EXPORT bool startScan(const char* ipStart, const char* ipEnd, int portStart, int portEnd, bool useSSL);
    DLL_EXPORT void stopScan();
    DLL_EXPORT bool isScanning();
    DLL_EXPORT void setMaxThreads(int count);

    // config
    DLL_EXPORT void setScanMode(int mode); // use ScanMode enum
    DLL_EXPORT void setConnectTimeoutMs(int ms);
    DLL_EXPORT void setSendData(const char* raw, int len);
    DLL_EXPORT void setBannerMatch(const char* pattern);

    // callback
    DLL_EXPORT void setBannerCallback(BannerCallback cb);

    // log/debug
    DLL_EXPORT const char* getLog();
    DLL_EXPORT void clearLog();

#ifdef __cplusplus
}
#endif
