/**
 * WinInetHook.cpp
 * WinInet API Hook 实现 - 拦截和重定向网络请求
 * 老王出品 - 安全测试专用
 *
 * 使用 MinHook 库进行 API Hook
 * 下载地址: https://github.com/TsudaKageworthy/minhook
 */

#include "WinInetHook.h"
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>
#include <mutex>

// MinHook 头文件 (需要添加到项目中)
#include "MinHook.h"
#pragma comment(lib, "libMinHook.x64.lib")

// ============================================
// 全局配置
// ============================================
static char g_szRedirectHost[256] = "127.0.0.1";
static INTERNET_PORT g_nRedirectPort = 2028;
static BOOL g_bLoggingEnabled = TRUE;
static std::vector<std::string> g_vecInterceptDomains;
static std::mutex g_mtxConfig;

// 日志输出宏
#define HOOK_LOG(fmt, ...) do { \
    if (g_bLoggingEnabled) { \
        printf("[WinInetHook] " fmt "\n", ##__VA_ARGS__); \
        OutputDebugStringA("[WinInetHook] "); \
        char _buf[1024]; \
        sprintf_s(_buf, fmt "\n", ##__VA_ARGS__); \
        OutputDebugStringA(_buf); \
    } \
} while(0)

// ============================================
// 原始函数指针
// ============================================
typedef HINTERNET (WINAPI *PFN_InternetConnectA)(
    HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort,
    LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);

typedef HINTERNET (WINAPI *PFN_InternetConnectW)(
    HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort,
    LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);

typedef HINTERNET (WINAPI *PFN_HttpOpenRequestA)(
    HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion,
    LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);

typedef HINTERNET (WINAPI *PFN_HttpOpenRequestW)(
    HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion,
    LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);

typedef BOOL (WINAPI *PFN_HttpSendRequestA)(
    HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength);

typedef BOOL (WINAPI *PFN_HttpSendRequestW)(
    HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength);

typedef BOOL (WINAPI *PFN_InternetReadFile)(
    HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);

// 原始函数指针存储
static PFN_InternetConnectA fpInternetConnectA = NULL;
static PFN_InternetConnectW fpInternetConnectW = NULL;
static PFN_HttpOpenRequestA fpHttpOpenRequestA = NULL;
static PFN_HttpOpenRequestW fpHttpOpenRequestW = NULL;
static PFN_HttpSendRequestA fpHttpSendRequestA = NULL;
static PFN_HttpSendRequestW fpHttpSendRequestW = NULL;
static PFN_InternetReadFile fpInternetReadFile = NULL;

// ============================================
// 辅助函数
// ============================================

// 检查域名是否需要拦截
static BOOL ShouldIntercept(const char* szDomain)
{
    if (!szDomain) return FALSE;

    std::lock_guard<std::mutex> lock(g_mtxConfig);

    // 如果没有配置拦截域名，默认拦截所有
    if (g_vecInterceptDomains.empty()) {
        return TRUE;
    }

    std::string domain(szDomain);
    for (const auto& d : g_vecInterceptDomains) {
        if (domain.find(d) != std::string::npos) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL ShouldInterceptW(const wchar_t* wszDomain)
{
    if (!wszDomain) return FALSE;

    // 转换为ANSI
    char szDomain[256] = {0};
    WideCharToMultiByte(CP_ACP, 0, wszDomain, -1, szDomain, sizeof(szDomain), NULL, NULL);
    return ShouldIntercept(szDomain);
}

// 安全读取字符串用于日志
static std::string SafeReadString(LPVOID lpData, DWORD dwLen)
{
    if (!lpData || dwLen == 0) return "<empty>";

    std::string result;
    result.reserve(dwLen + 1);

    const char* p = (const char*)lpData;
    for (DWORD i = 0; i < dwLen && i < 4096; i++) {
        if (p[i] >= 32 && p[i] < 127) {
            result += p[i];
        } else if (p[i] == '\r' || p[i] == '\n') {
            result += ' ';
        } else {
            result += '.';
        }
    }

    if (dwLen > 4096) {
        result += "...(truncated)";
    }

    return result;
}

// ============================================
// Hook 函数实现
// ============================================

// InternetConnectA Hook - 这是重定向的关键！
HINTERNET WINAPI Hooked_InternetConnectA(
    HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort,
    LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
    HOOK_LOG("========== InternetConnectA ==========");
    HOOK_LOG("  [原始服务器]: %s:%d", lpszServerName ? lpszServerName : "<null>", nServerPort);

    // 检查是否需要重定向
    if (lpszServerName && ShouldIntercept(lpszServerName)) {
        HOOK_LOG("  [重定向到]: %s:%d", g_szRedirectHost, g_nRedirectPort);

        // 重定向到本地代理
        HINTERNET hResult = fpInternetConnectA(
            hInternet, g_szRedirectHost, g_nRedirectPort,
            lpszUserName, lpszPassword, dwService,
            dwFlags & ~INTERNET_FLAG_SECURE,  // 移除HTTPS标志，因为本地代理是HTTP
            dwContext);

        HOOK_LOG("  [Handle]: %p", hResult);
        return hResult;
    }

    // 不需要重定向，调用原始函数
    return fpInternetConnectA(hInternet, lpszServerName, nServerPort,
                              lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

// InternetConnectW Hook
HINTERNET WINAPI Hooked_InternetConnectW(
    HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort,
    LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
    char szServer[256] = {0};
    if (lpszServerName) {
        WideCharToMultiByte(CP_ACP, 0, lpszServerName, -1, szServer, sizeof(szServer), NULL, NULL);
    }

    HOOK_LOG("========== InternetConnectW ==========");
    HOOK_LOG("  [原始服务器]: %s:%d", szServer, nServerPort);

    if (lpszServerName && ShouldInterceptW(lpszServerName)) {
        HOOK_LOG("  [重定向到]: %s:%d", g_szRedirectHost, g_nRedirectPort);

        // 转换重定向主机为宽字符
        wchar_t wszRedirectHost[256];
        MultiByteToWideChar(CP_ACP, 0, g_szRedirectHost, -1, wszRedirectHost, 256);

        HINTERNET hResult = fpInternetConnectW(
            hInternet, wszRedirectHost, g_nRedirectPort,
            lpszUserName, lpszPassword, dwService,
            dwFlags & ~INTERNET_FLAG_SECURE,
            dwContext);

        HOOK_LOG("  [Handle]: %p", hResult);
        return hResult;
    }

    return fpInternetConnectW(hInternet, lpszServerName, nServerPort,
                              lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

// HttpOpenRequestA Hook - 记录请求路径
HINTERNET WINAPI Hooked_HttpOpenRequestA(
    HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion,
    LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
{
    HOOK_LOG("========== HttpOpenRequestA ==========");
    HOOK_LOG("  [HTTP方法]: %s", lpszVerb ? lpszVerb : "GET");
    HOOK_LOG("  [请求路径]: %s", lpszObjectName ? lpszObjectName : "/");
    HOOK_LOG("  [HTTP版本]: %s", lpszVersion ? lpszVersion : "HTTP/1.1");
    HOOK_LOG("  [Flags]: 0x%08X", dwFlags);

    // 移除HTTPS相关标志（因为重定向到本地HTTP代理）
    DWORD newFlags = dwFlags & ~(INTERNET_FLAG_SECURE);

    HINTERNET hResult = fpHttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion,
                                           lpszReferrer, lplpszAcceptTypes, newFlags, dwContext);

    HOOK_LOG("  [Handle]: %p", hResult);
    return hResult;
}

// HttpOpenRequestW Hook
HINTERNET WINAPI Hooked_HttpOpenRequestW(
    HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion,
    LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
{
    char szVerb[32] = {0}, szPath[1024] = {0};
    if (lpszVerb) WideCharToMultiByte(CP_ACP, 0, lpszVerb, -1, szVerb, sizeof(szVerb), NULL, NULL);
    if (lpszObjectName) WideCharToMultiByte(CP_ACP, 0, lpszObjectName, -1, szPath, sizeof(szPath), NULL, NULL);

    HOOK_LOG("========== HttpOpenRequestW ==========");
    HOOK_LOG("  [HTTP方法]: %s", szVerb[0] ? szVerb : "GET");
    HOOK_LOG("  [请求路径]: %s", szPath[0] ? szPath : "/");
    HOOK_LOG("  [Flags]: 0x%08X", dwFlags);

    DWORD newFlags = dwFlags & ~(INTERNET_FLAG_SECURE);

    HINTERNET hResult = fpHttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion,
                                           lpszReferrer, lplpszAcceptTypes, newFlags, dwContext);

    HOOK_LOG("  [Handle]: %p", hResult);
    return hResult;
}

// HttpSendRequestA Hook - 记录POST数据，这是最关键的！
BOOL WINAPI Hooked_HttpSendRequestA(
    HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength)
{
    HOOK_LOG("========== HttpSendRequestA ==========");

    if (lpszHeaders && dwHeadersLength > 0) {
        std::string headers = SafeReadString((LPVOID)lpszHeaders, dwHeadersLength);
        HOOK_LOG("  [请求头]: %s", headers.c_str());
    }

    if (lpOptional && dwOptionalLength > 0) {
        std::string postData = SafeReadString(lpOptional, dwOptionalLength);
        HOOK_LOG("  [POST数据长度]: %d", dwOptionalLength);
        HOOK_LOG("  [POST数据]: %s", postData.c_str());
    }

    BOOL bResult = fpHttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);

    HOOK_LOG("  [返回值]: %s", bResult ? "成功" : "失败");
    if (!bResult) {
        HOOK_LOG("  [错误码]: %d", GetLastError());
    }

    return bResult;
}

// HttpSendRequestW Hook
BOOL WINAPI Hooked_HttpSendRequestW(
    HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength)
{
    HOOK_LOG("========== HttpSendRequestW ==========");

    if (lpszHeaders && dwHeadersLength > 0) {
        char szHeaders[4096] = {0};
        WideCharToMultiByte(CP_ACP, 0, lpszHeaders, dwHeadersLength, szHeaders, sizeof(szHeaders), NULL, NULL);
        HOOK_LOG("  [请求头]: %s", szHeaders);
    }

    if (lpOptional && dwOptionalLength > 0) {
        std::string postData = SafeReadString(lpOptional, dwOptionalLength);
        HOOK_LOG("  [POST数据长度]: %d", dwOptionalLength);
        HOOK_LOG("  [POST数据]: %s", postData.c_str());
    }

    BOOL bResult = fpHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);

    HOOK_LOG("  [返回值]: %s", bResult ? "成功" : "失败");
    return bResult;
}

// InternetReadFile Hook - 记录响应数据
BOOL WINAPI Hooked_InternetReadFile(
    HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
{
    BOOL bResult = fpInternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);

    if (bResult && lpdwNumberOfBytesRead && *lpdwNumberOfBytesRead > 0) {
        // 只记录前512字节，避免日志太长
        DWORD dwLogLen = min(*lpdwNumberOfBytesRead, 512);
        std::string response = SafeReadString(lpBuffer, dwLogLen);

        HOOK_LOG("========== InternetReadFile ==========");
        HOOK_LOG("  [读取字节数]: %d", *lpdwNumberOfBytesRead);
        HOOK_LOG("  [响应数据]: %s", response.c_str());
    }

    return bResult;
}

// ============================================
// 公开接口实现
// ============================================

BOOL InitWinInetHook()
{
    HOOK_LOG("========================================");
    HOOK_LOG("老王的 WinInet Hook 模块初始化中...");
    HOOK_LOG("========================================");

    // 初始化 MinHook
    if (MH_Initialize() != MH_OK) {
        HOOK_LOG("艹！MinHook 初始化失败！");
        return FALSE;
    }

    HMODULE hWininet = GetModuleHandleA("wininet.dll");
    if (!hWininet) {
        hWininet = LoadLibraryA("wininet.dll");
    }

    if (!hWininet) {
        HOOK_LOG("艹！加载 wininet.dll 失败！");
        MH_Uninitialize();
        return FALSE;
    }

    HOOK_LOG("wininet.dll 基址: %p", hWininet);

    // 创建所有 Hook
    BOOL bSuccess = TRUE;

    // InternetConnectA
    if (MH_CreateHookApi(L"wininet.dll", "InternetConnectA",
                         (LPVOID)Hooked_InternetConnectA, (LPVOID*)&fpInternetConnectA) != MH_OK) {
        HOOK_LOG("Hook InternetConnectA 失败！");
        bSuccess = FALSE;
    }

    // InternetConnectW
    if (MH_CreateHookApi(L"wininet.dll", "InternetConnectW",
                         (LPVOID)Hooked_InternetConnectW, (LPVOID*)&fpInternetConnectW) != MH_OK) {
        HOOK_LOG("Hook InternetConnectW 失败！");
        bSuccess = FALSE;
    }

    // HttpOpenRequestA
    if (MH_CreateHookApi(L"wininet.dll", "HttpOpenRequestA",
                         (LPVOID)Hooked_HttpOpenRequestA, (LPVOID*)&fpHttpOpenRequestA) != MH_OK) {
        HOOK_LOG("Hook HttpOpenRequestA 失败！");
        bSuccess = FALSE;
    }

    // HttpOpenRequestW
    if (MH_CreateHookApi(L"wininet.dll", "HttpOpenRequestW",
                         (LPVOID)Hooked_HttpOpenRequestW, (LPVOID*)&fpHttpOpenRequestW) != MH_OK) {
        HOOK_LOG("Hook HttpOpenRequestW 失败！");
        bSuccess = FALSE;
    }

    // HttpSendRequestA
    if (MH_CreateHookApi(L"wininet.dll", "HttpSendRequestA",
                         (LPVOID)Hooked_HttpSendRequestA, (LPVOID*)&fpHttpSendRequestA) != MH_OK) {
        HOOK_LOG("Hook HttpSendRequestA 失败！");
        bSuccess = FALSE;
    }

    // HttpSendRequestW
    if (MH_CreateHookApi(L"wininet.dll", "HttpSendRequestW",
                         (LPVOID)Hooked_HttpSendRequestW, (LPVOID*)&fpHttpSendRequestW) != MH_OK) {
        HOOK_LOG("Hook HttpSendRequestW 失败！");
        bSuccess = FALSE;
    }

    // InternetReadFile
    if (MH_CreateHookApi(L"wininet.dll", "InternetReadFile",
                         (LPVOID)Hooked_InternetReadFile, (LPVOID*)&fpInternetReadFile) != MH_OK) {
        HOOK_LOG("Hook InternetReadFile 失败！");
        bSuccess = FALSE;
    }

    // 启用所有 Hook
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        HOOK_LOG("艹！启用 Hook 失败！");
        MH_Uninitialize();
        return FALSE;
    }

    HOOK_LOG("========================================");
    HOOK_LOG("WinInet Hook 初始化完成！");
    HOOK_LOG("重定向目标: %s:%d", g_szRedirectHost, g_nRedirectPort);
    HOOK_LOG("========================================");

    return bSuccess;
}

void UninitWinInetHook()
{
    HOOK_LOG("卸载 WinInet Hook...");

    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();

    HOOK_LOG("WinInet Hook 已卸载");
}

void SetRedirectTarget(const char* host, INTERNET_PORT port)
{
    std::lock_guard<std::mutex> lock(g_mtxConfig);

    if (host) {
        strncpy_s(g_szRedirectHost, host, sizeof(g_szRedirectHost) - 1);
    }
    g_nRedirectPort = port;

    HOOK_LOG("重定向目标已更新: %s:%d", g_szRedirectHost, g_nRedirectPort);
}

void AddInterceptDomain(const char* domain)
{
    if (!domain) return;

    std::lock_guard<std::mutex> lock(g_mtxConfig);
    g_vecInterceptDomains.push_back(domain);

    HOOK_LOG("添加拦截域名: %s", domain);
}

void EnableHookLogging(BOOL bEnable)
{
    g_bLoggingEnabled = bEnable;
}
