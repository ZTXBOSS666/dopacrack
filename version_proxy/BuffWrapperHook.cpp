/**
 * BuffWrapperHook.cpp
 * Hook buff_wrapper.dll internal functions - Plan B
 * By LaoWang - Precise Hook without WinInet
 *
 * Based on IDA Pro reverse analysis:
 * - sub_18003E950 (offset 0x3E950) - Proxy request function
 * - sub_18004DFB0 (offset 0x4DFB0) - HTTP POST wrapper
 * - sub_18004E760 (offset 0x4E760) - Actual HTTP request function
 */

#include "BuffWrapperHook.h"
#include "MinHook.h"
#include <VMProtectSDK.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <mutex>
#include <wininet.h>

#pragma comment(lib, "MinHook.x64.lib")

// ============================================
// Global Config
// ============================================
static char g_szRedirectHost[256] = "127.0.0.1";
static int g_nRedirectPort = 2028;
static BOOL g_bLoggingEnabled = FALSE;
static BOOL g_bHookInitialized = FALSE;
static HMODULE g_hBuffWrapper = NULL;

// Callback functions
static PFN_OnRequest g_pfnOnRequest = NULL;
static PFN_OnResponse g_pfnOnResponse = NULL;

// ============================================
// Log output - 老王的调试日志系统
// ============================================
static FILE* g_logFile = NULL;
static std::mutex g_logMutex;

static void InitLogFile() {
    if (g_logFile) return;
    char szLogPath[MAX_PATH];
    DWORD len = GetTempPathA(MAX_PATH, szLogPath);
    if (len > 0 && len < MAX_PATH - 30) {
        strcat_s(szLogPath, MAX_PATH, "buff_hook_debug.log");
    } else {
        strcpy_s(szLogPath, MAX_PATH, "buff_hook_debug.log");
    }
    g_logFile = fopen(szLogPath, "a");
    if (g_logFile) {
        fprintf(g_logFile, "\n\n========== NEW SESSION ==========\n");
        fprintf(g_logFile, "Log path: %s\n", szLogPath);
        fflush(g_logFile);
    }
}

static void WriteLog(const char* fmt, ...) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (!g_logFile) InitLogFile();
    if (!g_logFile) return;

    // 时间戳
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_logFile, "[%02d:%02d:%02d.%03d] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list args;
    va_start(args, fmt);
    vfprintf(g_logFile, fmt, args);
    va_end(args);

    fprintf(g_logFile, "\n");
    fflush(g_logFile);  // 立即刷新，防止崩溃丢日志
}

#define BUFF_LOG(fmt, ...) WriteLog(fmt, ##__VA_ARGS__)

// ============================================
// MSVC std::string structure reading
// MSVC x64 std::string layout:
// +0x00: 16 bytes SSO buffer or pointer to heap
// +0x10: size (8 bytes)
// +0x18: capacity (8 bytes)
// Total size: 0x20 (32 bytes)
// ============================================

// Read std::string content
static std::string ReadStdString(void* pStdString)
{
    if (!pStdString) return "<null>";

    try {
        unsigned char* ptr = (unsigned char*)pStdString;

        // Read size and capacity
        size_t size = *(size_t*)(ptr + 0x10);
        size_t capacity = *(size_t*)(ptr + 0x18);

        if (size == 0) return "";
        if (size > 0x100000) return "<size too large>";

        const char* dataPtr;
        if (capacity <= 15) {
            // SSO mode: data inside object
            dataPtr = (const char*)ptr;
        } else {
            // Heap mode: first pointer points to data
            dataPtr = *(const char**)ptr;
            if (!dataPtr) return "<null data ptr>";
        }

        return std::string(dataPtr, size);
    }
    catch (...) {
        return "<read error>";
    }
}

// Modify std::string content (for redirection)
static BOOL WriteStdString(void* pStdString, const std::string& newValue)
{
    if (!pStdString) return FALSE;

    try {
        // Safest approach: treat it as std::string and let std handle reallocation
        std::string* p = reinterpret_cast<std::string*>(pStdString);
        *p = newValue;
        return TRUE;
    }
    catch (...) {
        // Fallback to manual copy if assignment fails
        try {
            unsigned char* ptr = (unsigned char*)pStdString;
            size_t capacity = *(size_t*)(ptr + 0x18);
            size_t newSize = newValue.size();

            if (capacity <= 15) {
                if (newSize <= 15) {
                    memcpy(ptr, newValue.c_str(), newSize + 1);
                    *(size_t*)(ptr + 0x10) = newSize;
                    return TRUE;
                }
            } else {
                char* dataPtr = *(char**)ptr;
                if (dataPtr && newSize <= capacity) {
                    memcpy(dataPtr, newValue.c_str(), newSize + 1);
                    *(size_t*)(ptr + 0x10) = newSize;
                    return TRUE;
                }
            }
        } catch (...) {}
    }
    return FALSE;
}

// ============================================
// Function offset definitions (from IDA)
// ============================================
#define OFFSET_PROXY_REQUEST    0x3E950   // sub_18003E950 - Proxy request
#define OFFSET_HTTP_POST_WRAP   0x4DFB0   // sub_18004DFB0 - HTTP POST wrapper
#define OFFSET_HTTP_REQUEST     0x4E760   // sub_18004E760 - Actual HTTP request

// ============================================
// Original function type definitions
// ============================================

// sub_18003E950: __int64 __fastcall(void* retStruct, std::string* apiPath, std::string* postData, std::string* signKey)
typedef __int64 (__fastcall *PFN_ProxyRequest)(void* a1, void* a2, void* a3, void* a4);

// sub_18004DFB0: bool __fastcall(void* httpClient, std::string* path, std::string* postData, std::string* response, std::string* error)
typedef bool (__fastcall *PFN_HttpPostWrapper)(void* a1, void* a2, void* a3, void* a4, void* a5);

// sub_18004E760: bool __fastcall(void* httpClient, std::string* method, std::string* path, std::string* postData, std::string* response, std::string* error)
typedef bool (__fastcall *PFN_HttpRequest)(void* a1, void* a2, void* a3, void* a4, void* a5, void* a6);

// WinInet API types for detour
typedef HINTERNET (WINAPI *PFN_InternetConnectA)(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET (WINAPI *PFN_HttpOpenRequestA)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR *, DWORD, DWORD_PTR);

// Original function pointers
static PFN_ProxyRequest fpProxyRequest = NULL;
static PFN_HttpPostWrapper fpHttpPostWrapper = NULL;
static PFN_HttpRequest fpHttpRequest = NULL;
static PFN_InternetConnectA fpInternetConnectA = NULL;
static PFN_HttpOpenRequestA fpHttpOpenRequestA = NULL;

// Hook target addresses
static LPVOID g_pProxyRequest = NULL;
static LPVOID g_pHttpPostWrapper = NULL;
static LPVOID g_pHttpRequest = NULL;

// ============================================
// Hook function implementations
// ============================================

// Hook: Proxy request function (sub_3E950)
__int64 __fastcall Hooked_ProxyRequest(void* a1, void* a2, void* a3, void* a4)
{
    VMProtectBeginUltra("__int64 __fastcall Hooked_ProxyRequest(void*, void*, void*, void*)");
    std::string apiPath = ReadStdString(a2);
    std::string postData = ReadStdString(a3);
    std::string signKey = ReadStdString(a4);

    // Force redirect path (host/port 由 WinInet hook 改)
    std::string redirectPath = "/proxy_login.php?target=" + apiPath;
    WriteStdString(a2, redirectPath);

    BUFF_LOG("========== Proxy Request (sub_3E950) ==========");
    BUFF_LOG("  [Server]: auth.game1337.com:443 -> %s:%d (WinInet)", g_szRedirectHost, g_nRedirectPort);
    BUFF_LOG("  [API Path]: %s", apiPath.c_str());
    BUFF_LOG("  [Redirected To]: %s", redirectPath.c_str());
    BUFF_LOG("  [POST Data Len]: %zu", postData.size());
    BUFF_LOG("  [POST Data]: %s", postData.c_str());
    BUFF_LOG("  [Sign Key]: %s", signKey.c_str());

    // Call callback
    if (g_pfnOnRequest) {
        g_pfnOnRequest(apiPath.c_str(), postData.c_str(), signKey.c_str());
    }

    // Call original function
    __int64 result = fpProxyRequest(a1, a2, a3, a4);

    BUFF_LOG("  [Return]: %lld", result);
    BUFF_LOG("================================================");

    VMProtectEnd();
    return result;
}

// Hook: HTTP POST wrapper (sub_4DFB0)
bool __fastcall Hooked_HttpPostWrapper(void* a1, void* a2, void* a3, void* a4, void* a5)
{
    VMProtectBeginUltra("bool __fastcall Hooked_HttpPostWrapper(void*, void*, void*, void*, void*)");
    std::string path = ReadStdString(a2);
    std::string postData = ReadStdString(a3);

    // Keep path relative; host/port handled by WinInet hook
    std::string redirectPath = path;
    if (!redirectPath.empty() && redirectPath[0] != '/') {
        redirectPath = "/" + redirectPath;
    }
    WriteStdString(a2, redirectPath);

    BUFF_LOG("========== HTTP POST Wrapper (sub_4DFB0) ==========");
    BUFF_LOG("  [Request Path]: %s", path.c_str());
    BUFF_LOG("  [Redirected Path]: %s", redirectPath.c_str());
    BUFF_LOG("  [POST Data]: %s", postData.c_str());

    // Call original function
    bool result = fpHttpPostWrapper(a1, a2, a3, a4, a5);

    // Read response
    if (result) {
        std::string response = ReadStdString(a4);
        BUFF_LOG("  [Response]: %s", response.c_str());

        if (g_pfnOnResponse) {
            g_pfnOnResponse(response.c_str());
        }
    } else {
        std::string error = ReadStdString(a5);
        BUFF_LOG("  [Error]: %s", error.c_str());
    }

    BUFF_LOG("  [Return]: %s", result ? "SUCCESS" : "FAILED");
    BUFF_LOG("===================================================");

    VMProtectEnd();
    return result;
}

// Hook: Actual HTTP request (sub_4E760)
bool __fastcall Hooked_HttpRequest(void* a1, void* a2, void* a3, void* a4, void* a5, void* a6)
{
    VMProtectBeginUltra("bool __fastcall Hooked_HttpRequest(void*, void*, void*, void*, void*, void*)");
    std::string method = ReadStdString(a2);
    std::string path = ReadStdString(a3);
    std::string postData = ReadStdString(a4);

    BUFF_LOG("========== HTTP Request (sub_4E760) ==========");
    BUFF_LOG("  [HTTP Method]: %s", method.c_str());
    BUFF_LOG("  [Request Path]: %s", path.c_str());
    BUFF_LOG("  [Redirect Host]: %s:%d (WinInet hook)", g_szRedirectHost, g_nRedirectPort);
    BUFF_LOG("  [POST Data Len]: %zu", postData.size());
    BUFF_LOG("  [POST Data]: %s", postData.c_str());

    // Call original function
    bool result = fpHttpRequest(a1, a2, a3, a4, a5, a6);

    // Read response
    if (result) {
        std::string response = ReadStdString(a5);
        BUFF_LOG("  [Response]: %s", response.c_str());

        if (g_pfnOnResponse) {
            g_pfnOnResponse(response.c_str());
        }
    } else {
        std::string error = ReadStdString(a6);
        BUFF_LOG("  [Error]: %s", error.c_str());
    }

    BUFF_LOG("  [Return]: %s", result ? "SUCCESS" : "FAILED");
    BUFF_LOG("===============================================");

    VMProtectEnd();
    return result;
}

// Hook: InternetConnectA 重定向 host/port，强制 HTTP
HINTERNET WINAPI Hooked_InternetConnectA(
    HINTERNET hInternet,
    LPCSTR lpszServerName,
    INTERNET_PORT nServerPort,
    LPCSTR lpszUserName,
    LPCSTR lpszPassword,
    DWORD dwService,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    VMProtectBeginUltra("HINTERNET WINAPI Hooked_InternetConnectA(HINTERNET, LPCSTR, INTERNET_PORT, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR)");

    BUFF_LOG(">>> Hooked_InternetConnectA CALLED!");
    BUFF_LOG("  [Original Host]: %s", lpszServerName ? lpszServerName : "<null>");
    BUFF_LOG("  [Original Port]: %d", nServerPort);
    BUFF_LOG("  [Service]: %d, [Flags]: 0x%08X", dwService, dwFlags);

    const char* newHost = lpszServerName;
    INTERNET_PORT newPort = nServerPort;
    if (lpszServerName && _stricmp(lpszServerName, "auth.game1337.com") == 0) {
        newHost = g_szRedirectHost;
        newPort = (INTERNET_PORT)g_nRedirectPort;
        dwService = INTERNET_SERVICE_HTTP;
        BUFF_LOG("  [REDIRECT!] %s:%d -> %s:%d", lpszServerName, nServerPort, newHost, newPort);
    } else {
        BUFF_LOG("  [NO REDIRECT] Host not matched");
    }

    HINTERNET h = fpInternetConnectA ? fpInternetConnectA(hInternet, newHost, newPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext) : NULL;
    BUFF_LOG("  [Result Handle]: %p", h);

    VMProtectEnd();
    return h;
}

// Hook: HttpOpenRequestA 去掉 HTTPS 标志，忽略证书
HINTERNET WINAPI Hooked_HttpOpenRequestA(
    HINTERNET hConnect,
    LPCSTR lpszVerb,
    LPCSTR lpszObjectName,
    LPCSTR lpszVersion,
    LPCSTR lpszReferrer,
    LPCSTR *lplpszAcceptTypes,
    DWORD dwFlags,
    DWORD_PTR dwContext)
{
    VMProtectBeginUltra("HINTERNET WINAPI Hooked_HttpOpenRequestA(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR)");

    BUFF_LOG(">>> Hooked_HttpOpenRequestA CALLED!");
    BUFF_LOG("  [Verb]: %s", lpszVerb ? lpszVerb : "<null>");
    BUFF_LOG("  [Path]: %s", lpszObjectName ? lpszObjectName : "<null>");
    BUFF_LOG("  [Original Flags]: 0x%08X", dwFlags);

    DWORD newFlags = dwFlags;
    newFlags &= ~INTERNET_FLAG_SECURE;
    newFlags |= INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

    BUFF_LOG("  [New Flags]: 0x%08X (removed SECURE)", newFlags);

    HINTERNET h = fpHttpOpenRequestA ? fpHttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, newFlags, dwContext) : NULL;
    BUFF_LOG("  [Result Handle]: %p", h);

    VMProtectEnd();
    return h;
}

// ============================================
// Wait for module and hook
// ============================================
static DWORD WINAPI HookThread(LPVOID lpParam)
{
    VMProtectBeginUltra("DWORD WINAPI HookThread(LPVOID lpParam)");
    BUFF_LOG("========================================");
    BUFF_LOG("LaoWang's buff_wrapper.dll Hook Thread Started");
    BUFF_LOG("========================================");

    // Wait for buff_wrapper.dll to load
    int nRetry = 0;
    while (nRetry < 300) { // Max 30 seconds
        g_hBuffWrapper = GetModuleHandleA("buff_wrapper.dll");
        if (g_hBuffWrapper) break;
        Sleep(100);
        nRetry++;
    }

    if (!g_hBuffWrapper) {
        BUFF_LOG("ERROR: buff_wrapper.dll not loaded after 30s!");
        return 1;
    }

    BUFF_LOG("Found buff_wrapper.dll @ %p", g_hBuffWrapper);

    // Calculate function addresses
    BYTE* baseAddr = (BYTE*)g_hBuffWrapper;
    g_pProxyRequest = baseAddr + OFFSET_PROXY_REQUEST;
    g_pHttpPostWrapper = baseAddr + OFFSET_HTTP_POST_WRAP;
    g_pHttpRequest = baseAddr + OFFSET_HTTP_REQUEST;

    BUFF_LOG("Proxy Request Addr: %p (offset 0x%X)", g_pProxyRequest, OFFSET_PROXY_REQUEST);
    BUFF_LOG("HTTP POST Wrapper Addr: %p (offset 0x%X)", g_pHttpPostWrapper, OFFSET_HTTP_POST_WRAP);
    BUFF_LOG("HTTP Request Addr: %p (offset 0x%X)", g_pHttpRequest, OFFSET_HTTP_REQUEST);

    // Initialize MinHook
    if (MH_Initialize() != MH_OK) {
        BUFF_LOG("ERROR: MinHook init failed!");
        return 1;
    }

    BOOL bSuccess = TRUE;

    // Hook proxy request function
    // 暂停内部函数 Hook，避免踩结构崩溃。只靠 WinInet 重定向。
    // if (MH_CreateHook(g_pProxyRequest, (LPVOID)Hooked_ProxyRequest, (LPVOID*)&fpProxyRequest) != MH_OK) {
    //     BUFF_LOG("Hook Proxy Request FAILED!");
    //     bSuccess = FALSE;
    // } else {
    //     BUFF_LOG("Hook Proxy Request SUCCESS!");
    // }

    // Hook HTTP POST wrapper
    // if (MH_CreateHook(g_pHttpPostWrapper, (LPVOID)Hooked_HttpPostWrapper, (LPVOID*)&fpHttpPostWrapper) != MH_OK) {
    //     BUFF_LOG("Hook HTTP POST Wrapper FAILED!");
    //     bSuccess = FALSE;
    // } else {
    //     BUFF_LOG("Hook HTTP POST Wrapper SUCCESS!");
    // }

    // Hook actual HTTP request
    // if (MH_CreateHook(g_pHttpRequest, (LPVOID)Hooked_HttpRequest, (LPVOID*)&fpHttpRequest) != MH_OK) {
    //     BUFF_LOG("Hook HTTP Request FAILED!");
    //     bSuccess = FALSE;
    // } else {
    //     BUFF_LOG("Hook HTTP Request SUCCESS!");
    // }

    // Hook WinInet APIs for彻底重定向
    BUFF_LOG(">>> Starting WinInet Hook...");
    HMODULE hWininet = GetModuleHandleA("wininet.dll");
    BUFF_LOG("GetModuleHandleA(wininet.dll) = %p", hWininet);
    if (!hWininet) {
        hWininet = LoadLibraryA("wininet.dll");
        BUFF_LOG("LoadLibraryA(wininet.dll) = %p", hWininet);
    }
    if (hWininet) {
        LPVOID pConnectA = GetProcAddress(hWininet, "InternetConnectA");
        LPVOID pOpenReqA = GetProcAddress(hWininet, "HttpOpenRequestA");
        BUFF_LOG("GetProcAddress InternetConnectA = %p", pConnectA);
        BUFF_LOG("GetProcAddress HttpOpenRequestA = %p", pOpenReqA);

        // Hook InternetConnectA
        if (pConnectA) {
            MH_STATUS st = MH_CreateHook(pConnectA, (LPVOID)Hooked_InternetConnectA, (LPVOID*)&fpInternetConnectA);
            BUFF_LOG("MH_CreateHook InternetConnectA: status=%d, trampoline=%p", st, fpInternetConnectA);
            if (st == MH_OK) {
                BUFF_LOG("Hook InternetConnectA SUCCESS!");
            } else {
                BUFF_LOG("Hook InternetConnectA FAILED! MH_STATUS=%d", st);
            }
        } else {
            BUFF_LOG("ERROR: InternetConnectA not found!");
        }

        // Hook HttpOpenRequestA
        if (pOpenReqA) {
            MH_STATUS st = MH_CreateHook(pOpenReqA, (LPVOID)Hooked_HttpOpenRequestA, (LPVOID*)&fpHttpOpenRequestA);
            BUFF_LOG("MH_CreateHook HttpOpenRequestA: status=%d, trampoline=%p", st, fpHttpOpenRequestA);
            if (st == MH_OK) {
                BUFF_LOG("Hook HttpOpenRequestA SUCCESS!");
            } else {
                BUFF_LOG("Hook HttpOpenRequestA FAILED! MH_STATUS=%d", st);
            }
        } else {
            BUFF_LOG("ERROR: HttpOpenRequestA not found!");
        }
    } else {
        BUFF_LOG("ERROR: wininet.dll not found, skip API hooks");
    }

    // Enable all hooks
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        BUFF_LOG("ERROR: Enable hooks failed!");
        MH_Uninitialize();
        return 1;
    }

    g_bHookInitialized = TRUE;

    BUFF_LOG("========================================");
    BUFF_LOG("buff_wrapper.dll Hook Init Complete!");
    BUFF_LOG("========================================");

    VMProtectEnd();
    return 0;
}

// ============================================
// Public interface implementation
// ============================================

BOOL InitBuffWrapperHook()
{
    VMProtectBeginUltra("BOOL InitBuffWrapperHook()");
    BUFF_LOG("Starting buff_wrapper.dll Hook...");

    // Create hook thread
    HANDLE hThread = CreateThread(NULL, 0, HookThread, NULL, 0, NULL);
    if (!hThread) {
        BUFF_LOG("ERROR: Create hook thread failed!");
        return FALSE;
    }

    CloseHandle(hThread);
    VMProtectEnd();
    return TRUE;
}

void UninitBuffWrapperHook()
{
    VMProtectBeginUltra("void UninitBuffWrapperHook()");
    if (g_bHookInitialized) {
        BUFF_LOG("Unloading buff_wrapper.dll Hook...");
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        g_bHookInitialized = FALSE;
        BUFF_LOG("Hook unloaded");
    }
    VMProtectEnd();
}

void SetBuffRedirectTarget(const char* host, int port)
{
    VMProtectBeginUltra("void SetBuffRedirectTarget(const char*, int)");
    if (host) {
        strncpy_s(g_szRedirectHost, host, sizeof(g_szRedirectHost) - 1);
    }
    g_nRedirectPort = port;
    BUFF_LOG("Redirect target set: %s:%d", g_szRedirectHost, g_nRedirectPort);
    VMProtectEnd();
}

void EnableBuffHookLogging(BOOL bEnable)
{
    VMProtectBeginUltra("void EnableBuffHookLogging(BOOL)");
    g_bLoggingEnabled = bEnable;
    VMProtectEnd();
}

void SetRequestCallback(PFN_OnRequest callback)
{
    VMProtectBeginUltra("void SetRequestCallback(PFN_OnRequest)");
    g_pfnOnRequest = callback;
    VMProtectEnd();
}

void SetResponseCallback(PFN_OnResponse callback)
{
    VMProtectBeginUltra("void SetResponseCallback(PFN_OnResponse)");
    g_pfnOnResponse = callback;
    VMProtectEnd();
}
