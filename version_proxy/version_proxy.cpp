#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <commctrl.h>


#include <QPVerify.h>
#include <QPModX64.h>
#include <VMProtectSDK.h>
#pragma comment(lib, "comctl32.lib")


#include "BuffWrapperHook.h"


static HMODULE g_hOrigDll = NULL;
static HINSTANCE g_hInstance = NULL;
static BOOL g_bHooked = FALSE;
static BOOL g_bVerified = FALSE;
static BOOL g_bVerifyStarted = FALSE;
static CRITICAL_SECTION g_csVerify;
static HANDLE g_hVerifyEvent = NULL;
static volatile LONG g_bDelayInitStarted = 0;

// Forward declaration
__declspec(noinline) void EnsureDelayedInit();

#define IDC_EDIT_KEY        1001
#define IDC_BTN_VERIFY      1002
#define IDC_BTN_EXIT        1003
#define IDC_STATIC_TITLE    1004
#define IDC_STATIC_NOTICE   1005
#define IDC_EDIT_NOTICE     1006
#define IDC_STATIC_KEY      1007
#define IDC_STATIC_STATUS   1008


static HWND g_hWndMain = NULL;
static HWND g_hEditKey = NULL;
static HWND g_hEditNotice = NULL;
static HWND g_hStaticStatus = NULL;
static char g_szInputKey[256] = {0};
static BOOL g_bDialogResult = FALSE;


typedef int (*Py_IsInitialized_t)(void);
typedef int (*PyGILState_Ensure_t)(void);
typedef void (*PyGILState_Release_t)(int);
typedef int (*PyRun_SimpleString_t)(const char*);


static const char* g_szHookCode =
"import sys, gc\n"
"try:\n"
"    import urllib3; urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\n"
"except Exception:\n"
"    pass\n"
"try:\n"
"    import requests\n"
"    from unittest.mock import Mock\n"
"    if not hasattr(requests.Session, '_ztx_hooked'):\n"
"        requests.Session._ztx_hooked = True\n"
"        _orig_session_request = requests.Session.request\n"
"        def _patched_session_request(self, method, url, **kwargs):\n"
"            if 'api.52vmy.cn/api/wl/t/onip' in url:\n"
"                m = Mock(); m.status_code = 200; m.text = '{}'; m.content = b'{}'; m.headers = {'Content-Type': 'application/json'}; m.ok = True; m.json = lambda: {}; m.raise_for_status = lambda: None; return m\n"
"            if url.startswith('https://qqun.game1337.com'):\n"
"                m = Mock(); m.status_code = 200; m.text = '<h5 id=\"qqun\">ZTX PJ  QQqun:1038819520</h5>'; m.content = b'<h5 id=\"qqun\">ZTX PJ</h5>'; m.headers = {'Content-Type': 'text/html'}; m.ok = True; m.json = lambda: {}; m.raise_for_status = lambda: None; return m\n"
"            if 'auth.game1337.com' in url:\n"
"                url = url.replace('https://auth.game1337.com', 'http://127.0.0.1:2028')\n"
"            kwargs['verify'] = False\n"
"            return _orig_session_request(self, method, url, **kwargs)\n"
"        requests.Session.request = _patched_session_request\n"
"        def make_patch(f):\n"
"            def patched(*args, **kwargs):\n"
"                if args:\n"
"                    url = args[0]\n"
"                    if 'api.52vmy.cn/api/wl/t/onip' in url:\n"
"                        m = Mock(); m.status_code = 200; m.text = '{}'; m.content = b'{}'; m.json = lambda: {}; return m\n"
"                    if 'auth.game1337.com' in url:\n"
"                        args = (url.replace('https://auth.game1337.com', 'http://127.0.0.1:2028'),) + args[1:]\n"
"                kwargs['verify'] = False\n"
"                return f(*args, **kwargs)\n"
"            return patched\n"
"        for func_name in ['get', 'post', 'put', 'delete', 'head', 'options', 'patch']:\n"
"            orig_func = getattr(requests, func_name)\n"
"            setattr(requests, func_name, make_patch(orig_func))\n"
"except Exception:\n"
"    pass\n"
"def do_patch():\n"
"    patched = []\n"
"    if 'verify' in sys.modules:\n"
"        m = sys.modules['verify']\n"
"        for attr in dir(m):\n"
"            if 'verify' in attr.lower() or 'check' in attr.lower():\n"
"                try:\n"
"                    if callable(getattr(m, attr)):\n"
"                        setattr(m, attr, lambda *a, **k: True)\n"
"                        patched.append('verify')\n"
"                except:\n"
"                    pass\n"
"    if 'core' in sys.modules:\n"
"        m = sys.modules['core']\n"
"        if hasattr(m, 'Valorant'):\n"
"            m.Valorant.is_using_dopa_model = lambda self: True\n"
"            m.Valorant.is_using_encrypted_model = lambda self: True\n"
"            patched.append('core.Valorant')\n"
"    for obj in gc.get_objects():\n"
"        try:\n"
"            if type(obj).__name__ == 'Valorant' and not getattr(obj, '_p', False):\n"
"                obj.verified = True\n"
"                obj.decrypted_model_data = b'DOPA'\n"
"                obj.original_model_path = 'dopa.engine'\n"
"                obj.is_using_dopa_model = lambda: True\n"
"                obj.is_using_encrypted_model = lambda: True\n"
"                obj._p = True\n"
"                patched.append('Valorant instance')\n"
"        except:\n"
"            pass\n"
"    return patched\n"
"import threading, time\n"
"_ztx_count = [0]\n"
"def _ztx_loop():\n"
"    while True:\n"
"        try:\n"
"            r = do_patch()\n"
"            if r and _ztx_count[0] < 3:\n"
"                _ztx_count[0] += 1\n"
"        except:\n"
"            pass\n"
"        time.sleep(1)\n"
"threading.Thread(target=_ztx_loop, daemon=True).start()\n";


BOOL LoadDllFromRes(PVOID* pDllData, DWORD* dwDllSize)
{
    VMProtectBeginUltra("BOOL LoadDllFromRes(PVOID* pDllData, DWORD* dwDllSize)");
    *pDllData = QPModX64_;
    *dwDllSize = QPModX64_size;
    VMProtectEnd();
    return TRUE;
}


DWORD WINAPI HeartbeatThread(LPVOID lpParam)
{
    VMProtectBeginUltra("DWORD WINAPI HeartbeatThread(LPVOID lpParam)");
    bool pbStart = false;
    bool pbAutoExit = false;
    int pHearMs = 0;

    if (QPGetHearBeatConfig(&pbStart, &pbAutoExit, &pHearMs) == false)
    {
        return 1;
    }

    if (pHearMs < 0)
        pHearMs = 1000;

    while (true)
    {
        QPLocalExpVerify();
        if (pbStart)
        {
            if (QPSendHearBeat() == false)
            {
                if (pbAutoExit)
                    ExitProcess(0);
            }
        }
        Sleep(pHearMs);
    }
    VMProtectEnd();
    return 0;
}


void SaveKey(const char* szKey)
{
    char szKeyFile[MAX_PATH];
    GetModuleFileNameA(NULL, szKeyFile, MAX_PATH);
    char* pLastSlash = strrchr(szKeyFile, '\\');
    if (pLastSlash) {
        strcpy_s(pLastSlash + 1, MAX_PATH - (pLastSlash - szKeyFile + 1), "ztx_key.txt");
        FILE* f = fopen(szKeyFile, "w");
        if (f) {
            fprintf(f, "%s", szKey);
            fclose(f);
        }
    }
}


BOOL LoadKey(char* szKey, int nMaxLen)
{
    char szKeyFile[MAX_PATH];
    GetModuleFileNameA(NULL, szKeyFile, MAX_PATH);
    char* pLastSlash = strrchr(szKeyFile, '\\');
    if (pLastSlash) {
        strcpy_s(pLastSlash + 1, MAX_PATH - (pLastSlash - szKeyFile + 1), "ztx_key.txt");
        FILE* f = fopen(szKeyFile, "r");
        if (f) {
            BOOL bResult = FALSE;
            if (fgets(szKey, nMaxLen, f)) {
                char* pNewline = strchr(szKey, '\n');
                if (pNewline) *pNewline = '\0';
                pNewline = strchr(szKey, '\r');
                if (pNewline) *pNewline = '\0';
                if (strlen(szKey) > 10) {
                    bResult = TRUE;
                }
            }
            fclose(f);
            return bResult;
        }
    }
    return FALSE;
}


void UpdateStatus(const wchar_t* wszStatus)
{
    if (g_hStaticStatus) {
        SetWindowTextW(g_hStaticStatus, wszStatus);
    }
}


LRESULT CALLBACK VerifyWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    VMProtectBeginUltra("LRESULT CALLBACK VerifyWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)");
    switch (uMsg)
    {
    case WM_CREATE:
    {

        HFONT hFontTitle = CreateFontW(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");
        HFONT hFontNormal = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Microsoft YaHei UI");


        HWND hTitle = CreateWindowW(L"STATIC", L"\x6B22\x8FCE\x4F7F\x7528",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            0, 10, 380, 30, hWnd, (HMENU)IDC_STATIC_TITLE, g_hInstance, NULL);
        SendMessage(hTitle, WM_SETFONT, (WPARAM)hFontTitle, TRUE);


        HWND hNoticeLabel = CreateWindowW(L"STATIC", L"\x7CFB\x7EDF\x516C\x544A:",
            WS_CHILD | WS_VISIBLE,
            15, 50, 80, 20, hWnd, (HMENU)IDC_STATIC_NOTICE, g_hInstance, NULL);
        SendMessage(hNoticeLabel, WM_SETFONT, (WPARAM)hFontNormal, TRUE);


        g_hEditNotice = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            15, 75, 350, 80, hWnd, (HMENU)IDC_EDIT_NOTICE, g_hInstance, NULL);
        SendMessage(g_hEditNotice, WM_SETFONT, (WPARAM)hFontNormal, TRUE);


        HWND hKeyLabel = CreateWindowW(L"STATIC", L"\x8BF7\x8F93\x5165\x5361\x5BC6:",
            WS_CHILD | WS_VISIBLE,
            15, 165, 100, 20, hWnd, (HMENU)IDC_STATIC_KEY, g_hInstance, NULL);
        SendMessage(hKeyLabel, WM_SETFONT, (WPARAM)hFontNormal, TRUE);


        g_hEditKey = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            15, 190, 350, 25, hWnd, (HMENU)IDC_EDIT_KEY, g_hInstance, NULL);
        SendMessage(g_hEditKey, WM_SETFONT, (WPARAM)hFontNormal, TRUE);


        HWND hBtnVerify = CreateWindowW(L"BUTTON", L"\x9A8C\x8BC1\x6388\x6743",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            80, 230, 100, 30, hWnd, (HMENU)IDC_BTN_VERIFY, g_hInstance, NULL);
        SendMessage(hBtnVerify, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

        HWND hBtnExit = CreateWindowW(L"BUTTON", L"\x9000\x51FA\x7A0B\x5E8F",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            200, 230, 100, 30, hWnd, (HMENU)IDC_BTN_EXIT, g_hInstance, NULL);
        SendMessage(hBtnExit, WM_SETFONT, (WPARAM)hFontNormal, TRUE);


        g_hStaticStatus = CreateWindowW(L"STATIC", L"\x9A8C\x8BC1\x7CFB\x7EDF\x521D\x59CB\x5316\x5B8C\x6210\xFF0C\x8BF7\x8F93\x5165\x5361\x5BC6",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            0, 270, 380, 20, hWnd, (HMENU)IDC_STATIC_STATUS, g_hInstance, NULL);
        SendMessage(g_hStaticStatus, WM_SETFONT, (WPARAM)hFontNormal, TRUE);
        VMProtectEnd();
        return 0;
        
    }

    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);
        switch (wmId)
        {
        case IDC_BTN_VERIFY:
        {
            GetWindowTextA(g_hEditKey, g_szInputKey, sizeof(g_szInputKey));
            if (strlen(g_szInputKey) < 10) {
                UpdateStatus(L"\x5361\x5BC6\x957F\x5EA6\x4E0D\x8DB3\xFF0C\x8BF7\x91CD\x65B0\x8F93\x5165");
                return 0;
            }
            g_bDialogResult = TRUE;
            DestroyWindow(hWnd);
            return 0;
        }
        case IDC_BTN_EXIT:
            g_bDialogResult = FALSE;
            DestroyWindow(hWnd);
            ExitProcess(0);
            return 0;
        }
        break;
    }

    case WM_CLOSE:
        g_bDialogResult = FALSE;
        DestroyWindow(hWnd);
        ExitProcess(0);
        return 0;

    case WM_DESTROY:
        g_hWndMain = NULL;
        PostQuitMessage(0);
        return 0;
    }
    VMProtectEnd();
    return DefWindowProcW(hWnd, uMsg, wParam, lParam);
}

BOOL ShowVerifyDialogGUI(char* szKey, int nMaxLen, const char* szBulletin)
{
    VMProtectBeginUltra("BOOL ShowVerifyDialogGUI(char* szKey, int nMaxLen, const char* szBulletin)");
    if (LoadKey(szKey, nMaxLen)) {
        return TRUE; 
    }

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = VerifyWndProc;
    wc.hInstance = g_hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"ZTXVerifyClass";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassExW(&wc)) {
    }

    g_hWndMain = CreateWindowExW(
        WS_EX_TOPMOST,
        L"ZTXVerifyClass",
        L"\x6B22\x8FCE\x4F7F\x7528ZTX-DopaAI",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 330,
        NULL, NULL, g_hInstance, NULL);

    if (!g_hWndMain) {
        MessageBoxW(NULL, L"\x521B\x5EFA\x7A97\x53E3\x5931\x8D25", L"Error", MB_ICONERROR);
        return FALSE;
    }

    if (g_hEditNotice && szBulletin) {
        int len = MultiByteToWideChar(CP_ACP, 0, szBulletin, -1, NULL, 0);
        if (len > 0) {
            wchar_t* wszBulletin = new wchar_t[len];
            MultiByteToWideChar(CP_ACP, 0, szBulletin, -1, wszBulletin, len);
            SetWindowTextW(g_hEditNotice, wszBulletin);
            delete[] wszBulletin;
        }
    }

    ShowWindow(g_hWndMain, SW_SHOW);
    UpdateWindow(g_hWndMain);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if (g_bDialogResult && strlen(g_szInputKey) > 0) {
        strcpy_s(szKey, nMaxLen, g_szInputKey);
        VMProtectEnd();
        return TRUE;
    }
    VMProtectEnd();
    return FALSE;
}

BOOL DoVerify()
{
    VMProtectBeginUltra("BOOL DoVerify()");
    char szKey[256] = {0};
    char* szBulletin = NULL;
    if (!QPLibInit(LoadDllFromRes)) {
        MessageBoxW(NULL, L"\x9A8C\x8BC1\x6A21\x5757\x521D\x59CB\x5316\x5931\x8D25\xFF01", L"ZTX PJ", MB_ICONERROR);
        return FALSE;
    }
    //验证自己删除
    if (!QPInit()) {
        MessageBoxW(NULL, L"\x65E0\x6CD5\x8FDE\x63A5\x9A8C\x8BC1\x670D\x52A1\x5668\xFF01", L"ZTX PJ", MB_ICONERROR);
        return FALSE;
    }
    QPGetBulletin(&szBulletin);
    if (!ShowVerifyDialogGUI(szKey, sizeof(szKey), szBulletin)) {
        if (szBulletin) QPFree(szBulletin);
        MessageBoxW(NULL, L"\x672A\x8F93\x5165\x5361\x5BC6\xFF01", L"ZTX PJ", MB_ICONWARNING);
        return FALSE;
    }
    if (szBulletin) QPFree(szBulletin);


    if (!QPKeyLogin(szKey)) {
        char* pErr = QPGetLastErrorString();
        wchar_t wszMsg[512];
        wcscpy_s(wszMsg, 512, L"\x9A8C\x8BC1\x5931\x8D25: ");
        if (pErr) {
            int len = MultiByteToWideChar(CP_ACP, 0, pErr, -1, NULL, 0);
            if (len > 0 && len < 400) {
                MultiByteToWideChar(CP_ACP, 0, pErr, -1, wszMsg + wcslen(wszMsg), 400);
            }
            QPFree(pErr);
        } else {
            wcscat_s(wszMsg, 512, L"\x672A\x77E5\x9519\x8BEF");
        }
        MessageBoxW(NULL, wszMsg, L"ZTX PJ", MB_ICONERROR);
        return FALSE;
    }


    SaveKey(szKey);


    CreateThread(NULL, 0, HeartbeatThread, NULL, 0, NULL);


    char* szTime = SecToDay((double)QPToInt(QPGetLoginData(3)));
    char szMsg[256];
    sprintf_s(szMsg, sizeof(szMsg), "Verification Success!\nRemaining Time: %s", szTime ? szTime : "Unknown");
    MessageBoxA(NULL, szMsg, "ZTX PJ", MB_ICONINFORMATION);
    if (szTime) QPFree(szTime);
    VMProtectEnd();
    return TRUE;
	
}


DWORD WINAPI InjectThread(LPVOID lpParam)
{
    VMProtectBeginUltra("DWORD WINAPI InjectThread(LPVOID lpParam)");
    HMODULE hPython = NULL;
    int nRetry = 0;


    while (nRetry < 100)
    {
        hPython = GetModuleHandleA("python311.dll");
        if (hPython) break;
        hPython = GetModuleHandleA("python310.dll");
        if (hPython) break;
        hPython = GetModuleHandleA("python39.dll");
        if (hPython) break;
        Sleep(100);
        nRetry++;
    }

    if (!hPython) return 1;

    Py_IsInitialized_t Py_IsInitialized =
        (Py_IsInitialized_t)GetProcAddress(hPython, "Py_IsInitialized");

    nRetry = 0;
    while (nRetry < 100)
    {
        if (Py_IsInitialized && Py_IsInitialized()) break;
        Sleep(100);
        nRetry++;
    }

    Sleep(1000);

    PyGILState_Ensure_t PyGILState_Ensure =
        (PyGILState_Ensure_t)GetProcAddress(hPython, "PyGILState_Ensure");
    PyGILState_Release_t PyGILState_Release =
        (PyGILState_Release_t)GetProcAddress(hPython, "PyGILState_Release");
    PyRun_SimpleString_t PyRun_SimpleString =
        (PyRun_SimpleString_t)GetProcAddress(hPython, "PyRun_SimpleString");

    if (!PyGILState_Ensure || !PyGILState_Release || !PyRun_SimpleString) return 1;

    int delays[] = {500, 1000, 1500, 2000, 3000};
    for (int i = 0; i < 5; i++)
    {
        Sleep(delays[i]);
        int gstate = PyGILState_Ensure();
        int result = PyRun_SimpleString(g_szHookCode);
        PyGILState_Release(gstate);
        if (result == 0)
        {
            g_bHooked = TRUE;
            if (i >= 2) break;
        }
    }

    VMProtectEnd();
    return 0;
}


void CheckAndVerify()
{
    EnsureDelayedInit();
    VMProtectBeginUltra("void CheckAndVerify()");
    EnterCriticalSection(&g_csVerify);

    if (!g_bVerifyStarted)
    {
        g_bVerifyStarted = TRUE;

        if (DoVerify())
        {
            g_bVerified = TRUE;
            SetEvent(g_hVerifyEvent);
            CreateThread(NULL, 0, InjectThread, NULL, 0, NULL);
        }
        else
        {
            LeaveCriticalSection(&g_csVerify);
            MessageBoxW(NULL, L"\x9A8C\x8BC1\x5931\x8D25\xFF0C\x7A0B\x5E8F\x5C06\x9000\x51FA\xFF01", L"ZTX PJ", MB_ICONERROR);
            ExitProcess(1);
            return;
        }
    }

    LeaveCriticalSection(&g_csVerify);

    WaitForSingleObject(g_hVerifyEvent, INFINITE);
    VMProtectEnd();
}


BOOL LoadOriginalDll(void)
{
    VMProtectBeginUltra("BOOL LoadOriginalDll(void)");
    char szPath[MAX_PATH];
    GetSystemDirectoryA(szPath, MAX_PATH);
    strcat_s(szPath, MAX_PATH, "\\version.dll");
    g_hOrigDll = LoadLibraryA(szPath);
    BOOL ok = (g_hOrigDll != NULL);
    VMProtectEnd();
    return ok;
}


extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            g_hInstance = hinstDLL;
            DisableThreadLibraryCalls(hinstDLL);
            if (!LoadOriginalDll()) return FALSE;
            InitializeCriticalSection(&g_csVerify);
            g_hVerifyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            // Delayed init: CreateThread + InitBuffWrapperHook moved to EnsureDelayedInit()
            break;

        case DLL_PROCESS_DETACH:
            UninitBuffWrapperHook();

            DeleteCriticalSection(&g_csVerify);
            if (g_hVerifyEvent)
            {
                CloseHandle(g_hVerifyEvent);
                g_hVerifyEvent = NULL;
            }
            if (g_hOrigDll)
            {
                FreeLibrary(g_hOrigDll);
                g_hOrigDll = NULL;
            }
            break;
    }
    return TRUE;
}


__declspec(noinline) void EnsureDelayedInit()
{
    if (InterlockedCompareExchange(&g_bDelayInitStarted, 1, 0) == 0)
    {
        CreateThread(NULL, 0, InjectThread, NULL, 0, NULL);
        InitBuffWrapperHook();
    }
}



extern "C" __declspec(dllexport) BOOL WINAPI GetFileVersionInfoA_Proxy(
    LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    CheckAndVerify();
    typedef BOOL (WINAPI *FN)(LPCSTR, DWORD, DWORD, LPVOID);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoA");
    return fn ? fn(lptstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

extern "C" __declspec(dllexport) BOOL WINAPI GetFileVersionInfoByHandle_Proxy(
    DWORD dwFlags, LPVOID lpData)
{
    CheckAndVerify();
    typedef BOOL (WINAPI *FN)(DWORD, LPVOID);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoByHandle");
    return fn ? fn(dwFlags, lpData) : FALSE;
}

extern "C" __declspec(dllexport) BOOL WINAPI GetFileVersionInfoExA_Proxy(
    DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    CheckAndVerify();
    typedef BOOL (WINAPI *FN)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoExA");
    return fn ? fn(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

extern "C" __declspec(dllexport) BOOL WINAPI GetFileVersionInfoExW_Proxy(
    DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    CheckAndVerify();
    typedef BOOL (WINAPI *FN)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoExW");
    return fn ? fn(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

extern "C" __declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeA_Proxy(
    LPCSTR lptstrFilename, LPDWORD lpdwHandle)
{
    CheckAndVerify();
    typedef DWORD (WINAPI *FN)(LPCSTR, LPDWORD);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoSizeA");
    return fn ? fn(lptstrFilename, lpdwHandle) : 0;
}

extern "C" __declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeExA_Proxy(
    DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle)
{
    CheckAndVerify();
    typedef DWORD (WINAPI *FN)(DWORD, LPCSTR, LPDWORD);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoSizeExA");
    return fn ? fn(dwFlags, lpwstrFilename, lpdwHandle) : 0;
}

extern "C" __declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeExW_Proxy(
    DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle)
{
    CheckAndVerify();
    typedef DWORD (WINAPI *FN)(DWORD, LPCWSTR, LPDWORD);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoSizeExW");
    return fn ? fn(dwFlags, lpwstrFilename, lpdwHandle) : 0;
}

extern "C" __declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeW_Proxy(
    LPCWSTR lptstrFilename, LPDWORD lpdwHandle)
{
    CheckAndVerify();
    typedef DWORD (WINAPI *FN)(LPCWSTR, LPDWORD);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoSizeW");
    return fn ? fn(lptstrFilename, lpdwHandle) : 0;
}

extern "C" __declspec(dllexport) BOOL WINAPI GetFileVersionInfoW_Proxy(
    LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    CheckAndVerify();
    typedef BOOL (WINAPI *FN)(LPCWSTR, DWORD, DWORD, LPVOID);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoW");
    return fn ? fn(lptstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

extern "C" __declspec(dllexport) DWORD WINAPI VerFindFileA_Proxy(
    DWORD uFlags, LPCSTR szFileName, LPCSTR szWinDir, LPCSTR szAppDir,
    LPSTR szCurDir, PUINT puCurDirLen, LPSTR szDestDir, PUINT puDestDirLen)
{
    CheckAndVerify();
    typedef DWORD (WINAPI *FN)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerFindFileA");
    return fn ? fn(uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen) : 0;
}

extern "C" __declspec(dllexport) DWORD WINAPI VerFindFileW_Proxy(
    DWORD uFlags, LPCWSTR szFileName, LPCWSTR szWinDir, LPCWSTR szAppDir,
    LPWSTR szCurDir, PUINT puCurDirLen, LPWSTR szDestDir, PUINT puDestDirLen)
{
    CheckAndVerify();
    typedef DWORD (WINAPI *FN)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerFindFileW");
    return fn ? fn(uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen) : 0;
}

extern "C" __declspec(dllexport) DWORD WINAPI VerInstallFileA_Proxy(
    DWORD uFlags, LPCSTR szSrcFileName, LPCSTR szDestFileName, LPCSTR szSrcDir,
    LPCSTR szDestDir, LPCSTR szCurDir, LPSTR szTmpFile, PUINT puTmpFileLen)
{
    CheckAndVerify();
    typedef DWORD (WINAPI *FN)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerInstallFileA");
    return fn ? fn(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen) : 0;
}

extern "C" __declspec(dllexport) DWORD WINAPI VerInstallFileW_Proxy(
    DWORD uFlags, LPCWSTR szSrcFileName, LPCWSTR szDestFileName, LPCWSTR szSrcDir,
    LPCWSTR szDestDir, LPCWSTR szCurDir, LPWSTR szTmpFile, PUINT puTmpFileLen)
{
    CheckAndVerify();
    typedef DWORD (WINAPI *FN)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerInstallFileW");
    return fn ? fn(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen) : 0;
}

extern "C" __declspec(dllexport) DWORD WINAPI VerLanguageNameA_Proxy(DWORD wLang, LPSTR szLang, DWORD cchLang)
{
    CheckAndVerify();
    typedef DWORD (WINAPI *FN)(DWORD, LPSTR, DWORD);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerLanguageNameA");
    return fn ? fn(wLang, szLang, cchLang) : 0;
}

extern "C" __declspec(dllexport) DWORD WINAPI VerLanguageNameW_Proxy(DWORD wLang, LPWSTR szLang, DWORD cchLang)
{
    CheckAndVerify();
    typedef DWORD (WINAPI *FN)(DWORD, LPWSTR, DWORD);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerLanguageNameW");
    return fn ? fn(wLang, szLang, cchLang) : 0;
}

extern "C" __declspec(dllexport) BOOL WINAPI VerQueryValueA_Proxy(
    LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen)
{
    CheckAndVerify();
    typedef BOOL (WINAPI *FN)(LPCVOID, LPCSTR, LPVOID*, PUINT);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerQueryValueA");
    return fn ? fn(pBlock, lpSubBlock, lplpBuffer, puLen) : FALSE;
}

extern "C" __declspec(dllexport) BOOL WINAPI VerQueryValueW_Proxy(
    LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen)
{
    CheckAndVerify();
    typedef BOOL (WINAPI *FN)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerQueryValueW");
    return fn ? fn(pBlock, lpSubBlock, lplpBuffer, puLen) : FALSE;
}
