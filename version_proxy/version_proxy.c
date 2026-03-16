/**
 * version.dll Proxy - ZTX PJ Hook
 * Security Testing Tool
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// Original DLL handle
static HMODULE g_hOrigDll = NULL;
static BOOL g_bHooked = FALSE;
static BOOL g_bLogoReplaced = FALSE;
static BOOL g_bWelcomeReplaced = FALSE;

// Original WriteConsoleW function pointer
typedef BOOL (WINAPI *WriteConsoleW_t)(HANDLE, const VOID*, DWORD, LPDWORD, LPVOID);
static WriteConsoleW_t g_pOrigWriteConsoleW = NULL;

// ZTX Logo
static const wchar_t* g_wszZtxLogo =
    L"\x1b[96m\r\n"
    L"ZZZZZ  TTTTT  X   X    PPPP    JJJJJ\r\n"
    L"   Z     T     X X     P   P      J\r\n"
    L"  Z      T      X      PPPP       J\r\n"
    L" Z       T     X X     P      J   J\r\n"
    L"ZZZZZ    T    X   X    P       JJJ\r\n"
    L"\x1b[0m\r\n";

static const wchar_t* g_wszWelcome = L"\x1b[93mZTX PJ v1.0 - Security Test Edition\x1b[0m\r\n";

// Hooked WriteConsoleW - simplified version
BOOL WINAPI Hooked_WriteConsoleW(
    HANDLE hConsoleOutput,
    const VOID* lpBuffer,
    DWORD nNumberOfCharsToWrite,
    LPDWORD lpNumberOfCharsWritten,
    LPVOID lpReserved)
{
    // Safety check
    if (!g_pOrigWriteConsoleW)
    {
        return FALSE;
    }

    if (lpBuffer && nNumberOfCharsToWrite > 10 && nNumberOfCharsToWrite < 5000)
    {
        const wchar_t* wszBuf = (const wchar_t*)lpBuffer;

        // Check for DOPASENSE logo - simple check
        if (!g_bLogoReplaced)
        {
            BOOL found = FALSE;
            for (DWORD i = 0; i < nNumberOfCharsToWrite && i < 200; i++)
            {
                if (wszBuf[i] == 0x2588 || wszBuf[i] == 0x2554 || wszBuf[i] == L'D')
                {
                    // Check if this might be DOPASENSE
                    if (wszBuf[i] == L'D' && i + 8 < nNumberOfCharsToWrite)
                    {
                        if (wszBuf[i+1] == L'O' && wszBuf[i+2] == L'P' && wszBuf[i+3] == L'A')
                        {
                            found = TRUE;
                            break;
                        }
                    }
                    else if (wszBuf[i] == 0x2588 || wszBuf[i] == 0x2554)
                    {
                        found = TRUE;
                        break;
                    }
                }
            }
            if (found)
            {
                g_bLogoReplaced = TRUE;
                DWORD written = 0;
                return g_pOrigWriteConsoleW(hConsoleOutput, g_wszZtxLogo,
                    (DWORD)wcslen(g_wszZtxLogo), &written, lpReserved);
            }
        }

        // Check for welcome message - simple check
        if (!g_bWelcomeReplaced)
        {
            for (DWORD i = 0; i < nNumberOfCharsToWrite && i < 200; i++)
            {
                if (wszBuf[i] == L'1' && i + 9 < nNumberOfCharsToWrite)
                {
                    if (wszBuf[i+1] == L'0' && wszBuf[i+2] == L'4' && wszBuf[i+3] == L'2')
                    {
                        g_bWelcomeReplaced = TRUE;
                        DWORD written = 0;
                        return g_pOrigWriteConsoleW(hConsoleOutput, g_wszWelcome,
                            (DWORD)wcslen(g_wszWelcome), &written, lpReserved);
                    }
                }
            }
        }
    }

    return g_pOrigWriteConsoleW(hConsoleOutput, lpBuffer,
        nNumberOfCharsToWrite, lpNumberOfCharsWritten, lpReserved);
}

// Simple IAT hook
BOOL HookIAT(HMODULE hModule, const char* szDllName, const char* szFuncName, void* pNewFunc, void** ppOrigFunc)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule +
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImportDesc->Name)
    {
        char* szModName = (char*)((BYTE*)hModule + pImportDesc->Name);
        if (_stricmp(szModName, szDllName) == 0)
        {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);
            PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->OriginalFirstThunk);

            while (pOrigThunk->u1.AddressOfData)
            {
                if (!(pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
                {
                    PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + pOrigThunk->u1.AddressOfData);
                    if (strcmp((char*)pImport->Name, szFuncName) == 0)
                    {
                        DWORD oldProtect;
                        VirtualProtect(&pThunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                        *ppOrigFunc = (void*)pThunk->u1.Function;
                        pThunk->u1.Function = (ULONG_PTR)pNewFunc;
                        VirtualProtect(&pThunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                        return TRUE;
                    }
                }
                pThunk++;
                pOrigThunk++;
            }
        }
        pImportDesc++;
    }
    return FALSE;
}

// Python C API types
typedef int (*Py_IsInitialized_t)(void);
typedef int (*PyGILState_Ensure_t)(void);
typedef void (*PyGILState_Release_t)(int);
typedef int (*PyRun_SimpleString_t)(const char*);

// Hook code for Python - matching frida_hook_v5.js
static const char* g_szHookCode =
"import sys\n"
"import gc\n"
"import builtins\n"
"try:\n"
"    import urllib3\n"
"    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)\n"
"except: pass\n"
"try:\n"
"    import requests\n"
"    from unittest.mock import Mock\n"
"    if not hasattr(requests.Session, '_ztx_hooked'):\n"
"        requests.Session._ztx_hooked = True\n"
"        _orig_session_request = requests.Session.request\n"
"        def _patched_session_request(self, method, url, **kwargs):\n"
"            if 'api.52vmy.cn/api/wl/t/onip' in url:\n"
"                m = Mock()\n"
"                m.status_code = 200\n"
"                m.text = '{}'\n"
"                m.content = b'{}'\n"
"                m.headers = {'Content-Type': 'application/json'}\n"
"                m.ok = True\n"
"                m.json = lambda: {}\n"
"                m.raise_for_status = lambda: None\n"
"                return m\n"
"            if url.startswith('https://qqun.game1337.com'):\n"
"                print('[HTTP] INTERCEPTED!')\n"
"                m = Mock()\n"
"                m.status_code = 200\n"
"                m.text = '<h5 id=\"qqun\">ZTX PJ</h5>'\n"
"                m.content = b'<h5 id=\"qqun\">ZTX PJ</h5>'\n"
"                m.headers = {'Content-Type': 'text/html'}\n"
"                m.ok = True\n"
"                m.json = lambda: {}\n"
"                m.raise_for_status = lambda: None\n"
"                return m\n"
"            if 'auth.game1337.com' in url:\n"
"                url = url.replace('https://auth.game1337.com', 'http://127.0.0.1:2028')\n"
"            kwargs['verify'] = False\n"
"            try:\n"
"                resp = _orig_session_request(self, method, url, **kwargs)\n"
"                return resp\n"
"            except Exception as e:\n"
"                raise\n"
"        requests.Session.request = _patched_session_request\n"
"        for func_name in ['get', 'post', 'put', 'delete', 'head', 'options', 'patch']:\n"
"            orig_func = getattr(requests, func_name)\n"
"            def make_patch(f, name):\n"
"                def patched(*args, **kwargs):\n"
"                    if args:\n"
"                        url = args[0]\n"
"                        if 'api.52vmy.cn/api/wl/t/onip' in url:\n"
"                            m = Mock()\n"
"                            m.status_code = 200\n"
"                            m.text = '{}'\n"
"                            m.content = b'{}'\n"
"                            m.json = lambda: {}\n"
"                            return m\n"
"                        if 'auth.game1337.com' in url:\n"
"                            new_url = url.replace('https://auth.game1337.com', 'http://127.0.0.1:2028')\n"
"                            args = (new_url,) + args[1:]\n"
"                    kwargs['verify'] = False\n"
"                    return f(*args, **kwargs)\n"
"                return patched\n"
"            setattr(requests, func_name, make_patch(orig_func, func_name))\n"
"except Exception as e:\n"
"    print(f'[ZTX] HOOK  ERR: {e}')\n"
"_orig_import = builtins.__import__\n"
"_dopa_patched = False\n"
"def _hooked_import(name, *args, **kwargs):\n"
"    global _dopa_patched\n"
"    module = _orig_import(name, *args, **kwargs)\n"
"    if name == 'core' and not _dopa_patched:\n"
"        if hasattr(module, 'Valorant'):\n"
"            module.Valorant.is_using_dopa_model = lambda self: True\n"
"            module.Valorant.is_using_encrypted_model = lambda self: True\n"
"            _dopa_patched = True\n"
"    return module\n"
"builtins.__import__ = _hooked_import\n"
"def do_patch():\n"
"    patched = []\n"
"    if 'verify' in sys.modules:\n"
"        m = sys.modules['verify']\n"
"        for attr in dir(m):\n"
"            if 'verify' in attr.lower() or 'check' in attr.lower():\n"
"                try:\n"
"                    if callable(getattr(m, attr)):\n"
"                        setattr(m, attr, lambda *a, **k: True)\n"
"                        patched.append(f'verify.{attr}')\n"
"                except: pass\n"
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
"        except: pass\n"
"    return patched\n"
"r = do_patch()\n"
"import threading\n"
"_ztx_count = [0]\n"
"def _ztx_loop():\n"
"    import time\n"
"    while True:\n"
"        try:\n"
"            r = do_patch()\n"
"            if r and _ztx_count[0] < 3:\n"
"                _ztx_count[0] += 1\n"
"        except: pass\n"
"        time.sleep(1)\n"
"threading.Thread(target=_ztx_loop, daemon=True).start()\n";

// Inject thread
DWORD WINAPI InjectThread(LPVOID lpParam)
{
    HMODULE hPython = NULL;
    int nRetry = 0;

    // NOTE: IAT hook disabled for now - causing crash
    // TODO: Fix IAT hook or use Detours library
    /*
    g_pOrigWriteConsoleW = (WriteConsoleW_t)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "WriteConsoleW");
    if (g_pOrigWriteConsoleW)
    {
        HMODULE hExe = GetModuleHandle(NULL);
        if (hExe)
        {
            HookIAT(hExe, "kernel32.dll", "WriteConsoleW",
                Hooked_WriteConsoleW, (void**)&g_pOrigWriteConsoleW);
        }
    }
    */

    // Wait for python DLL
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

    Sleep(500);

    PyGILState_Ensure_t PyGILState_Ensure =
        (PyGILState_Ensure_t)GetProcAddress(hPython, "PyGILState_Ensure");
    PyGILState_Release_t PyGILState_Release =
        (PyGILState_Release_t)GetProcAddress(hPython, "PyGILState_Release");
    PyRun_SimpleString_t PyRun_SimpleString =
        (PyRun_SimpleString_t)GetProcAddress(hPython, "PyRun_SimpleString");

    if (!PyGILState_Ensure || !PyGILState_Release || !PyRun_SimpleString) return 1;

    for (int i = 0; i < 5; i++)
    {
        Sleep(500);
        int gstate = PyGILState_Ensure();
        int result = PyRun_SimpleString(g_szHookCode);
        PyGILState_Release(gstate);
        if (result == 0)
        {
            g_bHooked = TRUE;
            break;
        }
    }

    return 0;
}

// Load original DLL
BOOL LoadOriginalDll(void)
{
    char szPath[MAX_PATH];
    GetSystemDirectoryA(szPath, MAX_PATH);
    strcat_s(szPath, MAX_PATH, "\\version.dll");
    g_hOrigDll = LoadLibraryA(szPath);
    return (g_hOrigDll != NULL);
}

// DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            if (!LoadOriginalDll()) return FALSE;
            CreateThread(NULL, 0, InjectThread, NULL, 0, NULL);
            break;

        case DLL_PROCESS_DETACH:
            if (g_hOrigDll)
            {
                FreeLibrary(g_hOrigDll);
                g_hOrigDll = NULL;
            }
            break;
    }
    return TRUE;
}

// ============================================
// Proxy functions - forward to original DLL
// ============================================

__declspec(dllexport) BOOL WINAPI GetFileVersionInfoA_Proxy(
    LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    typedef BOOL (WINAPI *FN)(LPCSTR, DWORD, DWORD, LPVOID);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoA");
    return fn ? fn(lptstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

__declspec(dllexport) BOOL WINAPI GetFileVersionInfoByHandle_Proxy(
    DWORD dwFlags, LPVOID lpData)
{
    typedef BOOL (WINAPI *FN)(DWORD, LPVOID);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoByHandle");
    return fn ? fn(dwFlags, lpData) : FALSE;
}

__declspec(dllexport) BOOL WINAPI GetFileVersionInfoExA_Proxy(
    DWORD dwFlags, LPCSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    typedef BOOL (WINAPI *FN)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoExA");
    return fn ? fn(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

__declspec(dllexport) BOOL WINAPI GetFileVersionInfoExW_Proxy(
    DWORD dwFlags, LPCWSTR lpwstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    typedef BOOL (WINAPI *FN)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoExW");
    return fn ? fn(dwFlags, lpwstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeA_Proxy(
    LPCSTR lptstrFilename, LPDWORD lpdwHandle)
{
    typedef DWORD (WINAPI *FN)(LPCSTR, LPDWORD);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoSizeA");
    return fn ? fn(lptstrFilename, lpdwHandle) : 0;
}

__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeExA_Proxy(
    DWORD dwFlags, LPCSTR lpwstrFilename, LPDWORD lpdwHandle)
{
    typedef DWORD (WINAPI *FN)(DWORD, LPCSTR, LPDWORD);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoSizeExA");
    return fn ? fn(dwFlags, lpwstrFilename, lpdwHandle) : 0;
}

__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeExW_Proxy(
    DWORD dwFlags, LPCWSTR lpwstrFilename, LPDWORD lpdwHandle)
{
    typedef DWORD (WINAPI *FN)(DWORD, LPCWSTR, LPDWORD);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoSizeExW");
    return fn ? fn(dwFlags, lpwstrFilename, lpdwHandle) : 0;
}

__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeW_Proxy(
    LPCWSTR lptstrFilename, LPDWORD lpdwHandle)
{
    typedef DWORD (WINAPI *FN)(LPCWSTR, LPDWORD);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoSizeW");
    return fn ? fn(lptstrFilename, lpdwHandle) : 0;
}

__declspec(dllexport) BOOL WINAPI GetFileVersionInfoW_Proxy(
    LPCWSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    typedef BOOL (WINAPI *FN)(LPCWSTR, DWORD, DWORD, LPVOID);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "GetFileVersionInfoW");
    return fn ? fn(lptstrFilename, dwHandle, dwLen, lpData) : FALSE;
}

__declspec(dllexport) DWORD WINAPI VerFindFileA_Proxy(
    DWORD uFlags, LPCSTR szFileName, LPCSTR szWinDir, LPCSTR szAppDir,
    LPSTR szCurDir, PUINT puCurDirLen, LPSTR szDestDir, PUINT puDestDirLen)
{
    typedef DWORD (WINAPI *FN)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerFindFileA");
    return fn ? fn(uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen) : 0;
}

__declspec(dllexport) DWORD WINAPI VerFindFileW_Proxy(
    DWORD uFlags, LPCWSTR szFileName, LPCWSTR szWinDir, LPCWSTR szAppDir,
    LPWSTR szCurDir, PUINT puCurDirLen, LPWSTR szDestDir, PUINT puDestDirLen)
{
    typedef DWORD (WINAPI *FN)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerFindFileW");
    return fn ? fn(uFlags, szFileName, szWinDir, szAppDir, szCurDir, puCurDirLen, szDestDir, puDestDirLen) : 0;
}

__declspec(dllexport) DWORD WINAPI VerInstallFileA_Proxy(
    DWORD uFlags, LPCSTR szSrcFileName, LPCSTR szDestFileName, LPCSTR szSrcDir,
    LPCSTR szDestDir, LPCSTR szCurDir, LPSTR szTmpFile, PUINT puTmpFileLen)
{
    typedef DWORD (WINAPI *FN)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerInstallFileA");
    return fn ? fn(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen) : 0;
}

__declspec(dllexport) DWORD WINAPI VerInstallFileW_Proxy(
    DWORD uFlags, LPCWSTR szSrcFileName, LPCWSTR szDestFileName, LPCWSTR szSrcDir,
    LPCWSTR szDestDir, LPCWSTR szCurDir, LPWSTR szTmpFile, PUINT puTmpFileLen)
{
    typedef DWORD (WINAPI *FN)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerInstallFileW");
    return fn ? fn(uFlags, szSrcFileName, szDestFileName, szSrcDir, szDestDir, szCurDir, szTmpFile, puTmpFileLen) : 0;
}

__declspec(dllexport) DWORD WINAPI VerLanguageNameA_Proxy(DWORD wLang, LPSTR szLang, DWORD cchLang)
{
    typedef DWORD (WINAPI *FN)(DWORD, LPSTR, DWORD);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerLanguageNameA");
    return fn ? fn(wLang, szLang, cchLang) : 0;
}

__declspec(dllexport) DWORD WINAPI VerLanguageNameW_Proxy(DWORD wLang, LPWSTR szLang, DWORD cchLang)
{
    typedef DWORD (WINAPI *FN)(DWORD, LPWSTR, DWORD);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerLanguageNameW");
    return fn ? fn(wLang, szLang, cchLang) : 0;
}

__declspec(dllexport) BOOL WINAPI VerQueryValueA_Proxy(
    LPCVOID pBlock, LPCSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen)
{
    typedef BOOL (WINAPI *FN)(LPCVOID, LPCSTR, LPVOID*, PUINT);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerQueryValueA");
    return fn ? fn(pBlock, lpSubBlock, lplpBuffer, puLen) : FALSE;
}

__declspec(dllexport) BOOL WINAPI VerQueryValueW_Proxy(
    LPCVOID pBlock, LPCWSTR lpSubBlock, LPVOID *lplpBuffer, PUINT puLen)
{
    typedef BOOL (WINAPI *FN)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
    static FN fn = NULL;
    if (!fn) fn = (FN)GetProcAddress(g_hOrigDll, "VerQueryValueW");
    return fn ? fn(pBlock, lpSubBlock, lplpBuffer, puLen) : FALSE;
}
