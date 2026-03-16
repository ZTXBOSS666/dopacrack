/**
 * WinInetHook.h
 * WinInet API Hook - 用于拦截和重定向网络请求
 * 老王出品 - 安全测试专用
 */

#pragma once
#ifndef WININET_HOOK_H
#define WININET_HOOK_H

#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")

// 初始化WinInet Hook
BOOL InitWinInetHook();

// 卸载WinInet Hook
void UninitWinInetHook();

// 设置重定向目标 (默认 127.0.0.1:2028)
void SetRedirectTarget(const char* host, INTERNET_PORT port);

// 添加需要拦截的域名
void AddInterceptDomain(const char* domain);

// 启用/禁用日志输出
void EnableHookLogging(BOOL bEnable);

#endif // WININET_HOOK_H
