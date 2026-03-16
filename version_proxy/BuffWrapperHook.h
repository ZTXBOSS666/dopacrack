/**
 * BuffWrapperHook.h
 * Hook buff_wrapper.dll internal functions
 * By LaoWang - Plan B: Precise Hook
 */

#pragma once
#ifndef BUFF_WRAPPER_HOOK_H
#define BUFF_WRAPPER_HOOK_H

#include <windows.h>
#include <string>

// Initialize buff_wrapper.dll Hook
// Will wait for DLL to load and then hook automatically
BOOL InitBuffWrapperHook();

// Uninitialize Hook
void UninitBuffWrapperHook();

// Set redirect target
void SetBuffRedirectTarget(const char* host, int port);

// Enable/Disable logging
void EnableBuffHookLogging(BOOL bEnable);

// Callback function types - for intercepting requests
typedef void (*PFN_OnRequest)(const char* apiPath, const char* postData, const char* signKey);
typedef void (*PFN_OnResponse)(const char* response);

// Set callbacks
void SetRequestCallback(PFN_OnRequest callback);
void SetResponseCallback(PFN_OnResponse callback);

#endif // BUFF_WRAPPER_HOOK_H
