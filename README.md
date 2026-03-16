# dopacrack

dopa 破解补丁源码

## 项目简介

本项目为 dopa 破解补丁的完整源码，包含服务端（易语言）和 DLL 劫持补丁（C++），供学习与研究使用。

## 项目结构

```
├── dopa服务端.e                     # 易语言服务端源码
├── SunnyNet.dll                     # SunnyNet 网络通信库
├── version_proxy/                   # DLL劫持补丁源码 (C++ / Visual Studio)
│   ├── version_proxy.cpp            # 版本代理主入口
│   ├── version_proxy.c              # 版本代理C实现
│   ├── BuffWrapperHook.cpp/.h       # Buff包装Hook
│   ├── WinInetHook.cpp/.h           # WinInet网络Hook
│   ├── MinHook.h                    # MinHook头文件
│   ├── MinHook.x64.lib              # MinHook静态库 (x64)
│   ├── version.def                  # DLL导出定义文件
│   ├── version_proxy.vcxproj        # Visual Studio项目文件
│   └── version_proxy.slnx           # Visual Studio解决方案
├── LICENSE                          # MIT 开源协议
└── README.md                        # 项目说明
```

## 技术栈

- **易语言** — 服务端主程序开发
- **C++ (C++20)** — DLL 劫持补丁开发
- **SunnyNet** — 网络通信库
- **MinHook** — x64 API Hook 引擎
- **Visual Studio 2022+** — C++项目编译环境

## 编译说明

### 服务端

使用易语言 IDE 打开 `dopa服务端.e` 查看/编译服务端源码，`SunnyNet.dll` 为运行时依赖库。

### DLL 劫持补丁

1. 使用 **Visual Studio 2022** 打开 `version_proxy/version_proxy.slnx`
2. 选择 **Release | x64** 配置
3. 编译生成 `version.dll`

#### 外部依赖

- [MinHook](https://github.com/TsudaKageworuo/minhook) — 已包含在项目中

## 开源协议

本项目采用 [MIT License](LICENSE) 开源协议。

## 作者

**战天下**

## 免责声明

本项目仅供学习交流使用，请勿用于非法用途。使用本项目所造成的一切后果由使用者自行承担。
