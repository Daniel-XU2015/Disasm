# Disasm - 纯 C++ 实现的轻量级反编译引擎

**Disasm** 是一个从零开始、纯 C++ 编写的轻量级静态反编译工具。它能够解析 Windows PE 文件，提取代码段，并将底层机器码翻译成可编译的高级 C 语言代码。

> ⚠️ **声明**：本项目的**反编译引擎核心逻辑（多线程分析、AST合并、深度溯源等）均由作者纯手写完成**。底层的 x86/x64 指令解码部分依赖了优秀的开源库 [Zydis](https://github.com/zyantific/zydis)。

## ✨ 核心特性

*   **多线程解析 (Multi-threaded)**：自动利用多核 CPU 并行处理不同函数的反编译，速度极快。
*   **API 签名映射 (API Mapping)**：内置签名数据库，自动将枯燥的 `call [rip+xxx]` 还原为 `MessageBoxA(...)` 等带类型的真实 API 调用。
*   **深度指针溯源 (Pointer Tracing)**：跨越寄存器和内存的符号执行，精准还原字符串字面量，消灭令人头疼的指针偏移乱码。
*   **AST 表达式合并 (AST Merging)**：合并冗余的寄存器中间状态，生成极度精简、像人类手写的 C 语言算术表达式。
*   **零第三方依赖**：除了源码级集成的 Zydis 外，没有任何臃肿的第三方库依赖。

## 🛠️ 编译指南

本项目使用 Visual Studio 进行编译。

1. **准备环境**：
   * 安装 [Visual Studio](https://visualstudio.microsoft.com/)（需勾选“使用 C++ 的桌面开发”工作负载）。
2. **获取 Zydis**：
   * 下载 [Zydis](https://github.com/zyantific/zydis) 的源码，将 `Zydis.h` 和 `Zydis.c` 复制到本项目目录中。
3. **配置项目**：
   * 新建空项目，将 `main.cpp`、`Zydis.c` 和 `Zydis.h` 加入项目中。
   * 在项目属性 -> C/C++ -> 预处理器中，添加宏定义 `ZYDIS_STATIC_BUILD`。
4. **编译生成**：
   * 将配置切换到 **Release** 和 **x64**，点击生成即可。

## 🚀 使用方法

在命令行中运行生成的 `Disasm.exe`：

```bash
Disasm.exe -f <input_exe> -c <output_c_file>
