
## sihook

simple inline hook.

简单的适用windows或linux环境的inline_hook，支持架构x86、x86_64.

## 特点

 - 简化引入其他汇编指令解析引擎库，直接用预编译好的ldasm的shellcode来计算inlinehook时涉及的指令长度。这块功能代码取自开源项目 github.com/thejanit0r/x86_ldasm
 - 接口简洁，仅sihook_create sihook_enable sihook_free三个函数。
 - 近跳需要5字节的inline指令，64位远跳则需要14字节。
 - win/linux目前已测试

## 不足

 - 仅适用函数头前面几个指令是位置无关的，与位置相关的指令备份移动后没有修正处理。

