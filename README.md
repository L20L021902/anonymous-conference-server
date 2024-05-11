# 匿名会议系统服务器

\>[可执行文件可在发布页面获取](https://github.com/L20L021902/anonymous-conference-server/releases/latest)<

## 运行方式

Windows:

1. 打开命令提示符
2. 执行`set RUST_LOG=debug`
3. 执行`.\anonymous-conference-server.exe`

Linux:

1. 执行`RUST_LOG=debug ./anonymous-conference-server`

>`RUST_LOG=debug`将日志级别设置为调试

## 编译方式

`cargo build`

## 可用命令
 
| 命令 | 说明 |
| ----------- | ----------- |
|`peers`| 列出所有已连接的客户端 |
|`conferences`| 列出所有会议 |
|`exit`| 启动清洁关机 |
