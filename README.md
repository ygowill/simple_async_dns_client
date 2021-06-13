# UESTC 互联网络程序设计作业

## 作业详情

### 场景

网络编程中常用`getaddrinfo()`函数从DNS地址获取IP地址，但是该函数是一个阻塞的调用，会阻塞调用线程

### 目标

* 在一个Reactor网络库上采用非阻塞方式编写一个DNS客户端，获得IP地址

### 要求

1. 查找资料了解DNS查询的报文交互过程，确定RFC对DNS交互报文的定义，根据报文定义设计并实现一个非阻塞DNS客户端
2. 基于Linux平台，可以借助于muduo，libevent，libuv等网络库

## 环境与依赖

本次作业主要环境如下：

* wsl2
* gcc/g++ 10.2

主要第三方库依赖如下：

* asio
* cmdline
* fmt
* tabulate

## 编译与使用

编译语句

```shell
cd $PROJECT_ROOT/build
cmake ..
make
```

如何使用

```shell
./dns_client -h

usage: ./dns_client [options] ...
options:
  -u, --url        query url (string [=])
  -s, --server     dns server (string [=114.114.114.114])
  -v, --verbose    dns packet verbose info
  -h, --help       usage instruction
  -c, --check      check your terminal window size
      --tips       you can expand your terminal window width upto 160 for the fancy output~
```

> Little Tips：尝试使用更大宽度的terminal(>160)来解锁意义不明的效果
