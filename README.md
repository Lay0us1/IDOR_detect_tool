# SaaS-API越权漏洞检测系统

## 概述

通过替换认证信息后重放请求，并对比数据包结果，判断接口是否存在越权漏洞

详细介绍：[水平越权挖掘技巧与自动化越权漏洞检测](https://www.gem-love.com/2023/01/26/%E6%B0%B4%E5%B9%B3%E8%B6%8A%E6%9D%83%E6%8C%96%E6%8E%98%E6%8A%80%E5%B7%A7%E4%B8%8E%E8%87%AA%E5%8A%A8%E5%8C%96%E8%B6%8A%E6%9D%83%E6%BC%8F%E6%B4%9E%E6%A3%80%E6%B5%8B/)

## 特点

1. 支持HTTPS
2. 自动过滤图片/js/css/html页面等静态内容
3. 多线程检测，避免阻塞
4. 支持输出报表与完整的URL、请求、响应

## 安装和使用

### 安装依赖

```
python3 -m pip install -r requirements.txt
```

### 启动

```
python3 start.py
```

即可监听socks5://127.0.0.1:8889。

### 安装证书

使用SwitchOmega等插件连接该代理，并访问[mitm.it](http://mitm.it)即可进入证书安装页面，根据操作系统进行证书安装。

以MacOS为例：

![175143_y7wfgR](http://cdn2.pic.y1ng.vip/uPic/2023/01/25/175143_y7wfgR.png)

下载安装后，打开钥匙串访问，找到mitmproxy证书，修改为alwaystrust

![175302_B8WD5s](http://cdn2.pic.y1ng.vip/uPic/2023/01/25/175302_B8WD5s.png)

### 检测漏洞

首先准备好目标系统的A、B两账号，根据系统的鉴权逻辑（Cookie、header、参数等）将A账号信息配置config/config.yml，之后登录B账号

![175522_XdPt84](http://cdn2.pic.y1ng.vip/uPic/2023/01/25/175522_XdPt84.png)

使用B账号访问，脚本会自动替换鉴权信息并重放，根据响应结果判断是否存在越权漏洞

![175435_PFm3WY](http://cdn2.pic.y1ng.vip/uPic/2023/01/25/175435_PFm3WY.png)

### 生成报表

每次有新漏洞都会自动添加到report/result.html中，通过浏览器打开：

![181645_PaztjA](http://cdn2.pic.y1ng.vip/uPic/2023/01/25/181645_PaztjA.png)

点击具体条目可以展开/折叠对应的请求和响应：

![181811_HJMDoo](http://cdn2.pic.y1ng.vip/uPic/2023/01/25/181811_HJMDoo.png)

## 检测逻辑

![230504_ECb2mP](http://cdn2.pic.y1ng.vip/uPic/2023/01/26/230504_ECb2mP.jpg)

「是否静态」那里是和否写反了