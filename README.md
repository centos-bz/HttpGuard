# http-guard

HttpGuard是基于openresty,以lua脚本语言开发的防cc攻击软件。而openresty是集成了高性能web服务器Nginx，以及一系列的Nginx模块，这其中最重要的，也是我们主要用到的nginx lua模块。HttpGuard基于nginx lua开发，继承了nginx高并发，高性能的特点，可以以非常小的性能损耗来防范大规模的cc攻击。

下面介绍HttpGuard防cc的一些特性：

1. 限制单个IP或者UA在一定时间内的请求次数
2. 向访客发送302转向响应头来识别恶意用户,并阻止其再次访问
3. 向访客发送带有跳转功能的js代码来识别恶意用户，并阻止其再次访问
4. 向访客发送cookie来识别恶意用户,并阻止其再次访问
5. 支持向访客发送带有验证码的页面，来进一步识别，以免误伤
6. 支持直接断开恶意访客的连接
7. 支持结合iptables来阻止恶意访客再次连接
8. 支持白名单/黑名单功能
9. 支持根据统计特定端口的连接数来自动开启或关闭防cc模式

## 部署HttpGuard
### 安装openresty或者nginx lua

按照openresty官网手动安装[http://openresty.com](http://openresty.com)

### 安装HttpGuard

假设我们把HttpGuard安装到/data/www/waf/，当然你可以选择安装在任意目录。

```
cd /data/www
wget --no-check-certificate https://github.com/wenjun1055/HttpGuard/archive/master.zip
unzip master.zip
mv HttpGuard-master waf
```

### 生成验证码图片

为了支持验证码识别用户，我们需要先生成验证码图片。生成验证码图片需要系统安装有php，以及php-gd模块。
用以下命令执行getImg.php文件生成验证码

```
cd /data/www/waf/captcha/
/usr/local/php/bin/php getImg.php
```

大概要生成一万个图片，可能需要花几分钟的时间。

### 修改nginx.conf配置文件

向http区块输入如下代码：

```
lua_package_path "/data/www/waf/?.lua";
lua_shared_dict guard_dict 100m;
lua_shared_dict dict_captcha 70m;
init_by_lua_file '/data/www/waf/init.lua';
access_by_lua_file '/data/www/waf/runtime.lua';
lua_max_running_timers 1;
```

### 配置HttpGuard

详细配置说明在[config.lua](https://github.com/wenjun1055/HttpGuard/blob/master/guard.lua)中，请根据需求进行配置