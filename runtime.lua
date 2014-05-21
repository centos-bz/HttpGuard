local Guard = require "guard"
local remoteIp = ngx.var.remote_addr
local headers = ngx.req.get_headers()
local ip = Guard:getRealIp(remoteIp,headers)
local reqFilename = ngx.var.request_filename
local reqUri = ngx.var.request_uri


--获取验证码
if ngx.re.match(reqUri,"/get-captcha.jpg$","i") then
	Guard:getCaptcha()

--验证验证码
elseif ngx.re.match(reqUri,"/verify-captcha.jpg$","i") then
	Guard:verifyCaptcha(ip)

--过滤php请求
elseif ngx.re.match(reqFilename,"\\.php$","i") then --请求的文件名是否为php
	Guard:debug("request filename "..reqFilename.." match reg .php$")
	--白名单模块
	if not Guard:ipInWhiteList(ip) then
		--黑名单模块
		Guard:blackListModules(ip,reqUri)

		--限制请求速率模块
		Guard:limitReqModules(ip,reqUri)

		--302转向模块
		Guard:redirectModules(ip,reqUri)

		--js跳转模块
		Guard:JsJumpModules(ip,reqUri)
	end	
end

