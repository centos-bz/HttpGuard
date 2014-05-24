local Guard = require "guard"
local remoteIp = ngx.var.remote_addr
local headers = ngx.req.get_headers()
local ip = Guard:getRealIp(remoteIp,headers)
local reqFilename = ngx.var.request_filename
local reqUri = ngx.var.request_uri
local uri = ngx.var.uri
local address = ''

--判断是某种url匹配模式
if _Conf.uriMode then
	address = uri
elseif _Conf.requestUriMode then
	address = reqUri
end	


--获取验证码
if ngx.re.match(reqUri,"/get-captcha.jpg$","i") then
	Guard:getCaptcha()

--验证验证码
elseif ngx.re.match(reqUri,"/verify-captcha.jpg$","i") then
	Guard:verifyCaptcha(ip)

--过滤请求
else
	--白名单模块
	if not Guard:ipInWhiteList(ip) then
		--黑名单模块
		Guard:blackListModules(ip,reqUri)

		--限制请求速率模块
		if ngx.re.match(address,_Conf.limitUrlProtect,"i") then
			Guard:debug("address "..address.." match reg ".._Conf.limitUrlProtect)
			Guard:limitReqModules(ip,reqUri)
		end

		--302转向模块
		if ngx.re.match(address,_Conf.redirectUrlProtect,"i") then
			Guard:debug("address "..address.." match reg ".._Conf.redirectUrlProtect)
			Guard:redirectModules(ip,reqUri)
		end	

		--js跳转模块
		if ngx.re.match(address,_Conf.JsJumpUrlProtect,"i") then
			Guard:debug("address "..address.." match reg ".._Conf.JsJumpUrlProtect)
			Guard:JsJumpModules(ip,reqUri)
		end
			
	end	
end

