local Config = require("config")

--开关转换为true或false函数
local function optionIsOn(options)
	if options == "On" then
		return true
	else
		return false
	end	
end

--解析文件到正则字符串函数
local function parseRuleFile(filePath)
	local list = ''
	local rfile = assert(io.open(filePath,'r'))
	for line in rfile:lines() do
		if not (string.match(line,"^ *$")) then
			list = list.."|"..line
		end
	end
	list = string.gsub(list,"^%|",'')
	rfile:close()
	return list
end

--解析动作
local function actionIsOn1(action)
	if action == "captcha" then
		return true	
	else
		return false
	end	
end

local function actionIsOn2(action)
	if action == "forbidden" then
		return true
	else
		return false
	end	
end

local function actionIsOn3(action)
	if action == "iptables" then
		return true
	else
		return false
	end	
end

--解析uri匹配模式
local function urlMode1(mode)
	if mode == "uri" then
		return true
	else
		return false
	end
end

local function urlMode2(mode)
	if mode == "requestUri" then
		return true
	else
		return false
	end	
end


--读取文件到内存
local function readFile2Mem(file)
	local fp = io.open(file,"r")
	if fp then
		return fp:read("*all")
	end
end

--读取验证码到字典
local function readCaptcha2Dict(dir,dict) 
	local i = 0
	for path in io.popen('ls -a '..dir..'*.png'):lines() do
		if i < 10000 then
			i = i + 1
			local fp = io.open(path,"rb")
			local img = fp:read("*all")
			local captcha = string.gsub(path,".*/(.*)%.png","%1")
			captcha = string.lower(captcha)
			dict:set(i,captcha)
			dict:set(captcha,img)
		else
			break
		end	
	end	
end

_Conf = {
	
	--引入原始设置
	limitReqModules = Config.limitReqModules,
	redirectModules = Config.redirectModules,
	JsJumpModules = Config.JsJumpModules,
	whiteIpModules = Config.whiteIpModules,
	realIpFromHeader = Config.realIpFromHeader,
	debug = Config.debug,
	blockTime = Config.blockTime,
	keySecret = Config.keySecret,
	keyExpire = Config.keyExpire,
	sudoPass = Confg.sudoPass

	--解析开关设置
	limitReqModulesIsOn = optionIsOn(Config.limitReqModules.state),
	redirectModulesIsOn = optionIsOn(Config.redirectModules.state),
	JsJumpModulesIsOn = optionIsOn(Config.JsJumpModules.state),
	whiteIpModulesIsOn = optionIsOn(Config.whiteIpModules.state),
	realIpFromHeaderIsOn = optionIsOn(Config.realIpFromHeader.state),

	--解析文件到正则
	redirectUrlProtect = parseRuleFile(Config.redirectModules.urlProtect),
	JsJumpUrlProtect = parseRuleFile(Config.JsJumpModules.urlProtect),
	limitUrlProtect = parseRuleFile(Config.limitReqModules.urlProtect),
	whiteIpList = parseRuleFile(Config.whiteIpModules.ipList),

	--读取文件到内存
	captchaPage = readFile2Mem(Config.captchaPage),
	reCaptchaPage = readFile2Mem(Config.reCaptchaPage),

	--新建字典(用于记录ip访问次数及黑名单)
	dict = ngx.shared.guard_dict,

	--新建字典(只用于记录验证码,防止丢失)
	dict_captcha = ngx.shared.dict_captcha,

	--验证码图片路径
	captchaDir = Config.captchaDir,

	captchaAction = actionIsOn1(Config.blockAction),
	forbiddenAction = actionIsOn2(Config.blockAction),
	iptablesAction = actionIsOn3(Config.blockAction),

	--解析url匹配模式
	uriMode = urlMode1(Config.urlMatchMode),
	requestUriMode = urlMode2(Config.urlMatchMode),

}

--读取验证码到字典
readCaptcha2Dict(_Conf.captchaDir,_Conf.dict_captcha)