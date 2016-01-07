local Config = require("config")

--开关转换为true或false函数
local function optionIsOn(options)
	local options = string.lower(options)
	if options == "on" then
		return true
	else
		return false
	end	
end

--生成密码
local function makePassword()
	local string="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	math.randomseed(os.time()) --随机种子
	local r1 = math.random(1,62) --生成1-62之间的随机数
	local r2 = math.random(1,62) --生成1-62之间的随机数
	local r3 = math.random(1,62) --生成1-62之间的随机数
	local r4 = math.random(1,62) --生成1-62之间的随机数
	local r5 = math.random(1,62) --生成1-62之间的随机数
	local r6 = math.random(1,62) --生成1-62之间的随机数
	local r7 = math.random(1,62) --生成1-62之间的随机数
	local r8 = math.random(1,62) --生成1-62之间的随机数

	local s1 = string.sub(string,r1,r1)
	local s2 = string.sub(string,r2,r2)
	local s3 = string.sub(string,r3,r3)
	local s4 = string.sub(string,r4,r4)
	local s5 = string.sub(string,r5,r5)
	local s6 = string.sub(string,r6,r6)
	local s7 = string.sub(string,r7,r7)
	local s8 = string.sub(string,r8,r8)

	return s1..s2..s3..s4..s5..s6..s7..s8
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
	cookieModules = Config.cookieModules,
	whiteIpModules = Config.whiteIpModules,
	realIpFromHeader = Config.realIpFromHeader,
	autoEnable = Config.autoEnable,
	debug = Config.debug,
	logPath = Config.logPath,
	blockTime = Config.blockTime,
	keyExpire = Config.keyExpire,
	sudoPass = Config.sudoPass,
	whiteTime = Config.whiteTime,
	captchaKey = Config.captchaKey,
	captchaToIptables = Config.captchaToIptables,

	--解析开关设置
	limitReqModulesIsOn = optionIsOn(Config.limitReqModules.state),
	whiteIpModulesIsOn = optionIsOn(Config.whiteIpModules.state),
	realIpFromHeaderIsOn = optionIsOn(Config.realIpFromHeader.state),
	autoEnableIsOn = optionIsOn(Config.autoEnable.state),
	redirectModulesIsOn = optionIsOn(Config.redirectModules.state),
	JsJumpModulesIsOn = optionIsOn(Config.JsJumpModules.state),
	cookieModulesIsOn = optionIsOn(Config.cookieModules.state),
	captchaToIptablesIsOn = optionIsOn(Config.captchaToIptables.state),

	--解析文件到正则
	redirectUrlProtect = parseRuleFile(Config.redirectModules.urlProtect),
	JsJumpUrlProtect = parseRuleFile(Config.JsJumpModules.urlProtect),
	limitUrlProtect = parseRuleFile(Config.limitReqModules.urlProtect),
	cookieUrlProtect = parseRuleFile(Config.cookieModules.urlProtect),
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

	normalCount = 0,
	exceedCount = 0,

}

--读取验证码到字典
if Config.blockAction == "captcha" then
	readCaptcha2Dict(_Conf.captchaDir,_Conf.dict_captcha)
end	

--判断redirectModules是否开启
if _Conf.redirectModulesIsOn then
	_Conf.dict_captcha:set("redirectOn",1)
else
	_Conf.dict_captcha:set("redirectOn",0)
end

--判断JsJumpModules是否开启
if _Conf.JsJumpModulesIsOn then
	_Conf.dict_captcha:set("jsOn",1)
else
	_Conf.dict_captcha:set("jsOn",0)
end

--判断cookieModules是否开启
if _Conf.cookieModulesIsOn then
	_Conf.dict_captcha:set("cookieOn",1)
else
	_Conf.dict_captcha:set("cookieOn",0)
end

--设置自动开启防cc相关变量
if _Conf.autoEnableIsOn then
	_Conf.dict_captcha:set("normalCount",0)
	_Conf.dict_captcha:set("exceedCount",0)
end	


--判断是否key是动态生成
if Config.keyDefine == "dynamic" then
	_Conf.redirectModules.keySecret = makePassword()
	_Conf.JsJumpModules.keySecret = makePassword()
	_Conf.cookieModules.keySecret = makePassword()
	_Conf.captchaKey = makePassword()
end	