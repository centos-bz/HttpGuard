local Config = {
	
	--被动防御,限制访问次数
	limitReqModules = { state = "On" , maxReqs = 300, keySecret = "948gkj3jdls",keyExpire = 600,amongTime = 60, action = "captchaAction" },

	--主动防御,发送302跳转识别
	redirectModules = { state = "Off" ,whiteTime = 3600, keySecret = "5C6NR8wLg2", keyExpire = 600, urlProtect = "/data/www/waf/send_302_redirect_url_protect"},

	--主动防御,发送js跳转代码
	JsJumpModules = { state = "Off" ,whiteTime = 3600, keySecret = "39durm82df",keyExpire = 600, urlProtect = "/data/www/waf/send_js_redirect_url_protect"},

	--黑名单时间
	blockTime = 600,
	
	--验证码页面路径
	captchaPage = "/data/www/waf/html/captcha.html",

	--再次获取验证码页面路径
	reCaptchaPage = "/data/www/waf/html/reCatchaPage.html",

	--白名单
	whiteIpModules = { state = "Off", ipList = "/data/www/waf/white_ip_list" },

	--如果需要从请求头获取真实ip,此值就需要设置,如x-forwarded-for,否则请设置为none
	realIpFromHeader = { state = "Off", header = "x-forwarded-for"},

	--指定验证码图片目录
	captchaDir = "/data/www/waf/captcha/",
	--是否开启debug日志
	debug = false,
}

return Config