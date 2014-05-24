--http-guard脚本目录
baseDir = '/data/www/waf/'

local Config = {
	
	--被动防御,限制访问次数
	limitReqModules = { state = "On" , maxReqs = 50 ,amongTime = 10, urlProtect = baseDir.."url-protect/limit.txt" },

	--主动防御,发送302跳转识别
	redirectModules = { state = "Off" ,verifyMaxFail = 3, amongTime = 60 ,urlProtect = baseDir.."url-protect/302.txt"},

	--主动防御,发送js跳转代码
	JsJumpModules = { state = "Off" ,verifyMaxFail = 3, amongTime = 60 , urlProtect = baseDir.."url-protect/js.txt"},

	--key值
	keySecret = '948gkj3jdls',

	--ip在黑名单时执行的动作(可选值captcha,forbidden,iptables)
	blockAction = "captcha",

	--黑名单时间
	blockTime = 600,

	--key过期时间
	keyExpire = 600,

	--匹配url模式，可选值requestUri,uri(注:requestUri是浏览器最初请求的地址且没有被decode,带参数;uri为经过重写过的地址,不带参数,且已经decode.)
	urlMatchMode = "uri",

	--nginx运行用户的sudo 密码
	sudoPass = '',
	
	--验证码页面路径
	captchaPage = baseDir.."html/captcha.html",

	--再次获取验证码页面路径
	reCaptchaPage = baseDir.."html/reCatchaPage.html",

	--白名单
	whiteIpModules = { state = "Off", ipList = baseDir.."url-protect/white_ip_list.txt" },

	--如果需要从请求头获取真实ip,此值就需要设置,如x-forwarded-for,否则请设置为none
	realIpFromHeader = { state = "Off", header = "x-forwarded-for"},

	--指定验证码图片目录
	captchaDir = baseDir.."captcha/",
	--是否开启debug日志
	debug = false,
}

return Config