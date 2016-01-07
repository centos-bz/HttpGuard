-- http-guard安装目录，修改为实际安装到的目录。
baseDir = '/data/www/waf/'

local Config = {
	-- key是否动态生成,可选static,dynamic,如果选dynamic,下面所有的keySecret不需要更改,如果选static,修改手动修改下面的keySecret
	keyDefine = "dynamic",

	-- 被动防御,限制请求模块。根据在一定时间内统计到的请求次数作限制,建议始终开启
	-- state : 为此模块的状态，表示开启或关闭，可选值为On或Off;
	-- maxReqs，amongTime : 在amongTime秒内允许请求的最大次数maxReqs，如默认的是在10s内最大允许请求50次。
	-- urlProtect : 指定限制请求次数的url正则表达式文件，默认值为\.php$，表示只限制php的请求(当然，当urlMatchMode = "uri"时，此正则才能起作用)
	limitReqModules = { state = "On" , maxReqs = 50 , amongTime = 10, urlProtect = baseDir.."url-protect/limit.txt" },


	-- 主动防御,302响应头跳转模块。利用cc控制端不支持解析响应头的特点，来识别是否为正常用户，当有必要时才建议开启。
	-- state : 为此模块的状态，表示开启或关闭，可选值为On或Off;
	-- verifyMaxFail  amongTime : 因为此模块会发送带有cckey及keyexpire的302响应头，如果访客在amongTime时间内超过verifyMaxFail次没有跳转到302响应头里的url，就会被添加到黑名单，默认值为5次。
	-- keySecret : 用于生成token的密码,如果上面的keyDefine为dynamic，就不需要修改
	-- urlProtect  同limitReqModules模块中的urlProtect的解释。
	redirectModules = { state = "Off" ,verifyMaxFail = 5, keySecret = 'yK48J276hg', amongTime = 60 ,urlProtect = baseDir.."url-protect/302.txt"},


	-- 主动防御,发送js跳转代码模块。利用cc控制端无法解析js跳转的特点，来识别是否为正常用户，当有必要时才建议开启。
	-- state : 为此模块的状态，表示开启或关闭，可选值为On或Off;
	-- verifyMaxFail  amongTime : 因为此模块会发送带有js跳转代码的响应体，如果访客在amongTime时间内超过verifyMaxFail次没有跳转到js跳转代码里的url，就会被添加到黑名单，默认值为5次。
	-- keySecret : 用于生成token的密码,如果上面的keyDefine为dynamic，就不需要修改
	-- urlProtect  同limitReqModules模块中的urlProtect的解释。
	JsJumpModules = { state = "Off" ,verifyMaxFail = 5, keySecret = 'QSjL6p38h9', amongTime = 60 , urlProtect = baseDir.."url-protect/js.txt"},

	-- 主动防御,发送cookie验证模块。此模块会向访客发送cookie，然后等待访客返回正确的cookie，此模块利用cc控制端无法支持cookie的特点，来识别cc攻击,当有必要时才建议开启
	-- state : 为此模块的状态，表示开启或关闭，可选值为On或Off;
	-- verifyMaxFail  amongTime : 因为此模块会发送cookie，如果访客在amongTime时间内超过verifyMaxFail次没有返回正确的cookie，就会被添加到黑名单，默认值为5次。
	-- keySecret : 用于生成token的密码,如果上面的keyDefine为dynamic，就不需要修改
	-- urlProtect  同limitReqModules模块中的urlProtect的解释。	
	cookieModules = { state = "Off" ,verifyMaxFail = 5, keySecret = 'bGMfY2D5t3', amongTime = 60 , urlProtect = baseDir.."url-protect/cookie.txt"},

	-- 自动开启主动防御,原理是根据protectPort端口的已连接数超过maxConnection来确定
	-- state : 为此模块的状态，表示开启或关闭，可选值为On或Off;
	-- interval  间隔30秒检查一次连接数，默认为30秒。
	-- protectPort，maxConnection,normalTimes,exceedTimes :  enableModule中的模块为关闭状态时，当端口protectPort的连接数连续exceedTimes次超过maxConnection时，开启enableModule中的模块；
	-- enableModule中的模块为开启状态时，当端口protectPort的连接数连续normalTimes次低于maxConnection时，关闭enableModule中的模块。
	-- ssCommand  : 我们是使用ss命令来检查特定端口的已连接的连接数，ss命令比同类的命令netstat快得多。请把ss命令的路径改为自己系统上的路径。
	-- enableModules : 自动启动哪个主动防御模块,可选值为redirectModules JsJumpModules cookieModules
	autoEnable = { state = "off", protectPort = "80", interval = 30, normalTimes = 3,exceedTimes = 2,maxConnection = 500, ssCommand = "/usr/sbin/ss" ,enableModule = "redirectModules"},

	-- 用于当输入验证码验证通过时,生成key的密码.如果上面的keyDefine为dynamic，就不需要修改
	captchaKey = "K4QEaHjwyF",

	-- ip在黑名单时执行的动作(可选值captcha,forbidden,iptables)
	-- 值为captcha时,表示ip在黑名单后返回带有验证码的页面,输入正确的验证码才允许继续访问网站
	-- 值为forbidden时,表示ip在黑名单后,服务器会直接断开与用户的连接.
	-- 值为iptables时,表示ip在黑名单后,http-guard会用iptables封锁此ip的连接
	-- 当值为iptables时,需要为nginx运行用户设置密码及添加到sudo以便能执行iptables命令。假设nginx运行用户为www,设置方法为：
	-- 1.设置www密码，命令为passwd www
	-- 2.以根用户执行visudo命令，添加www  ALL=(root) /sbin/iptables -I INPUT -p tcp -s [0-9.]* --dport 80 -j DROP
	-- 3.以根用户执行visudo命令，找到Default requiretty注释，即更改为#Default requiretty，如果找不到此设置，就不需要改。
	blockAction = "captcha",

	-- 用户IP在黑名单且blockAction为captcha时访问验证码页面超过一定次数触发iptables封锁
	captchaToIptables = { state = "off", maxReqs = 10 , amongTime = 10},

	-- nginx运行用户的sudo密码,blockAction值为iptables需要设置,否则不需要
	sudoPass = '',

	-- 表示http-guard封锁ip的时间
	blockTime = 600,

	-- JsJumpModules redirectModules cookieModules验证通过后,ip在白名单的时间
	whiteTime = 600,

	-- 用于生成token密码的key过期时间
	keyExpire = 600,

	-- 匹配url模式，可选值requestUri,uri
	-- 值requestUri时,url-protect目录下的正则匹配的是浏览器最初请求的地址且没有被decode,带参数的链接
	-- 值为uri时, url-protect目录下的正则匹配的是经过重写过的地址,不带参数,且已经decode.
	urlMatchMode = "uri",
	
	-- 验证码页面路径,一般不需要修改
	captchaPage = baseDir.."html/captcha.html",

	-- 输入验证码错误时显示的页面路径,一般不需要修改
	reCaptchaPage = baseDir.."html/reCatchaPage.html",

	-- 白名单ip文件,文件内容为正则表达式。
	whiteIpModules = { state = "Off", ipList = baseDir.."url-protect/white_ip_list.txt" },

	-- 如果需要从请求头获取真实ip,此值就需要设置,如x-forwarded-for
	-- 当state为on时,此设置才有效
	realIpFromHeader = { state = "Off", header = "x-forwarded-for"},

	-- 指定验证码图片目录,一般不需要修改
	captchaDir = baseDir.."captcha/",

	-- 是否开启debug日志
	debug = false,

	--日志目录,一般不需要修改.但需要设置logs所有者为nginx运行用户，如nginx运行用户为www，则命令为chown www logs
	logPath = baseDir.."logs/",
}

return Config