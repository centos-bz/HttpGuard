local Guard = {}

--debug日志
function Guard:debug(data)
	if _Conf.debug then
		ngx.log(ngx.ERR,data)
	end
end

--获取表元素数量
function Guard:tlen(t)
   local c = 0
   for k,v in pairs(t) do
        c = c+1
   end
   return c
end

--获取真实ip
function Guard:getRealIp(remoteIp,headers)
	if _Conf.realIpFromHeaderIsOn then
		readIp = headers[_Conf.realIpFromHeader.header]
		if readIp then
			self:debug("realIpFromHeader is on.return ip "..readIp)
			return headers[_Conf.realIpFromHeader.header]
		else
			return remoteIp
		end	
	else
		return remoteIp
	end	
end

--白名单模块
function Guard:ipInWhiteList(ip)
	if _Conf.whiteIpModulesIsOn then --判断是否开启白名单模块
		self:debug("whiteIpModules is on.")

		if ngx.re.match(ip, _Conf.whiteIpList) then --匹配白名单列表
			self:debug("ip "..ip.. " match white list ".._Conf.whiteIpList)
			return true
		else
			return false
		end	
	end
end

--黑名单模块
function Guard:blackListModules(ip,reqUri)
	local blackKey = ip.."black"
	if _Conf.dict:get(blackKey) then --判断ip是否存在黑名单字典
		self:debug("ip "..ip.." in blacklist")
		self:takeAction(ip,reqUri) --存在则执行相应动作
	end	
end

--限制请求速率模块
function Guard:limitReqModules(ip,reqUri,uri)
	if _Conf.limitReqModulesIsOn then --limitReq模块是否开启
		self:debug("limitReqModules is on.")	
		local blackKey = ip.."black"
		local limitReqKey = ip.."limitreqkey" --定义limitreq key
		local reqTimes = _Conf.dict:get(limitReqKey) --获取此ip请求的次数

		--增加一次请求记录
		if reqTimes then
			_Conf.dict:incr(limitReqKey, 1)
		else
			_Conf.dict:set(limitReqKey, 1, _Conf.limitReqModules.amongTime)
			reqTimes = 0
		end

		local newReqTimes  = reqTimes + 1
		self:debug("newReqTimes "..newReqTimes)

		--判断请求数是否大于阀值,大于则添加黑名单
		if newReqTimes > _Conf.limitReqModules.maxReqs then --判断是否请求数大于阀值
			self:debug("ip "..ip.. " request exceed ".._Conf.limitReqModules.maxReqs)
			_Conf.dict:set(blackKey,0,_Conf.blockTime) --添加此ip到黑名单
			ngx.log(ngx.ERR,"Warning:IP "..ip.." visit "..newReqTimes.." times,block it.")
		end

	end
end

--302转向模块
function Guard:redirectModules(ip,reqUri)
	if _Conf.redirectModulesIsOn then --判断转向模块是否开启
		self:debug("redirectModules is on.")
		local cookie_key = ngx.var["cookie_key302"] --获取cookie密钥
		local cookie_expire = ngx.var["cookie_expire302"] --获取cookie密钥过期时间
		local now = ngx.time() --当前时间戳
		local args = ngx.req.get_uri_args()
		local challengeTimesKey = table.concat({ip,"challenge"})
		local challengeTimesValue = _Conf.dict:get(challengeTimesKey)
		local blackKey = ip.."black"

		if cookie_key and cookie_expire then
			local key_make = ngx.md5(table.concat({ip,_Conf.keySecret,cookie_expire}))
			local key_make = string.sub(key_make,"1","10")
			if tonumber(cookie_expire) > now and cookie_key == key_make then
				self:debug("cookie key is valid.")
				if challengeTimesValue then
					_Conf.dict:delete(challengeTimesKey) --删除验证失败计数器
				end	
				return
			else
				self:debug("ip "..ip.." cookie key is invalid.")
				local expire = now + _Conf.keyExpire
				local key_new = ngx.md5(table.concat({ip,_Conf.keySecret,expire}))
				local key_new = string.sub(key_new,"1","10")					
				--定义转向的url
				local newUrl = ''
				if self:tlen(args) == 0 then
					newUrl = table.concat({reqUri,"?cckey=",key_new,"&keyexpire=",expire})
				else
					--删除cckey和keyexpire
					args.cckey = nil
					args.keyexpire = nil							
					--删除reqUri参数
					local newArgs = ''
					local reqUriNoneArgs = ngx.re.match(ngx.var.request_uri, "(.*?)\\?")[1]
					for key, value in pairs(args) do  
						newArgs = table.concat({newArgs,key,"=",value,"&"})
					end							

					if self:tlen(args) == 0 then
						newUrl = table.concat({reqUriNoneArgs,"?cckey=",key_new,"&keyexpire=",expire})
					else
						newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"cckey=",key_new,"&keyexpire=",expire})		
					end
				end

				--验证失败次数加1
				if challengeTimesValue then
					_Conf.dict:incr(challengeTimesKey,1)
					if challengeTimesValue + 1> _Conf.redirectModules.verifyMaxFail then
						_Conf.dict:set(blackKey,0,_Conf.blockTime) --添加此ip到黑名单
					end	
				else
					_Conf.dict:set(challengeTimesKey,1,_Conf.redirectModules.amongTime)
				end		

				--删除cookie
				ngx.header['Set-Cookie'] = {"key302=; path=/", "expire302=; expires=Sat, 01-Jan-2000 00:00:00 GMT; path=/"}
				return ngx.redirect(newUrl, 302) --发送302转向						
			end
		else
			local ccKeyValue = args["cckey"] --获取url中的cckey参数
			local expire = args['keyexpire'] --获取过期时间

			if ccKeyValue and expire then
				local key_make = ngx.md5(table.concat({ip,_Conf.keySecret,expire}))
				local key_make = string.sub(key_make,"1","10")
				self:debug("ccKeyValue "..ccKeyValue)
				self:debug("expire "..expire)
				self:debug("key_make "..key_make)
				self:debug("ccKeyValue "..ccKeyValue)
				if key_make == ccKeyValue and now < tonumber(expire) then--判断传过来的cckey参数值是否等于字典记录的值,且没有过期
					self:debug("ip "..ip.." arg cckey "..ccKeyValue.." is valid.set valid cookie.")
					local expire = now + _Conf.keyExpire
					local key_new = ngx.md5(table.concat({ip,_Conf.keySecret,expire}))
					local key_new = string.sub(key_new,"1","10")

					if challengeTimesValue then
						_Conf.dict:delete(challengeTimesKey) --删除验证失败计数器
					end								
					ngx.header['Set-Cookie'] = {"key302="..key_new.."; path=/", "expire302="..expire.."; path=/"}
					return
				else --如果不相等，则再发送302转向
					self:debug("ip "..ip.." arg cckey is invalid.")
					local expire = now + _Conf.keyExpire
					local key_new = ngx.md5(table.concat({ip,_Conf.keySecret,expire}))
					local key_new = string.sub(key_new,"1","10")

					--验证失败次数加1
					if challengeTimesValue then
						_Conf.dict:incr(challengeTimesKey,1)
						if challengeTimesValue + 1 > _Conf.redirectModules.verifyMaxFail then
							_Conf.dict:set(blackKey,0,_Conf.blockTime) --添加此ip到黑名单
						end	
					else
						_Conf.dict:set(challengeTimesKey,1,_Conf.redirectModules.amongTime)
					end												
					--定义转向的url
					local newUrl = ''
					if self:tlen(args) == 0 then
						newUrl = table.concat({reqUri,"?cckey=",key_new,"&keyexpire=",expire})
					else
						--删除cckey和keyexpire
						args.cckey = nil
						args.keyexpire = nil							
						--删除reqUri参数
						local newArgs = ''
						local reqUriNoneArgs = ngx.re.match(ngx.var.request_uri, "(.*?)\\?")[1]
						for key, value in pairs(args) do  
							newArgs = table.concat({newArgs,key,"=",value,"&"})
						end							

						if self:tlen(args) == 0 then
							newUrl = table.concat({reqUriNoneArgs,"?cckey=",key_new,"&keyexpire=",expire})
						else
							newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"cckey=",key_new,"&keyexpire=",expire})				
						end
					end

					return ngx.redirect(newUrl, 302) --发送302转向
				end
			else
				--验证失败次数加1
				if challengeTimesValue then
					_Conf.dict:incr(challengeTimesKey,1)
					if challengeTimesValue +1 > _Conf.redirectModules.verifyMaxFail then
						_Conf.dict:set(blackKey,0,_Conf.blockTime) --添加此ip到黑名单
					end	
				else
					_Conf.dict:set(challengeTimesKey,1,_Conf.redirectModules.amongTime)
				end

				local expire = now + _Conf.keyExpire
				local key_new = ngx.md5(table.concat({ip,_Conf.keySecret,expire}))
				local key_new = string.sub(key_new,"1","10")	
								
				--定义转向的url
				local newUrl = ''
				if self:tlen(args) == 0 then
					newUrl = table.concat({reqUri,"?cckey=",key_new,"&keyexpire=",expire})
				else
					--删除cckey和keyexpire
					args.cckey = nil
					args.keyexpire = nil							
					--删除reqUri参数
					local newArgs = ''
					local reqUriNoneArgs = ngx.re.match(ngx.var.request_uri, "(.*?)\\?")[1]
					for key, value in pairs(args) do  
						newArgs = table.concat({newArgs,key,"=",value,"&"})
					end							

					if self:tlen(args) == 0 then
						newUrl = table.concat({reqUriNoneArgs,"?cckey=",key_new,"&keyexpire=",expire})
					else
						newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"cckey=",key_new,"&keyexpire=",expire})				
					end
				end

				return ngx.redirect(newUrl, 302) --发送302转向			
			end	
		end
	end
end

--js跳转模块
function Guard:JsJumpModules(ip,reqUri)

	if _Conf.JsJumpModulesIsOn then --判断js跳转模块是否开启
		self:debug("JsJumpModules is on.")
		local cookie_key = ngx.var["cookie_keyjs"] --获取cookie密钥
		local cookie_expire = ngx.var["cookie_expirejs"] --获取cookie密钥过期时间
		local now = ngx.time() --当前时间戳
		local args = ngx.req.get_uri_args()
		local challengeTimesKey = table.concat({ip,"challenge"})
		local challengeTimesValue = _Conf.dict:get(challengeTimesKey)
		local blackKey = ip.."black"
				
		if cookie_key and cookie_expire then
			local key_make = ngx.md5(table.concat({ip,_Conf.keySecret,cookie_expire}))
			local key_make = string.sub(key_make,"1","10")
			if tonumber(cookie_expire) > now and cookie_key == key_make then
				if challengeTimesValue then
					_Conf.dict:delete(challengeTimesKey) --删除验证失败计数器
				end					
				self:debug("cookie key is valid.")
				return
			else
				--验证失败次数加1
				if challengeTimesValue then
					_Conf.dict:incr(challengeTimesKey,1)
					if challengeTimesValue +1 > _Conf.JsJumpModules.verifyMaxFail then
						_Conf.dict:set(blackKey,0,_Conf.blockTime) --添加此ip到黑名单
					end	
				else
					_Conf.dict:set(challengeTimesKey,1,_Conf.JsJumpModules.amongTime)
				end
				
				self:debug("ip "..ip.." cookie key is invalid.")
				local expire = now + _Conf.keyExpire
				local key_new = ngx.md5(table.concat({ip,_Conf.keySecret,expire}))
				local key_new = string.sub(key_new,"1","10")

				--定义转向的url
				local newUrl = ''
				if self:tlen(args) == 0 then
					newUrl = table.concat({reqUri,"?cckey=",key_new,"&keyexpire=",expire})
				else
					--删除cckey和keyexpire
					args.cckey = nil
					args.keyexpire = nil							
					--删除reqUri参数
					local newArgs = ''
					local reqUriNoneArgs = ngx.re.match(ngx.var.request_uri, "(.*?)\\?")[1]
					for key, value in pairs(args) do  
						newArgs = table.concat({newArgs,key,"=",value,"&"})
					end							

					if self:tlen(args) == 0 then
						newUrl = table.concat({reqUriNoneArgs,"?cckey=",key_new,"&keyexpire=",expire})
					else
						newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"cckey=",key_new,"&keyexpire=",expire})		
					end
				end

				local jsJumpCode=table.concat({"<script>window.location.href='",newUrl,"';</script>"}) --定义js跳转代码
				ngx.header.content_type = "text/html"
				--删除cookie
				ngx.header['Set-Cookie'] = {"keyjs=; path=/", "expirejs=; expires=Sat, 01-Jan-2000 00:00:00 GMT; path=/"}						
				ngx.print(jsJumpCode)
				ngx.exit(200)					
			end
		else
			local ccKeyValue = args["cckey"] --获取url中的cckey参数
			local expire = args['keyexpire'] --获取过期时间

			if ccKeyValue and expire then
				local key_make = ngx.md5(table.concat({ip,_Conf.keySecret,expire}))
				local key_make = string.sub(key_make,"1","10")

				if key_make == ccKeyValue and now < tonumber(expire) then--判断传过来的cckey参数值是否等于字典记录的值,且没有过期
					self:debug("ip "..ip.." arg cckey "..ccKeyValue.." is valid.set valid cookie.")
					if challengeTimesValue then
						_Conf.dict:delete(challengeTimesKey) --删除验证失败计数器
					end							
					ngx.header['Set-Cookie'] = {"keyjs="..ccKeyValue.."; path=/", "expirejs="..expire.."; path=/"}
					return
				else --如果不相等，则再发送302转向
					--验证失败次数加1
					if challengeTimesValue then
						_Conf.dict:incr(challengeTimesKey,1)
						if challengeTimesValue + 1 > _Conf.JsJumpModules.verifyMaxFail then
							_Conf.dict:set(blackKey,0,_Conf.blockTime) --添加此ip到黑名单
						end	
					else
						_Conf.dict:set(challengeTimesKey,1,_Conf.JsJumpModules.amongTime)
					end	
					
					self:debug("ip "..ip.." arg cckey is invalid.")
					local expire = now + _Conf.keyExpire
					local key_new = ngx.md5(table.concat({ip,_Conf.keySecret,expire}))
					local key_new = string.sub(key_new,"1","10")				
					--定义转向的url
					local newUrl = ''
					if self:tlen(args) == 0 then
						newUrl = table.concat({reqUri,"?cckey=",key_new,"&keyexpire=",expire})
					else
						--删除cckey和keyexpire
						args.cckey = nil
						args.keyexpire = nil							
						--删除reqUri参数
						local newArgs = ''
						local reqUriNoneArgs = ngx.re.match(ngx.var.request_uri, "(.*?)\\?")[1]
						for key, value in pairs(args) do  
							newArgs = table.concat({newArgs,key,"=",value,"&"})
						end							

						if self:tlen(args) == 0 then
							newUrl = table.concat({reqUriNoneArgs,"?cckey=",key_new,"&keyexpire=",expire})
						else
							newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"cckey=",key_new,"&keyexpire=",expire})		
						end
					end
					local jsJumpCode=table.concat({"<script>window.location.href='",newUrl,"';</script>"}) --定义js跳转代码
					ngx.header.content_type = "text/html"
					ngx.print(jsJumpCode)
					ngx.exit(200)
				end
			else
				--验证失败次数加1
				if challengeTimesValue then
					_Conf.dict:incr(challengeTimesKey,1)
					if challengeTimesValue + 1 > _Conf.JsJumpModules.verifyMaxFail then
						_Conf.dict:set(blackKey,0,_Conf.blockTime) --添加此ip到黑名单
					end	
				else
					_Conf.dict:set(challengeTimesKey,1,_Conf.JsJumpModules.amongTime)
				end
				
				--定义转向的url
				local expire = now + _Conf.keyExpire
				local key_new = ngx.md5(table.concat({ip,_Conf.keySecret,expire}))
				local key_new = string.sub(key_new,"1","10")
								
				--定义转向的url
				local newUrl = ''
				if self:tlen(args) == 0 then
					newUrl = table.concat({reqUri,"?cckey=",key_new,"&keyexpire=",expire})
				else
					--删除cckey和keyexpire
					args.cckey = nil
					args.keyexpire = nil							
					--删除reqUri参数
					local newArgs = ''
					local reqUriNoneArgs = ngx.re.match(ngx.var.request_uri, "(.*?)\\?")[1]
					for key, value in pairs(args) do  
						newArgs = table.concat({newArgs,key,"=",value,"&"})
					end							

					if self:tlen(args) == 0 then
						newUrl = table.concat({reqUriNoneArgs,"?cckey=",key_new,"&keyexpire=",expire})
					else
						newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"cckey=",key_new,"&keyexpire=",expire})		
					end
				end

				local jsJumpCode=table.concat({"<script>window.location.href='",newUrl,"';</script>"}) --定义js跳转代码
				ngx.header.content_type = "text/html"
				ngx.print(jsJumpCode)
				ngx.exit(200)				
			end	
		end
	end
end

--获取验证码
function Guard:getCaptcha()
	math.randomseed(ngx.now()) --随机种子
	local random = math.random(1,10000) --生成1-10000之前的随机数
	self:debug("get random num "..random)
	local captchaValue = _Conf.dict_captcha:get(random) --取得字典中的验证码
	self:debug("get captchaValue "..captchaValue)
	local captchaImg = _Conf.dict_captcha:get(captchaValue) --取得验证码对应的图片
	--返回图片
	ngx.header.content_type = "image/jpeg"
	ngx.header['Set-Cookie'] = table.concat({"captchaNum=",random,"; path=/"})
	ngx.print(captchaImg)
	ngx.exit(200)	
end

 --验证验证码
function Guard:verifyCaptcha(ip)
	ngx.req.read_body()
	local captchaNum = ngx.var["cookie_captchaNum"] --获取cookie captchaNum值
	local preurl = ngx.var["cookie_preurl"] --获取上次访问url
	self:debug("get cookie captchaNum "..captchaNum)
	local args = ngx.req.get_post_args() --获取post参数
	local postValue = args["response"] --获取post value参数
	postValue = string.lower(postValue)
	self:debug("get post arg response "..postValue)
	local captchaValue = _Conf.dict_captcha:get(captchaNum) --从字典获取post value对应的验证码值
	if captchaValue == postValue then --比较验证码是否相等
		self:debug("captcha is valid.delete from blacklist")
		_Conf.dict:delete(ip.."black") --从黑名单删除
		_Conf.dict:delete(ip.."limitreqkey") --访问记录删除
		local expire = ngx.time() + _Conf.keyExpire
		local captchaKey = ngx.md5(table.concat({ip,_Conf.keySecret,expire}))
		local captchaKey = string.sub(captchaKey,"1","10")
		self:debug("expire "..expire)
		self:debug("captchaKey "..captchaKey)	
		ngx.header['Set-Cookie'] = {"captchaKey="..captchaKey.."; path=/", "captchaExpire="..expire.."; path=/"}
		return ngx.redirect(preurl) --返回上次访问url
	else
		--重新发送验证码页面
		self:debug("captcha invalid")
		ngx.header.content_type = "text/html"
		ngx.print(_Conf.reCaptchaPage)
		ngx.exit(200)
	end 
end

--拒绝访问动作
function Guard:forbiddenAction()
		ngx.header.content_type = "text/html"
		ngx.exit(444)
end

--展示验证码页面动作
function Guard:captchaAction(reqUri)
	ngx.header.content_type = "text/html"
	ngx.header['Set-Cookie'] = table.concat({"preurl=",reqUri,"; path=/"})
	ngx.print(_Conf.captchaPage)
	ngx.exit(200)
end

--iptables动作
function Guard:iptablesAction(reqUri)
	ngx.header.content_type = "text/html"
	ngx.header['Set-Cookie'] = table.concat({"preurl=",reqUri,"; path=/"})
	ngx.print(_Conf.captchaPage)
	ngx.exit(200)
end


--执行相应动作
function Guard:takeAction(ip,reqUri)
	if _Conf.captchaAction then
		local cookie_key = ngx.var["cookie_captchaKey"] --获取cookie captcha密钥
		local cookie_expire = ngx.var["cookie_captchaExpire"] --获取cookie captcha过期时间
		if cookie_expire and cookie_key then
			local now = ngx.time()
			local key_make = ngx.md5(table.concat({ip,_Conf.keySecret,cookie_expire}))
			local key_make = string.sub(key_make,"1","10")
			self:debug("cookie_expire "..cookie_expire)
			self:debug("cookie_key "..cookie_key)
			self:debug("now "..now)
			self:debug("key_make "..key_make)
			if tonumber(cookie_expire) > now and cookie_key == key_make then
				self:debug("cookie key is valid.")
				return
			else
				self:debug("cookie key is invalid")
				self:captchaAction(reqUri)
			end	
		else	
			self:debug("return captchaAction")
			self:captchaAction(reqUri)
		end	
	elseif _Conf.forbiddenAction then
		self:debug("return forbiddenAction")
		self:forbiddenAction()

	elseif _Conf.iptablesAction then
		ngx.thread.spawn(Guard.addToIptables,Guard,ip)
	end
end

--添加进iptables drop表
function Guard:addToIptables(ip)
	local cmd = "echo ".._Conf.sudoPass.." | sudo -S /sbin/iptables -I INPUT -p tcp -s "..ip.." --dport 80 -j DROP"
	os.execute(cmd)
end

--自动开启或关闭防cc功能
function Guard:autoSwitch()
	if not _Conf.dict:get("monitor") then
		_Conf.dict:set("monitor",0,_Conf.autoEnable.interval)
		local f=io.popen(_Conf.autoEnable.ssCommand.." -tan state established '( sport = :".._Conf.autoEnable.protectPort.." )' | wc -l")
		local result=f:read("*all")
		local connection=tonumber(result)
		Guard:debug("current connection for port ".._Conf.autoEnable.protectPort.." is "..connection)
		if _Conf.autoEnable.enableModule == "redirectModules" then
			if _Conf.redirectModulesIsOn then
				_Conf.exceedCount = 0 --超限次数清0
				--如果当前连接在最大连接之下,为正常次数加1
				if connection < _Conf.autoEnable.maxConnection then
					_Conf.normalCount = _Conf.normalCount + 1
				end

				--如果正常次数大于_Conf.autoEnable.normalTimes,关闭redirectModules
				if _Conf.normalCount > _Conf.autoEnable.normalTimes then
					ngx.log(ngx.ERR,"turn redirectModules off.")
					_Conf.redirectModulesIsOn = false
				end	
			else
				_Conf.normalCount = 0 --正常次数清0
				--如果当前连接在最大连接之上,为超限次数加1
				if connection > _Conf.autoEnable.maxConnection then
					_Conf.exceedCount = _Conf.exceedCount + 1
				end

				--如果超限次数大于_Conf.autoEnable.exceedTimes,开启redirectModules
				if _Conf.exceedCount > _Conf.autoEnable.exceedTimes then
					ngx.log(ngx.ERR,"turn redirectModules on.")
					_Conf.redirectModulesIsOn = true
				end					
			end

		elseif 	_Conf.autoEnable.enableModule == "JsJumpModules" then
			if _Conf.JsJumpModulesIsOn then
				_Conf.exceedCount = 0 --超限次数清0
				--如果当前连接在最大连接之下,为正常次数加1
				if connection < _Conf.autoEnable.maxConnection then
					_Conf.normalCount = _Conf.normalCount + 1
				end

				--如果正常次数大于_Conf.autoEnable.normalTimes,关闭JsJumpModules
				if _Conf.normalCount > _Conf.autoEnable.normalTimes then
					ngx.log(ngx.ERR,"turn JsJumpModules off.")
					_Conf.JsJumpModulesIsOn = false
				end	
			else
				_Conf.normalCount = 0 --正常次数清0
				--如果当前连接在最大连接之上,为超限次数加1
				if connection > _Conf.autoEnable.maxConnection then
					_Conf.exceedCount = _Conf.exceedCount + 1
				end

				--如果超限次数大于_Conf.autoEnable.exceedTimes,开启JsJumpModules
				if _Conf.exceedCount > _Conf.autoEnable.exceedTimes then
					ngx.log(ngx.ERR,"turn JsJumpModules on.")
					_Conf.JsJumpModulesIsOn = true
				end					
			end
		end	
	end	
end

return Guard