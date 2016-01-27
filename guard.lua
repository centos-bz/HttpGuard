local Guard = {}

--debug日志
function Guard:debug(data,ip,reqUri)
	if _Conf.debug then
		local date = os.date("%Y-%m-%d")
		local filename = _Conf.logPath.."/debug-"..date..".log"
		local file = io.open(filename,"a+")
		file:write(os.date('%Y-%m-%d %H:%M:%S').." [DEBUG] "..data.." IP "..ip.." GET "..reqUri.."\n")
		file:close()
	end
end

--攻击日志
function Guard:log(data)
	local date = os.date("%Y-%m-%d")
	local filename = _Conf.logPath.."/attack-"..date..".log"
	local file = io.open(filename,"a+")
	file:write(os.date('%Y-%m-%d %H:%M:%S').." [WARNING] "..data.."\n")
	file:close()	
end

--获取真实ip
function Guard:getRealIp(remoteIp,headers)
    if _Conf.realIpFromHeaderIsOn then
        realIp = headers[_Conf.realIpFromHeader.header]
        if realIp then
            if type(realIp) == "table" then
                realIp = realIp[1]
            end      
            self:debug("[getRealIp] realIpFromHeader is on.return ip "..realIp,remoteIp,"")
            return realIp
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
		self:debug("[ipInWhiteList] whiteIpModules is on.",ip,"")

		if ngx.re.match(ip, _Conf.whiteIpList) then --匹配白名单列表
			self:debug("[ipInWhiteList] ip "..ip.. " match white list ".._Conf.whiteIpList,ip,"")
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
		self:debug("[blackListModules] ip "..ip.." in blacklist",ip,reqUri)
		self:takeAction(ip,reqUri) --存在则执行相应动作
	end	
end

--限制请求速率模块
function Guard:limitReqModules(ip,reqUri,address)
	if ngx.re.match(address,_Conf.limitUrlProtect,"i") then	
		self:debug("[limitReqModules] address "..address.." match reg ".._Conf.limitUrlProtect,ip,reqUri)	
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
		self:debug("[limitReqModules] newReqTimes "..newReqTimes,ip,reqUri)

		--判断请求数是否大于阀值,大于则添加黑名单
		if newReqTimes > _Conf.limitReqModules.maxReqs then --判断是否请求数大于阀值
			self:debug("[limitReqModules] ip "..ip.. " request exceed ".._Conf.limitReqModules.maxReqs,ip,reqUri)
			_Conf.dict:set(blackKey,0,_Conf.blockTime) --添加此ip到黑名单
			self:log("[limitReqModules] IP "..ip.." visit "..newReqTimes.." times,block it.")
		end

	end
end

--302转向模块
function Guard:redirectModules(ip,reqUri,address)
	if ngx.re.match(address,_Conf.redirectUrlProtect,"i") then
		self:debug("[redirectModules] address "..address.." match reg ".._Conf.redirectUrlProtect,ip,reqUri)
		local whiteKey = ip.."white302"
		local inWhiteList = _Conf.dict:get(whiteKey)
		
		if inWhiteList then --如果在白名单
			self:debug("[redirectModules] in white ip list",ip,reqUri)
			return
		else			
			--如果不在白名单,再检测是否有cookie凭证
			local now = ngx.time() --当前时间戳
			local challengeTimesKey = table.concat({ip,"challenge302"})
			local challengeTimesValue = _Conf.dict:get(challengeTimesKey)
			local blackKey = ip.."black"
			local cookie_key = ngx.var["cookie_key302"] --获取cookie密钥
			local cookie_expire = ngx.var["cookie_expire302"] --获取cookie密钥过期时间

			if cookie_key and cookie_expire then
				local key_make = ngx.md5(table.concat({ip,_Conf.redirectModules.keySecret,cookie_expire}))
				local key_make = string.sub(key_make,"1","10")
				--判断cookie是否有效
				if tonumber(cookie_expire) > now and cookie_key == key_make then
					self:debug("[redirectModules] cookie key is valid.",ip,reqUri)
					if challengeTimesValue then
						_Conf.dict:delete(challengeTimesKey) --删除验证失败计数器
					end
					_Conf.dict:set(whiteKey,0,_Conf.whiteTime) --添加到白名单
					return
				else
					self:debug("[redirectModules] cookie key is invalid.",ip,reqUri)
					local expire = now + _Conf.keyExpire
					local key_new = ngx.md5(table.concat({ip,_Conf.redirectModules.keySecret,expire}))
					local key_new = string.sub(key_new,"1","10")					
					--定义转向的url
					local newUrl = ''
					local newReqUri = ngx.re.match(reqUri, "(.*?)\\?(.+)")
					if newReqUri then
						local reqUriNoneArgs = newReqUri[1]
						local args = newReqUri[2]
						--删除cckey和keyexpire
						local newArgs = ngx.re.gsub(args, "[&?]?key302=[^&]+&?|expire302=[^&]+&?", "", "i")
						if newArgs == "" then
							newUrl = table.concat({reqUriNoneArgs,"?key302=",key_new,"&expire302=",expire})
						else
							newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"&key302=",key_new,"&expire302=",expire})
						end					
					else
						newUrl = table.concat({reqUri,"?key302=",key_new,"&expire302=",expire})

					end

					--验证失败次数加1
					if challengeTimesValue then
						_Conf.dict:incr(challengeTimesKey,1)
						if challengeTimesValue + 1> _Conf.redirectModules.verifyMaxFail then
							self:debug("[redirectModules] client "..ip.." challenge cookie failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
							self:log("[redirectModules] client "..ip.." challenge cookie failed "..challengeTimesValue.." times,add to blacklist.")
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
				--如果没有找到cookie,则检测是否带cckey参数
				local ccKeyValue = ngx.re.match(reqUri, "key302=([^&]+)","i")
				local expire = ngx.re.match(reqUri, "expire302=([^&]+)","i")

				if ccKeyValue and expire then --是否有cckey和keyexpire参数
					local ccKeyValue = ccKeyValue[1]
					local expire = expire[1]
					local key_make = ngx.md5(table.concat({ip,_Conf.redirectModules.keySecret,expire}))
					local key_make = string.sub(key_make,"1","10")
					self:debug("[redirectModules] ccKeyValue "..ccKeyValue,ip,reqUri)
					self:debug("[redirectModules] expire "..expire,ip,reqUri)
					self:debug("[redirectModules] key_make "..key_make,ip,reqUri)
					self:debug("[redirectModules] ccKeyValue "..ccKeyValue,ip,reqUri)
					if key_make == ccKeyValue and now < tonumber(expire) then--判断传过来的cckey参数值是否等于字典记录的值,且没有过期
						self:debug("[redirectModules] ip "..ip.." arg key302 "..ccKeyValue.." is valid.add ip to write list.",ip,reqUri)

						if challengeTimesValue then
							_Conf.dict:delete(challengeTimesKey) --删除验证失败计数器
						end								
						_Conf.dict:set(whiteKey,0,_Conf.whiteTime) --添加到白名单
						ngx.header['Set-Cookie'] = {"key302="..key_make.."; path=/", "expire302="..expire.."; path=/"} --发送cookie凭证
						return
					else --如果不相等，则再发送302转向
						self:debug("[redirectModules] ip "..ip.." arg key302 is invalid.",ip,reqUri)
						local expire = now + _Conf.keyExpire
						local key_new = ngx.md5(table.concat({ip,_Conf.redirectModules.keySecret,expire}))
						local key_new = string.sub(key_new,"1","10")

						--验证失败次数加1
						if challengeTimesValue then
							_Conf.dict:incr(challengeTimesKey,1)
							if challengeTimesValue + 1 > _Conf.redirectModules.verifyMaxFail then
								self:debug("[redirectModules] client "..ip.." challenge 302key failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
								self:log("[redirectModules] client "..ip.." challenge 302key failed "..challengeTimesValue.." times,add to blacklist.")
								_Conf.dict:set(blackKey,0,_Conf.blockTime) --添加此ip到黑名单
							end	
						else
							_Conf.dict:set(challengeTimesKey,1,_Conf.redirectModules.amongTime)
						end												
						--定义转向的url
						local newUrl = ''
						local newReqUri = ngx.re.match(reqUri, "(.*?)\\?(.+)")
						if newReqUri then
							local reqUriNoneArgs = newReqUri[1]
							local args = newReqUri[2]
							--删除cckey和keyexpire
							local newArgs = ngx.re.gsub(args, "[&?]?key302=[^&]+&?|expire302=[^&]+&?", "", "i")
							if newArgs == "" then
								newUrl = table.concat({reqUriNoneArgs,"?key302=",key_new,"&expire302=",expire})
							else
								newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"&key302=",key_new,"&expire302=",expire})
							end					
						else
							newUrl = table.concat({reqUri,"?key302=",key_new,"&expire302=",expire})

						end

						return ngx.redirect(newUrl, 302) --发送302转向
					end
				else
					--验证失败次数加1
					if challengeTimesValue then
						_Conf.dict:incr(challengeTimesKey,1)
						if challengeTimesValue +1 > _Conf.redirectModules.verifyMaxFail then
							self:debug("[redirectModules] client "..ip.." challenge 302key failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
							self:log("[redirectModules] client "..ip.." challenge 302key failed "..challengeTimesValue.." times,add to blacklist.")
							_Conf.dict:set(blackKey,0,_Conf.blockTime) --添加此ip到黑名单
						end	
					else
						_Conf.dict:set(challengeTimesKey,1,_Conf.redirectModules.amongTime)
					end

					local expire = now + _Conf.keyExpire
					local key_new = ngx.md5(table.concat({ip,_Conf.redirectModules.keySecret,expire}))
					local key_new = string.sub(key_new,"1","10")	
									
					--定义转向的url
					local newUrl = ''
					local newReqUri = ngx.re.match(reqUri, "(.*?)\\?(.+)")
					if newReqUri then
						local reqUriNoneArgs = newReqUri[1]
						local args = newReqUri[2]
						--删除cckey和keyexpire
						local newArgs = ngx.re.gsub(args, "[&?]?key302=[^&]+&?|expire302=[^&]+&?", "", "i")
						if newArgs == "" then
							newUrl = table.concat({reqUriNoneArgs,"?key302=",key_new,"&expire302=",expire})
						else
							newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"&key302=",key_new,"&expire302=",expire})
						end					
					else
						newUrl = table.concat({reqUri,"?key302=",key_new,"&expire302=",expire})

					end

					return ngx.redirect(newUrl, 302) --发送302转向
				end
			end	
		end
	end
end

--js跳转模块
function Guard:JsJumpModules(ip,reqUri,address)
	if ngx.re.match(address,_Conf.JsJumpUrlProtect,"i") then
		self:debug("[JsJumpModules] address "..address.." match reg ".._Conf.JsJumpUrlProtect,ip,reqUri)
		local whiteKey = ip.."whitejs"	
		local inWhiteList = _Conf.dict:get(whiteKey)
				
		if inWhiteList then --如果在白名单
			self:debug("[JsJumpModules] in white ip list",ip,reqUri)
			return
		else
			--如果不在白名单,检测是否有cookie凭证
			local cookie_key = ngx.var["cookie_keyjs"] --获取cookie密钥
			local cookie_expire = ngx.var["cookie_expirejs"] --获取cookie密钥过期时间
			local now = ngx.time() --当前时间戳
			local challengeTimesKey = table.concat({ip,"challengejs"})
			local challengeTimesValue = _Conf.dict:get(challengeTimesKey)
			local blackKey = ip.."black"
			local cookie_key = ngx.var["cookie_keyjs"] --获取cookie密钥
			local cookie_expire = ngx.var["cookie_expirejs"] --获取cookie密钥过期时间

			if cookie_key and cookie_expire then
				local key_make = ngx.md5(table.concat({ip,_Conf.JsJumpModules.keySecret,cookie_expire}))
				local key_make = string.sub(key_make,"1","10")
				if tonumber(cookie_expire) > now and cookie_key == key_make then
					if challengeTimesValue then
						_Conf.dict:delete(challengeTimesKey) --删除验证失败计数器
					end					
					self:debug("[JsJumpModules] cookie key is valid.",ip,reqUri)
					_Conf.dict:set(whiteKey,0,_Conf.whiteTime) --添加ip到白名单
					return
				else
					--验证失败次数加1
					if challengeTimesValue then
						_Conf.dict:incr(challengeTimesKey,1)
						if challengeTimesValue +1 > _Conf.JsJumpModules.verifyMaxFail then
							self:debug("[JsJumpModules] client "..ip.." challenge cookie failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
							self:log("[JsJumpModules] client "..ip.." challenge cookie failed "..challengeTimesValue.." times,add to blacklist.")
							_Conf.dict:set(blackKey,0,_Conf.blockTime) --添加此ip到黑名单
						end	
					else
						_Conf.dict:set(challengeTimesKey,1,_Conf.JsJumpModules.amongTime)
					end

					self:debug("[JsJumpModules] cookie key is invalid.",ip,reqUri)
					local expire = now + _Conf.keyExpire
					local key_new = ngx.md5(table.concat({ip,_Conf.JsJumpModules.keySecret,expire}))
					local key_new = string.sub(key_new,"1","10")

					--定义转向的url
					local newUrl = ''
					local newReqUri = ngx.re.match(reqUri, "(.*?)\\?(.+)")
					if newReqUri then
						local reqUriNoneArgs = newReqUri[1]
						local args = newReqUri[2]
						--删除cckey和keyexpire
						local newArgs = ngx.re.gsub(args, "[&?]?keyjs=[^&]+&?|expirejs=[^&]+&?", "", "i")
						if newArgs == "" then
							newUrl = table.concat({reqUriNoneArgs,"?keyjs=",key_new,"&expirejs=",expire})
						else
							newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"&keyjs=",key_new,"&expirejs=",expire})
						end					
					else
						newUrl = table.concat({reqUri,"?keyjs=",key_new,"&expirejs=",expire})

					end

					local jsJumpCode=table.concat({"<script>window.location.href='",newUrl,"';</script>"}) --定义js跳转代码
					ngx.header.content_type = "text/html"
					--删除cookie
					ngx.header['Set-Cookie'] = {"keyjs=; path=/", "expirejs=; expires=Sat, 01-Jan-2000 00:00:00 GMT; path=/"}						
					ngx.print(jsJumpCode)
					ngx.exit(200)					
				end
			else
				--如果没有cookie凭证,检测url是否带有cckey参数
				local ccKeyValue = ngx.re.match(reqUri, "keyjs=([^&]+)","i")
				local expire = ngx.re.match(reqUri, "expirejs=([^&]+)","i")

				if ccKeyValue and expire then
					local ccKeyValue = ccKeyValue[1]
					local expire = expire[1]

					local key_make = ngx.md5(table.concat({ip,_Conf.JsJumpModules.keySecret,expire}))
					local key_make = string.sub(key_make,"1","10")

					if key_make == ccKeyValue and now < tonumber(expire) then--判断传过来的cckey参数值是否等于字典记录的值,且没有过期
						self:debug("[JsJumpModules] ip "..ip.." arg keyjs "..ccKeyValue.." is valid.add ip to white list.",ip,reqUri)
						if challengeTimesValue then
							_Conf.dict:delete(challengeTimesKey) --删除验证失败计数器
						end							
						_Conf.dict:set(whiteKey,0,_Conf.whiteTime) --添加ip到白名单
						ngx.header['Set-Cookie'] = {"keyjs="..key_make.."; path=/", "expirejs="..expire.."; path=/"} --发送cookie凭证
						return
					else --如果不相等，则再发送302转向
						--验证失败次数加1
						if challengeTimesValue then
							_Conf.dict:incr(challengeTimesKey,1)
							if challengeTimesValue + 1 > _Conf.JsJumpModules.verifyMaxFail then
								self:debug("[JsJumpModules] client "..ip.." challenge jskey failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
								self:log("[JsJumpModules] client "..ip.." challenge jskey failed "..challengeTimesValue.." times,add to blacklist.")
								_Conf.dict:set(blackKey,0,_Conf.blockTime) --添加此ip到黑名单
							end	
						else
							_Conf.dict:set(challengeTimesKey,1,_Conf.JsJumpModules.amongTime)
						end	
						
						self:debug("[JsJumpModules] ip "..ip.." arg keyjs is invalid.",ip,reqUri)
						local expire = now + _Conf.keyExpire
						local key_new = ngx.md5(table.concat({ip,_Conf.JsJumpModules.keySecret,expire}))
						local key_new = string.sub(key_new,"1","10")				
						--定义转向的url
						local newUrl = ''
						local newReqUri = ngx.re.match(reqUri, "(.*?)\\?(.+)")
						if newReqUri then
							local reqUriNoneArgs = newReqUri[1]
							local args = newReqUri[2]
							--删除cckey和keyexpire
							local newArgs = ngx.re.gsub(args, "[&?]?keyjs=[^&]+&?|expirejs=[^&]+&?", "", "i")
							if newArgs == "" then
								newUrl = table.concat({reqUriNoneArgs,"?keyjs=",key_new,"&expirejs=",expire})
							else
								newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"&keyjs=",key_new,"&expirejs=",expire})
							end					
						else
							newUrl = table.concat({reqUri,"?keyjs=",key_new,"&expirejs=",expire})

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
							self:debug("[JsJumpModules] client "..ip.." challenge jskey failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
							self:log("[JsJumpModules] client "..ip.." challenge jskey failed "..challengeTimesValue.." times,add to blacklist.")
							_Conf.dict:set(blackKey,0,_Conf.blockTime) --添加此ip到黑名单
						end	
					else
						_Conf.dict:set(challengeTimesKey,1,_Conf.JsJumpModules.amongTime)
					end
					
					--定义转向的url
					local expire = now + _Conf.keyExpire
					local key_new = ngx.md5(table.concat({ip,_Conf.JsJumpModules.keySecret,expire}))
					local key_new = string.sub(key_new,"1","10")
									
					--定义转向的url
					local newUrl = ''
					local newReqUri = ngx.re.match(reqUri, "(.*?)\\?(.+)")
					if newReqUri then
						local reqUriNoneArgs = newReqUri[1]
						local args = newReqUri[2]
						--删除cckey和keyexpire
						local newArgs = ngx.re.gsub(args, "[&?]?keyjs=[^&]+&?|expirejs=[^&]+&?", "", "i")
						if newArgs == "" then
							newUrl = table.concat({reqUriNoneArgs,"?keyjs=",key_new,"&expirejs=",expire})
						else
							newUrl = table.concat({reqUriNoneArgs,"?",newArgs,"&keyjs=",key_new,"&expirejs=",expire})
						end					
					else
						newUrl = table.concat({reqUri,"?keyjs=",key_new,"&expirejs=",expire})

					end

					local jsJumpCode=table.concat({"<script>window.location.href='",newUrl,"';</script>"}) --定义js跳转代码
					ngx.header.content_type = "text/html"
					ngx.print(jsJumpCode)
					ngx.exit(200)	
				end
			end	
		end
	end
end

--cookie验证模块
function Guard:cookieModules(ip,reqUri,address)
	if ngx.re.match(address,_Conf.cookieUrlProtect,"i") then
		self:debug("[cookieModules] address "..address.." match reg ".._Conf.cookieUrlProtect,ip,reqUri)
		local whiteKey = ip.."whitecookie"
		local inWhiteList = _Conf.dict:get(whiteKey)

		if inWhiteList then --如果在白名单
			self:debug("[cookieModules] in white ip list.",ip,reqUri)
			return
		else
			local cookie_key = ngx.var["cookie_keycookie"] --获取cookie密钥
			local cookie_expire = ngx.var["cookie_expirecookie"] --获取cookie密钥过期时间
			local now = ngx.time() --当前时间戳
			local challengeTimesKey = table.concat({ip,"challengecookie"})
			local challengeTimesValue = _Conf.dict:get(challengeTimesKey)
			local blackKey = ip.."black"

			if cookie_key and cookie_expire then --判断是否有收到cookie
				local key_make = ngx.md5(table.concat({ip,_Conf.cookieModules.keySecret,cookie_expire}))
				local key_make = string.sub(key_make,"1","10")
				if tonumber(cookie_expire) > now and cookie_key == key_make then
					if challengeTimesValue then
						_Conf.dict:delete(challengeTimesKey) --删除验证失败计数器
					end
					self:debug("[cookieModules] cookie key is valid.add to white ip list",ip,reqUri)
					_Conf.dict:set(whiteKey,0,_Conf.whiteTime) --添加ip到白名单
					return
				else
					self:debug("[cookieModules] cookie key is invalid",ip,reqUri)
					--验证失败次数加1
					if challengeTimesValue then
						_Conf.dict:incr(challengeTimesKey,1)
						if challengeTimesValue +1 > _Conf.cookieModules.verifyMaxFail then
							self:debug("[cookieModules] client "..ip.." challenge cookie failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
							self:log("[cookieModules] client "..ip.." challenge cookie failed "..challengeTimesValue.." times,add to blacklist.")
							_Conf.dict:set(blackKey,0,_Conf.blockTime) --添加此ip到黑名单
						end
					else
						_Conf.dict:set(challengeTimesKey,1,_Conf.cookieModules.amongTime)
					end

					ngx.header['Set-Cookie'] = {"keycookie=; path=/", "expirecookie=; expires=Sat, 01-Jan-2000 00:00:00 GMT; path=/"} --删除cookie
				end		
			else --找不到cookie
				self:debug("[cookieModules] cookie not found.",ip,reqUri)
				--验证失败次数加1
				if challengeTimesValue then
					_Conf.dict:incr(challengeTimesKey,1)
					if challengeTimesValue +1 > _Conf.cookieModules.verifyMaxFail then
						self:debug("[cookieModules] client "..ip.." challenge cookie failed "..challengeTimesValue.." times,add to blacklist.",ip,reqUri)
						self:log("[cookieModules] client "..ip.." challenge cookie failed "..challengeTimesValue.." times,add to blacklist.")
						_Conf.dict:set(blackKey,0,_Conf.blockTime) --添加此ip到黑名单
					end
				else
					_Conf.dict:set(challengeTimesKey,1,_Conf.cookieModules.amongTime)
				end

				local expire = now + _Conf.keyExpire
				local key_new = ngx.md5(table.concat({ip,_Conf.cookieModules.keySecret,expire}))
				local key_new = string.sub(key_new,"1","10")

				self:debug("[cookieModules] send cookie to client.",ip,reqUri)
				ngx.header['Set-Cookie'] = {"keycookie="..key_new.."; path=/", "expirecookie="..expire.."; path=/"} --发送cookie凭证				
			end
		end
	end
end

--获取验证码
function Guard:getCaptcha()
	math.randomseed(ngx.now()) --随机种子
	local random = math.random(1,10000) --生成1-10000之前的随机数
	self:debug("[getCaptcha] get random num "..random,"","")
	local captchaValue = _Conf.dict_captcha:get(random) --取得字典中的验证码
        self:debug("[getCaptcha] get captchaValue "..(captchaValue or "nil"),"","")
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
	self:debug("[verifyCaptcha] get cookie captchaNum "..captchaNum,ip,"")
	local args = ngx.req.get_post_args() --获取post参数
	local postValue = args["response"] --获取post value参数
	postValue = string.lower(postValue)
	self:debug("[verifyCaptcha] get post arg response "..postValue,ip,"")
	local captchaValue = _Conf.dict_captcha:get(captchaNum) --从字典获取post value对应的验证码值
	if captchaValue == postValue then --比较验证码是否相等
		self:debug("[verifyCaptcha] captcha is valid.delete from blacklist",ip,"")
		_Conf.dict:delete(ip.."black") --从黑名单删除
		_Conf.dict:delete(ip.."limitreqkey") --访问记录删除
		local expire = ngx.time() + _Conf.keyExpire
		local captchaKey = ngx.md5(table.concat({ip,_Conf.captchaKey,expire}))
		local captchaKey = string.sub(captchaKey,"1","10")
		self:debug("[verifyCaptcha] expire "..expire,ip,"")
		self:debug("[verifyCaptcha] captchaKey "..captchaKey,ip,"")	
		ngx.header['Set-Cookie'] = {"captchaKey="..captchaKey.."; path=/", "captchaExpire="..expire.."; path=/"}
		return ngx.redirect(preurl) --返回上次访问url
	else
		--重新发送验证码页面
		self:debug("[verifyCaptcha] captcha invalid",ip,"")
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
function Guard:captchaAction(ip,reqUri)
	-- 访问验证码超过一定次数使用iptables封锁
	if _Conf.captchaToIptablesIsOn then
		local captchaReqKey = ip.."captchareqkey" --定义captcha req key
		local reqTimes = _Conf.dict:get(captchaReqKey) --获取此ip验证码请求的次数
		--增加一次请求记录
		if reqTimes then
			_Conf.dict:incr(captchaReqKey, 1)
		else
			_Conf.dict:set(captchaReqKey, 1, _Conf.captchaToIptables.amongTime)
			reqTimes = 0
		end

		local newReqTimes  = reqTimes + 1
		self:debug("[captchaToIptables] newReqTimes "..newReqTimes,ip,reqUri)
		--判断请求数是否大于阀值,大于则iptables封锁
		if newReqTimes > _Conf.captchaToIptables.maxReqs then --判断是否请求数大于阀值
			self:debug("[captchaToIptables] ip "..ip.. " request exceed ".._Conf.captchaToIptables.maxReqs,ip,reqUri)
			ngx.thread.spawn(Guard.addToIptables,Guard,ip) -- iptables封锁
			self:log("[captchaToIptables] IP "..ip.." visit "..newReqTimes.." times,iptables block it.")
		end

	end

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
			local key_make = ngx.md5(table.concat({ip,_Conf.captchaKey,cookie_expire}))
			local key_make = string.sub(key_make,"1","10")
			self:debug("[takeAction] cookie_expire "..cookie_expire,ip,reqUri)
			self:debug("[takeAction] cookie_key "..cookie_key,ip,reqUri)
			self:debug("[takeAction] now "..now,ip,reqUri)
			self:debug("[takeAction] key_make "..key_make,ip,reqUri)
			if tonumber(cookie_expire) > now and cookie_key == key_make then
				self:debug("[takeAction] cookie key is valid.",ip,reqUri)
				return
			else
				self:debug("[takeAction] cookie key is invalid",ip,reqUri)
				self:captchaAction(ip,reqUri)
			end	
		else	
			self:debug("[takeAction] return captchaAction",ip,reqUri)
			self:captchaAction(ip,reqUri)
		end	
	elseif _Conf.forbiddenAction then
		self:debug("[takeAction] return forbiddenAction",ip,reqUri)
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
	if not _Conf.dict_captcha:get("monitor") then
		_Conf.dict_captcha:set("monitor",0,_Conf.autoEnable.interval)
		local f=io.popen(_Conf.autoEnable.ssCommand.." -tan state established '( sport = :".._Conf.autoEnable.protectPort.." or dport = :".._Conf.autoEnable.protectPort.." )' | wc -l")
		local result=f:read("*all")
		local connection=tonumber(result)
		Guard:debug("[autoSwitch] current connection for port ".._Conf.autoEnable.protectPort.." is "..connection,"","")
		if _Conf.autoEnable.enableModule == "redirectModules" then
			local redirectOn = _Conf.dict_captcha:get("redirectOn")
			if redirectOn == 1 then
				_Conf.dict_captcha:set("exceedCount",0) --超限次数清0
				--如果当前连接在最大连接之下,为正常次数加1
				if connection < _Conf.autoEnable.maxConnection then
					_Conf.dict_captcha:incr("normalCount",1)
				end

				--如果正常次数大于_Conf.autoEnable.normalTimes,关闭redirectModules
				local normalCount = _Conf.dict_captcha:get("normalCount")
				if normalCount > _Conf.autoEnable.normalTimes then
					Guard:log("[autoSwitch] turn redirectModules off.")
					_Conf.dict_captcha:set("redirectOn",0)
				end	
			else
				_Conf.dict_captcha:set("normalCount",0) --正常次数清0
				--如果当前连接在最大连接之上,为超限次数加1
				if connection > _Conf.autoEnable.maxConnection then
					_Conf.dict_captcha:incr("exceedCount",1)
				end

				--如果超限次数大于_Conf.autoEnable.exceedTimes,开启redirectModules
				local exceedCount = _Conf.dict_captcha:get("exceedCount")
				if exceedCount > _Conf.autoEnable.exceedTimes then
					Guard:log("[autoSwitch] turn redirectModules on.")
					_Conf.dict_captcha:set("redirectOn",1)
				end					
			end

		elseif 	_Conf.autoEnable.enableModule == "JsJumpModules" then
			local jsOn = _Conf.dict_captcha:get("jsOn")
			if jsOn == 1 then
				_Conf.dict_captcha:set("exceedCount",0) --超限次数清0
				--如果当前连接在最大连接之下,为正常次数加1
				if connection < _Conf.autoEnable.maxConnection then
					_Conf.dict_captcha:incr("normalCount",1)
				end

				--如果正常次数大于_Conf.autoEnable.normalTimes,关闭JsJumpModules
				local normalCount = _Conf.dict_captcha:get("normalCount")
				if normalCount > _Conf.autoEnable.normalTimes then
					Guard:log("[autoSwitch] turn JsJumpModules off.")
					_Conf.dict_captcha:set("jsOn",0)
				end	
			else
				_Conf.dict_captcha:set("normalCount",0) --正常次数清0
				--如果当前连接在最大连接之上,为超限次数加1
				if connection > _Conf.autoEnable.maxConnection then
					_Conf.dict_captcha:incr("exceedCount",1)
				end

				--如果超限次数大于_Conf.autoEnable.exceedTimes,开启JsJumpModules
				local exceedCount = _Conf.dict_captcha:get("exceedCount")
				if exceedCount > _Conf.autoEnable.exceedTimes then
					Guard:log("[autoSwitch] turn JsJumpModules on.")
					_Conf.dict_captcha:set("jsOn",1)
				end					
			end

		elseif 	_Conf.autoEnable.enableModule == "cookieModules" then
			local cookieOn = _Conf.dict_captcha:get("cookieOn")
			if cookieOn == 1 then
				_Conf.dict_captcha:set("exceedCount",0) --超限次数清0
				--如果当前连接在最大连接之下,为正常次数加1
				if connection < _Conf.autoEnable.maxConnection then
					_Conf.dict_captcha:incr("normalCount",1)
				end

				--如果正常次数大于_Conf.autoEnable.normalTimes,关闭cookieModules
				local normalCount = _Conf.dict_captcha:get("normalCount")
				if normalCount > _Conf.autoEnable.normalTimes then
					Guard:log("[autoSwitch] turn cookieModules off.")
					_Conf.dict_captcha:set("cookieOn",0)
				end	
			else
				_Conf.dict_captcha:set("normalCount",0) --正常次数清0
				--如果当前连接在最大连接之上,为超限次数加1
				if connection > _Conf.autoEnable.maxConnection then
					_Conf.dict_captcha:incr("exceedCount",1)
				end

				--如果超限次数大于_Conf.autoEnable.exceedTimes,开启cookieModules
				local exceedCount = _Conf.dict_captcha:get("exceedCount")
				if exceedCount > _Conf.autoEnable.exceedTimes then
					Guard:log("[autoSwitch] turn cookieModules on.")
					_Conf.dict_captcha:set("cookieOn",1)
				end					
			end			
		end
	end	
end

return Guard
