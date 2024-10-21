## Rogue Robloxians
### Description
We recently found a rogue author who went and published their flag generator. Luckily, we've checked and they've uploaded the wrong one, and so the real flag is safe! Surely we're good now, right?

_Note: Attacking Roblox is out of scope for the CTF. This challenge does not require violating Roblox's EULA. Everything needed will be under materials posted to @sunshinectf2024. Do not attempt to login/access this account._

https://www.roblox.com/games/102169837739752/Flag-Generator


## Writeup
The link takes us to a roblox "place", created by the user @sunshinectf2024. It is named Flag-Generator, so most likely the flag is inside the files of this place with some form of logic to generate it.

We can open this place in RobloxStudio. This allows us to directly view all the files. Inside it, there is a `ServerScriptService` module, which has a lua script named `generateFlag`:
```lua
--[=[
Changelog:
10/17/2024 - Removed the actual flag for deployment
10/09/2024 - Generated the first instance of generateFlag
]=]--
-- to_base64 function taken from xDeltaXen
function to_base64(data) 
	local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
	return ((data:gsub('.', function(x) 
		local r,b='',x:byte()
		for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
		return r;
	end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
		if (#x < 6) then return '' end
		local c=0
		for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
		return b:sub(c+1,c+1)
	end)..({ '', '==', '=' })[#data%3+1])
end
local flag = "REDACTED"
print("The hidden flag you should give users is: ")
print(to_base64(flag))
```

It seems that the flag was removed during some older version of this place.
From here I went on a big search, reading many forum posts about previous or archived places. That's when I came across this reddit post made 8 years ago: https://www.reddit.com/r/roblox/comments/5qmrw5/be_able_to_see_every_games_by_someone/

Thanks to u/RavenValentijn:
>Yes, if you go to someones profile and scroll down a bit you see their hats and stuff under collection.
>At the right you see a button with "Inventory" it will redirect you to their inventory page and on the left you see the categories.
>"Places" is a listed category and shows every place owned by the person, active or not.

Following these steps we came across this https://www.roblox.com/users/7443913150/inventory/#!/places
which had three places listed in them, two of them private.

The oldest one https://www.roblox.com/games/109062725590729/sunshinectf2024s-Place isn't possible to edit, since it has been deleted/removed completely.

The second one however is peculiar, https://www.roblox.com/games/127150815094969/Flag-Generator
We again open this in RobloxStudio to check the same script:
```lua
--[=[
Changelog:
10/10/2024 - Removed the real flag and replaced it with a fake one
10/09/2024 - Generated the first instance of generateFlag
]=]
-- to_base64 function taken from xDeltaXen
function to_base64(data) 
	local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
	return ((data:gsub('.', function(x) 
		local r,b='',x:byte()
		for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
		return r;
	end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
		if (#x < 6) then return '' end
		local c=0
		for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
		return b:sub(c+1,c+1)
	end)..({ '', '==', '=' })[#data%3+1])
end

local flag = "sun{th1s_1s_4_f4k3_fl4g}"

print("The hidden flag you should give users is: ")
print(to_base64(flag))
```

Unfortunately we are greeted with a fake flag `sun{th1s_1s_4_f4k3_fl4g}`. We can see in the changelog, `10/10/2024 - Removed the real flag and replaced it with a fake one`. So we have to somehow access the previous versions of this place.

While my teammates were working on this challenge, they came across a very useful tool: https://gev.neocities.org/rblxplacedl
`With my place downloader, you can download earlier versions of uncopylocked places which could let you discover previously lost versions of Roblox games.`

All this tool does is make a call to the roblox API. We get placeID from the 2nd place link, which is `127150815094969`. For version I am not sure, so I decided to test it out with anything.

https://assetdelivery.roblox.com/v1/asset?id=127150815094969&version=idk
this is the link we get. This downloads a RobloxStudio file, which I am assuming is the latest version (since idk is not a valid version), whose extension we have to set `.rbxl` to open it in RobloxStudio.

Now, to understand how version=? works, I asked ChatGPT o1-preview model, who explained that version is simply put as a number, like version=1, version=2 etc.

So I tried downloading all the versions possible:
https://assetdelivery.roblox.com/v1/asset?id=127150815094969&version=1
https://assetdelivery.roblox.com/v1/asset?id=127150815094969&version=2
https://assetdelivery.roblox.com/v1/asset?id=127150815094969&version=3
https://assetdelivery.roblox.com/v1/asset?id=127150815094969&version=4
https://assetdelivery.roblox.com/v1/asset?id=127150815094969&version=5

Everything after 5 was downloading the same thing, that means we only have 5 versions of this place.
I opened all of them in RobloxStudio, and the one with version=2 had the flag!
```lua
--[=[
Changelog:
10/09/2024 - Generated the first instance of generateFlag
]=]
-- to_base64 function taken from xDeltaXen
function to_base64(data) 
	local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
	return ((data:gsub('.', function(x) 
		local r,b='',x:byte()
		for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
		return r;
	end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
		if (#x < 6) then return '' end
		local c=0
		for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
		return b:sub(c+1,c+1)
	end)..({ '', '==', '=' })[#data%3+1])
end

local flag = "sun{v3rs10n_c0ntr0l_v1a_r0bl0x?}"

print("The hidden flag you should give users is: ")
print(to_base64(flag))
```
`sun{v3rs10n_c0ntr0l_v1a_r0bl0x?}`
