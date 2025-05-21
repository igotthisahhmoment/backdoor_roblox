_G.Crypto = {}
local chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local reverseLookup = {}
for i = 1, #chars do
    reverseLookup[chars:sub(i, i)] = i - 1
end

function _G.Crypto.B64Enc(str)
    if not str or str == "" then return "" end
    local result = ""
    local padding = 0
    for i = 1, #str, 3 do
        local a, b, c = str:byte(i, i + 2)
        local n = bit32.bor(bit32.lshift(a or 0, 16), bit32.lshift(b or 0, 8), c or 0)
        local char1 = chars:sub(bit32.rshift(n, 18) % 64 + 1, bit32.rshift(n, 18) % 64 + 1)
        local char2 = chars:sub(bit32.band(bit32.rshift(n, 12), 63) + 1, bit32.band(bit32.rshift(n, 12), 63) + 1)
        local char3 = b and chars:sub(bit32.band(bit32.rshift(n, 6), 63) + 1, bit32.band(bit32.rshift(n, 6), 63) + 1) or "="
        local char4 = c and chars:sub(bit32.band(n, 63) + 1, bit32.band(n, 63) + 1) or "="
        
        result = result .. char1 .. char2 .. char3 .. char4
        padding = c and 0 or (b and 2 or 3)
    end
    return padding > 0 and result:sub(1, -padding) or result
end

function _G.Crypto.B64Dec(str)
    if not str or str == "" then return "" end
    str = str:gsub("[^%w%+%/%=]", "")
    
    local result = ""
    for i = 1, #str, 4 do
        if i + 3 > #str then break end
        
        local c1, c2, c3, c4 = str:sub(i, i), str:sub(i+1, i+1), str:sub(i+2, i+2), str:sub(i+3, i+3)
        local a = reverseLookup[c1] or 0
        local b = reverseLookup[c2] or 0
        local c = c3 == "=" and 0 or reverseLookup[c3] or 0
        local d = c4 == "=" and 0 or reverseLookup[c4] or 0
        
        local n = bit32.bor(bit32.lshift(a, 18), bit32.lshift(b, 12), bit32.lshift(c, 6), d)
        result = result .. string.char(bit32.rshift(n, 16))
        
        if c3 ~= "=" then 
            result = result .. string.char(bit32.band(bit32.rshift(n, 8), 255)) 
        end
        if c4 ~= "=" then 
            result = result .. string.char(bit32.band(n, 255)) 
        end
    end
    return result
end

function _G.Crypto.Xor(str, key)
    if not str or not key or #key == 0 then return str end
    local result = ""
    for i = 1, #str do
        local byte = str:byte(i)
        local keyByte = key:byte((i - 1) % #key + 1)
        result = result .. string.char(bit32.bxor(byte, keyByte))
    end
    return result
end

function _G.Crypto.Hash(str)
    if not str or str == "" then return "0" end
    
    local hash = 5381
    for i = 1, #str do
        hash = bit32.band(((hash * 33) + str:byte(i)), 0xFFFFFFFF)
    end
    
    local result = hash
    for i = 1, 5 do
        result = bit32.bxor(result, bit32.rshift(result, 6))
        result = bit32.band(result + bit32.lshift(result, 3), 0xFFFFFFFF)
        result = bit32.bxor(result, bit32.band(bit32.rshift(result, 11), 0x1FFFFF))
        result = bit32.band(result + bit32.lshift(result, 15), 0xFFFFFFFF)
    end
    
    return string.format("%08x", result)
end

function _G.Crypto.HexEnc(str)
    if not str or str == "" then return "" end
    local result = ""
    for i = 1, #str do
        result = result .. string.format("%02x", str:byte(i))
    end
    return result
end

function _G.Crypto.HexDec(hex)
    if not hex or hex == "" then return "" end
    hex = hex:gsub("[^0-9A-Fa-f]", "")
    if #hex % 2 == 1 then hex = "0" .. hex end
    
    local result = ""
    for i = 1, #hex, 2 do
        local byte = tonumber(hex:sub(i, i + 1), 16)
        if byte then
            result = result .. string.char(byte)
        end
    end
    return result
end
--
