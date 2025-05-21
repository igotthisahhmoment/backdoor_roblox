_G.Crypto = {}
local chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

function _G.Crypto.B64Enc(str)
    local result = ""
    local padding = 0
    for i = 1, #str, 3 do
        local a, b, c = str:byte(i, i + 2)
        local n = bit32.bor(bit32.lshift(a or 0, 16), bit32.lshift(b or 0, 8), c or 0)
        result = result .. chars:sub(bit32.rshift(n, 18) + 1, bit32.rshift(n, 18) + 1)
        result = result .. chars:sub(bit32.band(bit32.rshift(n, 12), 63) + 1, bit32.band(bit32.rshift(n, 12), 63) + 1)
        result = result .. (b and chars:sub(bit32.band(bit32.rshift(n, 6), 63) + 1, bit32.band(bit32.rshift(n, 6), 63) + 1) or "=")
        result = result .. (c and chars:sub(bit32.band(n, 63) + 1, bit32.band(n, 63) + 1) or "=")
        padding = c and 0 or (b and 1 or 2)
    end
    return result:sub(1, -padding - 1) .. ("="):rep(padding)
end

function _G.Crypto.B64Dec(str)
    local result = ""
    for i = 1, #str, 4 do
        local a, b, c, d = str:byte(i, i + 3)
        a = chars:find(string.char(a)) - 1
        b = chars:find(string.char(b)) - 1
        c = c and (chars:find(string.char(c)) - 1) or 0
        d = d and (chars:find(string.char(d)) - 1) or 0
        local n = bit32.bor(bit32.lshift(a, 18), bit32.lshift(b, 12), bit32.lshift(c, 6), d)
        result = result .. string.char(bit32.rshift(n, 16))
        if c ~= 61 then result = result .. string.char(bit32.band(bit32.rshift(n, 8), 255)) end
        if d ~= 61 then result = result .. string.char(bit32.band(n, 255)) end
    end
    return result
end

function _G.Crypto.Xor(str, key)
    local result = ""
    for i = 1, #str do
        local byte = str:byte(i)
        local keyByte = key:byte((i - 1) % #key + 1)
        result = result .. string.char(bit32.bxor(byte, keyByte))
    end
    return result
end

function _G.Crypto.Hash(str)
    local hash = 0
    for i = 1, #str do
        hash = bit32.bxor(hash, str:byte(i))
        hash = bit32.bor(bit32.lshift(hash, 1), bit32.rshift(hash, 31))
    end
    return string.format("%x", hash)
end

function _G.Crypto.HexEnc(str)
    local result = ""
    for i = 1, #str do
        result = result .. string.format("%02x", str:byte(i))
    end
    return result
end

function _G.Crypto.HexDec(hex)
    local result = ""
    for i = 1, #hex, 2 do
        local byte = tonumber(hex:sub(i, i + 1), 16)
        if byte then
            result = result .. string.char(byte)
        end
    end
    return result
end
