local OPCODES = {
    [1] = "LOAD.pri", [2] = "LOAD.alt", [3] = "LOAD.S.pri", [4] = "LOAD.S.alt",
    [5] = "LREF.pri", [6] = "LREF.alt", [7] = "LREF.S.pri", [8] = "LREF.S.alt",
    [9] = "LOAD.I", [10] = "LODB.I", [11] = "CONST.pri", [12] = "CONST.alt",
    [13] = "ADDR.pri", [14] = "ADDR.alt", [15] = "STOR.pri", [16] = "STOR.alt",
    [17] = "STOR.S.pri", [18] = "STOR.S.alt", [19] = "SREF.pri", [20] = "SREF.alt",
    [21] = "SREF.S.pri", [22] = "SREF.S.alt", [23] = "STOR.I", [24] = "STRB.I",
    [25] = "LIDX", [26] = "LIDX.B", [27] = "IDXADDR", [28] = "IDXADDR.B",
    [29] = "ALIGN.pri", [30] = "ALIGN.alt", [31] = "LCTRL", [32] = "SCTRL",
    [33] = "MOVE.pri", [34] = "MOVE.alt", [35] = "XCHG", [36] = "PUSH.pri",
    [37] = "PUSH.alt", [38] = "PUSH.R", [39] = "PUSH.C", [40] = "PUSH",
    [41] = "PUSH.S", [42] = "POP.pri", [43] = "POP.alt", [44] = "STACK",
    [45] = "HEAP", [46] = "PROC", [47] = "RET", [48] = "RETN",
    [49] = "CALL", [50] = "CALL.pri", [51] = "JUMP", [52] = "JREL",
    [53] = "JZER", [54] = "JNZ", [55] = "JEQ", [56] = "JNEQ",
    [57] = "JLESS", [58] = "JLEQ", [59] = "JGRTR", [60] = "JGEQ",
    [61] = "JSLESS", [62] = "JSLEQ", [63] = "JSGRTR", [64] = "JSGEQ",
    [65] = "SHL", [66] = "SHR", [67] = "SSHR", [68] = "SHL.C.pri",
    [69] = "SHL.C.alt", [70] = "SHR.C.pri", [71] = "SHR.C.alt", [72] = "SMUL",
    [73] = "SDIV", [74] = "SDIV.alt", [75] = "UMUL", [76] = "UDIV",
    [77] = "UDIV.alt", [78] = "ADD", [79] = "SUB", [80] = "SUB.alt",
    [81] = "AND", [82] = "OR", [83] = "XOR", [84] = "NOT",
    [85] = "NEG", [86] = "INVERT", [87] = "ADD.C", [88] = "SMUL.C",
    [89] = "ZERO.pri", [90] = "ZERO.alt", [91] = "ZERO", [92] = "ZERO.S",
    [93] = "SIGN.pri", [94] = "SIGN.alt", [95] = "EQ", [96] = "NEQ",
    [97] = "LESS", [98] = "LEQ", [99] = "GRTR", [100] = "GEQ",
    [101] = "SLESS", [102] = "SLEQ", [103] = "SGRTR", [104] = "SGEQ",
    [105] = "EQ.C.pri", [106] = "EQ.C.alt", [107] = "INC.pri", [108] = "INC.alt",
    [109] = "INC", [110] = "INC.S", [111] = "INC.I", [112] = "DEC.pri",
    [113] = "DEC.alt", [114] = "DEC", [115] = "DEC.S", [116] = "DEC.I",
    [117] = "MOVS", [118] = "CMPS", [119] = "FILL", [120] = "HALT",
    [121] = "BOUNDS", [122] = "SYSREQ.pri", [123] = "SYSREQ.C", [124] = "FILE",
    [125] = "LINE", [126] = "SYMBOL", [127] = "SRANGE", [128] = "JUMP.pri",
    [129] = "SWITCH", [130] = "CASETBL", [131] = "SWAP.pri", [132] = "SWAP.alt",
    [133] = "PUSHADDR", [134] = "NOP", [135] = "SYSREQ.D", [136] = "SYMTAG",
    [137] = "BREAK"
}

local PARAM_OPS = {
    ["LOAD.pri"]=1, ["LOAD.alt"]=1, ["LOAD.S.pri"]=1, ["LOAD.S.alt"]=1,
    ["LREF.pri"]=1, ["LREF.alt"]=1, ["LREF.S.pri"]=1, ["LREF.S.alt"]=1,
    ["CONST.pri"]=1, ["CONST.alt"]=1, ["ADDR.pri"]=1, ["ADDR.alt"]=1,
    ["STOR.pri"]=1, ["STOR.alt"]=1, ["STOR.S.pri"]=1, ["STOR.S.alt"]=1,
    ["SREF.pri"]=1, ["SREF.alt"]=1, ["SREF.S.pri"]=1, ["SREF.S.alt"]=1,
    ["PUSH.C"]=1, ["PUSH"]=1, ["PUSH.S"]=1, ["STACK"]=1, ["HEAP"]=1,
    ["CALL"]=1, ["JUMP"]=1, ["JZER"]=1, ["JNZ"]=1, ["JEQ"]=1, ["JNEQ"]=1,
    ["JLESS"]=1, ["JLEQ"]=1, ["JGRTR"]=1, ["JGEQ"]=1, ["JSLESS"]=1,
    ["JSLEQ"]=1, ["JSGRTR"]=1, ["JSGEQ"]=1, ["SHL.C.pri"]=1, ["SHL.C.alt"]=1,
    ["SHR.C.pri"]=1, ["SHR.C.alt"]=1, ["ADD.C"]=1, ["SMUL.C"]=1, ["ZERO"]=1,
    ["ZERO.S"]=1, ["EQ.C.pri"]=1, ["EQ.C.alt"]=1, ["INC"]=1, ["INC.S"]=1,
    ["DEC"]=1, ["DEC.S"]=1, ["MOVS"]=1, ["CMPS"]=1, ["FILL"]=1, ["HALT"]=1,
    ["BOUNDS"]=1, ["SYSREQ.C"]=1, ["SYSREQ.D"]=1, ["SWITCH"]=1, ["LODB.I"]=1,
    ["STRB.I"]=1
}

local AMXDisassembler = {}
AMXDisassembler.__index = AMXDisassembler

function AMXDisassembler:new()
    return setmetatable({hdr = {}, strings = {}, publics = {}, natives = {}, out = {}}, self)
end

function AMXDisassembler:readInt32(f)
    local bytes = {f:read(4):byte(1, 4)}
    local n = bytes[1] + (bytes[2] * 256) + (bytes[3] * 65536) + (bytes[4] * 16777216)
    return n > 2147483647 and (n - 4294967296) or n
end

function AMXDisassembler:readInt16(f)
    local b1, b2 = f:read(2):byte(1, 2)
    return b1 + (b2 * 256)
end

function AMXDisassembler:readHeader(f)
    local h = self.hdr
    h.size = self:readInt32(f)
    h.magic = self:readInt16(f)
    h.file_version = f:read(1):byte()
    h.amx_version = f:read(1):byte()
    h.flags = self:readInt16(f)
    h.defsize = self:readInt16(f)
    h.cod = self:readInt32(f)
    h.dat = self:readInt32(f)
    h.hea = self:readInt32(f)
    h.stp = self:readInt32(f)
    h.cip = self:readInt32(f)
    h.publics = self:readInt32(f)
    h.natives = self:readInt32(f)
    h.libraries = self:readInt32(f)
    h.pubvars = self:readInt32(f)
    h.tags = self:readInt32(f)
    h.nametable = self:readInt32(f)
end

function AMXDisassembler:readString(f)
    local name = {}
    while true do
        local c = f:read(1)
        if not c or c == "\0" then break end
        name[#name + 1] = c
    end
    return table.concat(name)
end

function AMXDisassembler:readTable(f, offset, next_offset)
    local entries = {}
    local count = (next_offset - offset) / self.hdr.defsize
    f:seek("set", offset)    
    for i = 1, count do
        local addr = self:readInt32(f)
        local nameofs = self:readInt32(f)
        local pos = f:seek()
        f:seek("set", nameofs)
        entries[i] = {addr = addr, name = self:readString(f)}
        f:seek("set", pos)
    end
    return entries
end

local function isValidChar(byte)
    return (byte >= 32 and byte <= 126) or byte == 9 or byte == 10 or byte == 13
end

function AMXDisassembler:extractStrings(f)
    f:seek("set", self.hdr.dat)
    local data = f:read(self.hdr.hea - self.hdr.dat)
    if not data then return end    
    local strings = {}
    local i = 1   
    while i <= #data do
        local str, start = {}, i - 1
        local j, valid = i, true        
        while j + 3 <= #data and valid do
            for k = 0, 3 do
                local byte = data:byte(j + k)
                if byte == 0 then
                    valid = false
                    break
                elseif isValidChar(byte) then
                    str[#str + 1] = string.char(byte)
                else
                    str, valid = {}, false
                    break
                end
            end
            j = j + 4
        end        
        if #str >= 3 then
            strings[start] = table.concat(str)
            i = j
        else
            i = i + 4
        end
    end   
    self.strings = strings
end

function AMXDisassembler:generateHeader(filename)
    local out = self.out
    out[#out + 1] = "; AMX Capture: " .. filename
    out[#out + 1] = string.format("; Code Size: %d Bytes, Data Size: %d Bytes", 
        self.hdr.dat - self.hdr.cod, self.hdr.hea - self.hdr.dat)
    out[#out + 1] = ""
end

function AMXDisassembler:generatePublics()
    if #self.publics == 0 then return end    
    local out = self.out
    out[#out + 1] = "; Public Functions:"
    for _, p in ipairs(self.publics) do
        out[#out + 1] = string.format("; %08X: %s", p.addr, p.name)
    end
    out[#out + 1] = ""
end

function AMXDisassembler:generateNatives()
    if #self.natives == 0 then return end    
    local out = self.out
    out[#out + 1] = "; Natives:"
    for i, n in ipairs(self.natives) do
        out[#out + 1] = string.format("; [%d] %s", i - 1, n.name)
    end
    out[#out + 1] = ""
end

function AMXDisassembler:generateStrings()
    local count = 0
    for _ in pairs(self.strings) do count = count + 1 end
    if count == 0 then return end    
    local out = self.out
    out[#out + 1] = string.format("; Strings: %d", count)    
    local sorted = {}
    for offset, str in pairs(self.strings) do
        sorted[#sorted + 1] = {off = offset, str = str}
    end
    table.sort(sorted, function(a, b) return a.off < b.off end)   
    for _, s in ipairs(sorted) do
        if #s.str < 60 then
            local clean = s.str:gsub('\n', '\\n'):gsub('\r', '\\r'):gsub('\t', '\\t')
            out[#out + 1] = string.format("; [%08X] \"%s\"", s.off, clean)
        end
    end
    out[#out + 1] = ""
end

function AMXDisassembler:disassembleCode(f)
    f:seek("set", self.hdr.cod)
    local size = self.hdr.dat - self.hdr.cod
    local pos = 0
    local out = self.out   
    while pos < size do
        local op_byte = f:read(1)
        if not op_byte then break end       
        local op = op_byte:byte()
        local name = OPCODES[op]       
        if not name then
            pos = pos + 4
            f:read(3)
        else
            local line = string.format("%08X %s", pos, name)
            pos = pos + 4            
            if PARAM_OPS[name] then
                local param = self:readInt32(f)               
                if name:match("^J") or name == "CALL" then
                    line = line .. string.format(" %08X", param)
                elseif name:match("SYSREQ") then
                    line = line .. string.format(" %d", param)
                    local nat = self.natives[param + 1]
                    if nat then line = line .. " ; " .. nat.name end
                elseif name == "PUSH.C" or name == "CONST.pri" or name == "CONST.alt" then
                    local str = self.strings[param]
                    if str and #str < 50 then
                        local clean = str:gsub('\n', '\\n'):gsub('\r', '\\r'):gsub('\t', '\\t')
                        line = line .. string.format(" %d ; \"%s\"", param, clean)
                    else
                        line = line .. string.format(" %d", param)
                    end
                else
                    line = line .. string.format(" %d", param)
                end
                pos = pos + 4
            else
                f:read(3)
            end           
            out[#out + 1] = line
        end
    end
end

function AMXDisassembler:disassemble(filename)
    local f = io.open(filename, "rb")
    if not f then
        return nil, "Could not open file '" .. filename .. "'"
    end   
    self:readHeader(f)    
    if self.hdr.magic ~= 0xF1E0 then
        f:close()
        return nil, "Invalid AMX file"
    end   
    self.publics = self:readTable(f, self.hdr.publics, self.hdr.natives)
    self.natives = self:readTable(f, self.hdr.natives, self.hdr.libraries)
    self:extractStrings(f)    
    self:generateHeader(filename)
    self:generatePublics()
    self:generateNatives()
    self:generateStrings()    
    self.out[#self.out + 1] = "; Disassembled Results:"
    self.out[#self.out + 1] = ""
    self:disassembleCode(f)    
    f:close()
    return table.concat(self.out, "\n")
end

local filename = arg[1]

if not filename then
    print("Use: lua amx.lua main.amx")
    os.exit(1)
end

local disasm = AMXDisassembler:new()
local result, err = disasm:disassemble(filename)

if not result then
    print("[ERROR]: " .. err)
    os.exit(1)
end

local output_filename = filename:gsub("%.amx$", ".asm")
local out_file = io.open(output_filename, "w")

if not out_file then
    print("[ERROR]: Could not create file: " .. output_filename)
    os.exit(1)
end

out_file:write(result)
out_file:close()
print("Result saved in " .. output_filename)