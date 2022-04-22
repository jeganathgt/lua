-- Copyright (c) 2018 Technicolor Delivery Technologies, SAS

---------------------------------

local M ={}
local json = require('traffic_seperation.dkjson')

function dump_table(o)
    if type(o) == 'table' then
        local s = '{ '
        for k,v in pairs(o) do
                if type(k) ~= 'number' then k = '"'..k..'"' end
                s = s .. '['..k..'] = ' .. dump_table(v) .. ','
        end
        return s .. '} '
    else
        return tostring(o)
    end
end

M.dump = dump_table


function get_iface_type(iface)
    if iface ~= nil then
        local iface_type = string.sub(iface, 1, 3)
        if iface_type == "eth" then
            return "ethernet","eth"
        end

        if iface_type == "wds" then
            return "wireless","wds"
        end

        iface_type = string.sub(iface, 1, 2)
        if iface_type == "wl" then
            return "wireless","wl"
        end
    end
    return nil
end

M.get_iface_type = get_iface_type

function M.execute(cmd)
    local handle = io.popen(cmd)
    local result = handle:read("*a")
    handle:close()
    return result
end

function write_file(file, buffer)
    local handle = io.open(file, "w")
    if handle ~= nil and buffer ~= nil then
        handle:write(buffer)
        handle:close()
    end
end

function read_file(file)
    local handle = io.open(file)
    if handle ~= nil then
        local result = handle:read("*a")
        handle:close()
        return result
    end
    return nil
end

function M.load_vlan_state()
    local buffer = {}
    local raw_buffer = read_file("/tmp/vlan.conf")
    if raw_buffer ~= nil then
        buffer = json.decode(raw_buffer)
    end
    return buffer
end

function M.save_vlan_state(vlan_dm_list)
    if vlan_dm_list ~= nil then
        local buffer = json.encode(vlan_dm_list)
        if buffer ~= nil then
            write_file("/tmp/vlan.conf", buffer)
        end
    end
end


function remove_vlanid_ifname(ifname)
    local iface  = ifname
    local vlanid = nil

    if ifname ~= nil then
        local delimit_from = string.find(ifname, ".", 1, 1)
        while delimit_from do
            iface = string.sub(ifname, 1, delimit_from-1)
            vlanid = string.sub(ifname, delimit_from+1, #ifname)
            vlanid = tonumber(vlanid)
            delimit_from = string.find(ifname, ".", delimit_from+1, 1)
        end
    end
    return iface, vlanid
end

M.remove_vlanid_ifname = remove_vlanid_ifname

function M.convert_iface_list(vlanid, iface_list)

    local result = {}
    local i      = 1
    if iface_list ~= nil and #iface_list > 0 then
        local iftype = nil
        local ifcategory = nil
        for k,v in ipairs(iface_list) do
            local ifname, vlid = remove_vlanid_ifname(v)
            if vlid ~= nil and vlid ~= vlanid then
                print("incorrect add iface:"..v.." with vlanid:"..vlid)
            else
    --            iftype, ifcategory = get_iface_type(ifname)
    --            if ifcategory ~= nil and ifcategory == "wl" then
    --                result[i] = ifname
    --            else
                    result[i] = ifname.."."..vlanid
    --            end
                i = i + 1
            end
        end
    end
    return result
end

return M
