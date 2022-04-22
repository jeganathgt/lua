-- Copyright (c) 2018 Technicolor Delivery Technologies, SAS

---------------------------------

-- _global_vlan_dm_type = { vlanid = 0, primary_vlan = 0, ifacelist = {} }

local _global_vlan_dm = {}

local platform = require("traffic_seperation.platform_apis")

local utils = require("traffic_seperation.utils")
local M ={}


local function remove_iface(vlan_index, iface)
    if vlan_index ~= nil and _global_vlan_dm[vlan_index] ~= nil and iface ~= nil then
        print("input remove iface _global_vlan_dm:".._global_vlan_dm[vlan_index].vlanid..", ifname:"..iface)

        local new_iflist    = {}
        local new_ifcnt     = 1
        if vlan_index ~= nil and _global_vlan_dm[vlan_index] ~= nil and iface ~= nil then
            for k, v in ipairs(_global_vlan_dm[vlan_index].ifacelist) do
                if v ~= nil and v ~= iface then
                    new_iflist[new_ifcnt] = v
                    new_ifcnt = new_ifcnt + 1
                end
            end

            print("updated new_iflist.."..utils.dump(new_iflist))
            _global_vlan_dm[vlan_index].ifacelist = new_iflist
        end
    end
    return nil
end

local function add_iface(vlan_index, iface)
    if vlan_index ~= nil and _global_vlan_dm[vlan_index] ~= nil and iface ~= nil then
        print("input add iface _global_vlan_dm:".._global_vlan_dm[vlan_index].vlanid..", ifname:"..iface)

        local last_index = #_global_vlan_dm[vlan_index].ifacelist
        last_index = last_index + 1
        _global_vlan_dm[vlan_index].ifacelist[last_index] = iface
    end
    return nil
end

local function add_vlan(vlan_id, vlan_iflist, primary_vlan)
    if vlan_id ~= nil and vlan_iflist ~= nil then

        local vlan_type = "secondary"
        if primary_vlan ~= nil and primary_vlan == 1 then
            vlan_type = "primary"
        end

        print("input add "..vlan_type.." vlan :"..vlan_id.."to datamodel")
 
        local last_index = #_global_vlan_dm
        local vlan_data  = {
            vlanid       = 0,
            primary_vlan = 0,
            ifacelist    = {}
        }

        vlan_data.vlanid    = vlan_id

        if vlan_type == "primary" then
            vlan_data.primary_vlan = 1
        end
        vlan_data.ifacelist = vlan_iflist

        last_index = last_index + 1
        _global_vlan_dm[last_index] = vlan_data
    end
    return nil
end

local function remove_vlan(vlan_id)
    if vlan_id ~= nil then
        local new_vlan_list  = {}
        local i = 1
        for k, v in ipairs(_global_vlan_dm) do
            if v.vlanid ~= vlan_id then
                new_vlan_list[i] = _global_vlan_dm[k]
                i = i + 1
            end
        end
        _global_vlan_dm = new_vlan_list
    end
    return nil
end


local function get_iface(vlan, iface)
    if vlan ~= nil and iface ~= nil then
        print("get_iface iface:"..iface.."from vlan "..vlan.vlanid)

        for k, v in ipairs(vlan.ifacelist) do
            if v ~= nil and v == iface then
                return k
            end
        end
    end
    return nil
end

local function get_vlan(vlanid)
     if vlanid ~= nil then
        print("get_vlan vlanid:"..vlanid)
        for k,v in ipairs(_global_vlan_dm) do
            if v.vlanid == vlanid then
                return k
            end
        end
     end
     return nil
end

local function get_primary_vlan()
     for k,v in ipairs(_global_vlan_dm) do
         if v.primary_vlan == 1 then
             return k
         end
     end
     return nil
end

function M.add_vlan_method(msg)

    local response  = {
        ["Status"]  = "Failure",
    }
    local new_ifacelist  = {}

    print(utils.dump(msg))
    --get _global_vlan_dm entry for the vlanid 

    if msg["vlanid"] and msg["iflist"] then
        print("Inside add_vlan_method() "..#msg["iflist"])
    end

    if msg["vlanid"] and msg["iflist"] and #msg["iflist"] > 0 then
        local vlan_index = get_vlan(msg["vlanid"])

        if vlan_index ~= nil and _global_vlan_dm[vlan_index] ~= nil and _global_vlan_dm[vlan_index].vlanid == msg["vlanid"] then

            local i              = 1
            local found          = 1
            local iflist         = utils.convert_iface_list(msg["vlanid"], msg["iflist"])

            for k, v in ipairs(iflist) do
                found = get_iface(_global_vlan_dm[vlan_index], v)
                if found == nil then
                    new_ifacelist[i] = v
                    i = i + 1
                end
            end

            print(utils.dump(new_ifacelist))
            platform.add_vlan(msg["vlanid"], new_ifacelist, _global_vlan_dm[vlan_index].primary_vlan)

            for k, v in ipairs(new_ifacelist) do
                add_iface(vlan_index, v)
            end

        else

            new_ifacelist  = utils.convert_iface_list(msg["vlanid"], msg["iflist"])
            --Check if there is already primary vlan in dm
            if msg["primary_vlan"] ~= nil and msg["primary_vlan"] == 1 then
                local primary_vlan = get_primary_vlan()
                if primary_vlan ~= nil then
                    utils.save_vlan_state(_global_vlan_dm)
                    return response
               end
                --Add primary vlan to dm
                platform.add_vlan(msg["vlanid"], new_ifacelist, 1)
                add_vlan(msg["vlanid"], new_ifacelist, 1)
            else 
                --Add secondary vlan to dm
                platform.create_br(msg["vlanid"])
                platform.add_vlan(msg["vlanid"], new_ifacelist, 0)
                add_vlan(msg["vlanid"], new_ifacelist, 0)
            end
        end
        response["Status"] = "Success"
        print(utils.dump(_global_vlan_dm))
        utils.save_vlan_state(_global_vlan_dm)
    end
    return response
end

function M.remove_vlan_method(msg)
    print("Inside remove_vlan_method()")
    local response  = {
        ["Status"]  = "Failure",
    }

    print(utils.dump(msg))
    --get _global_vlan_dm entry for the vlanid 

    if msg["vlanid"] and msg["iflist"] then
        print("Inside remove_vlan_method() "..#msg["iflist"])
    end

    if msg["vlanid"] and msg["iflist"] and #msg["iflist"] > 0 then
        local vlan_index = get_vlan(msg["vlanid"])

        if vlan_index ~= nil and _global_vlan_dm[vlan_index] ~= nil and _global_vlan_dm[vlan_index].vlanid == msg["vlanid"] then

            local i                 = 1
            local found             = 1
            local ifacelist_delete  = {}
            local iflist            = utils.convert_iface_list(msg["vlanid"], msg["iflist"])
       
            for k, v in ipairs(iflist) do
                found = get_iface(_global_vlan_dm[vlan_index], v)
                if found ~= nil then
                    ifacelist_delete[i] = v
                    i = i + 1
                    remove_iface(vlan_index, v)
                end
            end

            print(utils.dump(ifacelist_delete))
            if #ifacelist_delete > 0 then
                platform.delete_vlan(msg["vlanid"], ifacelist_delete, _global_vlan_dm[vlan_index].primary_vlan)
                response["Status"] = "Success"
            end
        end
    end
    utils.save_vlan_state(_global_vlan_dm)
    return response
end

function M.dump_vlan_method(msg)
  local response = {
    ["vlans"] = {}
  }

  local err_response = {
    ["Status"] = "Incorrect argument"
  }

  local len = 0
  for k, v in pairs(msg) do
      len = len + 1
  end

  if msg["vlanid"] and len == 1 then
      for k,v in ipairs(_global_vlan_dm) do
          if msg["vlanid"] == v.vlanid then
              response["vlans"][1] = v
              break;
          end
      end
      print(utils.dump(_global_vlan_dm))
      print(utils.dump(response))
      return response
  else
      if len == 0 then
          for k,v in ipairs(_global_vlan_dm) do
              response["vlans"][k] = v
          end
          print(utils.dump(_global_vlan_dm))
          print(utils.dump(response))
          return response
      end
  end

  print(utils.dump(_global_vlan_dm))
  print(utils.dump(err_response))
  return err_response
end

function M.delete_vlan_method(msg)
  local response  = { 
    ["Status"]  = "Failure",
  }

  if msg["vlanid"] then
      local vlan_index = get_vlan(msg["vlanid"])
      if vlan_index ~= nil and _global_vlan_dm[vlan_index] ~= nil and _global_vlan_dm[vlan_index].vlanid == msg["vlanid"] then

          print("iflist ...."..utils.dump(_global_vlan_dm[vlan_index].iflist))
          platform.delete_vlan(msg["vlanid"], _global_vlan_dm[vlan_index].ifacelist, _global_vlan_dm[vlan_index].primary_vlan)

          if _global_vlan_dm[vlan_index].primary_vlan == 0 then
              platform.delete_br(msg["vlanid"])
          end

          remove_vlan(msg["vlanid"])
          print(utils.dump(_global_vlan_dm))
          print(utils.dump(response))
          response["Status"] = "Success"
      end
  end
  utils.save_vlan_state(_global_vlan_dm)
  return response
end

function M.load_config()
    _global_vlan_dm = utils.load_vlan_state()
    print("Loading vlan state\n")
    print(utils.dump(_global_vlan_dm))
    print("Success Loading vlan state\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    return nil
end


return M
