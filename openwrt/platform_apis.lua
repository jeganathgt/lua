-- Copyright (c) 2018 Technicolor Delivery Technologies, SAS

---------------------------------

-- _global_vlan_dm_type = { vlanid = 0, primary_vlan = 0, ifacelist = {} }

local M ={}

local utils = require("traffic_seperation.utils")

function M.delete_br(vlanid)
    print("delete_br("..vlanid..")")
    local cmd = "brctl delbr br-guest"..vlanid
    utils.execute(cmd)
    return nil
end

function M.delete_vlan(vlanid, vlan_iface_list, primary_vlan)

    print("delete_vlan("..vlanid..","..utils.dump(vlan_iface_list)..")")
    for k,v in ipairs(vlan_iface_list) do
        utils.execute("vlanctl --if-delete "..v)
        if primary_vlan ~= nil and primary_vlan == 1 then
            local ifname = utils.remove_vlanid_ifname(v)
            utils.execute("brctl delif br-lan "..v)
            utils.execute("brctl addif br-lan "..ifname);
            utils.execute("ip link set "..ifname.." up");
        else
            utils.execute("brctl delif br-guest"..vlanid.." "..v)
        end
    end
    return nil
end

function M.create_br(vlanid)
    local cmd = "brctl addbr br-guest"..vlanid
    print("Try exec: "..cmd.."\n")
    utils.execute(cmd)
    return nil
end

function create_secondary_vlan_iface(vlanid, ifname)
    if vlanid ~= nil and ifname ~= nil then
       local ifr = remove_vlanid_ifname(ifname)
       local vprim = ifname

       -- Create VLAN interface
       utils.execute("vlanctl --mcast --if-create-name "..ifr.." "..vprim.." --if "..ifr.." --set-if-mode-rg");
       utils.execute("vlanctl --if "..ifr.." --tx --tags 0 --default-miss-drop");
       utils.execute("vlanctl --if "..ifr.." --tx --tags 1 --default-miss-drop");
       utils.execute("vlanctl --if "..ifr.." --tx --tags 2 --default-miss-drop");
       utils.execute("vlanctl --if "..ifr.." --rx --tags 0 --default-miss-drop");
       utils.execute("vlanctl --if "..ifr.." --rx --tags 1 --default-miss-drop");
       utils.execute("vlanctl --if "..ifr.." --rx --tags 2 --default-miss-drop");
   
       --Accept secondary tagged frame 
       utils.execute("vlanctl --if "..ifr.." --rx --tags 1 --filter-vid "..vlanid.." 0 --filter-ethertype 33024 --pop-tag --set-rxif "..vprim.." --rule-append");
   
       --Send secondary tagged frame 
       utils.execute("vlanctl --if "..ifr.." --tx --tags 0 --filter-txif "..vprim.." --push-tag --set-vid "..vlanid.." 0 --set-ethertype 33024 --set-pbits 0 0 --rule-append");

       utils.execute("brctl delif br-lan "..vprim);
       utils.execute("brctl addif br-guest"..vlanid.." "..vprim)
       utils.execute("ip link set "..vprim.." up")
       return prim
    end
    return nil
end

function create_primary_vlan_iface(vlanid, ifname)

    if vlanid ~= nil and ifname ~= nil then
        local iface = remove_vlanid_ifname(ifname)
        local vprim = ifname
        utils.execute("vlanctl --mcast --if-create-name "..iface.." "..vprim.." --if "..iface.." --set-if-mode-rg");
        utils.execute("vlanctl --if "..iface.." --tx --tags 0 --default-miss-drop");
        utils.execute("vlanctl --if "..iface.." --tx --tags 1 --default-miss-drop");
        utils.execute("vlanctl --if "..iface.." --tx --tags 2 --default-miss-drop");
        utils.execute("vlanctl --if "..iface.." --rx --tags 0 --default-miss-drop");
        utils.execute("vlanctl --if "..iface.." --rx --tags 1 --default-miss-drop");
        utils.execute("vlanctl --if "..iface.." --rx --tags 2 --default-miss-drop");
       
        --[[
         * Receive BRCM event packets to primary interface. This is to fix the issue where after
         * creating VLAN interface, BRCM events were not received at the application. So, adding a
         * rule while creating primary VLAN interface to receive BRCM events(with ether type 0x886c)
        ]]--
        utils.execute("vlanctl --if "..iface.." --rx --tags 0 --filter-ethertype 34924 --set-rxif "..vprim.." --rule-append");
       
        --[[ if noTag is true then its for ethernet interface --]]
        iface_type = utils.get_iface_type(iface)
        if iface_type ~= nil and iface_type == "ethernet" then
          print("ifacetype:"..iface..", "..iface_type.." ")
          --[[Accept Data with 0 tags --]]
          utils.execute("vlanctl --if "..iface.." --rx --tags 0 --set-rxif "..vprim.." --rule-append");
       
          --[[ Send only the 0 tagged packets --]]
          utils.execute("vlanctl --if "..iface.." --tx --tags 0 --filter-txif "..vprim.." --rule-append");
       
          utils.execute("brctl delif br-lan "..iface);
          utils.execute("brctl addif br-lan "..vprim);
          utils.execute("ip link set "..vprim.." up");
          return prim
        end
       
        if iface_type ~= nil and iface_type == "wireless" then 
          print("ifacetype:"..iface..", "..iface_type.." ")
          --[[ Receive EAPOL packets to primary interface without TAG ]]--
          utils.execute("vlanctl --if "..iface.." --rx --tags 0 --filter-ethertype 34958 --set-rxif "..vprim.." --rule-append");
       
          --Receive EAPOL packets to primary interface with TAG and remove the TAG 
          utils.execute("vlanctl --if "..iface.." --rx --tags 1 --filter-ethertype 34958 --pop-tag --set-rxif "..vprim.." --rule-append");
       
          --Accept primary tagged frame 
          utils.execute("vlanctl --if "..iface.." --rx --tags 1 --filter-vid "..vlanid.." 0 --filter-ethertype 33024 --pop-tag --set-rxif "..vprim.." --rule-append");
       
          --Send EAPOL packets without any TAGs 
          utils.execute("vlanctl --if "..iface.." --tx --tags 0 --filter-txif "..vprim.." --filter-ethertype 34958 --rule-append");
       
          --Send primary tagged frame 
          utils.execute("vlanctl --if "..iface.." --tx --tags  0 --filter-txif "..vprim.." --push-tag --set-vid "..vlanid.." 0 --set-ethertype 33024 --set-pbits 0 0 --rule-append");
          utils.execute("brctl delif br-lan "..iface);
          utils.execute("brctl addif br-lan "..vprim);
          utils.execute("ip link set "..vprim.." up");
          return prim
       end
   end
   return nil
end


function M.add_vlan(vlanid, vlan_iface_list, primary_vlan)

    local new_iface_list = {}
    local temp           = ""
    local i              = 1

    if vlanid~= nil and vlan_iface_list~= nil and primary_vlan ~= nil then
        print("add_vlan("..vlanid..", primary_vlan:"..primary_vlan..",ifaces:"..utils.dump(vlan_iface_list)..")")
        if primary_vlan == 1 then
            for k,v in ipairs(vlan_iface_list) do
                temp = create_primary_vlan_iface(vlanid, v)
                if temp ~= nil then
                    new_iface_list[i] = temp
                end
            end
        else 
             for k,v in ipairs(vlan_iface_list) do
                temp = create_secondary_vlan_iface(vlanid, v)
                if temp ~= nil then
                    new_iface_list[i] = temp
                end
            end

        end
    end
    return new_iface_list
end

return M
