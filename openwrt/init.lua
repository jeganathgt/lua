-- Copyright (c) 2018 Technicolor Delivery Technologies, SAS

---------------------------------
-- Initializes the Vendorextension daemon, vendor extension module is for communicating with the MAP Controller and its connected agents.
---------------------------------

---------------------------------
--! @file
--! @brief The entry point of traffic_seperation module
---------------------------------

local _global_dm                = {}
_global_dm.uloop          = require('uloop')
_global_dm.uci            = require('uci')
_global_dm.ubus_handler   = require('ubusPlugin')

local M = {}
local uci = _global_dm.uci.cursor()

--- Starts vendorextension daemon by initializing all scripts
function M.start()
  _global_dm.uloop.init()

  -- initialize logger and ubus
  local ret, err = _global_dm.ubus_handler.init(_global_dm)
  if not ret then
    --_global_dm.log:critical("Exiting vendor extension: Failed to initialize Ubus. Error: %s", err)
    return
  end

  _global_dm.uloop.run()
  _global_dm.log:info("Exiting vendor extension daemon")
  _global_dm.ubus:close()
  _global_dm.uloop.cancel()
  return true
end

return M
