-- Copyright (c) 2018 Technicolor Delivery Technologies, SAS

---------------------------------
-- The implementation of the UBUS handler functions for multiap controller object.
---------------------------------

local ubus = require('ubus')
local runtime = {}

-- vlan_dm_type = { vlanid = 0, ifacelist = {} }

local vlan_dm = {}
local vlan_cnt = 1

local M ={}
local conn = {}
local ubusConn = {}
ubusConn.__index = ubusConn


function trace(event, line)
    local file = debug.getinfo(2).short_src;
    print(file.." , line:"..line)
end

debug.sethook(trace, "l")

local br_member_dm = {
     ["br-guest"]  = { },
     ["br-guest2"] = { },
     ["br-lan"]    = { },
}

function execute(cmd)
    local handle = io.popen(cmd)
    local result = handle:read("*a")
    handle:close()
    return result
end

local function wireless_get_radio(req, msg)
    local response = {}


    local temp_response = {
        ['radio_2G'] = {
                ['capabilities'] = '802.11n 3x3 40MHz USM OCUSM',
                ['admin_state']  = 1,
                ['oper_state']   = 1,
                ['max_phy_rate']   =  288500,
                ['phy_rate']       =  288500,
                ['supported_frequency_bands'] = '2.4GHz',
                ['supported_standards']= 'bgn',
                ['standard']= 'bgn',
                ['band']= '2.4GHz',
                ['supported_countries']= 'EU US AU FR BE BG HR CY CZ DK EE FI DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE GB CH NO',
                ['country']= 'AU',
                ['allowed_channels']= '1 2 3 4 5 6 7 8 9 10 11 12 13',
                ['used_channels']= '1 4 6 9 10 11 13',
                ['requested_channel']= 'auto',
                ['channel']= 1,
                ['requested_channel_width']= '20MHz',
                ['channel_width']= '20MHz',
                ['ext_channel_location']= 'upper',
                ['beacon_period']= 100,
                ['dtim_interval']= 1,
                ['rts_threshold']= 2347,
                ['protection']= 'auto',
                ['protection_mode']= 'ctstoself',
                ['protection_trigger']= 'local&overlap',
                ['short_slot']= 'auto',
                ['rateset']= '1(b) 2(b) 5.5(b) 6(b) 9 11(b) 12(b) 18 24(b) 36 48 54 ',
                ['frame_bursting']= 1,
                ['sgi']= 1,
                ['cdd']= 'auto',
                ['stbc']= 0,
                ['ldpc']= 1,
                ['advanced_qam']= 1,
                ['ampdu']= 1,
                ['amsdu']= 0,
                ['amsdu_in_ampdu']= 0,
                ['txbf']= 'off',
                ['mumimo']= 'off',
                ['dl_ofdma']= 0,
                ['ul_ofdma']= 0,
                ['interference_mode']= 'auto',
                ['interference_channel_list']= '1 2 3 4 5 6 7 8 9 10 11 12 13',
                ['ht_security_restriction']= 1,
                ['max_target_power']= '21.50',
                ['max_target_power_adjusted']= '21.50',
                ['tx_power_adjust']= '0',
                ['tx_power_overrule_reg']= 1,
                ['sta_minimum_mode']= 'none',
                ['remotely_managed']= 0,
                ['integrated_ap']= 1,
                ['max_boot_cac']= 0,
                ['ocac']= 0,
                ['max_ba_window_size']= 64,
                ['driver_version']= '7.14.170.36'
        },
        ['radio_5G']= {
                ['capabilities']= '802.11ac 4x4 80MHz USM OCUSM',
                ['admin_state']= 1,
                ['oper_state']= 1,
                ['max_phy_rate']= 2166500,
                ['phy_rate']= 2166500,
                ['supported_frequency_bands']= '5GHz',
                ['supported_standards']= 'anac',
                ['standard']= 'anac',
                ['band']= '5GHz',
                ['supported_countries']= 'EU US AU FR BE BG HR CY CZ DK EE FI DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE GB CH NO',
                ['country']= 'AU',
                ['allowed_channels']= '36 40 44 48 52 56 60 64 100 104 108 112 116 132 136 149 153 157 161',
                ['used_channels']= '',
                ['requested_channel']= '36',
                ['channel']= 36,
                ['requested_channel_width']= 'auto',
                ['channel_width']= '80MHz',
                ['ext_channel_location']= 'upper',
                ['beacon_period']= 100,
                ['dtim_interval']= 1,
                ['rts_threshold']= 2347,
                ['protection']= 'auto',
                ['protection_mode']= 'ctstoself',
                ['protection_trigger']= 'local&overlap',
                ['short_slot']= 'auto',
                ['rateset']= '6(b) 9 12(b) 18 24(b) 36 48 54 ',
                ['frame_bursting']= 1,
                ['sgi']= 1,
                ['cdd']= 'auto',
                ['stbc']= 0,
                ['ldpc']= 1,
                ['advanced_qam']= 1,
                ['ampdu']= 1,
                ['amsdu']= 1,
                ['amsdu_in_ampdu']= 1,
                ['txbf']= 'auto',
                ['mumimo']= 'auto',
                ['dl_ofdma']= 0,
                ['ul_ofdma']= 0,
                ['interference_mode']= 'auto',
                ['interference_channel_list']= '',
                ['ht_security_restriction']= 1,
                ['max_target_power']= '16.50',
                ['max_target_power_adjusted']= '16.50',
                ['tx_power_adjust']= '0',
                ['tx_power_overrule_reg']= 1,
                ['sta_minimum_mode']= 'none',
                ['remotely_managed']= 0,
                ['integrated_ap']= 1,
                ['max_boot_cac']= 0,
                ['ocac']= 0,
                ['max_ba_window_size']= 64,
                ['driver_version']= '7.14.170.36'
        }
}

    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end

    conn:reply(req, response)
    return
end

local function wireless_accesspoint_get(req, msg)
    local response = {}
    local temp_response = {
	["ap0"]= {
		["ssid"]= "wl0",
		["admin_state"]= 1,
		["oper_state"]= 1,
		["config_state"]= 1,
		["ap_isolation"]= 0,
		["public"]= 1,
		["station_history"]= 1,
		["max_assoc"]= 0,
		["trace_modules"]= "",
		["trace_level"]= "some",
		["uuid"]= "ab1243d64aad56e197c478cd499f23e6",
		["uuid_idx"]= 0,
		["beacon_vsie"]= ""
	},
	["ap1"]= {
		["ssid"]= "wl1",
		["admin_state"]= 1,
		["oper_state"]= 1,
		["config_state"]= 1,
		["ap_isolation"]= 0,
		["public"]= 1,
		["station_history"]= 1,
		["max_assoc"]= 0,
		["trace_modules"]= "",
		["trace_level"]= "some",
		["uuid"]= "ab1243d64aad56e197c478cd499f23e6",
		["uuid_idx"]= 0,
		["beacon_vsie"]= ""
	},
	["ap2"]= {
		["ssid"]= "wl0_1",
		["admin_state"]= 1,
		["oper_state"]= 0,
		["config_state"]= 1,
		["ap_isolation"]= 1,
		["public"]= 1,
		["station_history"]= 1,
		["max_assoc"]= 8,
		["trace_modules"]= "",
		["trace_level"]= "some",
		["uuid"]= "fe4b74959ec9578ca06cee80f28d8c2e",
		["uuid_idx"]= 1,
		["beacon_vsie"]= ""
	},
	["ap3"]= {
		["ssid"]= "wl1_1",
		["admin_state"]= 1,
		["oper_state"]= 1,
		["config_state"]= 1,
		["ap_isolation"]= 0,
		["public"]= 1,
		["station_history"]= 1,
		["max_assoc"]= 0,
		["trace_modules"]= "",
		["trace_level"]= "some",
		["uuid"]= "e9e91c0411955a6a97dce58fc9dc7ce1",
		["uuid_idx"]= 9,
		["beacon_vsie"]= ""
	},
	["ap4"]= {
		["ssid"]= "wl1_2",
		["admin_state"]= 1,
		["oper_state"]= 1,
		["config_state"]= 1,
		["ap_isolation"]= 0,
		["public"]= 1,
		["station_history"]= 1,
		["max_assoc"]= 0,
		["trace_modules"]= "",
		["trace_level"]= "some",
		["uuid"]= "e9e91c0411955a6a97dce58fc9dc7ce1",
		["uuid_idx"]= 9,
		["beacon_vsie"]= ""
	}
    }

    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end

    conn:reply(req, response)
    return
end

local function wireless_get(req, msg)
  local response = {
     ["status"] = "true",
  };

    conn:reply(req, response)
    return
end

local function wireless_accesspoint_acl_deny(req, msg)
  local response = {
     ["status"] = "true",
  };

    conn:reply(req, response)
    return
end

local function wireless_accesspoint_acl_delete(req, msg)
  local response = {
     ["status"] = "true",
  };

    conn:reply(req, response)
    return
end

local function wireless_accesspoint_acl_flush(req, msg)
  local response = {
     ["status"] = "true",
  };

    conn:reply(req, response)
    return
end

local function wireless_accesspoint_acl_get(req, msg)
    local response = {}
    local temp_response = 
{
	["ap0"]= {
		["mode"]= "unlock",
		["state"]= "unlock",
		["registration_time"]= 60,
		["block_probe_response"]= 1,
		["accept_list"]= "",
		["deny_list"]= "",
		["dynamic_deny_list"]= ""
	},
	["ap1"]= {
		["mode"]= "unlock",
		["state"]= "unlock",
		["registration_time"]= 60,
		["block_probe_response"]= 1,
		["accept_list"]= "",
		["deny_list"]= "",
		["dynamic_deny_list"]= ""
	},
	["ap2"]= {
		["mode"]= "unlock",
		["state"]= "unlock",
		["registration_time"]= 60,
		["block_probe_response"]= 1,
		["accept_list"]= "",
		["deny_list"]= "",
		["dynamic_deny_list"]= ""
	},
	["ap3"]= {
		["mode"]= "unlock",
		["state"]= "unlock",
		["registration_time"]= 60,
		["block_probe_response"]= 1,
		["accept_list"]= "",
		["deny_list"]= "",
		["dynamic_deny_list"]= ""
	},
	["ap4"]= {
		["mode"]= "unlock",
		["state"]= "unlock",
		["registration_time"]= 60,
		["block_probe_response"]= 1,
		["accept_list"]= "",
		["deny_list"]= "",
		["dynamic_deny_list"]= ""
	}
}

    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end

    conn:reply(req, response)
    return
end

local function wireless_accesspoint_security_get(req, msg)
    local response = {}
    local temp_response = 
{
	["ap0"]= {
		["available_modes"]= "none wep wpa2-psk wpa-wpa2-psk wpa2 wpa-wpa2 osen",
		["supported_modes"]= "none wep wpa2-psk wpa-wpa2-psk wpa2 wpa-wpa2",
		["mode"]= "wpa2-psk",
		["wep_key"]= "15A5DE94E2",
		["wpa_psk_passphrase"]= "0123456789",
		["wpa_preshared_key"]= "44F56CB364206736872171575E788531128846ECDFE1377DB969E494F6578413",
		["pmf"]= "disabled",
		["pmksa_cache"]= 1,
		["reauth_ends_acct_session"]= 1,
		["reauth_period_pmksa_lifetime_linked"]= 0,
		["eap_reauth_period"]= 86400
	},
	["ap1"]= {
		["available_modes"]= "none wpa2-psk wpa-wpa2-psk wpa2 wpa-wpa2 osen",
		["supported_modes"]= "none wpa2-psk wpa-wpa2-psk wpa2 wpa-wpa2",
		["mode"]= "wpa2-psk",
		["wep_key"]= "47DA310E4A",
		["wpa_psk_passphrase"]= "0123456789",
		["wpa_preshared_key"]= "44F56CB364206736872171575E788531128846ECDFE1377DB969E494F6578413",
		["pmf"]= "disabled",
		["pmksa_cache"]= 1,
		["reauth_ends_acct_session"]= 1,
		["reauth_period_pmksa_lifetime_linked"]= 0,
		["eap_reauth_period"]= 86400
	},
	["ap2"]= {
		["available_modes"]= "none wep wpa2-psk wpa-wpa2-psk wpa2 wpa-wpa2 osen",
		["supported_modes"]= "none wep wpa2-psk wpa-wpa2-psk wpa2 wpa-wpa2",
		["mode"]= "none",
		["wep_key"]= "02A32AD751",
		["wpa_psk_passphrase"]= "mrpEyzJdZrrTLrmRHA2e",
		["wpa_preshared_key"]= "B1AE0AE90C5970C326F589E35E0FB873A9F98074C957082734A813C90537FF1B",
		["pmf"]= "disabled",
		["pmksa_cache"]= 1,
		["reauth_ends_acct_session"]= 1,
		["reauth_period_pmksa_lifetime_linked"]= 0,
		["eap_reauth_period"]= 86400
	},
	["ap3"]= {
		["available_modes"]= "none wpa2-psk wpa-wpa2-psk wpa2 wpa-wpa2 osen",
		["supported_modes"]= "none wpa2-psk wpa-wpa2-psk wpa2 wpa-wpa2",
		["mode"]= "wpa2-psk",
		["wep_key"]= "47DA310E4A",
		["wpa_psk_passphrase"]= "0123456789",
		["wpa_preshared_key"]= "8BB0D5538C0AE86932CE6BFE29F0F439D2EB78151496BD4B669FBDEC4E7B20BB",
		["pmf"]= "disabled",
		["pmksa_cache"]= 1,
		["reauth_ends_acct_session"]= 1,
		["reauth_period_pmksa_lifetime_linked"]= 0,
		["eap_reauth_period"]= 86400
	},
	["ap4"]= {
		["available_modes"]= "none wpa2-psk wpa-wpa2-psk wpa2 wpa-wpa2 osen",
		["supported_modes"]= "none wpa2-psk wpa-wpa2-psk wpa2 wpa-wpa2",
		["mode"]= "wpa2-psk",
		["wep_key"]= "47DA310E4A",
		["wpa_psk_passphrase"]= "0123456789",
		["wpa_preshared_key"]= "8BB0D5538C0AE86932CE6BFE29F0F439D2EB78151496BD4B669FBDEC4E7B20BB",
		["pmf"]= "disabled",
		["pmksa_cache"]= 1,
		["reauth_ends_acct_session"]= 1,
		["reauth_period_pmksa_lifetime_linked"]= 0,
		["eap_reauth_period"]= 86400
	}
}

    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end

    conn:reply(req, response)
    return
end

local function wireless_accesspoint_station_get(req, msg)
    local response = {}

    local temp_response_short = {
	["ap0"]= {
		["a2:a6:6c:5a:0a:e6"]= {
			["tx_packets"]= 151,
			["tx_bytes"]= 16021,
			["tx_phy_rate"]= 702000,
			["tx_phy_rate_coded"]= "MA82E",
			["rx_packets"]= 877,
			["rx_bytes"]= 41994,
			["rx_phy_rate"]= 6000,
			["rx_phy_rate_coded"]= "L5",
			["rssi"]= -39,
			["ps_on_time"]= 84217
		},
	},
	["ap1"]= {
		["d2:a6:6c:5a:0a:e6"]= {
			["tx_packets"]= 151,
			["tx_bytes"]= 16021,
			["tx_phy_rate"]= 702000,
			["tx_phy_rate_coded"]= "MA82E",
			["rx_packets"]= 877,
			["rx_bytes"]= 41994,
			["rx_phy_rate"]= 6000,
			["rx_phy_rate_coded"]= "L5",
			["rssi"]= -39,
			["ps_on_time"]= 84217
		}
	},
	["ap2"]= {
		["d4:a6:6c:5a:0a:e6"]= {
                        ["tx_packets"]= 151,
                        ["tx_bytes"]= 16021,
                        ["tx_phy_rate"]= 702000,
                        ["tx_phy_rate_coded"]= "MA82E",
                        ["rx_packets"]= 877,
                        ["rx_bytes"]= 41994,
                        ["rx_phy_rate"]= 6000, 
                        ["rx_phy_rate_coded"]= "L5",
                        ["rssi"]= -39,
                        ["ps_on_time"]= 84217
                }

	},
	["ap3"]= {
		["22:b0:01:2b:49:1f"]= {
                        ["tx_packets"]= 151,
                        ["tx_bytes"]= 16021,
                        ["tx_phy_rate"]= 702000,
                        ["tx_phy_rate_coded"]= "MA82E",
                        ["rx_packets"]= 877,
                        ["rx_bytes"]= 41994,
                        ["rx_phy_rate"]= 6000,
                        ["rx_phy_rate_coded"]= "L5",
                        ["rssi"]= -39,
                        ["ps_on_time"]= 84217
                }
	},
	["ap4"]= {
                ["d1:a6:6c:5a:1a:f6"]= {
                        ["tx_packets"]= 151,
                        ["tx_bytes"]= 16021,
                        ["tx_phy_rate"]= 702000,
                        ["tx_phy_rate_coded"]= "MA82E",
                        ["rx_packets"]= 877,
                        ["rx_bytes"]= 41994,
                        ["rx_phy_rate"]= 6000, 
                        ["rx_phy_rate_coded"]= "L5",
                        ["rssi"]= -39,
                        ["ps_on_time"]= 84217
                }

	}
}

    local temp_response_get = 
{
	["ap0"]= {
		["a2:a6:6c:5a:0a:e6"]= {
			["state"]= "Authenticated Associated Authorized",
			["flags"]= "Powersave WMM 80MHz AMPDU LDPC",
			["capabilities"]= "802.11ac 2x2 WMM 40MHz 80MHz SGI20 SGI40 SGI80 AMPDU STBC LDPC TXBF AMSDU AMSDU_IN_AMPDU DB 11V_S 11K 11K_BRP 11K_BRA",
			["authentication"]= "WPA2PSK",
			["encryption"]= "AES",
			["last_auth_timestamp"]= "09:09:30-08/10/2020",
			["last_authentication_status"]= "Success",
			["last_assoc_timestamp"]= "09:09:30-08/10/2020",
			["last_assoc_status"]= "Success",
			["last_ssid"]= "TCH2B49EB",
			["last_authentication"]= "WPA2PSK",
			["last_encryption"]= "AES",
			["num_associations"]= 1,
			["last_wpssession_timestamp"]= "",
			["last_wps_version"]= 0,
			["last_wps_method"]= "Unknown",
			["last_wps_status"]= "Unknown",
			["last_wpahandshake_timestamp"]= "09:09:30-08/10/2020",
			["last_wpahandshake_status"]= "Success",
			["last_authorization_timestamp"]= "09:09:30-08/10/2020",
			["last_disconnect_timestamp"]= "",
			["last_disconnect_by"]= "Station",
			["last_disconnect_reason"]= "Unspecified",
			["last_statistics_timestamp"]= "09:09:50-08/10/2020",
			["last_rssi"]= -39,
			["last_rssi_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["tx_packets"]= 11,
			["tx_bytes"]= 1379,
			["tx_noack_failures"]= 0,
			["tx_data_rate"]= 0,
			["tx_data_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["tx_phy_rate"]= 780000,
			["tx_phy_rate_coded"]= "MA92E",
			["tx_phy_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["rx_packets"]= 123,
			["rx_sec_failures"]= 0,
			["rx_bytes"]= 3943,
			["rx_data_rate"]= 1,
			["rx_data_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["rx_phy_rate"]= 6000,
			["rx_phy_rate_coded"]= "L5",
			["rx_phy_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["rssi"]= -39,
			["rssi_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["assoc_time"]= 20,
			["idle_time"]= 1,
			["ps_on_time"]= 13717,
			["ps_off_on_transistions"]= 40,
			["last_measurement"]= "09:09:44-08/10/2020",
			["av_txbw_used"]= 100,
			["av_rxbw_used"]= 100,
			["av_txss_used"]= 0,
			["av_rxss_used"]= 0,
			["av_rx_phyrate_history"]= 0,
			["av_tx_phyrate_history"]= 0,
			["av_rx_rate_history"]= 0,
			["av_tx_rate_history"]= 0,
			["av_rssi"]= 0,
			["av_ps_on_time"]= 0,
			["ps_on_time_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["assoc_frame"]= "11110100000954434832423439454201088c129824b048606c2102081e2436240128012c013001340138013c014001640168016c017001740178017c018001840188018c019001950199019d01a101a501a901ad012d1aef0113ffff00000000000000000000000000000000000000000030140100000fac040100000fac040100000fac0200003b1473515354737475767778797a7b7c7d7e7f808182460573109100047f080400088000400040bf0cb2718033faff0c03faff0c03dd070050f202000100dd088cfdf00101020100dd09506f9a160200030103",
			["btm_response"]= {
				["target_bss"]= "00:00:00:00:00:00",
				["response_code"]= 0,
				["timestamp"]= ""
			},
			["beacon_report"]= {
				
			}
		},
	},
	["ap1"]= {
		["d2:a6:6c:5a:0a:e6"]= {
			["state"]= "Authenticated Associated Authorized",
			["flags"]= "Powersave WMM 80MHz AMPDU LDPC",
			["capabilities"]= "802.11ac 2x2 WMM 40MHz 80MHz SGI20 SGI40 SGI80 AMPDU STBC LDPC TXBF AMSDU AMSDU_IN_AMPDU DB 11V_S 11K 11K_BRP 11K_BRA",
			["authentication"]= "WPA2PSK",
			["encryption"]= "AES",
			["last_auth_timestamp"]= "09:09:30-08/10/2020",
			["last_authentication_status"]= "Success",
			["last_assoc_timestamp"]= "09:09:30-08/10/2020",
			["last_assoc_status"]= "Success",
			["last_ssid"]= "TCH2B49EB",
			["last_authentication"]= "WPA2PSK",
			["last_encryption"]= "AES",
			["num_associations"]= 1,
			["last_wpssession_timestamp"]= "",
			["last_wps_version"]= 0,
			["last_wps_method"]= "Unknown",
			["last_wps_status"]= "Unknown",
			["last_wpahandshake_timestamp"]= "09:09:30-08/10/2020",
			["last_wpahandshake_status"]= "Success",
			["last_authorization_timestamp"]= "09:09:30-08/10/2020",
			["last_disconnect_timestamp"]= "",
			["last_disconnect_by"]= "Station",
			["last_disconnect_reason"]= "Unspecified",
			["last_statistics_timestamp"]= "09:09:50-08/10/2020",
			["last_rssi"]= -39,
			["last_rssi_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["tx_packets"]= 11,
			["tx_bytes"]= 1379,
			["tx_noack_failures"]= 0,
			["tx_data_rate"]= 0,
			["tx_data_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["tx_phy_rate"]= 780000,
			["tx_phy_rate_coded"]= "MA92E",
			["tx_phy_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["rx_packets"]= 123,
			["rx_sec_failures"]= 0,
			["rx_bytes"]= 3943,
			["rx_data_rate"]= 1,
			["rx_data_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["rx_phy_rate"]= 6000,
			["rx_phy_rate_coded"]= "L5",
			["rx_phy_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["rssi"]= -39,
			["rssi_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["assoc_time"]= 20,
			["idle_time"]= 1,
			["ps_on_time"]= 13717,
			["ps_off_on_transistions"]= 40,
			["last_measurement"]= "09:09:44-08/10/2020",
			["av_txbw_used"]= 100,
			["av_rxbw_used"]= 100,
			["av_txss_used"]= 0,
			["av_rxss_used"]= 0,
			["av_rx_phyrate_history"]= 0,
			["av_tx_phyrate_history"]= 0,
			["av_rx_rate_history"]= 0,
			["av_tx_rate_history"]= 0,
			["av_rssi"]= 0,
			["av_ps_on_time"]= 0,
			["ps_on_time_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["assoc_frame"]= "11110100000954434832423439454201088c129824b048606c2102081e2436240128012c013001340138013c014001640168016c017001740178017c018001840188018c019001950199019d01a101a501a901ad012d1aef0113ffff00000000000000000000000000000000000000000030140100000fac040100000fac040100000fac0200003b1473515354737475767778797a7b7c7d7e7f808182460573109100047f080400088000400040bf0cb2718033faff0c03faff0c03dd070050f202000100dd088cfdf00101020100dd09506f9a160200030103",
			["btm_response"]= {
				["target_bss"]= "00:00:00:00:00:00",
				["response_code"]= 0,
				["timestamp"]= ""
			},
			["beacon_report"]= {
				
			}
		}
	},
	["ap2"]= {
		["d4:a6:6c:5a:0a:e6"]= {
			["state"]= "Authenticated Associated Authorized",
			["flags"]= "Powersave WMM 80MHz AMPDU LDPC",
			["capabilities"]= "802.11ac 2x2 WMM 40MHz 80MHz SGI20 SGI40 SGI80 AMPDU STBC LDPC TXBF AMSDU AMSDU_IN_AMPDU DB 11V_S 11K 11K_BRP 11K_BRA",
			["authentication"]= "WPA2PSK",
			["encryption"]= "AES",
			["last_auth_timestamp"]= "09:09:30-08/10/2020",
			["last_authentication_status"]= "Success",
			["last_assoc_timestamp"]= "09:09:30-08/10/2020",
			["last_assoc_status"]= "Success",
			["last_ssid"]= "TCH2B49EB",
			["last_authentication"]= "WPA2PSK",
			["last_encryption"]= "AES",
			["num_associations"]= 1,
			["last_wpssession_timestamp"]= "",
			["last_wps_version"]= 0,
			["last_wps_method"]= "Unknown",
			["last_wps_status"]= "Unknown",
			["last_wpahandshake_timestamp"]= "09:09:30-08/10/2020",
			["last_wpahandshake_status"]= "Success",
			["last_authorization_timestamp"]= "09:09:30-08/10/2020",
			["last_disconnect_timestamp"]= "",
			["last_disconnect_by"]= "Station",
			["last_disconnect_reason"]= "Unspecified",
			["last_statistics_timestamp"]= "09:09:50-08/10/2020",
			["last_rssi"]= -39,
			["last_rssi_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["tx_packets"]= 11,
			["tx_bytes"]= 1379,
			["tx_noack_failures"]= 0,
			["tx_data_rate"]= 0,
			["tx_data_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["tx_phy_rate"]= 780000,
			["tx_phy_rate_coded"]= "MA92E",
			["tx_phy_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["rx_packets"]= 123,
			["rx_sec_failures"]= 0,
			["rx_bytes"]= 3943,
			["rx_data_rate"]= 1,
			["rx_data_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["rx_phy_rate"]= 6000,
			["rx_phy_rate_coded"]= "L5",
			["rx_phy_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["rssi"]= -39,
			["rssi_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["assoc_time"]= 20,
			["idle_time"]= 1,
			["ps_on_time"]= 13717,
			["ps_off_on_transistions"]= 40,
			["last_measurement"]= "09:09:44-08/10/2020",
			["av_txbw_used"]= 100,
			["av_rxbw_used"]= 100,
			["av_txss_used"]= 0,
			["av_rxss_used"]= 0,
			["av_rx_phyrate_history"]= 0,
			["av_tx_phyrate_history"]= 0,
			["av_rx_rate_history"]= 0,
			["av_tx_rate_history"]= 0,
			["av_rssi"]= 0,
			["av_ps_on_time"]= 0,
			["ps_on_time_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["assoc_frame"]= "11110100000954434832423439454201088c129824b048606c2102081e2436240128012c013001340138013c014001640168016c017001740178017c018001840188018c019001950199019d01a101a501a901ad012d1aef0113ffff00000000000000000000000000000000000000000030140100000fac040100000fac040100000fac0200003b1473515354737475767778797a7b7c7d7e7f808182460573109100047f080400088000400040bf0cb2718033faff0c03faff0c03dd070050f202000100dd088cfdf00101020100dd09506f9a160200030103",
			["btm_response"]= {
				["target_bss"]= "00:00:00:00:00:00",
				["response_code"]= 0,
				["timestamp"]= ""
			},
			["beacon_report"]= {
				
			}
		}
	},
	["ap3"]= {
		["22:b0:01:2b:49:1f"]= {
                        ["state"]= "Authenticated Associated Authorized",
			["flags"]= "Powersave WMM 80MHz AMPDU LDPC",
			["capabilities"]= "802.11ac 2x2 WMM 40MHz 80MHz SGI20 SGI40 SGI80 AMPDU STBC LDPC TXBF AMSDU 11V_S 11K 11K_BRP 11K_BRA",
			["authentication"]= "WPA2PSK",
			["encryption"]= "AES",
			["last_auth_timestamp"]= "09:09:27-08/10/2020",
			["last_authentication_status"]= "Success",
			["last_assoc_timestamp"]= "09:09:27-08/10/2020",
			["last_assoc_status"]= "Success",
			["last_ssid"]= "TCH2B49EB2",
			["last_authentication"]= "WPA2PSK",
			["last_encryption"]= "AES",
			["num_associations"]= 2,
			["last_wpssession_timestamp"]= "",
			["last_wps_version"]= 0,
			["last_wps_method"]= "Unknown",
			["last_wps_status"]= "Unknown",
			["last_wpahandshake_timestamp"]= "09:09:27-08/10/2020",
			["last_wpahandshake_status"]= "Failure",
			["last_authorization_timestamp"]= "",
			["last_disconnect_timestamp"]= "09:09:29-08/10/2020",
			["last_disconnect_by"]= "Station",
			["last_disconnect_reason"]= "Leaving",
			["last_statistics_timestamp"]= "09:09:19-08/10/2020",
			["last_rssi"]= -38,
			["last_rssi_history"]= "",
			["tx_packets"]= 0,
			["tx_bytes"]= 0,
			["tx_noack_failures"]= 0,
			["tx_data_rate"]= 0,
			["tx_data_rate_history"]= "",
			["tx_phy_rate"]= 0,
			["tx_phy_rate_coded"]= "L0",
			["tx_phy_rate_history"]= "",
			["rx_packets"]= 0,
			["rx_sec_failures"]= 0,
			["rx_bytes"]= 0,
			["rx_data_rate"]= 0,
			["rx_data_rate_history"]= "",
			["rx_phy_rate"]= 0,
			["rx_phy_rate_coded"]= "L0",
			["rx_phy_rate_history"]= "",
			["rssi"]= 0,
			["rssi_history"]= "",
			["assoc_time"]= 0,
			["idle_time"]= 0,
			["ps_on_time"]= 0,
			["ps_off_on_transistions"]= 0,
			["last_measurement"]= "",
			["av_txbw_used"]= 0,
			["av_rxbw_used"]= 0,
			["av_txss_used"]= 0,
			["av_rxss_used"]= 0,
			["av_rx_phyrate_history"]= 0,
			["av_tx_phyrate_history"]= 0,
			["av_rx_rate_history"]= 0,
			["av_tx_rate_history"]= 0,
			["av_rssi"]= 0,
			["av_ps_on_time"]= 0,
			["ps_on_time_history"] = "",
			["assoc_frame"]= "11110100000954434832423439454201088c129824b048606c2102081e2436240128012c013001340138013c014001640168016c017001740178017c018001840188018c019001950199019d01a101a501a901ad012d1aef0113ffff00000000000000000000000000000000000000000030140100000fac040100000fac040100000fac0200003b1473515354737475767778797a7b7c7d7e7f808182460573109100047f080400088000400040bf0cb2718033faff0c03faff0c03dd070050f202000100dd088cfdf00101020100dd09506f9a160200030103",
			["btm_response"]= {
				["target_bss"]= "00:00:00:00:00:00",
				["response_code"]= 0,
				["timestamp"]= ""
			},
			["beacon_report"]= {
				
			}
		}
	},
	["ap4"]= {
		["d1:a6:6c:5a:1a:f6"]= {
			["state"]= "Authenticated Associated Authorized",
			["flags"]= "Powersave WMM 80MHz AMPDU LDPC",
			["capabilities"]= "802.11ac 2x2 WMM 40MHz 80MHz SGI20 SGI40 SGI80 AMPDU STBC LDPC TXBF AMSDU AMSDU_IN_AMPDU DB 11V_S 11K 11K_BRP 11K_BRA",
			["authentication"]= "WPA2PSK",
			["encryption"]= "AES",
			["last_auth_timestamp"]= "09:09:30-08/10/2020",
			["last_authentication_status"]= "Success",
			["last_assoc_timestamp"]= "09:09:30-08/10/2020",
			["last_assoc_status"]= "Success",
			["last_ssid"]= "TCH2B49EB",
			["last_authentication"]= "WPA2PSK",
			["last_encryption"]= "AES",
			["num_associations"]= 1,
			["last_wpssession_timestamp"]= "",
			["last_wps_version"]= 0,
			["last_wps_method"]= "Unknown",
			["last_wps_status"]= "Unknown",
			["last_wpahandshake_timestamp"]= "09:09:30-08/10/2020",
			["last_wpahandshake_status"]= "Success",
			["last_authorization_timestamp"]= "09:09:30-08/10/2020",
			["last_disconnect_timestamp"]= "",
			["last_disconnect_by"]= "Station",
			["last_disconnect_reason"]= "Unspecified",
			["last_statistics_timestamp"]= "09:09:50-08/10/2020",
			["last_rssi"]= -39,
			["last_rssi_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["tx_packets"]= 11,
			["tx_bytes"]= 1379,
			["tx_noack_failures"]= 0,
			["tx_data_rate"]= 0,
			["tx_data_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["tx_phy_rate"]= 780000,
			["tx_phy_rate_coded"]= "MA92E",
			["tx_phy_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["rx_packets"]= 123,
			["rx_sec_failures"]= 0,
			["rx_bytes"]= 3943,
			["rx_data_rate"]= 1,
			["rx_data_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["rx_phy_rate"]= 6000,
			["rx_phy_rate_coded"]= "L5",
			["rx_phy_rate_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["rssi"]= -39,
			["rssi_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["assoc_time"]= 20,
			["idle_time"]= 1,
			["ps_on_time"]= 13717,
			["ps_off_on_transistions"]= 40,
			["last_measurement"]= "09:09:44-08/10/2020",
			["av_txbw_used"]= 100,
			["av_rxbw_used"]= 100,
			["av_txss_used"]= 0,
			["av_rxss_used"]= 0,
			["av_rx_phyrate_history"]= 0,
			["av_tx_phyrate_history"]= 0,
			["av_rx_rate_history"]= 0,
			["av_tx_rate_history"]= 0,
			["av_rssi"]= 0,
			["av_ps_on_time"]= 0,
			["ps_on_time_history"]= "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 ",
			["assoc_frame"]= "11110100000954434832423439454201088c129824b048606c2102081e2436240128012c013001340138013c014001640168016c017001740178017c018001840188018c019001950199019d01a101a501a901ad012d1aef0113ffff00000000000000000000000000000000000000000030140100000fac040100000fac040100000fac0200003b1473515354737475767778797a7b7c7d7e7f808182460573109100047f080400088000400040bf0cb2718033faff0c03faff0c03dd070050f202000100dd088cfdf00101020100dd09506f9a160200030103",
			["btm_response"]= {
				["target_bss"]= "00:00:00:00:00:00",
				["response_code"]= 0,
				["timestamp"]= ""
			},
			["beacon_report"]= {
				
			}
		}
	},
}

    if msg["short"] ~= nil then
        if msg["name"] ~= nil and temp_response_short[msg["name"]] ~= nil then
            response[msg["name"]] = temp_response_short[msg["name"]]
        end

        if msg["name"] == nil then
            response = temp_response_short
        end
    end

    if msg["short"] == nil then
        if msg["name"] ~= nil and temp_response_get[msg["name"]] ~= nil then
            response[msg["name"]] = temp_response_get[msg["name"]]
        end

        if msg["name"] == nil then
            response = temp_response_get
        end
    end

    conn:reply(req, response)
    return
end

local function wireless_accesspoint_station_reset(req, msg)
  local response = {
     ["status"] = "true",
  };

    conn:reply(req, response)
    return
end

local function wireless_accesspoint_station_disassoc(req, msg)
  local response = {
     ["status"] = "true",
  };

    conn:reply(req, response)
    return
end

local function wireless_accesspoint_station_deauth(req, msg)
  local response = {
     ["status"] = "true",
  };

    conn:reply(req, response)
    return
end

local function wireless_accesspoint_station_btm(req, msg)
  local response = {
     ["status"] = "true",
  };

    conn:reply(req, response)
    return
end

local function wireless_accesspoint_station_11k(req, msg)
  local response = {
     ["status"] = "true",
  };

    conn:reply(req, response)
    return
end

local function wireless_accesspoint_wps_get(req, msg)
    local response = {}
    local temp_response = 
{
	["ap0"]= {
		["admin_state"]= 1,
		["oper_state"]= 1,
		["wsc_state"]= "configured",
		["ap_setup_locked"]= 0,
		["ap_pin"]= "21449437",
		["session_state"]= 0,
		["session_type"]= "pin",
		["last_session_state"]= "idle",
		["enrollee_mac_address"]= "00:00:00:00:00:00",
		["w7pbc"]= 1,
		["credentialformat"]= "pmk",
		["enable_non_public"]= 0,
		["pairing_protection_mode"]= "disabled",
		["pairing_protection_accept_list"]= "",
		["pairing_protection_deny_list"]= "",
		["configuration_methods"]= "label keypad virtual_push_button physical_push_button"
	},
	["ap1"]= {
		["admin_state"]= 1,
		["oper_state"]= 1,
		["wsc_state"]= "configured",
		["ap_setup_locked"]= 0,
		["ap_pin"]= "21449437",
		["session_state"]= 0,
		["session_type"]= "pin",
		["last_session_state"]= "idle",
		["enrollee_mac_address"]= "00:00:00:00:00:00",
		["w7pbc"]= 1,
		["credentialformat"]= "pmk",
		["enable_non_public"]= 0,
		["pairing_protection_mode"]= "disabled",
		["pairing_protection_accept_list"]= "",
		["pairing_protection_deny_list"]= "",
		["configuration_methods"]= "label keypad virtual_push_button physical_push_button"
	},
	["ap2"]= {
		["admin_state"]= 0,
		["oper_state"]= 0,
		["wsc_state"]= "configured",
		["ap_setup_locked"]= 0,
		["ap_pin"]= "21449437",
		["session_state"]= 0,
		["session_type"]= "pbc",
		["last_session_state"]= "idle",
		["enrollee_mac_address"]= "00:00:00:00:00:00",
		["w7pbc"]= 1,
		["credentialformat"]= "pmk",
		["enable_non_public"]= 0,
		["pairing_protection_mode"]= "disabled",
		["pairing_protection_accept_list"]= "",
		["pairing_protection_deny_list"]= "",
		["configuration_methods"]= "label keypad virtual_push_button physical_push_button"
	},
	["ap3"]= {
		["admin_state"]= 1,
		["oper_state"]= 1,
		["wsc_state"]= "configured",
		["ap_setup_locked"]= 0,
		["ap_pin"]= "21449437",
		["session_state"]= 0,
		["session_type"]= "pin",
		["last_session_state"]= "idle",
		["enrollee_mac_address"]= "00:00:00:00:00:00",
		["w7pbc"]= 1,
		["credentialformat"]= "pmk",
		["enable_non_public"]= 0,
		["pairing_protection_mode"]= "disabled",
		["pairing_protection_accept_list"]= "",
		["pairing_protection_deny_list"]= "",
		["configuration_methods"]= "label keypad virtual_push_button physical_push_button"
	},
	["ap4"]= {
		["admin_state"]= 1,
		["oper_state"]= 1,
		["wsc_state"]= "configured",
		["ap_setup_locked"]= 0,
		["ap_pin"]= "21449437",
		["session_state"]= 0,
		["session_type"]= "pin",
		["last_session_state"]= "idle",
		["enrollee_mac_address"]= "00:00:00:00:00:00",
		["w7pbc"]= 1,
		["credentialformat"]= "pmk",
		["enable_non_public"]= 0,
		["pairing_protection_mode"]= "disabled",
		["pairing_protection_accept_list"]= "",
		["pairing_protection_deny_list"]= "",
		["configuration_methods"]= "label keypad virtual_push_button physical_push_button"
	},
}


    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end

    conn:reply(req, response)
    return
end

local function wireless_radio_acs_get(req, msg)
    local response = {}
    local temp_response = 
{
	["radio_2G"]= {
		["state"]= "Selecting",
		["policy"]= "legacy&noise",
		["rescan_period"]= 3600,
		["rescan_delay"]= 180,
		["rescan_delay_policy"]= "NoStation",
		["rescan_delay_max_events"]= 10,
		["channel_monitor_period"]= 5,
		["channel_monitor_action"]= "policy",
		["channel_fail_trigger_valid"]= 2,
		["channel_fail_max_events"]= 4,
		["channel_lockout_period"]= 28800,
		["tx_traffic_threshold"]= 50,
		["rx_traffic_threshold"]= 50,
		["traffic_sense_period"]= 5,
		["interference_span"]= 2,
		["no_restrict_align"]= 0,
		["channel_noise_threshold "]= 40,
		["channel_score_threshold"]= 25,
		["quick_scan"]= 0,
		["non_dfs_fallback"]= 1,
		["ctrl_chan_adjust"]= 1,
		["trace_level"]= 0,
		["chanim_tracing"]= 0,
		["traffic_tracing"]= 0,
		["allowed_channels"]= "1 6 11",
		["max_records"]= 10,
		["record_changes_only"]= 1,
		["dfs_reentry"]= "off",
		["bgdfs_preclearing"]= 0,
		["bgdfs_avoid_on_far_sta"]= 0,
		["bgdfs_far_sta_rssi"]= 0,
		["bgdfs_tx_time_threshold"]= 0,
		["bgdfs_rx_time_threshold"]= 0,
		["bgdfs_traffic_sense_period"]= 0,
		["profiles"]= {
			["Legacy"]= {
				["threshold_bg_noise"]= 0,
				["threshold_interference"]= 100,
				["weight_bss"]= -100,
				["weight_busy"]= 0,
				["weight_interference"]= 0,
				["weight_adj_interference"]= 0,
				["weight_fcs"]= 0,
				["weight_tx_power"]= 0,
				["weight_bg_noise"]= 0,
				["weight_bss_adj"]= 0
			},
			["Interference"]= {
				["threshold_bg_noise"]= -65,
				["threshold_interference"]= 40,
				["weight_bss"]= -1,
				["weight_busy"]= 0,
				["weight_interference"]= -100,
				["weight_adj_interference"]= -1,
				["weight_fcs"]= 0,
				["weight_tx_power"]= -5,
				["weight_bg_noise"]= 0,
				["weight_bss_adj"]= 0
			},
			["Interference&Busy"]= {
				["threshold_bg_noise"]= -65,
				["threshold_interference"]= 40,
				["weight_bss"]= -1,
				["weight_busy"]= -100,
				["weight_interference"]= -100,
				["weight_adj_interference"]= -1,
				["weight_fcs"]= 0,
				["weight_tx_power"]= -5,
				["weight_bg_noise"]= -100,
				["weight_bss_adj"]= 0
			},
			["Optimized"]= {
				["threshold_bg_noise"]= -65,
				["threshold_interference"]= 40,
				["weight_bss"]= -1,
				["weight_busy"]= -100,
				["weight_interference"]= -100,
				["weight_adj_interference"]= -1,
				["weight_fcs"]= -100,
				["weight_tx_power"]= -5,
				["weight_bg_noise"]= -100,
				["weight_bss_adj"]= 0
			},
			["Custom1"]= {
				["threshold_bg_noise"]= 0,
				["threshold_interference"]= 40,
				["weight_bss"]= -10,
				["weight_busy"]= 0,
				["weight_interference"]= -100,
				["weight_adj_interference"]= -100,
				["weight_fcs"]= 0,
				["weight_tx_power"]= 0,
				["weight_bg_noise"]= 0,
				["weight_bss_adj"]= 0
			},
			["Custom2"]= {
				["threshold_bg_noise"]= -70,
				["threshold_interference"]= 45,
				["weight_bss"]= -1,
				["weight_busy"]= -50,
				["weight_interference"]= -100,
				["weight_adj_interference"]= -10,
				["weight_fcs"]= -10,
				["weight_tx_power"]= -5,
				["weight_bg_noise"]= -50,
				["weight_bss_adj"]= 0
			},
			["legacy&noise"]= {
				["threshold_bg_noise"]= 0,
				["threshold_interference"]= 40,
				["weight_bss"]= -100,
				["weight_busy"]= 0,
				["weight_interference"]= 0,
				["weight_adj_interference"]= 0,
				["weight_fcs"]= 0,
				["weight_tx_power"]= 0,
				["weight_bg_noise"]= 0,
				["weight_bss_adj"]= 0
			},
			["FCS"]= {
				["threshold_bg_noise"]= 0,
				["threshold_interference"]= 40,
				["weight_bss"]= 0,
				["weight_busy"]= 0,
				["weight_interference"]= 0,
				["weight_adj_interference"]= 0,
				["weight_fcs"]= 0,
				["weight_tx_power"]= 0,
				["weight_bg_noise"]= 0,
				["weight_bss_adj"]= -1
			}
		},
		["channel_stats"]= "Chanim Stats Dump: count: 13\r\nchanspec    tx inbss  obss   fcs nopkt  doze  txop txop_raw   goodtx    badtx   glitch  badplcp  bgnoise    txpwr bss_noise composite timestamp\r\n  0x1001     6     0     0     0     1     0   100      100        0        0       23        0      -97       61         0       -97   3621112\n  0x1002     0     0     0     2     1     0   100       99        0        0       97        4      -96       59         0       -96   3618750\n  0x1003     0     0     2     1     1     0   100      100        0        0       44        0      -96       59         0       -96   3619002\n  0x1004     0     0     0     0     1     0   100      100        0        0       44        0      -96       59         0       -96   3619254\n  0x1005     0     0     0     1     2     0    98       98        0        0     1441       20      -90       59         0       -90   3619506\n  0x1006     0     0     1     1     1     0   100      100        0        0       24        0      -96       59         0       -96   3619758\n  0x1007     0     0     0     1     1     0    99       99        0        0       88       48      -97       59         0       -97   3620057\n  0x1008     0     0     3     1     1     0   100       99        0        0       20        0      -98       59       -71       -98   3620309\n  0x1009     0     0     2     0     1     0   100      100        0        0       32        0      -98       59         0       -98   3620561\n  0x100a     0     0     0     1     1     0    99       99        0        0       76       12      -81       59         0       -81   3620813\n  0x100b     0     0     0     0     1     0    99       99        0        0      815        0      -98       59         0       -98   3621065\n  0x100c     0     0     3     0     1     0   100       99        0        0       12        0      -97       59         0       -97   3621364\n  0x100d     0     0     0     0     1     0   100      100        0        0       44        0      -97       61         0       -97   3621616\n",
		["scan_report"]= "09:08:44-08/10/2020;2;1;;13;1:0:0:0:0;2:0:0:0:0;3:2:0:0:0;4:0:0:0:0;5:0:0:0:0;6:1:0:0:-100;7:0:0:0:-100;8:3:1:0:-100;9:2:0:0:-100;10:0:0:0:-100;11:0:0:0:0;12:3:0:0:0;13:0:0:0:0;",
		["scan_history"]= "1;08:08:40-08/10/2020;periodic;0;1;0;0;"
	},
	["radio_5G"]= {
		["state"]= "Monitoring",
		["policy"]= "legacy&noise",
		["rescan_period"]= 0,
		["rescan_delay"]= 180,
		["rescan_delay_policy"]= "NoStation",
		["rescan_delay_max_events"]= 10,
		["channel_monitor_period"]= 5,
		["channel_monitor_action"]= "policy",
		["channel_fail_trigger_valid"]= 2,
		["channel_fail_max_events"]= 4,
		["channel_lockout_period"]= 28800,
		["tx_traffic_threshold"]= 50,
		["rx_traffic_threshold"]= 50,
		["traffic_sense_period"]= 5,
		["interference_span"]= 2,
		["no_restrict_align"]= 0,
		["channel_noise_threshold "]= 40,
		["channel_score_threshold"]= 25,
		["quick_scan"]= 0,
		["non_dfs_fallback"]= 1,
		["ctrl_chan_adjust"]= 1,
		["trace_level"]= 0,
		["chanim_tracing"]= 0,
		["traffic_tracing"]= 0,
		["allowed_channels"]= "36 40 44 48 52 56 60 64 100 104 108 112 116 120 124 128 132 136 140 144 149 153 157 161 165",
		["max_records"]= 10,
		["record_changes_only"]= 1,
		["dfs_reentry"]= "bgdfs",
		["bgdfs_preclearing"]= 1,
		["bgdfs_avoid_on_far_sta"]= 1,
		["bgdfs_far_sta_rssi"]= -75,
		["bgdfs_tx_time_threshold"]= 17,
		["bgdfs_rx_time_threshold"]= 0,
		["bgdfs_traffic_sense_period"]= 30,
		["profiles"]= {
			["Legacy"]= {
				["threshold_bg_noise"]= 0,
				["threshold_interference"]= 100,
				["weight_bss"]= -100,
				["weight_busy"]= 0,
				["weight_interference"]= 0,
				["weight_adj_interference"]= 0,
				["weight_fcs"]= 0,
				["weight_tx_power"]= 0,
				["weight_bg_noise"]= 0,
				["weight_bss_adj"]= 0
			},
			["Interference"]= {
				["threshold_bg_noise"]= -65,
				["threshold_interference"]= 40,
				["weight_bss"]= -1,
				["weight_busy"]= 0,
				["weight_interference"]= -100,
				["weight_adj_interference"]= -1,
				["weight_fcs"]= 0,
				["weight_tx_power"]= -5,
				["weight_bg_noise"]= 0,
				["weight_bss_adj"]= 0
			},
			["Interference&Busy"]= {
				["threshold_bg_noise"]= -65,
				["threshold_interference"]= 40,
				["weight_bss"]= -1,
				["weight_busy"]= -100,
				["weight_interference"]= -100,
				["weight_adj_interference"]= -1,
				["weight_fcs"]= 0,
				["weight_tx_power"]= -5,
				["weight_bg_noise"]= -100,
				["weight_bss_adj"]= 0
			},
			["Optimized"]= {
				["threshold_bg_noise"]= -65,
				["threshold_interference"]= 40,
				["weight_bss"]= -1,
				["weight_busy"]= -100,
				["weight_interference"]= -100,
				["weight_adj_interference"]= -1,
				["weight_fcs"]= -100,
				["weight_tx_power"]= -5,
				["weight_bg_noise"]= -100,
				["weight_bss_adj"]= 0
			},
			["Custom1"]= {
				["threshold_bg_noise"]= 0,
				["threshold_interference"]= 40,
				["weight_bss"]= -10,
				["weight_busy"]= 0,
				["weight_interference"]= -100,
				["weight_adj_interference"]= -100,
				["weight_fcs"]= 0,
				["weight_tx_power"]= 0,
				["weight_bg_noise"]= 0,
				["weight_bss_adj"]= 0
			},
			["Custom2"]= {
				["threshold_bg_noise"]= -70,
				["threshold_interference"]= 45,
				["weight_bss"]= -1,
				["weight_busy"]= -50,
				["weight_interference"]= -100,
				["weight_adj_interference"]= -10,
				["weight_fcs"]= -10,
				["weight_tx_power"]= -5,
				["weight_bg_noise"]= -50,
				["weight_bss_adj"]= 0
			},
			["legacy&noise"]= {
				["threshold_bg_noise"]= 0,
				["threshold_interference"]= 40,
				["weight_bss"]= -100,
				["weight_busy"]= 0,
				["weight_interference"]= 0,
				["weight_adj_interference"]= 0,
				["weight_fcs"]= 0,
				["weight_tx_power"]= 0,
				["weight_bg_noise"]= 0,
				["weight_bss_adj"]= 0
			},
			["FCS"]= {
				["threshold_bg_noise"]= 0,
				["threshold_interference"]= 40,
				["weight_bss"]= 0,
				["weight_busy"]= 0,
				["weight_interference"]= 0,
				["weight_adj_interference"]= 0,
				["weight_fcs"]= 0,
				["weight_tx_power"]= 0,
				["weight_bg_noise"]= 0,
				["weight_bss_adj"]= -1
			}
		},
		["channel_stats"]= "No channel stats available\r\n",
		["scan_report"]= "",
		["scan_history"]= "1;08:08:47-08/10/2020;forced;0;36/80;0;0;"
	}
}

    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end
    conn:reply(req, response)
    return
end

local function wireless_radio_acs_rescan(req, msg)
  local response = {
     ["status"] = "true",
  };

    conn:reply(req, response)
    return
end

local function wireless_radio_acs_forced_acs_channel(req, msg)
  local response = {
     ["status"] = "true",
  };

    conn:reply(req, response)
    return
end

local function wireless_radio_acs_channel_stats_get(req, msg)
    local response = {}
    local temp_response = 
{
	["radio_2G"]= {
		["measurement_interval"]= 2,
		["medium_available"]= 98,
		["glitch"]= 5,
		["txtime"]= 3,
		["rx_inside_bss"]= 0,
		["rx_outside_bss"]= 0,
		["noise"]= -92
	},
	["radio_5G"]= {
		["measurement_interval"]= 2,
		["medium_available"]= 99,
		["glitch"]= 0,
		["txtime"]= 1,
		["rx_inside_bss"]= 0,
		["rx_outside_bss"]= 0,
		["noise"]= -86
	}
}

    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end
    conn:reply(req, response)
    return
end


local function wireless_radio_bsslist_get(req, msg)
    local response = {}
    local temp_response = 
{
	["radio_2G"]= {
		["1e:f5:e1:23:91:ec"] = {
			["ssid"]= "OnePlus",
			["channel"]= 6,
			["chan_descr"]= "6",
			["rssi"]= -42,
			["sec"]= "WPA2PSK",
			["cap"]= "1e520"
		}
	},
	["radio_5G"]= {
		["1e:f5:e1:23:91:dc"] = {
			["ssid"]= "OnePlus",
			["channel"]= 44,
			["chan_descr"]= "44",
			["rssi"]= -42,
			["sec"]= "WPA2PSK",
			["cap"]= "1e520"
		}
	}
}

    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end
    conn:reply(req, response)
    return
end

local function wireless_radio_dfs_get(req, msg)
    local response = {}
    local temp_response = 
{
	["radio_2G"]= {
		["available_channel"]= "",
		["usable_channel"]= "",
		["unusable_channel"]= "",
		["closed_channel"]= ""
	},
	["radio_5G"]= {
		["available_channel"]= "36 40 44 48 100 104 108 112",
		["usable_channel"]= "52 56 60 64 116 132 136 140",
		["unusable_channel"]= "120 124 128 118 126 118 126 122 122 122 122",
		["closed_channel"]= ""
	}
}

    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end
    conn:reply(req, response)
    return
end

local function wireless_radio_dfs_get(req, msg)
    local response = {}
    local temp_response = 
{
	["radio_2G"]= {
		["available_channel"]= "",
		["usable_channel"]= "",
		["unusable_channel"]= "",
		["closed_channel"]= ""
	},
	["radio_5G"]= {
		["available_channel"]= "36 40 44 48 100 104 108 112",
		["usable_channel"]= "52 56 60 64 116 132 136 140",
		["unusable_channel"]= "120 124 128 118 126 118 126 122 122 122 122",
		["closed_channel"]= ""
	}
}

    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end
    conn:reply(req, response)
    return
end

local function wireless_radio_monitor_get(req, msg)
    local response = {}
    local temp_response = 
{
	["radio_2G"]= {
		["last_measurement"]= "10:13:02-08/10/2020",
		["measurement_interval"]= 30,
		["medium_available"]= 97,
		["glitch"]= 12,
		["txtime"]= 3,
		["rxtime_inside_bss"]= 0,
		["rxtime_outside_bss"]= 0,
		["probe_monitor_vsie_oui"]= "",
		["db_validity"]= 86400,
		["debug_flags"]= 0,
		["probe_request"]= {
			["9a:b9:6f:53:26:d4"]= {
				["age"]= 9,
				["rssi"]= -93
			},
			["ee:b4:14:40:4b:e4"]= {
				["age"]= 30,
				["rssi"]= -93
			},
			["06:52:a8:ce:2d:e1"]= {
				["age"]= 35,
				["rssi"]= -93
			},
			["c2:c9:25:58:13:83"] ={
				["age"]= 54,
				["rssi"]= -91
			},
			["ce:6b:e9:3b:8f:82"] ={
				["age"]= 67,
				["rssi"]= -92
			},
			["26:b7:92:81:24:29"] ={
				["age"]= 76,
				["rssi"]= -91
			},
			["da:a1:19:46:2d:75"] ={
				["age"]= 158,
				["rssi"]= -62
			},
			["fe:28:84:68:d4:58"] ={
				["age"]= 269,
				["rssi"]= -93
			},
			["5c:99:60:f1:b0:92"] ={
				["age"]= 268,
				["rssi"]= -52
			},
			["3e:00:c1:cd:77:10"] ={
				["age"]= 311,
				["rssi"]= -93
			},
			["f2:bc:83:9b:b0:d6"] ={
				["age"]= 324,
				["rssi"]= -92
			},
			["ae:e7:7b:2d:1d:02"] ={
				["age"]= 398,
				["rssi"]= -92
			},
			["3a:4d:79:4d:ff:24"] ={
				["age"]= 555,
				["rssi"]= -49
			},
			["1e:f5:e1:23:91:ec"] ={
				["age"]= 551,
				["rssi"]= -69
			},
			["d2:a6:6c:5a:0a:e6"] ={
				["age"]= 557,
				["rssi"]= -47
			},
			["04:ea:56:37:22:b5"] = {
				["age"]= 4,
				["rssi"]= -67
			}
		}
	},
	["radio_5G"]= {
		["last_measurement"]= "10:13:07-08/10/2020",
		["measurement_interval"]= 30,
		["medium_available"]= 99,
		["glitch"]= 0,
		["txtime"]= 1,
		["rxtime_inside_bss"]= 0,
		["rxtime_outside_bss"]= 0,
		["probe_monitor_vsie_oui"]= "",
		["db_validity"]= 86400,
		["debug_flags"]= 0,
		["probe_request"]= {
			["04:ea:56:37:22:b5"]= {
				["age"]= 4,
				["rssi"]= -37
			}
		}
	}
}

    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end
    conn:reply(req, response)
    return
end

local function wireless_radio_monitor_station_get(req, msg)
    local response = {}
    local temp_response = 
{
	["radio_2G"]= {
		["admin_state"]= 1,
		["oper_state"]= 1,
		["requests"]= {
			
		},
		["measurements"]= {
			
		}
	},
	["radio_5G"]= {
		["admin_state"]= 1,
		["oper_state"]= 1,
		["requests"]= {
			
		},
		["measurements"]= {
			
		}
	}
}

    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end
    conn:reply(req, response)
    return
end

local function wireless_radio_monitor_station_add(req, msg)
  local response = {
     ["status"] = "true",
  };


    conn:reply(req, response)
    return
end

local function wireless_radio_monitor_station_flush(req, msg)
  local response = {
     ["status"] = "true",
  };

  conn:reply(req, response)
end

local function wireless_radio_monitor_station_delete(req, msg)
  local response = {
     ["status"] = "true",
  };
  conn:reply(req, response)
end

local function wireless_radio_stats_get(req, msg)
    local response = {}
    local temp_response = 
{
	["radio_2G"]= {
		["tx_packets"]= 3297,
		["tx_unicast_packets"]= 0,
		["tx_broadcast_packets"]= 1547,
		["tx_multicast_packets"]= 1750,
		["tx_errors"]= 0,
		["tx_discards"]= 0,
		["tx_bytes"]= 355197,
		["rx_packets"]= 0,
		["rx_unicast_packets"]= 0,
		["rx_broadcast_packets"]= 0,
		["rx_multicast_packets"]= 0,
		["rx_errors"]= 0,
		["rx_discards"]= 0,
		["rx_bytes"]= 0,
		["rx_bad_fcs"]= 3250,
		["rx_bad_plcp"]= 7665
	},
	["radio_5G"]= {
		["tx_packets"]= 4043,
		["tx_unicast_packets"]= 764,
		["tx_broadcast_packets"]= 1547,
		["tx_multicast_packets"]= 1732,
		["tx_errors"]= 0,
		["tx_discards"]= 0,
		["tx_bytes"]= 433910,
		["rx_packets"]= 1484,
		["rx_unicast_packets"]= 942,
		["rx_broadcast_packets"]= 514,
		["rx_multicast_packets"]= 28,
		["rx_errors"]= 0,
		["rx_discards"]= 0,
		["rx_bytes"]= 109386,
		["rx_bad_fcs"]= 391,
		["rx_bad_plcp"]= 955
	}
}


    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end
    conn:reply(req, response)
    return
end

local function wireless_ssid_get(req, msg)
    local response = {}
    local temp_response = 
{
	["wl0"]= {
		["radio"]= "radio_2G",
		["bssid"]= "20:b0:01:2b:49:eb",
		["mac_address"]= "20:b0:01:2b:49:eb",
		["ssid"]= "TCH2B49EB",
		["admin_state"]= 1,
		["oper_state"]= 1,
		["reliable_multicast"]= 0,
		["qos_prio_override"]= 0,
		["uapsd"]= 0,
		["vlan_id"]= 0,
		["fronthaul"]= 0,
		["backhaul"]= 0
	},
	["wl0_1"]= {
		["radio"]= "radio_2G",
		["bssid"]= "22:b0:01:2b:49:ec",
		["mac_address"]= "22:b0:01:2b:49:ec",
		["ssid"]= "Hotspot",
		["admin_state"]= 0,
		["oper_state"]= 0,
		["reliable_multicast"]= 0,
		["qos_prio_override"]= 0,
		["uapsd"]= 0,
		["vlan_id"]= 0,
		["fronthaul"]= 0,
		["backhaul"]= 0
	},
	["wl1"]= {
		["radio"]= "radio_5G",
		["bssid"]= "22:b0:01:2b:49:f3",
		["mac_address"]= "22:b0:01:2b:49:f3",
		["ssid"]= "TCH2B49EB",
		["admin_state"]= 1,
		["oper_state"]= 1,
		["reliable_multicast"]= 0,
		["qos_prio_override"]= 0,
		["uapsd"]= 0,
		["vlan_id"]= 0,
		["fronthaul"]= 1,
		["backhaul"]= 0
	},
	["wl1_1"]= {
		["radio"]= "radio_5G",
		["bssid"]= "22:b0:01:2b:49:f4",
		["mac_address"]= "22:b0:01:2b:49:f4",
		["ssid"]= "BH-2B49EB",
		["admin_state"]= 1,
		["oper_state"]= 1,
		["reliable_multicast"]= 0,
		["qos_prio_override"]= 0,
		["uapsd"]= 0,
		["vlan_id"]= 0,
		["fronthaul"]= 0,
		["backhaul"]= 1
	},
	["wl1_2"]= {
		["radio"]= "radio_5G",
		["bssid"]= "22:b0:01:2b:49:f5",
		["mac_address"]= "22:b0:01:2b:49:f5",
		["ssid"]= "Guest2B49EB",
		["admin_state"]= 1,
		["oper_state"]= 1,
		["reliable_multicast"]= 0,
		["qos_prio_override"]= 0,
		["uapsd"]= 0,
		["vlan_id"]= 0,
		["fronthaul"]= 0,
		["backhaul"]= 1
	}
}

    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end
    conn:reply(req, response)
    return
end


local function wireless_ssid_stats_get(req, msg)
    local response = {}
    local temp_response = 
{
	["wl0"]= {
		["tx_packets"]= 3587,
		["tx_unicast_packets"]= 0,
		["tx_broadcast_packets"]= 1783,
		["tx_multicast_packets"]= 1804,
		["tx_errors"]= 0,
		["tx_discards"]= 0,
		["tx_bytes"]= 384709,
		["rx_packets"]= 0,
		["rx_unicast_packets"]= 0,
		["rx_broadcast_packets"]= 0,
		["rx_multicast_packets"]= 0,
		["rx_errors"]= 0,
		["rx_discards"]= 0,
		["rx_bytes"]= 0
	},
	["wl0_1"]= {
		["tx_packets"]= 0,
		["tx_unicast_packets"]= 0,
		["tx_broadcast_packets"]= 0,
		["tx_multicast_packets"]= 0,
		["tx_errors"]= 0,
		["tx_discards"]= 0,
		["tx_bytes"]= 0,
		["rx_packets"]= 0,
		["rx_unicast_packets"]= 0,
		["rx_broadcast_packets"]= 0,
		["rx_multicast_packets"]= 0,
		["rx_errors"]= 0,
		["rx_discards"]= 0,
		["rx_bytes"]= 0
	},
	["wl1"]= {
		["tx_packets"]= 4333,
		["tx_unicast_packets"]= 764,
		["tx_broadcast_packets"]= 1783,
		["tx_multicast_packets"]= 1786,
		["tx_errors"]= 0,
		["tx_discards"]= 0,
		["tx_bytes"]= 463422,
		["rx_packets"]= 1484,
		["rx_unicast_packets"]= 942,
		["rx_broadcast_packets"]= 514,
		["rx_multicast_packets"]= 28,
		["rx_errors"]= 0,
		["rx_discards"]= 0,
		["rx_bytes"]= 109386
	},
	["wl1_1"]= {
		["tx_packets"]= 0,
		["tx_unicast_packets"]= 0,
		["tx_broadcast_packets"]= 0,
		["tx_multicast_packets"]= 0,
		["tx_errors"]= 0,
		["tx_discards"]= 0,
		["tx_bytes"]= 0,
		["rx_packets"]= 0,
		["rx_unicast_packets"]= 0,
		["rx_broadcast_packets"]= 0,
		["rx_multicast_packets"]= 0,
		["rx_errors"]= 0,
		["rx_discards"]= 0,
		["rx_bytes"]= 0
	},
        ["wl1_2"]= {
		["tx_packets"]= 0,
		["tx_unicast_packets"]= 0,
		["tx_broadcast_packets"]= 0,
		["tx_multicast_packets"]= 0,
		["tx_errors"]= 0,
		["tx_discards"]= 0,
		["tx_bytes"]= 0,
		["rx_packets"]= 0,
		["rx_unicast_packets"]= 0,
		["rx_broadcast_packets"]= 0,
		["rx_multicast_packets"]= 0,
		["rx_errors"]= 0,
		["rx_discards"]= 0,
		["rx_bytes"]= 0
	}
}

    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end
    conn:reply(req, response)
    return
end


local function wireless_ubus_stats_get(req, msg)
    local response = {}
    local temp_response = 
{
	["cmds"]= {
		["wireless__get"]= 1,
		["wireless__acl_button"]= 0,
		["wireless__wps_button"]= 0,
		["wireless__qos_map_set"]= 0,
		["wireless__reload"]= 1,
		["wireless__save_station_history"]= 0,
		["wireless__reset_station_history"]= 0,
		["wireless_bandsteer__get"]= 1,
		["wireless_accesspoint_group__get"]= 1,
		["wireless_radio__get"]= 1,
		["wireless_radio_acs__get"]= 1,
		["wireless_radio_acs__rescan"]= 3,
		["wireless_radio_acs__forced_acs_channel"]= 0,
		["wireless_radio_acs_channel_stats__get"]= 0,
		["wireless_radio_acs_qtn__get"]= 1,
		["wireless_radio_bsslist__get"]= 5,
		["wireless_radio_eco__get"]= 1,
		["wireless_radio_eco__set"]= 0,
		["wireless_radio_monitor__get"]= 1,
		["wireless_radio_monitor__set"]= 0,
		["wireless_radio_monitor__reset"]= 0,
		["wireless_radio_monitor_station__get"]= 2,
		["wireless_radio_monitor_station__add"]= 0,
		["wireless_radio_monitor_station__flush"]= 0,
		["wireless_radio_monitor_station__delete"]= 0,
		["wireless_radio_stats__get"]= 1,
		["wireless_radio_dfs__get"]= 1,
		["wireless_radio_txtest__get"]= 1,
		["wireless_radio_txtest__set"]= 0,
		["wireless_radio_remote__get"]= 0,
		["wireless_radio_remote_upgrade__get"]= 0,
		["wireless_radio_remote_upgrade__force_check"]= 0,
		["wireless_radio_remote_upgrade__force_upgrade"]= 0,
		["wireless_ssid__get"]= 37,
		["wireless_ssid_stats__get"]= 1,
		["wireless_accesspoint__get"]= 31,
		["wireless_accesspoint_acl__get"]= 1,
		["wireless_accesspoint_acl__deny"]= 0,
		["wireless_accesspoint_acl__delete"]= 0,
		["wireless_accesspoint_acl__flush"]= 0,
		["wireless_accesspoint_radius__get"]= 0,
		["wireless_accesspoint_security__get"]= 15,
		["wireless_accesspoint_station__get"]= 13,
		["wireless_accesspoint_station__reset"]= 0,
		["wireless_accesspoint_station__disassoc"]= 0,
		["wireless_accesspoint_station__deauth"]= 0,
		["wireless_accesspoint_station__bss_transition_request"]= 0,
		["wireless_accesspoint_station__beacon_request"]= 0,
		["wireless_accesspoint_wps__get"]= 1,
		["wireless_accesspoint_wps__enrollee_pin"]= 0,
		["wireless_accesspoint_wps__enrollee_pbc"]= 0,
		["wireless_accesspoint_hotspot__get"]= 0,
		["wireless_wds__get"]= 0,
		["wireless_backbone__get"]= 0,
		["total"]= 121
	},
	["events"]= {
		["wireless_radio"]= 2,
		["wireless_radio_channel"]= 605,
		["wireless_radio_monitor_station_report"]= 0,
		["wireless_ssid"]= 57,
		["wireless_accesspoint_station"]= 14,
		["wireless_accesspoint_station_beacon_report"]= 0,
		["wireless_accesspoint_station_btm_report"]= 0,
		["wireless_wds"]= 0,
		["wireless_backbone"]= 0,
		["wlan_led"]= 22,
		["wps_led"]= 0,
		["total"]= 700
	}
}

    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end
    conn:reply(req, response)
    return
end

local function wireless_uci_stats_get(req, msg)
  local response = {
     ["status"] = "true",
  }
  conn:reply(req, response)
end


local function wireless_wds_get(req, msg)
  local response = {
     ["status"] = "true",
  }
  conn:reply(req, response)
end

local function network_link_status(req, msg)
    local response = 
{
	["link"]= {
		{
			["interface"]= "ifb0",
			["action"]= "down"
		},
		{
			["interface"]= "ifb1",
			["action"]= "down"
		},
		{
			["interface"]= "sit0",
			["action"]= "down"
		},
		{
			["interface"]= "ip6tnl0",
			["action"]= "down"
		},
		{
			["interface"]= "tunl0",
			["action"]= "down"
		},
		{
			["interface"]= "gre0",
			["action"]= "down"
		},
		{
			["interface"]= "gretap0",
			["action"]= "down"
		},
		{
			["interface"]= "ip6gre0",
			["action"]= "down"
		},
		{
			["interface"]= "bcmsw",
			["action"]= "down"
		},
		{
			["interface"]= "enp0s3",
			["action"]= "up"
		},
		{
			["interface"]= "eth0",
			["action"]= "down"
		},
		{
			["interface"]= "eth1",
			["action"]= "down"
		},
		{
			["interface"]= "eth2",
			["action"]= "down"
		},
		{
			["interface"]= "eth3",
			["action"]= "down"
		},
		{
			["interface"]= "bcmswlpbk0",
			["action"]= "down"
		},
		{
			["interface"]= "dsl0",
			["action"]= "down"
		},
		{
			["interface"]= "wl0",
			["action"]= "up"
		},
		{
			["interface"]= "wl1",
			["action"]= "up"
		},
		{
			["interface"]= "wl0_1",
			["action"]= "down"
		},
		{
			["interface"]= "br-lan",
			["action"]= "up"
		},
		{
			["interface"]= "wl1_1",
			["action"]= "up"
		},
		{
			["interface"]= "wl1_2",
			["action"]= "up"
		},
		{
			["interface"]= "br-hotspot",
			["action"]= "down"
		}
	}
}

    conn:reply(req, response)
    return
end



local function add_brifaces()
    local node1 = {
        members = {}
    }

    local members = {}
    for i= 1,4 do
        local j = i - 1
        br_member_dm["br-guest"][i]  = "eth"..j..".4093"
    end

    for i= 1,4 do
        local j = i - 1
        br_member_dm["br-guest2"][i] = "eth"..j..".4094"
    end

    for i= 1,4 do
        local j = i - 1
        br_member_dm["br-lan"][i] = "eth"..j
    end
    br_member_dm["br-lan"][5] = "wl0"
    br_member_dm["br-lan"][6] = "wl1"
    br_member_dm["br-lan"][7] = "wl1_1"
    br_member_dm["br-lan"][8] = "wl1_2"

end

local function network_device_status(req, msg)
    local response = {} 

      local temp_response = {
	["br-guest"] = {
		["external"] = false,
		["present"] = true,
		["type"] = "bridge",
		["up"] = true,
		["carrier"] = true,
		["bridge-members"]= {
			"eth0",
			"eth1",
			"eth2",
			"eth3",
			"wl0",
			"wl1"
		},
		["mtu"] = 1500,
		["mtu6"] = 1500,
		["macaddr"] = "20:b0:01:2b:49:eb",
		["txqueuelen"] = 0,
		["ipv6"] = true,
		["promisc"] = false,
		["rpfilter"] = 1,
		["acceptlocal"] = false,
		["igmpversion"] = 0,
		["mldversion"] = 0,
		["neigh4reachabletime"] = 30000,
		["neigh6reachabletime"] = 30000,
		["neigh4gcstaletime"] = 60,
		["neigh6gcstaletime"] = 60,
		["neigh4locktime"] = 100,
		["dadtransmits"] = 4,
		["multicast"] = true,
		["sendredirects"] = true,
		["statistics"] = {
			["collisions"] = 0,
			["rx_frame_errors"] = 0,
			["tx_compressed"] = 0,
			["multicast"] = 0,
			["rx_length_errors"] = 0,
			["tx_dropped"] = 0,
			["rx_bytes"] = 0,
			["rx_missed_errors"] = 0,
			["tx_errors"] = 0,
			["rx_compressed"] = 0,
			["rx_over_errors"] = 0,
			["tx_fifo_errors"] = 0,
			["rx_crc_errors"] = 0,
			["rx_packets"] = 0,
			["tx_heartbeat_errors"] = 0,
			["rx_dropped"] = 0,
			["tx_aborted_errors"] = 0,
			["tx_packets"] = 30,
			["rx_errors"] = 0,
			["tx_bytes"] = 3908,
			["tx_window_errors"] = 0,
			["rx_fifo_errors"] = 0,
			["tx_carrier_errors"] = 0,
		}
	},
	["br-guest2"] = {
		["external"] = false,
		["present"] = true,
		["type"]= "bridge",
		["up"] = true,
		["carrier"] = true,
		["bridge-members"] = {
			"eth0",
			"eth1",
			"eth2",
			"eth3",
			"wl0",
			"wl1",
		},
		["mtu"] = 1500,
		["mtu6"] = 1500,
		["macaddr"] = "20:b0:01:2b:49:ea",
		["txqueuelen"] = 0,
		["ipv6"] = true,
		["promisc"] = false,
		["rpfilter"] = 1,
		["acceptlocal"] = false,
		["igmpversion"] = 0,
		["mldversion"] = 0,
		["neigh4reachabletime"] = 30000,
		["neigh6reachabletime"] = 30000,
		["neigh4gcstaletime"] = 60,
		["neigh6gcstaletime"] = 60,
		["neigh4locktime"] = 100,
		["dadtransmits"] = 4,
		["multicast"] = true,
		["sendredirects"] = true,
		["statistics"] = {
			["collisions"] = 0,
			["rx_frame_errors"] = 0,
			["tx_compressed"] = 0,
			["multicast"] = 0,
			["rx_length_errors"] = 0,
			["tx_dropped"] = 0,
			["rx_bytes"] = 0,
			["rx_missed_errors"] = 0,
			["tx_errors"] = 0,
			["rx_compressed"] = 0,
			["rx_over_errors"] = 0,
			["tx_fifo_errors"] = 0,
			["rx_crc_errors"] = 0,
			["rx_packets"] = 0,
			["tx_heartbeat_errors"] = 0,
			["rx_dropped"] = 0,
			["tx_aborted_errors"] = 0,
			["tx_packets"] = 26,
			["rx_errors"] = 0,
			["tx_bytes"] = 3536,
			["tx_window_errors"] = 0,
			["rx_fifo_errors"] = 0,
			["tx_carrier_errors"] = 0,
		}
	},
	["br-lan"] = {
		["external"] =  false,
		["present"] =  true,
		["type"] =  "bridge",
		["up"] =  true,
		["carrier"] =  true,
		["bridge-members"] = {
			"eth0",
			"eth1",
			"eth2",
			"eth3",
			"wl0",
			"wl1"
		},
		["mtu"] =  1500,
		["mtu6"] =  1500,
		["macaddr"] =  "20:b0:01:2b:49:ea",
		["txqueuelen"] =  0,
		["ipv6"] =  true,
		["promisc"] =  false,
		["rpfilter"] =  1,
		["acceptlocal"] =  false,
		["igmpversion"] =  0,
		["mldversion"] =  0,
		["neigh4reachabletime"] =  30000,
		["neigh6reachabletime"] =  30000,
		["neigh4gcstaletime"] =  60,
		["neigh6gcstaletime"] =  60,
		["neigh4locktime"] =  -1,
		["dadtransmits"] =  4,
		["multicast"] =  true,
		["sendredirects"] =  true,
		["statistics"] =  {
			["collisions"] =  0,
			["rx_frame_errors"] =  0,
			["tx_compressed"] =  0,
			["multicast"] =  0,
			["rx_length_errors"] =  0,
			["tx_dropped"] =  0,
			["rx_bytes"] =  114947,
			["rx_missed_errors"] =  0,
			["tx_errors"] =  0,
			["rx_compressed"] =  0,
			["rx_over_errors"] =  0,
			["tx_fifo_errors"] =  0,
			["rx_crc_errors"] =  0,
			["rx_packets"] =  1463,
			["tx_heartbeat_errors"] =  0,
			["rx_dropped"] =  0,
			["tx_aborted_errors"] =  0,
			["tx_packets"] =  1206,
			["rx_errors"] =  0,
			["tx_bytes"] =  194214,
			["tx_window_errors"] =  0,
			["rx_fifo_errors"] =  0,
			["tx_carrier_errors"] =  0,
		}
	},
}

    temp_response["br-lan"]["bridge-members"] = br_member_dm["br-lan"]
    temp_response["br-guest"]["bridge-members"] = br_member_dm["br-guest"]
    temp_response["br-guest2"]["bridge-members"] = br_member_dm["br-guest2"]

    if msg["name"] ~= nil and temp_response[msg["name"]] ~= nil then
        response[msg["name"]] = temp_response[msg["name"]]
    end

    if msg["name"] == nil then
        response = temp_response
    end

    conn:reply(req, response)
    return
end


local function network_interface_lan_add(req, msg)
    local response = {} 

    if msg["name"] ~= nil then
        local last = #br_member_dm["br-lan"]

        last = last + 1
        br_member_dm["br-lan"][last] = msg["name"]
        execute("brctl addif br-lan "..msg["name"])
    end

    --conn:reply(req, response)
    return
end

local function network_interface_lan_remove(req, msg)
    local response = {} 

    if msg["name"] ~= nil then
        local new_iface  = {}
        local i          = 1
        for k,v in ipairs(br_member_dm["br-lan"]) do
            if v ~= msg["name"] then
                new_iface[i] = v
                i = i + 1
            end
        end

        br_member_dm["br-lan"] = new_iface
        execute("brctl delif br-lan "..msg["name"])
    end

    --conn:reply(req, response)
    return
end


local function network_interface_guest_add(req, msg)
    local response = {} 

    if msg["name"] ~= nil then
        local last = #br_member_dm["br-guest"]

        last = last + 1
        br_member_dm["br-guest"][last] = msg["name"]
        execute("brctl addif br-guest "..msg["name"])
    end

    --conn:reply(req, response)
    return
end

local function network_interface_guest_remove(req, msg)
    local response = {} 

    if msg["name"] ~= nil then
        local new_iface  = {}
        local i          = 1
        for k,v in ipairs(br_member_dm["br-guest"]) do
            if v ~= msg["name"] then
                new_iface[i] = v
                i = i + 1
            end
        end

        execute("brctl delif br-guest "..msg["name"])
        br_member_dm["br-guest"] = new_iface
    end

    --conn:reply(req, response)
    return
end

local function network_interface_guest2_add(req, msg)
    local response = {} 

    if msg["name"] ~= nil then
        local last = #br_member_dm["br-guest2"]

        last = last + 1
        br_member_dm["br-guest2"][last] = msg["name"]
        execute("brctl addif br-guest2 "..msg["name"])
    end

    --conn:reply(req, response)
    return
end

local function network_interface_guest2_remove(req, msg)
    local response = {} 

    if msg["name"] ~= nil then
        local new_iface  = {}
        local i          = 1
        for k,v in ipairs(br_member_dm["br-guest2"]) do
            if v ~= msg["name"] then
                new_iface[i] = v
                i = i + 1
            end
        end

        execute("brctl delif br-guest2 "..msg["name"])
        br_member_dm["br-guest2"] = new_iface
    end

    --conn:reply(req, response)
    return
end

--- sends ubus response
-- @tparam #string req ubus request
-- @tparam #table data ubus reply data
function ubusConn:reply(req, data)
  if self.ubus then
    self.ubus:reply(req, data)
  end
end

--- adds new ubus object
-- @tparam #string method ubus object name
function ubusConn:add(method)
  if self.ubus then
    self.ubus:add(method)
  end
end

--- executes ubus call to retrieve data
-- @tparam string facility ubus object name
-- @tparam table func list of functions to be called for ubus output
-- @tparam table params parameters for ubus call
function ubusConn:call(facility, func, params)
  if self.ubus then
    return self.ubus:call(facility, func, params)
  end
end

--- sends ubus events
-- @tparam #string facility ubus object name
-- @tparam #table data ubus event data
function ubusConn:send(facility, data)
  if self.ubus then
    self.ubus:send(facility, data)
  end
end

--- listens for ubus events
function ubusConn:listen(events)
  if self.ubus then
    self.ubus:listen(events)
  end
end

--- removes ubus library
function ubusConn:close()
  self.ubus = nil
end

--- checks if ubus object is already existing
-- @treturn #boolean if object is present or not
function ubusConn:hasObject(object)
  if self.ubus then
    local namespaces = self.ubus:objects()
    for _, n in ipairs(namespaces) do
      if n == object then
        return true
      end
    end
  end
  return false
end

local function addhostapdObject()
  local network = {
      ['network.link'] = {
	status = { network_link_status, {}},
      },
      ['network.device'] = {
        status = { network_device_status, {["name"] = ubus.STRING}},
      },
      ['network.interface.lan'] = {
        add_device = { network_interface_lan_add, {["name"] = ubus.STRING}},
        remove_device = { network_interface_lan_remove, {["name"] = ubus.STRING}}
      },
      ['network.interface.guest'] = {
        add_device = { network_interface_guest_add, {["name"] = ubus.STRING}},
        remove_device = { network_interface_guest_remove, {["name"] = ubus.STRING}}
      },
      ['network.interface.guest2'] = {
        add_device = { network_interface_guest2_add, {["name"] = ubus.STRING}},
        remove_device = { network_interface_guest2_remove, {["name"] = ubus.STRING}}
      },
  }

  local wireless = {
      ['wireless'] = {
	get = { wireless_get, {}},
	acl_button = {wireless_get, {}},
	wps_button = {wireless_get, {}},
	reload = {wireless_get, {}},
	save_station_history = {wireless_get, {}},
	reset_station_history = {wireless_get, {}},
      },
      ['wireless.accesspoint'] = {
          get = { wireless_accesspoint_get, {['name'] = ubus.STRING} },
      },
      ['wireless.accesspoint.acl'] = {
          get    = { wireless_accesspoint_acl_get,    {["name"] = ubus.STRING}},
	  deny   = { wireless_accesspoint_acl_deny,   {["name"] = ubus.STRING, ["macaddr"] = ubus.STRING}},
	  delete = { wireless_accesspoint_acl_delete, {["name"] = ubus.STRING, ["macaddr"] = ubus.STRING}},
	  flush  = { wireless_accesspoint_acl_flush,  {["name"] = ubus.STRING}}
      },
      ['wireless.accesspoint.hotspot'] = {},
      ['wireless.accesspoint.radius'] = {},
      ['wireless.accesspoint.security'] = {
          get    = { wireless_accesspoint_security_get,    {["name"] = ubus.STRING}},
      },
      ['wireless.accesspoint.station'] = {
          get = { wireless_accesspoint_station_get,{ ["name"] = ubus.STRING,["macaddr"]=ubus.STRING,["short"] = ubus.INT32,["beacon_report"]=ubus.INT32,["max_beacon_age"]=ubus.INT32,["report_assoc_frame"]=ubus.INT32} }, 
	  reset = { wireless_accesspoint_station_reset, {["name"]=ubus.STRING,["macaddr"]=ubus.STRING} },
	  disassoc = { wireless_accesspoint_station_disassoc, {["name"]= ubus.STRING ,["macaddr"]=ubus.STRING,["reason"]=ubus.INT32} },
	  deauth = { wireless_accesspoint_station_deauth, {} },
	  send_bss_transition_request = {wireless_accesspoint_station_btm, {}},
	  send_beacon_report_request = { wireless_accesspoint_station_11k,{}}
      },
      ['wireless.accesspoint.wps'] = {
          get = { wireless_accesspoint_wps_get,{ }}, 
      },
      ['wireless.accesspoint_group'] = {},
      ['wireless.backbone'] = {},
      ['wireless.bandsteer'] = {},
      ['wireless.radio.acs'] = {
	get                = {wireless_radio_acs_get,{}},
	rescan             = {wireless_radio_acs_rescan,{}},
	forced_acs_channel = {wireless_radio_acs_forced_acs_channel,{}},
      },
      ['wireless.radio.acs.channel_stats'] = {
	get                = {wireless_radio_acs_channel_stats_get,{}},
      },
      ['wireless.radio.bsslist'] = {
	get                = {wireless_radio_bsslist_get,{}},
      },
      ['wireless.radio.caldata'] = {},
      ['wireless.radio.dfs'] = {
        get                = {wireless_radio_dfs_get, {}},
      },
      ['wireless.radio.eco'] = {},
      ['wireless.radio.monitor'] = {
        get                = {wireless_radio_monitor_get, {}}
      },
      ['wireless.radio.monitor.station'] = {
        get                = {wireless_radio_monitor_station_get, {}},
        add                = {wireless_radio_monitor_station_add, {}},
        flush              = {wireless_radio_monitor_station_flush,{}},
        delete             = {wireless_radio_monitor_station_delete,{}},
      },
      ['wireless.radio.stats'] = {
        get                = {wireless_radio_stats_get, {}},
      },
      ['wireless.radio.txtest'] = {},
      ['wireless.ssid'] = {
        get                = {wireless_ssid_get, {}},
      },
      ['wireless.ssid.stats'] = {
        get                = {wireless_ssid_stats_get, {}},
      },
      ['wireless.ubus_stats'] = {
        get                = {wireless_ubus_stats_get, {}},
      },
      ['wireless.uci_stats'] = {
        get                = {wireless_uci_stats_get, {}},
      },
      ['wireless.wds'] = {
        get                = {wireless_wds_get, {}},
      },
      ['wireless.radio'] = {
          get = {
              wireless_get_radio, {['name'] = ubus.STRING}
          },
      },
  }
  conn:add(network)
  conn:add(wireless)
end

--- Initializes ubus plugin
function M.init(rt)
  runtime = rt
  if not runtime.ubus then
    conn = {
      ubus = ubus.connect()
    }
    if not conn.ubus then
      return nil, 'Failed to connect to ubus'
    end
    setmetatable(conn, ubusConn)

    if conn:hasObject('wireless') then
      --runtime.log:error('traffic_seperation UBUS objects already present')
      print('traffic_seperation UBUS objects already present')
      return nil, 'Failed to initialize ubus'
    end

    addhostapdObject()
    add_brifaces()

    runtime.ubus = conn
  end
  return true
end

return M
