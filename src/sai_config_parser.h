// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco").
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// END_LEGAL

// Configuration files parser functions for read/load device configuration, lanes swap/inversion information, and SerDes parameters.

#ifndef __SAI_CONFIG_PARSER_H__
#define __SAI_CONFIG_PARSER_H__

#include "api/system/la_device.h"
#include <jansson.h>
#include <string.h>
#include "sai_device.h"

namespace silicon_one
{
namespace sai
{

using serdes_prop_defines_t = std::unordered_map<std::string, lsai_serdes_params_t>;
using s_stage = la_mac_port::serdes_param_stage_e;
using s_mode = la_mac_port::serdes_param_mode_e;

// Mapping table from json serdes parameter key to la_mac_port::serdes_param_e
const serdes_prop_defines_t serdes_prop_defines = {
    {"RX_PLL_BB", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::RX_PLL_BB, s_mode::FIXED, 1}}},
    {"RX_PLL_IFLT", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::RX_PLL_IFLT, s_mode::FIXED, 6}}},
    {"RX_PLL_INT", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::RX_PLL_INT, s_mode::FIXED, 8}}},
    {"TX_PLL_BB", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::TX_PLL_BB, s_mode::FIXED, 25}}},
    {"TX_PLL_IFLT", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::TX_PLL_IFLT, s_mode::FIXED, 1}}},
    {"TX_PLL_INT", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::TX_PLL_INT, s_mode::FIXED, 7}}},

    // TX_EQ
    {"TX_PRE1", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::TX_PRE1, s_mode::FIXED, 0}}},
    {"TX_PRE2", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::TX_PRE2, s_mode::FIXED, 0}}},
    {"TX_PRE3", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::TX_PRE3, s_mode::FIXED, 0}}},
    {"TX_ATTN", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::TX_ATTN, s_mode::FIXED, 0}}},
    {"TX_POST", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::TX_POST, s_mode::FIXED, 0}}},
    {"TX_POST2", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::TX_POST2, s_mode::FIXED, 0}}},
    {"TX_POST3", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::TX_POST3, s_mode::FIXED, 0}}},
    {"TX_MAIN", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::TX_MAIN, s_mode::FIXED, 0}}},
    {"CTLE_TUNE", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::CTLE_TUNE, s_mode::FIXED, 0}}},
    {"TX_LUT_MODE", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::TX_LUT_MODE, s_mode::FIXED, 0}}},
    {"TX_INNER_EYE1", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::TX_INNER_EYE1, s_mode::FIXED, 0}}},
    {"TX_INNER_EYE2", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::TX_INNER_EYE2, s_mode::FIXED, 0}}},
    {"EID_THRESHOLD", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::ELECTRICAL_IDLE_THRESHOLD, s_mode::FIXED, 2}}},

    // RX - CTLE/FFE activate stage
    {"RX_DSP_MODE", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::RX_DSP_MODE, s_mode::FIXED, 0}}},
    {"RX_CTLE_CODE", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::RX_CTLE_CODE, s_mode::FIXED, 0}}},
    {"RX_AFE_TRIM", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::RX_AFE_TRIM, s_mode::FIXED, 0}}},
    {"RX_VGA_TRACKING", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::RX_VGA_TRACKING, s_mode::FIXED, 0}}},
    {"RX_AC_COUPLING_BYPASS", {{s_stage::ACTIVATE, la_mac_port::serdes_param_e::RX_AC_COUPLING_BYPASS, s_mode::FIXED, 0}}},

    // ICAL - CTLE/FFE - used in serdes setting json file currently
    {"RX_GS1", {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_CTLE_GAINSHAPE1, s_mode::FIXED, 0}}},
    {"RX_GS2", {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_CTLE_GAINSHAPE2, s_mode::FIXED, 0}}},
    {"RX_GAIN_LF_MIN", {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_CTLE_LF_MIN, s_mode::FIXED, 0}}},
    {"RX_GAIN_LF_MAX", {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_CTLE_LF_MAX, s_mode::FIXED, 0}}},
    {"RX_GAIN_HF_MIN", {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_CTLE_HF_MIN, s_mode::FIXED, 0}}},
    {"RX_GAIN_HF_MAX", {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_CTLE_HF_MAX, s_mode::FIXED, 0}}},
    {"RX_TERM", {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_TERM, s_mode::FIXED, 0}}},
    {"RX_FFE_BFGLF",
     {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_FFE_BFLF, s_mode::FIXED, 1},
      {s_stage::PRE_PCAL, la_mac_port::serdes_param_e::RX_FFE_BFLF, s_mode::ADAPTIVE, 1}}},
    {"RX_FFE_BFGHF",
     {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_FFE_BFHF, s_mode::FIXED, 4},
      {s_stage::PRE_PCAL, la_mac_port::serdes_param_e::RX_FFE_BFHF, s_mode::ADAPTIVE, 4}}},
    {"RX_CTLE_LF", {{s_stage::PRE_PCAL, la_mac_port::serdes_param_e::RX_CTLE_LF, s_mode::STATIC, 0}}},
    {"HYSTERESIS_POST1_NEGATIVE", {{s_stage::PRE_PCAL, la_mac_port::serdes_param_e::HYSTERESIS_POST1_NEGATIVE, s_mode::FIXED, 0}}},
    {"HYSTERESIS_POST1_POSITIVE", {{s_stage::PRE_PCAL, la_mac_port::serdes_param_e::HYSTERESIS_POST1_POSETIVE, s_mode::FIXED, 0}}},

    // ICAL - FFE - not specified in json file.
    {"RX_FFE_POST", {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_FFE_POST, s_mode::FIXED, 0}}},
    {"RX_FFE_PRE2", {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_FFE_PRE2, s_mode::FIXED, 0}}},
    {"RX_FFE_PRE1", {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_FFE_PRE1, s_mode::FIXED, 0}}},
    {"RX_FFE_PRE1_MAX", {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_FFE_PRE1_MAX, s_mode::FIXED, 0}}},
    {"RX_FFE_PRE1_MIN", {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_FFE_PRE1_MIN, s_mode::FIXED, 0}}},
    {"RX_FFE_PRE2_MAX", {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_FFE_PRE2_MAX, s_mode::FIXED, 0}}},
    {"RX_FFE_PRE2_MIN", {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_FFE_PRE2_MIN, s_mode::FIXED, 0}}},
    {"RX_FFE_SHORT_CH_EN", {{s_stage::PRE_ICAL, la_mac_port::serdes_param_e::RX_FFE_SHORT_CHANNEL_EN, s_mode::FIXED, 0}}},

    // PCAL - CTLE Static - not specified in json file.
    {"RX_PCAL_EFFORT", {{s_stage::PRE_PCAL, la_mac_port::serdes_param_e::RX_PCAL_EFFORT, s_mode::FIXED, 0}}},
    {"RX_CTLE_HF", {{s_stage::PRE_PCAL, la_mac_port::serdes_param_e::RX_CTLE_HF, s_mode::STATIC, 0}}},
    {"RX_CTLE_DC", {{s_stage::PRE_PCAL, la_mac_port::serdes_param_e::RX_CTLE_DC, s_mode::STATIC, 0}}},
    {"RX_CTLE_BW", {{s_stage::PRE_PCAL, la_mac_port::serdes_param_e::RX_CTLE_BW, s_mode::STATIC, 0}}},
    {"RX_CTLE_SHORT_CH_EN", {{s_stage::PRE_PCAL, la_mac_port::serdes_param_e::RX_CTLE_SHORT_CHANNEL_EN, s_mode::STATIC, 0}}}};

class config_parser
{
public:
    /// @brief  config_parser constructor
    ///
    /// @param[in]	sdev	        pointer to a lsai_device object
    /// @param[in]	config_file     Path of Configuration File
    /// @param[in]	dev_cfg_idx     Configuration Index of devices[] in json file.
    ///
    config_parser(std::shared_ptr<lsai_device> sdev, const std::string& config_file, uint32_t dev_cfg_idx)
        : m_sdev(sdev), m_config_file(config_file), m_dev_cfg_idx(dev_cfg_idx){};

    config_parser(std::shared_ptr<lsai_device> sdev, const char* config_file, uint32_t dev_cfg_idx)
        : m_sdev(sdev), m_dev_cfg_idx(dev_cfg_idx)
    {
        // to protect char -> string conversion.
        m_config_file = (config_file == nullptr) ? "" : std::string(config_file);
    };

    ~config_parser()
    {
        json_dereference();
    };

    /// @brief	Read json key "media_type" from serdes parameters file
    ///
    /// @param[in]	j_media_type	json object that points to "media_type" json key in file.
    /// @param[out]	media_type	    SAI port media type (lsai_serdes_media_type_e)
    ///
    /// @return		true	Return true if "media_type" is not present in file or "media_type" has valid information.
    /// @return		false	Return false if "media_type" json key is specified in file but it has an invalid value.
    ///                     media_type will be set to "SAI_PORT_MEDIA_TYPE_UNKNOWN" in this situation.
    bool get_media_type_value(json_t* j_media_type, lsai_serdes_media_type_e& media_type);

    /// @brief	Convert media type information in string to lsai_serdes_media_type_e enum.
    ///
    /// @param[in]	media_type_name	Media type information in string format.
    /// @param[out]	media_type	    SAI port media type (lsai_serdes_media_type_e)
    ///
    /// @return		true	Return true of "media_type_name" has valid information.
    /// @return		false	Return false if "media_type_name" has an invalid information.
    ///                     media_type will be set to "SAI_PORT_MEDIA_TYPE_UNKNOWN" in this situation.
    bool get_media_type_value(const std::string& media_type_name, lsai_serdes_media_type_e& media_type);

    /// @brief  Load default Pacific board/serdes configurations to lsai_device object
    la_status load_pacific_default();

    /// @brief  Load all board/serdes configurations to lsai_device object
    ///
    /// @return		la_status
    /// @retval		LA_STATUS_SUCCESS           Configuration File is loaded correctly.
    ///             LA_STATUS_ENOTIMPLEMENTED   Setting(s) in configuration file is not supported.
    ///             LA_STATUS_EINVAL            Invalid setting in configuration file.
    ///             LA_STATUS_ENOTFOUND         Configuration File is missing.
    la_status load_configuration();

    /// @brief	    Open json configuration file and setup member pointers (json_t) in lsai_device class, whose pointers are used to
    /// load configurations.
    ///
    /// @return		la_status
    /// @retval		LA_STATUS_SUCCESS           Configuration File is loaded correctly.
    ///             LA_STATUS_ENOTIMPLEMENTED   Setting in configuration file is not supported.
    ///             LA_STATUS_EINVAL            Invalid setting in configuration file.
    ///             LA_STATUS_ENOTFOUND         Configuration File is missing.
    la_status open_cfg_file();

    /// @brief	    Load device property from json file.
    ///
    /// @return     la_status
    /// @retval		LA_STATUS_SUCCESS           Properties are loaded correctly.
    la_status load_device_property();

    /// @brief	    Load lane setting from configuration file.
    ///
    /// @return		la_status
    /// @retval		LA_STATUS_SUCCESS           Lane setting is loaded correctly.
    ///             LA_STATUS_EINVAL            Invalid setting in configuration file. Loading aborted.
    la_status load_lane_settings();

    /// @brief	Setup default pll and serdes parameters. If there is missing parameter of a SerDes lane, we should apply default
    /// parameters instead.
    ///
    /// @return		la_status
    /// @retval		LA_STATUS_SUCCESS   Default parameters are loaded.
    la_status load_default_serdes_param();

    /// @brief	    Read all serdes object (serdes key) from serdes setting file and create a list of serdes parameters for each
    /// serdes in unordered_map structure.
    ///
    /// @return		la_status
    /// @retval		LA_STATUS_SUCCESS   SerDes parameters are loaded correctly.
    /// @retval     LA_STATUS_EINVAL    Fail to build serdes_params_map from json file.
    la_status build_serdes_param_map();

    /// @brief	    Load "port_mix" json object from configuration file.
    ///
    /// @return     la_status
    /// @retval		LA_STATUS_SUCCESS   Successfully load all port configurations, missing "port_mix" or empty "port_mix"
    /// json objects.
    la_status load_port_mix();

    /// @brief	    Load "acl_key_profiles" json object from configuration file.
    ///
    /// @return     la_status
    /// @retval		LA_STATUS_SUCCESS   Successfully load all ACL key profile configurations, missing "acl_key_profiles"
    /// or empty "acl_key_profiles" json objects.
    la_status load_acl_key_profiles();

private:
    std::shared_ptr<lsai_device> m_sdev; // lsai_device which contains chip configuration and serdes parameter database.
    std::string m_config_file;           // configuration file
    uint32_t m_dev_cfg_idx; // configuration index in file; file may contain multipule device. This is index of json array.

    // json objects which are created for parsing
    json_t* m_json_root = nullptr;             // Root of json file
    json_t* m_json_devices = nullptr;          // JSON pointer to devices array in json configuration file.
    json_t* m_json_dev = nullptr;              // JSON pointer to the device in devices[cfg_idx]
    json_t* m_json_serdes_params = nullptr;    // SerDes parameters settings in device
    json_t* m_json_ifg_swap_lists = nullptr;   // SerDes Lanes setting, includes lane swaps and inversion in device
    json_t* m_json_port_mix = nullptr;         // JSON pointer to port_mix port configurations.
    json_t* m_json_dev_props = nullptr;        // JSON pointer to device property.
    json_t* m_json_dev_params = nullptr;       // JSON pointer to any device parameters to override
    json_t* m_json_acl_key_profiles = nullptr; // JSON pointer to acl_key_profiles configurations.

    /// @brief	    Delete all json objects in lsai_device. Should call after SerDes Parameters are loaded to free up memory.
    void json_dereference();

    /// @brief	check if there is a file_name key in json_obj. If there is, we redirect the json_obj to the root of the file.
    ///
    /// @param[inout]  json_obj	    pointr of json object.
    /// @param[in]  file_name_key	key of the file name. eg: "file_name"
    /// @param[in]  msg_whats_it    Few words descirption of the json key
    ///
    /// @return     la_status
    /// @retval		LA_STATUS_EINVAL    Invalid file name or path in json_obj.
    /// @retval		LA_STATUS_SUCCESS   Successfully open file in json_obj or skip file redirection in non-error case.
    la_status check_file_redirection(json_t*& json_obj, std::string file_name_key, std::string msg_whats_it);

    /// @brief	Convert hardware device type from string to enum
    ///
    /// @param[in]	hw_device_type	Media type information in string format.
    ///
    /// @return		hw_device_type_e::PACIFIC	If device type is pacific.
    /// @return		hw_device_type_e::GIBRALTAR	If device type is gibraltar.
    /// @return     hw_device_type_e::INVALID   If device type is unknown.
    hw_device_type_e hw_device_type_from_string(const char* hw_device_type);

    /// @brief	    Load a device property from json key and update the value in la_device
    ///
    /// @param[in]  json_obj	json object that contains all device properties
    /// @param[in]  prop_name	json key of device property
    /// @param[in]  prop_e	    property enum
    ///
    /// @return     la_status
    /// @retval     LA_STATUS_SUCCESS   Skip (No device_property with prop_name) or set property successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid device_property value in json.
    template <json_type j_type, typename T>
    la_status update_device_property(const json_t* json_obj,
                                     const std::string& prop_name,
                                     silicon_one::la_device_property_e prop_e);

    // Set value to la_device_property_e in la_device.
    la_status set_device_property(silicon_one::la_device_property_e prop_e, const bool& value);
    la_status set_device_property(silicon_one::la_device_property_e prop_e, const int& value);
    la_status set_device_property(silicon_one::la_device_property_e prop_e, const std::string& value);

    template <json_type j_type, typename T>
    la_status update_extended_property(const json_t* json_obj, const std::string& prop_name, lsai_extended_property_e ext_prop);

    // Set value to m_ext_properties_* in sai_device. They will be applied at the end of create_switch.
    void set_extended_property(lsai_extended_property_e ext_prop, const bool& value);

    // Read a json serdes object, create a vector of all serdes parameters for this serdes, and create a serdes_key of this
    // serdes.
    la_status json_load_serdes_param(json_t* json_serdes,
                                     lsai_serdes_params_map_key_t& serdes_key,
                                     lsai_serdes_params_t& serdes_params,
                                     bool ifg_key);

    // Read a json serdes object which contains a vector of serdes shared same set of serdes parameters.
    // create a vector of all serdes parameters (shared) for vector of serdes ids and a vector of serdes_key.
    la_status json_load_serdes_param_array(json_t* json_serdes,
                                           std::vector<lsai_serdes_params_map_key_t>& serdes_keys_vec,
                                           lsai_serdes_params_t& shared_serdes_params);

    // Read a single serdes parameter and construct its properties list by given a json object of the serdes parameter
    la_status json_get_serdes_prop(json_t* json_prop_key, lsai_serdes_params_t& param);

    // Construct a single serdes parameter properties list by given a name and value of a serdes parameter
    la_status json_get_serdes_prop(const std::string& prop_key, const int& prop_value, lsai_serdes_params_t& param);

    /// @brief	load port group (all port configurations in group) from json object
    ///
    /// @param[in]  j_port_grp	JSON pointer of a group of ports
    /// @param[in]  port_grp	vector of port configurations.
    ///
    /// @return     la_status
    /// @retval		LA_STATUS_EINVAL    Invalid structure or value from json file.
    /// @retval		LA_STATUS_SUCCESS   Successfully return port_grp.
    la_status json_load_port_group(json_t* j_port_grp, lsai_port_grp_t& port_grp);

    /// @brief	load port config (single port) from json object
    ///
    /// @param[in]  j_port_cfg	JSON pointer of a port configuration set.
    /// @param[out] port_cfg	port configuration set that contains all attributes.
    /// @param[out] lanes_count	Number of PIFs (number of port for this configuration set.)
    ///
    /// @return     la_status
    /// @retval		LA_STATUS_EINVAL    Invalid structure or value from json file.
    /// @retval		LA_STATUS_SUCCESS   Successfully return port_cfg and lanes_count.
    la_status json_load_port_cfg(json_t* j_port_cfg, lsai_port_cfg_t& port_cfg, uint32_t& lanes_count);

    /// @brief	Setup switch initialization method, m_sw_init_method in lsai_device
    ///
    /// @param[in]  j_init_sw	    json pointer of "init_switch"
    ///
    /// @return     la_status
    /// @retval		LA_STATUS_SUCCESS   Successfully update m_sw_init_method.
    /// @retval		LA_STATUS_EINVAL    Fail to parse the json value.
    la_status json_load_init_switch(json_t* j_init_sw);

    // Loads any device parameters that are supported for writing as
    // registered in the device_params structure.
    la_status json_load_dev_params();
};

/// @brief	Search serdes_key in serdes_params map and return all serdes parameters setting of the key.
///
/// @param[in]	serdes_params_map	serdes parameters map that contains all serdes keys and theirs parameters.
///                                 Prerequisites: serdes_params_map must be built using sai_json_build_serdes_param_map().
/// @param[in]	serdes_key	        SerDes Key
/// @param[out]	serdes_params	    return of a vector of SerDes parameters; empty if key is missing in map.
///
/// @return		la_status
/// @retval		LA_STATUS_SUCCESS   SerDes Key is found and serdes_params is returned without error.
/// @retval     LA_STATUS_ENOTFOUND SerDes Key is not found in map.
la_status sai_json_find_serdes_params(const lsai_serdes_params_map_t& serdes_params_map,
                                      const lsai_serdes_params_map_key_t& serdes_key,
                                      lsai_serdes_params_t& serdes_params);
}
}
#endif
