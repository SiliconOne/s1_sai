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

#include <algorithm>
#include <unordered_map>
#include <iterator>
#include <regex>
#include <typeinfo>
#include "sai_config_parser.h"
#include "sai_logger.h"
#include "sai_strings.h"
#include "json_struct_writer.h"
#include "json_utils.h"
#include "api/system/la_device.h"
#include "device_context/la_device_context_types.h"

namespace silicon_one
{

namespace sai
{

bool
config_parser::get_media_type_value(json_t* j_media_type, lsai_serdes_media_type_e& media_type)
{
    if (j_media_type == nullptr) {
        media_type = lsai_serdes_media_type_e::NOT_PRESENT;
        return true; // not an error, media type can be mising in m_config_file.
    }

    const char* media_type_name = json_string_value(j_media_type);
    if (!json_is_string(j_media_type)) {
        sai_log_error(SAI_API_SWITCH,
                      "\"media_type\" is not a string type json object. Set to lsai_serdes_media_type_e::NOT_PRESENT");
        media_type = lsai_serdes_media_type_e::NOT_PRESENT;

        return false;
    }

    return get_media_type_value(media_type_name, media_type);
}

bool
config_parser::get_media_type_value(const std::string& media_type_name, lsai_serdes_media_type_e& media_type)
{
    // Mapping table from json to lsai_serdes_media_type_e
    static const std::map<std::string, lsai_serdes_media_type_e> sai_port_media_type_enum_map{
        {"", lsai_serdes_media_type_e::NOT_PRESENT},
        {"COPPER", lsai_serdes_media_type_e::COPPER},
        {"OPTIC", lsai_serdes_media_type_e::OPTIC},
        {"FIBER", lsai_serdes_media_type_e::OPTIC},
        {"CHIP2CHIP", lsai_serdes_media_type_e::CHIP2CHIP},
        {"LOOPBACK", lsai_serdes_media_type_e::LOOPBACK}};

    media_type = lsai_serdes_media_type_e::NOT_PRESENT;

    auto it = sai_port_media_type_enum_map.find(media_type_name);
    if (it != sai_port_media_type_enum_map.end()) {
        media_type = it->second;
        return true;
    }

    sai_log_error(SAI_API_SWITCH, "\"media_type\" (%s) is not supported.", media_type_name.c_str());

    return false;
}

la_status
config_parser::load_pacific_default()
{
    m_sdev->m_hw_device_type = hw_device_type_e::PACIFIC;
    m_sdev->m_hw_device_id = 0;
    m_sdev->m_dev_params.initialize(m_sdev->m_hw_device_type, matilda_model_e::NONE);
    // la_status status = sai_json_load_lane_settings(m_sdev, nullptr);
    // la_return_on_error(status);

    // load Sherman P5 by default...
    sai_log_info(SAI_API_SWITCH, "Loading Sherman P5 by Default...");
    m_sdev->m_board_cfg.lanes = lsai_lane_settings_t();
    // slice 0
    m_sdev->m_board_cfg.lanes.ifg_swap.push_back({2, 3, 0, 1, 6, 7, 4, 5, 9, 11, 8, 10, 15, 13, 12, 14, 16, 17});
    m_sdev->m_board_cfg.lanes.rx_inverse.push_back({4, 5, 6, 7, 8, 15});
    m_sdev->m_board_cfg.lanes.tx_inverse.push_back({});
    m_sdev->m_board_cfg.lanes.ifg_swap.push_back({0, 1, 3, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 16});
    m_sdev->m_board_cfg.lanes.rx_inverse.push_back({});
    m_sdev->m_board_cfg.lanes.tx_inverse.push_back({});

    // Slice 1
    m_sdev->m_board_cfg.lanes.ifg_swap.push_back({0, 3, 2, 1, 6, 7, 5, 4, 8, 11, 10, 9, 15, 13, 14, 12, 16, 17});
    m_sdev->m_board_cfg.lanes.rx_inverse.push_back({0, 1, 4, 5, 8, 9, 10, 11, 12, 13, 14});
    m_sdev->m_board_cfg.lanes.tx_inverse.push_back({1, 3, 4, 7, 9, 10, 13});
    m_sdev->m_board_cfg.lanes.ifg_swap.push_back({0, 3, 2, 1, 7, 4, 5, 6, 9, 10, 8, 11, 12, 14, 15, 13, 16, 17});
    m_sdev->m_board_cfg.lanes.rx_inverse.push_back({0, 1, 2, 4, 5, 6, 8, 9, 12, 13, 14});
    m_sdev->m_board_cfg.lanes.tx_inverse.push_back({1, 4, 7});

    // Slice 2
    m_sdev->m_board_cfg.lanes.ifg_swap.push_back({0, 2, 3, 1, 6, 7, 4, 5, 10, 8, 11, 9, 12, 14, 13, 15, 16, 17});
    m_sdev->m_board_cfg.lanes.rx_inverse.push_back({0, 1, 2, 3, 4, 6, 7, 14});
    m_sdev->m_board_cfg.lanes.tx_inverse.push_back({0, 3, 4, 8, 10, 13, 14});
    m_sdev->m_board_cfg.lanes.ifg_swap.push_back({0, 2, 1, 3, 4, 5, 6, 7, 8, 10, 9, 11, 15, 14, 12, 13, 16, 17});
    m_sdev->m_board_cfg.lanes.rx_inverse.push_back({3, 6, 7, 10, 11, 14, 15});
    m_sdev->m_board_cfg.lanes.tx_inverse.push_back({2, 4, 6, 7, 14});

    // Slice 3
    m_sdev->m_board_cfg.lanes.ifg_swap.push_back({0, 3, 1, 2, 7, 6, 4, 5, 9, 11, 8, 10, 15, 13, 14, 12, 16, 17});
    m_sdev->m_board_cfg.lanes.rx_inverse.push_back({0, 1, 2, 5, 8, 12});
    m_sdev->m_board_cfg.lanes.tx_inverse.push_back({1, 3, 5, 9, 13, 15});
    m_sdev->m_board_cfg.lanes.ifg_swap.push_back({3, 0, 2, 1, 6, 7, 4, 5, 11, 8, 10, 9, 15, 12, 14, 13, 17, 16});
    m_sdev->m_board_cfg.lanes.rx_inverse.push_back({2, 6, 7, 8, 9, 12, 13, 14});
    m_sdev->m_board_cfg.lanes.tx_inverse.push_back({6, 12, 15});

    // Slice 4
    m_sdev->m_board_cfg.lanes.ifg_swap.push_back({0, 1, 3, 2, 4, 6, 5, 7, 8, 9, 10, 11, 13, 12, 14, 15, 16, 17});
    m_sdev->m_board_cfg.lanes.rx_inverse.push_back({6, 7, 10, 11, 12});
    m_sdev->m_board_cfg.lanes.tx_inverse.push_back({1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15});
    m_sdev->m_board_cfg.lanes.ifg_swap.push_back({2, 0, 1, 3, 5, 7, 4, 6, 8, 10, 11, 9, 13, 15, 12, 14, 16, 17});
    m_sdev->m_board_cfg.lanes.rx_inverse.push_back({1, 2, 3, 6, 7, 9, 11, 13, 14, 15});
    m_sdev->m_board_cfg.lanes.tx_inverse.push_back({0, 1, 2, 3, 5, 6, 8, 9, 10, 11, 13, 14, 15});

    // Slice 5
    m_sdev->m_board_cfg.lanes.ifg_swap.push_back({0, 1, 2, 3, 4, 5, 6, 7, 10, 9, 8, 11, 12, 13, 14, 15, 16, 17});
    m_sdev->m_board_cfg.lanes.rx_inverse.push_back({1, 2, 5, 12, 15});
    m_sdev->m_board_cfg.lanes.tx_inverse.push_back({0, 1, 10, 11, 12, 13, 14, 15});
    m_sdev->m_board_cfg.lanes.ifg_swap.push_back({3, 2, 1, 0, 4, 5, 6, 7, 9, 11, 8, 10, 12, 13, 14, 15, 17, 16});
    m_sdev->m_board_cfg.lanes.rx_inverse.push_back({1, 3, 4, 6, 12, 13, 14, 15});
    m_sdev->m_board_cfg.lanes.tx_inverse.push_back({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15});

    la_status status = load_default_serdes_param();
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

// Load all configurations to lsai_device object
la_status
config_parser::load_configuration()
{
    // Open configuration file.
    if (m_config_file == "") {
        // if m_config_file is not there, use pacific default...
        sai_log_warn(SAI_API_SWITCH, "Missing Board Configuration File.");
        return load_pacific_default();
    }
    la_status status = open_cfg_file();
    la_return_on_error(status);

    // load lane settings
    status = load_lane_settings();
    la_return_on_error(status);

    status = load_device_property();
    la_return_on_error(status);

    // load default serdes parameters and default pll settings.
    status = load_default_serdes_param();
    la_return_on_error(status);
    // Build serdes_param_map (used by sai_port.cpp to setup_mac_port())
    status = build_serdes_param_map();
    la_return_on_error(status);

    // Load any device parameters being overridden
    status = json_load_dev_params();
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

hw_device_type_e
config_parser::hw_device_type_from_string(const char* hw_device_type)
{
    if (!strcmp(hw_device_type, "pacific")) {
        return hw_device_type_e::PACIFIC;
    } else if (!strcmp(hw_device_type, "gibraltar")) {
        return hw_device_type_e::GIBRALTAR;
    }

    return hw_device_type_e::INVALID;
}

void
config_parser::json_dereference()
{
    // We don't incref intermediate nodes, so this will free the whole tree.
    if (m_json_root != nullptr) {
        json_decref(m_json_root);
    }
}

// check if there is a file_name key in json_obj. If there is, we redirect the json_obj to the root of the file.
la_status
config_parser::check_file_redirection(json_t*& json_obj, std::string file_name_key, std::string msg_whats_it)
{
    json_t* j_file_path = json_object_get(json_obj, file_name_key.c_str());
    if (json_obj == nullptr || j_file_path == nullptr) {
        // It is okay to missing a file_name_key or json object is null.
        // no file redirection.
        sai_log_debug(SAI_API_SWITCH, "No key \"%s\" detected.", file_name_key.c_str());

        return LA_STATUS_SUCCESS;
    }

    // found <file_name_key> under <json_obj>, open the file.
    // check the file.
    if (!json_is_string(j_file_path)) {
        sai_log_error(SAI_API_SWITCH,
                      "JSON error on loading object \"%s\" as %s in %s",
                      file_name_key.c_str(),
                      "string",
                      m_config_file.c_str());

        return LA_STATUS_EINVAL;
    }

    // open the file and move json_obj pointer to the file
    std::string file_name = json_string_value(j_file_path);
    if (file_name != "") {
        std::stringstream error_file_list;
        const char* base_output_dir = getenv("BASE_OUTPUT_DIR");
        json_error_t j_error;
        json_obj = json_load_file(file_name.c_str(), 0, &j_error);

        if (json_obj == nullptr) {
            // can't find the file
            error_file_list << "\n\t" << j_error.line << ": " << j_error.text;
        }

        if (json_obj == nullptr && base_output_dir != nullptr) {
            // check file in BASE_OUTPUT_DIR path...
            std::stringstream ss;
            ss << base_output_dir << "/" << file_name;
            json_obj = json_load_file(ss.str().c_str(), 0, &j_error);

            if (json_obj == nullptr) {
                error_file_list << "\n\t" << j_error.line << ": " << j_error.text;
            } else {
                // found it !
                file_name = ss.str();
            }
        }

        if (json_obj == nullptr && base_output_dir != nullptr) {
            // check file in SAI path relative to BASE_OUTPUT_DIR
            std::stringstream ss;
            ss << base_output_dir << "/../../../../sai/" << file_name;
            json_obj = json_load_file(ss.str().c_str(), 0, &j_error);

            if (json_obj == nullptr) {
                error_file_list << "\n\t" << j_error.line << ": " << j_error.text;
            } else {
                file_name = ss.str();
            }
        }

        if (json_obj == nullptr) {
            // tried everything... return error
            sai_log_error(SAI_API_SWITCH, "Fail to load json file(s):%s\n", error_file_list.str().c_str());
            return LA_STATUS_EINVAL;
        }

        sai_log_info(
            SAI_API_SWITCH, "Found %s json file: %s, key: %s", msg_whats_it.c_str(), file_name.c_str(), file_name_key.c_str());
    }

    return LA_STATUS_SUCCESS;
}

// Open json configuration file and setup member pointers (json_t) in lsai_device class, whose pointers are used to load
// configurations.
la_status
config_parser::open_cfg_file()
{
    la_status status;

    // Open json file for board configuration
    json_error_t j_error;

    m_json_root = json_load_file(m_config_file.c_str(), 0, &j_error);
    if (m_json_root == nullptr) {
        sai_log_error(SAI_API_SWITCH, "Loading Configuration Fail %d: %s", j_error.line, j_error.text);
        return LA_STATUS_ENOTFOUND;
    }

    // Load the configuration from File
    sai_log_info(SAI_API_SWITCH, "Loading Board Configuration from %s, Dev_index[%d]", m_config_file.c_str(), m_dev_cfg_idx);

    JSON_GET_OBJ_PTR(m_json_devices, "devices", array, m_json_root, m_config_file.c_str());
    // Get the device pointer to "devices[json_dev_idx]"
    m_json_dev = json_array_get(m_json_devices, m_dev_cfg_idx);
    if (m_json_dev == nullptr) {
        sai_log_error(SAI_API_SWITCH,
                      "Board Configuration Loading failed. \"devices\" must be array. Or, Index(%d) is out of range.",
                      m_dev_cfg_idx);
        return LA_STATUS_EINVAL;
    }

    json_t* j_dev_type;
    json_t* j_dev_id;
    JSON_GET_OBJ_PTR(j_dev_type, "type", string, m_json_dev, m_config_file.c_str());
    JSON_GET_OBJ_PTR(j_dev_id, "id", integer, m_json_dev, m_config_file.c_str());
    m_sdev->m_hw_device_type = hw_device_type_from_string(json_string_value(j_dev_type));
    m_sdev->m_hw_device_id = json_integer_value(j_dev_id);
    matilda_model_e matilda_type = matilda_model_e::NONE;
    if (m_sdev->m_hw_device_type == hw_device_type_e::GIBRALTAR) {
        status = m_sdev->m_dev->get_int_property(la_device_property_e::MATILDA_MODEL_TYPE, (int&)matilda_type);
        return_on_error(status);
    }
    status = m_sdev->m_dev_params.initialize(m_sdev->m_hw_device_type, matilda_type);
    if (status != LA_STATUS_SUCCESS) {
        sai_log_error(
            SAI_API_SWITCH, "Board Configuration Loading failed. \"type\" = %s is not supported.", json_string_value(j_dev_type));
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    JSON_GET_OBJ_PTR(m_json_ifg_swap_lists, "ifg_swap_lists", array, m_json_dev, m_config_file.c_str());

    m_json_dev_props = json_object_get(m_json_dev, "device_property");

    m_json_serdes_params = json_object_get(m_json_dev, "serdes_params");
    if ((m_json_serdes_params != nullptr) && !json_is_object(m_json_serdes_params)) {
        sai_log_error(
            SAI_API_SWITCH, "JSON error on loading object \"%s\" as %s in %s", "serdes_params", "object", m_config_file.c_str());
        return LA_STATUS_EINVAL;
    } else if (m_json_serdes_params != nullptr) {
        status = check_file_redirection(m_json_serdes_params, "file_name", "SerDes Parameters");
        la_return_on_error(status);
    }

    m_json_port_mix = json_object_get(m_json_dev, "port_mix");
    if ((m_json_port_mix != nullptr) && !json_is_object(m_json_port_mix)) {
        // if "port_mix" json key is not an object, return error.
        sai_log_error(
            SAI_API_SWITCH, "JSON error on loading object \"%s\" as %s in %s", "port_mix", "object", m_config_file.c_str());
        return LA_STATUS_EINVAL;
    } else if (m_json_port_mix != nullptr) {
        // check if there is a file redirection...
        status = check_file_redirection(m_json_port_mix, "file_name", "Port Mix Configurations");
        la_return_on_error(status);
    }

    json_t* j_board_type;
    JSON_GET_OBJ_PTR(j_board_type, "board-type", string, m_json_root, m_config_file.c_str());

    // check board-rev, can be string or integer
    json_t* j_board_rev = json_object_get(m_json_root, "board-rev");
    std::string board_rev_str = ".";
    if ((j_board_rev != nullptr) && (json_is_string(j_board_rev))) {
        board_rev_str += json_string_value(j_board_rev);
    } else if ((j_board_rev != nullptr) && (json_is_integer(j_board_rev))) {
        board_rev_str += std::to_string(json_integer_value(j_board_rev));
    } else if (j_board_rev == nullptr) {
        board_rev_str = "";
    } else {
        sai_log_error(SAI_API_SWITCH,
                      "JSON error on loading object \"%s\" as %s in %s",
                      "board-rev",
                      "string or integer",
                      m_config_file.c_str());
        return LA_STATUS_EINVAL;
    }

    m_json_dev_params = json_object_get(m_json_dev, "dev_params");
    if ((m_json_dev_params != nullptr) && (!json_is_object(m_json_dev_params))) {
        sai_log_error(
            SAI_API_SWITCH, "JSON error on loading object \"%s\" as %s in %s", "dev_params", "object", m_config_file.c_str());
        return LA_STATUS_EINVAL;
    }

    json_t* json_push_port_qos = json_object_get(m_json_dev, "push_port_qos_to_switch");
    if (json_push_port_qos != nullptr) {
        if (!json_is_boolean(json_push_port_qos)) {
            sai_log_error(SAI_API_SWITCH,
                          "JSON error on loading object \"%s\" as %s in %s",
                          "push_port_qos_to_switch",
                          "boolean",
                          m_config_file.c_str());
            return LA_STATUS_EINVAL;
        }

        m_sdev->m_push_port_qos_to_switch = json_boolean_value(json_push_port_qos);
    }

    sai_log_info(SAI_API_SWITCH,
                 "Board: %s%s, HW_Dev[%d] Dev_Type=\"%s\", Slice(%d)/IFG(%d)/Lane(%d)",
                 json_string_value(j_board_type),
                 board_rev_str.c_str(),
                 m_sdev->m_hw_device_id,
                 json_string_value(j_dev_type),
                 m_sdev->m_dev_params.slices_per_dev,
                 m_sdev->m_dev_params.ifgs_per_slice,
                 m_sdev->m_dev_params.serdes_per_ifg[0]);

    return LA_STATUS_SUCCESS;
}

// Load lane swap setting from j_ifg (which contains "swap" and "anlt_order" key of a IFG) to
static la_status
load_swap_settings(json_t* j_ifg, string key_name, la_uint32_t num_of_serdes_in_ifg, std::vector<la_uint32_t>& swap_vec)
{
    json_t* j_swap = json_object_get(j_ifg, key_name.c_str());

    // swap or ault_swap can be missing. Only apply them if they are valid.
    if (j_swap == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    // Check the array and vector size. They must match with num_of_serdes_in_ifg.
    if (!json_is_array(j_swap) || json_array_size(j_swap) != num_of_serdes_in_ifg) {
        sai_log_error(SAI_API_SWITCH,
                      "Board Configuration Loading failed. \"%s\" has to be integer array with size of %d.",
                      key_name.c_str(),
                      num_of_serdes_in_ifg);
        return LA_STATUS_EINVAL;
    }

    la_uint32_t swap_idx;
    json_t* swap_id;
    swap_vec.clear(); // clear the original array before apply the new cfg from json object.
    json_array_foreach(j_swap, swap_idx, swap_id)
    {
        swap_vec.push_back(json_integer_value(swap_id));
    }

    return LA_STATUS_SUCCESS;
}

static la_status
load_polarity_settings(json_t* j_ifg, string key_name, la_uint32_t num_of_serdes_in_ifg, std::vector<la_uint32_t>& polarity_vec)
{
    json_t* j_polarity = json_object_get(j_ifg, key_name.c_str());

    // polarity information can be missing in IFG.
    if (j_polarity == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    if (!json_is_array(j_polarity) || !(json_array_size(j_polarity) <= num_of_serdes_in_ifg)) {
        sai_log_error(SAI_API_SWITCH,
                      "Board Configuration Loading failed. \"%s\" has to be integer array with size < %d.",
                      key_name.c_str(),
                      num_of_serdes_in_ifg);

        return LA_STATUS_EINVAL;
    }

    la_uint32_t polar_idx;
    json_t* polar_id;
    polarity_vec.clear(); // clear the original array before apply the new cfg from json object.
    json_array_foreach(j_polarity, polar_idx, polar_id)
    {
        polarity_vec.push_back(json_integer_value(polar_id));
    }

    return LA_STATUS_SUCCESS;
}

// Load lane setting from configuration file.
la_status
config_parser::load_lane_settings()
{
    la_slice_id_t total_slice = m_sdev->m_dev_params.slices_per_dev;
    la_ifg_id_t total_ifg = m_sdev->m_dev_params.ifgs_per_slice;

    // Initialize settings lane swap and invertion for based on slice/ifg/serdes
    m_sdev->m_board_cfg.lanes = lsai_lane_settings_t();
    m_sdev->m_board_cfg.lanes.initialize(m_sdev->m_dev_params.serdes_per_ifg);

    if (m_json_ifg_swap_lists == nullptr) {
        // no ifg_swap_lists object is specified.
        sai_log_warn(SAI_API_SWITCH, "Warning: Missing Lane Settings (swap/inversion) Information. Use default settings.");
        return LA_STATUS_SUCCESS;
    }

    // loading the ifg_swap_lists
    la_uint32_t index = 0;
    json_t* j_ifg;
    json_t* j_slice_id;
    json_t* j_ifg_id;
    la_status status;

    json_array_foreach(m_json_ifg_swap_lists, index, j_ifg)
    {
        // a string for error messaging
        std::string current_ifg = "ifg_swap_lists[" + std::to_string(index) + "]";

        // Get the slice/ifg from the swap_list.
        JSON_GET_OBJ_PTR(j_slice_id, "slice", integer, j_ifg, current_ifg.c_str())
        JSON_GET_OBJ_PTR(j_ifg_id, "ifg", integer, j_ifg, current_ifg.c_str())

        // Check if "slice" and "ifg" are valid in cfg file.
        la_uint32_t slice_id = json_integer_value(j_slice_id);
        la_uint32_t ifg_id = json_integer_value(j_ifg_id);
        la_uint32_t ifg_idx = slice_id * total_ifg + ifg_id % total_ifg;

        if (ifg_idx >= (total_slice * total_ifg)) {
            sai_log_error(SAI_API_SWITCH,
                          "Board Configuration Loading failed. \"slice_id\"(%d) & \"ifg_id\"(%d) must be < (%d & %d).",
                          slice_id,
                          ifg_id,
                          total_slice,
                          total_ifg);
            return LA_STATUS_EINVAL;
        }

        auto num_of_serdes = m_sdev->m_dev_params.serdes_per_ifg[ifg_idx];

        // load swap, anlt_order, serdes_polarity_inverse_rx, and serdes_polarity_inverse_tx in swap_list
        status = load_swap_settings(j_ifg, "swap", num_of_serdes, m_sdev->m_board_cfg.lanes.ifg_swap[ifg_idx]);
        la_return_on_error(status, "Failed at ifg_idx(%d), num_of_serdes(%d), key(swap)", ifg_idx, num_of_serdes);

        status = load_swap_settings(j_ifg, "anlt_order", num_of_serdes, m_sdev->m_board_cfg.lanes.anlt_order[ifg_idx]);
        la_return_on_error(status, "Failed at ifg_idx(%d), num_of_serdes(%d), key(anlt_order)", ifg_idx, num_of_serdes);

        status = load_polarity_settings(
            j_ifg, "serdes_polarity_inverse_rx", num_of_serdes, m_sdev->m_board_cfg.lanes.rx_inverse[ifg_idx]);
        la_return_on_error(
            status, "Failed at ifg_idx(%d), num_of_serdes(%d), key(serdes_polarity_inverse_rx)", ifg_idx, num_of_serdes);

        status = load_polarity_settings(
            j_ifg, "serdes_polarity_inverse_tx", num_of_serdes, m_sdev->m_board_cfg.lanes.tx_inverse[ifg_idx]);
        la_return_on_error(
            status, "Failed at ifg_idx(%d), num_of_serdes(%d), key(serdes_polarity_inverse_tx)", ifg_idx, num_of_serdes);
    }

    // debugging log to print all lane settings
    for (uint ifg_idx = 0; ifg_idx < m_sdev->m_board_cfg.lanes.ifg_swap.size(); ifg_idx++) {
        std::string display_swap = "IFG[" + std::to_string(ifg_idx) + "] swap   - ";
        for (const auto& item : m_sdev->m_board_cfg.lanes.ifg_swap[ifg_idx]) {
            display_swap += std::to_string(item) + ", ";
        }

        std::string display_anlt = "IFG[" + std::to_string(ifg_idx) + "] anlt_order   - ";
        for (const auto& item : m_sdev->m_board_cfg.lanes.anlt_order[ifg_idx]) {
            display_anlt += std::to_string(item) + ", ";
        }

        std::string display_rxin = "IFG[" + std::to_string(ifg_idx) + "] rx_inv - ";
        for (const auto& item : m_sdev->m_board_cfg.lanes.rx_inverse[ifg_idx]) {
            display_rxin += std::to_string(item) + ", ";
        }

        std::string display_txin = "IFG[" + std::to_string(ifg_idx) + "] tx_inv - ";
        for (const auto& item : m_sdev->m_board_cfg.lanes.tx_inverse[ifg_idx]) {
            display_txin += std::to_string(item) + ", ";
        }

        sai_log_debug(SAI_API_SWITCH, "%s", display_swap.c_str());
        sai_log_debug(SAI_API_SWITCH, "%s", display_anlt.c_str());
        sai_log_debug(SAI_API_SWITCH, "%s", display_rxin.c_str());
        sai_log_debug(SAI_API_SWITCH, "%s", display_txin.c_str());
    }

    return LA_STATUS_SUCCESS;
}

// find the device property from json key and apply to la_device.
template <json_type j_type, typename T>
la_status
config_parser::update_device_property(const json_t* json_obj,
                                      const std::string& prop_name,
                                      silicon_one::la_device_property_e prop_e)
{
    json_t* j_prop = json_object_get(json_obj, prop_name.c_str());
    if (j_prop == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    // if j_prop->type is bool, it will be JSON_TRUE or JSON_FALSE, make it becomes JSON_TRUE for checking json type.
    json_type json_obj_type = json_is_boolean(j_prop) ? JSON_TRUE : json_typeof(j_prop);

    if (j_type != json_obj_type) {
        sai_log_error(SAI_API_SWITCH, "Device property(%s) is not a json_type(%d).", to_string(prop_e).c_str(), (int)j_type);
        return LA_STATUS_EINVAL;
    }

    T value;
    json_status_t jstatus = get_json_value(j_prop, value);
    la_return_on_json_error(jstatus, SAI_API_SWITCH, jstatus.message.c_str());
    la_status status = set_device_property(prop_e, value);
    la_return_on_error(status);
    sai_log_info(SAI_API_SWITCH, "Set device property(%s) to %s.", to_string(prop_e).c_str(), std::to_string(value).c_str());

    return LA_STATUS_SUCCESS;
}

la_status
config_parser::set_device_property(silicon_one::la_device_property_e prop_e, const bool& value)
{
    return m_sdev->m_dev->set_bool_property(prop_e, value);
}

la_status
config_parser::set_device_property(silicon_one::la_device_property_e prop_e, const int& value)
{
    return m_sdev->m_dev->set_int_property(prop_e, value);
}

la_status
config_parser::set_device_property(silicon_one::la_device_property_e prop_e, const std::string& value)
{
    return m_sdev->m_dev->set_string_property(prop_e, value);
}

// Get the value of json key from json object by given key string
template <json_type j_type, typename T>
la_status
config_parser::update_extended_property(const json_t* json_obj, const std::string& prop_name, lsai_extended_property_e ext_prop)
{
    json_t* j_prop = json_object_get(json_obj, prop_name.c_str());
    if (j_prop == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    // if j_prop->type is bool, it will be JSON_TRUE or JSON_FALSE, make it becomes JSON_TRUE for checking json type.
    json_type json_obj_type = json_is_boolean(j_prop) ? JSON_TRUE : json_typeof(j_prop);

    if (j_type != json_obj_type) {
        sai_log_error(
            SAI_API_SWITCH, "Extended property(%s) does not have a correct json_type(%d).", prop_name.c_str(), (int)j_type);
        return LA_STATUS_EINVAL;
    }

    T value;
    json_status_t jstatus = get_json_value(j_prop, value);
    la_return_on_json_error(jstatus, SAI_API_SWITCH, jstatus.message.c_str());
    // update extened property
    set_extended_property(ext_prop, value);
    sai_log_info(
        SAI_API_SWITCH, "Read Extended property(%s), value(%s).", to_string(ext_prop).c_str(), std::to_string(value).c_str());
    return LA_STATUS_SUCCESS;
}

void
config_parser::set_extended_property(lsai_extended_property_e ext_prop, const bool& value)
{
    m_sdev->m_ext_properties_bool[ext_prop] = value;
}

// load all properties (which are supported only) from json and apply to la_device.
la_status
config_parser::load_device_property()
{
    if (m_json_dev_props == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;
    status = update_device_property<JSON_TRUE, bool>(m_json_dev_props, "poll_msi", silicon_one::la_device_property_e::POLL_MSI);
    status = update_device_property<JSON_TRUE, bool>(
        m_json_dev_props, "process_interrupts", silicon_one::la_device_property_e::PROCESS_INTERRUPTS);
    status = update_device_property<JSON_TRUE, bool>(
        m_json_dev_props, "enable_mbist_repair", silicon_one::la_device_property_e::ENABLE_MBIST_REPAIR);
    status = update_device_property<JSON_TRUE, bool>(m_json_dev_props, "enable_hbm", silicon_one::la_device_property_e::ENABLE_HBM);
    status = update_device_property<JSON_TRUE, bool>(
        m_json_dev_props, "enable_hbm_route_extension", silicon_one::la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION);
    status = update_device_property<JSON_TRUE, bool>(m_json_dev_props,
                                                     "enable_hbm_route_extension_caching_mode",
                                                     silicon_one::la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION_CACHING_MODE);
    status = update_device_property<JSON_TRUE, bool>(
        m_json_dev_props, "enable_nsim_accurate_scale_model", silicon_one::la_device_property_e::ENABLE_NSIM_ACCURATE_SCALE_MODEL);
    status = update_device_property<JSON_INTEGER, int>(
        m_json_dev_props, "device_frequency", silicon_one::la_device_property_e::DEVICE_FREQUENCY);
    status = update_device_property<JSON_TRUE, bool>(
        m_json_dev_props, "enable_sensor_poll", silicon_one::la_device_property_e::ENABLE_SENSOR_POLL);

    status = update_device_property<JSON_TRUE, bool>(
        m_json_dev_props, "lc_type_2_4_t", silicon_one::la_device_property_e::LC_TYPE_2_4_T);
    status = update_device_property<JSON_TRUE, bool>(
        m_json_dev_props, "enable_serdes_low_power", silicon_one::la_device_property_e::ENABLE_SERDES_LOW_POWER);
    status = update_device_property<JSON_TRUE, bool>(
        m_json_dev_props, "enable_serdes_tx_slip", silicon_one::la_device_property_e::ENABLE_SERDES_TX_SLIP);
    status = update_device_property<JSON_TRUE, bool>(
        m_json_dev_props, "enable_serdes_tx_refresh", silicon_one::la_device_property_e::ENABLE_SERDES_TX_REFRESH);
    status = update_device_property<JSON_INTEGER, int>(
        m_json_dev_props, "mac_port_pcs_lock_time", silicon_one::la_device_property_e::MAC_PORT_PCS_LOCK_TIME);

    status = update_extended_property<JSON_TRUE, bool>(
        m_json_dev_props, "flow_cache_enable", lsai_extended_property_e::FLOW_CACHE_ENABLE);

    status = update_extended_property<JSON_TRUE, bool>(
        m_json_dev_props, "allow_smac_equals_dmac", lsai_extended_property_e::ALLOW_SMAC_EQUALS_DMAC);

    return LA_STATUS_SUCCESS;
}

// Read all serdes object (serdes key) from serdes setting file and create a list of serdes parameters for each serdes in
// unordered_map structure.
la_status
config_parser::build_serdes_param_map()
{
    if (m_json_serdes_params == nullptr) {
        // no serdes_params object is specified.
        sai_log_warn(SAI_API_SWITCH, "Warning: Missing SerDes Parameters Information in configuration file.");
        return LA_STATUS_SUCCESS;
    }

    m_sdev->m_board_cfg.serdes_params_map.clear();
    m_sdev->m_board_cfg.ifg_default_params_map.clear();
    m_sdev->m_board_cfg.serdes_key_counters = lsai_serdes_key_counters_t{};
    m_sdev->m_board_cfg.ifg_key_counters = lsai_serdes_key_counters_t{};

    // match json key format: eg."0,0,8,10,CHIP2CHIP" for serdes keys
    const std::regex serdes_key_regex("[0-9]+,[0-9]+,[0-9]+,[0-9]+,\\w*", std::regex_constants::optimize);
    const std::regex skip_word_regex("default_params|default_pll|VERSION", std::regex_constants::optimize);
    // match json key format: eg."2,1,25,OPTIC" for serdes keys in ifg group, ifg key
    const std::regex ifg_key_regex("[0-9]+,[0-9]+,[0-9]+,\\w*", std::regex_constants::optimize);

    const char* j_serdes_key_str;
    json_t* j_serdes;

    lsai_serdes_params_map_key_t serdes_key{};
    lsai_serdes_params_t serdes_param;
    la_status load_serdes_status;

    json_object_foreach(m_json_serdes_params, j_serdes_key_str, j_serdes)
    {
        std::string serdes_name = std::string(j_serdes_key_str);

        if (std::regex_match(serdes_name, skip_word_regex)) {
            // skipping this json key. It is just a serdes info but not serdes key.
            continue;
        }

        if (std::regex_match(serdes_name, serdes_key_regex)) {
            // load all params for this serdes_key
            // "0,0,8,50,CHIP2CHIP": {
            //     "slice_id": 0,
            //     "ifg_id": 0,
            //     "retimer": "0",
            //      ...
            //     "serdes_id": 8
            // },

            load_serdes_status = json_load_serdes_param(j_serdes, serdes_key, serdes_param, /*ifg_key*/ false);
            la_return_on_error(load_serdes_status);

            auto inserted = m_sdev->m_board_cfg.serdes_params_map.insert({serdes_key, serdes_param});
            if (!inserted.second) {
                m_sdev->m_board_cfg.serdes_key_counters.error_cnt++;
            } else {
                m_sdev->m_board_cfg.serdes_key_counters.inc(serdes_key.media_type);
            }
        } else if (std::regex_match(serdes_name, ifg_key_regex) && json_is_array(j_serdes)) {
            // This ifg_key is an array where serdes is defined. This is basically a compressed serdes keys.
            // "0,0,50,CHIP2CHIP":[        // <- j_serdes is pointing here.
            // {
            // "serdes":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
            // "slice_id": 0,
            // "ifg_id": 0,
            // ...
            // "RX_AFE_TRIM": 2,
            // "RX_AC_COUPLING_BYPASS": 1
            // },
            // {
            // "serdes":[16,17,18,19,20,21,22,23],
            // "slice_id": 0,
            // "ifg_id": 0,
            // ...
            // "RX_AC_COUPLING_BYPASS": 1
            // }
            // ]

            json_t* serdes_iter; // iterator of each group of serdes with the same value
            la_uint32_t idx = 0;
            json_array_foreach(j_serdes, idx, serdes_iter)
            {
                std::vector<lsai_serdes_params_map_key_t> serdes_keys_vec;
                load_serdes_status = json_load_serdes_param_array(serdes_iter, serdes_keys_vec, serdes_param);
                la_return_on_error(load_serdes_status);

                for (auto serdes_key : serdes_keys_vec) {
                    auto inserted = m_sdev->m_board_cfg.serdes_params_map.insert({serdes_key, serdes_param});
                    if (!inserted.second) {
                        m_sdev->m_board_cfg.serdes_key_counters.error_cnt++;
                    } else {
                        m_sdev->m_board_cfg.serdes_key_counters.inc(serdes_key.media_type);
                    }
                }
            }
        } else if (std::regex_match(serdes_name, ifg_key_regex)) {
            // load all params for this ifg key
            // "0,0,50,CHIP2CHIP": {
            //     "slice_id": 0,
            //     "ifg_id": 0,
            //     "speed": 50,
            //     ...
            //     "RX_AC_COUPLING_BYPASS": 1
            // },

            load_serdes_status = json_load_serdes_param(j_serdes, serdes_key, serdes_param, /*ifg_key*/ true);
            la_return_on_error(load_serdes_status);

            auto inserted = m_sdev->m_board_cfg.ifg_default_params_map.insert({serdes_key, serdes_param});
            if (!inserted.second) {
                m_sdev->m_board_cfg.ifg_key_counters.error_cnt++;
            } else {
                m_sdev->m_board_cfg.ifg_key_counters.inc(serdes_key.media_type);
            }
        } else {
            sai_log_warn(SAI_API_SWITCH, "Warning: Skip json key \"%s\". (not a serdes key).", j_serdes_key_str);
        }
    }

    for (const auto& serdes : m_sdev->m_board_cfg.serdes_params_map) {
        sai_log_debug(SAI_API_SWITCH,
                      "%s = %d,%d,%d,%d,%d",
                      "serdes_key",
                      serdes.first.slice_id,
                      serdes.first.ifg_id,
                      serdes.first.serdes_id,
                      serdes.first.serdes_speed,
                      serdes.first.media_type);
        for (const auto& param : serdes.second) {
            sai_log_debug(SAI_API_SWITCH, "%s", to_string(param).c_str());
        }
    }

    for (const auto& serdes : m_sdev->m_board_cfg.ifg_default_params_map) {
        sai_log_debug(SAI_API_SWITCH,
                      "%s = %d,%d,%d,%d,%d",
                      "ifg_key",
                      serdes.first.slice_id,
                      serdes.first.ifg_id,
                      serdes.first.serdes_id,
                      serdes.first.serdes_speed,
                      serdes.first.media_type);
        for (const auto& param : serdes.second) {
            sai_log_debug(SAI_API_SWITCH, "%s", to_string(param).c_str());
        }
    }

    if (m_sdev->m_board_cfg.serdes_key_counters.total() == 0 && m_sdev->m_board_cfg.ifg_key_counters.total() == 0) {
        sai_log_warn(SAI_API_SWITCH, "Warning: SerDes Property Map is empty! Please check SerDes configuration file.");
    } else {
        sai_log_info(SAI_API_SWITCH,
                     "SerDes Property Map was built. Serdes Properties Counts: %s",
                     to_string(m_sdev->m_board_cfg.serdes_key_counters).c_str());

        sai_log_info(SAI_API_SWITCH,
                     "SerDes Property Map was built. IFG Properties Counts: %s",
                     to_string(m_sdev->m_board_cfg.ifg_key_counters).c_str());
    }

    if (m_sdev->m_board_cfg.serdes_key_counters.error_cnt) {
        sai_log_error(
            SAI_API_SWITCH,
            "Error: There are %d numbers of duplicated insert to SerDes Property Map. (Duplicated properties are discarded.)",
            m_sdev->m_board_cfg.serdes_key_counters.error_cnt);

        return LA_STATUS_EINVAL;
    }

    if (m_sdev->m_board_cfg.ifg_key_counters.error_cnt) {
        sai_log_error(SAI_API_SWITCH,
                      "Error: There are %d numbers of duplicated IFG SerDes Properties. (Duplicated properties are discarded.)",
                      m_sdev->m_board_cfg.ifg_key_counters.error_cnt);

        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

// Setup default pll and serdes parameters. If there is missing parameter of a serdes lane, default parameters will be applied.
la_status
config_parser::load_default_serdes_param()
{
    if (m_json_serdes_params == nullptr) {
        sai_log_warn(SAI_API_SWITCH, "Warning: Missing \"serdes_params\" json object.");
    }

    m_sdev->m_board_cfg.serdes_default_pll.clear();

    json_t* json_default_pll = json_object_get(m_json_serdes_params, "default_pll");
    if (json_default_pll == nullptr) {
        sai_log_warn(SAI_API_SWITCH,
                     "Warning: Missing \"default_pll\". Use %s SDK default values.",
                     m_sdev->get_hw_device_type_str().c_str());
    } else {
        // load default pll params
        const char* j_obj_name;
        json_t* j_obj_item;
        lsai_serdes_params_t serdes_param;
        json_object_foreach(json_default_pll, j_obj_name, j_obj_item)
        {
            json_get_serdes_prop((std::string)j_obj_name, json_integer_value(j_obj_item), serdes_param);
            m_sdev->m_board_cfg.serdes_default_pll.insert(
                std::end(m_sdev->m_board_cfg.serdes_default_pll), std::begin(serdes_param), std::end(serdes_param));
        }
    }

    m_sdev->m_board_cfg.serdes_default_params.clear();

    json_t* json_default_params = json_object_get(m_json_serdes_params, "default_params");
    if (json_default_params == nullptr) {
        sai_log_warn(SAI_API_SWITCH,
                     "Warning: Missing \"default_params\". Use %s SDK default values.",
                     m_sdev->get_hw_device_type_str().c_str());
    } else {
        // load default serdes params
        const char* j_obj_name;
        json_t* j_obj_item;
        lsai_serdes_params_t serdes_param;
        json_object_foreach(json_default_params, j_obj_name, j_obj_item)
        {
            json_get_serdes_prop((std::string)j_obj_name, json_integer_value(j_obj_item), serdes_param);
            m_sdev->m_board_cfg.serdes_default_params.insert(
                std::end(m_sdev->m_board_cfg.serdes_default_params), std::begin(serdes_param), std::end(serdes_param));
        }
    }

    // Debugging log: Print all default PLL/SerDes parameters
    sai_log_debug(SAI_API_SWITCH, "default_pll = ");
    for (const auto& pll_prop : m_sdev->m_board_cfg.serdes_default_pll) {
        sai_log_debug(SAI_API_SWITCH, "%s", to_string(pll_prop).c_str());
    }
    sai_log_debug(SAI_API_SWITCH, "default_params = ");
    for (const auto& srd_prop : m_sdev->m_board_cfg.serdes_default_params) {
        sai_log_debug(SAI_API_SWITCH, "%s", to_string(srd_prop).c_str());
    }

    return LA_STATUS_SUCCESS;
}

// Read a json serdes object, create a vector of all serdes parameters for this serdes, and create a serdes_key of this serdes.
la_status
config_parser::json_load_serdes_param(json_t* json_serdes,
                                      lsai_serdes_params_map_key_t& serdes_key,
                                      lsai_serdes_params_t& serdes_params,
                                      bool ifg_key)
{
    if (json_serdes == nullptr) {
        return LA_STATUS_EINVAL;
    }

    serdes_params.clear();

    // create serdes_key from json serdes configuration format
    json_t* j_serdes_speed;
    json_t* j_serdes_id;
    json_t* j_slice_id;
    json_t* j_ifg_id;
    json_t* j_media_type;

    JSON_GET_OBJ_PTR(j_serdes_speed, "speed", integer, json_serdes, json_key_name(json_serdes));
    JSON_GET_OBJ_PTR(j_slice_id, "slice_id", integer, json_serdes, json_key_name(json_serdes));
    JSON_GET_OBJ_PTR(j_ifg_id, "ifg_id", integer, json_serdes, json_key_name(json_serdes));
    json_get_media_type_obj(j_media_type, json_serdes);

    serdes_key.serdes_speed = json_integer_value(j_serdes_speed);
    serdes_key.slice_id = json_integer_value(j_slice_id);
    serdes_key.ifg_id = json_integer_value(j_ifg_id);
    if (!get_media_type_value(j_media_type, serdes_key.media_type)) {
        // invalid media_type seen in json file.
        return LA_STATUS_EINVAL;
    }

    if (ifg_key) {
        // When this is a ifg key...
        serdes_key.serdes_id = 0;
    } else {
        JSON_GET_OBJ_PTR(j_serdes_id, "serdes_id", integer, json_serdes, json_key_name(json_serdes));
        serdes_key.serdes_id = json_integer_value(j_serdes_id);
    }

    lsai_serdes_params_t single_param;
    const char* j_param_name;
    json_t* j_param;

    json_object_foreach(json_serdes, j_param_name, j_param)
    {
        json_get_serdes_prop((std::string)j_param_name, json_integer_value(j_param), single_param);
        serdes_params.insert(std::end(serdes_params), std::begin(single_param), std::end(single_param));
    }

    return LA_STATUS_SUCCESS;
}

// Read a json serdes object which contains a vector of serdes shared same set of serdes parameters.
// create a vector of all serdes parameters (shared) for vector of serdes ids and a vector of serdes_key.
la_status
config_parser::json_load_serdes_param_array(json_t* json_serdes,
                                            std::vector<lsai_serdes_params_map_key_t>& serdes_keys_vec,
                                            lsai_serdes_params_t& shared_serdes_params)
{
    // {        <- json_serdes is pointing here now.
    // "serdes":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
    // "slice_id": 0,
    // "ifg_id": 0,
    // "speed": 50,
    // "module_type": "CHIP2CHIP",
    // "TX_LUT_MODE": 0,
    // ...
    // "RX_AFE_TRIM": 2,
    // "RX_AC_COUPLING_BYPASS": 1
    // },

    if (json_serdes == nullptr) {
        return LA_STATUS_EINVAL;
    }

    shared_serdes_params.clear();
    serdes_keys_vec.clear();

    lsai_serdes_params_map_key_t serdes_key;

    // create serdes_key from json serdes configuration format
    json_t* j_serdes_speed;
    json_t* j_serdes_id_vec;
    json_t* j_slice_id;
    json_t* j_ifg_id;
    json_t* j_media_type;

    JSON_GET_OBJ_PTR(j_serdes_speed, "speed", integer, json_serdes, json_key_name(json_serdes));
    JSON_GET_OBJ_PTR(j_slice_id, "slice_id", integer, json_serdes, json_key_name(json_serdes));
    JSON_GET_OBJ_PTR(j_ifg_id, "ifg_id", integer, json_serdes, json_key_name(json_serdes));
    json_get_media_type_obj(j_media_type, json_serdes);

    serdes_key.serdes_speed = json_integer_value(j_serdes_speed);
    serdes_key.slice_id = json_integer_value(j_slice_id);
    serdes_key.ifg_id = json_integer_value(j_ifg_id);
    if (!get_media_type_value(j_media_type, serdes_key.media_type)) {
        // invalid media_type seen in json file.
        return LA_STATUS_EINVAL;
    }

    // Check if "serdes" is one of the key.
    j_serdes_id_vec = json_object_get(json_serdes, "serdes");
    if (j_serdes_id_vec == nullptr) {
        // if "serdes" is missing, all serdes in this ifg has same parameters.
        uint32_t ifg_idx = serdes_key.slice_id * 2 + serdes_key.ifg_id;
        for (serdes_key.serdes_id = 0; serdes_key.serdes_id < m_sdev->m_dev_params.serdes_per_ifg[ifg_idx];
             serdes_key.serdes_id++) {
            serdes_keys_vec.push_back(serdes_key);
        }
    } else {
        // serdes must be an array, and push all into serdes_keys_vec
        JSON_GET_OBJ_PTR(j_serdes_id_vec, "serdes", array, json_serdes, json_key_name(json_serdes));
        la_uint32_t vec_idx;
        json_t* serdes_id;
        json_array_foreach(j_serdes_id_vec, vec_idx, serdes_id)
        {
            if (!json_is_integer(serdes_id)) {
                return LA_STATUS_EINVAL;
            }
            serdes_key.serdes_id = static_cast<uint32_t>(json_integer_value(serdes_id));
            serdes_keys_vec.push_back(serdes_key);
        }
    }

    lsai_serdes_params_t single_param;
    const char* j_param_name;
    json_t* j_param;

    json_object_foreach(json_serdes, j_param_name, j_param)
    {
        json_get_serdes_prop((std::string)j_param_name, json_integer_value(j_param), single_param);
        shared_serdes_params.insert(std::end(shared_serdes_params), std::begin(single_param), std::end(single_param));
    }

    return LA_STATUS_SUCCESS;
}

// Read a single serdes parameter and construct its properties list by given a json object of the serdes parameter
la_status
config_parser::json_get_serdes_prop(json_t* json_prop_key, lsai_serdes_params_t& param)
{
    if (json_prop_key == nullptr) {
        // An empty json object pointer is passed into function, return not found "param" value.
        param.clear();
        return LA_STATUS_ENOTFOUND;
    }

    return json_get_serdes_prop(json_key_name(json_prop_key), json_integer_value(json_prop_key), param);
}

// Construct a single serdes parameter properties list by given a name and value of a serdes parameter
la_status
config_parser::json_get_serdes_prop(const std::string& prop_key, const int& prop_value, lsai_serdes_params_t& param)
{
    // clear the param
    param.clear();

    std::regex skip_regex("slice_id|speed|serdes_id|serdes|port|media_type|module_type|line_host|ifg_id|retimer");
    if (std::regex_match(prop_key, skip_regex)) {
        // skipping this json key. It is just a serdes info but not serdes parameter.
        return LA_STATUS_SUCCESS;
    }

    // serdes_prop_defines is serdes properties definition and declarated in sai_config_parser.h
    auto found_iter = serdes_prop_defines.find(prop_key);

    if (found_iter == serdes_prop_defines.end()) {
        // Not found
        sai_log_warn(SAI_API_SWITCH,
                     "Warning: SerDes parameter (\"%s\" = %d) found in file but it is not yet supported.",
                     prop_key.c_str(),
                     prop_value);
        return LA_STATUS_ENOTIMPLEMENTED;
    } else {
        for (const auto& serdes_prop : found_iter->second) {
            param.push_back({serdes_prop.stage, serdes_prop.parameter, serdes_prop.mode, prop_value});
        }
    }

    return LA_STATUS_SUCCESS;
}

// Search serdes_key in serdes_params map and return all serdes parameters setting of the key.
la_status
sai_json_find_serdes_params(const lsai_serdes_params_map_t& serdes_params_map,
                            const lsai_serdes_params_map_key_t& serdes_key,
                            lsai_serdes_params_t& serdes_params)
{
    serdes_params.clear();

    auto found_iter = serdes_params_map.find(serdes_key);

    if (found_iter == serdes_params_map.end()) {
        // serdes_key not found. Return with error.
        return LA_STATUS_ENOTFOUND;
    } else {
        for (const auto& serdes_prop : found_iter->second) {
            serdes_params.push_back(serdes_prop);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
config_parser::load_port_mix()
{
    if (m_json_port_mix == nullptr) {
        sai_log_debug(SAI_API_PORT, "Missing \"port_mix\" Information in configuration file.");
        return LA_STATUS_SUCCESS;
    }

    // load all groups of port configuration and build a map database for ports initialization
    // json file example:
    // {    # <-- root of m_json_port_mix
    // "traffic_gen_port": [        # <- group of ports, beginning of j_port_group iterator,
    //     {
    //         "pif": 120,      # <- port configuration
    //         ...
    //     }
    // ],
    // "loopback_ports":        # <- another group of ports
    // [
    //     {"pif": ...}, {"pif": ...}, ...
    // ]
    //      ... more groups of ports

    m_sdev->m_port_mix_map.clear();

    la_status load_cfg_status;

    const std::regex init_key_regex("init|init_switch", std::regex_constants::icase);

    const char* j_port_group_key_str;
    json_t* j_port_group;

    json_object_foreach(m_json_port_mix, j_port_group_key_str, j_port_group)
    {
        std::string port_group_name = std::string(j_port_group_key_str);

        if (std::regex_match(port_group_name, init_key_regex)) {
            // if this is a init key, load the key and goto next key.
            load_cfg_status = json_load_init_switch(j_port_group);
            la_return_on_error(load_cfg_status);
            continue;
        }

        lsai_port_grp_t port_grp;

        // load ports configuration for this port_group_name
        load_cfg_status = json_load_port_group(j_port_group, port_grp);
        la_return_on_error(load_cfg_status);

        auto inserted = m_sdev->m_port_mix_map.insert({port_group_name, port_grp});
        if (!inserted.second) {
            sai_log_error(SAI_API_SWITCH, "Fail to insert \"%s\" to m_port_mix_map.", j_port_group_key_str);
            return LA_STATUS_EINVAL;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
config_parser::load_acl_key_profiles()
{
    json_error_t j_error;
    json_t* acl_key_profile_json_root;
    json_t* j_acl_key_profiles;
    json_t* j_acl_profile;
    json_t* j_profile_name;
    json_t* j_sai_attributes;
    std::unordered_map<string, sai_acl_table_attr_t> sai_acl_table_attr_field_umap;
    sai_status_t status;
    struct acl_dir_t {
        std::string dir_name;
        la_acl_direction_e dir_type;
    };
    std::vector<acl_dir_t> acl_dir_list = {{"ingress", la_acl_direction_e::INGRESS}, {"egress", la_acl_direction_e::EGRESS}};

    // If we find UDK ACL profiles already setup, do not
    // process the ACL key profile config file.
    const char* acl_key_profile_file = g_sai_service_method.profile_get_value(0, SAI_ACL_KEY_PROFILE_FILE);
    if (m_sdev->m_acl_handler->m_acl_udk.is_udk_acl_profiles()) {
        if (acl_key_profile_file != nullptr) {
            sai_log_warn(SAI_API_SWITCH,
                         "UDK ACL profiles found, "
                         "skipping parsing of ACL key profile config file %s",
                         acl_key_profile_file);
        }
        return LA_STATUS_SUCCESS;
    }

    if (acl_key_profile_file == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    status = m_sdev->m_acl_handler->m_acl_udk.create_sai_acl_table_attr_field_umap(sai_acl_table_attr_field_umap);
    la_return_on_error(to_la_status(status));

    sai_log_info(SAI_API_SWITCH, "Processing ACL_KEY_PROFILE %s", acl_key_profile_file);
    acl_key_profile_json_root = json_load_file(acl_key_profile_file, 0, &j_error);
    if (acl_key_profile_json_root == nullptr) {
        sai_log_error(SAI_API_SWITCH, "Loading %s failed %d: %s", acl_key_profile_file, j_error.line, j_error.text);
        return LA_STATUS_ENOTFOUND;
    }

    JSON_GET_OBJ_PTR(j_acl_key_profiles, "acl_key_profiles", array, acl_key_profile_json_root, acl_key_profile_file);
    if (j_acl_key_profiles == nullptr) {
        sai_log_error(SAI_API_SWITCH, "Missing acl_key_profiles information in %s.", acl_key_profile_file);
        return LA_STATUS_ENOTFOUND;
    }

    // Loop thru each direction type for ACL key profiles (ingress, egress)
    json_t* j_acl_dir;
    la_uint32_t dir_idx = 0;
    json_array_foreach(j_acl_key_profiles, dir_idx, j_acl_dir)
    {
        for (auto acl_dir : acl_dir_list) {
            std::set<std::set<uint32_t>> acl_key_profile_sets = {};
            json_t* j_dir_type = json_object_get(j_acl_dir, acl_dir.dir_name.c_str());
            if (j_dir_type) {
                la_uint32_t prof_idx = 0;
                // Loop thru each ACL key profile name (ipv4, ipv6, mirror, ...)
                json_array_foreach(j_dir_type, prof_idx, j_acl_profile)
                {
                    JSON_GET_OBJ_PTR(j_profile_name, "profile_name", string, j_acl_profile, json_key_name(j_acl_profile));
                    std::string profile_name = std::string(json_string_value(j_profile_name));
                    JSON_GET_OBJ_PTR(j_sai_attributes, "sai_attributes", array, j_acl_profile, json_key_name(j_acl_profile));
                    la_uint32_t attr_idx;
                    json_t* j_attr_name;
                    std::set<uint32_t> acl_key_profile{};
                    json_array_foreach(j_sai_attributes, attr_idx, j_attr_name)
                    {
                        std::string attr_name;
                        attr_name = std::string(json_string_value(j_attr_name));
                        auto item = sai_acl_table_attr_field_umap.find(attr_name);
                        if (item == sai_acl_table_attr_field_umap.end()) {
                            sai_log_error(SAI_API_SWITCH,
                                          "SAI ACL profile %s attribute %s not found",
                                          profile_name.c_str(),
                                          attr_name.c_str());
                            return LA_STATUS_ENOTFOUND;
                        }
                        acl_key_profile.insert(item->second);
                    }
                    sai_log_info(SAI_API_SWITCH, "Processed ACL key profile %s", profile_name.c_str());
                    m_sdev->m_acl_handler->m_acl_udk.set_acl_key_profile_set(acl_key_profile_sets, acl_key_profile);
                }

                status = m_sdev->m_acl_handler->m_acl_udk.process_acl_key_profiles(acl_dir.dir_type, acl_key_profile_sets);
                la_return_on_error(to_la_status(status), "Failed to process ACL key profiles for %s", acl_dir.dir_name.c_str());
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

// load port group (all port configurations in group) from json object
la_status
config_parser::json_load_port_group(json_t* j_port_grp, lsai_port_grp_t& port_grp)
{
    // load all port configuration under a "group" to lsai_port_grp_t structure (vector of lsai_port_cfg_t).
    // json file example:
    // "loopback_ports":    # <- j_port_grp is pointing at this group now
    // [
    //     {                # <- iterator: j_port_cfg_itr; (single configurations set of ports)
    //         "pif": [52, 60, 72, 76, 80, 84, 96, 100, 104, 108],
    //         ... (configurations of these PIFs)
    //     },
    //     {
    //         "pif": 124,
    //         ... (configurations of this PIF, 124)
    //     },
    //         ... other port configurations
    // ],
    // ... (other groups)

    la_status load_status;

    port_grp.clear();

    json_t* j_port_cfg_itr;
    uint32_t cfg_idx;
    json_array_foreach(j_port_grp, cfg_idx, j_port_cfg_itr)
    {
        // build the port configuration/attribute vector for each PIF...

        lsai_port_cfg_t port_cfg_set; // single configuration set of ports
        uint32_t lanes_count;         // lanes count of these ports

        load_status = json_load_port_cfg(j_port_cfg_itr, port_cfg_set, lanes_count);
        la_return_on_error(load_status);

        for (auto pif : port_cfg_set.m_pif_lanes) {
            // build a port_configuration structure for each pif
            lsai_port_cfg_t single_port_cfg = lsai_port_cfg_t(pif, lanes_count, port_cfg_set.m_attrs); // copy shared configurations

            // push the full set of attributes of this pif to the group.
            port_grp.push_back(single_port_cfg);
        }
    }

    return LA_STATUS_SUCCESS;
}

// template function to find the attribute value in map and return the value in its data type.
template <sai_port_attr_t attr_id, typename sai_port_enum_t>
static bool
json_string_to_sai_port_attr_enum(const std::map<std::string, sai_port_enum_t>& enum_map,
                                  const json_t* j_attr,
                                  sai_attribute_value_t& value,
                                  uint32_t& err_cnt)
{
    if (!json_is_string(j_attr)) {
        const char* j_attr_key_str;
        json_t* j_temp = const_cast<json_t*>(j_attr);
        j_attr_key_str = json_key_name(j_temp);
        sai_log_error(SAI_API_SWITCH, "JSON error: the value of \"%s\" is not string.", j_attr_key_str);
        return false;
    }

    std::string str_value = std::string(json_string_value(j_attr));
    // convert to lower case
    std::string lower_value = str_value;
    std::transform(lower_value.begin(), lower_value.end(), lower_value.begin(), [](unsigned char c) { return std::tolower(c); });

    auto iter = enum_map.find(lower_value);

    if (iter == enum_map.end()) {
        sai_log_error(SAI_API_SWITCH, "Fail to map value(%s) to type(%s).", str_value.c_str(), typeid(iter->second).name());
        err_cnt++;
        return false;
    }

    sai_port_enum_t rslt = iter->second;
    sai_port_attr_t_s32<attr_id, sai_port_enum_t>::set(value, rslt);
    return true;
}

// clang-format off
// Mapping table from json key name to sai_attribute_t. These are the currently supported attributes.
// Also, these are the default
static const std::map<std::string, sai_attribute_t> sai_port_attribute_map{
    // skip pif and pif_counts, they will be specially handler in json_load_port_group.
    // {"pif",         {sai_port_attr_t::SAI_PORT_ATTR_HW_LANE_LIST,                sai_attribute_value_t{.u32=0}}},
    // {"pif_counts",  {sai_port_attr_t::SAI_PORT_ATTR_HW_LANE_LIST,                sai_attribute_value_t{.u32=0}}},
    {"speed",       {sai_port_attr_t::SAI_PORT_ATTR_SPEED,                      sai_attribute_value_t{.u32=0}}},
    {"mac_lpbk",    {sai_port_attr_t::SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE,     sai_attribute_value_t{.s32=SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE}}},
    {"fc",          {sai_port_attr_t::SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE,   sai_attribute_value_t{.s32=SAI_PORT_FLOW_CONTROL_MODE_DISABLE}}},
    {"pfc_mode",    {sai_port_attr_t::SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE, sai_attribute_value_t{.s32=SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_COMBINED}}},
    {"pfc",         {sai_port_attr_t::SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL,      sai_attribute_value_t{.u8=0}}},
    {"fec",         {sai_port_attr_t::SAI_PORT_ATTR_FEC_MODE,                   sai_attribute_value_t{.s32=SAI_PORT_FEC_MODE_NONE}}},
    {"an",          {sai_port_attr_t::SAI_PORT_ATTR_AUTO_NEG_MODE,              sai_attribute_value_t{.booldata=false}}},
    {"admin_state", {sai_port_attr_t::SAI_PORT_ATTR_ADMIN_STATE,                sai_attribute_value_t{.booldata=false}}},
    {"mtu_size",    {sai_port_attr_t::SAI_PORT_ATTR_MTU,                        sai_attribute_value_t{.u32=SAI_DEFAULT_MTU_SIZE}}},
    {"media_type",  {sai_port_attr_t::SAI_PORT_ATTR_MEDIA_TYPE,                 sai_attribute_value_t{.s32=SAI_PORT_MEDIA_TYPE_NOT_PRESENT}}}
};

// Mapping table from json string value to sai_port_internal_loopback_mode_t
static const std::map<std::string, sai_port_internal_loopback_mode_t> sai_port_lpbk_str_map{
    {"mac", SAI_PORT_INTERNAL_LOOPBACK_MODE_MAC},
    {"phy", SAI_PORT_INTERNAL_LOOPBACK_MODE_PHY},
    {"none", SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE}
};

// Mapping table from json string value to sai_port_flow_control_mode_t
static const std::map<std::string, sai_port_flow_control_mode_t> sai_port_fc_str_map{
    {"enable", SAI_PORT_FLOW_CONTROL_MODE_BOTH_ENABLE},
    {"tx_only", SAI_PORT_FLOW_CONTROL_MODE_TX_ONLY},
    {"rx_only", SAI_PORT_FLOW_CONTROL_MODE_RX_ONLY},
    {"disable", SAI_PORT_FLOW_CONTROL_MODE_DISABLE}
};

// Mapping table from json string value to sai_port_priority_flow_control_mode_t
static const std::map<std::string, sai_port_priority_flow_control_mode_t> sai_port_pfc_str_map{
    {"combined", SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_COMBINED},
    {"separate", SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_SEPARATE}
};

// Mapping table from json string value to sai_port_fec_mode_t
static const std::map<std::string, sai_port_fec_mode_t> sai_port_fec_str_map{
    {"rs", SAI_PORT_FEC_MODE_RS},
    {"fc", SAI_PORT_FEC_MODE_FC},
    {"none", SAI_PORT_FEC_MODE_NONE}
};

// Mapping table from json string value to sai_port_media_type_t
static const std::map<std::string, sai_port_media_type_t> sai_port_media_type_str_map{
    {"copper", SAI_PORT_MEDIA_TYPE_COPPER},
    {"fiber", SAI_PORT_MEDIA_TYPE_FIBER},
    {"optic", SAI_PORT_MEDIA_TYPE_FIBER},
    {"unknown", SAI_PORT_MEDIA_TYPE_UNKNOWN},
    {"not_present", SAI_PORT_MEDIA_TYPE_NOT_PRESENT},
    {"", SAI_PORT_MEDIA_TYPE_NOT_PRESENT},
    {"none", SAI_PORT_MEDIA_TYPE_NOT_PRESENT}
};
// clang-format on

// load port config (single port) from json object
la_status
config_parser::json_load_port_cfg(json_t* j_port_cfg, lsai_port_cfg_t& port_cfg, uint32_t& lanes_count)
{
    // load this set of port configurations and save it as "lsai_port_cfg_t" which is a sai_attribute_t vector.
    // PIF of this set of configurations can be a array of PIFs or an integer of a single PIF.
    // json file example:
    //  ... within a group.
    //     {        # <- json_t pointer, j_port_cfg;
    //         "pif": [52, 60, 72, 76, 80, 84, 96, 100, 104, 108],      # <- return "pif" as port_cfg.m_pif_lanes
    //         "Description": "These are the serdes loopback ports. For external loopback, use loopback cables and set
    //         mac_lpbk=NONE.",
    //         "pif_counts": 4,         # <- return "pif_counts" of lanes_count
    //         "speed": 100000,         # <- return all other configurations as port_cfg in sai_attribute_t form.
    //         "fc": "disable",
    //         "pfc_mode": "combined",  # combined (default) | separate
    //         "pfc": "0x33",           # applicable on if pfc_mode = combined
    //         "fec": "RS",
    //         "mac_lpbk": "PHY",
    //         "mtu_size": 9600,
    //         "an": false
    //     },
    //  ... other port configuration set.

    // set the return value for port_cfg.m_pif_lanes
    port_cfg.m_pif_lanes.clear();
    json_t* j_pif = json_object_get(j_port_cfg, "pif");
    if (j_pif == nullptr) {
        sai_log_error(SAI_API_PORT, "JSON error at loading \"pif\" in port configuration.");
        return LA_STATUS_EINVAL;
    }

    uint32_t pif;
    if (json_is_array(j_pif)) {
        la_uint32_t pif_idx;
        json_t* pif_iter;
        json_array_foreach(j_pif, pif_idx, pif_iter)
        {
            if (!json_is_hex(pif_iter)) {
                sai_log_error(SAI_API_SWITCH, "JSON error \"pif\" must be an array of integers or strings.");
                return LA_STATUS_EINVAL;
            }
            pif = static_cast<uint32_t>(json_hex_value(pif_iter));
            port_cfg.m_pif_lanes.push_back(pif);
        }
    } else {
        if (!json_is_hex(j_pif)) {
            sai_log_error(SAI_API_SWITCH, "JSON error \"pif\" must be an integer, strings or array of integers/strings.");
            return LA_STATUS_EINVAL;
        }
        pif = static_cast<uint32_t>(json_hex_value(j_pif));
        port_cfg.m_pif_lanes.push_back(pif);
    }

    // set the return value for lanes_count.
    json_t* j_pif_counts;
    JSON_GET_OBJ_PTR(j_pif_counts, "pif_counts", integer, j_port_cfg, "json_load_port_cfg");
    lanes_count = json_integer_value(j_pif_counts);

    std::map<std::string, sai_attribute_t> port_cfg_map; // attribute vector of single port configuration

    uint32_t err_cnt = 0;
    const char* j_attr_key_str;
    json_t* j_attr;
    json_object_foreach(j_port_cfg, j_attr_key_str, j_attr)
    {
        // read each configuration and save them into the port_cfg_map

        // find if configuration is supported in sai_port_attribute_map...
        std::string attr_name = std::string(j_attr_key_str); // name of attribute in string
        auto iter = sai_port_attribute_map.find(attr_name);

        if (iter != sai_port_attribute_map.end()) {
            // if supported/found ...

            // create the attribute in port_cfg_map
            port_cfg_map[attr_name] = iter->second;

            switch ((sai_port_attr_t)iter->second.id) {
            // set the value based on the data type.
            case SAI_PORT_ATTR_SPEED: {
                set_attr_value(SAI_PORT_ATTR_SPEED, port_cfg_map[attr_name].value, (uint32_t)json_integer_value(j_attr));
            } break;
            case SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE: {
                json_string_to_sai_port_attr_enum<SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE>(
                    sai_port_lpbk_str_map, j_attr, port_cfg_map[attr_name].value, err_cnt);
            } break;
            case SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE: {
                json_string_to_sai_port_attr_enum<SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE>(
                    sai_port_fc_str_map, j_attr, port_cfg_map[attr_name].value, err_cnt);
            } break;
            case SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE: {
                json_string_to_sai_port_attr_enum<SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE>(
                    sai_port_pfc_str_map, j_attr, port_cfg_map[attr_name].value, err_cnt);
            } break;
            case SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL: {
                set_attr_value(SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, port_cfg_map[attr_name].value, (uint8_t)json_hex_value(j_attr));
            } break;
            case SAI_PORT_ATTR_FEC_MODE: {
                json_string_to_sai_port_attr_enum<SAI_PORT_ATTR_FEC_MODE>(
                    sai_port_fec_str_map, j_attr, port_cfg_map[attr_name].value, err_cnt);
            } break;
            case SAI_PORT_ATTR_AUTO_NEG_MODE: {
                set_attr_value(SAI_PORT_ATTR_AUTO_NEG_MODE, port_cfg_map[attr_name].value, json_boolean_value(j_attr));
            } break;
            case SAI_PORT_ATTR_ADMIN_STATE: {
                set_attr_value(SAI_PORT_ATTR_ADMIN_STATE, port_cfg_map[attr_name].value, json_boolean_value(j_attr));
            } break;
            case SAI_PORT_ATTR_MTU: {
                set_attr_value(SAI_PORT_ATTR_MTU, port_cfg_map[attr_name].value, (uint32_t)json_integer_value(j_attr));
            } break;
            case SAI_PORT_ATTR_MEDIA_TYPE: {
                json_string_to_sai_port_attr_enum<SAI_PORT_ATTR_MEDIA_TYPE>(
                    sai_port_media_type_str_map, j_attr, port_cfg_map[attr_name].value, err_cnt);
            } break;
            default: {
                sai_log_error(SAI_API_SWITCH, "\"%s\" json key is not implemented.", attr_name.c_str());
            }
            }
        }
    }

    // convert port_cfg_map to port_cfg vector
    port_cfg.m_attrs.clear();
    std::transform(port_cfg_map.begin(),
                   port_cfg_map.end(),
                   std::back_inserter(port_cfg.m_attrs),
                   [](std::pair<std::string, sai_attribute_t> x) { return x.second; });

    { // To print debugging message...
        std::stringstream log_message;
        for (const auto& item : port_cfg.m_pif_lanes) {
            log_message << std::hex << std::showbase << item << " ";
        }

        sai_log_debug(SAI_API_PORT, " <----------: \"%s\" = %s", "pif", log_message.str().c_str());
        sai_log_debug(SAI_API_PORT, " <- port_cfg: \"%s\" = %d", "pif_counts", lanes_count);

        for (const auto& attr : port_cfg.m_attrs) {
            std::stringstream log_message;
            log_message << "\"" << attr.id << "\" = " << attr.value.u32;
            sai_log_debug(SAI_API_PORT, " <- port_cfg: %s", log_message.str().c_str());
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
config_parser::json_load_init_switch(json_t* j_init_sw)
{
    if (!json_is_string(j_init_sw)) {
        const char* j_init_sw_str = json_key_name(j_init_sw);
        sai_log_error(SAI_API_SWITCH, "JSON error: the value of \"%s\" is not string.", j_init_sw_str);
        return LA_STATUS_EINVAL;
    }

    std::string raw_value = std::string(json_string_value(j_init_sw));

    // convert to upper case
    std::string init_value = raw_value;
    std::transform(init_value.begin(), init_value.end(), init_value.begin(), [](unsigned char c) { return std::toupper(c); });

    // clang-format off
    // Mapping table from json string value to lsai_sw_init_mode_e
    static const std::map<std::string, lsai_sw_init_mode_e> init_value_map{
        {"DEFAULT", lsai_sw_init_mode_e::L2BRIDGE},
        {"L2_BRIDGE", lsai_sw_init_mode_e::L2BRIDGE},
        {"PORT_ONLY", lsai_sw_init_mode_e::PORTONLY},
        {"", lsai_sw_init_mode_e::NONE},
        {"NONE", lsai_sw_init_mode_e::NONE}
    };
    // clang-format off

    auto iter = init_value_map.find(init_value);

    if (iter == init_value_map.end()) {
        sai_log_error(SAI_API_SWITCH, "Fail to map value(%s) to type(lsai_sw_init_mode_e).", raw_value.c_str());
        return LA_STATUS_EINVAL;
    }

    m_sdev->m_sw_init_mode = iter->second;

    return LA_STATUS_SUCCESS;
}

la_status
config_parser::json_load_dev_params() {
    if (m_json_dev_params == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    json_struct_writer writer("dev_params");
    m_sdev->m_dev_params.register_fields(writer);

    const char* j_attr_key_str;
    json_t* j_attr;
    json_object_foreach(m_json_dev_params, j_attr_key_str, j_attr) {
        writer.write(j_attr_key_str, j_attr);
    }
    return LA_STATUS_SUCCESS;
}

}
}
