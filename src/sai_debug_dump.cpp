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

#include <iostream>
#include <fstream>
#include <iomanip>
#include <ctime>
#include <sstream>

#include <jansson.h>
#include "sai_device.h"
#include "sai_logger.h"
#include "sai_port.h"
#include "sai_strings.h"
#include "sai_switch.h"
#include "sai_version.h"

json_t*
json_string(const std::string& str)
{
    return json_string(str.c_str());
}

json_t*
json_string(const std::stringstream& sstr)
{
    return json_string(sstr.str().c_str());
}

namespace silicon_one
{
namespace sai
{

static std::string
current_time_str()
{
    std::stringstream time_ss;
    std::time_t now = std::time(nullptr);
    char time_str[100];
    std::strftime(time_str, sizeof(time_str), "%c %Z", std::localtime(&now));
    time_ss << time_str;
    // time_ss << std::put_time(localtime(&now), "%c %Z");  // only in gcc 6.0 and above.
    return time_ss.str();
}

// dump a single mac_port setting to json object.
static sai_status_t
sai_debug_dump_port_config(la_mac_port* mac_port, json_t* port_json)
{
    la_status status;

    std::stringstream loc_str_ss;
    loc_str_ss << mac_port->get_slice() << "/" << mac_port->get_ifg() << "/" << mac_port->get_first_serdes_id() << "-("
               << mac_port->get_num_of_serdes() << ")";
    json_object_set_new(port_json, "phy_loc", json_string(loc_str_ss));

    la_mac_port::port_speed_e out_speed;
    status = mac_port->get_speed(out_speed);
    sai_return_on_la_error(status);
    json_object_set_new(port_json, "speed", json_string(to_string(out_speed)));

    la_mac_port::fec_mode_e out_fec;
    status = mac_port->get_fec_mode(out_fec);
    sai_return_on_la_error(status);
    json_object_set_new(port_json, "fec", json_string(to_string(out_fec)));

    la_mac_port::loopback_mode_e out_loopback_mode;
    status = mac_port->get_loopback_mode(out_loopback_mode);
    sai_return_on_la_error(status);
    json_object_set_new(port_json, "loopback", json_string(to_string(out_loopback_mode)));

    la_mac_port::fc_mode_e tx_fc, rx_fc;
    status = mac_port->get_fc_mode(la_mac_port::fc_direction_e::RX, rx_fc);
    sai_return_on_la_error(status);
    status = mac_port->get_fc_mode(la_mac_port::fc_direction_e::TX, tx_fc);
    sai_return_on_la_error(status);
    json_t* fc_json = json_object();
    json_object_set_new(fc_json, "rx", json_string(to_string(rx_fc)));
    json_object_set_new(fc_json, "tx", json_string(to_string(tx_fc)));
    json_object_set_new(port_json, "flow_control", fc_json);

    bool out_enable;
    status = mac_port->get_link_management_enabled(out_enable);
    sai_return_on_la_error(status);
    json_object_set_new(port_json, "link_management_enable", json_boolean(out_enable));
    status = mac_port->get_serdes_continuous_tuning_enabled(out_enable);
    sai_return_on_la_error(status);
    json_object_set_new(port_json, "continuous_tuning_enable", json_boolean(out_enable));

    la_mac_port::mac_status out_mac_status;
    status = mac_port->read_mac_status(out_mac_status);
    sai_return_on_la_error(status);
    json_t* link_json = json_object();
    json_object_set_new(port_json, "link_status", link_json);
    json_object_set_new(link_json, "pcs_status", json_boolean(out_mac_status.pcs_status));
    json_object_set_new(link_json, "link_state", json_boolean(out_mac_status.link_state));
    json_object_set_new(link_json, "high_ber", json_boolean(out_mac_status.high_ber));
    json_t* am_lock_json = json_array();
    for (uint idx = 0; idx < mac_port->get_num_of_serdes(); idx++) {
        json_array_append(am_lock_json, json_integer(out_mac_status.am_lock[idx]));
    }
    json_object_set_new(link_json, "am_lock", am_lock_json);

    la_mac_port::state_e out_state;
    status = mac_port->get_state(out_state);
    sai_return_on_la_error(status);
    json_object_set_new(port_json, "current_state", json_string(to_string(out_state)));

    la_mac_port::link_down_interrupt_histogram out_link_down_histogram;
    status = mac_port->get_link_down_histogram(false, out_link_down_histogram);
    sai_return_on_la_error(status);
    json_t* link_dn_cnt_json = json_object();
    json_object_set_new(port_json, "link_down_histogram", link_dn_cnt_json);
    json_object_set_new(link_dn_cnt_json, "rx_link_status_down", json_integer(out_link_down_histogram.rx_link_status_down_count));
    json_object_set_new(
        link_dn_cnt_json, "rx_pcs_link_status_down", json_integer(out_link_down_histogram.rx_pcs_link_status_down_count));
    json_object_set_new(
        link_dn_cnt_json, "rx_pcs_align_status_down", json_integer(out_link_down_histogram.rx_pcs_align_status_down_count));
    json_object_set_new(link_dn_cnt_json, "rx_pcs_hi_ber_up", json_integer(out_link_down_histogram.rx_pcs_hi_ber_up_count));
    json_object_set_new(
        link_dn_cnt_json, "rsf_rx_high_ser", json_integer(out_link_down_histogram.rsf_rx_high_ser_interrupt_register_count));
    json_t* rx_pma_sig_ok_loss_json = json_array();
    for (uint idx = 0; idx < mac_port->get_num_of_serdes(); idx++) {
        json_array_append(rx_pma_sig_ok_loss_json,
                          json_integer(out_link_down_histogram.rx_pma_sig_ok_loss_interrupt_register_count[idx]));
    }
    json_object_set_new(link_dn_cnt_json, "rx_pma_sig_ok_loss", rx_pma_sig_ok_loss_json);
    json_t* rx_deskew_fifo_overflow_json = json_array();
    for (auto value : out_link_down_histogram.rx_deskew_fifo_overflow_count) {
        if (value != 0) {
            json_array_append(rx_deskew_fifo_overflow_json, json_integer(value));
        }
    }
    json_object_set_new(link_dn_cnt_json, "rx_deskew_fifo_overflow", rx_deskew_fifo_overflow_json);

    return SAI_STATUS_SUCCESS;
}

// dump all activate ports' settings and parameters
sai_status_t
sai_debug_dump_port(std::shared_ptr<lsai_device> s_device, json_t* parent_json)
{
    sai_status_t sai_status;
    la_status status;

    // create debug info for all sai_port (only mac_port)
    std::vector<port_entry*> sai_mac_ports_list = s_device->get_mac_ports();
    for (auto& port_entry : sai_mac_ports_list) {
        // create a sai_port key for each sai_port
        json_t* port_json = json_object();
        std::stringstream port_ss;
        port_ss << std::hex << "sai_port_0x" << port_entry->service.oid;
        json_object_set_new(parent_json, port_ss.str().c_str(), port_json);

        json_object_set_new(port_json, "admin_state", json_string(to_string(port_entry->admin_state)));
        json_object_set_new(port_json, "port_type", json_string(to_string(port_entry->type)));
        json_object_set_new(port_json, "media_type", json_string(to_string(port_entry->media_type)));

        port_ss.str(std::string());
        port_ss << std::hex << "0x" << port_entry->service.ingress_acl;
        json_object_set_new(port_json, "ingress_acl", json_string(port_ss));
        port_ss.str(std::string());
        port_ss << std::hex << "0x" << port_entry->service.egress_acl;
        json_object_set_new(port_json, "egress_acl", json_string(port_ss));

        std::string sche_oid_str
            = to_string(port_entry->scheduling_oids.begin(), port_entry->scheduling_oids.end(), [](sai_object_id_t* it) {
                  std::stringstream ss;
                  ss << std::hex << "0x" << *it;
                  return ss.str();
              });
        json_object_set_new(port_json, "scheduling_oids", json_string(sche_oid_str));

        std::string wred_oid_str = to_string(port_entry->wred_oids.begin(), port_entry->wred_oids.end(), [](sai_object_id_t* it) {
            std::stringstream ss;
            ss << std::hex << "0x" << *it;
            return ss.str();
        });
        json_object_set_new(port_json, "wred_oids", json_string(wred_oid_str));

        std::string ig_mirror = to_string(port_entry->service.ingress_mirror_oids.begin(),
                                          port_entry->service.ingress_mirror_oids.end(),
                                          [](std::set<sai_object_id_t>::iterator it) {
                                              std::stringstream ss;
                                              ss << std::hex << "0x" << *it;
                                              return ss.str();
                                          });
        json_object_set_new(port_json, "ingress_mirror_oids", json_string(ig_mirror));

        std::string eg_mirror = to_string(port_entry->service.egress_mirror_oids.begin(),
                                          port_entry->service.egress_mirror_oids.end(),
                                          [](std::set<sai_object_id_t>::iterator it) {
                                              std::stringstream ss;
                                              ss << std::hex << "0x" << *it;
                                              return ss.str();
                                          });
        json_object_set_new(port_json, "egress_mirror_oids", json_string(eg_mirror));

        la_mac_port* mac_port = get_mac_port_by_eth_obj(port_entry->service.oid);
        if (mac_port == nullptr) {
            sai_log_error(SAI_API_SWITCH, "Fail to get mac_port from SAI object ID,s 0x%lx.", port_entry->service.oid);
            continue;
        }

        // create port ID info
        port_phy_loc port_phy_loc;
        port_phy_loc.slice = mac_port->get_slice();
        port_phy_loc.ifg = mac_port->get_ifg();
        port_phy_loc.pif = mac_port->get_first_serdes_id();
        sai_uint32_t port_pif = to_sai_lanes(port_phy_loc);
        json_object_set_new(port_json, "port_id", json_integer(port_pif));

        // put all debug info in the sai_port json key
        sai_status = sai_debug_dump_port_config(mac_port, port_json);
        if (sai_status != SAI_STATUS_SUCCESS) {
            sai_log_error(SAI_API_SWITCH,
                          "sai_debug_dump_port_config: fail to dump all configuration from sai_port 0x%lx",
                          port_entry->service.oid);
        };

        // dump mac_port states to sai_port json key
        status = mac_port->save_state(la_mac_port::port_debug_info_e::ALL, port_json);
        if (status != LA_STATUS_SUCCESS) {
            sai_log_error(
                SAI_API_SWITCH, "save_state: fail to dump all MAC port states from sai_port 0x%lx", port_entry->service.oid);
        };
    }

    return SAI_STATUS_SUCCESS;
}

// dump lane setting info
sai_status_t
sai_debug_dump_lane_setting(const std::shared_ptr<lsai_device> s_device, json_t* parent_json)
{
    // dump lane setting info
    json_t* j_lane_settings = json_object();
    json_object_set_new(parent_json, "Lane_Settings", j_lane_settings);

    for (uint ifg_idx = 0; ifg_idx < s_device->m_board_cfg.lanes.ifg_swap.size(); ifg_idx++) {
        json_t* j_ifg_setting = json_object();
        std::string ifg_name = "IFG_" + std::to_string(ifg_idx);
        json_object_set_new(j_lane_settings, ifg_name.c_str(), j_ifg_setting);

        std::string swap_str = to_string(s_device->m_board_cfg.lanes.ifg_swap[ifg_idx].begin(),
                                         s_device->m_board_cfg.lanes.ifg_swap[ifg_idx].end(),
                                         [](la_vsc_gid_vec_t::iterator it) { return *it; });
        json_object_set_new(j_ifg_setting, "swap", json_string(swap_str));

        std::string rxin_str = to_string(s_device->m_board_cfg.lanes.rx_inverse[ifg_idx].begin(),
                                         s_device->m_board_cfg.lanes.rx_inverse[ifg_idx].end(),
                                         [](la_vsc_gid_vec_t::iterator it) { return *it; });
        json_object_set_new(j_ifg_setting, "rx_inv", json_string(rxin_str));

        std::string txin_str = to_string(s_device->m_board_cfg.lanes.tx_inverse[ifg_idx].begin(),
                                         s_device->m_board_cfg.lanes.tx_inverse[ifg_idx].end(),
                                         [](la_vsc_gid_vec_t::iterator it) { return *it; });
        json_object_set_new(j_ifg_setting, "tx_inv", json_string(txin_str));
    }

    return SAI_STATUS_SUCCESS;
}

// dump port mix info to logger
sai_status_t
sai_debug_dump_port_mix(const std::shared_ptr<lsai_device> s_device, json_t* parent_json)
{
    json_t* j_port_mix = json_object();
    json_object_set_new(parent_json, "port_mix", j_port_mix);

    json_object_set_new(j_port_mix,
                        "Description",
                        json_string("Only reflects the switch initialization stage of ports creation. Not Current Port Status."));
    json_object_set_new(j_port_mix, "init_switch", json_string(to_string(s_device->m_sw_init_mode)));
    json_t* j_port_list = json_array();
    json_object_set_new(j_port_mix, "ports", j_port_list);

    for (auto port_grp_iter : s_device->m_port_mix_map) {
        for (auto port_cfg : port_grp_iter.second) {
            json_t* j_port = json_object();
            json_object_set_new(j_port, "pif", json_integer(port_cfg.m_pif_lanes[0]));
            json_object_set_new(j_port, "pif_counts", json_integer(port_cfg.m_pif_lanes.size()));

            std::stringstream hex_ss;
            hex_ss << std::hex << std::showbase << port_cfg.m_sai_port_id;
            json_object_set_new(j_port, "port_oid", json_string(hex_ss));

            hex_ss.str(std::string());
            hex_ss << port_cfg.m_sai_bridge_port_id;
            json_object_set_new(j_port, "bridge_port_oid", json_string(hex_ss));

            hex_ss.str(std::string());
            hex_ss << port_cfg.m_sai_vlan_member_id;
            json_object_set_new(j_port, "vlan_memeber_oid", json_string(hex_ss));
            json_array_append(j_port_list, j_port);
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_debug_dump_acl(const std::shared_ptr<lsai_device> s_device, json_t* parent_json)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
sai_debug_dump_vlan(const std::shared_ptr<lsai_device> s_device, json_t* parent_json)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

// Get the device property lsai_device.
sai_status_t
add_json_bool_device_prop(json_t* json_parent,
                          const std::shared_ptr<lsai_device> s_device,
                          string json_key,
                          silicon_one::la_device_property_e prop_e)
{
    bool value;
    la_status status = s_device->m_dev->get_bool_property(prop_e, value);
    sai_return_on_la_error(status, "add_json_bool_device_prop: fail get %s", to_string(prop_e).c_str());

    int json_err = json_object_set_new(json_parent, json_key.c_str(), json_boolean(value));
    if (json_err) {
        sai_log_error(SAI_API_SWITCH, "add_json_bool_device_prop: fail create json for %s", to_string(prop_e).c_str());
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
add_json_int_device_prop(json_t* json_parent,
                         const std::shared_ptr<lsai_device> s_device,
                         string json_key,
                         silicon_one::la_device_property_e prop_e)
{
    int value;
    la_status status = s_device->m_dev->get_int_property(prop_e, value);
    sai_return_on_la_error(status, "add_json_int_device_prop: fail get %s", to_string(prop_e).c_str());

    int json_err = json_object_set_new(json_parent, json_key.c_str(), json_integer(value));
    if (json_err) {
        sai_log_error(SAI_API_SWITCH, "add_json_int_device_prop: fail create json for %s", to_string(prop_e).c_str());
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
add_json_string_device_prop(json_t* json_parent,
                            const std::shared_ptr<lsai_device> s_device,
                            string json_key,
                            silicon_one::la_device_property_e prop_e)
{
    string value;
    la_status status = s_device->m_dev->get_string_property(prop_e, value);
    sai_return_on_la_error(status, "add_json_string_device_prop: fail get %s", to_string(prop_e).c_str());

    int json_err = json_object_set_new(json_parent, json_key.c_str(), json_string(value));
    if (json_err) {
        sai_log_error(SAI_API_SWITCH, "add_json_string_device_prop: fail create json for %s", to_string(prop_e).c_str());
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_debug_dump_create_sw_json(const uint32_t& switch_id,
                              const std::shared_ptr<lsai_device> s_device,
                              json_t* root_json,
                              json_t*& switch_json)
{
    // create a switch key
    switch_json = json_object();
    std::stringstream switch_ss;
    switch_ss << std::hex << "switch_0x" << switch_id;
    json_object_set_new(root_json, switch_ss.str().c_str(), switch_json);

    // create json key for each configurable device property for this device and add them in the switch_json.
    json_t* dprop_json = json_object();
    json_object_set_new(switch_json, "device property", dprop_json);
    add_json_bool_device_prop(dprop_json, s_device, "poll_msi", silicon_one::la_device_property_e::POLL_MSI);
    add_json_bool_device_prop(dprop_json, s_device, "process_interrupts", silicon_one::la_device_property_e::PROCESS_INTERRUPTS);
    add_json_bool_device_prop(dprop_json, s_device, "enable_mbist_repair", silicon_one::la_device_property_e::ENABLE_MBIST_REPAIR);
    add_json_bool_device_prop(dprop_json, s_device, "enable_hbm", silicon_one::la_device_property_e::ENABLE_HBM);
    add_json_bool_device_prop(
        dprop_json, s_device, "enable_hbm_route_extension", silicon_one::la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION);
    add_json_bool_device_prop(dprop_json,
                              s_device,
                              "enable_hbm_route_extension_caching_mode",
                              silicon_one::la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION_CACHING_MODE);
    add_json_int_device_prop(dprop_json, s_device, "device_frequency", silicon_one::la_device_property_e::DEVICE_FREQUENCY);
    add_json_bool_device_prop(dprop_json, s_device, "enable_sensor_poll", silicon_one::la_device_property_e::ENABLE_SENSOR_POLL);

    return SAI_STATUS_SUCCESS;
}

// create a json object of a switch and dump all debug information to it.
sai_status_t
sai_debug_dump_switch(const uint32_t& switch_id, std::shared_ptr<lsai_device> s_device, json_t* root_json)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    std::lock_guard<std::recursive_mutex> lock(s_device->m_mutex);

    json_t* switch_json = nullptr;

    status |= sai_debug_dump_create_sw_json(switch_id, s_device, root_json, switch_json);

    status |= sai_debug_dump_port_mix(s_device, switch_json);

    status |= sai_debug_dump_lane_setting(s_device, switch_json);

    status |= sai_debug_dump_port(s_device, switch_json);

    s_device->m_qos_handler->dump_json(switch_json);
    s_device->m_sched_handler->dump_json(switch_json);

    // TODO: dump other debug info in switch_json here...

    if (status != SAI_STATUS_SUCCESS) {
        sai_log_error(
            SAI_API_SWITCH, "Error happens while dumping debug information to json file. SAI object ID, 0x%lx", switch_id);
    }

    return status;
}
}
}
using namespace silicon_one::sai;

sai_status_t
sai_dbg_generate_dump(const char* dump_file_name)
{
    la_status status;

    // Check if any switch is created...
    auto switch_id_list = get_sai_switch_id_list();
    if (switch_id_list.size() == 0) {
        sai_return_on_la_error(LA_STATUS_ENOTFOUND);
    }

    json_t* root_json = json_object();
    json_object_set_new(root_json, "Date", json_string(current_time_str()));
    sai_version_t version = get_sai_sdk_version();
    json_object_set_new(root_json, "SDK version", json_string((version.sai_sdk_version)));
    json_object_set_new(root_json, "SAI version", json_string((version.ocp_sai_version)));

    for (uint32_t switch_id : switch_id_list) {
        std::shared_ptr<lsai_device> s_device;
        status = sai_get_device(switch_id, s_device);
        if (status != LA_STATUS_SUCCESS) {
            sai_log_error(SAI_API_SWITCH, "sai_dbg_generate_dump: lsai_device is a nullptr. SAI object ID, 0x%lx", switch_id);
            continue;
        }

        sai_debug_dump_switch(switch_id, s_device, root_json);
    }

    std::string dump_file = (dump_file_name == nullptr) ? "" : std::string(dump_file_name);
    std::ofstream outfile(dump_file, std::ios::out | std::ios::trunc); // open for write and truncate
    if (dump_file_name != nullptr && !outfile.is_open()) {
        sai_return_on_error(SAI_STATUS_FAILURE, "Fail to open file, %s\n", dump_file_name);
    }
    std::ostream& msgout = (dump_file_name == nullptr) ? std::cout : outfile;

    msgout << json_dumps(root_json, JSON_INDENT(4) | JSON_PRESERVE_ORDER) << std::endl;

    json_decref(root_json);

    return SAI_STATUS_SUCCESS;
}
