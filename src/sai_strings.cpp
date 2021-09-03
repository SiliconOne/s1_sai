// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco").
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

#include <arpa/inet.h>
#include <../../build/src/auto_gen_attr.h>
#include <iomanip>
#include <map>
#include "common/gen_utils.h"
#include "sai_strings.h"
#include "sai_constants.h"

namespace silicon_one
{
namespace sai
{

std::string
to_string(const lsai_sw_init_mode_e& value)
{
    std::stringstream return_val;
    if (value == lsai_sw_init_mode_e::L2BRIDGE) {
        return_val << "L2BRIDGE";
    } else if (value == silicon_one::sai::lsai_sw_init_mode_e::PORTONLY) {
        return_val << "PORTONLY";
    } else {
        return_val << "NONE";
    }
    return return_val.str();
}

std::string
to_string(const lsai_extended_property_e& value)
{
    static std::map<lsai_extended_property_e, const char*> strs = {
        {lsai_extended_property_e::FLOW_CACHE_ENABLE, "FLOW_CACHE_ENABLE"},
    };

    auto str = strs.find(value);
    if (str != strs.end()) {
        return str->second;
    }
    return "Unknown";
}

std::string
to_string(const silicon_one::la_mac_port::serdes_parameter& serdes_prop)
{
    std::stringstream return_val;
    return_val << silicon_one::to_string(serdes_prop.stage) << " ";
    return_val << silicon_one::to_string(serdes_prop.parameter) << " ";
    return_val << silicon_one::to_string(serdes_prop.mode) << " ";
    return_val << serdes_prop.value;
    return return_val.str();
}

std::string
to_string(const port_entry_type_e& pentry_type)
{
    static std::map<port_entry_type_e, const char*> strs = {
        {port_entry_type_e::MAC, "MAC"},
        {port_entry_type_e::PCI, "PCI"},
        {port_entry_type_e::INTERNAL_PCI, "INTERNAL_PCI"},
        {port_entry_type_e::RECYCLE, "RECYCLE"},
    };

    auto str = strs.find(pentry_type);
    if (str != strs.end()) {
        return str->second;
    }
    return "Unknown";
}

std::string
to_string(const lsai_serdes_params_map_key_t& value)
{
    return std::to_string(value.slice_id) + "," + std::to_string(value.ifg_id) + "," + std::to_string(value.serdes_id) + ","
           + std::to_string(value.serdes_speed) + "," + std::to_string((uint32_t)value.media_type);
}

std::string
to_string(const lsai_serdes_key_counters_t& value)
{
    std::string return_value = "NOT_PRESENT(" + std::to_string(value.not_present);
    return_value += ") COPPER(" + std::to_string(value.copper);
    return_value += ") OPTIC(" + std::to_string(value.optic);
    return_value += ") CHIP2CHIP(" + std::to_string(value.chip2chip);
    return_value += ") LOOPBACK(" + std::to_string(value.loopback);
    return_value += ")";
    return return_value;
}

std::string
to_string(const sai_port_lane_eye_values_t& ev)
{
    return "(" + std::to_string(ev.lane) + "," + std::to_string(ev.left) + "," + std::to_string(ev.right) + ","
           + std::to_string(ev.up) + "," + std::to_string(ev.down) + ")";
}

std::string
to_string(const sai_port_eye_values_list_t& evlst)
{
    std::stringstream log_message;

    if (evlst.list == nullptr) {
        return "nullptr";
    }
    for (uint32_t i = 0; i < evlst.count; i++) {
        log_message << to_string(evlst.list[i]);
    }
    return log_message.str();
}

std::string
to_string(attr_to_string_fn attr_func, unsigned int& value)
{
    std::stringstream log_message;
    log_message << value;

    return log_message.str();
}

std::string
to_string(attr_to_string_fn attr_func, const char*& value)
{
    if (value == nullptr) {
        return std::string("nullptr");
    }
    return std::string(value);
}

std::string
to_string(short unsigned int& x)
{
    std::stringstream log_message;
    log_message << std::hex << std::showbase << x;

    return log_message.str();
}

// This is an enum, not c++ bool type. We get here also for uint8
std::string
to_string(bool value)
{
    std::stringstream log_message;
    log_message << value;

    return log_message.str();
}

std::string
to_string(unsigned int& x)
{
    std::stringstream log_message;
    log_message << std::hex << std::showbase << x;

    return log_message.str();
}

std::string
to_string(long unsigned int& x)
{
    std::stringstream log_message;
    log_message << std::hex << std::showbase << x;

    return log_message.str();
}

std::string
to_string(const sai_map_t& mp)
{
    std::stringstream log_message;

    log_message << "(" << mp.key << "," << mp.value << ")";
    return log_message.str();
}

std::string
to_string(const sai_map_list_t& maplist)
{
    std::stringstream log_message;

    if (maplist.list == nullptr) {
        return "nullptr";
    }
    for (uint32_t i = 0; i < maplist.count; i++) {
        log_message << to_string(maplist.list[i]);
    }
    return log_message.str();
}

std::string
to_string(const sai_s8_list_t& s8list)
{
    std::stringstream log_message;

    if (s8list.list == nullptr) {
        return "nullptr";
    }
    for (uint32_t i = 0; i < s8list.count; i++) {
        log_message << s8list.list[i];
    }
    return log_message.str();
}

std::string
to_string(const sai_u8_list_t& u8list)
{
    std::stringstream log_message;

    if (u8list.list == nullptr) {
        return "nullptr";
    }
    for (uint32_t i = 0; i < u8list.count; i++) {
        log_message << u8list.list[i];
    }
    return log_message.str();
}

std::string
to_string(_sai_u16_list_t& u16list)
{
    std::stringstream log_message;

    if (u16list.list == nullptr) {
        return "nullptr";
    }
    for (uint32_t i = 0; i < u16list.count; i++) {
        log_message << u16list.list[i];
    }
    return log_message.str();
}

std::string
to_string(const sai_u32_range_t& u32r)
{
    std::stringstream log_message;
    log_message << u32r.min << u32r.max;

    return log_message.str();
}

std::string
to_string(const sai_qos_map_list_t& qosmlist)
{
    std::stringstream log_message;
    log_message << "count " << qosmlist.count << " " << std::endl;
    for (uint8_t i = 0; i < qosmlist.count; i++) {
        log_message << i + 1 << ") key:(";
        log_message << std::to_string(qosmlist.list[i].key.tc) << ", ";
        log_message << std::to_string(qosmlist.list[i].key.dscp) << ", ";
        log_message << std::to_string(qosmlist.list[i].key.dot1p) << ", ";
        log_message << std::to_string(qosmlist.list[i].key.prio) << ", ";
        log_message << std::to_string(qosmlist.list[i].key.pg) << ", ";
        log_message << std::to_string(qosmlist.list[i].key.queue_index) << ", ";
        log_message << to_string(qosmlist.list[i].key.color) << ", ";
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
        log_message << std::to_string(qosmlist.list[i].key.mpls_exp);
#endif
        log_message << ") value:(";
        log_message << std::to_string(qosmlist.list[i].value.tc) << ", ";
        log_message << std::to_string(qosmlist.list[i].value.dscp) << ", ";
        log_message << std::to_string(qosmlist.list[i].value.dot1p) << ", ";
        log_message << std::to_string(qosmlist.list[i].value.prio) << ", ";
        log_message << std::to_string(qosmlist.list[i].value.pg) << ", ";
        log_message << std::to_string(qosmlist.list[i].value.queue_index) << ", ";
        log_message << to_string(qosmlist.list[i].value.color) << ", ";
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
        log_message << std::to_string(qosmlist.list[i].value.mpls_exp) << ")";
#endif
        log_message << std::endl;
    }

    return log_message.str();
}

std::string
to_string(const sai_segment_list_t& seglist)
{
    std::stringstream log_message;
    log_message << "seglist to be implemented ...";

    return log_message.str();
}

std::string
to_string(const sai_tlv_list_t& tlvlist)
{
    std::stringstream log_message;
    log_message << "tlvlist to be implemented ...";

    return log_message.str();
}

std::string
to_string(const sai_acl_capability_t& aclcap)
{
    std::stringstream log_message;
    log_message << "acl cap to be implemented ...";

    return log_message.str();
}

std::string
to_string(const sai_acl_resource_list_t&)
{
    std::stringstream log_message;
    log_message << "acl_resource to be implemented ...";

    return log_message.str();
}

std::string
to_string(const sai_mac_t& mac)
{
    std::stringstream log_message;
    log_message << " ";
    for (int i = 0; i < 6; i++) {
        log_message << std::setfill('0') << std::setw(2) << std::hex << (int)mac[i];
    }

    return log_message.str();
}

std::string
to_string(const sai_ip_address_list_t& ipaddrlist)
{
    std::stringstream log_message;

    if (ipaddrlist.list == nullptr) {
        return "nullptr";
    }
    for (uint32_t i = 0; i < ipaddrlist.count; i++) {
        log_message << " " << to_string(ipaddrlist.list[i]);
    }
    return log_message.str();
}

std::string
to_string(const sai_s32_list_t& s32list)
{
    std::stringstream log_message;

    if (s32list.list == nullptr) {
        return "nullptr";
    }
    for (uint32_t i = 0; i < s32list.count; i++) {
        log_message << " " << std::hex << std::showbase << s32list.list[i];
    }
    return log_message.str();
}

std::string
to_string(const sai_vlan_list_t& vlanlist)
{
    std::stringstream log_message;

    if (vlanlist.list == nullptr) {
        return "nullptr";
    }
    for (uint32_t i = 0; i < vlanlist.count; i++) {
        log_message << " " << std::hex << std::showbase << vlanlist.list[i];
    }
    return log_message.str();
}

static void
sai_ipv4_to_str(const _In_ sai_ip4_t value, _In_ uint32_t max_length, _Out_ char* value_str)
{
    memset(value_str, '\0', max_length);
    inet_ntop(AF_INET, &value, value_str, max_length);
}

static void
sai_ipv6_to_str(const _In_ sai_ip6_t value, _In_ uint32_t max_length, _Out_ char* value_str)
{
    struct in6_addr addr;

    memset(value_str, '\0', max_length);
    memcpy(addr.s6_addr, value, sizeof(addr));
    inet_ntop(AF_INET6, &addr, value_str, max_length);
}

#define MAX_VALUE_STR_LEN 100

std::string
to_string(const sai_ip6_t& ip6)
{
    std::stringstream log_message;
    char value_str[MAX_VALUE_STR_LEN];

    sai_ipv6_to_str(ip6, MAX_VALUE_STR_LEN, value_str);
    log_message << "ipv6 " << value_str;
    return log_message.str();
}

std::string
to_string(const sai_ip_address_t& ipaddr)
{
    std::stringstream log_message;
    char value_str[MAX_VALUE_STR_LEN];

    if (ipaddr.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        sai_ipv4_to_str(ipaddr.addr.ip4, MAX_VALUE_STR_LEN, value_str);
        log_message << "ipv4 " << value_str;
    } else {
        sai_ipv6_to_str(ipaddr.addr.ip6, MAX_VALUE_STR_LEN, value_str);
        log_message << "ipv6 " << value_str;
    }

    return log_message.str();
}

std::string
to_string(const sai_ip_prefix_t& prefix)
{
    std::stringstream log_message;
    char value_str[MAX_VALUE_STR_LEN];

    if (prefix.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        sai_ipv4_to_str(prefix.addr.ip4, MAX_VALUE_STR_LEN, value_str);
        log_message << "prefix " << value_str;
        sai_ipv4_to_str(prefix.mask.ip4, MAX_VALUE_STR_LEN, value_str);
        log_message << " mask " << value_str;
    } else {
        sai_ipv6_to_str(prefix.addr.ip6, MAX_VALUE_STR_LEN, value_str);
        log_message << "prefix " << value_str;
        sai_ipv6_to_str(prefix.mask.ip6, MAX_VALUE_STR_LEN, value_str);
        log_message << " mask " << value_str;
    }

    return log_message.str();
}

std::string
to_string(attr_to_string_fn attr_func, const std::string& value)
{
    return (value);
}

std::string
to_string(attr_to_string_fn attr_func, const sai_object_id_t& obj_id)
{
    std::stringstream log_message;
    log_message << "id: " << std::hex << std::showbase << obj_id;

    return log_message.str();
}

std::string
to_string(attr_to_string_fn attr_func, sai_attribute_t& attr)
{
    std::stringstream log_message;
    log_message << (*attr_func)(attr);
    return log_message.str();
}

std::string
to_string(attr_to_string_fn attr_func, const sai_fdb_entry_t*& x)
{
    std::stringstream log_message;
    const sai_mac_t& mac = x->mac_address;
    log_message << " fdb_entry"
                << " switch" << to_string(attr_func, x->switch_id) << " mac" << to_string(mac) << " bridge"
                << to_string(attr_func, x->bv_id) << "\n";
    return log_message.str();
}

std::string
to_string(attr_to_string_fn attr_func, const sai_neighbor_entry_t*& x)
{
    std::stringstream log_message;
    const sai_ip_address_t& ipaddr = x->ip_address;

    log_message << "neighbor_entry"
                << " switch" << to_string(attr_func, x->switch_id) << " rif" << to_string(attr_func, x->rif_id) << " ip_address "
                << to_string(ipaddr) << "\n";
    return log_message.str();
}

std::string
to_string(attr_to_string_fn attr_func, const sai_inseg_entry_t*& x)
{
    std::stringstream log_message;
    log_message << "inseg_entry"
                << " switch" << to_string(attr_func, x->switch_id) << " label " << std::to_string(x->label);
    return log_message.str();
}

std::string
to_string(attr_to_string_fn attr_func, const sai_route_entry_t*& x)
{
    std::stringstream log_message;
    const sai_ip_prefix_t ip_prefix = x->destination;
    log_message << "route_entry"
                << " switch_" << to_string(attr_func, x->switch_id) << " vrf_" << to_string(attr_func, x->vr_id) << " destination_"
                << to_string(ip_prefix);
    return log_message.str();
}

std::string
to_string(attr_to_string_fn attr_func, std::unordered_map<sai_attr_id_t, sai_attribute_value_t>& attrs)
{
    std::stringstream log_message;

    for (auto it = attrs.begin(); it != attrs.end(); ++it) {
        sai_attribute_t attr = {it->first, it->second};
        log_message << to_string(attr_func, attr) << " ";
    }

    return log_message.str();
}

std::string
to_string(const sai_object_list_t& objlist)
{
    std::stringstream log_message;

    if (objlist.list == nullptr) {
        return "nullptr";
    }
    for (uint32_t i = 0; i < objlist.count; i++) {
        log_message << " " << std::hex << std::showbase << objlist.list[i];
    }
    return log_message.str();
}

std::string
to_string(const sai_u32_list_t& u32list)
{
    std::stringstream log_message;

    if (u32list.list == nullptr) {
        return "nullptr";
    }
    for (uint32_t i = 0; i < u32list.count; i++) {
        log_message << " " << std::hex << std::showbase << u32list.list[i];
    }

    return log_message.str();
}

std::string
to_string(const sai_timespec_t& ts)
{
    std::stringstream log_message;

    log_message << " " << std::hex << std::showbase << ts.tv_sec << " sec ";
    log_message << " " << std::hex << std::showbase << ts.tv_nsec << " nsec ";

    return log_message.str();
}

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)

/*
std::string
to_string(const sai_macsec_auth_key_t& x)
{
    std::stringstream log_message;
    log_message << " dump sai_macsec_auth_key_t TBD";
    return log_message.str();
}
}
*/

std::string
to_string(const sai_port_err_status_list_t& x)
{
    std::stringstream log_message;
    log_message << " dump sai_port_err_status_list_t TBD";
    return log_message.str();
}

std::string
to_string(const sai_fabric_port_reachability_t& x)
{
    std::stringstream log_message;
    log_message << " dump sai_fabric_port_reachability_t TBD";
    return log_message.str();
}

std::string
to_string(const sai_macsec_sak_t& x)
{
    std::stringstream log_message;
    log_message << " dump sai_macsec_sak_t TBD";
    return log_message.str();
}

std::string
to_string(const sai_macsec_salt_t& x)
{
    std::stringstream log_message;
    log_message << " dump sai_macsec_salt_t TBD";
    return log_message.str();
}

std::string
to_string(const sai_system_port_config_list_t& x)
{
    std::stringstream log_message;
    log_message << " dump sai_system_port_config_list_t TBD";
    return log_message.str();
}

std::string
to_string(const sai_system_port_config_t& x)
{
    std::stringstream log_message;
    log_message << "port_id " << x.port_id << " attached_switch_id " << x.attached_switch_id << " attached_core_index "
                << x.attached_core_index << " attached_core_port_index " << x.attached_core_port_index << " speed " << x.speed
                << " num_voq " << x.num_voq;
    return log_message.str();
}

#endif

// SAI_PORT_SERDES_ATTR to string functions
std::string
to_string(sai_port_serdes_attr_ext_t a, sai_attribute_value_t v)
{
    switch (a) {
    case SAI_PORT_SERDES_ATTR_EXT_CTLE_TUNE: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_CTLE_TUNE, v);
        return to_string(res);
    }
    case SAI_PORT_SERDES_ATTR_EXT_TX_LUT_MODE: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_TX_LUT_MODE, v);
        return to_string(res);
    }
    case SAI_PORT_SERDES_ATTR_EXT_TX_PRE1: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_TX_PRE1, v);
        return to_string(res);
    }
    case SAI_PORT_SERDES_ATTR_EXT_TX_PRE2: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_TX_PRE2, v);
        return to_string(res);
    }
    case SAI_PORT_SERDES_ATTR_EXT_TX_PRE3: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_TX_PRE3, v);
        return to_string(res);
    }
    case SAI_PORT_SERDES_ATTR_EXT_TX_MAIN: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_TX_MAIN, v);
        return to_string(res);
    }
    case SAI_PORT_SERDES_ATTR_EXT_TX_POST: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_TX_POST, v);
        return to_string(res);
    }
    case SAI_PORT_SERDES_ATTR_EXT_TX_POST2: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_TX_POST2, v);
        return to_string(res);
    }
    case SAI_PORT_SERDES_ATTR_EXT_TX_POST3: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_TX_POST3, v);
        return to_string(res);
    }
    case SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE1: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE1, v);
        return to_string(res);
    }
    case SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE2: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE2, v);
        return to_string(res);
    }
    case SAI_PORT_SERDES_ATTR_EXT_RX_CTLE_CODE: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_RX_CTLE_CODE, v);
        return to_string(res);
    }
    case SAI_PORT_SERDES_ATTR_EXT_RX_DSP_MODE: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_RX_DSP_MODE, v);
        return to_string(res);
    }
    case SAI_PORT_SERDES_ATTR_EXT_RX_AFE_TRIM: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_RX_AFE_TRIM, v);
        return to_string(res);
    }
    case SAI_PORT_SERDES_ATTR_EXT_RX_VGA_TRACKING: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_RX_VGA_TRACKING, v);
        return to_string(res);
    }
    case SAI_PORT_SERDES_ATTR_EXT_RX_AC_COUPLING_BYPASS: {
        auto res = get_attr_value(SAI_PORT_SERDES_ATTR_EXT_RX_AC_COUPLING_BYPASS, v);
        return to_string(res);
    }
    default:
        break;
    }
    return "Unknown";
}

std::string
to_string(const sai_hostif_trap_type_ext_t& x)
{
    if (x == SAI_HOSTIF_TRAP_TYPE_EXT_SMAC_EQUALS_DMAC) {
        return "SAI_HOSTIF_TRAP_TYPE_EXT_SMAC_EQUALS_DMAC";
    } else if (x == SAI_HOSTIF_TRAP_TYPE_BGP_KEEPALIVE) {
        return "SAI_HOSTIF_TRAP_TYPE_BGP_KEEPALIVE";
    } else if (x == SAI_HOSTIF_TRAP_TYPE_BGPV6_KEEPALIVE) {
        return "SAI_HOSTIF_TRAP_TYPE_BGPV6_KEEPALIVE";
    } else if (x == SAI_HOSTIF_TRAP_TYPE_NEIGHBOR_MISS) {
        return "SAI_HOSTIF_TRAP_TYPE_NEIGHBOR_MISS";
    }
    return "Unknown";
}

std::string
to_string(const sai_port_serdes_attr_ext_t& x)
{
    static std::map<sai_port_serdes_attr_ext_t, const char*> strs = {
        {SAI_PORT_SERDES_ATTR_EXT_CTLE_TUNE, "SAI_PORT_SERDES_ATTR_EXT_CTLE_TUNE"},
        {SAI_PORT_SERDES_ATTR_EXT_TX_LUT_MODE, "SAI_PORT_SERDES_ATTR_EXT_TX_LUT_MODE"},
        {SAI_PORT_SERDES_ATTR_EXT_TX_PRE1, "SAI_PORT_SERDES_ATTR_EXT_TX_PRE1"},
        {SAI_PORT_SERDES_ATTR_EXT_TX_PRE2, "SAI_PORT_SERDES_ATTR_EXT_TX_PRE2"},
        {SAI_PORT_SERDES_ATTR_EXT_TX_PRE3, "SAI_PORT_SERDES_ATTR_EXT_TX_PRE3"},
        {SAI_PORT_SERDES_ATTR_EXT_TX_MAIN, "SAI_PORT_SERDES_ATTR_EXT_TX_MAIN"},
        {SAI_PORT_SERDES_ATTR_EXT_TX_POST, "SAI_PORT_SERDES_ATTR_EXT_TX_POST"},
        {SAI_PORT_SERDES_ATTR_EXT_TX_POST2, "SAI_PORT_SERDES_ATTR_EXT_TX_POST2"},
        {SAI_PORT_SERDES_ATTR_EXT_TX_POST3, "SAI_PORT_SERDES_ATTR_EXT_TX_POST3"},
        {SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE1, "SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE1"},
        {SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE2, "SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE2"},
        {SAI_PORT_SERDES_ATTR_EXT_RX_CTLE_CODE, "SAI_PORT_SERDES_ATTR_EXT_RX_CTLE_CODE"},
        {SAI_PORT_SERDES_ATTR_EXT_RX_DSP_MODE, "SAI_PORT_SERDES_ATTR_EXT_RX_DSP_MODE"},
        {SAI_PORT_SERDES_ATTR_EXT_RX_AFE_TRIM, "SAI_PORT_SERDES_ATTR_EXT_RX_AFE_TRIM"},
        {SAI_PORT_SERDES_ATTR_EXT_RX_VGA_TRACKING, "SAI_PORT_SERDES_ATTR_EXT_RX_VGA_TRACKING"},
        {SAI_PORT_SERDES_ATTR_EXT_RX_AC_COUPLING_BYPASS, "SAI_PORT_SERDES_ATTR_EXT_RX_AC_COUPLING_BYPASS"},
    };

    auto str = strs.find(x);
    if (str != strs.end()) {
        return str->second;
    }
    return "Unknown";
}

std::string
to_string(const sai_switch_attr_ext_t& x)
{
    static std::map<sai_switch_attr_ext_t, const char*> strs = {
        {SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, "SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST"},
        {SAI_SWITCH_ATTR_EXT_HW_ECC_ERROR_INITIATE, "SAI_SWITCH_ATTR_EXT_HW_ECC_ERROR_INITIATE"},
    };

    auto str = strs.find(x);
    if (str != strs.end()) {
        return str->second;
    }
    return "Unknown";
}

std::string
to_string(const sai_switch_event_type_t& x)
{
    if (x == SAI_SWITCH_EVENT_TYPE_NONE) {
        return "SAI_SWITCH_EVENT_TYPE_NONE";
    } else if (x == SAI_SWITCH_EVENT_TYPE_ALL) {
        return "SAI_SWITCH_EVENT_TYPE_ALL";
    } else if (x == SAI_SWITCH_EVENT_TYPE_STABLE_FULL) {
        return "SAI_SWITCH_EVENT_TYPE_STABLE_FULL";
    } else if (x == SAI_SWITCH_EVENT_TYPE_STABLE_ERROR) {
        return "SAI_SWITCH_EVENT_TYPE_STABLE_ERROR";
    } else if (x == SAI_SWITCH_EVENT_TYPE_UNCONTROLLED_SHUTDOWN) {
        return "SAI_SWITCH_EVENT_TYPE_UNCONTROLLED_SHUTDOWN";
    } else if (x == SAI_SWITCH_EVENT_TYPE_WARM_BOOT_DOWNGRADE) {
        return "SAI_SWITCH_EVENT_TYPE_WARM_BOOT_DOWNGRADE";
    } else if (x == SAI_SWITCH_EVENT_TYPE_PARITY_ERROR) {
        return "SAI_SWITCH_EVENT_TYPE_PARITY_ERROR";
    }
    return "Unknown";
}

std::string
to_string(const sai_tam_switch_event_ecc_err_type_e& x)
{
    if (x == ECC_COR) {
        return "ECC_COR";
    } else if (x == ECC_UNCOR) {
        return "ECC_UNCOR";
    } else if (x == PARITY) {
        return "PARITY";
    }
    return "Unknown";
}

std::string
to_string(const sai_lag_attr_ext_t& x)
{
    static std::map<sai_lag_attr_ext_t, const char*> strs = {
        {SAI_LAG_ATTR_EXT_DISABLE_DECREMENT_TTL, "SAI_LAG_ATTR_EXT_DISABLE_DECREMENT_TTL"},
        {SAI_LAG_ATTR_EXT_INGRESS_MIRROR_SESSION, "SAI_LAG_ATTR_EXT_INGRESS_MIRROR_SESSION"},
        {SAI_LAG_ATTR_EXT_EGRESS_MIRROR_SESSION, "SAI_LAG_ATTR_EXT_EGRESS_MIRROR_SESSION"},
        {SAI_LAG_ATTR_EXT_INGRESS_SAMPLEPACKET_ENABLE, "SAI_LAG_ATTR_EXT_INGRESS_SAMPLEPACKET_ENABLE"},
        {SAI_LAG_ATTR_EXT_EGRESS_SAMPLEPACKET_ENABLE, "SAI_LAG_ATTR_EXT_EGRESS_SAMPLEPACKET_ENABLE"},
        {SAI_LAG_ATTR_EXT_INGRESS_SAMPLE_MIRROR_SESSION, "SAI_LAG_ATTR_EXT_INGRESS_SAMPLE_MIRROR_SESSION"},
        {SAI_LAG_ATTR_EXT_EGRESS_SAMPLE_MIRROR_SESSION, "SAI_LAG_ATTR_EXT_EGRESS_SAMPLE_MIRROR_SESSION"},
        {SAI_LAG_ATTR_EXT_MTU, "SAI_LAG_ATTR_EXT_MTU"},
    };

    auto str = strs.find(x);
    if (str != strs.end()) {
        return str->second;
    }
    return "Unknown";
}

std::string
to_string(const sai_in_drop_reason_ext_t& x)
{
    static std::map<sai_in_drop_reason_ext_t, const char*> debug_counter_strs
        = {{SAI_IN_DROP_REASON_MPLS_MISS, "SAI_IN_DROP_REASON_MPLS_MISS"}};

    auto debug_counter_str = debug_counter_strs.find(x);
    if (debug_counter_str != debug_counter_strs.end()) {
        return debug_counter_str->second;
    }
    return "Unknown";
}

std::string
to_string(sai_lag_attr_ext_t a, sai_attribute_value_t v)
{
    switch (a) {
    case SAI_LAG_ATTR_EXT_DISABLE_DECREMENT_TTL: {
        auto res = get_attr_value(SAI_LAG_ATTR_EXT_DISABLE_DECREMENT_TTL, v);
        return to_string(res);
    }
    default:
        break;
    }
    return "Unknown";
}

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 8, 0)

std::string
to_string(const sai_prbs_rx_state_t& rx_state)
{
    std::stringstream log_message;

    log_message << "rx_status " << rx_state.rx_status << "error_count " << rx_state.error_count << std::endl;

    return log_message.str();
}

#endif
}
}
