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

#include "sai_mirror.h"
#include "api/npu/la_l2_service_port.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_svi_port.h"
#include "common/la_ip_addr.h"
#include "sai_device.h"
#include "sai_logger.h"
#include <arpa/inet.h>

/*
 *  Salient sai mirror implementation/limitation points to be aware of.
 *      Limitations
 *          - Remote SPAN is not supported.
 *          - SAI attribute congestion mode is not consumed. Take what ASIC provides.
 *          - Varying mirror packet truncate size is not supported. When mirror traffic is truncated,
 *            mirrored packet is upto 255B (or truncate size depends on what is supported by ASIC).
 *          - Per mirror session, a list of mirror destination ports as provided in SAI API is not
 *            implementable. Currently SDK allows single mirror destination port per mirror command.
 *          - Metering/Policing is possible on local mirror session but not in erspan mirroring.
 *          - Mirror destination can be changed/modified in erspan but not for local mirroring
 *          - Mirror destination port cannot be LAG port.
 *          - In a given direction, not more than one mirror session can be attached to a port simultaneously.
 */

/*  Pending work items
 *          - Attach policers to local mirror session and test
 *          - Test egress mirroring
 */

namespace silicon_one
{
namespace sai
{
using namespace std;

// Reserve last two IDs for internal use.
static constexpr int MAX_MIRROR_SESSIONS = 30;
// default constructor for use by automatic serialization tool
sai_mirror::sai_mirror() : m_mirror_db(SAI_OBJECT_TYPE_MIRROR_SESSION, MAX_MIRROR_SESSIONS, 0, 1)
{
}

sai_mirror::sai_mirror(std::shared_ptr<lsai_device> sai_dev)
    : m_sdev(sai_dev), m_mirror_db(SAI_OBJECT_TYPE_MIRROR_SESSION, MAX_MIRROR_SESSIONS, 0, 1)
{
    // SDK has to add new limit-type mirror-session-limit. Until then define constant value here.
    // Once done, use sdk::get_limit_() API to size up m_mirror_db correctly.
    // (SDK code needs to export MAX_MIRROR_GID value)

    la_status lstatus;
    lstatus = m_sdev->m_dev->get_limit(limit_type_e::DEVICE__MIN_INGRESS_MIRROR_GID, m_ingress_gid_offset);

    lstatus = m_sdev->m_dev->get_limit(limit_type_e::DEVICE__MIN_EGRESS_MIRROR_GID, m_egress_gid_offset);
}

sai_mirror::~sai_mirror() = default;

la_status
sai_mirror::allocate_mirror_session_instance(uint32_t& mirror_instance_id)
{
    // Since mirror id values provided to datapath pipeline cannot start from zero,
    // mirror_db will generate index starting from 1
    return m_mirror_db.allocate_id(mirror_instance_id);
}

void
sai_mirror::free_mirror_session_instance(uint32_t mirror_instance_id)
{
    return m_mirror_db.release_id(mirror_instance_id);
}

la_mirror_gid_t
sai_mirror::mirror_session_instance_to_gid(uint32_t mirror_instance_id, bool is_ingress_stage)
{
    if (is_ingress_stage) {
        return (mirror_instance_id + m_ingress_gid_offset);
    } else {
        return (mirror_instance_id + m_egress_gid_offset);
    }
}

uint32_t
sai_mirror::mirror_session_gid_to_instance(la_mirror_gid_t mirror_gid, bool is_ingress_stage)
{
    if (is_ingress_stage) {
        return (mirror_gid - m_ingress_gid_offset);
    } else {
        return (mirror_gid - m_egress_gid_offset);
    }
}

// clang-format off
extern const sai_attribute_entry_t mirror_attribs[] = {
    // id, mandatory_on_create, valid_for_create, valid_for_set, valid_for_get, name
    {SAI_MIRROR_SESSION_ATTR_TYPE, true, true, false, true, "Mirror type", SAI_ATTR_VAL_TYPE_S32},
    {SAI_MIRROR_SESSION_ATTR_MONITOR_PORT, true, true, true, true, "Monitor port", SAI_ATTR_VAL_TYPE_OID},
    {SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE, false, true, true, true, "Truncate size", SAI_ATTR_VAL_TYPE_U16},
    {SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE, false, true, true, true, "Mirror sample rate", SAI_ATTR_VAL_TYPE_U32},
    {SAI_MIRROR_SESSION_ATTR_CONGESTION_MODE, false, true, true, true, "Congestion mode", SAI_ATTR_VAL_TYPE_S32},
    {SAI_MIRROR_SESSION_ATTR_TC, false, true, true, true, "Class of Service", SAI_ATTR_VAL_TYPE_U8},
    {SAI_MIRROR_SESSION_ATTR_VLAN_TPID, false, true, true, true, "L2 header TPID", SAI_ATTR_VAL_TYPE_U16},
    {SAI_MIRROR_SESSION_ATTR_VLAN_ID, false, true, true, true, "L2 header Vlan id", SAI_ATTR_VAL_TYPE_U16},
    {SAI_MIRROR_SESSION_ATTR_VLAN_PRI, false, true, true, true, "L2 header priority", SAI_ATTR_VAL_TYPE_U16},
    {SAI_MIRROR_SESSION_ATTR_VLAN_CFI, false, true, true, true, "L2 header CFI", SAI_ATTR_VAL_TYPE_U8},
    {SAI_MIRROR_SESSION_ATTR_VLAN_HEADER_VALID, false, true, true, true, "L2 header CFI", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_MIRROR_SESSION_ATTR_ERSPAN_ENCAPSULATION_TYPE, true, true, false, true, "Encapsulation type", SAI_ATTR_VAL_TYPE_S32},
    {SAI_MIRROR_SESSION_ATTR_IPHDR_VERSION, true, true, true, true, "Tunnel IP header version", SAI_ATTR_VAL_TYPE_U8},
    {SAI_MIRROR_SESSION_ATTR_TOS, true, true, true, true, "Tunnel header tos", SAI_ATTR_VAL_TYPE_U8},
    {SAI_MIRROR_SESSION_ATTR_TTL, false, true, true, true, "Tunnel header tos", SAI_ATTR_VAL_TYPE_U8},
    {SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS, true, true, true, true, "Tunnel SIP", SAI_ATTR_VAL_TYPE_IPADDR},
    {SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS, true, true, true, true, "Tunnel DIP", SAI_ATTR_VAL_TYPE_IPADDR},
    {SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS, true, true, true, true, "L2 SA", SAI_ATTR_VAL_TYPE_MAC},
    {SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS, true, true, true, true, "L2 DA", SAI_ATTR_VAL_TYPE_MAC},
    {SAI_MIRROR_SESSION_ATTR_GRE_PROTOCOL_TYPE, true, true, true, true, "GRE protocol id", SAI_ATTR_VAL_TYPE_U16},
    {SAI_MIRROR_SESSION_ATTR_MONITOR_PORTLIST_VALID, false, true, false, true, "Monitor port list valid", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_MIRROR_SESSION_ATTR_MONITOR_PORTLIST, true, true, true, true, "Monitor port list", SAI_ATTR_VAL_TYPE_OBJLIST},
    {SAI_MIRROR_SESSION_ATTR_POLICER, false, true, true, true, "Monitor port list", SAI_ATTR_VAL_TYPE_OID},
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    {SAI_MIRROR_SESSION_ATTR_UDP_SRC_PORT, true, true, true, true, "UDP source port", SAI_ATTR_VAL_TYPE_U16},
    {SAI_MIRROR_SESSION_ATTR_UDP_DST_PORT, true, true, true, true, "UDP destination port", SAI_ATTR_VAL_TYPE_U16},
#endif
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

#define MIRROR_SESSION_ATTR_GET(attr_id, out_val, in_val)   \
    case attr_id: {                                         \
        set_attr_value(attr_id, out_val, in_val);           \
        break;                                              \
    }

// clang-format on
sai_status_t
sai_mirror::mirror_attrib_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg)
{
    lsai_object mirror_obj(key->key.object_id);
    auto sdev = mirror_obj.get_device();
    lasai_mirror_session_t session;
    la_status lstatus = sdev->m_mirror_handler->m_mirror_db.get(mirror_obj.index, session);
    sai_return_on_la_error(lstatus);
    if (!session.mirror_cmd_ingress) {
        sai_log_error(SAI_API_MIRROR, "Mirror session oid 0x%lx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    uint32_t attr_id = (uintptr_t)arg;
    switch (attr_id) {
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_TYPE, *value, session.type);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_MONITOR_PORT, *value, session.destport_oid);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE, *value, session.truncate_size);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE, *value, session.sample_rate);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_CONGESTION_MODE, *value, session.congestion_mode);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_TC, *value, session.tc);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_VLAN_TPID, *value, session.tag.tpid);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_VLAN_ID, *value, session.tag.id);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_VLAN_PRI, *value, session.tag.pri);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_VLAN_CFI, *value, session.tag.cfi);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_VLAN_HEADER_VALID, *value, session.vlan_hdr_valid);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_ERSPAN_ENCAPSULATION_TYPE, *value, session.headers.erspan_encap_type);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_IPHDR_VERSION, *value, session.headers.iphdr_ver);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_TOS, *value, session.headers.tos);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_TTL, *value, session.headers.ttl);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS, *value, session.headers.sip);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS, *value, session.headers.dip);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS, *value, session.headers.sa);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS, *value, session.headers.da);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_GRE_PROTOCOL_TYPE, *value, session.headers.gre_proto_type);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_MONITOR_PORTLIST_VALID, *value, session.port_list_valid);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_POLICER, *value, session.policer_oid);
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_UDP_SRC_PORT, *value, session.headers.udp_sport);
        MIRROR_SESSION_ATTR_GET(SAI_MIRROR_SESSION_ATTR_UDP_DST_PORT, *value, session.headers.udp_dport);
#endif
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
        break;
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_mirror::mirror_command_attribute_set(uint32_t attr_id,
                                         lasai_mirror_session_t* session,
                                         la_mirror_command* mirror_cmd,
                                         const sai_attribute_value_t* value)
{
    if (mirror_cmd == nullptr) {
        return SAI_STATUS_FAILURE;
    }

    if (mirror_session_is_local(session->type)) {
        la_status lstatus = LA_STATUS_SUCCESS;
        la_l2_mirror_command* cmd = static_cast<la_l2_mirror_command*>(mirror_cmd);
        switch (attr_id) {
        case SAI_MIRROR_SESSION_ATTR_POLICER:
            // TODO from policer oid get poilcer sdk instance and associate with mirror command
            break;
        case SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE: {
            session->truncate_size = get_attr_value(SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE, (*value));
            bool truncate = (session->truncate_size != 0);
            lstatus = cmd->set_truncate(truncate);
            break;
        }
        case SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE: {
            session->sample_rate = get_attr_value(SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE, (*value));
            lstatus = cmd->set_probability((session->sample_rate) ? (1.0 / session->sample_rate) : 0);
            break;
        }
        case SAI_MIRROR_SESSION_ATTR_TC: {
            session->tc = get_attr_value(SAI_MIRROR_SESSION_ATTR_TC, (*value));
            session->tc_set = true;
            lstatus = cmd->set_voq_offset(session->tc);
            break;
        }
        default:
            // SDK does not let other modifyable attribute like TC to be changed.
            return SAI_STATUS_NOT_IMPLEMENTED;
            break;
        }
        sai_return_on_la_error(lstatus, "Error modifying local mirror attribute");
    } else if (mirror_session_is_remote(session->type)) {
        la_erspan_mirror_command* cmd = static_cast<la_erspan_mirror_command*>(mirror_cmd);
        la_status lstatus = LA_STATUS_SUCCESS;
        switch (attr_id) {
        case SAI_MIRROR_SESSION_ATTR_TOS: {
            session->headers.tos = get_attr_value(SAI_MIRROR_SESSION_ATTR_TOS, (*value));
            la_ip_dscp dscp = {.value = session->headers.tos};
            lstatus = cmd->set_dscp(dscp);
            break;
        }
        case SAI_MIRROR_SESSION_ATTR_TTL: {
            session->headers.ttl = get_attr_value(SAI_MIRROR_SESSION_ATTR_TTL, (*value));
            lstatus = cmd->set_ttl(session->headers.ttl);
            break;
        }
        case SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS: {
            sai_ip_address_t hdr = get_attr_value(SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS, (*value));
            session->headers.sip = hdr;
            la_ip_addr tunnel_source_addr = to_sdk(hdr);
            lstatus = cmd->set_tunnel_source(tunnel_source_addr);
            break;
        }
        case SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS: {
            sai_ip_address_t hdr = get_attr_value(SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS, (*value));
            session->headers.dip = hdr;
            la_ip_addr tunnel_dest_addr = to_sdk(hdr);
            lstatus = cmd->set_tunnel_destination(tunnel_dest_addr);
            break;
        }
        case SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS: {
            get_mac_attr_value(SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS, (*value), session->headers.sa);
            la_mac_addr_t src_mac;
            reverse_copy(std::begin(session->headers.sa), std::end(session->headers.sa), src_mac.bytes);
            lstatus = cmd->set_source_mac(src_mac);
            break;
        }
        case SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS: {
            get_mac_attr_value(SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS, (*value), session->headers.da);
            la_mac_addr_t dst_mac;
            reverse_copy(std::begin(session->headers.da), std::end(session->headers.da), dst_mac.bytes);
            lstatus = cmd->set_mac(dst_mac);
            break;
        }
        case SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE: {
            session->sample_rate = get_attr_value(SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE, (*value));
            lstatus = cmd->set_probability((session->sample_rate) ? (1.0 / session->sample_rate) : 0);
            break;
        }

        case SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE: {
            session->truncate_size = get_attr_value(SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE, (*value));
            bool truncate = (session->truncate_size != 0);
            lstatus = cmd->set_truncate(truncate);
            break;
        }
        case SAI_MIRROR_SESSION_ATTR_MONITOR_PORT: {
            la_ethernet_port* eth_port = nullptr;
            la_system_port* sys_port = nullptr;
            // Get destport_oid and convert to sys_port needed to update mirror session
            session->destport_oid = get_attr_value(SAI_MIRROR_SESSION_ATTR_MONITOR_PORT, (*value));
            sai_status_t status = get_mirror_destination_port_details(session->destport_oid, eth_port, sys_port);
            sai_return_on_error(status);

            // Update destport on current mirror session
            lstatus = cmd->set_egress_port(sys_port);
            break;
        }

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
        case SAI_MIRROR_SESSION_ATTR_UDP_SRC_PORT: {
            if (session->type != SAI_MIRROR_SESSION_TYPE_SFLOW) {
                sai_log_error(SAI_API_MIRROR,
                              "Mirror session attribute set failed. Can set udp source on a sflow mirror session alone.");
                return SAI_STATUS_INVALID_PARAMETER;
            }
            session->headers.udp_sport = get_attr_value(SAI_MIRROR_SESSION_ATTR_UDP_SRC_PORT, (*value));
            lstatus = cmd->set_source_port(session->headers.udp_sport);
            break;
        }
        case SAI_MIRROR_SESSION_ATTR_UDP_DST_PORT: {
            if (session->type != SAI_MIRROR_SESSION_TYPE_SFLOW) {
                sai_log_error(SAI_API_MIRROR,
                              "Mirror session attribute set failed. Can set udp destination on a sflow mirror session alone.");
                return SAI_STATUS_INVALID_PARAMETER;
            }
            session->headers.udp_dport = get_attr_value(SAI_MIRROR_SESSION_ATTR_UDP_DST_PORT, (*value));
            lstatus = cmd->set_destination_port(session->headers.udp_dport);
            break;
        }
        case SAI_MIRROR_SESSION_ATTR_VLAN_TPID: {
            if (!session->vlan_hdr_valid) {
                sai_log_error(SAI_API_MIRROR,
                              "Mirror session attribute set failed. Can set vlan tpid on a vlan tagged session only");
                return SAI_STATUS_INVALID_PARAMETER;
            }
            session->tag.tpid = get_attr_value(SAI_MIRROR_SESSION_ATTR_VLAN_TPID, (*value));
            lstatus = cmd->set_egress_vlan_tag(convert_vlan_tag_info(*session));
            break;
        }

        case SAI_MIRROR_SESSION_ATTR_VLAN_ID: {
            if (!session->vlan_hdr_valid) {
                sai_log_error(SAI_API_MIRROR, "Mirror session attribute set failed. Can set vid on a vlan tagged session only");
                return SAI_STATUS_INVALID_PARAMETER;
            }
            session->tag.id = get_attr_value(SAI_MIRROR_SESSION_ATTR_VLAN_ID, (*value));
            lstatus = cmd->set_egress_vlan_tag(convert_vlan_tag_info(*session));
            break;
        }

        case SAI_MIRROR_SESSION_ATTR_VLAN_PRI: {
            if (!session->vlan_hdr_valid) {
                sai_log_error(SAI_API_MIRROR, "Mirror session attribute set failed. Can set pri on a vlan tagged session only");
                return SAI_STATUS_INVALID_PARAMETER;
            }
            session->tag.pri = get_attr_value(SAI_MIRROR_SESSION_ATTR_VLAN_PRI, (*value));
            lstatus = cmd->set_egress_vlan_tag(convert_vlan_tag_info(*session));
            break;
        }

        case SAI_MIRROR_SESSION_ATTR_VLAN_CFI: {
            if (!session->vlan_hdr_valid) {
                sai_log_error(SAI_API_MIRROR, "Mirror session attribute set failed. Can set cfi on a vlan tagged session only");
                return SAI_STATUS_INVALID_PARAMETER;
            }
            session->tag.cfi = get_attr_value(SAI_MIRROR_SESSION_ATTR_VLAN_CFI, (*value));
            lstatus = cmd->set_egress_vlan_tag(convert_vlan_tag_info(*session));
            break;
        }

        case SAI_MIRROR_SESSION_ATTR_VLAN_HEADER_VALID: {
            session->vlan_hdr_valid = get_attr_value(SAI_MIRROR_SESSION_ATTR_VLAN_HEADER_VALID, (*value));
            if (session->vlan_hdr_valid) {
                lstatus = cmd->set_egress_vlan_tag(convert_vlan_tag_info(*session));
            } else {
                lstatus = cmd->set_egress_vlan_tag(LA_VLAN_TAG_UNTAGGED);
            }
            break;
        }
        case SAI_MIRROR_SESSION_ATTR_TC: {
            session->tc = get_attr_value(SAI_MIRROR_SESSION_ATTR_TC, (*value));
            session->tc_set = true;
            lstatus = cmd->set_voq_offset(session->tc);
            break;
        }
#endif
        default:
            // All other erspan attr are not mutable once erspan is created.
            return SAI_STATUS_NOT_IMPLEMENTED;
            break;
        }
        sai_return_on_la_error(lstatus, "Error modifying remote mirror/sflow attribute");
    }

    return SAI_STATUS_SUCCESS;
}

// Modify/Update only mutable mirror session attributes. Mutable attribute set
// can be smaller than what sai spec requires due to fwd device/sw limitation.
sai_status_t
sai_mirror::mirror_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object mirror_obj(key->key.object_id);
    auto sdev = mirror_obj.get_device();
    lasai_mirror_session_t* session = sdev->m_mirror_handler->m_mirror_db.get_ptr(mirror_obj.index);
    if (session == nullptr) {
        sai_log_error(SAI_API_MIRROR, "Mirror session oid 0x%lx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    uint32_t attr_id = (uintptr_t)arg;
    sai_status_t status
        = sdev->m_mirror_handler->mirror_command_attribute_set(attr_id, session, session->mirror_cmd_ingress, value);
    sai_return_on_error(status);
    if (session->mirror_cmd_egress) {
        status = sdev->m_mirror_handler->mirror_command_attribute_set(attr_id, session, session->mirror_cmd_egress, value);
        sai_return_on_error(status);
    }
    sai_log_debug(SAI_API_MIRROR, "Mirror session's 0x%lx attribute %d updated.", key->key.object_id, attr_id);

    if (attr_id != SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE) {
        // Since mirror object property is changed, apply the same change to all mirror instances
        // used for sampling. Sampling mirror instances are cloned using this mirror object; Hence
        // it is required to apply the change.
        // Note - When sampling rate on mirror object is modified, sampling rate is not applied
        // on mirror instances used for packet sampling.
        uint8_t mirror_sample_instances_updated_count = 0;
        for (auto& per_port_sample : session->per_port_ingress_sample_mirrors) {
            sai_status_t status = sdev->m_mirror_handler->mirror_command_attribute_set(
                attr_id, session, per_port_sample.second.sample_mirror_cmd, value);
            sai_return_on_error(status);
            ++mirror_sample_instances_updated_count;
        }

        for (auto& per_port_sample : session->per_port_egress_sample_mirrors) {
            sai_status_t status = sdev->m_mirror_handler->mirror_command_attribute_set(
                attr_id, session, per_port_sample.second.sample_mirror_cmd, value);
            sai_return_on_error(status);
            ++mirror_sample_instances_updated_count;
        }

        if (mirror_sample_instances_updated_count) {
            sai_log_debug(SAI_API_MIRROR,
                          "Apply Mirror session's 0x%lx attribute %d on mirror sample instances too. %d mirror sample instances "
                          "updated to match the change in mirror attribute.",
                          key->key.object_id,
                          attr_id,
                          mirror_sample_instances_updated_count);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static const sai_vendor_attribute_entry_t mirror_vendor_attribs[] = {
    SAI_ATTR_CREATE_ONLY(SAI_MIRROR_SESSION_ATTR_TYPE, sai_mirror::mirror_attrib_get),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_MONITOR_PORT, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_CONGESTION_MODE, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_TC, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_VLAN_TPID, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_VLAN_ID, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_VLAN_PRI, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_VLAN_CFI, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_VLAN_HEADER_VALID,
                            sai_mirror::mirror_attrib_get,
                            sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_ONLY(SAI_MIRROR_SESSION_ATTR_ERSPAN_ENCAPSULATION_TYPE, sai_mirror::mirror_attrib_get),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_IPHDR_VERSION, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_TOS, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_TTL, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_GRE_PROTOCOL_TYPE,
                            sai_mirror::mirror_attrib_get,
                            sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_MONITOR_PORTLIST_VALID,
                            sai_mirror::mirror_attrib_get,
                            sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_MONITOR_PORTLIST, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_POLICER, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_UDP_SRC_PORT, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set),
    SAI_ATTR_CREATE_AND_SET(SAI_MIRROR_SESSION_ATTR_UDP_DST_PORT, sai_mirror::mirror_attrib_get, sai_mirror::mirror_attrib_set)
#endif
};

// clang-format on

// convert mirror session attribute to string for logging purposes.
std::string
sai_mirror::mirror_session_attr_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_mirror_session_attr_t)attr.id;
    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value);
    return log_message.str();
}

// parses mirror session attributes as well as returns error in case
// invalid values or unsupported attributes
sai_status_t
sai_mirror::parse_session_attributes(const std::shared_ptr<lsai_device>& sdev,
                                     const std::unordered_map<sai_attr_id_t, sai_attribute_value_t>& attrs,
                                     lasai_mirror_session_t& session)
{
    session.truncate_size = 0; // Default value of zero is no truncate
    session.sample_rate = 1;   // 0 => no sampling, 1 is default value, otherwise mirror 1/sample-rate.
    session.congestion_mode = SAI_MIRROR_SESSION_CONGESTION_MODE_INDEPENDENT;
    session.vlan_hdr_valid = false; // default
    get_attrs_value(SAI_MIRROR_SESSION_ATTR_TRUNCATE_SIZE, attrs, session.truncate_size, false);
    get_attrs_value(SAI_MIRROR_SESSION_ATTR_SAMPLE_RATE, attrs, session.sample_rate, false);
    get_attrs_value(SAI_MIRROR_SESSION_ATTR_CONGESTION_MODE, attrs, session.congestion_mode, false);
    get_attrs_value(SAI_MIRROR_SESSION_ATTR_POLICER, attrs, session.policer_oid, false);

    session.tc = SAI_MIRROR_TC_VAL_DISABLED;
    session.tc_set = false;
    get_attrs_value(SAI_MIRROR_SESSION_ATTR_TC, attrs, session.tc, false);
    if (session.tc != SAI_MIRROR_TC_VAL_DISABLED) {
        session.tc_set = true;
    } else if (sdev->m_mirror_handler->m_switch_attr_mirror_tc_val != SAI_MIRROR_TC_VAL_DISABLED) {
        session.tc = sdev->m_mirror_handler->m_switch_attr_mirror_tc_val;
    } else {
        // No TC configuration .. default to 0
        session.tc = 0;
    }

    switch (session.type) {
    case SAI_MIRROR_SESSION_TYPE_LOCAL:
        break;
    case SAI_MIRROR_SESSION_TYPE_REMOTE:
        return SAI_STATUS_NOT_IMPLEMENTED;
        break;
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    case SAI_MIRROR_SESSION_TYPE_SFLOW:
#endif
    case SAI_MIRROR_SESSION_TYPE_ENHANCED_REMOTE:
        get_attrs_value(SAI_MIRROR_SESSION_ATTR_VLAN_HEADER_VALID, attrs, session.vlan_hdr_valid, false);
        break;
    default:
        // error
        break;
    }

    session.port_list_valid = false;
    get_attrs_value(SAI_MIRROR_SESSION_ATTR_MONITOR_PORTLIST_VALID, attrs, session.port_list_valid, false);
    if (session.port_list_valid) {
        return SAI_STATUS_NOT_IMPLEMENTED;
    } else {
        get_attrs_value(SAI_MIRROR_SESSION_ATTR_MONITOR_PORT, attrs, session.destport_oid, true);
        if (session.destport_oid == SAI_NULL_OBJECT_ID) {
            sai_log_error(SAI_API_MIRROR, "Mirror session creation failed. Monitor port 0x%lx is invalid.", session.destport_oid);
            return SAI_STATUS_FAILURE;
        }

        lsai_object port_obj(session.destport_oid);
        lsai_object la_obj(session.switch_oid);
        if (la_obj.switch_id != port_obj.switch_id) {
            sai_log_error(SAI_API_MIRROR,
                          "Mirror session creation failed. Monitor port 0x%lx is invalid. Port does not belong to the switch",
                          session.destport_oid);
            return SAI_STATUS_FAILURE;
        }
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_mirror::parse_tag_attributes(const std::unordered_map<sai_attr_id_t, sai_attribute_value_t>& attrs, lasai_vlan_tag_t& tag)
{
    tag.tpid = 0;
    tag.id = 0;
    tag.pri = 0;
    tag.cfi = 0;
    get_attrs_value(SAI_MIRROR_SESSION_ATTR_VLAN_TPID, attrs, tag.tpid, false);
    get_attrs_value(SAI_MIRROR_SESSION_ATTR_VLAN_ID, attrs, tag.id, false);
    get_attrs_value(SAI_MIRROR_SESSION_ATTR_VLAN_PRI, attrs, tag.pri, false);
    get_attrs_value(SAI_MIRROR_SESSION_ATTR_VLAN_CFI, attrs, tag.cfi, false);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_mirror::switch_mirror_tc_attr_val_set(uint8_t tc)
{
    // 255 means disable global TC value for all mirrors
    // Only 0-7 supported for mirror packets.
    if (tc > 7 && tc != SAI_MIRROR_TC_VAL_DISABLED) {
        sai_log_error(SAI_API_MIRROR, "invalid global tc %d", tc);
        return SAI_STATUS_INVALID_ATTR_VALUE_0; // attr index is not known. using 0
    }
    if (m_switch_attr_mirror_tc_val == tc) {
        return SAI_STATUS_SUCCESS;
    }

    m_switch_attr_mirror_tc_val = tc;

    /* update all existing mirror sessions that don't have TC set explicitly  */
    auto& all_mirror_sessions = m_mirror_db.map();
    for (auto& session : all_mirror_sessions) {
        if (!session.second.tc_set) {
            session.second.tc = m_switch_attr_mirror_tc_val == SAI_MIRROR_TC_VAL_DISABLED ? 0 : m_switch_attr_mirror_tc_val;
            auto lstatus = session.second.mirror_cmd_ingress->set_voq_offset(session.second.tc);
            sai_return_on_la_error(lstatus);
        }
    }
    return SAI_STATUS_SUCCESS;
}

// parses ip tunnel related attributes

#define PARSE_IPTUNNEL_ATTRIBUTES(attrs, hdr)                                                                                      \
    {                                                                                                                              \
        hdr.ttl = 255;                                                                                                             \
        get_attrs_value(SAI_MIRROR_SESSION_ATTR_TTL, attrs, hdr.ttl, false);                                                       \
        get_attrs_value(SAI_MIRROR_SESSION_ATTR_IPHDR_VERSION, attrs, hdr.iphdr_ver, true);                                        \
        get_attrs_value(SAI_MIRROR_SESSION_ATTR_TOS, attrs, hdr.tos, true);                                                        \
        get_attrs_value(SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS, attrs, hdr.sip, true);                                             \
        get_attrs_value(SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS, attrs, hdr.dip, true);                                             \
        if (hdr.sip.addr_family != hdr.dip.addr_family) {                                                                          \
            return SAI_STATUS_INVALID_PARAMETER;                                                                                   \
        }                                                                                                                          \
    }

#define PARSE_ETHERNET_HDR_ATTRIBUTES(attrs, hdr)                                                                                  \
    {                                                                                                                              \
        get_mac_attrs_value(SAI_MIRROR_SESSION_ATTR_SRC_MAC_ADDRESS, attrs, hdr.sa, true);                                         \
        get_mac_attrs_value(SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS, attrs, hdr.da, true);                                         \
    }

// parses erspan session related attributes as well as returns error in case
// invalid values or unsupported attributes
sai_status_t
sai_mirror::parse_erspan_attributes(const std::unordered_map<sai_attr_id_t, sai_attribute_value_t>& attrs,
                                    lasai_mirror_headers_t& hdr)
{
    PARSE_IPTUNNEL_ATTRIBUTES(attrs, hdr);
    PARSE_ETHERNET_HDR_ATTRIBUTES(attrs, hdr);
    get_attrs_value(SAI_MIRROR_SESSION_ATTR_GRE_PROTOCOL_TYPE, attrs, hdr.gre_proto_type, true);
    if (hdr.gre_proto_type != 0x88BE) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    get_attrs_value(SAI_MIRROR_SESSION_ATTR_ERSPAN_ENCAPSULATION_TYPE, attrs, hdr.erspan_encap_type, true);
    if (hdr.erspan_encap_type != SAI_ERSPAN_ENCAPSULATION_TYPE_MIRROR_L3_GRE_TUNNEL) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
// parses sflow session related attributes as well as returns error in case
// invalid values or unsupported attributes
sai_status_t
sai_mirror::parse_sflow_attributes(const std::unordered_map<sai_attr_id_t, sai_attribute_value_t>& attrs,
                                   lasai_mirror_headers_t& hdr)
{
    PARSE_IPTUNNEL_ATTRIBUTES(attrs, hdr);
    PARSE_ETHERNET_HDR_ATTRIBUTES(attrs, hdr);

    // Fetch mandatory attrib UDP SPORT and DPORT
    get_attrs_value(SAI_MIRROR_SESSION_ATTR_UDP_SRC_PORT, attrs, hdr.udp_sport, true);
    get_attrs_value(SAI_MIRROR_SESSION_ATTR_UDP_DST_PORT, attrs, hdr.udp_dport, true);

    return SAI_STATUS_SUCCESS;
}
#endif

// collect all mirror sessions that the port applies.
void
sai_mirror::get_all_mirror_sessions_on_port(port_lag_common* service,
                                            bool is_ingress_stage,
                                            std::vector<sai_object_id_t>& mirror_sessions)
{
    const auto& all_mirror_sessions = m_mirror_db.map();
    if (all_mirror_sessions.empty()) {
        // no mirror session active.
        return;
    }

    for (const auto& mirror_session : all_mirror_sessions) {
        if (is_ingress_stage) {
            if (mirror_session.second.ingress_mirrored_port_oids.find(service->oid)
                != mirror_session.second.ingress_mirrored_port_oids.end()) {
                mirror_sessions.push_back(mirror_session.second.session_oid);
            }
        } else {
            if (mirror_session.second.egress_mirrored_port_oids.find(service->oid)
                != mirror_session.second.egress_mirrored_port_oids.end()) {
                mirror_sessions.push_back(mirror_session.second.session_oid);
            }
        }
    }
}

sai_status_t
sai_mirror::update_mirror_command_on_port(la_object* la_port,
                                          bool is_ingress_stage,
                                          la_mirror_command* mirror_cmd,
                                          bool is_acl_conditioned)
{
    if (la_port == nullptr) {
        sai_log_error(SAI_API_MIRROR, "Invalid port object. Could not attach mirror session to port");
        return SAI_STATUS_FAILURE;
    }

    la_status lstatus = LA_STATUS_SUCCESS;
    switch (la_port->type()) {
    case la_object::object_type_e::L3_AC_PORT: {
        la_l3_port* l3_port = static_cast<la_l3_ac_port*>(la_port);
        if (is_ingress_stage) {
            lstatus = l3_port->set_ingress_mirror_command(mirror_cmd, is_acl_conditioned);
        } else {
            lstatus = l3_port->set_egress_mirror_command(mirror_cmd, is_acl_conditioned);
        }

        break;
    }
    case la_object::object_type_e::L2_SERVICE_PORT: {
        la_l2_service_port* l2_port = static_cast<la_l2_service_port*>(la_port);
        if (is_ingress_stage) {
            lstatus = l2_port->set_ingress_mirror_command(mirror_cmd, is_acl_conditioned);
        } else {
            lstatus = l2_port->set_egress_mirror_command(mirror_cmd, is_acl_conditioned);
        }

        break;
    }
    case la_object::object_type_e::SVI_PORT: {
        la_svi_port* svi_port = static_cast<la_svi_port*>(la_port);
        if (is_ingress_stage) {
            lstatus = svi_port->set_ingress_mirror_command(mirror_cmd, is_acl_conditioned);
        } else {
            lstatus = svi_port->set_egress_mirror_command(mirror_cmd, is_acl_conditioned);
        }
    }
    default:
        break;
    }
    sai_return_on_la_error(lstatus, "Failed to update mirror command on port object");
    return SAI_STATUS_SUCCESS;
}

// Mirror command is attached or detached on the port where mirroring
// has to occur, either in ingress direction of egress direction.
sai_status_t
sai_mirror::update_mirror_command_on_port(sai_object_id_t port_oid,
                                          bool is_ingress_stage,
                                          la_mirror_command* mirror_cmd,
                                          bool is_acl_conditioned)
{
    lsai_object port_obj(port_oid);
    auto sdev = port_obj.get_device();

    sai_status_t status = SAI_STATUS_SUCCESS;

    if (IS_SAI_SERVICE_PORT(port_obj)) {
        port_lag_common* service = nullptr;
        la_status lstatus = sai_port_get_service(sdev, port_oid, service);
        sai_return_on_la_error(lstatus);

        if (service == nullptr) {
            return SAI_STATUS_SUCCESS;
        }

        if (service->eth_port == nullptr) {
            sai_log_error(SAI_API_MIRROR, "Unknown device object for port oid 0x%lx", port_oid);
            status = SAI_STATUS_FAILURE;
        }

        // Attach mirror to all constituent logical ports of the physical port
        std::vector<la_object*> la_port_objs = sdev->m_dev->get_dependent_objects(service->eth_port);
        for (la_object* la_port : la_port_objs) {
            status = update_mirror_command_on_port(la_port, is_ingress_stage, mirror_cmd, is_acl_conditioned);
        }
        sai_return_on_la_error(lstatus, "Failed to update mirror command on port 0x%lx", port_oid);
        auto gress = (is_ingress_stage) ? "Ingress" : "Egress";
        auto ops = (mirror_cmd == nullptr) ? "detached" : "attached";
        sai_log_debug(SAI_API_MIRROR, "%s mirror session %s to all logical ports of port 0x%llx.", gress, ops, port_oid);
    } else if (port_obj.type == SAI_OBJECT_TYPE_ROUTER_INTERFACE) {
        rif_entry rif;
        la_status lstatus = sdev->m_l3_ports.get(port_obj.index, rif);
        sai_return_on_la_error(lstatus, "Unknown port oid 0x%lx", port_oid);
        if (rif.l3_port == nullptr) {
            sai_log_error(SAI_API_MIRROR, "Unknown device object for port oid 0x%lx", port_oid);
            status = SAI_STATUS_FAILURE;
        }

        status = update_mirror_command_on_port(rif.l3_port, is_ingress_stage, mirror_cmd, is_acl_conditioned);
    } else if (port_obj.type == SAI_OBJECT_TYPE_BRIDGE_PORT || port_obj.type == SAI_OBJECT_TYPE_VLAN_MEMBER) {
        bridge_port_entry bridge_port{};
        la_status lstatus = sdev->m_bridge_ports.get(port_obj.index, bridge_port);
        sai_return_on_la_error(lstatus, "Unknown port oid 0x%lx", port_oid);
        if (bridge_port.l2_port == nullptr) {
            sai_log_error(SAI_API_MIRROR, "Unknown device object for port oid 0x%lx", port_oid);
            status = SAI_STATUS_FAILURE;
        }

        status = update_mirror_command_on_port(bridge_port.l2_port, is_ingress_stage, mirror_cmd, is_acl_conditioned);
    } else {
        sai_log_error(SAI_API_MIRROR, "Unknown port oid 0x%lx type", port_oid);
        status = SAI_STATUS_FAILURE;
    }
    sai_return_on_error(status, "Failed to update mirror command on port 0x%lx", port_oid);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_mirror::validate_mirror_session_oid(sai_object_id_t port_oid,
                                        sai_object_id_t mirror_session_oid,
                                        lasai_mirror_session_t& session)
{
    lsai_object port_obj(port_oid);
    lsai_object mirror_obj(mirror_session_oid);
    if (mirror_obj.switch_id != port_obj.switch_id) {
        sai_log_error(SAI_API_MIRROR,
                      "Switch id of mirror session oid 0x%lx is not same as switch id of port oid",
                      mirror_session_oid,
                      port_oid);
        return SAI_STATUS_FAILURE;
    }

    auto sdev = mirror_obj.get_device();
    sai_check_object(mirror_obj, SAI_OBJECT_TYPE_MIRROR_SESSION, sdev, "mirror_session", mirror_session_oid);

    la_status lstatus = m_mirror_db.get(mirror_obj.index, session);
    sai_return_on_la_error(lstatus);
    if (session.mirror_cmd_ingress == nullptr) {
        sai_log_error(SAI_API_MIRROR, "Mirror session oid 0x%lx is unrecognized", mirror_session_oid);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

// Detach a mirror session from a port.
sai_status_t
sai_mirror::do_detach_mirror_session(sai_object_id_t port_oid, sai_object_id_t mirror_session_oid, bool is_ingress_stage)
{
    lasai_mirror_session_t session;
    sai_status_t status = validate_mirror_session_oid(port_oid, mirror_session_oid, session);
    sai_return_on_error(status, "Failed to validate mirror session oid 0x%lx", mirror_session_oid);
    std::set<sai_object_id_t>* port_oid_set = nullptr;
    if (is_ingress_stage) {
        port_oid_set = &(session.ingress_mirrored_port_oids);
    } else {
        port_oid_set = &(session.egress_mirrored_port_oids);
    }

    auto gress = (is_ingress_stage) ? "ingress" : "egress";
    status = update_mirror_command_on_port(port_oid, is_ingress_stage, nullptr, false /* is_acl_conditioned */);
    sai_return_on_error(status, "Could not detach %s mirror session to port 0x%lx", gress, port_oid);
    // In case of port, update oid set associated with mirror session to include new port.
    // For logical ports are not tracked against mirror session. Currently SAI spec
    // attaches mirror/s to port.
    lsai_object port_obj(port_oid);
    if (IS_SAI_SERVICE_PORT(port_obj)) {
        port_oid_set->erase(port_oid);
        lsai_object mirror_obj(mirror_session_oid);
        la_status lstatus = m_mirror_db.set(mirror_obj.index, session);
        sai_return_on_la_error(lstatus);
    }

    return SAI_STATUS_SUCCESS;
}

// Detach all mirror sessions in either ingress/egress direction that are
// already attached to a port; initiated by SAI PORT API opertaion.
sai_status_t
sai_mirror::detach_mirror_sessions(sai_object_id_t port_oid, bool is_ingress_stage)
{
    lsai_object port_obj(port_oid);
    auto sdev = port_obj.get_device();

    port_lag_common* service = nullptr;
    la_status lstatus = sai_port_get_service(sdev, port_oid, service);
    sai_return_on_la_error(lstatus);

    if (service == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    std::vector<sai_object_id_t> mirror_sessions{};
    get_all_mirror_sessions_on_port(service, is_ingress_stage, mirror_sessions);
    if (mirror_sessions.empty()) {
        // no mirror session active.
        return SAI_STATUS_SUCCESS;
    }

    auto gress = (is_ingress_stage) ? "ingress" : "egress";
    for (auto mirror_session_oid : mirror_sessions) {
        sai_status_t status = do_detach_mirror_session(port_oid, mirror_session_oid, is_ingress_stage);
        sai_return_on_error(status, "Could not detach %s mirror session from port 0x%lx", gress, port_oid);
        sai_log_debug(SAI_API_MIRROR, "Successfully detached %s mirror session from port 0x%lx", gress, port_oid);
    }

    return SAI_STATUS_SUCCESS;
}

// Detach from logical port a set of mirror sessions in ingress and/or egress direction
// as well as packet sampling related mirror sessions that are already attached to
// underlying port. Triggered by deletion of logical port created over underlying port.
sai_status_t
sai_mirror::detach_mirror_sessions(sai_object_id_t logical_port_oid, sai_object_id_t underlying_port_oid)
{
    lsai_object port_obj(underlying_port_oid);

    auto sdev = port_obj.get_device();
    if (sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    port_lag_common* service = nullptr;
    la_status lstatus = sai_port_get_service(sdev, underlying_port_oid, service);
    sai_return_on_la_error(lstatus);

    if (service == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    lsai_object lport_obj(logical_port_oid);
    if (IS_SAI_SERVICE_PORT(lport_obj)) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // get all mirror sessions of the underlying port
    std::vector<sai_object_id_t> ingress_mirror_session_oids{};
    get_all_mirror_sessions_on_port(service, true /* is_ingress_stage */, ingress_mirror_session_oids);
    std::vector<sai_object_id_t> egress_mirror_session_oids{};
    get_all_mirror_sessions_on_port(service, false /* is_ingress_stage */, egress_mirror_session_oids);

    // Get slow path packet sampling mirror session.
    sai_object_id_t ingress_psample_mirror_oid, egress_psample_mirror_oid;
    sai_status_t status
        = get_slow_path_packet_sample_mirror_session(sdev, service, ingress_psample_mirror_oid, egress_psample_mirror_oid);
    sai_return_on_error(status, "Erroring finding packet sample mirror session from port 0x%lx", logical_port_oid);

    if (ingress_psample_mirror_oid != SAI_NULL_OBJECT_ID) {
        ingress_mirror_session_oids.push_back(ingress_psample_mirror_oid);
    }

    if (egress_psample_mirror_oid != SAI_NULL_OBJECT_ID) {
        egress_mirror_session_oids.push_back(egress_psample_mirror_oid);
    }

    if (ingress_mirror_session_oids.empty() && egress_mirror_session_oids.empty()) {
        // No active mirror sessions or packet sampling session to detach.
        return SAI_STATUS_SUCCESS;
    }

    // Detach all mirror sessions of underlying port to logical port
    for (auto oid : ingress_mirror_session_oids) {
        sai_status_t status = do_detach_mirror_session(logical_port_oid, oid, true /*is_ingress_stage*/);
        sai_return_on_error(status, "Could not detach ingress mirror session to port 0x%lx", logical_port_oid);
    }

    for (auto oid : egress_mirror_session_oids) {
        sai_status_t status = do_detach_mirror_session(logical_port_oid, oid, false /*is_ingress_stage*/);
        sai_return_on_error(status, "Could not detach egress mirror session to port 0x%lx", logical_port_oid);
    }

    return SAI_STATUS_SUCCESS;
}

// Attach mirror session to a port either in ingress or egress direction
sai_status_t
sai_mirror::do_attach_mirror_session(sai_object_id_t port_oid, sai_object_id_t mirror_session_oid, bool is_ingress_stage)
{
    lasai_mirror_session_t session;
    sai_status_t status = validate_mirror_session_oid(port_oid, mirror_session_oid, session);
    sai_return_on_error(status, "Failed to validate mirror session oid 0x%lx", mirror_session_oid);
    auto gress = (is_ingress_stage) ? "ingress" : "egress";
    std::set<sai_object_id_t>* port_oid_set = nullptr;
    if (is_ingress_stage) {
        port_oid_set = &(session.ingress_mirrored_port_oids);
    } else {
        port_oid_set = &(session.egress_mirrored_port_oids);
    }

    lsai_object port_obj(port_oid);
    if (IS_SAI_SERVICE_PORT(port_obj)) {
        // In case of port, check if mirror session is already attached.
        if (port_oid_set->find(port_oid) != port_oid_set->end()) {
            // mirror session already attached.
            sai_log_debug(
                SAI_API_MIRROR, "Mirror session 0x%lx is already %s attached on port 0x%lx.", mirror_session_oid, gress, port_oid);
            return SAI_STATUS_SUCCESS;
        }
    }

    auto mirror_cmd = is_ingress_stage ? session.mirror_cmd_ingress : session.mirror_cmd_egress;
    status = update_mirror_command_on_port(port_oid, is_ingress_stage, mirror_cmd, false /* not conditional */);
    sai_return_on_error(status, "Could not attach %s mirror session to port 0x%lx", gress, port_oid);

    // In case of port, update oid set associated with mirror session to include new port.
    // Logical ports are not tracked against mirror session. Currently SAI spec
    // attaches mirror/s to port.
    if (IS_SAI_SERVICE_PORT(port_obj)) {
        port_oid_set->insert(port_oid);
        lsai_object mirror_obj(mirror_session_oid);
        la_status lstatus = m_mirror_db.set(mirror_obj.index, session);
        sai_return_on_la_error(lstatus);
    }
    sai_log_debug(SAI_API_MIRROR, "Successfully attached %s mirror session to port 0x%lx", gress, port_oid);

    return SAI_STATUS_SUCCESS;
}

// Attach a set of mirror sessions to a port either in ingress or egress direction.
// Used by sai port api to bind mirror session to port
sai_status_t
sai_mirror::attach_mirror_sessions(sai_object_id_t port_oid,
                                   bool is_ingress_stage,
                                   const std::vector<sai_object_id_t>& mirror_session_oids)
{
    for (auto oid : mirror_session_oids) {
        sai_status_t status = do_attach_mirror_session(port_oid, oid, is_ingress_stage);
        sai_return_on_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

// Attach to logical port a set of mirror sessions in ingress and/or egress direction
// that are already attached to underlying port. Used when a new logical port is created.
sai_status_t
sai_mirror::attach_mirror_sessions(sai_object_id_t logical_port_oid, sai_object_id_t underlying_port_oid)
{
    lsai_object port_obj(underlying_port_oid);
    auto sdev = port_obj.get_device();
    if (sdev == nullptr || (port_obj.type != SAI_OBJECT_TYPE_PORT && port_obj.type != SAI_OBJECT_TYPE_LAG)) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    port_lag_common* service = nullptr;
    la_status lstatus = sai_port_get_service(sdev, underlying_port_oid, service);
    sai_return_on_la_error(lstatus);

    if (service == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    lsai_object lport_obj(logical_port_oid);
    if (IS_SAI_SERVICE_PORT(lport_obj)) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // get all mirror sessions of the underlying port
    std::vector<sai_object_id_t> ingress_mirror_session_oids{};
    get_all_mirror_sessions_on_port(service, true /* is_ingress_stage */, ingress_mirror_session_oids);
    std::vector<sai_object_id_t> egress_mirror_session_oids{};
    get_all_mirror_sessions_on_port(service, false /* is_ingress_stage */, egress_mirror_session_oids);

    // Get slow path packet sampling mirror session.
    sai_object_id_t ingress_psample_mirror_oid, egress_psample_mirror_oid;
    get_slow_path_packet_sample_mirror_session(sdev, service, ingress_psample_mirror_oid, egress_psample_mirror_oid);

    if (ingress_psample_mirror_oid != SAI_NULL_OBJECT_ID) {
        ingress_mirror_session_oids.push_back(ingress_psample_mirror_oid);
    }

    if (egress_psample_mirror_oid != SAI_NULL_OBJECT_ID) {
        egress_mirror_session_oids.push_back(egress_psample_mirror_oid);
    }

    if (ingress_mirror_session_oids.empty() && egress_mirror_session_oids.empty()) {
        // No active mirror sessions.
        return SAI_STATUS_SUCCESS;
    }

    // attach all mirror sessions of underlying port to logical port
    for (auto oid : ingress_mirror_session_oids) {
        sai_status_t status = do_attach_mirror_session(logical_port_oid, oid, true /*is_ingress_stage*/);
        sai_return_on_error(status, "Could not attach ingress mirror session to port 0x%lx", logical_port_oid);
    }
    sai_log_debug(SAI_API_MIRROR, "Attached all ingress mirror sessions to all logical ports of port 0x%llx.", underlying_port_oid);

    for (auto oid : egress_mirror_session_oids) {
        sai_status_t status = do_attach_mirror_session(logical_port_oid, oid, false /*is_ingress_stage*/);
        sai_return_on_error(status, "Could not attach egress mirror session to port 0x%lx", logical_port_oid);
    }
    sai_log_debug(SAI_API_MIRROR, "Attached all egress mirror sessions to all logical ports of port 0x%llx.", underlying_port_oid);

    return SAI_STATUS_SUCCESS;
}

// Using mirror destination / mirror monitor port, fetch port details and
// underlying port types requried for creating mirror command.
sai_status_t
sai_mirror::get_mirror_destination_port_details(sai_object_id_t mirror_dest_port_oid,
                                                la_ethernet_port*& out_eth_port,
                                                la_system_port*& out_sys_port)
{
    lsai_object destport_obj(mirror_dest_port_oid);
    auto sdev = destport_obj.get_device();
    uint32_t port_index = 0;
    if (destport_obj.type != SAI_OBJECT_TYPE_LAG) {
        if (destport_obj.type == SAI_OBJECT_TYPE_PORT) {
            port_index = destport_obj.index;
        } else if (destport_obj.type == SAI_OBJECT_TYPE_ROUTER_INTERFACE) {
            rif_entry rif;
            la_status lstatus = sdev->m_l3_ports.get(destport_obj.index, rif);
            sai_return_on_la_error(lstatus);
            lsai_object port_obj(rif.port_obj);
            if (port_obj.type != SAI_OBJECT_TYPE_PORT) {
                sai_log_error(
                    SAI_API_MIRROR, "Device port details associated with monitor port 0x%lx is invalid.", mirror_dest_port_oid);
                return SAI_STATUS_FAILURE;
            }

            port_index = port_obj.index;
        } else if (destport_obj.type == SAI_OBJECT_TYPE_BRIDGE_PORT || destport_obj.type == SAI_OBJECT_TYPE_VLAN_MEMBER) {
            // get eth and sys port associated with bridge port
            bridge_port_entry bridge_port{};
            la_status lstatus = sdev->m_bridge_ports.get(destport_obj.index, bridge_port);
            sai_return_on_la_error(lstatus, "Unknown port oid 0x%lx", mirror_dest_port_oid);
            lsai_object port_obj(bridge_port.port_obj);
            port_index = port_obj.index;
        } else {
            sai_log_error(SAI_API_MIRROR, "Device port 0x%lx is invalid.", mirror_dest_port_oid);
            return SAI_STATUS_FAILURE;
        }
    } else {
        // No support for lag port as mirror destination
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    port_entry* port = sdev->m_ports.get_ptr(port_index);
    if (port == nullptr) {
        sai_return_on_error(SAI_STATUS_INVALID_PARAMETER, "Invalid port 0x%ld for mirror monitor", mirror_dest_port_oid);
    }

    // return lag eth port for the lag member
    out_eth_port = port->service.eth_port;
    if (port->lag_oid != SAI_NULL_OBJECT_ID) {
        lsai_object la_lag(port->lag_oid);
        lag_entry* lag_entry = sdev->m_lags.get_ptr(la_lag.index);
        if (lag_entry != nullptr) {
            out_eth_port = lag_entry->service.eth_port;
        }
    }
    out_sys_port = port->sys_port;
    return SAI_STATUS_SUCCESS;
}

static void
fill_transport(const lasai_mirror_session_t& session, la_erspan_mirror_command::ipv4_encapsulation& encaps)
{
    la_ip_addr sip = to_sdk(session.headers.sip);
    la_ip_addr dip = to_sdk(session.headers.dip);

    encaps.ipv4.tunnel_source_addr = sip.to_v4();
    encaps.ipv4.tunnel_dest_addr = dip.to_v4();

    encaps.ipv4.dscp = {.value = session.headers.tos};
    encaps.ipv4.ttl = session.headers.ttl;
}

static void
fill_transport(const lasai_mirror_session_t& session, la_erspan_mirror_command::ipv6_encapsulation& encaps)
{
    la_ip_addr sip = to_sdk(session.headers.sip);
    la_ip_addr dip = to_sdk(session.headers.dip);

    encaps.ipv6.tunnel_source_addr = sip.to_v6();
    encaps.ipv6.tunnel_dest_addr = dip.to_v6();

    encaps.ipv6.dscp = {.value = session.headers.tos};
    encaps.ipv6.ttl = session.headers.ttl;
}

template <typename Encaps>
Encaps
sai_mirror::fill_erspan_encaps(const lasai_mirror_session_t& session, uint32_t session_instance)
{
    Encaps encaps{};

    if (session.type == SAI_MIRROR_SESSION_TYPE_ENHANCED_REMOTE) {
        encaps.type = la_erspan_mirror_command::type_e::ERSPAN;
        encaps.session.session_id = session_instance;
    } else {
        encaps.type = la_erspan_mirror_command::type_e::SFLOW_TUNNEL;
        encaps.session.sflow.sport = session.headers.udp_sport;
        encaps.session.sflow.dport = session.headers.udp_dport;
    }

    encaps.vlan_tag = session.vlan_hdr_valid ? convert_vlan_tag_info(session) : LA_VLAN_TAG_UNTAGGED;
    reverse_copy(std::begin(session.headers.da), std::end(session.headers.da), encaps.mac_addr.bytes);
    reverse_copy(std::begin(session.headers.sa), std::end(session.headers.sa), encaps.source_mac_addr.bytes);

    fill_transport(session, encaps);

    return encaps;
}

// Instantiate mirroring in npu. The device allocate mirror command that is used
// to attach to mirroring ports.
sai_status_t
sai_mirror::create_device_mirror_command(const lasai_mirror_session_t& session,
                                         uint32_t session_instance,
                                         bool is_ingress_stage,
                                         la_mirror_command*& device_mirror_cmd)
{
    la_ethernet_port* eth_port = nullptr;
    la_system_port* sys_port = nullptr;
    sai_status_t status = get_mirror_destination_port_details(session.destport_oid, eth_port, sys_port);
    sai_return_on_error(status);
    lsai_object obj(session.switch_oid);
    auto sdev = obj.get_device();

    if (mirror_session_is_local(session.type)) {
        if (sys_port == nullptr || eth_port == nullptr) {
            sai_log_error(SAI_API_MIRROR,
                          "Mirror session creation failed. Device port details associated with monitor port 0x%lx is invalid.",
                          session.destport_oid);
            return SAI_STATUS_FAILURE;
        }

        // create l2 mirror command.
        la_l2_mirror_command* l2_mirror_cmd;
        la_mirror_gid_t mirror_gid;
        mirror_gid = sdev->m_mirror_handler->mirror_session_instance_to_gid(session_instance, is_ingress_stage);
        la_status lstatus = sdev->m_dev->create_l2_mirror_command(mirror_gid,
                                                                  eth_port,
                                                                  sys_port,
                                                                  0 /* voq_offset */,
                                                                  /* probability of pkt gen  == sample_rate */
                                                                  (session.sample_rate) ? (1.0 / session.sample_rate) : 0,
                                                                  l2_mirror_cmd);
        sai_return_on_la_error(lstatus);
        device_mirror_cmd = l2_mirror_cmd;
        sai_log_debug(SAI_API_MIRROR, "Local l2 mirror command created.");
        l2_mirror_cmd->set_truncate(session.truncate_size != 0);

        uint8_t tc = session.tc_set ? session.tc
                                    : (sdev->m_mirror_handler->m_switch_attr_mirror_tc_val == SAI_MIRROR_TC_VAL_DISABLED)
                                          ? 0
                                          : sdev->m_mirror_handler->m_switch_attr_mirror_tc_val;
        lstatus = l2_mirror_cmd->set_voq_offset(tc);
        sai_return_on_la_error(lstatus);
    } else if (mirror_session_is_remote(session.type)) {
        if (sys_port == nullptr) {
            sai_log_error(SAI_API_MIRROR,
                          "Mirror session creation failed. Device port details associated with monitor port 0x%lx is invalid.",
                          session.destport_oid);
            return SAI_STATUS_FAILURE;
        }

        la_mirror_gid_t mirror_gid;
        mirror_gid = sdev->m_mirror_handler->mirror_session_instance_to_gid(session_instance, is_ingress_stage);

        // Check/Disconnect: max number of mirror sessions and max number of erspan
        // sessions supported by device are not same currently. For now
        // limit erspan sessions and mirror sessions to common denominator.

        la_erspan_mirror_command* erspan_mirror_cmd = nullptr;

        if (session.headers.iphdr_ver == 6) {
            auto encaps = fill_erspan_encaps<la_erspan_mirror_command::ipv6_encapsulation>(session, session_instance);

            la_status lstatus = sdev->m_dev->create_erspan_mirror_command(mirror_gid,
                                                                          encaps,
                                                                          0 /* voq offset */,
                                                                          sys_port,
                                                                          /* probability of pkt gen  == sample_rate */
                                                                          (session.sample_rate) ? (1.0 / session.sample_rate) : 0,
                                                                          erspan_mirror_cmd);
            sai_return_on_la_error(lstatus);
        } else {
            auto encaps = fill_erspan_encaps<la_erspan_mirror_command::ipv4_encapsulation>(session, session_instance);

            la_status lstatus = sdev->m_dev->create_erspan_mirror_command(mirror_gid,
                                                                          encaps,
                                                                          0 /* voq offset */,
                                                                          sys_port,
                                                                          /* probability of pkt gen  == sample_rate */
                                                                          (session.sample_rate) ? (1.0 / session.sample_rate) : 0,
                                                                          erspan_mirror_cmd);
            sai_return_on_la_error(lstatus);
        }

        device_mirror_cmd = erspan_mirror_cmd;
        sai_log_debug(SAI_API_MIRROR, "erspan mirror command created.");
        erspan_mirror_cmd->set_truncate(session.truncate_size != 0);
        uint8_t tc = session.tc_set ? session.tc
                                    : (sdev->m_mirror_handler->m_switch_attr_mirror_tc_val == SAI_MIRROR_TC_VAL_DISABLED)
                                          ? 0
                                          : sdev->m_mirror_handler->m_switch_attr_mirror_tc_val;
        la_status lstatus = erspan_mirror_cmd->set_voq_offset(tc);
        sai_return_on_la_error(lstatus);
    } else if (session.type == SAI_MIRROR_SESSION_TYPE_REMOTE) {
        return SAI_STATUS_NOT_IMPLEMENTED; // RSPAN is supported in SDK
    }

    return SAI_STATUS_SUCCESS;
}

// Using mirror session attributes, create mirror session
sai_status_t
sai_mirror::create_mirror_session(_Out_ sai_object_id_t* mirror_session_id,
                                  _In_ sai_object_id_t switch_id,
                                  _In_ uint32_t attr_count,
                                  _In_ const sai_attribute_t* attr_list)
{
    sai_status_t status;
    auto attrs = sai_parse_attributes(attr_count, attr_list);

    // macro performs sai_log, define sdev, initialize sdev and mutex lock
    sai_start_api(SAI_API_MIRROR, SAI_OBJECT_TYPE_SWITCH, switch_id, &mirror_session_attr_to_string, "attrs", attrs);

    if (sdev->m_mirror_handler->m_mirror_db.get_free_space() == 0) {
        sai_log_error(SAI_API_MIRROR, "Device mirror session limit reached.");
        return SAI_STATUS_FAILURE;
    }

    sai_mirror_session_type_t type;
    get_attrs_value(SAI_MIRROR_SESSION_ATTR_TYPE, attrs, type, true);

    lasai_mirror_session_t session;
    session.switch_oid = switch_id;
    session.type = type;
    status = parse_session_attributes(sdev, attrs, session);
    sai_return_on_error(status);
    if (session.vlan_hdr_valid) {
        status = parse_tag_attributes(attrs, session.tag);
        sai_return_on_error(status);
    }

    if (session.type == SAI_MIRROR_SESSION_TYPE_ENHANCED_REMOTE) {
        status = parse_erspan_attributes(attrs, session.headers);
        sai_return_on_error(status);
    }

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    if (session.type == SAI_MIRROR_SESSION_TYPE_SFLOW) {
        status = parse_sflow_attributes(attrs, session.headers);
        sai_return_on_error(status);
    }
#endif
    // During mirror session creation time, SAI layer will not bother itself of duplicate
    // mirror session with exact same attribute values. The reason being at some point in
    // future matching sessions might not match anymore due to set/change in mirror attributes.
    // Create a new SAI mirror session instance.
    uint32_t session_instance;
    la_status lstatus = sdev->m_mirror_handler->allocate_mirror_session_instance(session_instance);
    sai_return_on_la_error(lstatus);
    transaction txn;
    txn.on_fail([=]() { sdev->m_mirror_handler->free_mirror_session_instance(session_instance); });

    // create new ingress mirror command in device using newly allocated session_instance
    status = create_device_mirror_command(session, session_instance, true, session.mirror_cmd_ingress);
    txn.status = to_la_status(status);
    sai_return_on_error(status);
    txn.on_fail([=]() {
        if (mirror_session_is_local(session.type) || mirror_session_is_remote(session.type)) {
            sdev->m_dev->destroy(session.mirror_cmd_ingress);
        }
    });

    // clear out list of ports that the mirror session can be attached
    session.ingress_mirrored_port_oids.clear();
    session.egress_mirrored_port_oids.clear();
    lsai_object mirror_object(SAI_OBJECT_TYPE_MIRROR_SESSION, la_obj.switch_id, session_instance);
    session.session_oid = mirror_object.object_id();
    lstatus = sdev->m_mirror_handler->m_mirror_db.set(session_instance, session);
    sai_return_on_la_error(lstatus);
    *mirror_session_id = mirror_object.object_id();
    sdev->m_mirror_handler->m_mirror_session_oids.insert(*mirror_session_id);
    sai_log_debug(SAI_API_MIRROR, "Mirror session 0x%lx created", *mirror_session_id);

    return status;
}

// Mirror session can be removed once no ports (either in ingress/egress) direction
// use the session for mirroring purpose.
sai_status_t
sai_mirror::remove_mirror_session(_In_ sai_object_id_t mirror_session_id)
{
    // macro performs sai_log, define sdev, initialize sdev and mutex lock
    sai_start_api(
        SAI_API_MIRROR, SAI_OBJECT_TYPE_MIRROR_SESSION, mirror_session_id, &mirror_session_attr_to_string, mirror_session_id);

    lasai_mirror_session_t* session = sdev->m_mirror_handler->m_mirror_db.get_ptr(la_obj.index);
    if (session == nullptr) {
        sai_log_error(SAI_API_MIRROR, "Mirror session oid 0x%lx is unrecognized", mirror_session_id);
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    if (session->mirror_cmd_ingress == nullptr) {
        sai_log_error(SAI_API_MIRROR, "Mirror session oid 0x%lx is unrecognized. Mirror command error", mirror_session_id);
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    // check if mirror session is in use.
    if (!session->ingress_mirrored_port_oids.empty() || !session->egress_mirrored_port_oids.empty()) {
        // mirror session is in use.
        sai_log_error(SAI_API_MIRROR,
                      "Mirror session still in use. Ingress mirror session count = %d, Egress mirror session count = %d",
                      session->ingress_mirrored_port_oids.size(),
                      session->egress_mirrored_port_oids.size());
        return SAI_STATUS_OBJECT_IN_USE;
    }

    if (session->ingress_ace_ref_count || session->egress_ace_ref_count) {
        sai_log_error(
            SAI_API_MIRROR,
            "Mirror object 0x%lx in use by ACL. Used by %d ACEs in ingress ACL table/s, and %d ACEs in egress ACL table/s.",
            mirror_session_id,
            session->ingress_ace_ref_count,
            session->egress_ace_ref_count);
        return SAI_STATUS_OBJECT_IN_USE;
    }

    la_status lstatus;
    // Remove SDK object
    if (mirror_session_is_local(session->type) || mirror_session_is_remote(session->type)) {
        lstatus = sdev->m_dev->destroy(session->mirror_cmd_ingress);
        sai_return_on_la_error(lstatus);
        if (session->mirror_cmd_egress) {
            lstatus = sdev->m_dev->destroy(session->mirror_cmd_egress);
            sai_return_on_la_error(lstatus);
        }
    }

    // remove mirror session
    lstatus = sdev->m_mirror_handler->m_mirror_db.remove(la_obj.index);
    sai_return_on_la_error(lstatus);

    sdev->m_mirror_handler->m_mirror_session_oids.erase(mirror_session_id);
    sai_log_debug(SAI_API_MIRROR, "Mirror session 0x%lx removed", mirror_session_id);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_mirror::set_mirror_session_attribute(_In_ sai_object_id_t mirror_session_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    key.key.object_id = mirror_session_id;
    sai_start_api(SAI_API_MIRROR, SAI_OBJECT_TYPE_MIRROR_SESSION, mirror_session_id, &mirror_session_attr_to_string, "attr", *attr);
    char key_str[MAX_KEY_STR_LEN];
    snprintf(key_str, MAX_KEY_STR_LEN, "mirror session 0x%lx", mirror_session_id);
    printf("mirror_session_id: %d\n", (int)mirror_session_id);
    return sai_set_attribute(&key, key_str, mirror_attribs, mirror_vendor_attribs, attr);
}

sai_status_t
sai_mirror::get_mirror_session_attribute(_In_ sai_object_id_t mirror_session_id,
                                         _In_ uint32_t attr_count,
                                         _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    key.key.object_id = mirror_session_id;
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_MIRROR, SAI_OBJECT_TYPE_MIRROR_SESSION, mirror_session_id, &mirror_session_attr_to_string, "attrs", attrs);
    char key_str[MAX_KEY_STR_LEN];
    snprintf(key_str, MAX_KEY_STR_LEN, "mirror session 0x%lx", mirror_session_id);
    return sai_get_attributes(&key, key_str, mirror_attribs, mirror_vendor_attribs, attr_count, attr_list);
}

const sai_mirror_api_t mirror_api = {sai_mirror::create_mirror_session,
                                     sai_mirror::remove_mirror_session,
                                     sai_mirror::set_mirror_session_attribute,
                                     sai_mirror::get_mirror_session_attribute};

// Returns mirror sessions ids associated with slow path packet sampling
sai_status_t
sai_mirror::get_slow_path_packet_sample_mirror_session(const std::shared_ptr<lsai_device>& sdev,
                                                       const port_lag_common* service,
                                                       sai_object_id_t& ingress_psample_mirror_oid,
                                                       sai_object_id_t& egress_psample_mirror_oid)
{
    ingress_psample_mirror_oid = SAI_NULL_OBJECT_ID;
    egress_psample_mirror_oid = SAI_NULL_OBJECT_ID;

    // Get mirror session created for slow path packet sampling in ingress dir.
    if (service->ingress_packet_sample_oid != SAI_NULL_OBJECT_ID) {
        // get mirror session oid used by packet sampling.
        lsai_object packetsample_obj(service->ingress_packet_sample_oid);
        lasai_samplepacket_t* packet_sample = sdev->m_samplepacket_handler->m_samplepacket_db.get_ptr(packetsample_obj.index);
        if (packet_sample != nullptr) {
            if (packet_sample->slow_path_mirror_session_oid != SAI_NULL_OBJECT_ID) {
                ingress_psample_mirror_oid = packet_sample->slow_path_mirror_session_oid;
            }
        }
    }

    if (service->egress_packet_sample_oid != SAI_NULL_OBJECT_ID) {
        // Get mirror session created slow path packet sampling in egress dir.
        lsai_object packetsample_obj(service->egress_packet_sample_oid);
        lasai_samplepacket_t* packet_sample = sdev->m_samplepacket_handler->m_samplepacket_db.get_ptr(packetsample_obj.index);
        if (packet_sample != nullptr) {
            if (packet_sample->slow_path_mirror_session_oid != SAI_NULL_OBJECT_ID) {
                egress_psample_mirror_oid = packet_sample->slow_path_mirror_session_oid;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

// Attach slow path packet sampler either ingress/egress direction. Initiated by SAI PORT API enable packet sampling.
sai_status_t
sai_mirror::attach_slow_path_packet_sampling(sai_object_id_t port_oid,
                                             bool is_ingress_stage,
                                             sai_object_id_t slow_path_sampling_mirror_session_oid)
{
    lsai_object port_obj(port_oid);
    auto sdev = port_obj.get_device();
    port_entry* pentry = sdev->m_ports.get_ptr(port_obj.index);
    if (pentry == nullptr) {
        sai_log_error(SAI_API_MIRROR, "Unable to get packet sampling object associated with port object 0x%lx.", port_oid);
        return SAI_STATUS_FAILURE;
    }

    lasai_mirror_session_t session;
    sai_status_t status = validate_mirror_session_oid(port_oid, slow_path_sampling_mirror_session_oid, session);
    sai_return_on_error(
        status, "Failed to validate packet sampling mirror session oid 0x%lx", slow_path_sampling_mirror_session_oid);

    auto gress = (is_ingress_stage) ? "ingress" : "egress";
    la_mirror_command* mirror_cmd = (is_ingress_stage) ? session.mirror_cmd_ingress : session.mirror_cmd_egress;
    status = update_mirror_command_on_port(port_oid, is_ingress_stage, mirror_cmd, false /* not conditional */);
    sai_return_on_error(status,
                        "Could not attach %s packet sampling mirror session object 0x%lx to port 0x%lx",
                        gress,
                        slow_path_sampling_mirror_session_oid,
                        port_oid);

    sai_log_debug(SAI_API_MIRROR,
                  "Successfully attached %s packet samlping mirror session 0x%lx to port 0x%lx",
                  gress,
                  slow_path_sampling_mirror_session_oid,
                  port_oid);

    return SAI_STATUS_SUCCESS;
}

// Detach slow path packet sampler either ingress/egress direction. Initiated by SAI PORT API enable packet sampling.
sai_status_t
sai_mirror::detach_slow_path_packet_sampling(sai_object_id_t port_oid,
                                             bool is_ingress_stage,
                                             sai_object_id_t slow_path_sampling_mirror_session_oid)
{
    lsai_object port_obj(port_oid);
    auto sdev = port_obj.get_device();
    if (sdev == nullptr || (port_obj.type != SAI_OBJECT_TYPE_PORT && port_obj.type != SAI_OBJECT_TYPE_LAG)) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // Attempt to detach in both directions since the use case is of this call is when logical port is removed/deleted.
    port_lag_common* service = nullptr;
    la_status lstatus = sai_port_get_service(sdev, port_oid, service);
    sai_return_on_la_error(lstatus);

    if (service == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    lasai_mirror_session_t session;
    sai_status_t status = validate_mirror_session_oid(port_oid, slow_path_sampling_mirror_session_oid, session);
    sai_return_on_error(
        status, "Failed to validate packet sampling mirror session oid 0x%lx", slow_path_sampling_mirror_session_oid);

    auto gress = (is_ingress_stage) ? "ingress" : "egress";
    status = update_mirror_command_on_port(port_oid, is_ingress_stage, nullptr, false /* is_acl_conditioned */);
    sai_return_on_error(status, "Could not detach %s packet sampling mirror session from port 0x%lx", gress, port_oid);

    sai_log_debug(SAI_API_MIRROR, "Successfully detached %s packet sampling mirror session from port 0x%lx", gress, port_oid);

    return SAI_STATUS_SUCCESS;
}

// This function creates mirror session instance/sdk mirror command with same attributes
// as mirror session identified by mirror_session_oid. The new sdk mirror command is
// saved in mirror-session data instance corresponding to NOS aware mirror session oid
// within its per port per_port_ingress_sample_mirrors or per_port_egress_sample_mirrors.
sai_status_t
sai_mirror::create_sample_mirror_instance_for_port(sai_object_id_t port_oid,
                                                   sai_object_id_t mirror_session_oid,
                                                   bool is_ingress_stage)
{
    lsai_object mirror_obj(mirror_session_oid);
    auto sdev = mirror_obj.get_device();
    lasai_mirror_session_t* session = sdev->m_mirror_handler->m_mirror_db.get_ptr(mirror_obj.index);
    if (session == nullptr) {
        sai_log_error(
            SAI_API_MIRROR, "Mirror session context corressponding to %s mirror session 0x%lx not found.", mirror_session_oid);
        return SAI_STATUS_FAILURE;
    }

    if (is_ingress_stage) {
        auto it = session->per_port_ingress_sample_mirrors.find(port_oid);
        if (it != session->per_port_ingress_sample_mirrors.end()) {
            // Unusal. A sample mirror instance corresponding to the mirror-session mirror_session_oid
            // on the port port_oid already exists. This can happen if a mirror session object is
            // attached to port as sample mirror session multiple times. Caller would have already
            // checked for duplicate attachment. In any case assume idempotent operation and return success.
            return SAI_STATUS_SUCCESS;
        }
    }

    if (!is_ingress_stage) {
        auto it = session->per_port_egress_sample_mirrors.find(port_oid);
        if (it != session->per_port_egress_sample_mirrors.end()) {
            return SAI_STATUS_SUCCESS;
        }
    }

    auto gress = (is_ingress_stage) ? "ingress" : "egress";
    transaction txn;
    uint32_t session_instance;
    la_status lstatus = sdev->m_mirror_handler->allocate_mirror_session_instance(session_instance);
    sai_return_on_la_error(lstatus);
    txn.on_fail([=]() { sdev->m_mirror_handler->free_mirror_session_instance(session_instance); });

    // create new sample mirror command using newly allocated session_instance and borrowing mirror
    //  encap attributes from mirror session object
    lasai_sample_mirror_t sample_mirror_instance;
    sai_status_t status
        = create_device_mirror_command(*session, session_instance, is_ingress_stage, sample_mirror_instance.sample_mirror_cmd);
    txn.status = to_la_status(status);
    sai_return_on_error(status);
    txn.on_fail([=]() { sdev->m_dev->destroy(sample_mirror_instance.sample_mirror_cmd); });

    // Set port sample mirror instance borrowed attributes from mirror session object(encap information)
    sample_mirror_instance.session_oid = mirror_session_oid;
    // For now set mirror session's sample rate which can be updated to reflect
    // sampling rate of packet-sampling object thats get associated with sample mirror sesison.
    sample_mirror_instance.sample_rate = session->sample_rate;
    // save mirror command instance id that can be released when sample mirror is deleted.
    sample_mirror_instance.mirror_command_instance_id = session_instance;

    // Save per port sample mirror instance in the mirror session object, whoes object id
    // is used for operations related to packet sampling with mirroring.
    if (is_ingress_stage) {
        session->per_port_ingress_sample_mirrors.emplace(port_oid, sample_mirror_instance);
    } else {
        session->per_port_egress_sample_mirrors.emplace(port_oid, sample_mirror_instance);
    }

    sai_log_debug(
        SAI_API_MIRROR,
        "Successfully created in %s direction a new mirror instance using mirror session object 0x%lx to be used on port 0x%lx",
        gress,
        mirror_session_oid,
        port_oid);

    return SAI_STATUS_SUCCESS;
}

// Detaches sample mirror instance if already attached to port. Packet sampling based
// on mirror session stops after successful detach. Detaches sample mirror instance
// from all logical ports that exist on the port. Device mirror commands and global ids used
// for creating sample mirror commands are released. Per port sample mirror instance mapping
// maintained within NOS aware mirror session context is cleared.
sai_status_t
sai_mirror::detach_and_delete_sample_mirror_instance_from_port(sai_object_id_t port_oid,
                                                               sai_object_id_t mirror_session_oid,
                                                               bool is_ingress_stage)
{
    // When mirror session object associated with packet sampling is detached,
    // delete corresponding per port sample mirror instance used on port
    lsai_object mirror_obj(mirror_session_oid);
    auto sdev = mirror_obj.get_device();
    lasai_mirror_session_t* session = sdev->m_mirror_handler->m_mirror_db.get_ptr(mirror_obj.index);
    if (session == nullptr) {
        sai_log_error(
            SAI_API_MIRROR, "Mirror session context corressponding to %s mirror session 0x%lx not found.", mirror_session_oid);
        return SAI_STATUS_FAILURE;
    }

    // From the mirror object, get corresponding sample-mirror instance.
    lasai_sample_mirror_t sample_mirror_ctx;
    sai_status_t status
        = sdev->m_mirror_handler->get_sample_mirror_context(port_oid, mirror_session_oid, is_ingress_stage, sample_mirror_ctx);
    if (status == SAI_STATUS_ITEM_NOT_FOUND) {
        // No sample mirror instance corresponding to mirror_oid object exists.
        // Probably duplicate delete
        return SAI_STATUS_SUCCESS;
    }

    sai_return_on_error(status);

    if (sample_mirror_ctx.sample_mirror_cmd != nullptr) {
        // If a sample mirror session exists, then sample mirror_cmd should be valid.
        // Clear mirror command on all logical ports of the port.
        status = sdev->m_mirror_handler->update_mirror_command_on_port(
            port_oid, is_ingress_stage, nullptr, false /* not conditioned */);
        sai_return_on_error(status);
        sdev->m_dev->destroy(sample_mirror_ctx.sample_mirror_cmd);
    }

    if (sample_mirror_ctx.mirror_command_instance_id != INVALID_MIRROR_ID) {
        free_mirror_session_instance(sample_mirror_ctx.mirror_command_instance_id);
    }

    if (is_ingress_stage) {
        session->per_port_ingress_sample_mirrors.erase(port_oid);
    } else {
        session->per_port_egress_sample_mirrors.erase(port_oid);
    }

    auto gress = (is_ingress_stage) ? "ingress" : "egress";
    sai_log_debug(SAI_API_MIRROR,
                  "Successfully detached and deleted in %s direction the mirror instance that was created using mirror session "
                  "object 0x%lx and used on port 0x%lx",
                  gress,
                  mirror_session_oid,
                  port_oid);

    return SAI_STATUS_SUCCESS;
}

// Detaches sample mirror instance if already attached to port. Packet sampling based
// on mirror session stops after successful detach. Detaches sample mirror instance
// from all logical ports that exist on the port. Device mirror commands and global ids used
// for creating sample mirror commands are NOT released. Per port sample mirror instance mapping
// maintained within NOS aware mirror session context is NOT cleared. This allows to attach
// back sample mirror sessions when same or new packet sample object is attached to port.
sai_status_t
sai_mirror::detach_sample_mirror_instance_from_port(sai_object_id_t port_oid,
                                                    sai_object_id_t mirror_session_oid,
                                                    bool is_ingress_stage)
{
    // When mirror session object associated with packet sampling is detached,
    // delete corresponding per port sample mirror instance used on port
    lsai_object mirror_obj(mirror_session_oid);
    auto sdev = mirror_obj.get_device();
    lasai_mirror_session_t* session = sdev->m_mirror_handler->m_mirror_db.get_ptr(mirror_obj.index);
    if (session == nullptr) {
        sai_log_error(
            SAI_API_MIRROR, "Mirror session context corressponding to %s mirror session 0x%lx not found.", mirror_session_oid);
        return SAI_STATUS_FAILURE;
    }

    // From the mirror object, get corresponding sample-mirror instance.
    lasai_sample_mirror_t sample_mirror_ctx;
    sai_status_t status
        = sdev->m_mirror_handler->get_sample_mirror_context(port_oid, mirror_session_oid, is_ingress_stage, sample_mirror_ctx);
    if (status == SAI_STATUS_ITEM_NOT_FOUND) {
        // No sample mirror instance corresponding to mirror_oid object exists.
        // Probably duplicate delete
        return SAI_STATUS_SUCCESS;
    }
    sai_return_on_error(status);

    if (sample_mirror_ctx.sample_mirror_cmd != nullptr) {
        // If a sample mirror session exists, then sample mirror_cmd should be valid.
        // Clear mirror command on all logical ports of the port.
        status = sdev->m_mirror_handler->update_mirror_command_on_port(
            port_oid, is_ingress_stage, nullptr, false /* not conditioned */);
        sai_return_on_error(status);
    }

    auto gress = (is_ingress_stage) ? "ingress" : "egress";
    sai_log_debug(SAI_API_MIRROR,
                  "Successfully detached in %s direction the mirror instance that was created using mirror session object 0x%lx "
                  "and used on port 0x%lx",
                  gress,
                  mirror_session_oid,
                  port_oid);

    return SAI_STATUS_SUCCESS;
}

// The functions helps to either attach or detach device mirror command meant for
// mirror based packet sampling from a logical port. Used when a logical port is created or
// destroyed.
sai_status_t
sai_mirror::update_sample_mirror_instance_from_logical_port(sai_object_id_t logical_port_oid,
                                                            sai_object_id_t underlying_port_oid,
                                                            sai_object_id_t mirror_session_oid,
                                                            bool is_ingress_stage,
                                                            bool do_detach)
{
    lsai_object lport_obj(logical_port_oid);
    if (IS_SAI_SERVICE_PORT(lport_obj)) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto sdev = lport_obj.get_device();

    // From the mirror object, get corresponding sample-mirror instance.
    lasai_sample_mirror_t sample_mirror_ctx;
    sai_status_t status = sdev->m_mirror_handler->get_sample_mirror_context(
        underlying_port_oid, mirror_session_oid, is_ingress_stage, sample_mirror_ctx);
    if (status == SAI_STATUS_ITEM_NOT_FOUND) {
        // No sample mirror instance corresponding to mirror_oid object exists.
        // Probably duplicate delete
        return status;
    }

    sai_return_on_error(status);

    // Do attach
    if (sample_mirror_ctx.sample_mirror_cmd != nullptr && !do_detach) {
        // If a sample mirror session exists, then sample mirror_cmd should be valid.
        // Clear mirror command on all logical ports of the port.
        status = sdev->m_mirror_handler->update_mirror_command_on_port(
            logical_port_oid, is_ingress_stage, sample_mirror_ctx.sample_mirror_cmd, false /* not conditioned */);
        sai_return_on_error(status);
    }

    // Do detach
    if (sample_mirror_ctx.sample_mirror_cmd != nullptr && do_detach) {
        // If a sample mirror session exists, then sample mirror_cmd should be valid.
        // Clear mirror command on all logical ports of the port.
        status = sdev->m_mirror_handler->update_mirror_command_on_port(
            logical_port_oid, is_ingress_stage, nullptr, false /* not conditioned */);
        sai_return_on_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

// Detaches sample mirror instance if already attached from a logical port. Packet sample
// based on mirror session stops after successful detach. Use case: When a logical port is delete.
sai_status_t
sai_mirror::detach_sample_mirror_instance_from_logical_port(sai_object_id_t logical_port_oid, sai_object_id_t underlying_port_oid)
{
    lsai_object port_obj(underlying_port_oid);
    auto sdev = port_obj.get_device();
    if (sdev == nullptr || (port_obj.type != SAI_OBJECT_TYPE_PORT && port_obj.type != SAI_OBJECT_TYPE_LAG)) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // Attempt to detach in both directions since the use case is of this call is when logical port is removed/deleted.
    port_lag_common* service = nullptr;
    la_status lstatus = sai_port_get_service(sdev, underlying_port_oid, service);
    sai_return_on_la_error(lstatus);

    if (service == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    for (bool is_ingress_stage : {true, false}) {
        auto gress = (is_ingress_stage) ? "ingress" : "egress";
        const std::set<sai_object_id_t>& sample_mirror_oids
            = (is_ingress_stage) ? service->ingress_sample_mirror_oids : service->egress_sample_mirror_oids;
        for (auto sample_mirror_oid : sample_mirror_oids) {
            sai_status_t status = update_sample_mirror_instance_from_logical_port(
                logical_port_oid, underlying_port_oid, sample_mirror_oid, is_ingress_stage, true /* detach */);
            if (status != SAI_STATUS_SUCCESS && status != SAI_STATUS_ITEM_NOT_FOUND) {
                sai_log_error(SAI_API_MIRROR,
                              "Failed to detach in %s direction the mirror instance that was created using mirror session object "
                              "0x%lx and used on logical port 0x%lx created over port 0x%lx",
                              gress,
                              sample_mirror_oid,
                              logical_port_oid,
                              underlying_port_oid);
                sai_return_on_error(status);
            }

            if (status == SAI_STATUS_ITEM_NOT_FOUND) {
                // No sampling attached on port; hence nothing to detach from logical port.
                continue;
            }

            sai_log_debug(SAI_API_MIRROR,
                          "Successfully detached in %s direction the mirror instance that was created using mirror session object "
                          "0x%lx and used on logical port 0x%lx created over port 0x%lx",
                          gress,
                          sample_mirror_oid,
                          logical_port_oid,
                          underlying_port_oid);
        }
    }

    return SAI_STATUS_SUCCESS;
}

// Attach sample mirror instance if already attached to a logical port. Packet sample based
// on mirror session starts after successful attach. Use case: When a logical port is created.
sai_status_t
sai_mirror::attach_sample_mirror_instance_to_logical_port(sai_object_id_t logical_port_oid, sai_object_id_t underlying_port_oid)
{

    // Attempt to attach in both directions since the use case is of this call is when logical port is created.

    lsai_object port_obj(underlying_port_oid);
    auto sdev = port_obj.get_device();

    port_lag_common* service = nullptr;
    la_status lstatus = sai_port_get_service(sdev, underlying_port_oid, service);
    sai_return_on_la_error(lstatus);

    if (service == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    for (bool is_ingress_stage : {true, false}) {
        auto gress = (is_ingress_stage) ? "ingress" : "egress";
        const std::set<sai_object_id_t>& sample_mirror_oids
            = (is_ingress_stage) ? service->ingress_sample_mirror_oids : service->egress_sample_mirror_oids;
        for (auto sample_mirror_oid : sample_mirror_oids) {

            sai_status_t status = update_sample_mirror_instance_from_logical_port(
                logical_port_oid, underlying_port_oid, sample_mirror_oid, is_ingress_stage, false /* detach */);

            if (status != SAI_STATUS_SUCCESS && status != SAI_STATUS_ITEM_NOT_FOUND) {
                sai_log_error(SAI_API_MIRROR,
                              "Failed to attach in %s direction the mirror instance that was created using mirror session object "
                              "0x%lx and used on logical port 0x%lx created over port 0x%lx",
                              gress,
                              sample_mirror_oid,
                              logical_port_oid,
                              underlying_port_oid);
                sai_return_on_error(status);
            }

            if (status == SAI_STATUS_ITEM_NOT_FOUND) {
                // No sampling attached on port; hence nothing to attach to logical port.
                continue;
            }

            sai_log_debug(SAI_API_MIRROR,
                          "Successfully attached in %s direction the mirror instance that was created using mirror session object "
                          "0x%lx and used on logical port 0x%lx created over port 0x%lx",
                          gress,
                          sample_mirror_oid,
                          logical_port_oid,
                          underlying_port_oid);
        }
    }

    return SAI_STATUS_SUCCESS;
}

// Returns mirror context created based on mirror session oid and to the port mirror
// session is attached as sampling based mirror object.
sai_status_t
sai_mirror::get_sample_mirror_context(sai_object_id_t port_oid,
                                      sai_object_id_t mirror_oid,
                                      bool is_ingress_stage,
                                      lasai_sample_mirror_t& sample_mirror_ctx)
{
    auto gress = (is_ingress_stage) ? "ingress" : "egress";
    lsai_object mirror_obj(mirror_oid);
    auto sdev = mirror_obj.get_device();
    lasai_mirror_session_t* session = sdev->m_mirror_handler->m_mirror_db.get_ptr(mirror_obj.index);
    if (session != nullptr && is_ingress_stage) {
        auto it = session->per_port_ingress_sample_mirrors.find(port_oid);
        if (it != session->per_port_ingress_sample_mirrors.end()) {
            sample_mirror_ctx = it->second;
        } else {
            return SAI_STATUS_ITEM_NOT_FOUND;
        }
    }

    if (session != nullptr && !is_ingress_stage) {
        auto it = session->per_port_egress_sample_mirrors.find(port_oid);
        if (it != session->per_port_egress_sample_mirrors.end()) {
            sample_mirror_ctx = it->second;
        } else {
            return SAI_STATUS_ITEM_NOT_FOUND;
        }
    }

    if (session == nullptr) {
        sai_log_error(SAI_API_MIRROR,
                      "Sample mirror context corressponding to %s mirror session 0x%lx on port 0x%lx not found.",
                      gress,
                      mirror_oid,
                      port_oid);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

// This function changes sampling rate on device mirror command created for each sampled mirror
// instance attached on a port.
sai_status_t
sai_mirror::set_sampling_rate_on_sample_mirror_instance(sai_object_id_t port_oid,
                                                        sai_object_id_t mirror_oid,
                                                        bool is_ingress_stage,
                                                        uint32_t sample_rate)
{
    auto gress = (is_ingress_stage) ? "ingress" : "egress";
    lsai_object mirror_obj(mirror_oid);
    auto sdev = mirror_obj.get_device();
    lasai_mirror_session_t* session = sdev->m_mirror_handler->m_mirror_db.get_ptr(mirror_obj.index);
    la_mirror_command* sample_mirror_command = nullptr;
    if (session != nullptr && is_ingress_stage) {
        auto it = session->per_port_ingress_sample_mirrors.find(port_oid);
        if (it != session->per_port_ingress_sample_mirrors.end()) {
            it->second.sample_rate = sample_rate;
            sample_mirror_command = it->second.sample_mirror_cmd;
        }
    }

    if (session != nullptr && !is_ingress_stage) {
        auto it = session->per_port_egress_sample_mirrors.find(port_oid);
        if (it != session->per_port_egress_sample_mirrors.end()) {
            it->second.sample_rate = sample_rate;
            sample_mirror_command = it->second.sample_mirror_cmd;
        }
    }

    if (session == nullptr) {
        sai_log_error(SAI_API_MIRROR,
                      "Sample mirror context corressponding to %s mirror session 0x%lx on port 0x%lx not found.",
                      gress,
                      mirror_oid,
                      port_oid);
        return SAI_STATUS_FAILURE;
    }

    if (sample_mirror_command == nullptr) {
        // No per port sample mirror found corresponding to port_oid
        return SAI_STATUS_SUCCESS;
    }

    if (mirror_session_is_local(session->type)) {
        la_l2_mirror_command* cmd = static_cast<la_l2_mirror_command*>(sample_mirror_command);
        la_status lstatus = cmd->set_probability((sample_rate) ? (1.0 / sample_rate) : 0);
        sai_return_on_la_error(lstatus);
    } else if (mirror_session_is_remote(session->type)) {
        la_erspan_mirror_command* cmd = static_cast<la_erspan_mirror_command*>(sample_mirror_command);
        la_status lstatus = cmd->set_probability((sample_rate) ? (1.0 / sample_rate) : 0);
        sai_return_on_la_error(lstatus);
    }

    sai_log_debug(
        SAI_API_MIRROR, "Sampling rate on sample mirror command associated with sample mirror is updateed to %d.", sample_rate);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_mirror::set_mirror_session_used_by_ace(const std::shared_ptr<lsai_device>& sdev,
                                           uint32_t mirror_session_instance,
                                           bool is_ingress)
{
    lasai_mirror_session_t* session = sdev->m_mirror_handler->m_mirror_db.get_ptr(mirror_session_instance);
    if (session == nullptr || session->mirror_cmd_ingress == nullptr) {
        sai_log_error(SAI_API_MIRROR, "Mirror session instance 0x%x is unrecognized", mirror_session_instance);
        return SAI_STATUS_FAILURE;
    }

    uint32_t& new_mirror_ace_ref_count = (is_ingress) ? session->ingress_ace_ref_count : session->egress_ace_ref_count;
    ++new_mirror_ace_ref_count;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_mirror::clear_mirror_session_used_by_ace(const std::shared_ptr<lsai_device>& sdev,
                                             uint32_t mirror_session_instance,
                                             bool is_ingress)
{
    lasai_mirror_session_t* session = sdev->m_mirror_handler->m_mirror_db.get_ptr(mirror_session_instance);
    if (session == nullptr || session->mirror_cmd_ingress == nullptr) {
        sai_log_error(SAI_API_MIRROR, "Mirror session instance 0x%x is unrecognized", mirror_session_instance);
        return SAI_STATUS_FAILURE;
    }

    uint32_t& new_mirror_ace_ref_count = (is_ingress) ? session->ingress_ace_ref_count : session->egress_ace_ref_count;
    if (new_mirror_ace_ref_count) {
        --new_mirror_ace_ref_count;
    } else {
        sai_log_warn(SAI_API_MIRROR, "Mirror session oid 0x%lx is not used by any ACE", mirror_session_instance);
    }

    return SAI_STATUS_SUCCESS;
}

la_vlan_tag_t
sai_mirror::convert_vlan_tag_info(const lasai_mirror_session_t& session)
{
    la_vlan_tag_t tag{};
    tag.tpid = session.tag.tpid;
    tag.tci.fields.pcp = session.tag.pri;
    tag.tci.fields.dei = session.tag.cfi;
    tag.tci.fields.vid = session.tag.id;
    return tag;
}

sai_status_t
laobj_db_mirror::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    lsai_object sw_obj(SAI_OBJECT_TYPE_SWITCH, sdev->m_switch_id, sdev->m_switch_id);
    *count = sdev->m_mirror_handler->m_mirror_session_oids.size();

    sai_log_debug(SAI_API_SWITCH, "Total mirror entries: %d", *count);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_mirror::get_object_keys(std::shared_ptr<lsai_device> sdev, uint32_t* object_count, sai_object_key_t* object_list) const
{
    uint32_t requested_object_count = *object_count;

    sai_status_t status = get_object_count(sdev, object_count);
    sai_return_on_error(status);

    if (requested_object_count < *object_count) {
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    uint32_t object_index = 0;
    for (const auto& oid : sdev->m_mirror_handler->m_mirror_session_oids) {
        object_list[object_index].key.object_id = oid;
        object_index++;
    }

    return SAI_STATUS_SUCCESS;
}
}
}
