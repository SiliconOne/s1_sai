// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco").
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

/*
 *
 *   ACL UDK (User Defined Key/Field) Requirement Summary :
 *   ----------------------------------------------------
 *      1.  In most cases, ACL match key are sourced from packet header (L2/L3/L4).
 *          However in special cases, if ACL match key need to be sourced from both
 *          inner and outer headers, there needs to be a mechanism for facilitating
 *          such ACL match capability.
 *      2.  Include user defined field or intrinsic field, produced-by / sourced-from
 *          datapath pipeline into ACL match key. As an example, in special cases, ACL match
 *          key need to be sourced from attributes like SAI_NEIGHBOR_ENTRY_ATTR_META_DATA
 *          or custom extended SAI attributes. Provide a mechanism for facilitating
 *          such ACL match capability.
 *
 *   Phase-0 Implementation:
 *   -----------------------
 *      1. In this phase, at the time of creating switch instance, along with standard
 *         ACL fields sourced from L2/L3/L4 headers (inner and outer), a list of
 *         sdk supported custom fields not from packet header UDK(User defined key)
 *         can be provided. Such a list can be provided at the create-switch time only.
 *
 *      2. If ACL field list provided at switch creation time is empty, then
 *         SAI adaption layer will fallback to a default set of ACL fields all sourced
 *         packet header.
 *
 *      3. Example: In this case a subset of outer L3 hdr fields, inner l4 fields
 *                  and a custom field like SAI_ROUTE_ENTRY_ATTR_META_DATA
 *         Field-List = {
 *          SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6, SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6,
 *          SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER, SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_FRAG,
 *          SAI_ACL_TABLE_ATTR_FIELD_INNER_L4_SRC_PORT, case SAI_ACL_TABLE_ATTR_FIELD_INNER_L4_DST_PORT,
 *          SAI_ROUTE_ENTRY_ATTR_META_DATA
 *         }
 *
 * Post Phase-0 Solution
 * --------------------
 *      Enhanced version of phase-0 will allow to provide a list of ACL match
 *      fields at any time. ACL table field schema will have both standard ACL
 *      fields and extended fields. Such a list can be provided at sai acl table
 *      create time. There is no need to provide list at switch creation time.
 */

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <algorithm>
#include "lld/ll_device.h"
#include "acl_udk.h"
#include "sai_device.h"
#include "sai_logger.h"
#include "auto_gen_attr_ext.h"

namespace silicon_one
{
namespace sai
{

using namespace std;

namespace
{

uint8_t
get_tcam_pool_id()
{
    // TODO once tcam pool id is clear, replace this function appropriately.
    return 0;
}
}

acl_udk::acl_udk(std::shared_ptr<lsai_device> sai_dev) : m_sdev(sai_dev)
{
}

acl_udk::~acl_udk() = default;

void
acl_udk::set_device_property_if_class_id_used(const std::set<uint32_t>& udk_fields, bool& user_meta_device_property_set) const
{
    // If user-meta is used in ACLs, then set device property.
    if (udk_fields.find(SAI_ACL_TABLE_ATTR_FIELD_FDB_DST_USER_META) != udk_fields.end()) {
        user_meta_device_property_set = true;
    }

    if (udk_fields.find(SAI_ACL_TABLE_ATTR_FIELD_ROUTE_DST_USER_META) != udk_fields.end()) {
        user_meta_device_property_set = true;
    }

    if (udk_fields.find(SAI_ACL_TABLE_ATTR_FIELD_NEIGHBOR_DST_USER_META) != udk_fields.end()) {
        user_meta_device_property_set = true;
    }

    if (user_meta_device_property_set) {
        m_sdev->m_dev->set_bool_property(la_device_property_e::ENABLE_CLASS_ID_ACLS, true);
    }
}

bool
acl_udk::skip_udk_attribute(uint32_t attr_id) const
{
    if (attr_id == SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE) {
        // Do not add IP_TYPE into list of UDK fields to be used for creating
        // UDK ACL match schema.
        return true;
    }
    if (attr_id == SAI_ACL_TABLE_ATTR_ACL_STAGE) {
        return true;
    }
    return false;
}

void
acl_udk::is_acl_table_attr_iphdr_distinguisher_field(uint32_t attr, bool& is_ipv4, bool& is_ipv6) const
{
    is_ipv4 = false;
    is_ipv6 = false;
    switch (attr) {
    case SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6:
    case SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6:
    case SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER:
    case SAI_ACL_TABLE_ATTR_FIELD_IPV6_FLOW_LABEL:
    case SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_FRAG: {
        is_ipv6 = true;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_SRC_IP:
    case SAI_ACL_TABLE_ATTR_FIELD_DST_IP:
    case SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS:
    case SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL: {
        // SAI_ACL_TABLE_ATTR_FIELD_TTL is common sai attribute to both v4 and v6 header.
        // Hence not used to identify header type.
        is_ipv4 = true;
        break;
    }
    default:
        // Attribute is in header other than IPv/6.
        break;
    }
}

// For ACL table attribute, based on its position in packet header stack,
//  get details to build sdk data type.
sai_status_t
acl_udk::get_udf_description(uint32_t attr, int& offset, uint8_t& width, int& pl, int& layer, la_acl_field_type_e& type) const
{
    constexpr int INNER_PL = 1;
    constexpr int OUTER_PL = 0;
    constexpr int L3 = 0;
    constexpr int L4 = 1;
    auto udf_values = [&](uint8_t w, int p, int l) {
        width = div_round_up(w, 8); // Udf field width should be in units of bytes
        pl = p;
        layer = l;
    };
    switch (attr) {
    case SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6: {
        type = la_acl_field_type_e::IPV6_SIP;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6: {
        type = la_acl_field_type_e::IPV6_DIP;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_SRC_IPV6: {
        offset = offsetof(ip6_hdr, ip6_src);
        udf_values(128, INNER_PL, L3);
        type = la_acl_field_type_e::UDF;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_DST_IPV6: {
        offset = offsetof(ip6_hdr, ip6_dst);
        udf_values(128, INNER_PL, L3);
        type = la_acl_field_type_e::UDF;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER: {
        type = la_acl_field_type_e::LAST_NEXT_HEADER;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_IPV6_FLOW_LABEL: {
        type = la_acl_field_type_e::IPV6_FLOW_LABEL;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_SRC_IP: {
        type = la_acl_field_type_e::IPV4_SIP;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_DST_IP: {
        type = la_acl_field_type_e::IPV4_DIP;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_SRC_IP: {
        offset = offsetof(iphdr, saddr);
        udf_values(32, INNER_PL, L3);
        type = la_acl_field_type_e::UDF;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_DST_IP: {
        offset = offsetof(iphdr, daddr);
        udf_values(32, INNER_PL, L3);
        type = la_acl_field_type_e::UDF;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL: {
        type = la_acl_field_type_e::PROTOCOL;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_IP_PROTOCOL: {
        offset = offsetof(iphdr, protocol);
        udf_values(8, INNER_PL, L3);
        type = la_acl_field_type_e::UDF;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_IP_IDENTIFICATION: {
        offset = offsetof(iphdr, id);
        udf_values(16, OUTER_PL, L3);
        type = la_acl_field_type_e::UDF;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_ECN:
    case SAI_ACL_TABLE_ATTR_FIELD_DSCP:
    case SAI_ACL_TABLE_ATTR_FIELD_TOS: {
        // SDK combines ECN and DSCP
        type = la_acl_field_type_e::TOS;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_TTL: {
        type = la_acl_field_type_e::TTL;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT: {
        type = la_acl_field_type_e::SPORT;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT: {
        type = la_acl_field_type_e::DPORT;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_L4_SRC_PORT: {
        offset = offsetof(tcphdr, source);
        udf_values(16, INNER_PL, L4);
        type = la_acl_field_type_e::UDF;
        break;
    }
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_L4_DST_PORT:
        offset = offsetof(tcphdr, dest);
        udf_values(16, INNER_PL, L4);
        type = la_acl_field_type_e::UDF;
        break;
    case SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE:
    case SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_TYPE:
        type = la_acl_field_type_e::MSG_TYPE;
        break;
    case SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE:
    case SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_CODE:
        type = la_acl_field_type_e::MSG_CODE;
        break;
    case SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS:
        type = la_acl_field_type_e::IPV4_FLAGS;
        break;
    case SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS:
        type = la_acl_field_type_e::TCP_FLAGS;
        break;
    case SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE:
        type = la_acl_field_type_e::ETHER_TYPE;
        break;
    case SAI_ACL_TABLE_ATTR_FIELD_SRC_MAC:
        type = la_acl_field_type_e::SA;
        break;
    case SAI_ACL_TABLE_ATTR_FIELD_DST_MAC:
        type = la_acl_field_type_e::DA;
        break;
    case SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_ID:
        type = la_acl_field_type_e::VLAN_OUTER;
        break;
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_ID:
        type = la_acl_field_type_e::VLAN_INNER;
        break;
    case SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_FRAG:
        type = la_acl_field_type_e::IPV6_FRAGMENT;
        break;
    case SAI_ACL_TABLE_ATTR_FIELD_TUNNEL_VNI:
        // VNI is the 24 bit field 32 bits offset vxlan header after UDP header
        offset = sizeof(udphdr) + 4;
        udf_values(24, OUTER_PL, L4);
        type = la_acl_field_type_e::UDF;
        break;
    case SAI_ACL_TABLE_ATTR_FIELD_FDB_DST_USER_META:
    case SAI_ACL_TABLE_ATTR_FIELD_ROUTE_DST_USER_META:
    case SAI_ACL_TABLE_ATTR_FIELD_NEIGHBOR_DST_USER_META:
        type = la_acl_field_type_e::CLASS_ID;
        break;
    case SAI_ACL_TABLE_ATTR_FIELD_IN_PORT:
    case SAI_ACL_TABLE_ATTR_FIELD_IN_PORTS:
        type = la_acl_field_type_e::SOURCE_SYSTEM_PORT;
        break;
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_ETHER_TYPE:
    case SAI_ACL_TABLE_ATTR_FIELD_OUT_PORTS:
    case SAI_ACL_TABLE_ATTR_FIELD_OUT_PORT:
    case SAI_ACL_TABLE_ATTR_FIELD_SRC_PORT:
    case SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_PRI:
    case SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_CFI:
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_PRI:
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_VLAN_CFI:
    case SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE:
    case SAI_ACL_TABLE_ATTR_FIELD_TC:
    case SAI_ACL_TABLE_ATTR_FIELD_PACKET_VLAN:
    case SAI_ACL_TABLE_ATTR_FIELD_PORT_USER_META:
    case SAI_ACL_TABLE_ATTR_FIELD_VLAN_USER_META:
    case SAI_ACL_TABLE_ATTR_FIELD_ACL_USER_META:
    case SAI_ACL_TABLE_ATTR_FIELD_FDB_NPU_META_DST_HIT:
    case SAI_ACL_TABLE_ATTR_FIELD_NEIGHBOR_NPU_META_DST_HIT:
    case SAI_ACL_TABLE_ATTR_FIELD_ROUTE_NPU_META_DST_HIT:
    case SAI_ACL_TABLE_ATTR_FIELD_BTH_OPCODE:
    case SAI_ACL_TABLE_ATTR_FIELD_AETH_SYNDROME:
    case SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE: {
        return SAI_STATUS_NOT_SUPPORTED;
        break;
    }
    default:
        return SAI_STATUS_INVALID_PARAMETER;
        break;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
acl_udk::build_udf_field(la_acl_field_def& udk_acl_field, uint32_t acl_field) const
{
    sai_status_t status = get_udf_description(acl_field,
                                              udk_acl_field.udf_desc.offset,
                                              udk_acl_field.udf_desc.width,
                                              udk_acl_field.udf_desc.protocol_layer,
                                              udk_acl_field.udf_desc.header,
                                              udk_acl_field.type);
    if (status != SAI_STATUS_SUCCESS) {
        // Unsupported yet ACL match field.
        sai_log_error(SAI_API_ACL, "Invalid or unsupported ACL match field %u.", acl_field);
        return status;
    }

    udk_acl_field.udf_desc.index = (acl_field - SAI_ACL_TABLE_ATTR_FIELD_START) + 1;
    udk_acl_field.udf_desc.is_relative = true;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
acl_udk::build_udf_hop_limit(la_acl_field_def& udk_acl_field) const
{
    udk_acl_field.udf_desc.offset = offsetof(ip6_hdr, ip6_hlim);
    udk_acl_field.udf_desc.width = 1; // one byte
    udk_acl_field.udf_desc.protocol_layer = 0;
    udk_acl_field.udf_desc.header = 0;
    udk_acl_field.type = la_acl_field_type_e::UDF;

    // It fine to use TTL as udf field index as there will be two seperate
    // sdk acl match key vectors.
    udk_acl_field.udf_desc.index = (SAI_ACL_TABLE_ATTR_FIELD_TTL - SAI_ACL_TABLE_ATTR_FIELD_START) + 1;
    udk_acl_field.udf_desc.is_relative = true;

    return SAI_STATUS_SUCCESS;
}

// Using a list of SAI table match fields, SDK match key vector is created.
// Special case handling.
//      1. If udk_fields contains only TTL, then two sdk_key_vec should be created.
//          1.a UDK = la_acl_field_type_e::TTL
//          1.b UDK = la_acl_field_type_e::UDF (that describes HOP_LIMIT)
//      2. If udk_fields contains ipv4 header field/s and TTL, sdk key vector should be built using la_acl_field_type_e::TTL
//      3. If udk_fields contains ipv6 header field/s and TTL, sdk key vector should be built using la_acl_field_type_e::UDF that
//      describes HOP_LIMIT.

sai_status_t
acl_udk::build_la_acl_key_vector(la_acl_direction_e sdk_acl_dir,
                                 const std::set<uint32_t>& udk_fields,
                                 la_acl_key_def_vec_t& sdk_key_vec,
                                 bool& is_v4_profile,
                                 bool& is_v6_profile,
                                 bool& add_ttl_and_hop_limit)
{
    bool tos_inserted = false;
    bool udk_has_ttl_match_field = false;
    bool is_ipv4_profile = false, is_ipv6_profile = false;
    add_ttl_and_hop_limit = false;
    // udk_fields set contain all ACL fields for a single ACL match profile.
    for (auto& acl_field : udk_fields) {
        // build from each user provided acl field, udk component.
        // Tag all acl fields as udk component. Use list of acl fields
        // built as udk component to create an acl profile
        if (acl_field >= SAI_ACL_TABLE_ATTR_FIELD_START && acl_field <= SAI_ACL_TABLE_ATTR_FIELD_END) {
            if (acl_field == SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE) {
                // For now, do nothing. ACE in HW table will not contain ip-type.
                // Currently, only V4 and V6 ACLs are supported and as seperate hw lookup tables.
                continue;
            }

            // if field/s that make up TOS are already added, then no need to add again
            // for not yet added TOS subfields. For SDK adding TOS is equivalent to adding
            // all fields that make up TOS.
            if (tos_inserted && (acl_field == SAI_ACL_TABLE_ATTR_FIELD_ECN || acl_field == SAI_ACL_TABLE_ATTR_FIELD_DSCP
                                 || acl_field == SAI_ACL_TABLE_ATTR_FIELD_TOS)) {
                continue;
            }

            if (acl_field == SAI_ACL_TABLE_ATTR_FIELD_TTL) {
                // Because attribute TTL is common to both v4 and v6 lookup (SAI spec doesn't define
                // HOP_LIMIT as acl table/entry attribute), handle it as special case
                // after processing all other table match fields.
                udk_has_ttl_match_field = true;
                continue;
            }

            // If the ACL direction is egress, remove ethertype from the sdk acl fields.
            // The SDK/NPL does not support Etherype as a key field in the profile for egress direction.
            // We can claim support as long as the ACL entries (ACEs) use a value of IPv4(0x0800) and
            // IPv6(0x86DD) for IPv4 and IPv6 ACLs respectively.
            // The NPL supports this by matching ethertype already by executing IPv4 ACL for 0x0800
            // and IPv6 ACL for 0x86DD. Any other values for Ethertype in the ACL entry will be rejected.
            if ((acl_field == SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE) && (sdk_acl_dir == la_acl_direction_e::EGRESS)) {
                continue;
            }

            la_acl_field_def udk_acl_field;
            sai_status_t status = build_udf_field(udk_acl_field, acl_field);
            if (status == SAI_STATUS_NOT_SUPPORTED) {
                // Skip this ACL key field if not supported.
                // If there are keys passed in that we do not support, they should be failed
                // when the ACL entry is created.
                continue;
            }
            sai_return_on_error(status);

            bool is_ipv4_profile_field, is_ipv6_profile_field;
            is_acl_table_attr_iphdr_distinguisher_field(acl_field, is_ipv4_profile_field, is_ipv6_profile_field);
            is_ipv4_profile |= is_ipv4_profile_field;
            is_ipv6_profile |= is_ipv6_profile_field;
            if (is_ipv4_profile && is_ipv6_profile) {
                // ACL table match field set has fields from both v4 and v6 header.
                // Invalid match field set.
                sai_log_error(SAI_API_ACL,
                              "Invalid ACL match field set. Contains both v4 and v6 match fields in single match profile");
                return SAI_STATUS_FAILURE;
            }

            sdk_key_vec.push_back(udk_acl_field);
            if (acl_field == SAI_ACL_TABLE_ATTR_FIELD_ECN || acl_field == SAI_ACL_TABLE_ATTR_FIELD_DSCP
                || acl_field == SAI_ACL_TABLE_ATTR_FIELD_TOS) {
                // SDK requires one field for both ECN,DSCP
                tos_inserted = true;
            }
        } else {
            sai_log_error(SAI_API_ACL, "Extended ACL table match fields are not supported yet. Or invalid ACL match field.");
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    if (udk_has_ttl_match_field) {
        if (is_ipv4_profile) {
            la_acl_field_def udk_acl_field;
            sai_status_t status = build_udf_field(udk_acl_field, SAI_ACL_TABLE_ATTR_FIELD_TTL);
            sai_return_on_error(status);
            sdk_key_vec.push_back(udk_acl_field);
        } else if (is_ipv6_profile) {
            // build UDF for HOP_LIMIT
            la_acl_field_def udk_acl_field;
            sai_status_t status = build_udf_hop_limit(udk_acl_field);
            sai_return_on_error(status);
            sdk_key_vec.push_back(udk_acl_field);
        } else {
            // ACL table with TTL and no l3 header field and with/without other L2/L4 fields.
            add_ttl_and_hop_limit = true;
        }
    }

    is_v4_profile = is_ipv4_profile;
    is_v6_profile = is_ipv6_profile;
    return SAI_STATUS_SUCCESS;
}

void
acl_udk::destroy_acl_key_profiles()
{
    std::vector<sdk_acl_profile_details> perm_profiles;

    for (auto const& udk_field_profile : m_sdk_acl_profiles) {
        // Skip permanent user defined key profiles
        if (udk_field_profile.m_permanent) {
            perm_profiles.push_back(udk_field_profile);
        } else {
            m_sdev->m_dev->destroy(udk_field_profile.m_sdk_acl_profile);
        }
    }

    m_sdk_acl_profiles.clear();
    for (auto const& udk_field_profile : perm_profiles) {
        m_sdk_acl_profiles.push_back(udk_field_profile);
    }
}

la_status
acl_udk::create_sdk_acl_key_profile(uint8_t sdk_profile_type,
                                    la_acl_direction_e sdk_acl_dir,
                                    bool permanent_profile,
                                    const la_acl_key_def_vec_t& udk_fields,
                                    const std::set<uint32_t>& acl_table_fields)
{
    la_acl_key_profile* sdk_acl_key_profile;
    la_acl_key_type_e key_type
        = (sdk_profile_type == sai_acl::SDK_ACL_PROFILE_TYPE_V4) ? la_acl_key_type_e::IPV4 : la_acl_key_type_e::IPV6;
    bool is_v4_profile = (sdk_profile_type == sai_acl::SDK_ACL_PROFILE_TYPE_V4) ? true : false;

    // try 160B key. If it fails, try 320
    la_status lstatus = m_sdev->m_dev->create_acl_key_profile(
        key_type, sdk_acl_dir, udk_fields, la_acl_tcam_interface_e::E_0, sdk_acl_key_profile);
    if (lstatus != LA_STATUS_SUCCESS) {
        lstatus = m_sdev->m_dev->create_acl_key_profile(
            key_type, sdk_acl_dir, udk_fields, la_acl_tcam_interface_e::E_0_AND_1, sdk_acl_key_profile);
    }
    la_return_on_error_log(lstatus, "Error creating UDK acl match profile");
    sai_log_debug(SAI_API_ACL, "ACL sdk %s match profile created using user defined key set.", (is_v4_profile) ? "v4" : "v6");
    sai_log_debug(SAI_API_ACL, "ACL sdk match profile created using user defined key set.");

    sdk_acl_profile_details udk_profile(acl_table_fields, sdk_profile_type, sdk_acl_dir, permanent_profile, sdk_acl_key_profile);
    m_sdk_acl_profiles.push_back(udk_profile);

    return LA_STATUS_SUCCESS;
}

// Using a list of user defined acl match field set, a sdk acl profile is created one per each
// user defined acl field match set.
sai_status_t
acl_udk::create_user_defined_acl_sdk_profiles(la_acl_direction_e sdk_acl_dir, const std::set<std::set<uint32_t>>& udk_field_set)
{
    // one or more lists of user defined acl field list are present.
    uint8_t v4_profile_count = 0;
    uint8_t v6_profile_count = 0;
    bool user_meta_device_property_set = false;

    for (const auto& udk_fields : udk_field_set) {
        // If user-meta is used in ACLs, then set device property.
        if (!user_meta_device_property_set) {
            set_device_property_if_class_id_used(udk_fields, user_meta_device_property_set);
        }

        la_acl_key_def_vec_t sdk_key_vec;
        bool is_v4_profile = false;
        bool is_v6_profile = false;
        bool add_ttl_and_hop_limit_udf = false;
        sai_status_t status = build_la_acl_key_vector(
            sdk_acl_dir, udk_fields, sdk_key_vec, is_v4_profile, is_v6_profile, add_ttl_and_hop_limit_udf);
        sai_return_on_error(status, "Error processing user defined ACL keys. Could not build sdk acl profile");
        if (is_v4_profile) {
            ++v4_profile_count;
        } else if (is_v6_profile) {
            ++v6_profile_count;
        } else {
            // In case of match vector without any L3 header fields, create both
            // v4 and v6 profiles and acl table.
            ++v4_profile_count;
            ++v6_profile_count;
        }

        // Create upto allowed number of v4 and v6 match profiles.
        if (v4_profile_count > UDK_MAX_V4_PROFILE_COUNT || v6_profile_count > UDK_MAX_V6_PROFILE_COUNT) {
            // Device cannot support more than one (UDK_MAX_*_PROFILE_COUNT) profiles for given v4/v6 type..
            sai_log_error(SAI_API_ACL,
                          "Device ACL match profile overflow. More match profiles specified than the device can handle.");
            return SAI_STATUS_FAILURE;
        }

        // create acl profile for each of the lists and cache it.
        // L3  hdr field/s present
        if (is_v4_profile || is_v6_profile) {
            uint8_t sdk_profile_type = is_v4_profile ? sai_acl::SDK_ACL_PROFILE_TYPE_V4 : sai_acl::SDK_ACL_PROFILE_TYPE_V6;
            acl_udk::create_sdk_acl_key_profile(sdk_profile_type, sdk_acl_dir, true, sdk_key_vec, udk_fields);
        } else { // (!is_v4_profile && !is_v6_profile)
            // ACL match vector with non L3 fields and with or without TTL
            // or ACL match vector with only TTL
            la_acl_key_def_vec_t sdk_key_v4_vec = sdk_key_vec;
            la_acl_key_def_vec_t sdk_key_v6_vec = sdk_key_vec;
            if (add_ttl_and_hop_limit_udf) {
                la_acl_field_def udk_acl_field;
                sai_status_t status = build_udf_field(udk_acl_field, SAI_ACL_TABLE_ATTR_FIELD_TTL);
                sai_return_on_error(status);
                sdk_key_v4_vec.push_back(udk_acl_field);
                status = build_udf_hop_limit(udk_acl_field);
                sai_return_on_error(status);
                sdk_key_v6_vec.push_back(udk_acl_field);
            }

            acl_udk::create_sdk_acl_key_profile(sai_acl::SDK_ACL_PROFILE_TYPE_V4, sdk_acl_dir, true, sdk_key_v4_vec, udk_fields);
            acl_udk::create_sdk_acl_key_profile(sai_acl::SDK_ACL_PROFILE_TYPE_V6, sdk_acl_dir, true, sdk_key_v6_vec, udk_fields);
        }
    }

    return SAI_STATUS_SUCCESS;
}

// The function checks if to be added set of fields (udk_fields) is already part or subset
// of already collected user defined field sets.
void
acl_udk::consolidate_set_of_udk_acl_fieldset(std::set<std::set<uint32_t>>& udk_field_sets,
                                             const std::set<uint32_t>& udk_fields) const
{
    // If udk_fields set is super set of a set already present in udk_field_sets, then such a set
    // from udk_field_sets is removed and new udk_fields is added to to the set of sets.
    // If udk_fields is subset of a set present in udk_field_sets, then udk_fields set is
    // not added to udk_field_sets. In all other cases, udk_fields which is a set is added
    // to udk_field_sets.
    bool add_new_set = true;
    for (auto const& field_set : udk_field_sets) {
        if (field_set.size() == udk_fields.size() && field_set == udk_fields) {
            // already processed ACL field list. Duplicate
            add_new_set = false;
            break;
        }

        if (field_set.size() == udk_fields.size()) {
            // new to be added udk field set might match another already included
            // udk set or be subset
            continue;
        }

        if (field_set.size() != udk_fields.size()) {
            const std::set<uint32_t>* smaller_set;
            const std::set<uint32_t>* larger_set;
            if (field_set.size() < udk_fields.size()) {
                smaller_set = &field_set;
                larger_set = &udk_fields;
            } else {
                smaller_set = &udk_fields;
                larger_set = &field_set;
            }

            if (std::includes(larger_set->begin(), larger_set->end(), smaller_set->begin(), smaller_set->end())) {
                // smaller set is subset
                if (smaller_set == &field_set) {
                    // an already processed user-field-list is subset of
                    // newly provided user field list.
                    udk_field_sets.erase(field_set);
                    // There cannot be more subsets.
                    break;
                } else {
                    // new set of user defined fields are subset of already processed
                    // user provided field list. Ignore new one.
                    add_new_set = false;
                    break;
                }
            }
        }
    }

    if (add_new_set) {
        udk_field_sets.insert(udk_fields);
    }
}

bool
acl_udk::is_udk_field_set_v4_v6_combined(const std::set<uint32_t>& udk_field_set)
{
    bool is_v4 = false;
    bool is_v6 = false;
    for (auto field : udk_field_set) {
        if (field == SAI_ACL_TABLE_ATTR_FIELD_TTL) {
            // There is no SAI attribute ACL_ATTR_FIELD_HOP_LIMIT
            // TTL is used on both v4 and v6. Treat it like non l3 field
            // and let other fields in the field set help to identify
            // field set is combined v4 and v6.
            continue;
        }
        is_v4 |= sai_acl::is_v4_acl_table_field(field);
        is_v6 |= sai_acl::is_v6_acl_table_field(field);
    }

    return is_v4 && is_v6;
}

// Iterate over a list of user defined acl match field set. When a UDK field-set is combined v4 and v6,
// create two seperate user defined sets. First field-set will include in it v4 header fields
// and all non L3 fields. Second field-set will include in it V6 header fields and all non L3 fields.
void
acl_udk::create_v4_v6_field_sets_from_udk(std::set<std::set<uint32_t>>& udk_field_set)
{
    std::set<std::set<uint32_t>> v4_v6_field_sets{};
    for (auto it = udk_field_set.cbegin(); it != udk_field_set.cend();) {
        if (is_udk_field_set_v4_v6_combined(*it)) {
            v4_v6_field_sets.insert(*it);
            it = udk_field_set.erase(it);
        } else {
            ++it;
        }
    }

    if (!v4_v6_field_sets.empty()) {
        for (auto& v4_v6_fields : v4_v6_field_sets) {
            std::set<uint32_t> v4_acl_fields{};
            std::set<uint32_t> v6_acl_fields{};
            sai_acl::create_seperate_v4_v6_acl_table_field_set(v4_v6_fields, v4_acl_fields, v6_acl_fields);
            udk_field_set.insert(v4_acl_fields);
            udk_field_set.insert(v6_acl_fields);
        }
    }
}

// Processes a list of list of user defined acl fields. Each list of acl fields will
// be treated as an instance of acl match profile. This allows to provide
// as an example seperate list of user defined fields for v4 and v6 packets.
// Example:
//  AttributeList[
//      Attribute[SAI_SWITCH_ATTR_EXT_ACL_FEILD_LIST] = { Keys for V4 match }
//      Attribute[SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST] = { Keys for v6 match }
//  ]
//  Each such SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST will be treated a complete
//  list of user provided fields for acl match profile.
//  When second set of fields is subset of already provided user acl fields,
//  both use same match profile.
sai_status_t
acl_udk::process_user_defined_acl_table_fields(const sai_attribute_t* attr_list, uint32_t attr_count)
{
    // Since table field list provided at switch init time will be phased out, until
    // then, set ACL direction to ingress.
    la_acl_direction_e sdk_acl_dir = la_acl_direction_e::INGRESS;
    std::set<std::set<uint32_t>> udk_field_sets{};
    for (size_t attr_index = 0; attr_index < attr_count; ++attr_index) {
        const sai_attribute_t* attr = &attr_list[attr_index];
        if (attr->id != SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST) {
            // Since this function is expected to be invoked at the time
            // of switch creation, this function will NOT process any other
            // switch attributes other than acl field list provided
            // as value for extended switch attribute ACL_FIELD_LIST
            continue;
        }

        // get list of ACL fields associated with SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST
        if (attr->value.u32list.count && attr->value.u32list.list != nullptr) {
            std::set<uint32_t> udk_fields{};
            for (size_t s = 0; s < attr->value.u32list.count; ++s) {
                auto attr_id = attr->value.u32list.list[s];
                if (attr_id >= SAI_ACL_TABLE_ATTR_FIELD_START && attr_id <= SAI_ACL_TABLE_ATTR_FIELD_END) {
                    if (skip_udk_attribute(attr_id)) {
                        continue;
                    }
                    udk_fields.insert(attr_id);
                } else {
                    sai_log_error(SAI_API_ACL,
                                  "Extended ACL table match fields are not supported yet. Or invalid ACL match field.");
                    return SAI_STATUS_INVALID_PARAMETER;
                }
            }

            if (!udk_fields.empty()) {
                consolidate_set_of_udk_acl_fieldset(udk_field_sets, udk_fields);
            }
        }
    }

    // A set of user defined acl match fields are provided at the time
    // of switch creation as switch extended attributes. Create SDK
    // acl profile for each user defined match set.
    if (!udk_field_sets.empty()) {
        // one or more lists of user defined acl field list are present.
        // If there are combined v4 and v6 UDK field-set, create two sets
        // one for each v4 and v6 protocol and add it to udk_field_sets.
        create_v4_v6_field_sets_from_udk(udk_field_sets);
        sai_status_t status = create_user_defined_acl_sdk_profiles(sdk_acl_dir, udk_field_sets);
        sai_return_on_error(status, "Error processing user defined ACL keys");
    } else {
        // No user defined ACL table fields. No acl profiles created.
        sai_log_debug(SAI_API_SWITCH, "Empty user defined key set for acl match.");
    }

    return SAI_STATUS_SUCCESS;
}

bool
acl_udk::is_udk_acl_profiles() const
{
    return (m_sdk_acl_profiles.size() != 0);
}

// If an acl profile for a given subset of udk acl table fields already exist,
// return acl_profile
la_acl_key_profile*
acl_udk::get_udk_acl_profile(const std::set<uint32_t>& table_fields, uint8_t profile_type, la_acl_direction_e dir) const
{
    for (auto const& udk_field_profile : m_sdk_acl_profiles) {
        if ((udk_field_profile.m_profile_type == profile_type) && (udk_field_profile.m_dir == dir)
            && (table_fields.size() <= udk_field_profile.m_udks.size())
            && std::includes(udk_field_profile.m_udks.cbegin(),
                             udk_field_profile.m_udks.cend(),
                             table_fields.cbegin(),
                             table_fields.cend())) {
            return udk_field_profile.m_sdk_acl_profile;
        }
    }
    return nullptr;
}

// A set of UDK fields used as acl table field attributes are returned
// by this function.
const std::set<std::set<uint32_t>>
acl_udk::get_udk_field_sets() const
{
    std::set<std::set<uint32_t>> acl_table_field_sets{};
    for (auto const& udk_field_profile : m_sdk_acl_profiles) {
        acl_table_field_sets.insert(udk_field_profile.m_udks);
    }
    return acl_table_field_sets;
}

// Returns true if input acl table field set matches non default acl table
// fields.
bool
acl_udk::is_udk_acl_field_set(const std::set<uint32_t>& table_fields) const
{
    for (auto const& udk_field_profile : m_sdk_acl_profiles) {
        if (udk_field_profile.m_udks == table_fields) {
            return true;
        }
    }
    return false;
}

sai_status_t
acl_udk::create_sdk_acl_key_with_udf_fields(uint8_t profile_type,
                                            const std::set<uint32_t>& table_fields,
                                            la_acl_key_def_vec_t& sdk_key_vec) const
{
    return SAI_STATUS_SUCCESS;
}

sai_status_t
acl_udk::create_sai_acl_table_attr_field_umap(std::unordered_map<std::string, sai_acl_table_attr_t>& umap) const
{
    // Create list of SAI ACL table field attributes to be used to process
    // ACL key profiles.
    umap.reserve(SAI_ACL_TABLE_ATTR_FIELD_END - SAI_ACL_TABLE_ATTR_FIELD_START);
    for (uint32_t attr = SAI_ACL_TABLE_ATTR_FIELD_START; attr <= SAI_ACL_TABLE_ATTR_FIELD_END; ++attr) {
        if ((attr >= SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MIN)
            && (attr <= SAI_ACL_TABLE_ATTR_USER_DEFINED_FIELD_GROUP_MAX)) {
            continue;
        }
        sai_acl_table_attr_t attr_id = (sai_acl_table_attr_t)attr;
        sai_log_info(SAI_API_ACL, "SAI ACL table attr field name %s is %u", to_string(attr_id).c_str(), attr);
        umap.emplace(to_string(attr_id), attr_id);
    }

    return SAI_STATUS_SUCCESS;
}

void
acl_udk::set_acl_key_profile_set(std::set<std::set<uint32_t>>& acl_key_profile_sets,
                                 const std::set<uint32_t> acl_key_profile_fields) const
{
    if (!acl_key_profile_fields.empty()) {
        consolidate_set_of_udk_acl_fieldset(acl_key_profile_sets, acl_key_profile_fields);
    }
}

sai_status_t
acl_udk::process_acl_key_profiles(la_acl_direction_e dir, std::set<std::set<uint32_t>> acl_key_profile_sets)
{
    if (!acl_key_profile_sets.empty()) {
        create_v4_v6_field_sets_from_udk(acl_key_profile_sets);
        sai_status_t status = create_user_defined_acl_sdk_profiles(dir, acl_key_profile_sets);
        if (status != SAI_STATUS_SUCCESS) {
            sai_log_error(SAI_API_SWITCH, "Error processing ACL key profile sets");
            return status;
        }
    } else {
        sai_log_debug(SAI_API_SWITCH, "Empty ACL key profiles set for match");
    }

    return SAI_STATUS_SUCCESS;
}
}
}
