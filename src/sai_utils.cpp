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

// -----------------------------------------
// Some portions are also:
//
// Copyright (C) 2014 Mellanox Technologies, Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License); You may
// Obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//
// -----------------------------------------
//

#include "sai_constants.h"
#include "sai_device.h"
#include "sai_logger.h"
#include <algorithm>
#include <arpa/inet.h>
#include <bitset>
#include <cassert>
#include <inttypes.h>
#include <map>
#include <sys/socket.h>

namespace silicon_one
{
namespace sai
{

using namespace std;

unordered_map<sai_attr_id_t, sai_attribute_value_t>
sai_parse_attributes(uint32_t attr_count, const sai_attribute_t* attr_list)
{
    unordered_map<sai_attr_id_t, sai_attribute_value_t> output;

    for (uint32_t i = 0; i < attr_count; ++i) {
        sai_attribute_t attr = attr_list[i];
        output[attr.id] = attr.value;
    }

    return output;
}

static inline uint32_t
find_first_zero(uint8_t byte)
{
    uint8_t bit_mask = 1 << 7;
    for (uint32_t bit_index = 0; bit_index < 8; bit_index++, bit_mask >>= 1) {
        if ((byte & bit_mask) == 0) {
            return bit_index;
        }
    }
    return 8;
}

uint32_t
ip_mask_to_length(uint32_t mask)
{
    for (uint32_t byte_index = 0; byte_index < 4; byte_index++, mask >>= 8) {
        if ((mask & 0xffU) != 0xffU) {
            return byte_index * 8 + find_first_zero(mask);
        }
    }
    return 32;
}

uint32_t
ipv6_mask_to_length(const sai_ip6_t& mask)
{
    const uint32_t byte_count = sizeof(sai_ip6_t);

    for (uint32_t byte_index = 0; byte_index < byte_count; byte_index++) {
        const uint8_t byte = mask[byte_index];
        if (byte != 0xffU) {
            return byte_index * 8 + find_first_zero(byte);
        }
    }

    return byte_count * 8;
}

void
ipv4_prefix_length_to_mask(uint8_t prefix_length, sai_ip4_t& mask)
{
    uint64_t calc_mask = ((uint64_t)0xFFFFFFFF >> (uint64_t(32 - prefix_length))) << (uint64_t)(32 - prefix_length);
    mask = htonl((uint32_t)calc_mask);
}

void
ipv6_prefix_length_to_mask(uint8_t prefix_length, sai_ip6_t& mask)
{
    memset(mask, 0xff, 16);
    uint8_t idx;
    for (idx = (prefix_length / 8) + 1; idx < 16; idx++) {
        // Flip these bytes to 0
        mask[idx] = 0;
    }
    // Now handle the remainder
    idx = prefix_length / 8;
    uint8_t bits_to_shift = (8 - prefix_length % 8);
    mask[idx] = (mask[idx] >> bits_to_shift) << bits_to_shift;
}

static sai_status_t
find_functionality_attrib_index(_In_ const sai_attr_id_t id,
                                _In_ const sai_attribute_entry_t* functionality_attr,
                                _Out_ uint32_t* index)
{
    uint32_t curr_index;

    //    STUB_LOG_ENTER();

    if (nullptr == functionality_attr) {
        sai_log_debug(SAI_API_SWITCH, "nullptr value functionality attrib");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (nullptr == index) {
        sai_log_debug(SAI_API_SWITCH, "nullptr value index");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (curr_index = 0; END_FUNCTIONALITY_ATTRIBS_ID != functionality_attr[curr_index].id; curr_index++) {
        if (id == functionality_attr[curr_index].id) {
            *index = curr_index;
            // STUB_LOG_EXIT();
            return SAI_STATUS_SUCCESS;
        }
    }

    //    STUB_LOG_EXIT();
    return SAI_STATUS_ITEM_NOT_FOUND;
}

sai_status_t
check_attribs_metadata(_In_ uint32_t attr_count,
                       _In_ const sai_attribute_t* attr_list,
                       _In_ const sai_attribute_entry_t* functionality_attr,
                       _In_ const sai_vendor_attribute_entry_t* functionality_vendor_attr,
                       _In_ sai_operation_t oper)
{
    uint32_t functionality_attr_count, ii, index;
    bool* attr_present;

    //    STUB_LOG_ENTER();

    if ((attr_count) && (nullptr == attr_list)) {
        sai_log_debug(SAI_API_SWITCH, "nullptr value attr list");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (nullptr == functionality_attr) {
        sai_log_debug(SAI_API_SWITCH, "nullptr value functionality attrib");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (nullptr == functionality_vendor_attr) {
        sai_log_debug(SAI_API_SWITCH, "nullptr value functionality vendor attrib");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_OPERATION_MAX <= oper) {
        sai_log_debug(SAI_API_SWITCH, "Invalid operation %d", oper);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (SAI_OPERATION_REMOVE == oper) {
        /* No attributes expected for remove at this point */
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    if (SAI_OPERATION_SET == oper) {
        if (1 != attr_count) {
            sai_log_debug(SAI_API_SWITCH, "Set operation supports only single attribute");
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    for (functionality_attr_count = 0; END_FUNCTIONALITY_ATTRIBS_ID != functionality_attr[functionality_attr_count].id;
         functionality_attr_count++) {
        if (functionality_attr[functionality_attr_count].id != functionality_vendor_attr[functionality_attr_count].id) {
            sai_log_debug(SAI_API_SWITCH,
                          "Mismatch between functionality attribute and vendor attribute index %u %u %u",
                          functionality_attr_count,
                          functionality_attr[functionality_attr_count].id,
                          functionality_vendor_attr[functionality_attr_count].id);
            return SAI_STATUS_FAILURE;
        }
    }

    attr_present = (bool*)calloc(functionality_attr_count, sizeof(bool));
    if (nullptr == attr_present) {
        sai_log_info(SAI_API_SWITCH, "Can't allocate memory");
        return SAI_STATUS_NO_MEMORY;
    }

    for (ii = 0; ii < attr_count; ii++) {
        if (SAI_STATUS_SUCCESS != find_functionality_attrib_index(attr_list[ii].id, functionality_attr, &index)) {
            sai_log_debug(SAI_API_SWITCH, "Invalid attribute %d", attr_list[ii].id);
            free(attr_present);
            return SAI_STATUS_ATTR_NOT_IMPLEMENTED_0 + ii;
        }

        if ((SAI_OPERATION_CREATE == oper) && (!(functionality_attr[index].valid_for_create))) {
            sai_log_debug(SAI_API_SWITCH, "Invalid attribute %s for create", functionality_attr[index].attrib_name);
            free(attr_present);
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }

        if ((SAI_OPERATION_SET == oper) && (!(functionality_attr[index].valid_for_set))) {
            sai_log_debug(SAI_API_SWITCH, "Invalid attribute %s for set", functionality_attr[index].attrib_name);
            free(attr_present);
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }

        if ((SAI_OPERATION_GET == oper) && (!(functionality_attr[index].valid_for_get))) {
            sai_log_debug(SAI_API_SWITCH, "Invalid attribute %s for get", functionality_attr[index].attrib_name);
            free(attr_present);
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }

        if (!(functionality_vendor_attr[index].is_supported[oper])) {
            sai_log_debug(SAI_API_SWITCH, "Not supported attribute %s", functionality_attr[index].attrib_name);
            free(attr_present);
            return SAI_STATUS_ATTR_NOT_SUPPORTED_0 + ii;
        }

        if (!(functionality_vendor_attr[index].is_implemented[oper])) {
            sai_log_debug(SAI_API_SWITCH, "Not implemented attribute %s", functionality_attr[index].attrib_name);
            free(attr_present);
            return SAI_STATUS_ATTR_NOT_IMPLEMENTED_0 + ii;
        }

        if (attr_present[index]) {
            sai_log_debug(SAI_API_SWITCH,
                          "Attribute %s appears twice in attribute list at index %d",
                          functionality_attr[index].attrib_name,
                          ii);
            free(attr_present);
            return SAI_STATUS_INVALID_ATTRIBUTE_0 + ii;
        }
        // For some attribs, a nullptr value in attr value is valid and expected as per the SAI spec.
        // Comment this early detection out in order to return proper count.
        /*
        if (((SAI_ATTR_VAL_TYPE_OBJLIST == functionality_attr[index].type) && (nullptr == attr_list[ii].value.objlist.list))
            || ((SAI_ATTR_VAL_TYPE_U32LIST == functionality_attr[index].type) && (nullptr == attr_list[ii].value.u32list.list))
            || ((SAI_ATTR_VAL_TYPE_S32LIST == functionality_attr[index].type) && (nullptr == attr_list[ii].value.s32list.list))
            || ((SAI_ATTR_VAL_TYPE_VLANLIST == functionality_attr[index].type) && (nullptr == attr_list[ii].value.vlanlist.list))
            || ((SAI_ATTR_VAL_TYPE_MAPLIST == functionality_attr[index].type) && (nullptr == attr_list[ii].value.maplist.list))) {
            sai_log_debug(SAI_API_SWITCH, "Null list attribute %s at index %d", functionality_attr[index].attrib_name, ii);
            free(attr_present);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + ii;
        }
        */
        attr_present[index] = true;
    }

    /*
    if (SAI_OPERATION_CREATE == oper) {
        for (ii = 0; ii < functionality_attr_count; ii++) {
            if ((functionality_attr[ii].mandatory_on_create) && (!attr_present[ii])) {
                sai_log_debug(SAI_API_SWITCH, "Missing mandatory attribute %s on create", functionality_attr[ii].attrib_name);
                free(attr_present);
                return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
            }
        }
    }
    */

    free(attr_present);

    //    STUB_LOG_EXIT();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
sai_ipv4_to_str(_In_ sai_ip4_t value, _In_ uint32_t max_length, _Out_ char* value_str, _Out_ int* chars_written)
{
    uint32_t ipaddr = htobe32(value);
    inet_ntop(AF_INET, &ipaddr, value_str, max_length);

    if (nullptr != chars_written) {
        *chars_written = (int)strlen(value_str);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
sai_ipv6_to_str(_In_ sai_ip6_t value, _In_ uint32_t max_length, _Out_ char* value_str, _Out_ int* chars_written)
{
    struct in6_addr addr;

    memset(value_str, '\0', max_length);
    memcpy(addr.s6_addr, value, sizeof(addr));

    inet_ntop(AF_INET6, &addr, value_str, max_length);

    if (nullptr != chars_written) {
        *chars_written = (int)strlen(value_str);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_ipaddr_to_str(_In_ sai_ip_address_t value, _In_ uint32_t max_length, _Out_ char* value_str, _Out_ int* chars_written)
{
    int res;

    if (SAI_IP_ADDR_FAMILY_IPV4 == value.addr_family) {
        sai_ipv4_to_str(value.addr.ip4, max_length, value_str, chars_written);
    } else if (SAI_IP_ADDR_FAMILY_IPV6 == value.addr_family) {
        sai_ipv6_to_str(value.addr.ip6, max_length, value_str, chars_written);
    } else {
        res = snprintf(value_str, max_length, "Invalid ipaddr family %d", value.addr_family);
        if (nullptr != chars_written) {
            *chars_written = res;
        }
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_ipprefix_to_str(_In_ sai_ip_prefix_t value, _In_ uint32_t max_length, _Out_ char* value_str)
{
    int chars_written;
    uint32_t pos = 0;

    if (SAI_IP_ADDR_FAMILY_IPV4 == value.addr_family) {
        sai_ipv4_to_str(value.addr.ip4, max_length, value_str, &chars_written);
        pos += chars_written;
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        pos += snprintf(value_str + pos, max_length - pos, " ");
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        sai_ipv4_to_str(value.mask.ip4, max_length - pos, value_str + pos, &chars_written);
    } else if (SAI_IP_ADDR_FAMILY_IPV6 == value.addr_family) {
        sai_ipv6_to_str(value.addr.ip6, max_length, value_str, &chars_written);
        pos += chars_written;
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        pos += snprintf(value_str + pos, max_length - pos, " ");
        if (pos > max_length) {
            return SAI_STATUS_SUCCESS;
        }
        sai_ipv6_to_str(value.mask.ip6, max_length - pos, value_str + pos, &chars_written);
    } else {
        snprintf(value_str, max_length, "Invalid addr family %d", value.addr_family);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_dispatch_attribs_handler(_In_ uint32_t attr_count,
                             _Inout_ sai_attribute_t* attr_list,
                             _In_ const sai_attribute_entry_t* functionality_attr,
                             _In_ const sai_vendor_attribute_entry_t* functionality_vendor_attr,
                             _In_ const sai_object_key_t* key,
                             _In_ const char* key_str)
{
    uint32_t ii, index = 0;
    vendor_cache_t cache;
    sai_status_t status;

    if ((attr_count) && (nullptr == attr_list)) {
        sai_log_debug(SAI_API_SWITCH, "nullptr value attr list");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (nullptr == functionality_attr) {
        sai_log_debug(SAI_API_SWITCH, "nullptr value functionality attrib");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (nullptr == functionality_vendor_attr) {
        sai_log_debug(SAI_API_SWITCH, "nullptr value functionality vendor attrib");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    memset(&cache, 0, sizeof(cache));

    bool buffer_overflow = false;

    for (ii = 0; ii < attr_count; ii++) {
        assert(SAI_STATUS_SUCCESS == find_functionality_attrib_index(attr_list[ii].id, functionality_attr, &index));

        if (!functionality_vendor_attr[index].getter) {
            sai_log_debug(SAI_API_SWITCH,
                          "Attribute %s not implemented on get and defined incorrectly",
                          functionality_attr[index].attrib_name);
            return SAI_STATUS_ATTR_NOT_IMPLEMENTED_0 + ii;
        }

        status = functionality_vendor_attr[index].getter(
            key, &(attr_list[ii].value), ii, &cache, functionality_vendor_attr[index].getter_arg);

        // In case of insufficient buffer, remember but continue processing
        // so user can get all needed buffer sizes in one shot
        if (status == SAI_STATUS_BUFFER_OVERFLOW) {
            buffer_overflow = true;
            continue;
        }

        if (status != SAI_STATUS_SUCCESS) {
            sai_log_debug(SAI_API_SWITCH, "Failed getting attrib %s", functionality_attr[index].attrib_name);
        }
        sai_return_on_error(status);
    }

    return buffer_overflow ? SAI_STATUS_BUFFER_OVERFLOW : SAI_STATUS_SUCCESS;
}

sai_status_t
sai_get_attributes(_In_ const sai_object_key_t* key,
                   _In_ const char* key_str,
                   _In_ const sai_attribute_entry_t* functionality_attr,
                   _In_ const sai_vendor_attribute_entry_t* functionality_vendor_attr,
                   _In_ uint32_t attr_count,
                   _Inout_ sai_attribute_t* attr_list)
{
    sai_status_t status;

    status = check_attribs_metadata(attr_count, attr_list, functionality_attr, functionality_vendor_attr, SAI_OPERATION_GET);
    if (status != SAI_STATUS_SUCCESS) {
        sai_log_debug(SAI_API_SWITCH, "Failed attribs check, key:%s", key_str);
    }
    sai_return_on_error(status);

    status = get_dispatch_attribs_handler(attr_count, attr_list, functionality_attr, functionality_vendor_attr, key, key_str);
    sai_return_on_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_dispatch_attrib_handler(_In_ const sai_attribute_t* attr,
                            _In_ const sai_attribute_entry_t* functionality_attr,
                            _In_ const sai_vendor_attribute_entry_t* functionality_vendor_attr,
                            _In_ const sai_object_key_t* key,
                            _In_ const char* key_str)
{
    uint32_t index = 0;
    sai_status_t err;

    if (nullptr == attr) {
        sai_log_debug(SAI_API_SWITCH, "nullptr value attr");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (nullptr == functionality_attr) {
        sai_log_debug(SAI_API_SWITCH, "nullptr value functionality attrib");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (nullptr == functionality_vendor_attr) {
        sai_log_debug(SAI_API_SWITCH, "nullptr value functionality vendor attrib");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    assert(SAI_STATUS_SUCCESS == find_functionality_attrib_index(attr->id, functionality_attr, &index));

    if (!functionality_vendor_attr[index].setter) {
        sai_log_debug(
            SAI_API_SWITCH, "Attribute %s not implemented on set and defined incorrectly", functionality_attr[index].attrib_name);
        return SAI_STATUS_ATTR_NOT_IMPLEMENTED_0;
    }

    err = functionality_vendor_attr[index].setter(key, &(attr->value), functionality_vendor_attr[index].setter_arg);

    return err;
}

sai_status_t
sai_create_and_set_attribute(_In_ const sai_object_key_t* key,
                             _In_ const char* key_str,
                             _In_ const sai_attribute_entry_t* functionality_attr,
                             _In_ const sai_vendor_attribute_entry_t* functionality_vendor_attr,
                             _In_ const sai_attribute_t* attr)
{
    sai_status_t status;

    if (SAI_STATUS_SUCCESS
        != (status = check_attribs_metadata(1, attr, functionality_attr, functionality_vendor_attr, SAI_OPERATION_CREATE))) {
        sai_log_debug(SAI_API_SWITCH, "Failed attribs check, key:%s", key_str);
        return status;
    }

    if (SAI_STATUS_SUCCESS
        != (status = set_dispatch_attrib_handler(attr, functionality_attr, functionality_vendor_attr, key, key_str))) {
        sai_log_debug(SAI_API_SWITCH, "Failed set attrib dispatch");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_set_attribute(_In_ const sai_object_key_t* key,
                  _In_ const char* key_str,
                  _In_ const sai_attribute_entry_t* functionality_attr,
                  _In_ const sai_vendor_attribute_entry_t* functionality_vendor_attr,
                  _In_ const sai_attribute_t* attr)
{
    sai_status_t status;

    if (SAI_STATUS_SUCCESS
        != (status = check_attribs_metadata(1, attr, functionality_attr, functionality_vendor_attr, SAI_OPERATION_SET))) {
        sai_log_debug(SAI_API_SWITCH, "Failed attribs check, key:%s", key_str);
        return status;
    }

    if (SAI_STATUS_SUCCESS
        != (status = set_dispatch_attrib_handler(attr, functionality_attr, functionality_vendor_attr, key, key_str))) {
        sai_log_debug(SAI_API_SWITCH, "Failed set attrib dispatch");
        return status;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
find_attrib_in_list(_In_ uint32_t attr_count,
                    _In_ const sai_attribute_t* attr_list,
                    _In_ sai_attr_id_t attrib_id,
                    _Out_ const sai_attribute_value_t** attr_value,
                    _Out_ uint32_t* index)
{
    uint32_t ii;

    if ((attr_count) && (nullptr == attr_list)) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (nullptr == attr_value) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (nullptr == index) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (ii = 0; ii < attr_count; ii++) {
        if (attr_list[ii].id == attrib_id) {
            *attr_value = &(attr_list[ii].value);
            *index = ii;
            return SAI_STATUS_SUCCESS;
        }
    }

    return SAI_STATUS_ITEM_NOT_FOUND;
}

/* Data needed for sai_query_attribute_capability */
extern const sai_attribute_entry_t acl_counter_attribs[];
extern const sai_attribute_entry_t acl_entry_attribs[];
extern const sai_attribute_entry_t acl_table_attribs[];
extern const sai_attribute_entry_t acl_table_group_attribs[];
extern const sai_attribute_entry_t acl_table_group_member_attribs[];
extern const sai_attribute_entry_t bridge_attribs[];
extern const sai_attribute_entry_t bridge_port_attribs[];
extern const sai_attribute_entry_t debug_counter_attribs[];
extern const sai_attribute_entry_t fdb_attribs[];
extern const sai_attribute_entry_t hostif_attribs[];
extern const sai_attribute_entry_t hostif_trap_attribs[];
extern const sai_attribute_entry_t hostif_trap_group_attribs[];
extern const sai_attribute_entry_t inseg_attribs[];
extern const sai_attribute_entry_t lag_attribs[];
extern const sai_attribute_entry_t lag_member_attribs[];
extern const sai_attribute_entry_t neighbor_attribs[];
extern const sai_attribute_entry_t next_hop_attribs[];
extern const sai_attribute_entry_t next_hop_group_attribs[];
extern const sai_attribute_entry_t next_hop_group_member_attribs[];
extern const sai_attribute_entry_t port_attribs[];
extern const sai_attribute_entry_t qos_map_attribs[];
extern const sai_attribute_entry_t queue_attribs[];
extern const sai_attribute_entry_t rif_attribs[];
extern const sai_attribute_entry_t route_attribs[];
extern const sai_attribute_entry_t scheduler_attribs[];
extern const sai_attribute_entry_t scheduler_group_attribs[];
extern const sai_attribute_entry_t switch_attribs[];
extern const sai_attribute_entry_t system_port_attribs[];
extern const sai_attribute_entry_t vlan_attribs[];
extern const sai_attribute_entry_t vlan_member_attribs[];
extern const sai_attribute_entry_t wred_attribs[];

static const std::map<sai_object_type_t, const sai_attribute_entry_t*> obj_types_info = {
    {SAI_OBJECT_TYPE_ACL_COUNTER, acl_counter_attribs},
    {SAI_OBJECT_TYPE_ACL_ENTRY, acl_entry_attribs},
    {SAI_OBJECT_TYPE_ACL_TABLE, acl_table_attribs},
    {SAI_OBJECT_TYPE_ACL_TABLE_GROUP, acl_table_group_attribs},
    {SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, acl_table_group_member_attribs},
    {SAI_OBJECT_TYPE_BRIDGE, bridge_attribs},
    {SAI_OBJECT_TYPE_BRIDGE_PORT, bridge_port_attribs},
    {SAI_OBJECT_TYPE_DEBUG_COUNTER, debug_counter_attribs},
    {SAI_OBJECT_TYPE_FDB_ENTRY, fdb_attribs},
    {SAI_OBJECT_TYPE_HOSTIF, hostif_attribs},
    {SAI_OBJECT_TYPE_HOSTIF_TRAP, hostif_trap_attribs},
    {SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, hostif_trap_group_attribs},
    {SAI_OBJECT_TYPE_INSEG_ENTRY, inseg_attribs},
    {SAI_OBJECT_TYPE_LAG, lag_attribs},
    {SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_attribs},
    {SAI_OBJECT_TYPE_NEIGHBOR_ENTRY, neighbor_attribs},
    {SAI_OBJECT_TYPE_NEXT_HOP, next_hop_attribs},
    {SAI_OBJECT_TYPE_NEXT_HOP_GROUP, next_hop_group_attribs},
    {SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER, next_hop_group_member_attribs},
    {SAI_OBJECT_TYPE_PORT, port_attribs},
    {SAI_OBJECT_TYPE_QOS_MAP, qos_map_attribs},
    {SAI_OBJECT_TYPE_QUEUE, queue_attribs},
    {SAI_OBJECT_TYPE_ROUTER_INTERFACE, rif_attribs},
    {SAI_OBJECT_TYPE_ROUTE_ENTRY, route_attribs},
    {SAI_OBJECT_TYPE_SCHEDULER, scheduler_attribs},
    {SAI_OBJECT_TYPE_SCHEDULER_GROUP, scheduler_group_attribs},
    {SAI_OBJECT_TYPE_SWITCH, switch_attribs},
    {SAI_OBJECT_TYPE_SYSTEM_PORT, system_port_attribs},
    {SAI_OBJECT_TYPE_VLAN, vlan_attribs},
    {SAI_OBJECT_TYPE_VLAN_MEMBER, vlan_member_attribs},
    {SAI_OBJECT_TYPE_WRED, wred_attribs},
};

const sai_attribute_entry_t*
obj_type_attr_info_get(_In_ sai_object_type_t object_type)
{
    auto pos = obj_types_info.find(object_type);
    if (pos == obj_types_info.end()) {
        return nullptr;
    } else {
        return pos->second;
    }
}

uint32_t
to_sai_lane(const sai_system_port_config_t& sp_config)
{
    return (sp_config.attached_core_index << BITS_IN_BYTE) | sp_config.attached_core_port_index;
}

uint32_t
to_sai_lane(uint32_t slice_id, uint32_t ifg_id, uint32_t pif)
{
    uint32_t ifg_idx = (IFGS_PER_SLICE * slice_id) + ifg_id;
    return (ifg_idx << BITS_IN_BYTE) | pif;
}

bool
continue_on_failure(uint32_t from, uint32_t object_count, sai_bulk_op_error_mode_t mode, sai_status_t* object_statuses)
{
    uint32_t i;

    if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
        // Set remaining object status values to SAI_STATUS_NOT_EXECUTED
        // as defined in the spec
        for (i = from; i < object_count; i++) {
            object_statuses[i] = SAI_STATUS_NOT_EXECUTED;
        }
        return false;
    }
    return true;
}
}
}
