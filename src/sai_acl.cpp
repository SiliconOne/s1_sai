// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco").
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

#include "sai_acl.h"

#include <algorithm>
#include <arpa/inet.h>

#include "sai_device.h"
#include "sai_logger.h"
#include "sai_mirror.h"

namespace silicon_one
{
namespace sai
{
const std::set<sai_acl_action_type_t> sai_acl::supported_ingress_acl_actions_list = {SAI_ACL_ACTION_TYPE_COUNTER,
                                                                                     SAI_ACL_ACTION_TYPE_PACKET_ACTION,
                                                                                     SAI_ACL_ACTION_TYPE_SET_TC,
                                                                                     SAI_ACL_ACTION_TYPE_SET_DSCP,
                                                                                     SAI_ACL_ACTION_TYPE_MIRROR_INGRESS,
                                                                                     SAI_ACL_ACTION_TYPE_REDIRECT,
                                                                                     SAI_ACL_ACTION_TYPE_SET_POLICER,
                                                                                     SAI_ACL_ACTION_TYPE_INT_INSERT};

const std::set<sai_acl_action_type_t> sai_acl::supported_egress_acl_actions_list
    = {SAI_ACL_ACTION_TYPE_COUNTER, SAI_ACL_ACTION_TYPE_PACKET_ACTION};

sai_acl::sai_acl(std::shared_ptr<lsai_device> sai_dev)
    : m_sdev(sai_dev),
      m_acl_table_db(SAI_OBJECT_TYPE_ACL_TABLE, MAX_ACL_TABLES),
      m_acl_entry_db(SAI_OBJECT_TYPE_ACL_ENTRY, MAX_ACL_ENTRIES),
      m_acl_counter_db(SAI_OBJECT_TYPE_ACL_COUNTER, MAX_ACL_COUNTERS),
      m_acl_range_db(SAI_OBJECT_TYPE_ACL_RANGE, MAX_ACL_RANGES),
      m_acl_table_group_db(SAI_OBJECT_TYPE_ACL_TABLE_GROUP, MAX_ACL_TABLE_GROUPS),
      m_acl_table_group_member_db(SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, MAX_ACL_TABLE_GROUP_MEMBERS),
      m_acl_udk(sai_dev)
{
}

sai_acl::~sai_acl() = default;

sai_status_t
sai_acl::sai_acl_stage_to_sdk_acl_dir(sai_acl_stage_t sai_acl_stage, la_acl_direction_e& sdk_acl_dir)
{
    switch (sai_acl_stage) {
    case SAI_ACL_STAGE_INGRESS:
        sdk_acl_dir = la_acl_direction_e::INGRESS;
        break;
    case SAI_ACL_STAGE_EGRESS:
        sdk_acl_dir = la_acl_direction_e::EGRESS;
        break;
    default:
        sai_log_error(SAI_API_ACL, "ACL stage %d is not supported.", sai_acl_stage);
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::sdk_acl_dir_to_sai_acl_stage(la_acl_direction_e sdk_acl_dir, sai_acl_stage_t& sai_acl_stage)
{

    switch (sdk_acl_dir) {
    case la_acl_direction_e::INGRESS:
        sai_acl_stage = SAI_ACL_STAGE_INGRESS;
        break;
    case la_acl_direction_e::EGRESS:
        sai_acl_stage = SAI_ACL_STAGE_EGRESS;
        break;
    default:
        sai_log_error(SAI_API_ACL, "SDK supported ACL direction/stage %d is not mappable to sai stage.", sdk_acl_dir);
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::sai_attr_to_sdk_field_type(_In_ sai_attr_id_t sai_id, _Out_ la_acl_field_type_e& sdk_type)
{
    switch (sai_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6:
        sdk_type = la_acl_field_type_e::IPV6_SIP;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6:
        sdk_type = la_acl_field_type_e::IPV6_DIP;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP:
        sdk_type = la_acl_field_type_e::IPV4_SIP;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IP:
        sdk_type = la_acl_field_type_e::IPV4_DIP;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT:
        sdk_type = la_acl_field_type_e::SPORT;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT:
        sdk_type = la_acl_field_type_e::DPORT;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL:
        sdk_type = la_acl_field_type_e::PROTOCOL;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_DSCP:
    case SAI_ACL_ENTRY_ATTR_FIELD_ECN:
        sdk_type = la_acl_field_type_e::TOS;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_TTL:
        sdk_type = la_acl_field_type_e::TTL;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS:
        sdk_type = la_acl_field_type_e::IPV4_FLAGS;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS:
        sdk_type = la_acl_field_type_e::TCP_FLAGS;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE:
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE:
        sdk_type = la_acl_field_type_e::MSG_TYPE;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE:
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE:
        sdk_type = la_acl_field_type_e::MSG_CODE;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER:
        sdk_type = la_acl_field_type_e::LAST_NEXT_HEADER;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_IPV6_FLOW_LABEL:
        sdk_type = la_acl_field_type_e::IPV6_FLOW_LABEL;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG:
        sdk_type = la_acl_field_type_e::IPV6_FRAGMENT;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_FDB_DST_USER_META:
    case SAI_ACL_ENTRY_ATTR_FIELD_ROUTE_DST_USER_META:
    case SAI_ACL_ENTRY_ATTR_FIELD_NEIGHBOR_DST_USER_META: {
        sdk_type = la_acl_field_type_e::CLASS_ID;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC:
        sdk_type = la_acl_field_type_e::DA;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC:
        sdk_type = la_acl_field_type_e::SA;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE:
        sdk_type = la_acl_field_type_e::ETHER_TYPE;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT:
    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS:
        sdk_type = la_acl_field_type_e::SOURCE_SYSTEM_PORT;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID:
        sdk_type = la_acl_field_type_e::VLAN_OUTER;
        break;
    default:
        sai_log_error(SAI_API_ACL, "Entry field match rule not supported.");
        return SAI_STATUS_NOT_SUPPORTED;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::check_and_get_device_and_map_index(_In_ sai_object_id_t acl_obj_id,
                                            _In_ sai_object_type_t type,
                                            _Out_ std::shared_ptr<lsai_device>& sdev,
                                            _Out_ uint32_t& map_id)
{
    lsai_object la_obj(acl_obj_id);
    sdev = la_obj.get_device();
    if (la_obj.type != type || sdev == nullptr || sdev->m_dev == nullptr) {
        sai_log_error(SAI_API_ACL, "Bad ACL Object id %lu", acl_obj_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    map_id = la_obj.index;
    switch (type) {
    case SAI_OBJECT_TYPE_ACL_TABLE: {
        lasai_acl_table_t table;
        if (sdev->m_acl_handler->m_acl_table_db.get(map_id, table) != LA_STATUS_SUCCESS) {
            sai_log_error(SAI_API_ACL, "Unable to find ACL Table with id %lu", acl_obj_id);
            return SAI_STATUS_ITEM_NOT_FOUND;
        }
        break;
    }
    case SAI_OBJECT_TYPE_ACL_ENTRY: {
        lasai_acl_entry_t entry;
        if (sdev->m_acl_handler->m_acl_entry_db.get(map_id, entry) != LA_STATUS_SUCCESS) {
            sai_log_error(SAI_API_ACL, "Unable to find ACL Entry with id %lu", acl_obj_id);
            return SAI_STATUS_ITEM_NOT_FOUND;
        }
        break;
    }
    case SAI_OBJECT_TYPE_ACL_COUNTER: {
        lasai_acl_counter_t counter;
        if (sdev->m_acl_handler->m_acl_counter_db.get(map_id, counter) != LA_STATUS_SUCCESS) {
            sai_log_error(SAI_API_ACL, "Unable to find ACL Counter with id %lu", acl_obj_id);
            return SAI_STATUS_ITEM_NOT_FOUND;
        }
        break;
    }
    case SAI_OBJECT_TYPE_ACL_RANGE: {
        lasai_acl_range_t range;
        if (sdev->m_acl_handler->m_acl_range_db.get(map_id, range) != LA_STATUS_SUCCESS) {
            sai_log_error(SAI_API_ACL, "Unable to find ACL Range with id %lu", acl_obj_id);
            return SAI_STATUS_ITEM_NOT_FOUND;
        }
        break;
    }
    case SAI_OBJECT_TYPE_ACL_TABLE_GROUP: {
        lasai_acl_table_group_t table_group;
        if (sdev->m_acl_handler->m_acl_table_group_db.get(map_id, table_group) != LA_STATUS_SUCCESS) {
            sai_log_error(SAI_API_ACL, "Unable to find ACL Table Group with id %lu", acl_obj_id);
            return SAI_STATUS_ITEM_NOT_FOUND;
        }
        break;
    }
    case SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER: {
        lasai_acl_table_group_member_t member;
        if (sdev->m_acl_handler->m_acl_table_group_member_db.get(map_id, member) != LA_STATUS_SUCCESS) {
            sai_log_error(SAI_API_ACL, "Unable to find ACL Table Group Member with id %lu", acl_obj_id);
            return SAI_STATUS_ITEM_NOT_FOUND;
        }
        break;
    }
    default: {
        sai_log_error(SAI_API_ACL, "Unsupported ACL object type.");
        return SAI_STATUS_NOT_SUPPORTED;
    }
    }

    return SAI_STATUS_SUCCESS;
}

sai_uint32_t
sai_acl::get_acl_actions_max_count()
{
    std::set<sai_acl_action_type_t> all_actions = supported_ingress_acl_actions_list;
    all_actions.insert(supported_egress_acl_actions_list.begin(), supported_egress_acl_actions_list.end());

    return static_cast<sai_uint32_t>(all_actions.size());
}

sai_status_t
sai_acl::get_acl_table_and_check_attr(_In_ const sai_object_key_t* key,
                                      _Inout_ sai_attribute_value_t* attr,
                                      _Out_ lasai_acl_table_t& acl_table)
{
    if (key == nullptr || attr == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status_t sstatus;
    la_status status;
    sai_object_id_t acl_table_id = key->key.object_id;

    std::shared_ptr<lsai_device> sdev;
    uint32_t map_id;

    sstatus = check_and_get_device_and_map_index(acl_table_id, SAI_OBJECT_TYPE_ACL_TABLE, sdev, map_id);
    sai_return_on_error(sstatus);

    status = sdev->m_acl_handler->m_acl_table_db.get(map_id, acl_table);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_table_attr_stage(_In_ const sai_object_key_t* key,
                                  _Inout_ sai_attribute_value_t* attr,
                                  _In_ unsigned int attr_index,
                                  _Inout_ vendor_cache_t* cache,
                                  void* arg)
{
    lasai_acl_table_t acl_table;
    sai_status_t sstatus;

    sstatus = get_acl_table_and_check_attr(key, attr, acl_table);
    sai_return_on_error(sstatus);

    attr->u32 = acl_table.stage;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_table_attr_bind_point_type_list(_In_ const sai_object_key_t* key,
                                                 _Inout_ sai_attribute_value_t* attr,
                                                 _In_ unsigned int attr_index,
                                                 _Inout_ vendor_cache_t* cache,
                                                 void* arg)
{
    lasai_acl_table_t acl_table;
    sai_status_t sstatus;

    sstatus = get_acl_table_and_check_attr(key, attr, acl_table);
    sai_return_on_error(sstatus);

    sstatus = fill_sai_list(acl_table.bind_point_types.begin(), acl_table.bind_point_types.end(), attr->s32list);
    sai_return_on_error(sstatus);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_table_attr_size(_In_ const sai_object_key_t* key,
                                 _Inout_ sai_attribute_value_t* attr,
                                 _In_ unsigned int attr_index,
                                 _Inout_ vendor_cache_t* cache,
                                 void* arg)
{
    lasai_acl_table_t acl_table;
    sai_status_t sstatus;

    sstatus = get_acl_table_and_check_attr(key, attr, acl_table);
    sai_return_on_error(sstatus);

    attr->u32 = (acl_table.table_size == MAX_ACL_ENTRIES_PER_TABLE) ? 0 : acl_table.table_size;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_table_action_type_list(_In_ const sai_object_key_t* key,
                                        _Inout_ sai_attribute_value_t* attr,
                                        _In_ unsigned int attr_index,
                                        _Inout_ vendor_cache_t* cache,
                                        void* arg)
{
    lasai_acl_table_t acl_table;
    sai_status_t sstatus;

    sstatus = get_acl_table_and_check_attr(key, attr, acl_table);
    sai_return_on_error(sstatus);

    sstatus = fill_sai_list(acl_table.acl_action_types.begin(), acl_table.acl_action_types.end(), attr->s32list);
    sai_return_on_error(sstatus);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_table_attr_match_field(_In_ const sai_object_key_t* key,
                                        _Inout_ sai_attribute_value_t* attr,
                                        _In_ unsigned int attr_index,
                                        _Inout_ vendor_cache_t* cache,
                                        void* arg)
{
    lasai_acl_table_t acl_table;
    sai_status_t sstatus;

    sstatus = get_acl_table_and_check_attr(key, attr, acl_table);
    sai_return_on_error(sstatus);

    uint64_t index = (uint64_t)arg - SAI_ACL_TABLE_ATTR_FIELD_START;

    if (index >= acl_table.match_field.size()) {
        attr->booldata = false;
    } else {
        attr->booldata = acl_table.match_field[index];
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_table_attr_match_range(_In_ const sai_object_key_t* key,
                                        _Inout_ sai_attribute_value_t* attr,
                                        _In_ unsigned int attr_index,
                                        _Inout_ vendor_cache_t* cache,
                                        void* arg)
{
    lasai_acl_table_t acl_table;
    sai_status_t sstatus = SAI_STATUS_SUCCESS;

    sstatus = get_acl_table_and_check_attr(key, attr, acl_table);
    sai_return_on_error(sstatus);

    return fill_sai_list(acl_table.match_range.begin(), acl_table.match_range.end(), attr->s32list);
}

sai_status_t
sai_acl::get_acl_table_attr_entry_list(_In_ const sai_object_key_t* key,
                                       _Inout_ sai_attribute_value_t* attr,
                                       _In_ unsigned int attr_index,
                                       _Inout_ vendor_cache_t* cache,
                                       void* arg)
{
    lasai_acl_table_t acl_table;
    sai_status_t sstatus = SAI_STATUS_SUCCESS;

    sstatus = get_acl_table_and_check_attr(key, attr, acl_table);
    sai_return_on_error(sstatus);

    // Make a copy that skips duplicate entries from range expansion
    std::vector<sai_object_id_t> unique_entries(acl_table.entry_list);
    auto new_end = std::unique(unique_entries.begin(), unique_entries.end());
    unique_entries.resize(std::distance(unique_entries.begin(), new_end));

    return fill_sai_list(unique_entries.begin(), unique_entries.end(), attr->objlist);
}

sai_status_t
sai_acl::get_acl_table_attr_avail_entry_count(_In_ const sai_object_key_t* key,
                                              _Inout_ sai_attribute_value_t* attr,
                                              _In_ unsigned int attr_index,
                                              _Inout_ vendor_cache_t* cache,
                                              void* arg)
{
    lasai_acl_table_t acl_table;
    sai_status_t sstatus;

    sstatus = get_acl_table_and_check_attr(key, attr, acl_table);
    sai_return_on_error(sstatus);

    // Use SAI Defined MAX_ACL_ENTRIES_PER_TABLE.
    // Is this limit lower than available TCAM?
    // Possibly check TCAM util
    attr->u32 = MAX_ACL_ENTRIES_PER_TABLE - acl_table.entry_list.size();

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_table_attr_avail_acl_counters(_In_ const sai_object_key_t* key,
                                               _Inout_ sai_attribute_value_t* attr,
                                               _In_ unsigned int attr_index,
                                               _Inout_ vendor_cache_t* cache,
                                               void* arg)
{
    lasai_acl_table_t acl_table;
    sai_status_t sstatus;

    sstatus = get_acl_table_and_check_attr(key, attr, acl_table);
    sai_return_on_error(sstatus);

    sai_object_id_t table_id = key->key.object_id;

    std::shared_ptr<lsai_device> sdev;
    uint32_t map_id;
    sstatus = check_and_get_device_and_map_index(table_id, SAI_OBJECT_TYPE_ACL_TABLE, sdev, map_id);
    sai_return_on_error(sstatus);

    size_t used = 0;

    auto& map = sdev->m_acl_handler->m_acl_counter_db.map();

    for (auto iter = map.cbegin(); iter != map.cend(); iter++) {
        if (iter->second.table_id == table_id) {
            used++;
        }
    }

    auto remaining_elements = sdev->m_acl_handler->m_acl_counter_db.get_free_space();

    attr->u32 = min((MAX_ACL_ENTRIES_PER_TABLE - used), remaining_elements);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_entry_and_check_attr(_In_ const sai_object_key_t* key,
                                      _Inout_ sai_attribute_value_t* attr,
                                      _Out_ lasai_acl_entry_t& acl_entry)
{
    if (key == nullptr || attr == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_status status;
    sai_status_t sstatus;
    sai_object_id_t acl_entry_id = key->key.object_id;

    std::shared_ptr<lsai_device> sdev;
    uint32_t map_id;

    sstatus = check_and_get_device_and_map_index(acl_entry_id, SAI_OBJECT_TYPE_ACL_ENTRY, sdev, map_id);
    sai_return_on_error(sstatus);

    status = sdev->m_acl_handler->m_acl_entry_db.get(map_id, acl_entry);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_entry_attr_table_id(_In_ const sai_object_key_t* key,
                                     _Inout_ sai_attribute_value_t* attr,
                                     _In_ unsigned int attr_index,
                                     _Inout_ vendor_cache_t* cache,
                                     void* arg)
{
    lasai_acl_entry_t acl_entry;
    sai_status_t sstatus;

    sstatus = get_acl_entry_and_check_attr(key, attr, acl_entry);
    sai_return_on_error(sstatus);

    attr->oid = acl_entry.table_id;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_entry_attr_priority(_In_ const sai_object_key_t* key,
                                     _Inout_ sai_attribute_value_t* attr,
                                     _In_ unsigned int attr_index,
                                     _Inout_ vendor_cache_t* cache,
                                     void* arg)
{
    lasai_acl_entry_t acl_entry;
    sai_status_t sstatus;

    sstatus = get_acl_entry_and_check_attr(key, attr, acl_entry);
    sai_return_on_error(sstatus);

    attr->u32 = acl_entry.priority;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_entry_attr_admin_state(_In_ const sai_object_key_t* key,
                                        _Inout_ sai_attribute_value_t* attr,
                                        _In_ unsigned int attr_index,
                                        _Inout_ vendor_cache_t* cache,
                                        void* arg)
{
    lasai_acl_entry_t acl_entry;
    sai_status_t sstatus;

    sstatus = get_acl_entry_and_check_attr(key, attr, acl_entry);
    sai_return_on_error(sstatus);

    attr->booldata = acl_entry.admin_state;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::set_acl_entry_attr_admin_state(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_status status;
    lsai_object sai_acl_entry(key->key.object_id);
    auto sdev = sai_acl_entry.get_device();

    lasai_acl_entry_t acl_entry;
    status = sdev->m_acl_handler->m_acl_entry_db.get(sai_acl_entry.index, acl_entry);
    sai_return_on_la_error(status);

    acl_entry.admin_state = value->booldata;
    status = sdev->m_acl_handler->m_acl_entry_db.set(sai_acl_entry.index, acl_entry);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

bool
sai_acl::is_v6_ace_field(uint32_t attr_id)
{
    switch (attr_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6:
    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6:
    case SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER:
    case SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG:
    case SAI_ACL_ENTRY_ATTR_FIELD_IPV6_FLOW_LABEL:
        return true;
    default:
        return false;
    }

    return false;
}

bool
sai_acl::is_v4_ace_field(uint32_t attr_id)
{
    switch (attr_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP:
    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IP:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP:
    case SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS:
    case SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_IP_PROTOCOL:
    case SAI_ACL_ENTRY_ATTR_FIELD_IP_IDENTIFICATION:
        // case SAI_ACL_ENTRY_ATTR_FIELD_TTL:
        return true;
    default:
        return false;
    }

    return false;
}

bool
sai_acl::is_v6_sdk_ace_field(const la_acl_field& sdk_acl_field)
{
    switch (sdk_acl_field.type) {
    case la_acl_field_type_e::IPV6_SIP:
    case la_acl_field_type_e::IPV6_DIP:
    case la_acl_field_type_e::LAST_NEXT_HEADER:
    case la_acl_field_type_e::IPV6_FRAGMENT:
    case la_acl_field_type_e::HOP_LIMIT:
    case la_acl_field_type_e::IPV6_FLOW_LABEL:
        return true;
    default:
        return false;
    }

    return false;
}

bool
sai_acl::is_v4_sdk_ace_field(const la_acl_field& sdk_acl_field)
{
    switch (sdk_acl_field.type) {
    case la_acl_field_type_e::IPV4_SIP:
    case la_acl_field_type_e::IPV4_DIP:
    case la_acl_field_type_e::IPV4_FLAGS:
    case la_acl_field_type_e::PROTOCOL:
    case la_acl_field_type_e::IPV4_FRAG_OFFSET:
        return true;
    default:
        return false;
    }

    return false;
}

sai_status_t
sai_acl::get_acl_entry_attr_field_rule(_In_ const sai_object_key_t* key,
                                       _Inout_ sai_attribute_value_t* attr,
                                       _In_ unsigned int attr_index,
                                       _Inout_ vendor_cache_t* cache,
                                       void* arg)
{
    lasai_acl_entry_t acl_entry;
    sai_status_t sstatus;
    la_status status;

    sstatus = get_acl_entry_and_check_attr(key, attr, acl_entry);
    sai_return_on_error(sstatus);

    lsai_object sai_obj(key->key.object_id);
    auto sdev = sai_obj.get_device();
    lasai_acl_table_t acl_table;

    status = sdev->m_acl_handler->m_acl_table_db.get(acl_entry.table_id, acl_table);
    sai_return_on_la_error(status);

    if (((uint64_t)arg - SAI_ACL_ENTRY_ATTR_FIELD_START) >= acl_table.match_field.size()) {
        attr->aclfield.enable = false;
        return SAI_STATUS_SUCCESS;
    }

    if (!acl_table.match_field[(uint64_t)arg - SAI_ACL_ENTRY_ATTR_FIELD_START]) {
        attr->aclfield.enable = false;
        return SAI_STATUS_SUCCESS;
    }
    attr->aclfield.enable = true;

    auto iter = acl_table.entry_list.cbegin();
    for (; iter != acl_table.entry_list.cend(); iter++) {
        if (*iter == key->key.object_id) {
            break;
        }
    }

    if (iter == acl_table.entry_list.cend()) {
        sai_log_error(SAI_API_ACL, "Entry not found in table.");
        return SAI_STATUS_FAILURE;
    }

    if ((uint64_t)arg == SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE) {
        // return shadow value.
        attr->aclfield.data.u32 = acl_entry.ip_type;
        attr->aclfield.mask.u32 = acl_entry.ip_type_mask;
        return SAI_STATUS_SUCCESS;
    }

    if ((uint64_t)arg == SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE) {
        return fill_sai_list(acl_entry.range_list.begin(), acl_entry.range_list.end(), attr->aclfield.data.objlist);
    }

    if ((uint64_t)arg == SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS) {
        return fill_sai_list(acl_entry.port_list.begin(), acl_entry.port_list.end(), attr->aclfield.data.objlist);
    }

    if (((uint64_t)arg == SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE) && (acl_table.stage == SAI_ACL_STAGE_EGRESS)) {
        // return shadow value.
        attr->aclfield.mask.u16 = 0xffff;
        if (acl_table.is_v4_acl) {
            attr->aclfield.data.u16 = 0x0800;
        } else if (acl_table.is_v6_acl) {
            attr->aclfield.data.u16 = 0x86DD;
        }
        return SAI_STATUS_SUCCESS;
    }

    uint32_t position = std::distance(acl_table.entry_list.cbegin(), iter);
    acl_entry_desc sdk_entry_desc;
    if (acl_table.is_v4_acl != acl_table.is_v6_acl) {
        if (acl_table.is_v4_acl) {
            status = acl_table.v4_sdk_acl->get(position, sdk_entry_desc);
        } else {
            status = acl_table.v6_sdk_acl->get(position, sdk_entry_desc);
        }

        sai_return_on_la_error(status);
    } else {
        if (is_v4_ace_field((uint64_t)arg)) {
            status = acl_table.v4_sdk_acl->get(position, sdk_entry_desc);
        } else if (is_v6_ace_field((uint64_t)arg)) {
            status = acl_table.v6_sdk_acl->get(position, sdk_entry_desc);
        } else {
            // Non l3 field or TTL. ACE field value can be obtained from either v4 or v6 acl table.
            status = acl_table.v4_sdk_acl->get(position, sdk_entry_desc);
        }

        sai_return_on_la_error(status);
    }

    la_acl_field_type_e sdk_field_type;
    sstatus = sai_attr_to_sdk_field_type((uint64_t)arg, sdk_field_type);
    sai_return_on_error(sstatus);

    for (la_acl_field field : sdk_entry_desc.key_val) {
        if (field.type == sdk_field_type) {
            switch ((uint64_t)arg) {
            case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6:
                reverse_copy(std::begin(field.val.ipv6_sip.b_addr),
                             std::end(field.val.ipv6_sip.b_addr),
                             std::begin(attr->aclfield.data.ip6));
                reverse_copy(std::begin(field.mask.ipv6_sip.b_addr),
                             std::end(field.mask.ipv6_sip.b_addr),
                             std::begin(attr->aclfield.mask.ip6));
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6:
                reverse_copy(std::begin(field.val.ipv6_dip.b_addr),
                             std::end(field.val.ipv6_dip.b_addr),
                             std::begin(attr->aclfield.data.ip6));
                reverse_copy(std::begin(field.mask.ipv6_dip.b_addr),
                             std::end(field.mask.ipv6_dip.b_addr),
                             std::begin(attr->aclfield.mask.ip6));
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP:
                attr->aclfield.data.ip4 = ntohl(field.val.ipv4_sip.s_addr);
                attr->aclfield.mask.ip4 = ntohl(field.mask.ipv4_sip.s_addr);
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_DST_IP:
                attr->aclfield.data.ip4 = ntohl(field.val.ipv4_dip.s_addr);
                attr->aclfield.mask.ip4 = ntohl(field.mask.ipv4_dip.s_addr);
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT:
                attr->aclfield.data.u16 = field.val.sport;
                attr->aclfield.mask.u16 = field.mask.sport;
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT:
                attr->aclfield.data.u16 = field.val.dport;
                attr->aclfield.mask.u16 = field.mask.dport;
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL:
                attr->aclfield.data.u8 = field.val.protocol;
                attr->aclfield.mask.u8 = field.mask.protocol;
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_DSCP:
                attr->aclfield.data.u8 = field.val.tos.fields.dscp;
                attr->aclfield.mask.u8 = field.mask.tos.fields.dscp;
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_ECN:
                attr->aclfield.data.u8 = field.val.tos.fields.ecn;
                attr->aclfield.mask.u8 = field.mask.tos.fields.ecn;
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_TTL:
                attr->aclfield.data.u8 = field.val.ttl;
                attr->aclfield.mask.u8 = field.mask.ttl;
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS:
                memcpy(&attr->aclfield.data.u8, &field.val.ipv4_flags, sizeof(sai_uint8_t));
                memcpy(&attr->aclfield.mask.u8, &field.mask.ipv4_flags, sizeof(sai_uint8_t));
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS:
                attr->aclfield.data.u8 = field.val.tcp_flags.flat;
                attr->aclfield.mask.u8 = field.mask.tcp_flags.flat;
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE:
            case SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE:
                attr->aclfield.data.u8 = field.val.mtype;
                attr->aclfield.mask.u8 = field.mask.mtype;
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE:
            case SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE:
                attr->aclfield.data.u8 = field.val.mcode;
                attr->aclfield.mask.u8 = field.mask.mtype;
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER:
                attr->aclfield.data.u8 = field.val.last_next_header;
                attr->aclfield.mask.u8 = field.mask.last_next_header;
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_IPV6_FLOW_LABEL:
                attr->aclfield.data.u32 = field.val.ipv6_flow_label;
                attr->aclfield.mask.u32 = field.mask.ipv6_flow_label;
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG:
                memcpy(&attr->aclfield.data.u8, &field.val.ipv6_fragment, sizeof(sai_uint8_t));
                memcpy(&attr->aclfield.mask.u8, &field.mask.ipv6_fragment, sizeof(sai_uint8_t));
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_FDB_DST_USER_META:
            case SAI_ACL_ENTRY_ATTR_FIELD_ROUTE_DST_USER_META:
            case SAI_ACL_ENTRY_ATTR_FIELD_NEIGHBOR_DST_USER_META: {
                attr->aclfield.data.u32 = field.val.class_id;
                attr->aclfield.mask.u32 = field.mask.class_id;
                break;
            }
            case SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC:
                reverse_copy(std::begin(field.val.da.bytes), std::end(field.val.da.bytes), std::begin(attr->aclfield.data.mac));
                reverse_copy(std::begin(field.mask.da.bytes), std::end(field.mask.da.bytes), std::begin(attr->aclfield.mask.mac));
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC:
                reverse_copy(std::begin(field.val.sa.bytes), std::end(field.val.sa.bytes), std::begin(attr->aclfield.data.mac));
                reverse_copy(std::begin(field.mask.sa.bytes), std::end(field.mask.sa.bytes), std::begin(attr->aclfield.mask.mac));
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE:
                attr->aclfield.data.u16 = field.val.ethtype;
                attr->aclfield.mask.u16 = field.mask.ethtype;
                break;
            case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT: {
                sai_object_id_t port_oid = SAI_NULL_OBJECT_ID;
                if (field.val.source_system_port != nullptr) {
                    status = sdev->get_la2sai_port(field.val.source_system_port->get_gid(), port_oid);
                    if (status != LA_STATUS_SUCCESS) {
                        sai_log_warn(
                            SAI_API_ACL, "Can not get sai port object for sys port %d", field.val.source_system_port->get_gid());
                    }
                }
                attr->aclfield.data.oid = port_oid;
                break;
            }
            case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID:
                attr->aclfield.data.u16 = field.val.vlan1.tci.fields.vid;
                attr->aclfield.mask.u16 = field.mask.vlan1.tci.fields.vid;
                break;
            default:
                sai_log_error(SAI_API_ACL, "Unsupported ACL Entry field match rule attribute.");
                return SAI_STATUS_NOT_SUPPORTED;
            }

            return SAI_STATUS_SUCCESS;
        }
    }

    // acl field can be disabled as default and should not return failure
    attr->aclfield.enable = false;
    return SAI_STATUS_SUCCESS;
}

std::vector<la_acl_command_action>::iterator
sai_acl::find_sdk_acl_action_command(la_acl_command_actions& sdk_acl_command_actions, la_acl_action_type_e acl_action_type)
{
    return std::find_if(sdk_acl_command_actions.begin(),
                        sdk_acl_command_actions.end(),
                        [acl_action_type](const la_acl_command_action& action) { return action.type == acl_action_type; });
}

sai_status_t
sai_acl::get_acl_entry_attr_action_rule(_In_ const sai_object_key_t* key,
                                        _Inout_ sai_attribute_value_t* attr,
                                        _In_ unsigned int attr_index,
                                        _Inout_ vendor_cache_t* cache,
                                        void* arg)
{
    lasai_acl_entry_t acl_entry;
    sai_status_t sstatus;
    la_status status;

    sstatus = get_acl_entry_and_check_attr(key, attr, acl_entry);
    sai_return_on_error(sstatus);

    lsai_object sai_obj(key->key.object_id);
    auto sdev = sai_obj.get_device();
    lasai_acl_table_t acl_table;
    status = sdev->m_acl_handler->m_acl_table_db.get(acl_entry.table_id, acl_table);
    sai_return_on_la_error(status);

    auto iter = acl_table.entry_list.cbegin();
    for (; iter != acl_table.entry_list.cend(); iter++) {
        if (*iter == key->key.object_id) {
            break;
        }
    }

    if (iter == acl_table.entry_list.cend()) {
        sai_log_error(SAI_API_ACL, "Entry not found in table.");
        return SAI_STATUS_FAILURE;
    }

    uint32_t position = std::distance(acl_table.entry_list.cbegin(), iter);

    acl_entry_desc sdk_entry_desc;
    if (acl_table.is_v4_acl && acl_table.is_v6_acl) {
        // If key vector in both v4 and v6 table is same, return action rule
        // from either table.
        // If key vector in v4 and v6 are different,
        //    then return action rule from sdk table that has atleast one
        //    l3 header field. Do not return action rule from SDK table that
        //    does NOT have l3 header field in the key vector.
        acl_entry_desc sdk_entry_desc_v4;
        acl_entry_desc sdk_entry_desc_v6;
        status = acl_table.v4_sdk_acl->get(position, sdk_entry_desc_v4);
        sai_return_on_la_error(status);
        status = acl_table.v6_sdk_acl->get(position, sdk_entry_desc_v6);
        sai_return_on_la_error(status);
        auto v4_iter = std::find_if(sdk_entry_desc_v4.key_val.cbegin(),
                                    sdk_entry_desc_v4.key_val.cend(),
                                    [](const la_acl_field& acl_field) { return is_v4_sdk_ace_field(acl_field); });
        auto v6_iter = std::find_if(sdk_entry_desc_v6.key_val.cbegin(),
                                    sdk_entry_desc_v6.key_val.cend(),
                                    [](const la_acl_field& acl_field) { return is_v6_sdk_ace_field(acl_field); });
        if (v4_iter == sdk_entry_desc_v4.key_val.cend() && v6_iter == sdk_entry_desc_v6.key_val.cend()) {
            // Both key and action rule in both v4 and v6 SDK table is same and do not contain l3 header field.
            // Command action rule value can be returned from either table.
            sdk_entry_desc = sdk_entry_desc_v4;
        } else {
            if (v4_iter != sdk_entry_desc_v4.key_val.cend()) {
                sdk_entry_desc = sdk_entry_desc_v4;
            } else {
                sdk_entry_desc = sdk_entry_desc_v6;
            }
        }
    } else if (acl_table.is_v4_acl) {
        status = acl_table.v4_sdk_acl->get(position, sdk_entry_desc);
        sai_return_on_la_error(status);
    } else {
        status = acl_table.v6_sdk_acl->get(position, sdk_entry_desc);
        sai_return_on_la_error(status);
    }

    bool drop = false;
    bool trap = false;
    bool copy = false;
    auto iter2 = find_sdk_acl_action_command(sdk_entry_desc.cmd_actions, la_acl_action_type_e::DROP);
    if (iter2 != sdk_entry_desc.cmd_actions.end()) {
        drop = iter2->data.drop;
    }

    auto iter3 = find_sdk_acl_action_command(sdk_entry_desc.cmd_actions, la_acl_action_type_e::PUNT);
    if (iter3 != sdk_entry_desc.cmd_actions.end()) {
        trap = iter3->data.punt;
    }

    auto iter4 = find_sdk_acl_action_command(sdk_entry_desc.cmd_actions, la_acl_action_type_e::MIRROR_CMD);
    if (iter4 != sdk_entry_desc.cmd_actions.end()) {
        auto mirror_id = iter4->data.mirror_cmd->get_gid();
        copy = std::any_of(sdev->m_acl_mirror_cmds.begin(), sdev->m_acl_mirror_cmds.end(), [mirror_id](la_l2_mirror_command* x) {
            return x->get_gid() == mirror_id;
        });
    }

    attr->aclaction.enable = false;
    switch ((uint64_t)arg) {
    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT: {
        auto iter = find_sdk_acl_action_command(sdk_entry_desc.cmd_actions, la_acl_action_type_e::L3_DESTINATION);
        if (iter == sdk_entry_desc.cmd_actions.end()) {
            iter = find_sdk_acl_action_command(sdk_entry_desc.cmd_actions, la_acl_action_type_e::L2_DESTINATION);
        }
        if (iter != sdk_entry_desc.cmd_actions.end()) {
            attr->aclaction.enable = true;
            attr->aclaction.parameter.oid = acl_entry.redirect_id;
        } else {
            attr->aclaction.enable = false;
        }
    } break;
    case SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION:
        if (trap) {
            attr->aclaction.enable = true;
            attr->aclaction.parameter.u32 = SAI_PACKET_ACTION_TRAP;
        } else if (copy) {
            attr->aclaction.enable = true;
            attr->aclaction.parameter.u32 = SAI_PACKET_ACTION_COPY;
        } else {
            if (drop) {
                attr->aclaction.enable = true;
                attr->aclaction.parameter.u32 = SAI_PACKET_ACTION_DROP;
            } else {
                attr->aclaction.enable = true;
                attr->aclaction.parameter.u32 = SAI_PACKET_ACTION_FORWARD;
            }
        }
        break;
    case SAI_ACL_ENTRY_ATTR_ACTION_COUNTER:
        attr->aclaction.enable = true;
        attr->aclaction.parameter.oid = acl_entry.counter_id;
        break;
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER:
        attr->aclaction.enable = true;
        attr->aclaction.parameter.oid = acl_entry.policer_id;
        break;
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_TC: {
        auto iter = find_sdk_acl_action_command(sdk_entry_desc.cmd_actions, la_acl_action_type_e::TRAFFIC_CLASS);
        if (iter != sdk_entry_desc.cmd_actions.end()) {
            attr->aclaction.enable = true;
            attr->aclaction.parameter.u8 = iter->data.traffic_class;
        } else {
            // If ACL action to set TC is not applied
            attr->aclaction.enable = false;
        }
    } break;
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP: {
        auto iter = find_sdk_acl_action_command(sdk_entry_desc.cmd_actions, la_acl_action_type_e::REMARK_FWD);
        if (iter != sdk_entry_desc.cmd_actions.end()) {
            attr->aclaction.enable = true;
            attr->aclaction.parameter.u8 = iter->data.remark_fwd;
        } else {
            attr->aclaction.enable = false;
        }
    } break;
    case SAI_ACL_ENTRY_ATTR_ACTION_INT_INSERT: {
        auto iter = find_sdk_acl_action_command(sdk_entry_desc.cmd_actions, la_acl_action_type_e::INBAND_NETWORK_TELEMETRY);
        if (iter != sdk_entry_desc.cmd_actions.end()) {
            attr->aclaction.enable = true;
            attr->aclaction.parameter.booldata = true;
        } else {
            attr->aclaction.enable = false;
        }
    } break;
    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS:
    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS: {
        auto iter = find_sdk_acl_action_command(sdk_entry_desc.cmd_actions, la_acl_action_type_e::MIRROR_CMD);
        if (!copy && iter != sdk_entry_desc.cmd_actions.end()) {
            attr->aclaction.enable = false;
            auto mirror_cmd = iter->data.mirror_cmd;
            bool is_ingress_stage = ((uint64_t)arg) == SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS;
            uint32_t mirror_session_instance
                = sdev->m_mirror_handler->mirror_session_gid_to_instance(mirror_cmd->get_gid(), is_ingress_stage);

            lasai_mirror_session_t* session = sdev->m_mirror_handler->m_mirror_db.get_ptr(mirror_session_instance);
            if (session == nullptr || session->mirror_cmd_ingress == nullptr) {
                sai_log_error(SAI_API_ACL, "Mirror object applied as ACL action has seen internal error.");
                return SAI_STATUS_FAILURE;
            }
            // Currently sdk supports only one mirror command as ACL action.
            std::vector<sai_object_id_t> mirror_oids{session->session_oid};
            sstatus = fill_sai_list(mirror_oids.begin(), mirror_oids.end(), attr->aclaction.parameter.objlist);
            sai_return_on_error(sstatus);
            attr->aclaction.enable = true;
        } else {
            attr->aclaction.enable = false;
            attr->aclaction.parameter.objlist.count = 0;
            attr->aclaction.parameter.objlist.list = nullptr;
        }
    } break;
    default:
        sai_log_error(SAI_API_ACL, "ACL Entry Action Rule not supported.");
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::build_new_acl_mirror_action_commands(sai_object_id_t mirror_oid, bool is_ingress, la_acl_command_actions& acl_commands)
{
    // From mirror oid, get sdk mirror gid and program ACL payload.
    // SDK currently supports only one mirror session per ACL entry action.
    // Even though SAI spec specifies a list of possible mirror sessions to
    // apply as ACL action, the implementation will accept only if only one
    // mirror session is applied as ACL action.
    lsai_object mirror_obj(mirror_oid);
    auto sdev = mirror_obj.get_device();
    sai_check_object(mirror_obj, SAI_OBJECT_TYPE_MIRROR_SESSION, sdev, "Mirror Object", mirror_oid);

    lasai_mirror_session_t* session = sdev->m_mirror_handler->m_mirror_db.get_ptr(mirror_obj.index);
    if (session == nullptr || session->mirror_cmd_ingress == nullptr) {
        sai_log_error(SAI_API_ACL, "Mirror object 0x%lx applied as ACL action is not recognized.", mirror_oid);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    // Set new mirror command's SDK oid
    la_acl_command_action sdk_acl_command_action_mirror_cmd{};
    sdk_acl_command_action_mirror_cmd.type = la_acl_action_type_e::MIRROR_CMD;
    auto mirror_cmd = is_ingress ? session->mirror_cmd_ingress : session->mirror_cmd_egress;
    sdk_acl_command_action_mirror_cmd.data.mirror_cmd = mirror_cmd;

    la_acl_command_action sdk_acl_command_action_do_mirror{};
    sdk_acl_command_action_do_mirror.type = la_acl_action_type_e::DO_MIRROR;
    sdk_acl_command_action_do_mirror.data.do_mirror = la_acl_mirror_src_e::DO_MIRROR_FROM_CMD;

    acl_commands.push_back(sdk_acl_command_action_mirror_cmd);
    acl_commands.push_back(sdk_acl_command_action_do_mirror);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::clear_acl_entry_action_mirror(const std::shared_ptr<lsai_device>& sdev,
                                       sai_object_id_t acl_table_oid,
                                       acl_entry_desc& sdk_entry_desc,
                                       bool is_ingress)
{

    auto& sdk_acl_command_actions = sdk_entry_desc.cmd_actions;
    auto iter = find_sdk_acl_action_command(sdk_acl_command_actions, la_acl_action_type_e::MIRROR_CMD);
    if (iter != sdk_acl_command_actions.end()) {
        // modify existing mirror command used as acl action.
        // Release current mirror session used by ACE
        auto current_mirror_cmd = iter->data.mirror_cmd;
        if (current_mirror_cmd == nullptr) {
            return SAI_STATUS_INVALID_PARAMETER;
        }
        sdk_acl_command_actions.erase(iter);

        uint32_t mirror_session_instance
            = sdev->m_mirror_handler->mirror_session_gid_to_instance(current_mirror_cmd->get_gid(), is_ingress);
        sai_status_t status = sdev->m_mirror_handler->clear_mirror_session_used_by_ace(sdev, mirror_session_instance, is_ingress);
        sai_return_on_error(status);
        auto iter2 = find_sdk_acl_action_command(sdk_acl_command_actions, la_acl_action_type_e::DO_MIRROR);
        if (iter2 != sdk_acl_command_actions.end()) {
            sdk_acl_command_actions.erase(iter2);
        }
    } else {
        // clearing mirror acl action on ACE that was not mirroring
        // duplicate mirorring clear on ace.
        // Or when removing ACE, this function is used to clear any attached
        // mirror sessions.
        // In either case, there is no need to log or take an action.
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::set_acl_entry_action_redirect(la_acl_command_action& sdk_acl_command, sai_object_id_t target_oid)
{
    lsai_object target_obj(target_oid);
    auto sdev = target_obj.get_device();
    if (sdev == nullptr || sdev->m_dev == nullptr) {
        sai_log_error(SAI_API_ACL, "ACL Redirect target is an invalid object 0x%lx", target_oid);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_status status;
    switch (target_obj.type) {
    case SAI_OBJECT_TYPE_NEXT_HOP: {
        next_hop_entry* nh_entry = nullptr;
        status = sdev->m_next_hops.get_ptr(target_obj.index, nh_entry);
        sai_return_on_la_error(status);

        switch (nh_entry->type) {
        case SAI_NEXT_HOP_TYPE_IP:
            sdk_acl_command.type = la_acl_action_type_e::L3_DESTINATION;
            sdk_acl_command.data.l3_dest = nh_entry->next_hop;
            break;
        case SAI_NEXT_HOP_TYPE_MPLS:
        case SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP:
        case SAI_NEXT_HOP_TYPE_SEGMENTROUTE_SIDLIST:
        case SAI_NEXT_HOP_TYPE_SEGMENTROUTE_ENDPOINT:
        default:
            sai_log_error(SAI_API_ACL, "ACL Redirect target next hop type is unsupported: %d", nh_entry->type);
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
        break;
    }
    case SAI_OBJECT_TYPE_PORT: {
        port_entry* pentry = nullptr;
        status = sdev->m_ports.get_ptr(target_obj.index, pentry);
        sai_return_on_la_error(status);

        if (pentry->service.eth_port == nullptr) {
            sai_log_error(SAI_API_ACL, "ACL Redirect target port type is unsupported: %d", pentry->type);
            return SAI_STATUS_FAILURE;
        }

        sdk_acl_command.type = la_acl_action_type_e::L2_DESTINATION;
        sdk_acl_command.data.l2_dest = pentry->service.eth_port;
        break;
    }
    case SAI_OBJECT_TYPE_SYSTEM_PORT:
    case SAI_OBJECT_TYPE_LAG:
    case SAI_OBJECT_TYPE_NEXT_HOP_GROUP:
    case SAI_OBJECT_TYPE_BRIDGE_PORT:
    case SAI_OBJECT_TYPE_L2MC_GROUP:
    case SAI_OBJECT_TYPE_IPMC_GROUP:
        sai_log_error(SAI_API_ACL, "ACL Redirect target type is unsupported: %d", target_obj.type);
        return SAI_STATUS_NOT_IMPLEMENTED;
    default:
        sai_log_error(SAI_API_ACL, "ACL Redirect target type is invalid: %d", target_obj.type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::set_acl_entry_action_mirror(sai_object_id_t mirror_oid,
                                     sai_object_id_t acl_table_oid,
                                     acl_entry_desc& sdk_entry_desc,
                                     bool is_ingress)
{

    lsai_object mirror_obj(mirror_oid);
    auto sdev = mirror_obj.get_device();
    sai_check_object(mirror_obj, SAI_OBJECT_TYPE_MIRROR_SESSION, sdev, "Mirror Object", mirror_oid);
    // For later more robust check: Assert mirror oid's mirroring direction is same as ACL table's
    lasai_mirror_session_t* session = sdev->m_mirror_handler->m_mirror_db.get_ptr(mirror_obj.index);
    if (session == nullptr) {
        sai_log_error(SAI_API_ACL, "Mirror object 0x%lx applied as ACL action is not recognized.", mirror_oid);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    auto& sdk_acl_command_actions = sdk_entry_desc.cmd_actions;
    auto iter = find_sdk_acl_action_command(sdk_acl_command_actions, la_acl_action_type_e::MIRROR_CMD);
    if (iter != sdk_acl_command_actions.end()) {
        // modify existing mirror command used as acl action.
        // Release current mirror session used by ACE
        auto current_mirror_cmd = iter->data.mirror_cmd;

        uint32_t mirror_session_instance
            = sdev->m_mirror_handler->mirror_session_gid_to_instance(current_mirror_cmd->get_gid(), is_ingress);
        sai_status_t status = sdev->m_mirror_handler->clear_mirror_session_used_by_ace(sdev, mirror_session_instance, is_ingress);
        sai_return_on_error(status);

        // Set new mirror command
        auto mirror_cmd = is_ingress ? session->mirror_cmd_ingress : session->mirror_cmd_egress;
        iter->data.mirror_cmd = mirror_cmd;

    } else {
        // add mirror command as acl action and append new ACL action to existing acl actions.
        sai_status_t status = build_new_acl_mirror_action_commands(mirror_oid, is_ingress, sdk_entry_desc.cmd_actions);
        sai_return_on_error(status);
    }

    return sdev->m_mirror_handler->set_mirror_session_used_by_ace(sdev, mirror_obj.index, is_ingress);
}

sai_status_t
sai_acl::set_acl_entry_attr_action_rule(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_status status;
    lsai_object sai_acl_entry(key->key.object_id);
    auto sdev = sai_acl_entry.get_device();
    sai_check_object(sai_acl_entry, SAI_OBJECT_TYPE_ACL_ENTRY, sdev, "acl entry", key->key.object_id);

    lasai_acl_entry_t acl_entry;
    status = sdev->m_acl_handler->m_acl_entry_db.get(sai_acl_entry.index, acl_entry);
    sai_return_on_la_error(status);

    lasai_acl_table_t acl_table;
    status = sdev->m_acl_handler->m_acl_table_db.get(acl_entry.table_id, acl_table);
    sai_return_on_la_error(status);

    auto iter = acl_table.entry_list.cbegin();
    for (; iter != acl_table.entry_list.cend(); iter++) {
        if (*iter == key->key.object_id) {
            break;
        }
    }

    if (iter == acl_table.entry_list.cend()) {
        sai_log_error(SAI_API_ACL, "ACL entry not found in table.");
        return SAI_STATUS_FAILURE;
    }

    auto update_acl_action_cmd = [&arg, &acl_entry, &sdev](
        sai_object_id_t acl_table_oid, acl_entry_desc& sdk_entry_desc, const sai_attribute_value_t* value) -> sai_status_t {
        switch ((uint64_t)arg) {
        case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT: {
            sai_status_t sstatus;
            auto& sdk_acl_command_actions = sdk_entry_desc.cmd_actions;

            // Search for an existing redirect (L2 or L3 destination)
            auto iter = find_sdk_acl_action_command(sdk_acl_command_actions, la_acl_action_type_e::L3_DESTINATION);
            if (iter == sdk_acl_command_actions.end()) {
                iter = find_sdk_acl_action_command(sdk_acl_command_actions, la_acl_action_type_e::L2_DESTINATION);
            }

            if (iter != sdk_acl_command_actions.end()) {
                // Redirect exists, Modify it in place
                sstatus = set_acl_entry_action_redirect(*iter, value->aclaction.parameter.oid);
                sai_return_on_error(sstatus);
            } else {
                // No redirect found, Append a new one
                la_acl_command_action sdk_acl_command_action{};
                sstatus = set_acl_entry_action_redirect(sdk_acl_command_action, value->aclaction.parameter.oid);
                sai_return_on_error(sstatus);
                sdk_acl_command_actions.push_back(sdk_acl_command_action);
            }
            acl_entry.redirect_id = value->aclaction.parameter.oid;
            break;
        }
        case SAI_ACL_ENTRY_ATTR_ACTION_SET_TC: {
            auto& sdk_acl_command_actions = sdk_entry_desc.cmd_actions;
            auto iter = find_sdk_acl_action_command(sdk_acl_command_actions, la_acl_action_type_e::TRAFFIC_CLASS);
            if (iter != sdk_acl_command_actions.end()) {
                // modify action to new tc value
                iter->data.traffic_class = value->aclaction.parameter.u8;
            } else {
                // add action to set tc value
                la_acl_command_action sdk_acl_command_action{};
                sdk_acl_command_action.data.traffic_class = value->aclaction.parameter.u8;
                sdk_acl_command_actions.push_back(sdk_acl_command_action);
            }
            break;
        }
        case SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP: {
            auto& sdk_acl_command_actions = sdk_entry_desc.cmd_actions;
            auto iter = find_sdk_acl_action_command(sdk_acl_command_actions, la_acl_action_type_e::REMARK_FWD);
            if (iter != sdk_acl_command_actions.end()) {
                // modify action's dscp value
                iter->data.remark_fwd = value->aclaction.parameter.u8;
            } else {
                // apply new action to set dscp value
                la_acl_command_action sdk_acl_command_action{};
                sdk_acl_command_action.data.remark_fwd = value->aclaction.parameter.u8;
                sdk_acl_command_actions.push_back(sdk_acl_command_action);
            }
            break;
        }
        case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS:
        case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS: {
            bool gress = ((uint64_t)arg == SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS) ? true : false;
            if (!value->aclaction.enable) {
                return clear_acl_entry_action_mirror(sdev, acl_table_oid, sdk_entry_desc, gress);
            }

            if (value->aclaction.enable && value->aclaction.parameter.objlist.count > 1) {
                sai_log_error(SAI_API_ACL, "ACL Action can support at most one mirror session.");
                return SAI_STATUS_FAILURE;
            }

            auto mirror_oid = value->aclaction.parameter.objlist.list[0];
            return set_acl_entry_action_mirror(mirror_oid, acl_table_oid, sdk_entry_desc, gress);
        }
        default:
            sai_log_error(SAI_API_ACL, "ACL Entry Action Rule set not supported.");
            return SAI_STATUS_NOT_IMPLEMENTED;
        }

        return SAI_STATUS_SUCCESS;
    };

    uint32_t position = std::distance(acl_table.entry_list.cbegin(), iter);
    for (uint32_t i = 0; i < acl_entry.sdk_entries; i++, position++) {
        if (acl_table.is_v4_acl != acl_table.is_v6_acl) {
            acl_entry_desc sdk_entry_desc;
            if (acl_table.is_v4_acl) {
                status = acl_table.v4_sdk_acl->get(position, sdk_entry_desc);
            } else {
                status = acl_table.v6_sdk_acl->get(position, sdk_entry_desc);
            }

            sai_return_on_la_error(status);

            sai_status_t sstatus = update_acl_action_cmd(acl_entry.table_id, sdk_entry_desc, value);
            sai_return_on_error(sstatus);

            if (acl_table.is_v4_acl) {
                status = acl_table.v4_sdk_acl->set(position, sdk_entry_desc.key_val, sdk_entry_desc.cmd_actions);
            } else {
                status = acl_table.v6_sdk_acl->set(position, sdk_entry_desc.key_val, sdk_entry_desc.cmd_actions);
            }

            sai_return_on_la_error(status);
        } else {
            //   - Update in both v4 and v6 sdk tables if both key vector match or when both
            //     key vector have atleast one respective L3 header field..
            //   - Otherwise, update in either sdk v4 or sdk v6 table that has atleast one L3 header field.
            acl_entry_desc sdk_entry_desc_v4;
            status = acl_table.v4_sdk_acl->get(position, sdk_entry_desc_v4);
            sai_return_on_la_error(status);

            acl_entry_desc sdk_entry_desc_v6;
            status = acl_table.v6_sdk_acl->get(position, sdk_entry_desc_v6);
            sai_return_on_la_error(status);

            auto v4_iter = std::find_if(sdk_entry_desc_v4.key_val.cbegin(),
                                        sdk_entry_desc_v4.key_val.cend(),
                                        [](const la_acl_field& acl_field) { return is_v4_sdk_ace_field(acl_field); });
            auto v6_iter = std::find_if(sdk_entry_desc_v6.key_val.cbegin(),
                                        sdk_entry_desc_v6.key_val.cend(),
                                        [](const la_acl_field& acl_field) { return is_v6_sdk_ace_field(acl_field); });
            if (v4_iter == sdk_entry_desc_v4.key_val.cend() && v6_iter == sdk_entry_desc_v6.key_val.cend()) {
                sai_status_t sstatus = update_acl_action_cmd(acl_entry.table_id, sdk_entry_desc_v4, value);
                sai_return_on_error(sstatus);

                status = acl_table.v4_sdk_acl->set(position, sdk_entry_desc_v4.key_val, sdk_entry_desc_v4.cmd_actions);
                sai_return_on_la_error(status);

                sstatus = update_acl_action_cmd(acl_entry.table_id, sdk_entry_desc_v6, value);
                sai_return_on_error(sstatus);

                status = acl_table.v6_sdk_acl->set(position, sdk_entry_desc_v6.key_val, sdk_entry_desc_v6.cmd_actions);
                sai_return_on_la_error(status);
            } else {
                // If SDK key vector that has L3 header field, update acl action of that sdk table entry.
                if (v4_iter != sdk_entry_desc_v4.key_val.cend()) {
                    sai_status_t sstatus = update_acl_action_cmd(acl_entry.table_id, sdk_entry_desc_v4, value);
                    sai_return_on_error(sstatus);

                    status = acl_table.v4_sdk_acl->set(position, sdk_entry_desc_v4.key_val, sdk_entry_desc_v4.cmd_actions);
                    sai_return_on_la_error(status);
                }

                if (v6_iter != sdk_entry_desc_v6.key_val.cend()) {
                    sai_status_t sstatus = update_acl_action_cmd(acl_entry.table_id, sdk_entry_desc_v6, value);
                    sai_return_on_error(sstatus);

                    status = acl_table.v6_sdk_acl->set(position, sdk_entry_desc_v6.key_val, sdk_entry_desc_v6.cmd_actions);
                    sai_return_on_la_error(status);
                }
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_counter_and_check_attr(_In_ const sai_object_key_t* key,
                                        _Inout_ sai_attribute_value_t* attr,
                                        _Out_ lasai_acl_counter_t& acl_counter)
{
    if (key == nullptr || attr == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status_t sstatus;
    la_status status;
    sai_object_id_t acl_counter_id = key->key.object_id;

    std::shared_ptr<lsai_device> sdev;
    uint32_t map_id;
    sstatus = check_and_get_device_and_map_index(acl_counter_id, SAI_OBJECT_TYPE_ACL_COUNTER, sdev, map_id);
    sai_return_on_error(sstatus);

    status = sdev->m_acl_handler->m_acl_counter_db.get(map_id, acl_counter);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_counter_attr_table_id(_In_ const sai_object_key_t* key,
                                       _Inout_ sai_attribute_value_t* attr,
                                       _In_ unsigned int attr_index,
                                       _Inout_ vendor_cache_t* cache,
                                       void* arg)
{
    lasai_acl_counter_t acl_counter;
    sai_status_t sstatus;

    sstatus = get_acl_counter_and_check_attr(key, attr, acl_counter);
    sai_return_on_error(sstatus);

    attr->oid = acl_counter.table_id;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::acl_counter_attr_counter_enabled(_In_ const sai_object_key_t* key,
                                          _Inout_ sai_attribute_value_t* attr,
                                          _In_ unsigned int attr_index,
                                          _Inout_ vendor_cache_t* cache,
                                          void* arg)
{
    lasai_acl_counter_t acl_counter;
    sai_status_t sstatus;

    sstatus = get_acl_counter_and_check_attr(key, attr, acl_counter);
    sai_return_on_error(sstatus);

    switch ((uint64_t)arg) {
    case SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT:
        attr->booldata = acl_counter.packet_count;
        break;
    case SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT:
        attr->booldata = acl_counter.byte_count;
        break;
    default:
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_counter_attr_counter(_In_ const sai_object_key_t* key,
                                      _Inout_ sai_attribute_value_t* attr,
                                      _In_ unsigned int attr_index,
                                      _Inout_ vendor_cache_t* cache,
                                      void* arg)
{
    lasai_acl_counter_t acl_counter;
    sai_status_t sstatus;
    la_status status;

    sstatus = get_acl_counter_and_check_attr(key, attr, acl_counter);
    sai_return_on_error(sstatus);

    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    uint64_t packet_count;
    uint64_t byte_count;
    status = acl_counter.sdk_counter->read(0, sdev->m_force_update, false, packet_count, byte_count);
    sai_return_on_la_error(status);

    if ((uint64_t)arg == SAI_ACL_COUNTER_ATTR_PACKETS) {
        if (!acl_counter.packet_count) {
            // return default value instead of return failure
            attr->u64 = 0;
        } else {
            attr->u64 = packet_count;
        }
    } else if ((uint64_t)arg == SAI_ACL_COUNTER_ATTR_BYTES) {
        if (!acl_counter.byte_count) {
            attr->u64 = 0;
        } else {
            attr->u64 = byte_count;
        }
    } else {
        sai_log_error(SAI_API_ACL, "Unknown argument for counter.");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_table_group_and_check_attr(_In_ const sai_object_key_t* key,
                                            _Inout_ sai_attribute_value_t* attr,
                                            _Out_ lasai_acl_table_group_t& table_group)
{
    if (key == nullptr || attr == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status_t sstatus;
    la_status status;
    sai_object_id_t table_group_id = key->key.object_id;

    std::shared_ptr<lsai_device> sdev;
    uint32_t map_id;
    sstatus = check_and_get_device_and_map_index(table_group_id, SAI_OBJECT_TYPE_ACL_TABLE_GROUP, sdev, map_id);
    sai_return_on_error(sstatus);

    status = sdev->m_acl_handler->m_acl_table_group_db.get(map_id, table_group);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_table_group(_In_ const sai_object_key_t* key,
                             _Inout_ sai_attribute_value_t* value,
                             _In_ unsigned int attr_index,
                             _Inout_ vendor_cache_t* cache,
                             void* arg)
{
    lasai_acl_table_group_t table_group;
    sai_status_t sstatus;

    sstatus = get_acl_table_group_and_check_attr(key, value, table_group);
    sai_return_on_error(sstatus);

    switch ((int64_t)arg) {
    case SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE:
        set_attr_value(SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE, *value, table_group.stage);
        return SAI_STATUS_SUCCESS;
    case SAI_ACL_TABLE_GROUP_ATTR_MEMBER_LIST:
        sstatus = fill_sai_list(table_group.group_member_ids.begin(), table_group.group_member_ids.end(), value->objlist);
        sai_return_on_error(sstatus);
        return SAI_STATUS_SUCCESS;
    case SAI_ACL_TABLE_GROUP_ATTR_ACL_BIND_POINT_TYPE_LIST:
        sstatus = fill_sai_list(table_group.bind_point_types.begin(), table_group.bind_point_types.end(), value->s32list);
        sai_return_on_error(sstatus);
        return SAI_STATUS_SUCCESS;
    case SAI_ACL_TABLE_GROUP_ATTR_TYPE:
        set_attr_value(SAI_ACL_TABLE_GROUP_ATTR_TYPE, *value, table_group.type);
        return SAI_STATUS_SUCCESS;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_table_group_member_and_check_attr(_In_ const sai_object_key_t* key,
                                                   _Inout_ sai_attribute_value_t* value,
                                                   _Out_ lasai_acl_table_group_member_t& member)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status_t sstatus;
    la_status status;
    sai_object_id_t member_id = key->key.object_id;

    std::shared_ptr<lsai_device> sdev;
    uint32_t map_id;
    sstatus = check_and_get_device_and_map_index(member_id, SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, sdev, map_id);
    sai_return_on_error(sstatus);

    status = sdev->m_acl_handler->m_acl_table_group_member_db.get(map_id, member);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_group_member(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ unsigned int attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg)
{
    lasai_acl_table_group_member_t member;
    sai_status_t sstatus;

    sstatus = get_acl_table_group_member_and_check_attr(key, value, member);
    sai_return_on_error(sstatus);

    switch ((int64_t)arg) {
    case SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID:
        set_attr_value(SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID, *value, member.table_group_id);
        return SAI_STATUS_SUCCESS;
    case SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID:
        set_attr_value(SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID, *value, member.table_id);
        return SAI_STATUS_SUCCESS;
    case SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY:
        set_attr_value(SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY, *value, member.priority);
        return SAI_STATUS_SUCCESS;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::validate_acl_table_bind_point(const lasai_acl_table_t* table, sai_acl_stage_t stage, sai_acl_bind_point_type_t bind_point)
{
    if (table == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (table->stage != stage) {
        sai_log_error(SAI_API_ACL, "ACL Table's stage and attachment stage point are different");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::build_sdk_acl_group(const std::shared_ptr<lsai_device>& sdev,
                             const lasai_acl_table_t* acl_table,
                             la_acl_group*& sdk_acl_group)
{
    // create ACL group
    la_status status = sdev->m_dev->create_acl_group(sdk_acl_group);
    sai_return_on_la_error(status);
    sai_log_debug(SAI_API_ACL, "Created SDK acl group");

    la_acl_vec_t v4_acls{acl_table->v4_sdk_acl};
    la_acl_vec_t v6_acls{acl_table->v6_sdk_acl};
    if (acl_table->is_v4_udk || acl_table->is_v4_acl) {
        status = sdk_acl_group->set_acls(la_acl_packet_format_e::IPV4, v4_acls);
        sai_return_on_la_error(status);
    }

    if (acl_table->is_v6_udk || acl_table->is_v6_acl) {
        status = sdk_acl_group->set_acls(la_acl_packet_format_e::IPV6, v6_acls);
        sai_return_on_la_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::add_acl_table_to_sdk_acl_group(const std::shared_ptr<lsai_device>& sdev,
                                        const lasai_acl_table_t* acl_table,
                                        la_acl_group* sdk_acl_group)
{
    sai_log_debug(SAI_API_ACL, "Add ACL table to SDK acl group");
    la_acl_vec_t v4_acls;
    la_acl_vec_t v6_acls;

    la_status status = sdk_acl_group->get_acls(la_acl_packet_format_e::IPV4, v4_acls);
    sai_return_on_la_error(status);
    status = sdk_acl_group->get_acls(la_acl_packet_format_e::IPV6, v6_acls);
    sai_return_on_la_error(status);

    if (acl_table->is_v4_udk || acl_table->is_v4_acl) {
        la_acl* sdk_acl_table = acl_table->v4_sdk_acl;
        v4_acls.push_back(sdk_acl_table);
        status = sdk_acl_group->set_acls(la_acl_packet_format_e::IPV4, v4_acls);
        sai_return_on_la_error(status);
    }

    if (acl_table->is_v6_udk || acl_table->is_v6_acl) {
        la_acl* sdk_acl_table = acl_table->v6_sdk_acl;
        v6_acls.push_back(sdk_acl_table);
        status = sdk_acl_group->set_acls(la_acl_packet_format_e::IPV6, v6_acls);
        sai_return_on_la_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::bind_acl(sai_object_id_t oid,
                  std::shared_ptr<lsai_device>& sdev,
                  sai_acl_stage_t stage,
                  sai_acl_bind_point_type_t bind_point,
                  la_l3_port* l3_port)
{

    if (oid == SAI_NULL_OBJECT_ID) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object acl_obj(oid);
    if (acl_obj.type != SAI_OBJECT_TYPE_ACL_TABLE) {
        sai_log_error(SAI_API_ACL, "ID provided does not represent ACL Table");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (l3_port == nullptr) {
        sai_log_error(SAI_API_ACL, "Null or invalid sdk port");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_acl_direction_e acl_dir;
    sai_status_t sstatus = sai_acl_stage_to_sdk_acl_dir(stage, acl_dir);
    if (sstatus != SAI_STATUS_SUCCESS) {
        sai_log_error(SAI_API_ACL, "ACL Table's stage is invalid");
        return sstatus;
    }

    // SAI spec allows single ACL OID to be attached to bind-point.
    // The single ACL OID can be a single ACL table or a ACL table
    // group. This simplifies the notion that when an ACL OID is
    // attached to bind point, in correct sequence of operations,
    // no ACL OID should have been already bound to the bind point.
    la_acl_group* sdk_acl_group = nullptr;
    l3_port->get_acl_group(acl_dir, sdk_acl_group);

    lasai_acl_table_t* acl_table = sdev->m_acl_handler->m_acl_table_db.get_ptr(acl_obj.index);
    sstatus = validate_acl_table_bind_point(acl_table, stage, bind_point);
    sai_return_on_error(sstatus);

    if (sdk_acl_group == nullptr) {
        // create ACL group
        sstatus = build_sdk_acl_group(sdev, acl_table, sdk_acl_group);
        sai_return_on_error(sstatus);
    } else {
        // Add ACL table to existing ACL group
        // sdk_acl_group = const_cast<la_acl_group*>(acl_group);
        sstatus = add_acl_table_to_sdk_acl_group(sdev, acl_table, sdk_acl_group);
        sai_return_on_error(sstatus);
    }

    la_status status = l3_port->set_acl_group(acl_dir, sdk_acl_group);
    sai_return_on_la_error(status);

    sai_log_info(SAI_API_ACL, "ACL object 0x%lx has been successfully bound to an l3_port", oid);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::build_sdk_acl_group_l2_attachment(const std::shared_ptr<lsai_device>& sdev,
                                           const lasai_acl_table_t* acl_table,
                                           la_acl_group*& sdk_acl_group)
{
    // create ACL group
    la_status status = sdev->m_dev->create_acl_group(sdk_acl_group);
    sai_return_on_la_error(status);
    sai_log_debug(SAI_API_ACL, "Created SDK acl group to attach on L2 port");

    la_acl_vec_t v4_acls{acl_table->v4_sdk_acl};
    la_acl_vec_t v6_acls{acl_table->v6_sdk_acl};

    if (acl_table->is_v4_udk || acl_table->is_v4_acl) {
        status = sdk_acl_group->set_acls(la_acl_packet_format_e::IPV4, v4_acls);
        sai_return_on_la_error(status);
    }

    if (acl_table->is_v6_udk || acl_table->is_v6_acl) {
        status = sdk_acl_group->set_acls(la_acl_packet_format_e::IPV6, v6_acls);
        sai_return_on_la_error(status);
    }

    // TODO add L2 ACL support.

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::bind_acl(sai_object_id_t oid,
                  std::shared_ptr<lsai_device>& sdev,
                  sai_acl_stage_t stage,
                  sai_acl_bind_point_type_t bind_point,
                  la_l2_service_port* l2_port)
{
    if (oid == SAI_NULL_OBJECT_ID) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object acl_obj(oid);
    if (acl_obj.type != SAI_OBJECT_TYPE_ACL_TABLE) {
        sai_log_error(SAI_API_ACL, "ID provided does not represent ACL Table");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (l2_port == nullptr) {
        sai_log_error(SAI_API_ACL, "Null or invalid sdk port");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_acl_direction_e acl_dir;
    sai_status_t sstatus = sai_acl_stage_to_sdk_acl_dir(stage, acl_dir);
    if (sstatus != SAI_STATUS_SUCCESS) {
        sai_log_error(SAI_API_ACL, "ACL Table's stage is invalid");
        return sstatus;
    }

    // SAI spec allows single ACL OID to be attached to bind-point.
    // The single ACL OID can be a single ACL table or a ACL table
    // group. This simplifies the notion that when an ACL OID is
    // attached to bind point, in correct sequence of operations,
    // no ACL OID should have been already bound to the bind point.
    la_acl_group* sdk_acl_group = nullptr;
    l2_port->get_acl_group(acl_dir, sdk_acl_group);

    lasai_acl_table_t* acl_table = sdev->m_acl_handler->m_acl_table_db.get_ptr(acl_obj.index);
    sstatus = validate_acl_table_bind_point(acl_table, stage, bind_point);
    sai_return_on_error(sstatus);

    if (sdk_acl_group == nullptr) {
        // create ACL group
        sstatus = build_sdk_acl_group_l2_attachment(sdev, acl_table, sdk_acl_group);
        sai_return_on_error(sstatus);
    } else {
        // Add ACL table to existing ACL group
        sstatus = add_acl_table_to_sdk_acl_group(sdev, acl_table, sdk_acl_group);
        sai_return_on_error(sstatus);
    }

    la_status status = l2_port->set_acl_group(acl_dir, sdk_acl_group);
    sai_return_on_la_error(status);

    sai_log_info(SAI_API_ACL, "ACL object 0x%lx has been successfully bound to an l2_port", oid);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::bind_group_acl(sai_object_id_t acl_oid,
                        std::shared_ptr<lsai_device>& sdev,
                        sai_acl_stage_t stage,
                        sai_acl_bind_point_type_t bind_point,
                        la_l3_port* l3_port)
{
    lsai_object acl_obj(acl_oid);
    lasai_acl_table_group_t table_group;
    la_status status = sdev->m_acl_handler->m_acl_table_group_db.get(acl_obj.index, table_group);
    sai_return_on_la_error(status);

    if (table_group.group_member_ids.empty()) {
        sai_log_warn(SAI_API_ACL, "Empty ACL Table Group attached");
        return SAI_STATUS_SUCCESS;
    }

    la_acl_direction_e acl_dir;
    sai_status_t sstatus = sai_acl_stage_to_sdk_acl_dir(stage, acl_dir);
    if (sstatus != SAI_STATUS_SUCCESS) {
        sai_log_error(SAI_API_ACL, "ACL Table's stage is invalid");
        return sstatus;
    }

    la_acl_vec_t v4_acls{};
    la_acl_vec_t v6_acls{};

    for (auto oid : table_group.group_member_ids) {
        lsai_object acl_group_member(oid);
        lasai_acl_table_group_member_t member;
        status = m_acl_table_group_member_db.get(acl_group_member.index, member);
        sai_return_on_la_error(status);

        lsai_object acl_obj(member.table_id);
        if (acl_obj.type != SAI_OBJECT_TYPE_ACL_TABLE) {
            sai_log_error(SAI_API_ACL, "ID provided does not represent ACL Table");
            return SAI_STATUS_INVALID_PARAMETER;
        }

        lasai_acl_table_t* acl_table = sdev->m_acl_handler->m_acl_table_db.get_ptr(acl_obj.index);
        sai_status_t sstatus = validate_acl_table_bind_point(acl_table, stage, bind_point);
        sai_return_on_error(sstatus);

        if (acl_table->is_v4_udk || acl_table->is_v4_acl) {
            v4_acls.push_back(acl_table->v4_sdk_acl);
        }

        if (acl_table->is_v6_udk || acl_table->is_v6_acl) {
            v6_acls.push_back(acl_table->v6_sdk_acl);
        }
    }

    // create ACL group
    la_acl_group* sdk_acl_group = nullptr;
    status = sdev->m_dev->create_acl_group(sdk_acl_group);
    sai_return_on_la_error(status);
    sai_log_debug(SAI_API_ACL, "Created SDK acl group");

    if (!v4_acls.empty()) {
        status = sdk_acl_group->set_acls(la_acl_packet_format_e::IPV4, v4_acls);
        sai_return_on_la_error(status);
    }

    if (!v6_acls.empty()) {
        status = sdk_acl_group->set_acls(la_acl_packet_format_e::IPV6, v6_acls);
        sai_return_on_la_error(status);
    }

    sai_log_debug(SAI_API_ACL, "Added ACLs to SDK acl group");

    status = l3_port->set_acl_group(acl_dir, sdk_acl_group);
    sai_return_on_la_error(status);

    sai_log_debug(SAI_API_ACL, "ACL Group object 0x%lx has been successfully bound to l3_port", acl_oid);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::bind_group_acl(sai_object_id_t acl_oid,
                        std::shared_ptr<lsai_device>& sdev,
                        sai_acl_stage_t stage,
                        sai_acl_bind_point_type_t bind_point,
                        la_l2_service_port* l2_port)
{
    lsai_object acl_obj(acl_oid);
    lasai_acl_table_group_t table_group;
    la_status status = sdev->m_acl_handler->m_acl_table_group_db.get(acl_obj.index, table_group);
    sai_return_on_la_error(status);
    for (auto oid : table_group.group_member_ids) {
        lsai_object acl_group_member(oid);
        lasai_acl_table_group_member_t member;
        status = m_acl_table_group_member_db.get(acl_group_member.index, member);
        sai_return_on_la_error(status);
        sai_status_t sstatus = sai_acl::bind_acl(member.table_id, sdev, stage, bind_point, l2_port);
        sai_return_on_error(sstatus);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::unbind_acl(sai_object_id_t acl_oid, std::shared_ptr<lsai_device>& sdev, la_l3_port* l3_port)
{
    lsai_object acl_obj(acl_oid);
    lasai_acl_table_t acl_table;
    la_status status = sdev->m_acl_handler->m_acl_table_db.get(acl_obj.index, acl_table);
    sai_return_on_la_error(status);

    la_acl_direction_e sdk_acl_dir;
    sai_status_t sstatus = sai_acl::sai_acl_stage_to_sdk_acl_dir(acl_table.stage, sdk_acl_dir);
    sai_return_on_error(sstatus);

    la_acl_group* sdk_acl_group = nullptr;
    status = l3_port->get_acl_group(sdk_acl_dir, sdk_acl_group);

    status = l3_port->clear_acl_group(sdk_acl_dir);
    sai_return_on_la_error(status);

    sai_log_debug(SAI_API_ACL, "ACL object 0x%lx has been successfully detached from l3_port", acl_oid);

    if (sdk_acl_group) {
        status = sdev->m_dev->destroy(sdk_acl_group);
        sai_return_on_la_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::unbind_acl(sai_object_id_t acl_oid, std::shared_ptr<lsai_device>& sdev, la_l2_service_port* l2_port)
{
    lsai_object acl_obj(acl_oid);
    lasai_acl_table_t acl_table;
    la_status status = sdev->m_acl_handler->m_acl_table_db.get(acl_obj.index, acl_table);
    sai_return_on_la_error(status);

    la_acl_direction_e sdk_acl_dir;
    sai_status_t sstatus = sai_acl::sai_acl_stage_to_sdk_acl_dir(acl_table.stage, sdk_acl_dir);
    sai_return_on_error(sstatus);

    la_acl_group* sdk_acl_group = nullptr;
    status = l2_port->get_acl_group(sdk_acl_dir, sdk_acl_group);

    status = l2_port->clear_acl_group(sdk_acl_dir);
    sai_return_on_la_error(status);

    sai_log_debug(SAI_API_ACL, "ACL object 0x%lx has been successfully detached from l2_port", acl_oid);

    if (sdk_acl_group) {
        status = sdev->m_dev->destroy(sdk_acl_group);
        sai_return_on_la_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::unbind_group_acl(sai_object_id_t acl_oid, std::shared_ptr<lsai_device>& sdev, la_l3_port* l3_port)
{
    lsai_object acl_obj(acl_oid);
    lasai_acl_table_group_t table_group;
    la_status status = sdev->m_acl_handler->m_acl_table_group_db.get(acl_obj.index, table_group);
    sai_return_on_la_error(status);

    la_acl_direction_e sdk_acl_dir;
    sai_status_t sstatus = sai_acl::sai_acl_stage_to_sdk_acl_dir(table_group.stage, sdk_acl_dir);
    sai_return_on_error(sstatus);

    la_acl_group* sdk_acl_group = nullptr;
    status = l3_port->get_acl_group(sdk_acl_dir, sdk_acl_group);

    status = l3_port->clear_acl_group(sdk_acl_dir);
    sai_return_on_la_error(status);

    sai_log_debug(SAI_API_ACL, "ACL group object 0x%lx has been successfully detached from l3_port", acl_oid);

    if (sdk_acl_group) {
        status = sdev->m_dev->destroy(sdk_acl_group);
        sai_return_on_la_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::unbind_group_acl(sai_object_id_t acl_oid, std::shared_ptr<lsai_device>& sdev, la_l2_service_port* l2_port)
{
    lsai_object acl_obj(acl_oid);
    lasai_acl_table_group_t table_group;
    la_status status = sdev->m_acl_handler->m_acl_table_group_db.get(acl_obj.index, table_group);
    sai_return_on_la_error(status);

    la_acl_direction_e sdk_acl_dir;
    sai_status_t sstatus = sai_acl::sai_acl_stage_to_sdk_acl_dir(table_group.stage, sdk_acl_dir);
    sai_return_on_error(sstatus);

    la_acl_group* acl_group = nullptr;
    status = l2_port->get_acl_group(sdk_acl_dir, acl_group);

    status = l2_port->clear_acl_group(sdk_acl_dir);
    sai_return_on_la_error(status);

    sai_log_debug(SAI_API_ACL, "ACL group object 0x%lx has been successfully detached from l2_port", acl_oid);

    if (acl_group) {
        status = sdev->m_dev->destroy(acl_group);
        sai_return_on_la_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

// oid is of sai object used at the bindpoint. It can be port, lag, switch
la_status
sai_acl::get_acls_attached_on_bindpoint(const std::shared_ptr<lsai_device>& sdev,
                                        sai_object_id_t oid,
                                        sai_object_id_t& ingress_acl_oid,
                                        sai_object_id_t& egress_acl_oid) const
{
    la_status status = LA_STATUS_SUCCESS;
    port_lag_common* service = nullptr;

    status = sai_port_get_service(sdev, oid, service);
    la_return_on_error(status);

    if (service == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    if (service->ingress_acl == SAI_NULL_OBJECT_ID && service->egress_acl == SAI_NULL_OBJECT_ID) {
        // When no acl attached to port, return ACLs attached to switch bind point if any
        ingress_acl_oid = sdev->switch_ingress_acl_oid;
        egress_acl_oid = sdev->switch_egress_acl_oid;
    }

    return status;
}

sai_status_t
sai_acl::update_acl_on_l3_port(la_l3_port* l3_port,
                               sai_object_id_t acl_oid,
                               sai_acl_stage_t stage,
                               sai_acl_bind_point_type_t bind_point,
                               sai_object_id_t old_acl_oid)
{

    if (old_acl_oid != SAI_NULL_OBJECT_ID && acl_oid == SAI_NULL_OBJECT_ID) {
        // Unbind previously bound ACL.
        lsai_object acl_obj(old_acl_oid);
        if (acl_obj.type == SAI_OBJECT_TYPE_ACL_TABLE) {
            sai_status_t sstatus = sai_acl::unbind_acl(old_acl_oid, m_sdev, l3_port);
            sai_return_on_error(sstatus);
        } else if (acl_obj.type == SAI_OBJECT_TYPE_ACL_TABLE_GROUP) {
            sai_status_t sstatus = unbind_group_acl(old_acl_oid, m_sdev, l3_port);
            sai_return_on_error(sstatus);
        } else {
            sai_log_error(SAI_API_PORT, "ACL attached on port %lu is invalid", old_acl_oid);
            return SAI_STATUS_FAILURE;
        }
    } else if (old_acl_oid != SAI_NULL_OBJECT_ID && acl_oid != SAI_NULL_OBJECT_ID) {
        // Trying to set new ACL without clearing existing one.
        sai_log_error(SAI_API_PORT, "Reattaching new ACL on port with existing ACL %lu ", old_acl_oid);
        return SAI_STATUS_FAILURE;
    } else if (acl_oid != SAI_NULL_OBJECT_ID) {
        lsai_object acl_obj(acl_oid);
        if (acl_obj.type == SAI_OBJECT_TYPE_ACL_TABLE) {
            sai_status_t sstatus = sai_acl::bind_acl(acl_oid, m_sdev, stage, bind_point, l3_port);
            sai_return_on_error(sstatus);
        } else if (acl_obj.type == SAI_OBJECT_TYPE_ACL_TABLE_GROUP) {
            sai_status_t sstatus = bind_group_acl(acl_oid, m_sdev, stage, bind_point, l3_port);
            sai_return_on_error(sstatus);
        } else {
            sai_log_error(SAI_API_PORT, "ACL object id 0x%llx is neither of type table or table group", acl_oid);
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::update_acl_on_l2_port(la_l2_service_port* l2_port,
                               sai_object_id_t acl_oid,
                               sai_acl_stage_t stage,
                               sai_acl_bind_point_type_t bind_point,
                               sai_object_id_t old_acl_oid)
{
    if (old_acl_oid != SAI_NULL_OBJECT_ID && acl_oid == SAI_NULL_OBJECT_ID) {
        // Unbind previously bound ACL.
        lsai_object acl_obj(old_acl_oid);
        if (acl_obj.type == SAI_OBJECT_TYPE_ACL_TABLE) {
            sai_status_t sstatus = sai_acl::unbind_acl(old_acl_oid, m_sdev, l2_port);
            sai_return_on_error(sstatus);
        } else if (acl_obj.type == SAI_OBJECT_TYPE_ACL_TABLE_GROUP) {
            sai_status_t sstatus = unbind_group_acl(old_acl_oid, m_sdev, l2_port);
            sai_return_on_error(sstatus);
        } else {
            sai_log_error(SAI_API_PORT, "ACL attached on port %lu is invalid", old_acl_oid);
            return SAI_STATUS_FAILURE;
        }
    } else if (old_acl_oid != SAI_NULL_OBJECT_ID && acl_oid != SAI_NULL_OBJECT_ID) {
        // Trying to set new ACL without clearing existing one.
        sai_log_error(SAI_API_PORT, "Reattaching new ACL on port with existing ACL %lu ", old_acl_oid);
        return SAI_STATUS_FAILURE;
    } else if (acl_oid != SAI_NULL_OBJECT_ID) {
        lsai_object acl_obj(acl_oid);
        if (acl_obj.type == SAI_OBJECT_TYPE_ACL_TABLE) {
            sai_status_t sstatus = sai_acl::bind_acl(acl_oid, m_sdev, stage, bind_point, l2_port);
            sai_return_on_error(sstatus);
        } else if (acl_obj.type == SAI_OBJECT_TYPE_ACL_TABLE_GROUP) {
            sai_status_t sstatus = bind_group_acl(acl_oid, m_sdev, stage, bind_point, l2_port);
            sai_return_on_error(sstatus);
        } else {
            sai_log_error(SAI_API_PORT, "ACL object id 0x%llx is neither of type table or table group", acl_oid);
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::validate_acl_on_rif(sai_object_id_t acl_oid, const rif_entry* rif_entry, sai_acl_stage_t stage) const
{
    lsai_object acl_obj(acl_oid);
    if (acl_oid != SAI_NULL_OBJECT_ID && acl_obj.type != SAI_OBJECT_TYPE_ACL_TABLE
        && acl_obj.type != SAI_OBJECT_TYPE_ACL_TABLE_GROUP) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (stage == SAI_ACL_STAGE_INGRESS && m_sdev->switch_ingress_acl_oid != SAI_NULL_OBJECT_ID
        && m_sdev->switch_ingress_acl_oid != acl_oid) {
        sai_log_error(SAI_API_ROUTER_INTERFACE,
                      "Ingress ACL configured at switch level. A new ingress ACL cannot be attach to rif");
        return SAI_STATUS_FAILURE;
    }

    if (stage == SAI_ACL_STAGE_EGRESS && m_sdev->switch_egress_acl_oid != SAI_NULL_OBJECT_ID
        && m_sdev->switch_egress_acl_oid != acl_oid) {
        sai_log_error(SAI_API_ROUTER_INTERFACE, "Egress ACL configured at switch level. A new egress ACL cannot be attach to rif");
        return SAI_STATUS_FAILURE;
    }

    if (rif_entry->type != SAI_ROUTER_INTERFACE_TYPE_PORT && rif_entry->type != SAI_ROUTER_INTERFACE_TYPE_VLAN) {
        sai_log_error(SAI_API_ROUTER_INTERFACE, "ACL is supported only on port and SVI");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (rif_entry->port_obj != SAI_NULL_OBJECT_ID) {
        sai_object_id_t ingress_acl = SAI_NULL_OBJECT_ID, egress_acl = SAI_NULL_OBJECT_ID;
        la_status status = get_acls_attached_on_bindpoint(m_sdev, rif_entry->port_obj, ingress_acl, egress_acl);
        sai_return_on_la_error(status);

        if (stage == SAI_ACL_STAGE_INGRESS && ingress_acl != SAI_NULL_OBJECT_ID) {
            sai_log_error(SAI_API_ROUTER_INTERFACE, "Ingress ACL already applied on port");
            return SAI_STATUS_FAILURE;
        } else if (stage == SAI_ACL_STAGE_EGRESS && egress_acl != SAI_NULL_OBJECT_ID) {
            sai_log_error(SAI_API_ROUTER_INTERFACE, "Egress ACL already applied on port");
            return SAI_STATUS_FAILURE;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::attach_acl_on_rif(sai_object_id_t acl_oid, sai_acl_stage_t stage, rif_entry* rif_entry)
{
    sai_status_t status = validate_acl_on_rif(acl_oid, rif_entry, stage);
    sai_return_on_error(status);

    // Binding new ACL Object to RIF.
    auto bind_point = SAI_ACL_BIND_POINT_TYPE_ROUTER_INTERFACE;
    if (rif_entry->type == SAI_ROUTER_INTERFACE_TYPE_VLAN) {
        bind_point = SAI_ACL_BIND_POINT_TYPE_VLAN;
    }

    status = update_acl_on_l3_port(rif_entry->l3_port,
                                   acl_oid,
                                   stage,
                                   bind_point,
                                   (stage == SAI_ACL_STAGE_INGRESS) ? rif_entry->ingress_acl : rif_entry->egress_acl);
    sai_return_on_error(status);

    if (stage == SAI_ACL_STAGE_INGRESS) {
        rif_entry->ingress_acl = acl_oid;
    } else {
        rif_entry->egress_acl = acl_oid;
    }

    return SAI_STATUS_SUCCESS;
}

// When rif is created, attach parent ACL. Parent can be ACL attached to switch or physical port
sai_status_t
sai_acl::attach_acl_on_rif_create(rif_entry* rif_entry)
{
    if (rif_entry->l3_port != nullptr) {
        sai_acl_bind_point_type_t bind_point = SAI_ACL_BIND_POINT_TYPE_PORT;
        sai_object_id_t ingress_acl_oid = SAI_NULL_OBJECT_ID;
        sai_object_id_t egress_acl_oid = SAI_NULL_OBJECT_ID;
        if (m_sdev->switch_ingress_acl_oid != SAI_NULL_OBJECT_ID || m_sdev->switch_egress_acl_oid != SAI_NULL_OBJECT_ID) {
            bind_point = SAI_ACL_BIND_POINT_TYPE_SWITCH;
            ingress_acl_oid = m_sdev->switch_ingress_acl_oid;
            egress_acl_oid = m_sdev->switch_egress_acl_oid;
        } else {
            if (rif_entry->port_obj != SAI_NULL_OBJECT_ID) {
                // if any acl bound on port, apply port acl on rif.
                bind_point = SAI_ACL_BIND_POINT_TYPE_PORT;
            }
        }

        if (bind_point == SAI_ACL_BIND_POINT_TYPE_PORT && rif_entry->port_obj != SAI_NULL_OBJECT_ID) {
            la_status status = get_acls_attached_on_bindpoint(m_sdev, rif_entry->port_obj, ingress_acl_oid, egress_acl_oid);
            sai_return_on_la_error(status);
        } else if (bind_point == SAI_ACL_BIND_POINT_TYPE_VLAN && rif_entry->bridge_obj != SAI_NULL_OBJECT_ID) {
            // Currently ACLs attached to VLANs are not applied to SVIs.
            sai_log_error(SAI_API_ACL, "ACL bound to VLANs are not applied to member ports yet. Unsupported.");
            return SAI_STATUS_NOT_IMPLEMENTED;
        }

        sai_status_t sstatus
            = update_acl_on_l3_port(rif_entry->l3_port, ingress_acl_oid, SAI_ACL_STAGE_INGRESS, bind_point, rif_entry->ingress_acl);
        sai_return_on_error(sstatus);
        rif_entry->ingress_acl = ingress_acl_oid;

        sstatus
            = update_acl_on_l3_port(rif_entry->l3_port, egress_acl_oid, SAI_ACL_STAGE_EGRESS, bind_point, rif_entry->egress_acl);
        sai_return_on_error(sstatus);
        rif_entry->egress_acl = egress_acl_oid;
    }

    return SAI_STATUS_SUCCESS;
}

// when rif is removed, clear parent bound ACL. Parent can be switch or physical port
sai_status_t
sai_acl::clear_acl_on_rif_removal(const rif_entry& rif_entry)
{
    if (rif_entry.l3_port != nullptr) {
        // nullptr in case of loopback type rif
        for (auto oid : {rif_entry.ingress_acl, rif_entry.egress_acl}) {
            if (oid != SAI_NULL_OBJECT_ID) {
                lsai_object acl_obj(oid);
                if (acl_obj.type == SAI_OBJECT_TYPE_ACL_TABLE) {
                    sai_status_t status = sai_acl::unbind_acl(oid, m_sdev, rif_entry.l3_port);
                    sai_return_on_error(status);
                } else {
                    sai_status_t status = sai_acl::unbind_group_acl(oid, m_sdev, rif_entry.l3_port);
                    sai_return_on_error(status);
                }
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

// When bridge port is created, attach parent ACL. Parent can be ACL attached to switch or physical port
sai_status_t
sai_acl::attach_acl_on_bridge_port_create(bridge_port_entry* bport_entry)
{
    if (bport_entry->l2_port != nullptr) {
        sai_acl_bind_point_type_t bind_point = SAI_ACL_BIND_POINT_TYPE_PORT;
        sai_object_id_t ingress_acl_oid = SAI_NULL_OBJECT_ID;
        sai_object_id_t egress_acl_oid = SAI_NULL_OBJECT_ID;
        if (m_sdev->switch_ingress_acl_oid != SAI_NULL_OBJECT_ID || m_sdev->switch_egress_acl_oid != SAI_NULL_OBJECT_ID) {
            bind_point = SAI_ACL_BIND_POINT_TYPE_SWITCH;
            ingress_acl_oid = m_sdev->switch_ingress_acl_oid;
            egress_acl_oid = m_sdev->switch_egress_acl_oid;
        } else {
            // if any acl bound on port, apply port acl on bridge port.
            if (bport_entry->port_obj != SAI_NULL_OBJECT_ID) {
                bind_point = SAI_ACL_BIND_POINT_TYPE_PORT;
            }
        }

        if (bind_point == SAI_ACL_BIND_POINT_TYPE_PORT && bport_entry->port_obj != SAI_NULL_OBJECT_ID) {
            sai_object_id_t port_oid = bport_entry->port_obj;
            lsai_object la_bport(port_oid);
            if (la_bport.type == SAI_OBJECT_TYPE_BRIDGE_PORT) {
                bridge_port_entry* entry = m_sdev->m_bridge_ports.get_ptr(la_bport.index);
                if (entry != nullptr) {
                    port_oid = entry->port_obj;
                }
            }
            la_status status = get_acls_attached_on_bindpoint(m_sdev, port_oid, ingress_acl_oid, egress_acl_oid);
            sai_return_on_la_error(status);
        } else if (bind_point == SAI_ACL_BIND_POINT_TYPE_VLAN && bport_entry->bridge_obj != SAI_NULL_OBJECT_ID) {
            // Currently ACLs attached to VLANs are not applied to bridge port.
            sai_log_error(SAI_API_ACL, "ACL bound to VLANs are not applied to member ports yet. Unsupported.");
            return SAI_STATUS_NOT_IMPLEMENTED;
        }

        if (ingress_acl_oid != SAI_NULL_OBJECT_ID) {
            sai_status_t sstatus = update_acl_on_l2_port(
                bport_entry->l2_port, ingress_acl_oid, SAI_ACL_STAGE_INGRESS, bind_point, bport_entry->ingress_acl_oid);
            sai_return_on_error(sstatus);
            bport_entry->ingress_acl_oid = ingress_acl_oid;
        }

        if (egress_acl_oid != SAI_NULL_OBJECT_ID) {
            sai_status_t sstatus = update_acl_on_l2_port(
                bport_entry->l2_port, egress_acl_oid, SAI_ACL_STAGE_EGRESS, bind_point, bport_entry->egress_acl_oid);
            sai_return_on_error(sstatus);
            bport_entry->egress_acl_oid = egress_acl_oid;
        }
    }

    return SAI_STATUS_SUCCESS;
}

// when bridge port is removed, clear parent bound ACL. Parent can be switch or physical port
sai_status_t
sai_acl::clear_acl_on_bridge_port_removal(const bridge_port_entry& bport_entry)
{
    if (bport_entry.l2_port != nullptr) {
        for (auto oid : {bport_entry.ingress_acl_oid, bport_entry.egress_acl_oid}) {
            if (oid != SAI_NULL_OBJECT_ID) {
                lsai_object acl_obj(oid);
                if (acl_obj.type == SAI_OBJECT_TYPE_ACL_TABLE) {
                    sai_status_t status = sai_acl::unbind_acl(oid, m_sdev, bport_entry.l2_port);
                    sai_return_on_error(status);
                } else {
                    sai_status_t status = sai_acl::unbind_group_acl(oid, m_sdev, bport_entry.l2_port);
                    sai_return_on_error(status);
                }
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::attach_acl_on_cpu_l2_port(sai_object_id_t acl_oid,
                                   sai_acl_stage_t stage,
                                   cpu_l2_port_entry& cpu_l2_port,
                                   sai_acl_bind_point_type_t bind_point)
{
    sai_object_id_t old_acl_oid = SAI_NULL_OBJECT_ID;
    if (stage == SAI_ACL_STAGE_INGRESS) {
        old_acl_oid = cpu_l2_port.ingress_acl_oid;
    } else {
        old_acl_oid = cpu_l2_port.egress_acl_oid;
    }

    if (acl_oid == old_acl_oid || cpu_l2_port.l2_port == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    sai_status_t sstatus = update_acl_on_l2_port(cpu_l2_port.l2_port, acl_oid, stage, bind_point, old_acl_oid);
    sai_return_on_error(sstatus);

    if (stage == SAI_ACL_STAGE_INGRESS) {
        cpu_l2_port.ingress_acl_oid = acl_oid;
    } else {
        cpu_l2_port.egress_acl_oid = acl_oid;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::attach_acl_on_cpu_l2_port_create(cpu_l2_port_entry& cpu_l2_port)
{
    cpu_l2_port.ingress_acl_oid = SAI_NULL_OBJECT_ID;
    cpu_l2_port.egress_acl_oid = SAI_NULL_OBJECT_ID;

    if (cpu_l2_port.l2_port != nullptr) {
        sai_acl_bind_point_type_t bind_point = SAI_ACL_BIND_POINT_TYPE_SWITCH;
        sai_object_id_t ingress_acl_oid = m_sdev->switch_ingress_acl_oid;
        sai_object_id_t egress_acl_oid = m_sdev->switch_egress_acl_oid;

        if (ingress_acl_oid != SAI_NULL_OBJECT_ID) {
            sai_status_t sstatus = attach_acl_on_cpu_l2_port(ingress_acl_oid, SAI_ACL_STAGE_INGRESS, cpu_l2_port, bind_point);
            sai_return_on_error(sstatus);
        }

        if (egress_acl_oid != SAI_NULL_OBJECT_ID) {
            sai_status_t sstatus = attach_acl_on_cpu_l2_port(egress_acl_oid, SAI_ACL_STAGE_EGRESS, cpu_l2_port, bind_point);
            sai_return_on_error(sstatus);
        }
    }

    return SAI_STATUS_SUCCESS;
}

// when bridge port is removed, clear parent bound ACL. Parent can be switch or physical port
sai_status_t
sai_acl::clear_acl_on_cpu_l2_port_removal(cpu_l2_port_entry& cpu_l2_port)
{
    if (cpu_l2_port.l2_port != nullptr) {
        sai_acl_bind_point_type_t bind_point = SAI_ACL_BIND_POINT_TYPE_SWITCH;
        if (cpu_l2_port.ingress_acl_oid != SAI_NULL_OBJECT_ID) {
            sai_status_t sstatus = attach_acl_on_cpu_l2_port(SAI_NULL_OBJECT_ID, SAI_ACL_STAGE_INGRESS, cpu_l2_port, bind_point);
            sai_return_on_error(sstatus);
        }

        if (cpu_l2_port.egress_acl_oid != SAI_NULL_OBJECT_ID) {
            sai_status_t sstatus = attach_acl_on_cpu_l2_port(SAI_NULL_OBJECT_ID, SAI_ACL_STAGE_EGRESS, cpu_l2_port, bind_point);
            sai_return_on_error(sstatus);
        }
    }

    return SAI_STATUS_SUCCESS;
}

// Attach ACL to all L2, L3 ports that are created on eth_port.
// This will not attach ACLs to SVIs
sai_status_t
sai_acl::attach_acl_on_logical_ports(sai_object_id_t acl_oid,
                                     sai_acl_stage_t stage,
                                     la_ethernet_port* eth_port,
                                     sai_acl_bind_point_type_t bind_point,
                                     sai_object_id_t old_acl_oid)
{
    std::vector<la_object*> vec = m_sdev->m_dev->get_dependent_objects(eth_port);
    sai_status_t status = SAI_STATUS_SUCCESS;
    for (la_object* elem : vec) {
        if (elem->type() == la_object::object_type_e::L3_AC_PORT) {
            la_l3_port* l3_port = static_cast<la_l3_ac_port*>(elem);
            if (l3_port != nullptr) {
                status = update_acl_on_l3_port(l3_port, acl_oid, stage, bind_point, old_acl_oid);
                rif_entry* entry = m_sdev->m_l3_ports.get_ptr(l3_port->get_gid());
                if (entry != nullptr) {
                    if (stage == SAI_ACL_STAGE_INGRESS) {
                        entry->ingress_acl = acl_oid;
                    } else {
                        entry->egress_acl = acl_oid;
                    }
                }
            }
        } else if (elem->type() == la_object::object_type_e::L2_SERVICE_PORT) {
            la_l2_service_port* l2_port = static_cast<la_l2_service_port*>(elem);
            if (l2_port != nullptr) {
                status = update_acl_on_l2_port(l2_port, acl_oid, stage, bind_point, old_acl_oid);
                bridge_port_entry* bport_entry = m_sdev->m_bridge_ports.get_ptr(l2_port->get_gid());
                if (bport_entry != nullptr) {
                    if (stage == SAI_ACL_STAGE_INGRESS) {
                        bport_entry->ingress_acl_oid = acl_oid;
                    } else {
                        bport_entry->egress_acl_oid = acl_oid;
                    }
                }
            }
        }

        sai_return_on_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

// Attaches/Detaches new ACL on all logical ports constructed on a port.
sai_status_t
sai_acl::attach_acl_on_port(sai_object_id_t acl_oid,
                            sai_acl_stage_t stage,
                            port_entry* pentry,
                            sai_acl_bind_point_type_t bind_point)
{
    sai_object_id_t old_acl_oid = SAI_NULL_OBJECT_ID;
    if (stage == SAI_ACL_STAGE_INGRESS) {
        old_acl_oid = pentry->service.ingress_acl;
    } else {
        old_acl_oid = pentry->service.egress_acl;
    }

    if (acl_oid == old_acl_oid || pentry->service.eth_port == nullptr) {
        // eth_port is set to nullptr when port is part of lag.
        return SAI_STATUS_SUCCESS;
    }

    sai_status_t status = attach_acl_on_logical_ports(acl_oid, stage, pentry->service.eth_port, bind_point, old_acl_oid);
    sai_return_on_error(status);
    if (stage == SAI_ACL_STAGE_INGRESS) {
        pentry->service.ingress_acl = acl_oid;
    } else {
        pentry->service.egress_acl = acl_oid;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::attach_acl_on_port_create(const port_entry& port_entry)
{
    // ACLs are applied only on logical ports created on top of port. At the time of
    // port creation, parent ACL (in this case switch acl) can be applied after
    // logical ports are created on this port. ACL attachment has to wait until
    // new logical ports are created.
    // When SDK allows to apply ACLs at ethernet port, use this function to extend
    // the functionality.
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::clear_acl_on_port_removal(port_entry& port_entry)
{
    // ACLs are applied/detached only on logical ports created on top of port. At the time of
    // port deletion/removal, all constituent logical port in this port are already removed.
    // ACLs are already detached from those logical ports.
    port_entry.service.ingress_acl = SAI_NULL_OBJECT_ID;
    port_entry.service.egress_acl = SAI_NULL_OBJECT_ID;

    // When SDK allows to apply ACLs at ethernet port, use this function to extend
    // the functionality.
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::attach_acl_on_lag(sai_object_id_t acl_oid,
                           sai_acl_stage_t stage,
                           lag_entry* lag_entry,
                           sai_acl_bind_point_type_t bind_point)
{
    lsai_object acl_obj(acl_oid);
    if (acl_oid != SAI_NULL_OBJECT_ID && acl_obj.type != SAI_OBJECT_TYPE_ACL_TABLE
        && acl_obj.type != SAI_OBJECT_TYPE_ACL_TABLE_GROUP) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_object_id_t old_acl_oid = SAI_NULL_OBJECT_ID;
    if (stage == SAI_ACL_STAGE_INGRESS) {
        old_acl_oid = lag_entry->service.ingress_acl;
    } else {
        old_acl_oid = lag_entry->service.egress_acl;
    }

    if (acl_oid == old_acl_oid || lag_entry->service.eth_port == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    sai_status_t status = attach_acl_on_logical_ports(acl_oid, stage, lag_entry->service.eth_port, bind_point, old_acl_oid);
    sai_return_on_error(status);
    if (stage == SAI_ACL_STAGE_INGRESS) {
        lag_entry->service.ingress_acl = acl_oid;
    } else {
        lag_entry->service.egress_acl = acl_oid;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::attach_acl_on_lag_create(lag_entry& lag_entry)
{
    // If switch ACL is applied, we better remember that for later during cleanup.
    lag_entry.service.ingress_acl = m_sdev->switch_ingress_acl_oid;
    lag_entry.service.egress_acl = m_sdev->switch_egress_acl_oid;

    // ACLs are applied only on logical ports created on top of port. At the time of
    // port creation, parent ACL (in this case switch acl) can be applied after
    // logical ports are created on this port. ACL attachment has to wait until
    // new logical ports are created.
    // When SDK allows to apply ACLs at ethernet port, use this function to extend
    // the functionality.

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::clear_acl_on_lag_removal(lag_entry& lag_entry)
{
    // ACLs are applied/detached only on logical ports created on top of port. At the time of
    // port deletion/removal, all constituent logical port in this port are already removed.
    // ACLs are already detached from those logical ports.
    lag_entry.service.ingress_acl = SAI_NULL_OBJECT_ID;
    lag_entry.service.egress_acl = SAI_NULL_OBJECT_ID;
    // When SDK allows to apply ACLs at ethernet port, use this function to extend
    // the functionality.
    return SAI_STATUS_SUCCESS;
}

bool
sai_acl::is_acl_set_on_non_switch_bindpoints(sai_acl_stage_t stage) const
{
    for (const auto& entry : m_sdev->m_lags.map()) {
        auto lag_entry = entry.second;
        auto lag_acl_oid = (stage == SAI_ACL_STAGE_INGRESS) ? lag_entry.service.ingress_acl : lag_entry.service.egress_acl;
        if (lag_acl_oid != SAI_NULL_OBJECT_ID) {
            return true;
        }
    }

    for (const auto& entry : m_sdev->m_ports.map()) {
        auto port_entry = entry.second;
        if (port_entry.service.eth_port == nullptr) {
            // when port is added to lag, port_entry.eth_port is set to nullptr.
            continue;
        }
        auto port_acl_oid = (stage == SAI_ACL_STAGE_INGRESS) ? port_entry.service.ingress_acl : port_entry.service.egress_acl;
        if (port_acl_oid != SAI_NULL_OBJECT_ID) {
            return true;
        }
    }

    for (const auto& entry : m_sdev->m_l3_ports.map()) {
        auto rif_entry = entry.second;
        auto rif_acl_oid = (stage == SAI_ACL_STAGE_INGRESS) ? rif_entry.ingress_acl : rif_entry.egress_acl;
        if (rif_acl_oid != SAI_NULL_OBJECT_ID) {
            return true;
        }
    }

    return false;
}

sai_status_t
sai_acl::attach_acl_on_switch(sai_acl_stage_t stage, sai_object_id_t acl_oid)
{
    auto gress = (stage == SAI_ACL_STAGE_INGRESS) ? "Ingress" : "Egress";
    auto current_oid = (stage == SAI_ACL_STAGE_INGRESS) ? m_sdev->switch_ingress_acl_oid : m_sdev->switch_egress_acl_oid;
    if (current_oid == acl_oid) {
        sai_log_debug(SAI_API_ACL, "Reattaching same %s ACL 0x%lx with switch bind scope", gress, acl_oid);
    }

    // Check if on any port, lag, rif ingress/egress ACL set. If so fail.
    if (is_acl_set_on_non_switch_bindpoints(stage)) {
        sai_log_error(
            SAI_API_ACL,
            "%s ACL/s attached at non switch bind points (port, interface, lag..). Cannot attach ACL at switch bind point.",
            gress);
        return SAI_STATUS_FAILURE;
    }

    // Attach acl bound at swtich point to all constituent acl attachment points like ports, lag
    for (auto& entry : m_sdev->m_lags.map()) {
        auto& lag_entry = entry.second;
        sai_status_t status = attach_acl_on_lag(acl_oid, stage, &lag_entry, SAI_ACL_BIND_POINT_TYPE_SWITCH);
        sai_return_on_error(status);
    }

    // Attach acl bound at switch point to all vlan l2 cpu ports.
    for (auto& entry : m_sdev->m_cpu_l2_port_map) {
        auto& cpu_l2_port_entry = entry.second;
        sai_status_t status = attach_acl_on_cpu_l2_port(acl_oid, stage, cpu_l2_port_entry, SAI_ACL_BIND_POINT_TYPE_SWITCH);
        sai_return_on_error(status);
    }

    for (auto& entry : m_sdev->m_ports.map()) {
        auto& port_entry = entry.second;
        if (port_entry.service.eth_port == nullptr) {
            // when port is added to lag, port_entry.eth_port is set to nullptr.
            continue;
        }

        sai_status_t status = attach_acl_on_port(acl_oid, stage, &port_entry, SAI_ACL_BIND_POINT_TYPE_SWITCH);
        sai_return_on_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::clear_acl_on_switch(sai_acl_stage_t stage)
{
    auto current_oid = (stage == SAI_ACL_STAGE_INGRESS) ? m_sdev->switch_ingress_acl_oid : m_sdev->switch_egress_acl_oid;
    auto gress = (stage == SAI_ACL_STAGE_INGRESS) ? "Ingress" : "Egress";
    if (current_oid == SAI_NULL_OBJECT_ID) {
        sai_log_debug(SAI_API_ACL, "No %s ACLs attached at switch bind point", gress);
        return SAI_STATUS_SUCCESS;
    }

    // Detach acl bound at swtich point from all constituent acl attachment points like ports, lag
    for (auto& entry : m_sdev->m_lags.map()) {
        auto& lag_entry = entry.second;
        sai_status_t status = attach_acl_on_lag(SAI_NULL_OBJECT_ID, stage, &lag_entry, SAI_ACL_BIND_POINT_TYPE_SWITCH);
        sai_return_on_error(status);
    }

    // Detach acl bound at switch point from all vlan l2 cpu ports.
    for (auto& entry : m_sdev->m_cpu_l2_port_map) {
        auto& cpu_l2_port_entry = entry.second;
        sai_status_t status
            = attach_acl_on_cpu_l2_port(SAI_NULL_OBJECT_ID, stage, cpu_l2_port_entry, SAI_ACL_BIND_POINT_TYPE_SWITCH);
        sai_return_on_error(status);
    }

    for (auto& entry : m_sdev->m_ports.map()) {
        auto& port_entry = entry.second;
        if (port_entry.service.eth_port == nullptr) {
            // when port is added to lag, port_entry.eth_port is set to nullptr.
            continue;
        }
        sai_status_t status = attach_acl_on_port(
            SAI_NULL_OBJECT_ID /* NULL OID will detach ACL */, stage, &port_entry, SAI_ACL_BIND_POINT_TYPE_SWITCH);
        sai_return_on_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

la_meter_set*
sai_acl::get_acl_sdk_meter(sai_object_id_t policer_oid)
{
    auto it = m_sdev->m_acl_handler->m_acl_policers.find(policer_oid);
    if (it != m_sdev->m_acl_handler->m_acl_policers.end()) {
        return it->second.sdk_meter;
    }

    return nullptr;
}

// id; mandatory_on_create; valid_for_create; valid_for_set; valid_for_get
// *attrib_name; type;
extern const sai_attribute_entry_t acl_table_attribs[] = {
    {SAI_ACL_TABLE_ATTR_ACL_STAGE, true, true, false, true, "ACL stage", SAI_ATTR_VAL_TYPE_S32},
    {SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST, true, false, false, true, "List of valid bind points", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_ACL_TABLE_ATTR_SIZE, false, true, false, true, "Table size", SAI_ATTR_VAL_TYPE_U32},
    {SAI_ACL_TABLE_ATTR_ACL_ACTION_TYPE_LIST, false, true, false, true, "List of actions", SAI_ATTR_VAL_TYPE_S32LIST},
    // Table Match Field Attributes.
    {SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6, false, true, false, true, "IPv6 Source IP Address", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6, false, true, false, true, "IPv6 Destination IP Address", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_SRC_IP, false, true, false, true, "IPv4 Source IP Address", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_DST_IP, false, true, false, true, "IPv4 Destination IP Address", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT, false, true, false, true, "L4 Source port", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT, false, true, false, true, "L4 Destination port", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL, false, true, false, true, "IP Protocol", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_DSCP, false, true, false, true, "IP DSCP", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_ECN, false, true, false, true, "IP ECN", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_TTL, false, true, false, true, "IP TTL", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS, false, true, false, true, "IP Flags", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS, false, true, false, true, "TCP Flags", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE, false, true, false, true, "ICMP Type", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE, false, true, false, true, "ICMP Code", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_TYPE, false, true, false, true, "ICMPV6 Type", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_CODE, false, true, false, true, "ICMPV6 Code", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER, false, true, false, true, "IPv6 Next Header", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_IPV6_FLOW_LABEL, false, true, false, true, "IPv6 Flow Label", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_FRAG, false, true, false, true, "IPv6 Fragment Header", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE, false, true, false, true, "IP Type", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_ROUTE_DST_USER_META, false, true, false, true, "Route user meta", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_NEIGHBOR_DST_USER_META, false, true, false, true, "Neighbor user meta", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_FDB_DST_USER_META, false, true, false, true, "fdb user meta", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_DST_MAC, false, true, true, true, "Destination mac", SAI_ATTR_VAL_TYPE_ACLFIELD},
    {SAI_ACL_TABLE_ATTR_FIELD_SRC_MAC, false, true, true, true, "Source mac", SAI_ATTR_VAL_TYPE_ACLFIELD},
    {SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE, false, true, true, true, "Ethernet type", SAI_ATTR_VAL_TYPE_ACLFIELD},
    {SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_ID, false, true, true, true, "Outer VLAN ID", SAI_ATTR_VAL_TYPE_ACLFIELD},
    {SAI_ACL_TABLE_ATTR_FIELD_SRC_PORT, false, false, false, true, "Source Port", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_OUT_PORT, false, false, false, true, "output port", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE, false, true, false, true, "List of range types", SAI_ATTR_VAL_TYPE_S32LIST},
    // End of Table Match Field.
    {SAI_ACL_TABLE_ATTR_ENTRY_LIST, false, false, false, true, "List of entries associated with table", SAI_ATTR_VAL_TYPE_OBJLIST},
    {SAI_ACL_TABLE_ATTR_AVAILABLE_ACL_ENTRY, false, false, false, true, "Number of entries", SAI_ATTR_VAL_TYPE_U32},
    {SAI_ACL_TABLE_ATTR_AVAILABLE_ACL_COUNTER, false, false, false, true, "Number of counters", SAI_ATTR_VAL_TYPE_U32},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

extern const sai_attribute_entry_t acl_entry_attribs[]
    = {{SAI_ACL_ENTRY_ATTR_TABLE_ID, true, true, false, true, "SAI ACL table object id", SAI_ATTR_VAL_TYPE_OID},
       {SAI_ACL_ENTRY_ATTR_PRIORITY, false, true, true, true, "Priority", SAI_ATTR_VAL_TYPE_U32},
       {SAI_ACL_ENTRY_ATTR_ADMIN_STATE, false, true, true, true, "Admin state", SAI_ATTR_VAL_TYPE_BOOL},
       // Rule Match Field Attributes.
       {SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6, false, true, true, true, "IPv6 Source IP Address", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6, false, true, true, true, "IPv6 Destination IP Address", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP, false, true, true, true, "IPv4 Source IP Address", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_DST_IP, false, true, true, true, "IPv4 Destination IP Address", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT, false, true, true, true, "L4 Source port", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT, false, true, true, true, "L4 Destination port", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL, false, true, true, true, "IP Protocol", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_DSCP, false, true, true, true, "IP DSCP", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_ECN, false, true, true, true, "IP ECN", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_TTL, false, true, true, true, "IP TTL", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS, false, true, true, true, "IP Flags", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS, false, true, true, true, "TCP Flags", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE, false, true, true, true, "ICMP Type", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE, false, true, true, true, "ICMP Code", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE, false, true, true, true, "ICMPV6 Type", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE, false, true, true, true, "ICMPV6 Code", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER, false, true, true, true, "IPv6 Next Header", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_IPV6_FLOW_LABEL, false, true, true, true, "IPv6 Flow Label", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG, false, true, true, true, "IPv6 Fragment Header", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE, false, true, true, true, "IP Type", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_ROUTE_DST_USER_META, false, true, true, true, "Route user meta", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_NEIGHBOR_DST_USER_META, false, true, true, true, "Neighbor user meta", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_FDB_DST_USER_META, false, true, true, true, "Fdb user meta", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC, false, true, true, true, "Destination mac", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC, false, true, true, true, "Source mac", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE, false, true, true, true, "Ethernet type", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID, false, true, true, true, "Outer VLAN ID", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_SRC_PORT, false, true, true, true, "Source Port", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT, false, true, true, true, "Out Port", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE, false, true, true, true, "List of ranges", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT, false, true, true, true, "input port", SAI_ATTR_VAL_TYPE_ACLFIELD},
       {SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS, false, true, true, true, "input ports", SAI_ATTR_VAL_TYPE_ACLFIELD},
       // End of Rule Match Field.
       // Rule Action Attributes.
       {SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT, false, true, true, true, "Redirect packet", SAI_ATTR_VAL_TYPE_ACLACTION},
       {SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION, false, true, true, true, "Drop packet", SAI_ATTR_VAL_TYPE_ACLACTION},
       {SAI_ACL_ENTRY_ATTR_ACTION_COUNTER, false, true, true, true, "Attach/detach counter to entry", SAI_ATTR_VAL_TYPE_ACLACTION},
       {SAI_ACL_ENTRY_ATTR_ACTION_SET_TC, false, true, true, true, "Set traffic class", SAI_ATTR_VAL_TYPE_U8},
       {SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP, false, true, true, true, "Set DSCP", SAI_ATTR_VAL_TYPE_U8},
       {SAI_ACL_ENTRY_ATTR_ACTION_INT_INSERT, false, true, true, true, "INT insert", SAI_ATTR_VAL_TYPE_BOOL},
       {SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS, false, true, true, true, "Mirror Ingress packet", SAI_ATTR_VAL_TYPE_OBJLIST},
       {SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS, false, true, true, true, "Mirror Egress packet", SAI_ATTR_VAL_TYPE_OBJLIST},
       {SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER, false, true, true, true, "Policer", SAI_ATTR_VAL_TYPE_OID},
       // End of Rule Action.
       {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

extern const sai_attribute_entry_t acl_counter_attribs[]
    = {{SAI_ACL_COUNTER_ATTR_TABLE_ID, true, true, false, true, "SAI ACL table object id", SAI_ATTR_VAL_TYPE_OID},
       {SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT, false, true, false, true, "Enable/disable packet count", SAI_ATTR_VAL_TYPE_BOOL},
       {SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT, false, true, false, true, "Enable/disable byte count", SAI_ATTR_VAL_TYPE_BOOL},
       {SAI_ACL_COUNTER_ATTR_PACKETS, false, true, false, true, "Get packet count", SAI_ATTR_VAL_TYPE_BOOL},
       {SAI_ACL_COUNTER_ATTR_BYTES, false, true, false, true, "Get byte count", SAI_ATTR_VAL_TYPE_BOOL},
       {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

extern const sai_attribute_entry_t acl_range_attribs[]
    = {{SAI_ACL_RANGE_ATTR_TYPE, true, true, false, true, "ACL range type", SAI_ATTR_VAL_TYPE_S32},
       {SAI_ACL_RANGE_ATTR_LIMIT, true, true, false, true, "ACL range limit", SAI_ATTR_VAL_TYPE_U32RANGE},
       {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

extern const sai_attribute_entry_t acl_table_group_attribs[]
    = {{SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE, true, true, false, true, "ACL Stage", SAI_ATTR_VAL_TYPE_S32},
       {SAI_ACL_TABLE_GROUP_ATTR_MEMBER_LIST, false, false, false, true, "ACL table group members.", SAI_ATTR_VAL_TYPE_OBJLIST},
       {SAI_ACL_TABLE_GROUP_ATTR_ACL_BIND_POINT_TYPE_LIST,
        false,
        false,
        false,
        true,
        "ACL bind point list.",
        SAI_ATTR_VAL_TYPE_U32LIST},
       {SAI_ACL_TABLE_GROUP_ATTR_TYPE, false, false, false, true, "ACL table group type.", SAI_ATTR_VAL_TYPE_S32},
       {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

extern const sai_attribute_entry_t acl_table_group_member_attribs[]
    = {{SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID, true, true, false, true, "ACL Table group id", SAI_ATTR_VAL_TYPE_OID},
       {SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID, true, true, false, true, "ACL Table id", SAI_ATTR_VAL_TYPE_OID},
       {SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY, true, true, false, true, "Priority", SAI_ATTR_VAL_TYPE_U32},
       {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t acl_table_vendor_attribs[] = {
    /*
    id,
    {create, remove, set, get}, // implemented
    {create, remove, set, get}, // supported
    getter, getter_arg,
    setter, setter_arg
    */
    {SAI_ACL_TABLE_ATTR_ACL_STAGE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_stage,
     nullptr,
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_bind_point_type_list,
     nullptr,
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_SIZE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_size,
     nullptr,
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_ACL_ACTION_TYPE_LIST,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_action_type_list,
     nullptr,
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_SRC_IP,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_SRC_IP),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_DST_IP,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_DST_IP),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_DSCP,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_DSCP),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_ECN,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_ECN),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_TTL,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_TTL),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_TCP_FLAGS),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_TYPE),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_CODE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_CODE),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_IPV6_FLOW_LABEL,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_IPV6_FLOW_LABEL),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_FRAG,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_FRAG),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_ROUTE_DST_USER_META,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_ROUTE_DST_USER_META),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_NEIGHBOR_DST_USER_META,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_NEIGHBOR_DST_USER_META),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_FDB_DST_USER_META,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_FDB_DST_USER_META),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_DST_MAC,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_DST_MAC),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_SRC_MAC,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_SRC_MAC),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_ID,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_OUTER_VLAN_ID),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_SRC_PORT,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_SRC_PORT),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_OUT_PORT,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_field,
     (void*)(SAI_ACL_TABLE_ATTR_FIELD_OUT_PORT),
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_match_range,
     nullptr,
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_ENTRY_LIST,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_entry_list,
     nullptr,
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_AVAILABLE_ACL_ENTRY,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_avail_entry_count,
     nullptr,
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_ATTR_AVAILABLE_ACL_COUNTER,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_attr_avail_acl_counters,
     nullptr,
     nullptr,
     nullptr}};

static const sai_vendor_attribute_entry_t acl_entry_vendor_attribs[] = {
    /*
    id,
    {create, remove, set, get}, // implemented
    {create, remove, set, get}, // supported
    getter, getter_arg,
    setter, setter_arg
    */
    {SAI_ACL_ENTRY_ATTR_TABLE_ID,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_table_id,
     nullptr,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_PRIORITY,
     {true, false, false, true},
     {true, false, true, true},
     sai_acl::get_acl_entry_attr_priority,
     nullptr,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_ADMIN_STATE,
     {true, false, true, true},
     {true, false, true, true},
     sai_acl::get_acl_entry_attr_admin_state,
     nullptr,
     sai_acl::set_acl_entry_attr_admin_state,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_DST_IP,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_DST_IP,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_DSCP,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_DSCP,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_ECN,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_ECN,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_TTL,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_TTL,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_IPV6_FLOW_LABEL,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_IPV6_FLOW_LABEL,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_ROUTE_DST_USER_META,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_ROUTE_DST_USER_META,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_NEIGHBOR_DST_USER_META,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_NEIGHBOR_DST_USER_META,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_FDB_DST_USER_META,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_FDB_DST_USER_META,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)(SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC),
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)(SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC),
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)(SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE),
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)(SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID),
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_SRC_PORT,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)(SAI_ACL_ENTRY_ATTR_FIELD_SRC_PORT),
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)(SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT),
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_field_rule,
     (void*)SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT,
     {true, false, true, true},
     {true, false, true, true},
     sai_acl::get_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT,
     sai_acl::set_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT},
    {SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_ACTION_COUNTER,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_COUNTER,
     nullptr,
     nullptr},
    {SAI_ACL_ENTRY_ATTR_ACTION_SET_TC,
     {true, false, true, true},
     {true, false, true, true},
     sai_acl::get_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_TC,
     sai_acl::set_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_TC},
    {SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP,
     {true, false, true, true},
     {true, false, true, true},
     sai_acl::get_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP,
     sai_acl::set_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP},
    {SAI_ACL_ENTRY_ATTR_ACTION_INT_INSERT,
     {true, false, true, true},
     {true, false, true, true},
     sai_acl::get_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_INT_INSERT,
     sai_acl::set_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_INT_INSERT},
    {SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS,
     {true, false, true, true},
     {true, false, true, true},
     sai_acl::get_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS,
     sai_acl::set_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS},
    {SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS,
     {true, false, true, true},
     {true, false, true, true},
     sai_acl::get_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS,
     sai_acl::set_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS},
    {SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER,
     {true, false, true, true},
     {true, false, true, true},
     sai_acl::get_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER,
     sai_acl::set_acl_entry_attr_action_rule,
     (void*)SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER},
};

static const sai_vendor_attribute_entry_t acl_counter_vendor_attribs[] = {
    /*
    id,
    {create, remove, set, get}, // implemented
    {create, remove, set, get}, // supported
    getter, getter_arg,
    setter, setter_arg
    */
    {SAI_ACL_COUNTER_ATTR_TABLE_ID,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_counter_attr_table_id,
     nullptr,
     nullptr,
     nullptr},
    {SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::acl_counter_attr_counter_enabled,
     (void*)SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT,
     nullptr,
     nullptr},
    {SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::acl_counter_attr_counter_enabled,
     (void*)SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT,
     nullptr,
     nullptr},
    {SAI_ACL_COUNTER_ATTR_PACKETS,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_counter_attr_counter,
     (void*)SAI_ACL_COUNTER_ATTR_PACKETS,
     nullptr,
     nullptr},
    {SAI_ACL_COUNTER_ATTR_BYTES,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_counter_attr_counter,
     (void*)SAI_ACL_COUNTER_ATTR_BYTES,
     nullptr,
     nullptr}};

static const sai_vendor_attribute_entry_t acl_range_vendor_attribs[] = {
    /*
    id,
    {create, remove, set, get}, // implemented
    {create, remove, set, get}, // supported
    getter, getter_arg,
    setter, setter_arg
    */
    {SAI_ACL_RANGE_ATTR_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_range_attr_val,
     (void*)SAI_ACL_RANGE_ATTR_TYPE,
     nullptr,
     nullptr},

    {SAI_ACL_RANGE_ATTR_LIMIT,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_range_attr_val,
     (void*)SAI_ACL_RANGE_ATTR_LIMIT,
     nullptr,
     nullptr}};

static const sai_vendor_attribute_entry_t acl_table_group_vendor_attribs[] = {
    /*
    id,
    {create, remove, set, get}, // implemented
    {create, remove, set, get}, // supported
    getter, getter_arg,
    setter, setter_arg
    */
    {SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_group,
     (void*)SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE,
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_GROUP_ATTR_MEMBER_LIST,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_group,
     (void*)SAI_ACL_TABLE_GROUP_ATTR_MEMBER_LIST,
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_GROUP_ATTR_ACL_BIND_POINT_TYPE_LIST,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_group,
     (void*)SAI_ACL_TABLE_GROUP_ATTR_ACL_BIND_POINT_TYPE_LIST,
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_GROUP_ATTR_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_table_group,
     (void*)SAI_ACL_TABLE_GROUP_ATTR_TYPE,
     nullptr,
     nullptr}};

static const sai_vendor_attribute_entry_t acl_table_group_member_vendor_attribs[] = {
    /*
    id,
    {create, remove, set, get}, // implemented
    {create, remove, set, get}, // supported
    getter, getter_arg,
    setter, setter_arg
    */
    {SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_group_member,
     (void*)SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID,
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_group_member,
     (void*)SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID,
     nullptr,
     nullptr},
    {SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY,
     {true, false, false, true},
     {true, false, false, true},
     sai_acl::get_acl_group_member,
     (void*)SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY,
     nullptr,
     nullptr}};

std::string
sai_acl::acl_table_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_acl_table_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << "\n";

    return log_message.str();
}

bool
sai_acl::is_v6_acl_table_field(uint32_t attr_id)
{
    switch (attr_id) {
    case SAI_ACL_TABLE_ATTR_FIELD_SRC_IPV6:
    case SAI_ACL_TABLE_ATTR_FIELD_DST_IPV6:
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_SRC_IPV6:
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_DST_IPV6:
    case SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_FRAG:
    case SAI_ACL_TABLE_ATTR_FIELD_IPV6_FLOW_LABEL:
    case SAI_ACL_TABLE_ATTR_FIELD_IPV6_NEXT_HEADER:
    case SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_TYPE:
    case SAI_ACL_TABLE_ATTR_FIELD_ICMPV6_CODE:
        return true;
        break;
    default:
        return false;
    }

    return false;
}

bool
sai_acl::is_v4_acl_table_field(uint32_t attr_id)
{
    switch (attr_id) {
    case SAI_ACL_TABLE_ATTR_FIELD_SRC_IP:
    case SAI_ACL_TABLE_ATTR_FIELD_DST_IP:
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_SRC_IP:
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_DST_IP:
    case SAI_ACL_TABLE_ATTR_FIELD_IP_PROTOCOL:
    case SAI_ACL_TABLE_ATTR_FIELD_INNER_IP_PROTOCOL:
    case SAI_ACL_TABLE_ATTR_FIELD_IP_IDENTIFICATION:
    case SAI_ACL_TABLE_ATTR_FIELD_ICMP_TYPE:
    case SAI_ACL_TABLE_ATTR_FIELD_ICMP_CODE:
    case SAI_ACL_TABLE_ATTR_FIELD_IP_FLAGS:
    case SAI_ACL_TABLE_ATTR_FIELD_ETHER_TYPE:
    case SAI_ACL_TABLE_ATTR_FIELD_TUNNEL_VNI:
        // Do not use SAI_ACL_TABLE_ATTR_FIELD_TTL to qualify lookup type as V4
        return true;
        break;
    default:
        return false;
    }
    return false;
}

// Returns true is acl_table_attr field is one of the default acl table match field
// and also categories the field as v4/v6/other (when its not in ip header)
bool
sai_acl::is_non_l3_header_field(uint32_t attr_id)
{
    return !is_v4_acl_table_field(attr_id) && !is_v6_acl_table_field(attr_id);
}

// If l3 field from both v4 and v6 header is in the table-field list, then the function
// marks the field set as invalid.
bool
sai_acl::is_valid_acl_field_set(const std::set<uint32_t>& table_fields, uint8_t profile_type)
{
    bool is_valid_field_set = true;
    uint32_t mismatched_acl_field_id;
    for (auto acl_field : table_fields) {
        if (!is_non_l3_header_field(acl_field)) {
            if (is_v4_acl_table_field(acl_field) && profile_type == SDK_ACL_PROFILE_TYPE_V6) {
                if (acl_field == SAI_ACL_TABLE_ATTR_FIELD_TTL) {
                    // TTL although categrized as v4 field, same attribute is used match
                    // field in place of HOP_LIMIT along with other v6 header fields.
                    continue;
                }
                is_valid_field_set = false;
                mismatched_acl_field_id = acl_field;
                break;
            }

            if (!is_v4_acl_table_field(acl_field) && profile_type == SDK_ACL_PROFILE_TYPE_V4) {
                if (acl_field == SAI_ACL_TABLE_ATTR_FIELD_TTL) {
                    // TTL although categrized as v4 field, same attribute is used match
                    // field in place of HOP_LIMIT along with other v6 header fields.
                    continue;
                }
                is_valid_field_set = false;
                mismatched_acl_field_id = acl_field;
                break;
            }
        }
    }

    if (!is_valid_field_set) {
        sai_log_error(SAI_API_ACL,
                      "Acl match field %d conflicts with another match field"
                      " in the match vector set",
                      mismatched_acl_field_id);
    }

    return is_valid_field_set;
}

sai_status_t
sai_acl::process_acl_table_range_type(const sai_s32_list_t& range_list,
                                      lasai_acl_table_t& table,
                                      std::set<uint32_t>& acl_table_fields)
{
    for (uint32_t i = 0; i < range_list.count; i++) {
        sai_acl_range_type_t range_type = (sai_acl_range_type_t)range_list.list[i];
        switch (range_type) {
        case SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE:
            acl_table_fields.insert(SAI_ACL_TABLE_ATTR_FIELD_L4_SRC_PORT);
            break;
        case SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE:
            acl_table_fields.insert(SAI_ACL_TABLE_ATTR_FIELD_L4_DST_PORT);
            break;
        case SAI_ACL_RANGE_TYPE_OUTER_VLAN:
        case SAI_ACL_RANGE_TYPE_INNER_VLAN:
        case SAI_ACL_RANGE_TYPE_PACKET_LENGTH:
        default:
            sai_log_error(SAI_API_ACL, "Unsupported table range type: (%d)", range_type);
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
        table.match_range.push_back(range_type);
    }
    return SAI_STATUS_SUCCESS;
}

// Collect ACL table match fields, bind points, acl-actions
sai_status_t
sai_acl::process_acl_table_attributes(const sai_attribute_t* attr_list,
                                      uint32_t attr_count,
                                      lasai_acl_table_t& table,
                                      std::set<uint32_t>& acl_table_fields)
{
    for (uint32_t attr_index = 0; attr_index < attr_count; attr_index++) {
        const sai_attribute_t* attr = &attr_list[attr_index];
        if (attr->id == SAI_ACL_TABLE_ATTR_ACL_STAGE) {
            continue;
        } else if (attr->id == SAI_ACL_TABLE_ATTR_SIZE) {
            table.table_size = attr->value.u32;
        } else if (attr->id == SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST) {
            for (uint32_t i = 0; i < attr->value.s32list.count; i++) {
                table.bind_point_types.push_back(attr->value.s32list.list[i]);
            }
        } else if (attr->id == SAI_ACL_TABLE_ATTR_ACL_ACTION_TYPE_LIST) {
            for (size_t i = 0; i < attr->value.s32list.count; ++i) {
                sai_acl_action_type_t acl_table_action = static_cast<sai_acl_action_type_t>(attr->value.s32list.list[i]);

                if (((table.stage == SAI_ACL_STAGE_INGRESS)
                     && (supported_ingress_acl_actions_list.find(acl_table_action) == supported_ingress_acl_actions_list.end()))
                    || ((table.stage == SAI_ACL_STAGE_EGRESS)
                        && (supported_egress_acl_actions_list.find(acl_table_action)) == supported_egress_acl_actions_list.end())) {
                    sai_log_error(SAI_API_ACL, "Unsupported ACL action: %u for stage: %u", acl_table_action, table.stage);
                    return SAI_STATUS_NOT_SUPPORTED;
                }
                table.acl_action_types.push_back(attr->value.s32list.list[i]);
            }
        } else if (attr->id >= SAI_ACL_TABLE_ATTR_FIELD_START && attr->id <= SAI_ACL_TABLE_ATTR_FIELD_END) {
            if (attr->id == SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE) {
                table.match_field[attr->id - SAI_ACL_TABLE_ATTR_FIELD_START] = true;
                // no need to add IP-type into table match-field vector.
            } else if (attr->id == SAI_ACL_TABLE_ATTR_FIELD_ACL_RANGE_TYPE) {
                sai_status_t sstatus = process_acl_table_range_type(attr->value.s32list, table, acl_table_fields);
                sai_return_on_error(sstatus);
                table.match_field[attr->id - SAI_ACL_TABLE_ATTR_FIELD_START] = true;
            } else {
                // Include only those match fields in acl-table that are enabled.
                if (attr->value.booldata) {
                    if (attr->id == SAI_ACL_TABLE_ATTR_FIELD_OUT_PORT || attr->id == SAI_ACL_TABLE_ATTR_FIELD_OUT_PORTS) {
                        // TODO: Remove this check after ACL functionality expectation is adjusted both in NOS test cases and our
                        // support for customer. Until then, make progress by ignoring OUT port usage in ACE match vector.
                        continue;
                    }
                    acl_table_fields.insert(attr->id);
                    table.match_field[attr->id - SAI_ACL_TABLE_ATTR_FIELD_START] = true;
                    if (attr->id == SAI_ACL_TABLE_ATTR_FIELD_TTL) {
                        continue;
                    } else {
                        table.is_v6_acl |= is_v6_acl_table_field(attr->id);
                        table.is_v4_acl |= is_v4_acl_table_field(attr->id);
                    }
                }
            }
        } else {
            sai_log_error(SAI_API_ACL, "ACL table attribute %d is invalid.", attr->id);
            return SAI_STATUS_FAILURE;
        }
    }

    if (acl_table_fields.empty()) {
        sai_log_error(SAI_API_ACL, "ACL table match fields not specified.");
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

// From combined v4 and v6 acl match table fields, create acl match table fields
// v4 acl table and v6 acl sdk table lookups.
void
sai_acl::create_seperate_v4_v6_acl_table_field_set(const std::set<uint32_t>& acl_table_combined_fields,
                                                   std::set<uint32_t>& v4_table_fields,
                                                   std::set<uint32_t>& v6_table_fields)
{
    v4_table_fields = acl_table_combined_fields;
    v6_table_fields = acl_table_combined_fields;
    for (auto it = v4_table_fields.cbegin(); it != v4_table_fields.cend();) {
        if (*it != SAI_ACL_TABLE_ATTR_FIELD_TTL && is_v6_acl_table_field(*it)) {
            it = v4_table_fields.erase(it);
        } else {
            ++it;
        }
    }

    for (auto it = v6_table_fields.cbegin(); it != v6_table_fields.cend();) {
        if (*it != SAI_ACL_TABLE_ATTR_FIELD_TTL && is_v4_acl_table_field(*it)) {
            it = v6_table_fields.erase(it);
        } else {
            ++it;
        }
    }
}

// Creates either V4 or V6 default SDK acl key. Also checks for
sai_status_t
sai_acl::create_default_sdk_acl_key(uint8_t profile_type,
                                    const std::set<uint32_t>& acl_table_fields,
                                    la_acl_key_def_vec_t& sdk_key_vec)
{
    if (profile_type == SDK_ACL_PROFILE_TYPE_V4) {
        const la_acl_key_def_vec_t SAI_DEFAULT_ACL_KEY_IPV4 = {{.type = la_acl_field_type_e::IPV4_SIP, {}},
                                                               {.type = la_acl_field_type_e::IPV4_DIP, {}},
                                                               {.type = la_acl_field_type_e::TOS, {}},
                                                               {.type = la_acl_field_type_e::PROTOCOL, {}},
                                                               {.type = la_acl_field_type_e::IPV4_FLAGS, {}},
                                                               {.type = la_acl_field_type_e::TTL, {}},
                                                               {.type = la_acl_field_type_e::SPORT, {}},
                                                               {.type = la_acl_field_type_e::DPORT, {}},
                                                               {.type = la_acl_field_type_e::TCP_FLAGS, {}},
                                                               {.type = la_acl_field_type_e::MSG_CODE, {}},
                                                               {.type = la_acl_field_type_e::MSG_TYPE, {}}};

        sdk_key_vec = SAI_DEFAULT_ACL_KEY_IPV4;
    } else {
        // cannot use LA_ACL_KEY_IPV6 since by default it provides
        // limited set of ACL match fields.
        const la_acl_key_def_vec_t SAI_DEFAULT_ACL_KEY_IPV6 = {// TODO Once object group ACL allow to use both V6 SIP and DIP
                                                               // also include IPV6_SIP. Lets not forget to make corresponding
                                                               // changes in unit test code to enable back IPV6 SIP
                                                               //{.type = la_acl_field_type_e::IPV6_SIP, {}},
                                                               {.type = la_acl_field_type_e::IPV6_DIP, {}},
                                                               {.type = la_acl_field_type_e::TOS, {}},
                                                               {.type = la_acl_field_type_e::LAST_NEXT_HEADER, {}},
                                                               {.type = la_acl_field_type_e::SPORT, {}},
                                                               {.type = la_acl_field_type_e::DPORT, {}},
                                                               {.type = la_acl_field_type_e::TCP_FLAGS, {}},
                                                               {.type = la_acl_field_type_e::MSG_CODE, {}},
                                                               {.type = la_acl_field_type_e::MSG_TYPE, {}}};

        sdk_key_vec = SAI_DEFAULT_ACL_KEY_IPV6;
    }

    for (auto attr_id : acl_table_fields) {
        if (attr_id == SAI_ACL_TABLE_ATTR_FIELD_ACL_IP_TYPE) {
            // Currently IP-TYPE is not a well defined SDK acl field.
            continue;
        }

        la_acl_field_type_e sdk_field;
        sai_status_t sstatus = sai_attr_to_sdk_field_type(attr_id, sdk_field);
        sai_return_on_error(sstatus);

        auto iter = std::find_if(sdk_key_vec.cbegin(), sdk_key_vec.cend(), [&sdk_field](const la_acl_field_def& elem) {
            return sdk_field == elem.type;
        });

        if (iter == sdk_key_vec.cend()) {
            if (attr_id == SAI_ACL_TABLE_ATTR_FIELD_TTL && profile_type == SDK_ACL_PROFILE_TYPE_V6) {
                // !!!! HACK !!!!!
                // Currently SDK cannot support TTL as match field for V6 packet unless UDF is used.
                // When default ACL capability is used, for now add hack to allow ACL table creation
                // This is to allow any NOS that has already TTL as match along with V6 key vector.
                // Its important to remember that v6 packets that are supposed to be processed
                // by ACL based on HOP_LIMIT will not be correctly treated in the hw/pipeline.
                continue; // Remove this line/block once NOS adhere to TTL match limitation.
            }
            sai_log_error(SAI_API_ACL, "Acl table field %d is not found in sdk default key profile.", attr_id);
            return SAI_STATUS_NOT_SUPPORTED;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::create_sdk_acl_table_key_profile(const std::shared_ptr<lsai_device>& sdev,
                                          const std::set<uint32_t>& acl_table_fields,
                                          uint8_t profile_type,
                                          lasai_acl_table_t& table,
                                          la_acl_key_profile*& sdk_acl_key_profile)
{
    bool is_valid_field_set = false;
    la_acl_key_def_vec_t sdk_key_vec;
    la_acl_key_def_vec_t sdk_key_vec_other;
    la_acl_direction_e sdk_acl_dir;
    sai_status_t sstatus = sai_acl_stage_to_sdk_acl_dir(table.stage, sdk_acl_dir);
    sai_return_on_error(sstatus);

    is_valid_field_set = is_valid_acl_field_set(acl_table_fields, profile_type);
    if (!is_valid_field_set) {
        sai_log_error(SAI_API_ACL, "Acl match field set is invalid.");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    std::set<uint32_t> acl_table_fields_empty;
    auto profile_type_name = (profile_type == SDK_ACL_PROFILE_TYPE_V4) ? "v4" : "v6";
    sdk_acl_key_profile = sdev->m_acl_handler->m_acl_udk.get_udk_acl_profile(acl_table_fields, profile_type, sdk_acl_dir);

    if (sdk_acl_key_profile == nullptr) {
        // try look up with empty fields, in case it matches the default profile created without user request
        sdk_acl_key_profile = sdev->m_acl_handler->m_acl_udk.get_udk_acl_profile(acl_table_fields_empty, profile_type, sdk_acl_dir);
    }

    if (sdk_acl_key_profile == nullptr) {
        // Since we can't create more key profiles after creating acl object in SDK. for now
        // create here all possible default key profile combinations. (IPv4/6, ingress/egress)
        // For the one the user requested, check validity. For others, just create default.
        sstatus = create_default_sdk_acl_key(profile_type, acl_table_fields, sdk_key_vec);
        sai_return_on_error_log(sstatus, "One or more acl table match/key fields are unsupported.");

        uint8_t profile_type_other = (profile_type == SDK_ACL_PROFILE_TYPE_V4) ? SDK_ACL_PROFILE_TYPE_V6 : SDK_ACL_PROFILE_TYPE_V4;
        // empty fields list. Will not validate. Just create default key vector
        sstatus = create_default_sdk_acl_key(profile_type_other, acl_table_fields_empty, sdk_key_vec_other);

        la_acl_direction_e sdk_acl_dir_opposite;
        if (sdk_acl_dir == la_acl_direction_e::INGRESS) {
            sdk_acl_dir_opposite = la_acl_direction_e::EGRESS;
        } else {
            sdk_acl_dir_opposite = la_acl_direction_e::INGRESS;
        }

        la_status status = sdev->m_acl_handler->m_acl_udk.create_sdk_acl_key_profile(
            profile_type, sdk_acl_dir, false, sdk_key_vec, acl_table_fields);
        sai_return_on_la_error_log(status, "SDK %s acl match profile create failed.", profile_type_name);

        status = sdev->m_acl_handler->m_acl_udk.create_sdk_acl_key_profile(
            profile_type, sdk_acl_dir_opposite, false, sdk_key_vec, acl_table_fields);
        // best effort. Don't fail if opposite direction key profile create fail
        if (status != LA_STATUS_SUCCESS) {
            sai_log_debug(SAI_API_ACL, "SDK %s acl match profile opposite direction create failed.", profile_type_name);
        }

        // best effort. Don't fail if could not create other protocol key profile
        sdev->m_acl_handler->m_acl_udk.create_sdk_acl_key_profile(
            profile_type_other, sdk_acl_dir, false, sdk_key_vec_other, acl_table_fields_empty);
        sdev->m_acl_handler->m_acl_udk.create_sdk_acl_key_profile(
            profile_type_other, sdk_acl_dir_opposite, false, sdk_key_vec_other, acl_table_fields_empty);

        // make sure we return the profile requested by the user
        sdk_acl_key_profile = sdev->m_acl_handler->m_acl_udk.get_udk_acl_profile(acl_table_fields, profile_type, sdk_acl_dir);

        if (sdk_acl_key_profile == nullptr) {
            sai_return_on_error_log(SAI_STATUS_FAILURE, "Failed creating acl match key profile");
        } else {
            sai_log_debug(SAI_API_ACL, "SDK %s acl match key profile created.", profile_type_name);
        }
    } else {
        if (profile_type == SDK_ACL_PROFILE_TYPE_V4) {
            table.is_v4_udk = true;
        } else {
            table.is_v6_udk = true;
        }
        sai_log_debug(SAI_API_ACL, "SDK %s using existing acl key profile", profile_type_name);
    }

    return SAI_STATUS_SUCCESS;
}

// Using sai acl match table fields, create sdk acl table.
sai_status_t
sai_acl::create_sdk_acl_table(const std::shared_ptr<lsai_device>& sdev,
                              la_acl_key_profile* sdk_acl_key_profile,
                              uint8_t profile_type,
                              lasai_acl_table_t& table,
                              la_acl*& sdk_acl_table)
{
    la_acl_command_profile* sdk_acl_command_profile = nullptr;
    la_status status = sdev->m_dev->create_acl_command_profile(LA_ACL_SUPPORTED_COMMANDS, sdk_acl_command_profile);
    sai_return_on_la_error_log(status, "acl command profile create failed");
    sai_log_debug(SAI_API_ACL, "SDK acl command profile created");

    status = sdev->m_dev->create_acl(sdk_acl_key_profile, sdk_acl_command_profile, sdk_acl_table);
    sai_return_on_la_error_log(status, "Acl table creation failed");
    if (profile_type == SDK_ACL_PROFILE_TYPE_V4) {
        table.v4_sdk_acl_key_profile = sdk_acl_key_profile;
        table.v4_sdk_acl_command_profile = sdk_acl_command_profile;
    } else {
        table.v6_sdk_acl_key_profile = sdk_acl_key_profile;
        table.v6_sdk_acl_command_profile = sdk_acl_command_profile;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::create_acl_table(_Out_ sai_object_id_t* acl_table_id,
                          _In_ sai_object_id_t switch_id,
                          _In_ uint32_t attr_count,
                          _In_ const sai_attribute_t* attr_list)
{
    la_status status;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_SWITCH, switch_id, &acl_table_to_string, "attrs", attrs);

    sai_acl_stage_t acl_stage;
    get_attrs_value(SAI_ACL_TABLE_ATTR_ACL_STAGE, attrs, acl_stage, true);
    if ((acl_stage != SAI_ACL_STAGE_INGRESS) && (acl_stage != SAI_ACL_STAGE_EGRESS)) {
        sai_log_error(SAI_API_ACL, "ACL table creation error - stage not supported.");
        return SAI_STATUS_NOT_SUPPORTED;
    }

    lasai_acl_table_t table;
    // Size is added by 1 more slot because SAI_ACL_TABLE_ATTR_FIELD_END is valid attribute
    table.match_field.resize((SAI_ACL_TABLE_ATTR_FIELD_END - SAI_ACL_TABLE_ATTR_FIELD_START) + 1, false);

    table.table_size = 0; // 0 means that it can dynamically grow until maximum, default.
    table.stage = acl_stage;
    std::set<uint32_t> acl_table_fields{};
    sai_status_t sstatus = process_acl_table_attributes(attr_list, attr_count, table, acl_table_fields);
    sai_return_on_error(sstatus);

    std::set<uint32_t> acl_table_v4_fields{};
    std::set<uint32_t> acl_table_v6_fields{};
    if (table.is_v4_acl && table.is_v6_acl) {
        sai_log_debug(SAI_API_ACL, "Combined v4 and v6 sai acl table");
        // Combined v4 and v6 table with L3 header fields. Create two sets of match key vector
        // one for v4 packet lookup and another for v6 packet lookup. Since ACL match for v4
        // and v6 are in two different ACL tables in hw.
        create_seperate_v4_v6_acl_table_field_set(acl_table_fields, acl_table_v4_fields, acl_table_v6_fields);
        if (acl_table_v4_fields.empty() || acl_table_v6_fields.empty()) {
            sai_log_error(SAI_API_ACL, "Combined V4 V6 ACL table creation error.");
            return SAI_STATUS_FAILURE;
        }
    } else if (!table.is_v4_acl && !table.is_v6_acl) {
        // ACL table is comprised of only non L3 fields or non L3 fields + TTL field  or only TTL.
        // Create both v4 and v6 sdk tables used for lookup respectively for v4 and v6 packet.
        sai_log_debug(SAI_API_ACL, "acl table creation with non L3 header fields and/or TTL.");
        table.is_v4_acl = true;
        table.is_v6_acl = true;
        acl_table_v4_fields = acl_table_fields;
        acl_table_v6_fields = acl_table_fields;
    } else {
        // one of either v4 or v6 field based acl table.
        sai_log_debug(SAI_API_ACL, "One of v4 or v6 sai acl table");
    }

    if (table.table_size == 0) {
        table.table_size = MAX_ACL_ENTRIES_PER_TABLE;
    } else if (table.table_size > MAX_ACL_ENTRIES_PER_TABLE) {
        sai_log_error(SAI_API_ACL, "ACL table size is too large to support.");
        return SAI_STATUS_FAILURE;
    }

    table.device_id = la_obj.switch_id;
    la_acl* sdk_acl_table = nullptr;
    table.v4_sdk_acl = sdk_acl_table;
    table.v6_sdk_acl = sdk_acl_table;

    transaction txn{};
    if (table.is_v4_acl && table.is_v6_acl) {
        // Acl table with combined v4 and v6 match fields.
        // Create two sdk tables one for each l3 based lookup
        // It is required to create all ACL table key profile before creating first ACL table.
        la_acl_key_profile* sdk_acl_v4_key_profile = nullptr;
        sstatus
            = create_sdk_acl_table_key_profile(sdev, acl_table_v4_fields, SDK_ACL_PROFILE_TYPE_V4, table, sdk_acl_v4_key_profile);
        sai_return_on_error(sstatus);
        txn.on_fail([=]() { sdev->m_dev->destroy(sdk_acl_v4_key_profile); });
        la_acl_key_profile* sdk_acl_v6_key_profile = nullptr;
        sstatus
            = create_sdk_acl_table_key_profile(sdev, acl_table_v6_fields, SDK_ACL_PROFILE_TYPE_V6, table, sdk_acl_v6_key_profile);
        sai_return_on_error(sstatus);
        txn.on_fail([=]() { sdev->m_dev->destroy(sdk_acl_v6_key_profile); });
        sstatus = create_sdk_acl_table(sdev, sdk_acl_v4_key_profile, SDK_ACL_PROFILE_TYPE_V4, table, sdk_acl_table);
        sai_return_on_error(sstatus);
        table.v4_sdk_acl = sdk_acl_table;
        txn.on_fail([=]() { sdev->m_dev->destroy(table.v4_sdk_acl); });
        sdk_acl_table = nullptr;
        sstatus = create_sdk_acl_table(sdev, sdk_acl_v6_key_profile, SDK_ACL_PROFILE_TYPE_V6, table, sdk_acl_table);
        sai_return_on_error(sstatus);
        table.v6_sdk_acl = sdk_acl_table;
        txn.on_fail([=]() { sdev->m_dev->destroy(table.v6_sdk_acl); });
    } else if (table.is_v4_acl) {
        la_acl_key_profile* sdk_acl_v4_key_profile = nullptr;
        sstatus = create_sdk_acl_table_key_profile(sdev, acl_table_fields, SDK_ACL_PROFILE_TYPE_V4, table, sdk_acl_v4_key_profile);
        sai_return_on_error(sstatus);
        txn.on_fail([=]() { sdev->m_dev->destroy(sdk_acl_v4_key_profile); });
        sstatus = create_sdk_acl_table(sdev, sdk_acl_v4_key_profile, SDK_ACL_PROFILE_TYPE_V4, table, sdk_acl_table);
        sai_return_on_error(sstatus);
        table.v4_sdk_acl = sdk_acl_table;
        txn.on_fail([=]() { sdev->m_dev->destroy(table.v4_sdk_acl); });
    } else if (table.is_v6_acl) {
        la_acl_key_profile* sdk_acl_v6_key_profile = nullptr;
        sstatus = create_sdk_acl_table_key_profile(sdev, acl_table_fields, SDK_ACL_PROFILE_TYPE_V6, table, sdk_acl_v6_key_profile);
        sai_return_on_error(sstatus);
        txn.on_fail([=]() { sdev->m_dev->destroy(sdk_acl_v6_key_profile); });
        sstatus = create_sdk_acl_table(sdev, sdk_acl_v6_key_profile, SDK_ACL_PROFILE_TYPE_V6, table, sdk_acl_table);
        sai_return_on_error(sstatus);
        table.v6_sdk_acl = sdk_acl_table;
        txn.on_fail([=]() { sdev->m_dev->destroy(table.v6_sdk_acl); });
    }

    uint32_t map_id;
    status = sdev->m_acl_handler->m_acl_table_db.allocate_id(map_id);
    sai_return_on_la_error(status);

    lsai_object la_acl_table_id(SAI_OBJECT_TYPE_ACL_TABLE, la_obj.switch_id, map_id);
    *acl_table_id = la_acl_table_id.object_id();
    table.table_id = la_acl_table_id.object_id();

    status = sdev->m_acl_handler->m_acl_table_db.set(map_id, table);
    sai_return_on_la_error(status);

    sai_log_info(SAI_API_ACL, "acl table id 0x%lx created", *acl_table_id);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::remove_acl_table(_In_ sai_object_id_t acl_table_id)
{
    la_status status;
    lasai_acl_table_t table;

    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_ACL_TABLE, acl_table_id, &acl_table_to_string, acl_table_id);

    for (auto member : sdev->m_acl_handler->m_acl_table_group_member_db.map()) {
        if (member.second.table_id == acl_table_id) {
            sai_log_error(SAI_API_ACL, "Failed to remove ACL Table 0x%lx, it's used as member %lu", acl_table_id, member.first);
            return SAI_STATUS_OBJECT_IN_USE;
        }
    }

    status = sdev->m_acl_handler->m_acl_table_db.get(la_obj.index, table);
    sai_return_on_la_error_log(status, "Failed to remove ACL Table 0x%lx, no such table.", acl_table_id);

    if (!table.entry_list.empty()) {
        sai_log_error(SAI_API_ACL, "Failed to remove ACL Table 0x%lx, it has entries", acl_table_id);
        return SAI_STATUS_OBJECT_IN_USE;
    }

    if (!table.counters.empty()) {
        sai_log_error(SAI_API_ACL, "Failed to remove ACL Table 0x%lx, it has counters", acl_table_id);
        return SAI_STATUS_OBJECT_IN_USE;
    }

    for (auto pair : sdev->m_ports.map()) {
        if (pair.second.service.ingress_acl == acl_table_id || pair.second.service.egress_acl == acl_table_id) {
            sai_log_error(SAI_API_ACL, "Failed to remove ACL Table 0x%lx, it's bound to port %lu", acl_table_id, pair.first);
            return SAI_STATUS_OBJECT_IN_USE;
        }
    }

    for (auto pair : sdev->m_l3_ports.map()) {
        if (pair.second.ingress_acl == acl_table_id || pair.second.egress_acl == acl_table_id) {
            sai_log_error(SAI_API_ACL, "Failed to remove ACL Table 0x%lx, it's bound to port %lu", acl_table_id, pair.first);
            return SAI_STATUS_OBJECT_IN_USE;
        }
    }

    for (auto pair : sdev->m_lags.map()) {
        if (pair.second.service.ingress_acl == acl_table_id || pair.second.service.egress_acl == acl_table_id) {
            sai_log_error(SAI_API_ACL, "Failed to remove ACL Table 0x%lx, it's bound to port %lu", acl_table_id, pair.first);
            return SAI_STATUS_OBJECT_IN_USE;
        }
    }

    // All ACL table/s have to be destroyed first before ACL key/command profiles can be deleted.
    if (table.is_v4_acl) {
        status = sdev->m_dev->destroy(table.v4_sdk_acl);
        sai_return_on_la_error_log(status, "Failed to remove V4 ACL Table 0x%lx.", acl_table_id);
        table.v4_sdk_acl = nullptr;
    }

    if (table.is_v6_acl) {
        status = sdev->m_dev->destroy(table.v6_sdk_acl);
        sai_return_on_la_error_log(status, "Failed to remove V6 ACL Table 0x%lx.", acl_table_id);
        table.v6_sdk_acl = nullptr;
    }

    if (table.is_v4_acl) {
        // todo. Need better key_profile create/destroy handling
        // For now, it can't be deleted from here, because another ACL table might be using it.
        // There is also refernce to it in sdk_acl_profile_details vector in acl_udk.h
        // status = sdev->m_dev->destroy(table.v4_sdk_acl_key_profile);
        // sai_return_on_la_error_log(status, "Failed to remove match key  profile of ACL Table with id %lu.", acl_table_id);
        table.v4_sdk_acl_key_profile = nullptr;
        status = sdev->m_dev->destroy(table.v4_sdk_acl_command_profile);
        sai_return_on_la_error_log(status, "Failed to remove acl command profile of ACL Table 0x%lx.", acl_table_id);
        table.v4_sdk_acl_command_profile = nullptr;
    }

    if (table.is_v6_acl) {
        // See command above.for why we can't destroy the key profile here
        // status = sdev->m_dev->destroy(table.v6_sdk_acl_key_profile);
        // sai_return_on_la_error_log(status, "Failed to remove match key  profile of ACL Table with id %lu.", acl_table_id);
        table.v6_sdk_acl_key_profile = nullptr;
        status = sdev->m_dev->destroy(table.v6_sdk_acl_command_profile);
        sai_return_on_la_error_log(status, "Failed to remove acl command profile of ACL Table 0x%lx.", acl_table_id);
        table.v6_sdk_acl_command_profile = nullptr;
    }

    status = sdev->m_acl_handler->m_acl_table_db.remove(acl_table_id);
    sai_return_on_la_error_log(status, "Failed to remove ACL Table 0x%lx.", acl_table_id);

    // If all acl tables deleted, we can destroy all key profiles, and have a fresh start
    if (sdev->m_acl_handler->m_acl_table_db.is_empty()) {
        sdev->m_acl_handler->m_acl_udk.destroy_acl_key_profiles();
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::set_acl_table_attribute(_In_ sai_object_id_t acl_table_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
sai_acl::get_acl_table_attribute(_In_ sai_object_id_t acl_table_id, _In_ uint32_t attr_count, _Out_ sai_attribute_t* attr_list)
{
    sai_object_key_t key = {};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = acl_table_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_ACL_TABLE, acl_table_id, &acl_table_to_string, acl_table_id, "attrs", attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "acl_table 0x%lx", acl_table_id);
    return sai_get_attributes(&key, key_str, acl_table_attribs, acl_table_vendor_attribs, attr_count, attr_list);
}

std::string
sai_acl::acl_entry_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_acl_entry_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << "\n";

    return log_message.str();
}
sai_status_t
sai_acl::copy_sai_ace_field_to_sdk_udf_field(uint32_t attr_id,
                                             const sai_acl_field_data_t& sai_acl_field,
                                             la_acl_field& sdk_acl_field)
{
    switch (attr_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP: {
        sdk_acl_field.val.udf.d_data[0] = ntohl(sai_acl_field.data.ip4);
        sdk_acl_field.val.udf.d_data[0] = ntohl(sai_acl_field.mask.ip4);
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6: {
        reverse_copy(
            std::begin(sai_acl_field.data.ip6), std::end(sai_acl_field.data.ip6), std::begin(sdk_acl_field.val.udf.b_data));
        reverse_copy(
            std::begin(sai_acl_field.mask.ip6), std::end(sai_acl_field.mask.ip6), std::begin(sdk_acl_field.mask.udf.b_data));
        break;
    }
    // single byte fields
    case SAI_ACL_ENTRY_ATTR_FIELD_TTL:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_IP_PROTOCOL: {
        sdk_acl_field.val.udf.b_data[0] = sai_acl_field.data.u8;
        sdk_acl_field.mask.udf.b_data[0] = sai_acl_field.mask.u8;
        break;
    }
    // two byte fields
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_SRC_PORT:
    case SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_DST_PORT:
    case SAI_ACL_ENTRY_ATTR_FIELD_IP_IDENTIFICATION: {
        sdk_acl_field.val.udf.w_data[0] = sai_acl_field.data.u16;
        sdk_acl_field.mask.udf.w_data[0] = sai_acl_field.mask.u16;
        break;
    }

    // three-four byte fields
    case SAI_ACL_ENTRY_ATTR_FIELD_TUNNEL_VNI: {
        sdk_acl_field.val.udf.d_data[0] = sai_acl_field.data.u32;
        sdk_acl_field.mask.udf.d_data[0] = sai_acl_field.mask.u32;
        break;
    }

    default:
        sai_log_error(SAI_API_ACL, "ACL entry field attribute %d is not supported as udf.", attr_id);
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    // remove the assumption that SAI_ACL_TABLE_ATTR_FIELD_* and SAI_ACL_ENTRY_ATTR_FIELD_*
    // are sequenced in same order wrt to field attribute in sai enum numbering.
    sdk_acl_field.udf_index = attr_id - SAI_ACL_ENTRY_ATTR_FIELD_START + 1;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_sdk_port_field(sai_object_id_t port_oid, la_acl_field& sdk_acl_field)
{
    lsai_object la_port(port_oid);
    auto sdev = la_port.get_device();
    if (la_port.type != SAI_OBJECT_TYPE_PORT || sdev == nullptr) {
        sai_log_error(SAI_API_PORT, "Acl field is not port oid 0x%llx", port_oid);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    port_entry* pentry = sdev->m_ports.get_ptr(la_port.index);
    if (pentry == nullptr) {
        sai_log_error(SAI_API_PORT, "Acl field with unknown port oid 0x%llx", port_oid);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    sdk_acl_field.val.source_system_port = pentry->sys_port;
    sdk_acl_field.mask.source_system_port = sdk_acl_field.val.source_system_port;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::copy_sai_ace_field_to_sdk_field(uint32_t attr_id,
                                         const sai_acl_field_data_t& sai_acl_field,
                                         la_acl_field& sdk_acl_field,
                                         tos_info_t& tos_info)
{
    switch (attr_id) {
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IPV6: {
        reverse_copy(
            std::begin(sai_acl_field.data.ip6), std::end(sai_acl_field.data.ip6), std::begin(sdk_acl_field.val.ipv6_sip.b_addr));
        reverse_copy(
            std::begin(sai_acl_field.mask.ip6), std::end(sai_acl_field.mask.ip6), std::begin(sdk_acl_field.mask.ipv6_sip.b_addr));
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IPV6: {
        reverse_copy(
            std::begin(sai_acl_field.data.ip6), std::end(sai_acl_field.data.ip6), std::begin(sdk_acl_field.val.ipv6_dip.b_addr));
        reverse_copy(
            std::begin(sai_acl_field.mask.ip6), std::end(sai_acl_field.mask.ip6), std::begin(sdk_acl_field.mask.ipv6_dip.b_addr));
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_IP: {
        sdk_acl_field.val.ipv4_sip.s_addr = ntohl(sai_acl_field.data.ip4);
        sdk_acl_field.mask.ipv4_sip.s_addr = ntohl(sai_acl_field.mask.ip4);
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_DST_IP: {
        sdk_acl_field.val.ipv4_dip.s_addr = ntohl(sai_acl_field.data.ip4);
        sdk_acl_field.mask.ipv4_dip.s_addr = ntohl(sai_acl_field.mask.ip4);
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_L4_SRC_PORT: {
        sdk_acl_field.val.sport = sai_acl_field.data.u16;
        sdk_acl_field.mask.sport = sai_acl_field.mask.u16;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT: {
        sdk_acl_field.val.dport = sai_acl_field.data.u16;
        sdk_acl_field.mask.dport = sai_acl_field.mask.u16;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL: {
        sdk_acl_field.val.protocol = sai_acl_field.data.u8;
        sdk_acl_field.mask.protocol = sai_acl_field.mask.u8;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_DSCP: {
        tos_info.contains_tos = true;
        tos_info.val.fields.dscp = sai_acl_field.data.u8 & 0x3f;
        tos_info.mask.fields.dscp = sai_acl_field.mask.u8 & 0x3f;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_ECN: {
        tos_info.contains_tos = true;
        tos_info.val.fields.ecn = sai_acl_field.data.u8 & 0x3;
        tos_info.mask.fields.ecn = sai_acl_field.mask.u8 & 0x3;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_TTL: {
        sdk_acl_field.val.ttl = sai_acl_field.data.u8;
        sdk_acl_field.mask.ttl = sai_acl_field.mask.u8;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_IP_FLAGS: {
        memcpy(&sdk_acl_field.val.ipv4_flags, &sai_acl_field.data.u8, sizeof(sai_uint8_t));
        memcpy(&sdk_acl_field.mask.ipv4_flags, &sai_acl_field.mask.u8, sizeof(sai_uint8_t));
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_TCP_FLAGS: {
        sdk_acl_field.val.tcp_flags.flat = sai_acl_field.data.u8;
        sdk_acl_field.mask.tcp_flags.flat = sai_acl_field.mask.u8;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMP_TYPE:
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_TYPE: {
        sdk_acl_field.val.mtype = sai_acl_field.data.u8;
        sdk_acl_field.mask.mtype = sai_acl_field.mask.u8;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMP_CODE:
    case SAI_ACL_ENTRY_ATTR_FIELD_ICMPV6_CODE: {
        sdk_acl_field.val.mcode = sai_acl_field.data.u8;
        sdk_acl_field.mask.mcode = sai_acl_field.mask.u8;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER: {
        sdk_acl_field.val.last_next_header = sai_acl_field.data.u8;
        sdk_acl_field.mask.last_next_header = sai_acl_field.mask.u8;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_IPV6_FLOW_LABEL: {
        sdk_acl_field.val.ipv6_flow_label = sai_acl_field.data.u32;
        sdk_acl_field.mask.ipv6_flow_label = sai_acl_field.mask.u32;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_FRAG: {
        memcpy(&sdk_acl_field.val.ipv6_fragment, &sai_acl_field.data.u8, sizeof(sai_uint8_t));
        memcpy(&sdk_acl_field.mask.ipv6_fragment, &sai_acl_field.mask.u8, sizeof(sai_uint8_t));
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_FDB_DST_USER_META:
    case SAI_ACL_ENTRY_ATTR_FIELD_ROUTE_DST_USER_META:
    case SAI_ACL_ENTRY_ATTR_FIELD_NEIGHBOR_DST_USER_META: {
        sdk_acl_field.val.class_id = sai_acl_field.data.u32;
        sdk_acl_field.mask.class_id = sai_acl_field.mask.u32;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_DST_MAC:
        reverse_copy(std::begin(sai_acl_field.data.mac), std::end(sai_acl_field.data.mac), std::begin(sdk_acl_field.val.da.bytes));
        reverse_copy(std::begin(sai_acl_field.mask.mac), std::end(sai_acl_field.mask.mac), std::begin(sdk_acl_field.mask.da.bytes));
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_SRC_MAC:
        reverse_copy(std::begin(sai_acl_field.data.mac), std::end(sai_acl_field.data.mac), std::begin(sdk_acl_field.val.sa.bytes));
        reverse_copy(std::begin(sai_acl_field.mask.mac), std::end(sai_acl_field.mask.mac), std::begin(sdk_acl_field.mask.sa.bytes));
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE:
        sdk_acl_field.val.ethtype = sai_acl_field.data.u16;
        sdk_acl_field.mask.ethtype = sai_acl_field.mask.u16;
        break;
    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT: {
        return get_sdk_port_field(sai_acl_field.data.oid, sdk_acl_field);
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS: {
        break;
    }
    case SAI_ACL_ENTRY_ATTR_FIELD_OUTER_VLAN_ID:
        sdk_acl_field.val.vlan1.tpid = 0;
        sdk_acl_field.val.vlan1.tci.raw = 0;
        sdk_acl_field.val.vlan1.tci.fields.vid = sai_acl_field.data.u16;
        sdk_acl_field.mask.vlan1.tpid = 0;
        sdk_acl_field.mask.vlan1.tci.raw = 0;
        sdk_acl_field.mask.vlan1.tci.fields.vid = sai_acl_field.mask.u16;
        break;
    default:
        sai_log_error(SAI_API_ACL, "ACL entry field attribute %d is not supported.", attr_id);
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    return SAI_STATUS_SUCCESS;
}

bool
sai_acl::is_acl_entry_field_udf(uint8_t profile_type, const lasai_acl_table_t& table, uint32_t attr_id)
{
    if (profile_type == SDK_ACL_PROFILE_TYPE_V4 && table.is_v4_udk) {
        // Following list of packet header fields or payload fields are treated as UDF.
        // This list of fields should be in sync with acl_udk::get_udf_description()
        switch (attr_id) {
        case SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IP:
        case SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IP:
        case SAI_ACL_ENTRY_ATTR_FIELD_INNER_IP_PROTOCOL:
        case SAI_ACL_ENTRY_ATTR_FIELD_IP_IDENTIFICATION:
        case SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_SRC_PORT:
        case SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_DST_PORT:
        case SAI_ACL_ENTRY_ATTR_FIELD_TUNNEL_VNI:
            return true;
        default:
            return false;
        }
    }

    if (profile_type == SDK_ACL_PROFILE_TYPE_V6 && table.is_v6_udk) {
        switch (attr_id) {
        case SAI_ACL_ENTRY_ATTR_FIELD_INNER_SRC_IPV6:
        case SAI_ACL_ENTRY_ATTR_FIELD_INNER_DST_IPV6:
        case SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_SRC_PORT:
        case SAI_ACL_ENTRY_ATTR_FIELD_INNER_L4_DST_PORT:
        case SAI_ACL_ENTRY_ATTR_FIELD_TTL:
            // Currently SDK does NOT support HOP_LIMIT as default ACL match field.
            // It has to be built as UDF field. Sai spec does not call out
            // HOP_LIMIT attribute.
            return true;
        default:
            return false;
        }
    }

    return false;
}

// For a SAI ACL table entry field, build equivalent SDK match field.
// A series of such SDK match fields will make up an ACL entry inserted into ACL table
// through SDK API.
sai_status_t
sai_acl::build_sdk_ace_field(const sai_attribute_t* attr,
                             uint8_t profile_type,
                             const lasai_acl_table_t& table,
                             const sai_acl_field_data_t& sai_acl_field,
                             tos_info_t& tos_info,
                             la_acl_field& sdk_acl_field)
{
    sai_status_t sstatus;

    if (is_acl_entry_field_udf(profile_type, table, attr->id)) {
        sdk_acl_field.type = la_acl_field_type_e::UDF;
        sstatus = copy_sai_ace_field_to_sdk_udf_field(attr->id, sai_acl_field, sdk_acl_field);
        sai_return_on_error(sstatus);
    } else {
        la_acl_field_type_e sdk_field_type;
        sstatus = sai_attr_to_sdk_field_type(attr->id, sdk_field_type);
        sai_return_on_error(sstatus);

        sdk_acl_field.type = sdk_field_type;
        sstatus = copy_sai_ace_field_to_sdk_field(attr->id, sai_acl_field, sdk_acl_field, tos_info);
        sai_return_on_error(sstatus);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::build_sdk_action_rule(const sai_attribute_t* attr,
                               sai_acl_action_data_t sai_acl_action,
                               lasai_acl_entry_t& acl_entry,
                               la_acl_command_actions& sdk_acl_commands)
{
    la_acl_command_action sdk_acl_command{};
    switch (attr->id) {
    case SAI_ACL_ENTRY_ATTR_ACTION_REDIRECT: {
        sai_status_t status = set_acl_entry_action_redirect(sdk_acl_command, sai_acl_action.parameter.oid);
        sai_return_on_error(status);
        acl_entry.redirect_id = sai_acl_action.parameter.oid;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION: {
        switch (sai_acl_action.parameter.u32) {
        case SAI_PACKET_ACTION_DROP: {
            sdk_acl_command.type = la_acl_action_type_e::DROP;
            sdk_acl_command.data.drop = true;
            break;
        }
        case SAI_PACKET_ACTION_FORWARD: {
            // dummy will be added only if there is no other actions.
            return SAI_STATUS_SUCCESS;
        }
        case SAI_PACKET_ACTION_TRAP: {
            sdk_acl_command.type = la_acl_action_type_e::PUNT;
            sdk_acl_command.data.punt = true;
            break;
        }
        case SAI_PACKET_ACTION_COPY: {
            // sdk_acl_command.type = la_acl_action_type_e::DO_MIRROR;
            // sdk_acl_command.data.do_mirror = la_acl_mirror_src_e::DO_MIRROR_FROM_CMD;
            // add mirror command after tc has been scanned
            return SAI_STATUS_SUCCESS;
        }
        default:
            sai_log_error(SAI_API_ACL, "ACL Entry Packet Action attribute is not supported.");
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
        break;
    }
    case SAI_ACL_ENTRY_ATTR_ACTION_COUNTER: {
        lsai_object la_counter(sai_acl_action.parameter.oid);
        auto sdev = la_counter.get_device();
        if (la_counter.type != SAI_OBJECT_TYPE_ACL_COUNTER || sdev == nullptr || sdev->m_dev == nullptr) {
            sai_log_error(SAI_API_ACL, "ACL Entry Action does not provide counter");
            return SAI_STATUS_NOT_IMPLEMENTED;
        }

        lasai_acl_counter_t counter;
        la_status status;
        status = sdev->m_acl_handler->m_acl_counter_db.get(la_counter.index, counter);
        sai_return_on_la_error(status);

        if (counter.table_id != acl_entry.table_id) {
            sai_log_error(SAI_API_ACL, "ACL Counter not available for this table");
            return SAI_STATUS_NOT_IMPLEMENTED;
        }

        sdk_acl_command.type = la_acl_action_type_e::COUNTER;
        sdk_acl_command.data.counter = counter.sdk_counter;
        acl_entry.counter_id = sai_acl_action.parameter.oid;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_POLICER: {
        lsai_object la_policer(sai_acl_action.parameter.oid);
        auto sdev = la_policer.get_device();
        if (la_policer.type != SAI_OBJECT_TYPE_POLICER || sdev == nullptr || sdev->m_dev == nullptr) {
            sai_log_error(SAI_API_ACL, "ACL Entry Action does not provide policer");
            return SAI_STATUS_INVALID_PARAMETER;
        }

        lasai_acl_meter_t* acl_meter = nullptr;
        la_status status = get_or_create_sdk_acl_meter(sdev, sai_acl_action.parameter.oid, acl_meter);
        sai_return_on_la_error(status);

        sdk_acl_command.type = la_acl_action_type_e::COUNTER_TYPE;
        sdk_acl_command.data.counter_type = la_acl_counter_type_e::OVERRIDE_METERING_PTR;
        sdk_acl_commands.push_back(sdk_acl_command);
        sdk_acl_command.type = la_acl_action_type_e::METER;
        sdk_acl_command.data.meter = acl_meter->sdk_meter;
        acl_entry.policer_id = sai_acl_action.parameter.oid;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_TC: {
        sdk_acl_command.type = la_acl_action_type_e::TRAFFIC_CLASS;
        sdk_acl_command.data.traffic_class = sai_acl_action.parameter.u8;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_ACTION_SET_DSCP: {
        sdk_acl_command.type = la_acl_action_type_e::REMARK_FWD;
        sdk_acl_command.data.remark_fwd = sai_acl_action.parameter.u8;
        break;
    }
    case SAI_ACL_ENTRY_ATTR_ACTION_INT_INSERT: {
        if (sai_acl_action.parameter.booldata == true) {
            sdk_acl_command.type = la_acl_action_type_e::INBAND_NETWORK_TELEMETRY;
            sdk_acl_command.data.inband_network_telemetry = true;
        } else {
            return SAI_STATUS_SUCCESS;
        }
        break;
    }
    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS:
    case SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_EGRESS: {
        if (sai_acl_action.parameter.objlist.count > 1) {
            sai_log_error(SAI_API_ACL, "ACL Action can support at most one mirror session.");
            return SAI_STATUS_FAILURE;
        }
        auto mirror_oid = sai_acl_action.parameter.objlist.list[0];
        lsai_object mirror_obj(mirror_oid);
        auto sdev = mirror_obj.get_device();
        sai_check_object(mirror_obj, SAI_OBJECT_TYPE_MIRROR_SESSION, sdev, "Mirror Object", mirror_oid);

        bool is_ingress = (attr->id == SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_INGRESS) ? true : false;
        sai_status_t status = build_new_acl_mirror_action_commands(mirror_oid, is_ingress, sdk_acl_commands);
        sai_return_on_error(status);
        return sdev->m_mirror_handler->set_mirror_session_used_by_ace(sdev, mirror_obj.index, is_ingress);
    }
    default:
        sai_log_error(SAI_API_ACL, "ACL Entry Action attribute is not supported.");
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    sdk_acl_commands.push_back(sdk_acl_command);
    return SAI_STATUS_SUCCESS;
}

la_status
sai_acl::get_or_create_sdk_acl_meter(const std::shared_ptr<lsai_device>& sdev,
                                     sai_object_id_t policer_oid,
                                     lasai_acl_meter_t*& acl_meter)
{
    lsai_object la_policer(policer_oid);

    auto it = sdev->m_acl_handler->m_acl_policers.find(policer_oid);
    if (it != sdev->m_acl_handler->m_acl_policers.end()) {
        acl_meter = &it->second;
        acl_meter->ref_count++;
        return LA_STATUS_SUCCESS;
    }

    lasai_policer* policer = sdev->m_policer_manager->m_policer_db.get_ptr(la_policer.index);
    if (policer == nullptr) {
        return LA_STATUS_EINVAL;
    }

    // policer->m_attach_list.insert(object_id); // acl obj id
    transaction txn;
    la_meter_profile* la_meter_prof = nullptr;
    la_meter_action_profile* la_meter_action_prof = nullptr;

    lasai_acl_meter_t new_acl_meter = {};

    policer->m_profile.m_la_type = la_meter_profile::type_e::PER_IFG;
    txn.status = sdev->m_policer_manager->create_policer_profile(policer->m_profile, la_meter_prof);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { sdev->m_policer_manager->remove_policer_profile(policer->m_profile); });

    txn.status = sdev->m_policer_manager->create_policer_action_profile(policer->m_action_profile, la_meter_action_prof);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { sdev->m_policer_manager->remove_policer_action_profile(policer->m_action_profile); });

    // create new meter
    la_meter_set* meter = nullptr;
    la_status status = sdev->m_dev->create_meter(la_meter_set::type_e::PER_IFG_EXACT, 1, meter);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { sdev->m_dev->destroy(meter); });

    txn.status = meter->set_committed_bucket_coupling_mode(0, la_meter_set::coupling_mode_e::TO_EXCESS_BUCKET);
    la_return_on_error(txn.status);

    txn.status = meter->set_meter_profile(0, la_meter_prof);
    la_return_on_error(txn.status);

    txn.status = meter->set_meter_action_profile(0, la_meter_action_prof);
    la_return_on_error(txn.status);

    for (la_slice_id_t slice_id = 0; slice_id < sdev->m_dev_params.slices_per_dev; slice_id++) {
        for (la_ifg_id_t ifg = 0; ifg < sdev->m_dev_params.ifgs_per_slice; ifg++) {
            la_slice_ifg slice_ifg{slice_id, ifg};
            status = meter->set_cir(0, slice_ifg, policer->m_cir);
            la_return_on_error(status);

            status = meter->set_eir(0, slice_ifg, policer->m_pir);
            la_return_on_error(status);
        }
    }

    new_acl_meter.policer_id = policer_oid;
    new_acl_meter.sdk_meter = meter;
    new_acl_meter.ref_count = 1;

    sdev->m_acl_handler->m_acl_policers.emplace(policer_oid, new_acl_meter);

    it = sdev->m_acl_handler->m_acl_policers.find(policer_oid);
    if (it != sdev->m_acl_handler->m_acl_policers.end()) {
        acl_meter = &it->second;
    }

    return LA_STATUS_SUCCESS;
}

la_status
sai_acl::remove_sdk_acl_meter(const std::shared_ptr<lsai_device>& sdev, sai_object_id_t policer_oid)
{
    lsai_object la_policer(policer_oid);

    auto it = sdev->m_acl_handler->m_acl_policers.find(policer_oid);
    if (it == sdev->m_acl_handler->m_acl_policers.end()) {
        return LA_STATUS_SUCCESS;
    }

    lasai_acl_meter_t* acl_meter = &it->second;
    if (acl_meter->ref_count > 1) {
        acl_meter->ref_count--;
        return LA_STATUS_SUCCESS;
    }

    auto policer = sdev->m_policer_manager->m_policer_db.get_ptr(la_policer.index);
    transaction txn;

    if (policer != nullptr) {
        policer->m_profile.m_la_type = la_meter_profile::type_e::PER_IFG;
        la_status status = sdev->m_policer_manager->remove_policer_profile(policer->m_profile);
        if (status != LA_STATUS_SUCCESS) {
            sai_log_warn(SAI_API_ACL, "Failed to remvove policer profile %s", status.message().c_str());
        }
        status = sdev->m_policer_manager->remove_policer_action_profile(policer->m_action_profile);
        if (status != LA_STATUS_SUCCESS) {
            sai_log_warn(SAI_API_ACL, "Failed to remvove policer action profile %s", status.message().c_str());
        }
    }

    // remove meter
    if (acl_meter->sdk_meter != nullptr) {
        la_status status = sdev->m_dev->destroy(acl_meter->sdk_meter);
        if (status != LA_STATUS_SUCCESS) {
            sai_log_warn(SAI_API_ACL, "Failed to remvove acl meter %s", status.message().c_str());
        }
    }
    sdev->m_acl_handler->m_acl_policers.erase(policer_oid);

    return LA_STATUS_SUCCESS;
}

// Using sai acl match table fields, create sdk acl table key.
sai_status_t
sai_acl::create_sdk_acl_key(const std::vector<const sai_attribute_t*>& ace_field_attrs,
                            uint8_t profile_type,
                            const lasai_acl_table_t& table,
                            lasai_acl_entry_t& acl_entry,
                            la_acl_key& sdk_acl_key)
{
    tos_info_t tos_info;
    tos_info.val.flat = 0;
    tos_info.mask.flat = 0; // init mask to don't care.
    for (auto attr : ace_field_attrs) {
        if (attr->id >= SAI_ACL_ENTRY_ATTR_FIELD_START && attr->id <= SAI_ACL_ENTRY_ATTR_FIELD_END) {
            if (attr->id == SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS) {
                // IN_PORTS will be handled later
                continue;
            }
            if (!table.match_field[attr->id - SAI_ACL_ENTRY_ATTR_FIELD_START]) {
                if (attr->id == SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORT || attr->id == SAI_ACL_ENTRY_ATTR_FIELD_OUT_PORTS) {
                    // TODO: Remove this check after ACL functionality expectation is adjusted both in NOS test cases and our
                    // support for customer. Until then, make progress by ignoring OUT port usage in ACE match vector.
                    continue;
                }
                sai_log_error(SAI_API_ACL, "Key error, table does not support attribute with id %u", attr->id);
                return SAI_STATUS_NOT_IMPLEMENTED;
            }

            la_acl_field sdk_acl_field;
            sai_acl_field_data_t sai_acl_field = attr->value.aclfield;
            if (attr->id == SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE) {
                switch (sai_acl_field.data.s32) {
                case SAI_ACL_IP_TYPE_ANY:
                case SAI_ACL_IP_TYPE_IP:
                case SAI_ACL_IP_TYPE_IPV4ANY:
                case SAI_ACL_IP_TYPE_IPV6ANY:
                    // store ip_type in shadow ace to facilitate get SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE
                    acl_entry.ip_type = sai_acl_field.data.s32;
                    acl_entry.ip_type_mask = sai_acl_field.mask.s32;
                    // For now do not program ip-type in ACE.
                    // Data path pipeline currently handles V4 and V6 lookups as seperate tables.
                    continue;
                    break;
                default:
                    // unsupported IP types.
                    sai_log_error(SAI_API_ACL, "ACL does not support IP type %d", sai_acl_field.data.s32);
                    return SAI_STATUS_NOT_IMPLEMENTED;
                    break;
                }
            }

            sai_status_t sstatus = build_sdk_ace_field(attr, profile_type, table, sai_acl_field, tos_info, sdk_acl_field);
            sai_return_on_error(sstatus);
            // TOS fields are handled separately after the for loop.
            if (sdk_acl_field.type == la_acl_field_type_e::TOS) {
                continue;
            }

            sdk_acl_key.push_back(sdk_acl_field);
        }
    }
    // If there were DSCP/ECN attributes, insert them to key.
    if (tos_info.contains_tos) {
        la_acl_field sdk_acl_field;
        sdk_acl_field.type = la_acl_field_type_e::TOS;
        sdk_acl_field.val.tos.flat = tos_info.val.flat;
        sdk_acl_field.mask.tos.flat = tos_info.mask.flat;
        sdk_acl_key.push_back(sdk_acl_field);
    }
    return SAI_STATUS_SUCCESS;
}

// Find insertion position in hw table for the ace with ace_priority.
sai_status_t
sai_acl::find_ace_position(const lasai_acl_table_t& table, uint32_t& ace_position, uint32_t ace_priority)
{
    auto iter = table.entry_list.cbegin();
    for (; iter != table.entry_list.cend(); iter++) {
        lsai_object ace_obj(*iter);
        auto sdev = ace_obj.get_device();

        if (ace_obj.type != SAI_OBJECT_TYPE_ACL_ENTRY || sdev == nullptr || sdev->m_dev == nullptr) {
            sai_log_error(SAI_API_ACL, "ACL Table Entry with id %lu has configuration.", *iter);
            return SAI_STATUS_FAILURE;
        }

        lasai_acl_entry_t entry{};
        la_status status = sdev->m_acl_handler->m_acl_entry_db.get(ace_obj.index, entry);
        sai_return_on_la_error(status);

        // Higher priority ACEs should be lower position in HW table.
        if (entry.priority <= ace_priority) {
            break;
        }
    }

    ace_position = std::distance(table.entry_list.cbegin(), iter);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::build_sdk_ace_range_field(const sai_acl_range_type_t type,
                                   const uint16_t val,
                                   const uint16_t mask,
                                   la_acl_field& sdk_acl_field)
{
    switch (type) {
    case SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE:
        sdk_acl_field.type = la_acl_field_type_e::SPORT;
        sdk_acl_field.val.sport = val;
        sdk_acl_field.mask.sport = mask;
        break;
    case SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE:
        sdk_acl_field.type = la_acl_field_type_e::DPORT;
        sdk_acl_field.val.dport = val;
        sdk_acl_field.mask.dport = mask;
        break;
    default:
        sai_log_error(SAI_API_ACL, "Unsupported range type (%d)", type);
        sai_return_on_error(SAI_STATUS_NOT_IMPLEMENTED);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::insert_ace_with_range_expansion(lasai_acl_table_t& table,
                                         lasai_acl_entry_t& entry,
                                         la_acl* sdk_acl,
                                         uint32_t position,
                                         std::vector<std::vector<la_acl_field>>& key_set,
                                         const la_acl_command_actions& cmd,
                                         transaction& txn)
{
    sai_status_t sstatus;
    std::shared_ptr<lsai_device> sdev;
    uint32_t map_id;

    for (auto range_id : entry.range_list) {
        sstatus = check_and_get_device_and_map_index(range_id, SAI_OBJECT_TYPE_ACL_RANGE, sdev, map_id);
        sai_return_on_error(sstatus);

        lasai_acl_range_t* range = sdev->m_acl_handler->m_acl_range_db.get_ptr(map_id);
        if (range == nullptr) {
            return SAI_STATUS_ITEM_NOT_FOUND;
        }

        if (find(table.match_range.begin(), table.match_range.end(), range->type) == table.match_range.end()) {
            sai_log_error(SAI_API_ACL, "Key error, table does not support range type %u", range->type);
            return SAI_STATUS_FAILURE;
        }

        std::vector<la_acl_field> field_set;
        for (auto val_mask : range->expansion) {
            la_acl_field field;
            sstatus = build_sdk_ace_range_field(range->type, val_mask.first, val_mask.second, field);
            sai_return_on_error(sstatus);

            field_set.push_back(field);
        }

        cartesion_product_append(key_set, field_set);
        range->ref_count++;
        txn.on_fail([=]() { range->ref_count--; });
    }

    if (table.table_size - table.entry_list.size() < key_set.size()) {
        sai_log_error(SAI_API_ACL, "ACL Table 0x%lx does not have space for %u entries.", table.table_id, key_set.size());
        txn.status = LA_STATUS_ERESOURCE;
        sai_return_on_error(SAI_STATUS_TABLE_FULL);
    }

    for (auto key : key_set) {
        txn.status = sdk_acl->insert(position, key, cmd);
        sai_return_on_la_error(txn.status);
        txn.on_fail([=]() { sdk_acl->erase(position); });
    }
    entry.sdk_entries = key_set.size();

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::create_acl_key_list_with_in_ports(lasai_acl_entry_t& entry, std::vector<std::vector<la_acl_field>>& key_set)
{
    sai_status_t sstatus;

    std::vector<la_acl_field> field_set;
    for (auto port_id : entry.port_list) {
        la_acl_field field;
        field.type = la_acl_field_type_e::SOURCE_SYSTEM_PORT;
        sstatus = get_sdk_port_field(port_id, field);
        sai_return_on_error(sstatus);

        field_set.push_back(field);
    }
    cartesion_product_append(key_set, field_set);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::create_acl_entry(_Out_ sai_object_id_t* acl_entry_id,
                          _In_ sai_object_id_t switch_id,
                          _In_ uint32_t attr_count,
                          _In_ const sai_attribute_t* attr_list)
{
    la_status status;
    sai_status_t sstatus;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_SWITCH, switch_id, &acl_entry_to_string, "attrs", attrs);

    sai_object_id_t acl_table_id;
    get_attrs_value(SAI_ACL_ENTRY_ATTR_TABLE_ID, attrs, acl_table_id, true);
    lasai_acl_table_t table;
    status = sdev->m_acl_handler->m_acl_table_db.get(acl_table_id, table);
    sai_return_on_la_error(status);

    if (table.table_size <= table.entry_list.size()) {
        sai_log_error(SAI_API_ACL, "ACL Table %lu is already full.", acl_table_id);
        return SAI_STATUS_TABLE_FULL;
    }

    lasai_acl_entry_t acl_entry;
    acl_entry.table_id = acl_table_id;
    std::vector<const sai_attribute_t*> sai_acl_key_attr{};
    std::vector<const sai_attribute_t*> sai_v4_acl_key_attr{};
    std::vector<const sai_attribute_t*> sai_v6_acl_key_attr{};
    uint8_t user_meta_field_count = 0;
    bool contains_v4_header_field = false;
    bool contains_v6_header_field = false;
    uint16_t ethertype = 0;
    for (uint32_t attr_index = 0; attr_index < attr_count; ++attr_index) {
        const sai_attribute_t* attr = &attr_list[attr_index];
        if (attr->id >= SAI_ACL_ENTRY_ATTR_FIELD_START && attr->id <= SAI_ACL_ENTRY_ATTR_FIELD_END) {
            sai_acl_field_data_t sai_acl_field = attr->value.aclfield;
            if (!sai_acl_field.enable) {
                // Skip it, if not enabled.
                continue;
            }

            if (attr->id == SAI_ACL_ENTRY_ATTR_FIELD_ROUTE_DST_USER_META) {
                ++user_meta_field_count;
            }

            if (attr->id == SAI_ACL_ENTRY_ATTR_FIELD_NEIGHBOR_DST_USER_META) {
                ++user_meta_field_count;
            }

            if (attr->id == SAI_ACL_ENTRY_ATTR_FIELD_FDB_DST_USER_META) {
                ++user_meta_field_count;
            }

            if (user_meta_field_count > 1) {
                // ACL entry cannot have more than 1 dst_user_meta values.
                sai_log_error(SAI_API_ACL,
                              "Key error, table entry can have atmost one of the three destination user meta field%u, %u",
                              SAI_ACL_ENTRY_ATTR_FIELD_FDB_DST_USER_META,
                              SAI_ACL_ENTRY_ATTR_FIELD_ROUTE_DST_USER_META,
                              SAI_ACL_ENTRY_ATTR_FIELD_NEIGHBOR_DST_USER_META);
                return SAI_STATUS_FAILURE;
            }

            if (attr->id == SAI_ACL_ENTRY_ATTR_FIELD_ACL_RANGE_TYPE) {
                if (!table.match_field[attr->id - SAI_ACL_ENTRY_ATTR_FIELD_START]) {
                    sai_log_error(SAI_API_ACL, "Key error, table does not support range fields");
                    return SAI_STATUS_FAILURE;
                }

                const sai_object_list_t* range_list = &(attr->value.aclfield.data.objlist);
                for (uint32_t i = 0; i < range_list->count; i++) {
                    acl_entry.range_list.push_back(range_list->list[i]);
                }
                continue;
            }

            if (attr->id == SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS) {
                if (!table.match_field[attr->id - SAI_ACL_ENTRY_ATTR_FIELD_START]) {
                    sai_log_error(SAI_API_ACL, "Key error, table does not support IN_PORTS fields");
                    return SAI_STATUS_FAILURE;
                }

                const sai_object_list_t* port_list = &(attr->value.aclfield.data.objlist);
                for (uint32_t i = 0; i < port_list->count; i++) {
                    acl_entry.port_list.push_back(port_list->list[i]);
                }
                continue;
            }

            // If the table is egress with ethertype, we need to validate correct value for IP protocol.
            // But do not put the field in the ACE rule as SDK will error as not supported.
            // NPL is already hardwired to take IPV4 for 0x0800 anbd IPv6 for 0x86DD.
            if ((attr->id == SAI_ACL_ENTRY_ATTR_FIELD_ETHER_TYPE) && (table.stage == SAI_ACL_STAGE_EGRESS)) {
                if (sai_acl_field.mask.u16 != 0xffff) {
                    sai_log_error(SAI_API_ACL, "Key error, Egress Ethertype mask(0x%04x must be 0xffff", sai_acl_field.mask.u16);
                    return SAI_STATUS_FAILURE;
                }
                // Keep and check later after we know IPv4 or IPv6, not both
                ethertype = sai_acl_field.data.u16;
                continue;
            }

            if (table.is_v4_acl != table.is_v6_acl) {
                // either v4 or v6 acl
                sai_acl_key_attr.push_back(attr);
            } else {
                // combined v4, v6 acl
                if (is_v4_ace_field(attr->id)) {
                    sai_v4_acl_key_attr.push_back(attr);
                    contains_v4_header_field = true;
                } else if (is_v6_ace_field(attr->id)) {
                    if (attr->id == SAI_ACL_TABLE_ATTR_FIELD_TTL && !table.is_v6_udk) {
                        // !!! HACK !!!
                        // In case of non UDK, V6 ACL cannot match on TTL.
                        // Until NOS cuts over to use UDK (if TTL is intended to be in ACL)
                        // allow ACE creation without TTL. This will allow test cases
                        // that do not use TTL to pass.
                        continue;
                    }
                    contains_v6_header_field = true;
                    sai_v6_acl_key_attr.push_back(attr);
                } else {
                    sai_v4_acl_key_attr.push_back(attr);
                    if (attr->id == SAI_ACL_TABLE_ATTR_FIELD_TTL && !table.is_v6_udk) {
                        // !!! HACK !!!
                        // In case of non UDK, V6 ACL cannot match on TTL.
                        // Until NOS cuts over to use UDK (if TTL is intended to be in ACL)
                        // allow ACE creation without TTL. This will allow test cases
                        // that do not use TTL to pass.
                        continue;
                    }
                    sai_v6_acl_key_attr.push_back(attr);
                }
            }
        }
    }

    la_acl_key sdk_acl_key = {};
    la_acl_key sdk_v4_acl_key = {};
    la_acl_key sdk_v6_acl_key = {};
    if (table.is_v4_acl != table.is_v6_acl) {
        // If egress ethertype field is set, confirm value is correct for the protocol.
        if (ethertype != 0) {
            if (table.is_v4_acl) {
                if (ethertype != 0x0800) {
                    sai_log_error(SAI_API_ACL, "Key error, Egress Ethertype value(0x%04x) invalid for IPv4", ethertype);
                    return SAI_STATUS_FAILURE;
                }
            } else {
                if (ethertype != 0x86DD) {
                    sai_log_error(SAI_API_ACL, "Key error, Egress Ethertype value(0x%04x) invalid for IPv6", ethertype);
                    return SAI_STATUS_FAILURE;
                }
            }
        }
        sstatus = create_sdk_acl_key(
            sai_acl_key_attr, table.is_v4_acl ? SDK_ACL_PROFILE_TYPE_V4 : SDK_ACL_PROFILE_TYPE_V6, table, acl_entry, sdk_acl_key);
        sai_return_on_error(sstatus);
    } else {
        // If egress ethertype field is set, no value works for both IPv4 and IPv6 so fail.
        if (ethertype != 0) {
            sai_log_error(SAI_API_ACL, "Key error, Egress Ethertype value(0x%04x) not valid for IPv4 and IPv6", ethertype);
            return SAI_STATUS_FAILURE;
        }
        sstatus = create_sdk_acl_key(sai_v4_acl_key_attr, SDK_ACL_PROFILE_TYPE_V4, table, acl_entry, sdk_v4_acl_key);
        sai_return_on_error(sstatus);
        sstatus = create_sdk_acl_key(sai_v6_acl_key_attr, SDK_ACL_PROFILE_TYPE_V6, table, acl_entry, sdk_v6_acl_key);
        sai_return_on_error(sstatus);
    }

    uint32_t priority = 0; // Default value.
    bool admin_state = true;
    la_acl_command_actions sdk_acl_command_actions{};
    bool acl_action_set_tc = false;
    bool acl_action_set_color = false;
    uint8_t acl_action_tc_value = 0;
    bool acl_action_set_copy = false;
    bool acl_in_ports = false;
    bool acl_in_port = false;
    for (uint32_t attr_index = 0; attr_index < attr_count; ++attr_index) {
        const sai_attribute_t* attr = &attr_list[attr_index];
        if (attr->id == SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS) {
            if (acl_in_port) {
                sai_log_error(SAI_API_ACL,
                              "SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS and SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT should not co-exists");
                return SAI_STATUS_INVALID_PARAMETER;
            }
            acl_in_ports = true;
        }
        if (attr->id == SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT) {
            if (acl_in_ports) {
                sai_log_error(SAI_API_ACL,
                              "SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS and SAI_ACL_ENTRY_ATTR_FIELD_IN_PORT should not co-exists");
                return SAI_STATUS_INVALID_PARAMETER;
            }
            acl_in_port = true;
        }
        if (attr->id >= SAI_ACL_ENTRY_ATTR_FIELD_START && attr->id <= SAI_ACL_ENTRY_ATTR_FIELD_END) {
            continue;
        } else if (attr->id >= SAI_ACL_ENTRY_ATTR_ACTION_START && attr->id <= SAI_ACL_ENTRY_ATTR_ACTION_END) {
            sai_acl_action_data_t sai_acl_action = attr->value.aclaction;
            if (!sai_acl_action.enable) {
                // Skip it, if not enabled.
                continue;
            }
            la_acl_command_actions acl_command_actions{};
            sstatus = build_sdk_action_rule(attr, sai_acl_action, acl_entry, acl_command_actions);
            sai_return_on_error_log(sstatus, "Could not build sdk ACL action for %d", attr->id);

            for (auto& sdk_acl_command_action : acl_command_actions) {
                auto iter = sai_acl::find_sdk_acl_action_command(sdk_acl_command_actions, sdk_acl_command_action.type);
                if (iter != sdk_acl_command_actions.end()) {
                    sai_log_error(SAI_API_ACL, "Duplicate ACL Action specified. Acl action attribute id is", attr->id);
                    return SAI_STATUS_FAILURE;
                }
                sdk_acl_command_actions.push_back(sdk_acl_command_action);
            }

            if (attr->id == SAI_ACL_ENTRY_ATTR_ACTION_SET_TC) {
                acl_action_set_tc = true;
                if (sai_acl_action.parameter.u8 < lsai_device::SAI_NUMBER_OF_CPU_QUEUES) {
                    acl_action_tc_value = sai_acl_action.parameter.u8;
                }
            }
            if (attr->id == SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION && sai_acl_action.parameter.u32 == SAI_PACKET_ACTION_COPY) {
                acl_action_set_copy = true;
            }
            if (attr->id == SAI_ACL_ENTRY_ATTR_ACTION_SET_PACKET_COLOR) {
                acl_action_set_color = true;
            }
        } else if (attr->id == SAI_ACL_ENTRY_ATTR_TABLE_ID) {
            // Already covered above.
            continue;
        } else if (attr->id == SAI_ACL_ENTRY_ATTR_PRIORITY) {
            priority = attr->value.u32;
        } else if (attr->id == SAI_ACL_ENTRY_ATTR_ADMIN_STATE) {
            admin_state = attr->value.booldata;
        } else {
            sai_log_error(SAI_API_ACL, "ACL Entry attribute is not supported.");
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
    }

    if (acl_action_set_copy) {
        la_l2_mirror_command* mirror_cmd = sdev->m_acl_mirror_cmds[acl_action_tc_value];
        la_acl_command_action sdk_acl_command_action_mirror_cmd{};
        sdk_acl_command_action_mirror_cmd.type = la_acl_action_type_e::MIRROR_CMD;
        sdk_acl_command_action_mirror_cmd.data.mirror_cmd = mirror_cmd;

        la_acl_command_action sdk_acl_command_action_do_mirror{};
        sdk_acl_command_action_do_mirror.type = la_acl_action_type_e::DO_MIRROR;
        sdk_acl_command_action_do_mirror.data.do_mirror = la_acl_mirror_src_e::DO_MIRROR_FROM_CMD;

        sdk_acl_command_actions.push_back(sdk_acl_command_action_mirror_cmd);
        sdk_acl_command_actions.push_back(sdk_acl_command_action_do_mirror);
    }

    if (acl_action_set_tc || acl_action_set_color) {
        // SDK expects when acl actions is TC, then color also has to be set.
        if (!acl_action_set_color) {
            la_acl_command_action sdk_acl_command_action{};
            sdk_acl_command_action.data.color = la_qos_color_e::NONE;
            sdk_acl_command_action.type = la_acl_action_type_e::COLOR;
            sdk_acl_command_actions.push_back(sdk_acl_command_action);
        }
    }

    // Calculate position that is used in SDK.
    uint32_t ace_position;
    sstatus = find_ace_position(table, ace_position, priority);

    // Begin transactional SDK modifications
    transaction txn;

    // Insert ACE in hw table.
    if (table.is_v4_acl != table.is_v6_acl) {
        std::vector<std::vector<la_acl_field>> sdk_acl_key_set = {sdk_acl_key};
        if (acl_in_ports) {
            sstatus = create_acl_key_list_with_in_ports(acl_entry, sdk_acl_key_set);
            sai_return_on_error(sstatus);
        }

        // Either v4 or v6 acl
        if (table.is_v4_acl) {
            sstatus = insert_ace_with_range_expansion(
                table, acl_entry, table.v4_sdk_acl, ace_position, sdk_acl_key_set, sdk_acl_command_actions, txn);
        } else {
            sstatus = insert_ace_with_range_expansion(
                table, acl_entry, table.v6_sdk_acl, ace_position, sdk_acl_key_set, sdk_acl_command_actions, txn);
        }
        sai_return_on_error(sstatus);
    } else {
        // combined v4, v6 ace, install ace in both sdk's v4 and v6 table.
        //      - When v4_acl_key and v6_acl_key both contain atleast one L3 header field
        //        or both do not contain any L3 header field, install into both SDK tables.
        //      - If v4_acl_key contains V4 field from L3 header
        //          - install acl-key and action into v4_sdk table.
        //          - install NOP (match none) and ACL action None in v6-sdk table
        //            (This is done so that when ACL entry is removed, an entry
        //             can be removed from both SDK tables)
        //      - If v6_acl_key contains V6 field from L3 header
        //          - install acl-key and action into v6_sdk table.
        //          - install NOP (match none) and ACL action None in v4-sdk table
        std::vector<std::vector<la_acl_field>> sdk_v4_acl_key_set = {sdk_v4_acl_key};
        std::vector<std::vector<la_acl_field>> sdk_v6_acl_key_set = {sdk_v6_acl_key};
        if (acl_in_ports) {
            sstatus = create_acl_key_list_with_in_ports(acl_entry, sdk_v4_acl_key_set);
            sai_return_on_error(sstatus);
            sstatus = create_acl_key_list_with_in_ports(acl_entry, sdk_v6_acl_key_set);
            sai_return_on_error(sstatus);
        }

        if (contains_v4_header_field == contains_v6_header_field) {
            // Either both keys contain L3 header fields or both keys do NOT contain L3 header fields
            sstatus = insert_ace_with_range_expansion(
                table, acl_entry, table.v4_sdk_acl, ace_position, sdk_v4_acl_key_set, sdk_acl_command_actions, txn);
            sai_return_on_error(sstatus);
            sstatus = insert_ace_with_range_expansion(
                table, acl_entry, table.v6_sdk_acl, ace_position, sdk_v6_acl_key_set, sdk_acl_command_actions, txn);
            sai_return_on_error(sstatus);
        } else if (contains_v4_header_field) {
            sstatus = insert_ace_with_range_expansion(
                table, acl_entry, table.v4_sdk_acl, ace_position, sdk_v4_acl_key_set, sdk_acl_command_actions, txn);
            sai_return_on_error(sstatus);
            la_acl_command_actions sdk_acl_nop_command_action{};
            sstatus = insert_ace_with_range_expansion(
                table, acl_entry, table.v6_sdk_acl, ace_position, sdk_v6_acl_key_set, sdk_acl_nop_command_action, txn);
            sai_return_on_error(sstatus);
        } else if (contains_v6_header_field) {
            sstatus = insert_ace_with_range_expansion(
                table, acl_entry, table.v6_sdk_acl, ace_position, sdk_v6_acl_key_set, sdk_acl_command_actions, txn);
            sai_return_on_error(sstatus);
            la_acl_command_actions sdk_acl_nop_command_action{};
            sstatus = insert_ace_with_range_expansion(
                table, acl_entry, table.v4_sdk_acl, ace_position, sdk_v4_acl_key_set, sdk_acl_nop_command_action, txn);
            sai_return_on_error(sstatus);
        }
    }

    // Update sai acl entry
    uint32_t entry_map_id;
    txn.status = sdev->m_acl_handler->m_acl_entry_db.allocate_id(entry_map_id);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_acl_handler->m_acl_entry_db.release_id(entry_map_id); });

    acl_entry.priority = priority;
    acl_entry.admin_state = admin_state;

    lsai_object la_ace(SAI_OBJECT_TYPE_ACL_ENTRY, la_obj.switch_id, entry_map_id);
    *acl_entry_id = la_ace.object_id();
    acl_entry.entry_id = la_ace.object_id();

    txn.status = sdev->m_acl_handler->m_acl_entry_db.set(entry_map_id, acl_entry);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_acl_handler->m_acl_entry_db.erase_id(entry_map_id); });

    // Update sai acl table to recognize new ace
    for (uint32_t i = 0; i < acl_entry.sdk_entries; i++) {
        table.entry_list.insert(table.entry_list.cbegin() + ace_position, *acl_entry_id);
    }
    txn.status = sdev->m_acl_handler->m_acl_table_db.set(acl_table_id, table);
    sai_return_on_la_error(txn.status);

    sai_log_info(SAI_API_ACL, "acl entry id 0x%lx created", *acl_entry_id);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::remove_acl_entry(_In_ sai_object_id_t acl_entry_id)
{
    la_status status;

    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_ACL_ENTRY, acl_entry_id, &acl_entry_to_string, acl_entry_id);

    lasai_acl_entry_t entry;
    uint32_t map_id = la_obj.index;
    status = sdev->m_acl_handler->m_acl_entry_db.get(map_id, entry);
    sai_return_on_la_error_log(status, "Failed to remove ACL Entry with id %lu, no such table.", acl_entry_id);

    lsai_object la_acl_table(entry.table_id);

    uint32_t table_map_id = la_acl_table.index;
    lasai_acl_table_t* table = sdev->m_acl_handler->m_acl_table_db.get_ptr(table_map_id);
    if (table == nullptr) {
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    auto iter = std::find(table->entry_list.begin(), table->entry_list.end(), acl_entry_id);

    if (iter == table->entry_list.end()) {
        sai_log_error(SAI_API_ACL, "Failed to remove ACL Entry with id %lu, it's not in the table", acl_entry_id);
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    uint32_t position = std::distance(table->entry_list.begin(), iter);
    for (size_t i = 0; i < entry.sdk_entries; i++) {
        table->entry_list.erase(iter);

        if (table->is_v4_acl) {
            acl_entry_desc sdk_entry_desc;
            status = table->v4_sdk_acl->get(position, sdk_entry_desc);
            // If ACL table attached on ingress port, remove ingress acl mirror object
            clear_acl_entry_action_mirror(sdev, entry.table_id, sdk_entry_desc, true /*is_ingress*/);
            // If ACL table attached on egress port, remove egress acl mirror object
            clear_acl_entry_action_mirror(sdev, entry.table_id, sdk_entry_desc, false /*is_ingress*/);
            status = table->v4_sdk_acl->erase(position);
            sai_return_on_la_error(status);
        }

        if (table->is_v6_acl) {
            acl_entry_desc sdk_entry_desc;
            status = table->v6_sdk_acl->get(position, sdk_entry_desc);
            // If ACL table attached on ingress port, remove ingress acl mirror object
            clear_acl_entry_action_mirror(sdev, entry.table_id, sdk_entry_desc, true /*is_ingress*/);
            // If ACL table attached on egress port, remove egress acl mirror object
            clear_acl_entry_action_mirror(sdev, entry.table_id, sdk_entry_desc, false /*is_ingress*/);
            status = table->v6_sdk_acl->erase(position);
            sai_return_on_la_error(status);
        }
    }

    for (auto range_id : entry.range_list) {
        lsai_object la_acl_range(range_id);
        uint32_t range_map_id = la_acl_range.index;
        lasai_acl_range_t* range = sdev->m_acl_handler->m_acl_range_db.get_ptr(range_map_id);
        if (range == nullptr) {
            return SAI_STATUS_ITEM_NOT_FOUND;
        }

        if (table->is_v4_acl) {
            range->ref_count--;
        }
        if (table->is_v6_acl) {
            range->ref_count--;
        }
    }

    status = sdev->m_acl_handler->m_acl_entry_db.remove(map_id);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::set_acl_entry_attribute(_In_ sai_object_id_t acl_entry_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = acl_entry_id;

    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_ACL_ENTRY, acl_entry_id, &acl_entry_to_string, acl_entry_id, "attrs", *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "acl_entry 0x%lx", acl_entry_id);
    return sai_set_attribute(&key, key_str, acl_entry_attribs, acl_entry_vendor_attribs, attr);
}

sai_status_t
sai_acl::get_acl_entry_attribute(_In_ sai_object_id_t acl_entry_id, _In_ uint32_t attr_count, _Out_ sai_attribute_t* attr_list)
{
    sai_object_key_t key = {};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = acl_entry_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_ACL_ENTRY, acl_entry_id, &acl_entry_to_string, acl_entry_id, "attrs", attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "acl_entry 0x%lx", acl_entry_id);
    return sai_get_attributes(&key, key_str, acl_entry_attribs, acl_entry_vendor_attribs, attr_count, attr_list);
}

std::string
sai_acl::acl_counter_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_acl_counter_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << "\n";

    return log_message.str();
}

sai_status_t
sai_acl::create_acl_counter(_Out_ sai_object_id_t* acl_counter_id,
                            _In_ sai_object_id_t switch_id,
                            _In_ uint32_t attr_count,
                            _In_ const sai_attribute_t* attr_list)
{
    la_status status;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_SWITCH, switch_id, &acl_counter_to_string, "attrs", attrs);

    sai_object_id_t acl_table_id;
    get_attrs_value(SAI_ACL_COUNTER_ATTR_TABLE_ID, attrs, acl_table_id, true);

    lasai_acl_table_t* table = sdev->m_acl_handler->m_acl_table_db.get_ptr(acl_table_id);
    if (table == nullptr) {
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    lasai_acl_counter_t counter;
    counter.table_id = acl_table_id;

    get_attrs_value(SAI_ACL_COUNTER_ATTR_ENABLE_PACKET_COUNT, attrs, counter.packet_count, false);
    get_attrs_value(SAI_ACL_COUNTER_ATTR_ENABLE_BYTE_COUNT, attrs, counter.byte_count, false);

    transaction txn;
    status = sdev->m_dev->create_counter(1, counter.sdk_counter);
    sai_return_on_la_error(status);
    txn.on_fail([=]() { sdev->m_dev->destroy(counter.sdk_counter); });

    uint32_t counter_map_id;
    txn.status = sdev->m_acl_handler->m_acl_counter_db.allocate_id(counter_map_id);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_acl_handler->m_acl_counter_db.release_id(counter_map_id); });

    lsai_object la_counter(SAI_OBJECT_TYPE_ACL_COUNTER, la_obj.switch_id, counter_map_id);
    *acl_counter_id = la_counter.object_id();
    counter.counter_id = la_counter.object_id();

    txn.status = sdev->m_acl_handler->m_acl_counter_db.set(counter_map_id, counter);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_acl_handler->m_acl_counter_db.erase_id(counter_map_id); });

    table->counters.insert(*acl_counter_id);

    sai_log_info(SAI_API_ACL, "acl counter id 0x%lx created", *acl_counter_id);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::remove_acl_counter(_In_ sai_object_id_t acl_counter_id)
{
    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_ACL_COUNTER, acl_counter_id, &acl_counter_to_string, acl_counter_id);

    lasai_acl_counter_t counter;
    uint32_t map_id = la_obj.index;

    la_status status;

    status = sdev->m_acl_handler->m_acl_counter_db.get(map_id, counter);
    sai_return_on_la_error(status);

    lasai_acl_table_t* table = sdev->m_acl_handler->m_acl_table_db.get_ptr(counter.table_id);
    if (table == nullptr) {
        return SAI_STATUS_FAILURE;
    }

    status = sdev->m_dev->destroy(counter.sdk_counter);
    sai_return_on_la_error(status);

    status = sdev->m_acl_handler->m_acl_counter_db.remove(map_id);
    sai_return_on_la_error(status);

    table->counters.erase(acl_counter_id);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::set_acl_counter_attribute(_In_ sai_object_id_t acl_counter_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
sai_acl::get_acl_counter_attribute(_In_ sai_object_id_t acl_counter_id, _In_ uint32_t attr_count, _Out_ sai_attribute_t* attr_list)
{
    sai_object_key_t key = {};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = acl_counter_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_ACL_COUNTER, acl_counter_id, &acl_counter_to_string, acl_counter_id, "attrs", attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "acl counter 0x%lx", acl_counter_id);
    return sai_get_attributes(&key, key_str, acl_counter_attribs, acl_counter_vendor_attribs, attr_count, attr_list);
}

std::string
sai_acl::acl_range_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_acl_range_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << "\n";

    return log_message.str();
}

sai_status_t
sai_acl::create_acl_range(_Out_ sai_object_id_t* acl_range_id,
                          _In_ sai_object_id_t switch_id,
                          _In_ uint32_t attr_count,
                          _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_SWITCH, switch_id, &acl_range_to_string, "attrs", attrs);

    lasai_acl_range_t range;
    get_attrs_value(SAI_ACL_RANGE_ATTR_TYPE, attrs, range.type, true);
    get_attrs_value(SAI_ACL_RANGE_ATTR_LIMIT, attrs, range.limit, true);

    sai_status_t sstatus;
    sstatus = expand_acl_range(range);
    sai_return_on_error(sstatus);

    transaction txn;
    uint32_t range_map_id;
    txn.status = sdev->m_acl_handler->m_acl_range_db.allocate_id(range_map_id);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_acl_handler->m_acl_range_db.release_id(range_map_id); });

    lsai_object la_range(SAI_OBJECT_TYPE_ACL_RANGE, la_obj.switch_id, range_map_id);
    *acl_range_id = la_range.object_id();
    range.range_id = la_range.object_id();

    txn.status = sdev->m_acl_handler->m_acl_range_db.set(range_map_id, range);
    sai_return_on_la_error(txn.status);

    sai_log_info(SAI_API_ACL, "acl range id 0x%lx created", *acl_range_id);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::expand_acl_range(lasai_acl_range_t& range)
{
    uint32_t width;

    switch (range.type) {
    case SAI_ACL_RANGE_TYPE_L4_SRC_PORT_RANGE:
    case SAI_ACL_RANGE_TYPE_L4_DST_PORT_RANGE:
        width = 16;
        break;
    default:
        sai_log_error(SAI_API_ACL, "Unsupported range type (%d)", range.type);
        sai_return_on_error(SAI_STATUS_NOT_IMPLEMENTED);
    }

    uint32_t val;
    uint32_t mask;
    uint32_t hi_bit = 0x1;
    uint32_t lo_bit = 0x1;
    uint32_t width_bit = (1 << width);

    if (range.limit.max >= width_bit || range.limit.max < range.limit.min) {
        sai_log_error(SAI_API_ACL, "Invalid range: %u..%u", range.limit.min, range.limit.max);
        sai_return_on_error(SAI_STATUS_INVALID_PARAMETER);
    }

    /*
     * Initialize port register with upper boundary. turning all
     * consecutive low-order 1 bits into don't-cares.  For example,
     * 01100111 becomes 01100xxx
     */
    val = range.limit.max;
    mask = width_bit - 1;
    while ((hi_bit < width_bit) && (val & hi_bit)) {
        val &= ~hi_bit;
        mask &= ~hi_bit;
        hi_bit <<= 1;
    }

    /*
     * Now iterate until we pass the lower boundary.  At each iteration,
     * we turn all consecutive low-order zeros into don't-cares, and
     * the following 1 into a 0.  Example: 001100xx -> 0010xxxx
     */
    while (val >= range.limit.min) {
        range.expansion.emplace_back(val, mask);

        while ((hi_bit < width_bit) && (val & hi_bit) == 0) {
            mask &= ~hi_bit;
            hi_bit <<= 1;
        }
        if (hi_bit >= width_bit) {
            break;
        }
        val &= ~hi_bit;
    }

    /*
     * We've passed the lower boundary.  Start working from the lower
     * boundary, and move upward.  First, turn all consecutive low-order
     * 0 bits into don't-cares.  Example: 00011000 -> 00011xxx
     */
    val = range.limit.min;
    mask = width_bit - 1;
    while ((lo_bit <= hi_bit) && (val & lo_bit) == 0) {
        mask &= ~lo_bit;
        lo_bit <<= 1;
    }

    /*
     * Finally, iterate until we reach the point we stopped before.  At
     * each iteration, we turn all consecutive low-order ones into don't-
     * cares, and the following 0 into a 1.  Example: 001011xx -> 0011xxxx
     */
    while (lo_bit < hi_bit) {
        range.expansion.emplace_back(val, mask);

        while ((lo_bit < hi_bit) && (val & lo_bit)) {
            val &= ~lo_bit;
            mask &= ~lo_bit;
            lo_bit <<= 1;
        }
        val |= lo_bit;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::remove_acl_range(_In_ sai_object_id_t acl_range_id)
{
    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_ACL_RANGE, acl_range_id, &acl_range_to_string, acl_range_id);

    lasai_acl_range_t range;
    uint32_t map_id = la_obj.index;

    la_status status;
    status = sdev->m_acl_handler->m_acl_range_db.get(map_id, range);
    sai_return_on_la_error(status);

    if (range.ref_count > 0) {
        sai_log_error(SAI_API_ACL, "Failed to remove ACL Range 0x%lx, still in use", acl_range_id);
        return SAI_STATUS_OBJECT_IN_USE;
    }

    status = sdev->m_acl_handler->m_acl_range_db.remove(map_id);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::set_acl_range_attribute(_In_ sai_object_id_t acl_range_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_SUPPORTED;
}

sai_status_t
sai_acl::get_acl_range_attribute(_In_ sai_object_id_t acl_range_id, _In_ uint32_t attr_count, _Out_ sai_attribute_t* attr_list)
{
    sai_object_key_t key = {};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = acl_range_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_ACL_RANGE, acl_range_id, &acl_range_to_string, acl_range_id, "attrs", attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "acl_range 0x%lx", acl_range_id);

    return sai_get_attributes(&key, key_str, acl_range_attribs, acl_range_vendor_attribs, attr_count, attr_list);
}

sai_status_t
sai_acl::get_acl_range_and_check_attr(_In_ const sai_object_key_t* key,
                                      _Inout_ sai_attribute_value_t* attr,
                                      _Out_ lasai_acl_range_t& range)
{
    if (key == nullptr || attr == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status_t sstatus;
    la_status status;
    sai_object_id_t range_id = key->key.object_id;

    std::shared_ptr<lsai_device> sdev;
    uint32_t map_id;

    sstatus = check_and_get_device_and_map_index(range_id, SAI_OBJECT_TYPE_ACL_RANGE, sdev, map_id);
    sai_return_on_error(sstatus);

    status = sdev->m_acl_handler->m_acl_range_db.get(map_id, range);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::get_acl_range_attr_val(_In_ const sai_object_key_t* key,
                                _Inout_ sai_attribute_value_t* attr,
                                _In_ unsigned int attr_index,
                                _Inout_ vendor_cache_t* cache,
                                void* arg)
{
    lasai_acl_range_t range;
    sai_status_t sstatus;

    sstatus = get_acl_range_and_check_attr(key, attr, range);
    sai_return_on_error(sstatus);

    switch ((uint64_t)arg) {
    case SAI_ACL_RANGE_ATTR_TYPE:
        set_attr_value(SAI_ACL_RANGE_ATTR_TYPE, *attr, range.type);
        break;
    case SAI_ACL_RANGE_ATTR_LIMIT:
        set_attr_value(SAI_ACL_RANGE_ATTR_LIMIT, *attr, range.limit);
        break;
    default:
        sai_log_error(SAI_API_ACL, "Invalid range attribute %d.", (uint64_t)arg);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

std::string
sai_acl::acl_table_group_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_acl_table_group_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << "\n";

    return log_message.str();
}

sai_status_t
sai_acl::create_acl_table_group(_Out_ sai_object_id_t* acl_table_group_id,
                                _In_ sai_object_id_t switch_id,
                                _In_ uint32_t attr_count,
                                _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_SWITCH, switch_id, &acl_table_group_to_string, "attrs", attrs);

    sai_acl_stage_t stage;
    get_attrs_value(SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE, attrs, stage, true);

    lasai_acl_table_group_t table_group;
    table_group.stage = stage;

    sai_s32_list_t bind_points{};
    get_attrs_value(SAI_ACL_TABLE_GROUP_ATTR_ACL_BIND_POINT_TYPE_LIST, attrs, bind_points, false);
    for (uint32_t i = 0; i < bind_points.count; i++) {
        table_group.bind_point_types.push_back(bind_points.list[i]);
    }

    sai_acl_table_group_type_t group_type = SAI_ACL_TABLE_GROUP_TYPE_SEQUENTIAL;
    get_attrs_value(SAI_ACL_TABLE_GROUP_ATTR_TYPE, attrs, group_type, false);
    table_group.type = group_type;

    uint32_t table_group_map_id;
    la_status status;
    status = sdev->m_acl_handler->m_acl_table_group_db.allocate_id(table_group_map_id);
    sai_return_on_la_error(status);

    lsai_object la_table_group(SAI_OBJECT_TYPE_ACL_TABLE_GROUP, la_obj.switch_id, table_group_map_id);
    *acl_table_group_id = la_table_group.object_id();
    table_group.group_id = la_table_group.object_id();

    status = sdev->m_acl_handler->m_acl_table_group_db.set(table_group_map_id, table_group);
    sai_return_on_la_error(status);

    sai_log_info(SAI_API_ACL, "acl table group id 0x%lx created", *acl_table_group_id);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::remove_acl_table_group(_In_ sai_object_id_t acl_table_group_id)
{
    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_ACL_TABLE_GROUP, acl_table_group_id, &acl_table_group_to_string, acl_table_group_id);

    lasai_acl_table_group_t table_group;
    uint32_t map_id = la_obj.index;

    la_status status;

    status = sdev->m_acl_handler->m_acl_table_group_db.get(map_id, table_group);
    sai_return_on_la_error(status);

    if (!table_group.group_member_ids.empty()) {
        sai_log_error(SAI_API_ACL, "ACL Table Group 0x%x contains members", acl_table_group_id);
        return SAI_STATUS_OBJECT_IN_USE;
    }

    for (auto pair : sdev->m_ports.map()) {
        if (pair.second.service.ingress_acl == acl_table_group_id || pair.second.service.egress_acl == acl_table_group_id) {
            sai_log_error(
                SAI_API_ACL, "Failed to remove ACL Table Group 0x%lx, it's bound to port %lu", acl_table_group_id, pair.first);
            return SAI_STATUS_OBJECT_IN_USE;
        }
    }

    for (auto pair : sdev->m_l3_ports.map()) {
        if (pair.second.ingress_acl == acl_table_group_id || pair.second.egress_acl == acl_table_group_id) {
            sai_log_error(
                SAI_API_ACL, "Failed to remove ACL Table Group 0x%lx, it's bound to port %lu", acl_table_group_id, pair.first);
            return SAI_STATUS_OBJECT_IN_USE;
        }
    }

    for (auto pair : sdev->m_lags.map()) {
        if (pair.second.service.ingress_acl == acl_table_group_id || pair.second.service.egress_acl == acl_table_group_id) {
            sai_log_error(
                SAI_API_ACL, "Failed to remove ACL Table Group 0x%lx, it's bound to port %lu", acl_table_group_id, pair.first);
            return SAI_STATUS_OBJECT_IN_USE;
        }
    }

    status = sdev->m_acl_handler->m_acl_table_group_db.remove(map_id);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::set_acl_table_group_attribute(_In_ sai_object_id_t acl_table_group_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
sai_acl::get_acl_table_group_attribute(_In_ sai_object_id_t acl_table_group_id,
                                       _In_ uint32_t attr_count,
                                       _Out_ sai_attribute_t* attr_list)
{
    sai_object_key_t key = {};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = acl_table_group_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_ACL, SAI_OBJECT_TYPE_ACL_TABLE_GROUP, acl_table_group_id, &acl_table_group_to_string, acl_table_group_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "acl table group 0x%lx", acl_table_group_id);

    return sai_get_attributes(&key, key_str, acl_table_group_attribs, acl_table_group_vendor_attribs, attr_count, attr_list);
}

std::string
sai_acl::acl_table_group_member_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_acl_table_group_member_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << "\n";

    return log_message.str();
}

sai_status_t
sai_acl::create_acl_table_group_member(_Out_ sai_object_id_t* acl_table_group_member_id,
                                       _In_ sai_object_id_t switch_id,
                                       _In_ uint32_t attr_count,
                                       _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_ACL, SAI_OBJECT_TYPE_SWITCH, switch_id, &acl_table_group_member_to_string, "attrs", attrs);

    sai_object_id_t acl_table_group_id;
    get_attrs_value(SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID, attrs, acl_table_group_id, true);

    lsai_object la_acl_table_group(acl_table_group_id);
    if (la_acl_table_group.type != SAI_OBJECT_TYPE_ACL_TABLE_GROUP) {
        sai_log_error(SAI_API_ACL, "Bad table group id %lu", acl_table_group_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_object_id_t acl_table_id;
    get_attrs_value(SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID, attrs, acl_table_id, true);

    lsai_object la_acl_table(acl_table_id);
    if (la_acl_table.type != SAI_OBJECT_TYPE_ACL_TABLE) {
        sai_log_error(SAI_API_ACL, "Bad table id %lu", acl_table_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    uint32_t priority;
    get_attrs_value(SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY, attrs, priority, true);

    lasai_acl_table_group_member_t member;
    member.table_group_id = acl_table_group_id;
    member.table_id = acl_table_id;
    member.priority = priority;

    uint32_t member_map_id;
    la_status status;
    status = sdev->m_acl_handler->m_acl_table_group_member_db.allocate_id(member_map_id);
    sai_return_on_la_error(status);

    lsai_object la_member(SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, la_obj.switch_id, member_map_id);
    *acl_table_group_member_id = la_member.object_id();
    member.member_id = la_member.object_id();

    lasai_acl_table_group_t group;
    status = sdev->m_acl_handler->m_acl_table_group_db.get(la_acl_table_group.index, group);
    sai_return_on_la_error(status);

    group.group_member_ids.push_back(member.member_id);

    status = sdev->m_acl_handler->m_acl_table_group_db.set(la_acl_table_group.index, group);
    sai_return_on_la_error(status);

    status = sdev->m_acl_handler->m_acl_table_group_member_db.set(member_map_id, member);
    sai_return_on_la_error(status);

    sai_status_t sstatus;
    bool bind = false;
    for (const auto& pair : sdev->m_ports.map()) {
        auto switch_acl_oid = sdev->switch_ingress_acl_oid;
        if (group.stage == SAI_ACL_STAGE_INGRESS) {
            if (pair.second.service.ingress_acl == acl_table_group_id || sdev->switch_ingress_acl_oid == acl_table_group_id) {
                bind = true;
                switch_acl_oid = sdev->switch_ingress_acl_oid;
            }
        } else {
            if (pair.second.service.egress_acl == acl_table_group_id || sdev->switch_egress_acl_oid == acl_table_group_id) {
                bind = true;
                switch_acl_oid = sdev->switch_egress_acl_oid;
            }
        }

        if (bind) {
            sai_log_debug(SAI_API_ACL, "Binding ACL to port 0x%lx", pair.second.service.oid);
            std::vector<la_object*> vec = sdev->m_dev->get_dependent_objects(pair.second.service.eth_port);
            for (auto elem : vec) {
                if (elem->type() == la_object::object_type_e::L3_AC_PORT) {
                    la_l3_port* l3_port = static_cast<la_l3_ac_port*>(elem);
                    auto bind_point
                        = (switch_acl_oid != SAI_NULL_OBJECT_ID) ? SAI_ACL_BIND_POINT_TYPE_SWITCH : SAI_ACL_BIND_POINT_TYPE_PORT;
                    sstatus = sai_acl::bind_acl(acl_table_id, sdev, group.stage, bind_point, l3_port);
                    sai_return_on_error(sstatus);
                } else if (elem->type() == la_object::object_type_e::L2_SERVICE_PORT) {
                    la_l2_service_port* l2_port = static_cast<la_l2_service_port*>(elem);
                    auto bind_point
                        = (switch_acl_oid != SAI_NULL_OBJECT_ID) ? SAI_ACL_BIND_POINT_TYPE_SWITCH : SAI_ACL_BIND_POINT_TYPE_PORT;
                    sstatus = sai_acl::bind_acl(acl_table_id, sdev, group.stage, bind_point, l2_port);
                    sai_return_on_error(sstatus);
                }
            }

            bind = false;
        }
    }

    for (const auto& pair : sdev->m_l3_ports.map()) {
        if ((pair.second.l3_port == nullptr) || (pair.second.l3_port->type() != la_object::object_type_e::SVI_PORT)) {
            // L3 ports are already handled in the previous iteration over m_ports
            continue;
        }

        auto switch_acl_oid = sdev->switch_ingress_acl_oid;
        if (group.stage == SAI_ACL_STAGE_INGRESS) {
            if (pair.second.ingress_acl == acl_table_group_id || sdev->switch_ingress_acl_oid == acl_table_group_id) {
                bind = true;
                switch_acl_oid = sdev->switch_ingress_acl_oid;
            }
        } else {
            if (pair.second.egress_acl == acl_table_group_id || sdev->switch_egress_acl_oid == acl_table_group_id) {
                bind = true;
                switch_acl_oid = sdev->switch_egress_acl_oid;
            }
        }

        if (bind) {
            sai_log_debug(SAI_API_ACL, "Binding ACL to port 0x%lx", pair.second.port_obj);
            auto bind_point = SAI_ACL_BIND_POINT_TYPE_ROUTER_INTERFACE;
            if (pair.second.type == SAI_ROUTER_INTERFACE_TYPE_VLAN) {
                bind_point = SAI_ACL_BIND_POINT_TYPE_VLAN;
            }

            bind_point = (switch_acl_oid != SAI_NULL_OBJECT_ID) ? SAI_ACL_BIND_POINT_TYPE_SWITCH : bind_point;
            sstatus = sai_acl::bind_acl(acl_table_id, sdev, group.stage, bind_point, pair.second.l3_port);
            sai_return_on_error(sstatus);

            bind = false;
        }
    }

    for (const auto& pair : sdev->m_lags.map()) {
        auto switch_acl_oid = sdev->switch_ingress_acl_oid;
        if (group.stage == SAI_ACL_STAGE_INGRESS) {
            if (pair.second.service.ingress_acl == acl_table_group_id || sdev->switch_ingress_acl_oid == acl_table_group_id) {
                bind = true;
                switch_acl_oid = sdev->switch_ingress_acl_oid;
            }
        } else {
            if (pair.second.service.egress_acl == acl_table_group_id || sdev->switch_egress_acl_oid == acl_table_group_id) {
                bind = true;
                switch_acl_oid = sdev->switch_egress_acl_oid;
            }
        }

        if (bind) {
            if (pair.second.service.eth_port == nullptr) {
                bind = false;
                continue;
            }
            std::vector<la_object*> vec = sdev->m_dev->get_dependent_objects(pair.second.service.eth_port);
            for (auto elem : vec) {
                sai_log_debug(SAI_API_ACL, "Binding ACL to port 0x%lx", elem->oid());
                if (elem->type() == la_object::object_type_e::L3_AC_PORT) {
                    la_l3_port* l3_port = static_cast<la_l3_ac_port*>(elem);
                    auto bind_point
                        = (switch_acl_oid != SAI_NULL_OBJECT_ID) ? SAI_ACL_BIND_POINT_TYPE_SWITCH : SAI_ACL_BIND_POINT_TYPE_LAG;
                    sstatus = sai_acl::bind_acl(acl_table_id, sdev, group.stage, bind_point, l3_port);
                    sai_return_on_error(sstatus);
                } else if (elem->type() == la_object::object_type_e::L2_SERVICE_PORT) {
                    la_l2_service_port* l2_port = static_cast<la_l2_service_port*>(elem);
                    auto bind_point
                        = (switch_acl_oid != SAI_NULL_OBJECT_ID) ? SAI_ACL_BIND_POINT_TYPE_SWITCH : SAI_ACL_BIND_POINT_TYPE_PORT;
                    sstatus = sai_acl::bind_acl(acl_table_id, sdev, group.stage, bind_point, l2_port);
                    sai_return_on_error(sstatus);
                }
            }

            bind = false;
        }
    }

    sai_log_info(SAI_API_ACL, "acl table group member id 0x%lx created", *acl_table_group_member_id);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::remove_acl_table_group_member(_In_ sai_object_id_t acl_table_group_member_id)
{
    sai_start_api(SAI_API_ACL,
                  SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER,
                  acl_table_group_member_id,
                  &acl_table_group_member_to_string,
                  acl_table_group_member_id);

    lasai_acl_table_group_member_t member;
    uint32_t map_id = la_obj.index;

    la_status status;

    status = sdev->m_acl_handler->m_acl_table_group_member_db.get(map_id, member);
    sai_return_on_la_error(status);

    lsai_object la_table_group(member.table_group_id);
    // Getting reference to table from db, so we will be able to change it
    lasai_acl_table_group_t* group = sdev->m_acl_handler->m_acl_table_group_db.get_ptr(la_table_group.index);
    if (group == nullptr) {
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    group->group_member_ids.erase(
        std::remove(group->group_member_ids.begin(), group->group_member_ids.end(), acl_table_group_member_id),
        group->group_member_ids.end());

    status = sdev->m_acl_handler->m_acl_table_group_member_db.remove(map_id);
    sai_return_on_la_error(status);

    sai_status_t sstatus;
    bool bind = false;
    for (const auto& pair : sdev->m_ports.map()) {
        if (group->stage == SAI_ACL_STAGE_INGRESS) {
            if (pair.second.service.ingress_acl == member.table_group_id || sdev->switch_ingress_acl_oid == member.table_group_id) {
                bind = true;
            }
        } else {
            if (pair.second.service.egress_acl == member.table_group_id || sdev->switch_egress_acl_oid == member.table_group_id) {
                bind = true;
            }
        }

        if (bind) {
            sai_log_debug(SAI_API_ACL, "Unbinding ACL from port 0x%lx", pair.second.service.oid);
            std::vector<la_object*> vec = sdev->m_dev->get_dependent_objects(pair.second.service.eth_port);
            for (auto elem : vec) {
                if (elem->type() == la_object::object_type_e::L3_AC_PORT) {
                    la_l3_port* l3_port = static_cast<la_l3_ac_port*>(elem);

                    sstatus = sai_acl::unbind_acl(member.table_id, sdev, l3_port);
                    sai_return_on_error(sstatus);
                } else if (elem->type() == la_object::object_type_e::L2_SERVICE_PORT) {
                    la_l2_service_port* l2_port = static_cast<la_l2_service_port*>(elem);
                    sstatus = sai_acl::unbind_acl(member.table_id, sdev, l2_port);
                    sai_return_on_error(sstatus);
                }
            }

            bind = false;
        }
    }

    for (const auto& pair : sdev->m_l3_ports.map()) {
        if ((pair.second.l3_port == nullptr) || (pair.second.l3_port->type() != la_object::object_type_e::SVI_PORT)) {
            // L3 ports are already handled in the previous iteration over m_ports
            continue;
        }

        if (group->stage == SAI_ACL_STAGE_INGRESS) {
            if (pair.second.ingress_acl == member.table_group_id || sdev->switch_ingress_acl_oid == member.table_group_id) {
                bind = true;
            }
        } else {
            if (pair.second.egress_acl == member.table_group_id || sdev->switch_egress_acl_oid == member.table_group_id) {
                bind = true;
            }
        }

        if (bind) {
            sai_log_debug(SAI_API_ACL, "Unbinding ACL from port 0x%lx", pair.second.port_obj);
            sstatus = sai_acl::unbind_acl(member.table_id, sdev, pair.second.l3_port);
            sai_return_on_error(sstatus);
            bind = false;
        }
    }

    for (const auto& pair : sdev->m_lags.map()) {
        if (group->stage == SAI_ACL_STAGE_INGRESS) {
            if (pair.second.service.ingress_acl == member.table_group_id || sdev->switch_ingress_acl_oid == member.table_group_id) {
                bind = true;
            }
        } else {
            if (pair.second.service.egress_acl == member.table_group_id || sdev->switch_egress_acl_oid == member.table_group_id) {
                bind = true;
            }
        }

        if (bind) {
            std::vector<la_object*> vec = sdev->m_dev->get_dependent_objects(pair.second.service.eth_port);
            if (pair.second.service.eth_port == nullptr) {
                bind = false;
                continue;
            }

            for (auto elem : vec) {
                sai_log_debug(SAI_API_ACL, "Unbinding ACL from port 0x%lx", elem->oid());
                if (elem->type() == la_object::object_type_e::L3_AC_PORT) {
                    la_l3_port* l3_port = static_cast<la_l3_ac_port*>(elem);
                    sstatus = sai_acl::unbind_acl(member.table_id, sdev, l3_port);
                    sai_return_on_error(sstatus);
                } else if (elem->type() == la_object::object_type_e::L2_SERVICE_PORT) {
                    la_l2_service_port* l2_port = static_cast<la_l2_service_port*>(elem);
                    sstatus = sai_acl::unbind_acl(member.table_id, sdev, l2_port);
                    sai_return_on_error(sstatus);
                }
            }

            bind = false;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_acl::set_acl_table_group_member_attribute(_In_ sai_object_id_t acl_table_group_member_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
sai_acl::get_acl_table_group_member_attribute(_In_ sai_object_id_t acl_table_group_member_id,
                                              _In_ uint32_t attr_count,
                                              _Out_ sai_attribute_t* attr_list)
{
    sai_object_key_t key = {};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = acl_table_group_member_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_ACL,
                  SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER,
                  acl_table_group_member_id,
                  &acl_table_group_member_to_string,
                  acl_table_group_member_id,
                  "attrs",
                  attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "acl table group member 0x%lx", acl_table_group_member_id);
    return sai_get_attributes(
        &key, key_str, acl_table_group_member_attribs, acl_table_group_member_vendor_attribs, attr_count, attr_list);
}

const sai_acl_api_t acl_api = {sai_acl::create_acl_table,
                               sai_acl::remove_acl_table,
                               sai_acl::set_acl_table_attribute,
                               sai_acl::get_acl_table_attribute,
                               sai_acl::create_acl_entry,
                               sai_acl::remove_acl_entry,
                               sai_acl::set_acl_entry_attribute,
                               sai_acl::get_acl_entry_attribute,
                               sai_acl::create_acl_counter,
                               sai_acl::remove_acl_counter,
                               sai_acl::set_acl_counter_attribute,
                               sai_acl::get_acl_counter_attribute,
                               sai_acl::create_acl_range,
                               sai_acl::remove_acl_range,
                               sai_acl::set_acl_range_attribute,
                               sai_acl::get_acl_range_attribute,
                               sai_acl::create_acl_table_group,
                               sai_acl::remove_acl_table_group,
                               sai_acl::set_acl_table_group_attribute,
                               sai_acl::get_acl_table_group_attribute,
                               sai_acl::create_acl_table_group_member,
                               sai_acl::remove_acl_table_group_member,
                               sai_acl::set_acl_table_group_member_attribute,
                               sai_acl::get_acl_table_group_member_attribute};
}
}
