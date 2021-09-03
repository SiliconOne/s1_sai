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

#ifndef __SAI_ACL_H__
#define __SAI_ACL_H__

#include <vector>

extern "C" {
#include <sai.h>
}

#include "common/ranged_index_generator.h"
#include "api/npu/la_acl.h"
#include "api/types/la_acl_types.h"
#include "api/types/la_common_types.h"
#include "sai_db.h"
#include "sai_utils.h"
#include "sai_warm_boot.h"
#include "acl_udk.h"

namespace silicon_one
{
namespace sai
{

class lsai_device;
struct rif_entry;
struct port_entry;
struct lag_entry;
struct bridge_port_entry;
struct cpu_l2_port_entry;

#define MAX_ACL_TABLES 16
#define MAX_ACL_ENTRIES_PER_TABLE 512
#define MAX_ACL_TABLE_GROUPS 1024 * 16
#define MAX_ACL_TABLE_GROUP_MEMBERS MAX_ACL_TABLE_GROUPS
#define MAX_ACL_ENTRIES (MAX_ACL_TABLES * MAX_ACL_ENTRIES_PER_TABLE)
#define MAX_ACL_COUNTERS 6400
#define MAX_ACL_RANGES 6400

struct lasai_acl_table_t {
    uint32_t table_size;
    sai_object_id_t table_id = 0;
    sai_object_id_t device_id = 0;
    std::vector<sai_object_id_t> entry_list;
    std::vector<int32_t> bind_point_types;
    std::vector<bool> match_field;
    std::vector<uint32_t> acl_action_types;
    std::vector<int32_t> match_range;
    std::set<sai_object_id_t> counters;
    sai_acl_stage_t stage;
    // sdk ACL key profile
    la_obj_wrap<la_acl_key_profile> v4_sdk_acl_key_profile;
    la_obj_wrap<la_acl_key_profile> v6_sdk_acl_key_profile;
    // sdk ACL command profile
    la_obj_wrap<la_acl_command_profile> v4_sdk_acl_command_profile;
    la_obj_wrap<la_acl_command_profile> v6_sdk_acl_command_profile;
    // SDK ACL table used with v4 header fields
    la_obj_wrap<la_acl> v4_sdk_acl;
    // SDK ACL table used with v6 header fields
    la_obj_wrap<la_acl> v6_sdk_acl;
    // If true, ACL table match field contains v4 header fields
    bool is_v4_acl = false;
    // If true, ACL table match field contains v6 header fields
    bool is_v6_acl = false;
    // True when acl table is created using UDK fields and applicable to v4 packets
    bool is_v4_udk = false;
    // True when acl table is created using UDK fields and applicable to v6 packets
    bool is_v6_udk = false;
};

struct lasai_acl_entry_t {
    sai_object_id_t entry_id = 0;
    sai_object_id_t table_id = 0;
    sai_object_id_t counter_id = 0;
    sai_object_id_t policer_id = 0;
    sai_object_id_t redirect_id = 0;
    bool admin_state = true;
    uint32_t priority;
    std::vector<sai_object_id_t> range_list;
    std::vector<sai_object_id_t> port_list;
    uint32_t sdk_entries = 0;
    // Since IP_TYPE is not pushed into ACE, to facilitate get IP_TYPE
    // shadow copy of ip-type is stored. This shadow value is returned
    // on attribute get SAI_ACL_ENTRY_ATTR_FIELD_ACL_IP_TYPE.
    uint8_t ip_type;
    uint8_t ip_type_mask;
};

struct lasai_acl_counter_t {
    sai_object_id_t counter_id = 0;
    sai_object_id_t table_id = 0;
    la_obj_wrap<la_counter_set> sdk_counter;
    bool packet_count = false;
    bool byte_count = false;
};

struct lasai_acl_meter_t {
    sai_object_id_t policer_id = SAI_NULL_OBJECT_ID;
    la_obj_wrap<la_meter_set> sdk_meter;
    uint32_t ref_count = 0;
};

struct lasai_acl_range_t {
    sai_object_id_t range_id = 0;
    sai_acl_range_type_t type;
    sai_u32_range_t limit;
    uint32_t ref_count = 0;
    std::vector<std::pair<uint16_t, uint16_t>> expansion;
};

struct lasai_acl_table_group_t {
    sai_object_id_t group_id = 0;
    std::vector<sai_object_id_t> group_member_ids;
    sai_acl_stage_t stage;
    std::vector<int32_t> bind_point_types;
    sai_acl_table_group_type_t type;
};

struct lasai_acl_table_group_member_t {
    sai_object_id_t member_id = 0;
    sai_object_id_t table_group_id = 0;
    sai_object_id_t table_id = 0;
    // TODO(srkovace): See what to do with priority.
    uint32_t priority;
};

class sai_acl
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

#define GET_ACL_ATTR_FUNCTION_ARGS                                                                                                 \
    _In_ const sai_object_key_t *key, _Inout_ sai_attribute_value_t *attr, _In_ unsigned int attr_index,                           \
        _Inout_ vendor_cache_t *cache, void *arg

#define CREATE_ACL_ATTR_FUNCTION_ARGS                                                                                              \
    _Out_ sai_object_id_t *, _In_ sai_object_id_t switch_id, _In_ uint32_t attr_count, _In_ const sai_attribute_t *attr_list

#define GET_ACL_ATTRS_LIST_FUNCTION_ARGS _In_ sai_object_id_t, _In_ uint32_t attr_count, _Out_ sai_attribute_t *attr_list

public:
    sai_acl() : sai_acl(nullptr)
    {
    }
    sai_acl(std::shared_ptr<lsai_device> sai_dev);
    ~sai_acl();

    static sai_status_t sai_acl_stage_to_sdk_acl_dir(sai_acl_stage_t sai_acl_stage, la_acl_direction_e& sdk_acl_dir);
    static sai_status_t sdk_acl_dir_to_sai_acl_stage(la_acl_direction_e sdk_acl_stage, sai_acl_stage_t& sai_acl_stage);
    static std::vector<la_acl_command_action>::iterator find_sdk_acl_action_command(la_acl_command_actions& sdk_acl_command_actions,
                                                                                    la_acl_action_type_e acl_action_type);
    static sai_status_t sai_attr_to_sdk_field_type(_In_ sai_attr_id_t sai_id, _Out_ la_acl_field_type_e& sdk_type);
    static sai_uint32_t get_acl_actions_max_count();
    static sai_status_t get_acl_table_attr_stage(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_table_attr_bind_point_type_list(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_table_attr_size(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_table_action_type_list(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_table_attr_match_field(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_table_attr_match_range(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_table_attr_entry_list(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_table_attr_avail_entry_count(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_table_attr_avail_acl_counters(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_entry_attr_table_id(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_entry_attr_priority(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_entry_attr_field_rule(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_counter_attr_table_id(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t acl_counter_attr_counter_enabled(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_counter_attr_counter(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_range_attr_val(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_table_group(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_group_member(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t get_acl_entry_attr_action_rule(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t set_acl_entry_attr_action_rule(_In_ const sai_object_key_t* key,
                                                       _In_ const sai_attribute_value_t* value,
                                                       void* arg);
    static sai_status_t get_acl_entry_attr_admin_state(GET_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t set_acl_entry_attr_admin_state(_In_ const sai_object_key_t* key,
                                                       _In_ const sai_attribute_value_t* value,
                                                       void* arg);
    static sai_status_t create_acl_table(CREATE_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t remove_acl_table(_In_ sai_object_id_t acl_table_id);
    static sai_status_t set_acl_table_attribute(_In_ sai_object_id_t acl_table_id, _In_ const sai_attribute_t* attr);
    static sai_status_t get_acl_table_attribute(GET_ACL_ATTRS_LIST_FUNCTION_ARGS);
    static sai_status_t create_acl_entry(CREATE_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t remove_acl_entry(_In_ sai_object_id_t acl_entry_id);
    static sai_status_t set_acl_entry_attribute(_In_ sai_object_id_t acl_entry_id, _In_ const sai_attribute_t* attr);
    static sai_status_t get_acl_entry_attribute(GET_ACL_ATTRS_LIST_FUNCTION_ARGS);
    static sai_status_t create_acl_counter(CREATE_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t remove_acl_counter(_In_ sai_object_id_t acl_counter_id);
    static sai_status_t set_acl_counter_attribute(_In_ sai_object_id_t acl_counter_id, _In_ const sai_attribute_t* attr);
    static sai_status_t get_acl_counter_attribute(GET_ACL_ATTRS_LIST_FUNCTION_ARGS);
    static sai_status_t create_acl_range(CREATE_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t remove_acl_range(_In_ sai_object_id_t acl_range_id);
    static sai_status_t set_acl_range_attribute(_In_ sai_object_id_t acl_range_id, _In_ const sai_attribute_t* attr);
    static sai_status_t get_acl_range_attribute(GET_ACL_ATTRS_LIST_FUNCTION_ARGS);
    static sai_status_t create_acl_table_group(CREATE_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t remove_acl_table_group(_In_ sai_object_id_t acl_table_group_id);
    static sai_status_t set_acl_table_group_attribute(_In_ sai_object_id_t acl_table_group_id, _In_ const sai_attribute_t* attr);
    static sai_status_t get_acl_table_group_attribute(GET_ACL_ATTRS_LIST_FUNCTION_ARGS);
    static sai_status_t create_acl_table_group_member(CREATE_ACL_ATTR_FUNCTION_ARGS);
    static sai_status_t remove_acl_table_group_member(_In_ sai_object_id_t acl_table_group_member_id);
    static sai_status_t set_acl_table_group_member_attribute(_In_ sai_object_id_t acl_table_group_member_id,
                                                             _In_ const sai_attribute_t* attr);
    static sai_status_t get_acl_table_group_member_attribute(GET_ACL_ATTRS_LIST_FUNCTION_ARGS);

    // On an already created rif, the function facilitates ingress/egress acl attachment.
    sai_status_t attach_acl_on_rif(sai_object_id_t acl_obj_id, sai_acl_stage_t stage, rif_entry* rif_entry);
    // At the time of rif creation, the function facilitates parent's (from port or switch instance) ACL attachment.
    sai_status_t attach_acl_on_rif_create(rif_entry* rif_entry);
    // At the time of rif removal, the function facilitates parent's (from port or switch instance) ACL detachment.
    sai_status_t clear_acl_on_rif_removal(const rif_entry& rif_entry);
    // At the time of bridge port creation, the function facilitates parent's (from port or switch instance) ACL attachment.
    sai_status_t attach_acl_on_bridge_port_create(bridge_port_entry* bport_entry);
    // At the time of bridge port removal, the function facilitates parent's (from port or switch instance) ACL detachment.
    sai_status_t clear_acl_on_bridge_port_removal(const bridge_port_entry& bport_entry);
    sai_status_t attach_acl_on_cpu_l2_port(sai_object_id_t acl_oid,
                                           sai_acl_stage_t stage,
                                           cpu_l2_port_entry& cpu_l2_port,
                                           sai_acl_bind_point_type_t bind_point);

    // At the time of cpu l2 port creation, the function facilitates parent's (only switch instance) ACL attachment.
    sai_status_t attach_acl_on_cpu_l2_port_create(cpu_l2_port_entry& cpu_l2_port);
    // At the time of cpu l2 port removal, the function facilitates parent's (only switch instance) ACL detachment.
    sai_status_t clear_acl_on_cpu_l2_port_removal(cpu_l2_port_entry& cpu_l2_port);

    // On an already created lag, the function facilitates ingress/egress acl attachment.
    sai_status_t attach_acl_on_lag(sai_object_id_t acl_oid,
                                   sai_acl_stage_t stage,
                                   lag_entry* lag_entry,
                                   sai_acl_bind_point_type_t bind_point);
    // At the time of lag creation, the function facilitates parent's (from switch instance) ACL attachment.
    sai_status_t attach_acl_on_lag_create(lag_entry& lag_entry);
    // At the time of lag removal, the function facilitates parent's (from switch instance) ACL detachment.
    sai_status_t clear_acl_on_lag_removal(lag_entry& lag_entry);

    // On an already created port, the function facilitates ingress/egress acl attachment.
    sai_status_t attach_acl_on_port(sai_object_id_t acl_oid,
                                    sai_acl_stage_t stage,
                                    port_entry* port_entry,
                                    sai_acl_bind_point_type_t bind_point);
    // At the time of port creation, the function facilitates parent's (from switch instance) ACL attachment.
    sai_status_t attach_acl_on_port_create(const port_entry& port_entry);
    // At the time of port removal, the function facilitates parent's (from switch instance) ACL deattachment.
    sai_status_t clear_acl_on_port_removal(port_entry& port_entry);

    // Attach ACL to switch instance that also gets applied to all constituents entities like ports, lag, rif
    sai_status_t attach_acl_on_switch(sai_acl_stage_t stage, sai_object_id_t acl_oid);
    // Detach ACL from switch instance. ACL detachment gets applied to all constituents entities like ports, lag, rif
    sai_status_t clear_acl_on_switch(sai_acl_stage_t stage);

    // Returns true when sai acl table match field belongs to v6 header
    static bool is_v6_acl_table_field(uint32_t attr_id);
    // Returns true when sai acl table match field belongs to v4 header
    static bool is_v4_acl_table_field(uint32_t attr_id);

    // From combined v4 and v6 acl match table fields, create acl match table fields
    // v4 acl table and v6 acl sdk table lookups.
    static void create_seperate_v4_v6_acl_table_field_set(const std::set<uint32_t>& acl_table_combined_fields,
                                                          std::set<uint32_t>& v4_table_fields,
                                                          std::set<uint32_t>& v6_table_fields);

    la_meter_set* get_acl_sdk_meter(sai_object_id_t policer_id);

private:
    sai_status_t validate_acl_on_rif(sai_object_id_t acl_obj_id, const rif_entry* rif_entry, sai_acl_stage_t stage) const;
    static sai_status_t validate_acl_table_bind_point(const lasai_acl_table_t* table,
                                                      sai_acl_stage_t stage,
                                                      sai_acl_bind_point_type_t bind_point);
    static sai_status_t build_sdk_acl_group(const std::shared_ptr<lsai_device>& sdev,
                                            const lasai_acl_table_t* acl_table,
                                            la_acl_group*& sdk_acl_group);

    static sai_status_t add_acl_table_to_sdk_acl_group(const std::shared_ptr<lsai_device>& sdev,
                                                       const lasai_acl_table_t* acl_table,
                                                       la_acl_group* sdk_acl_group);
    static sai_status_t bind_acl(sai_object_id_t oid,
                                 std::shared_ptr<lsai_device>& sdev,
                                 sai_acl_stage_t stage,
                                 sai_acl_bind_point_type_t bind_point,
                                 la_l3_port* l3_port);
    static sai_status_t build_sdk_acl_group_l2_attachment(const std::shared_ptr<lsai_device>& sdev,
                                                          const lasai_acl_table_t* acl_table,
                                                          la_acl_group*& sdk_acl_group);
    static sai_status_t bind_acl(sai_object_id_t oid,
                                 std::shared_ptr<lsai_device>& sdev,
                                 sai_acl_stage_t stage,
                                 sai_acl_bind_point_type_t bind_point,
                                 la_l2_service_port* l2_port);
    sai_status_t bind_group_acl(sai_object_id_t acl_oid,
                                std::shared_ptr<lsai_device>& sdev,
                                sai_acl_stage_t stage,
                                sai_acl_bind_point_type_t bind_point,
                                la_l3_port* l3_port);
    sai_status_t bind_group_acl(sai_object_id_t acl_oid,
                                std::shared_ptr<lsai_device>& sdev,
                                sai_acl_stage_t stage,
                                sai_acl_bind_point_type_t bind_point,
                                la_l2_service_port* l2_port);
    static sai_status_t unbind_acl(sai_object_id_t acl_oid, std::shared_ptr<lsai_device>& sdev, la_l3_port* l3_port);
    static sai_status_t unbind_acl(sai_object_id_t oid, std::shared_ptr<lsai_device>& sdev, la_l2_service_port* l2_port);
    sai_status_t unbind_group_acl(sai_object_id_t acl_oid, std::shared_ptr<lsai_device>& sdev, la_l3_port* l3_port);
    sai_status_t unbind_group_acl(sai_object_id_t acl_oid, std::shared_ptr<lsai_device>& sdev, la_l2_service_port* l3_port);

    static void acl_id_to_str(_In_ sai_object_id_t acl_table_id,
                              _In_ sai_object_type_t type,
                              _Out_ char* key_str,
                              _Out_ std::shared_ptr<lsai_device>& sdev);
    static sai_status_t check_and_get_device_and_map_index(_In_ sai_object_id_t acl_table_id,
                                                           _In_ sai_object_type_t type,
                                                           _Out_ std::shared_ptr<lsai_device>& sdev,
                                                           _Out_ uint32_t& map_id);
    static sai_status_t get_acl_table_and_check_attr(_In_ const sai_object_key_t* key,
                                                     _Inout_ sai_attribute_value_t* attr,
                                                     _Out_ lasai_acl_table_t& acl_table);
    static sai_status_t get_acl_entry_and_check_attr(_In_ const sai_object_key_t* key,
                                                     _Inout_ sai_attribute_value_t* attr,
                                                     _Out_ lasai_acl_entry_t& acl_entry);
    static sai_status_t get_acl_counter_and_check_attr(_In_ const sai_object_key_t* key,
                                                       _Inout_ sai_attribute_value_t* attr,
                                                       _Out_ lasai_acl_counter_t& acl_counter);
    static sai_status_t get_acl_range_and_check_attr(_In_ const sai_object_key_t* key,
                                                     _Inout_ sai_attribute_value_t* attr,
                                                     _Out_ lasai_acl_range_t& range);
    static sai_status_t get_acl_table_group_and_check_attr(_In_ const sai_object_key_t* key,
                                                           _Inout_ sai_attribute_value_t* attr,
                                                           _Out_ lasai_acl_table_group_t& table_group);
    static sai_status_t get_acl_table_group_member_and_check_attr(_In_ const sai_object_key_t* key,
                                                                  _Inout_ sai_attribute_value_t* attr,
                                                                  _Out_ lasai_acl_table_group_member_t& member);
    static std::string acl_table_to_string(sai_attribute_t& attr);
    static std::string acl_entry_to_string(sai_attribute_t& attr);
    static std::string acl_counter_to_string(sai_attribute_t& attr);
    static std::string acl_range_to_string(sai_attribute_t& attr);
    static std::string acl_table_group_to_string(sai_attribute_t& attr);
    static std::string acl_table_group_member_to_string(sai_attribute_t& attr);

    struct tos_info_t {
        bool contains_tos = false;
        la_ip_tos val;
        la_ip_tos mask;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(tos_info_t);

    static sai_status_t copy_sai_ace_field_to_sdk_udf_field(uint32_t attr_id,
                                                            const sai_acl_field_data_t& sai_acl_field,
                                                            la_acl_field& sdk_acl_field);
    static sai_status_t copy_sai_ace_field_to_sdk_field(uint32_t attr_id,
                                                        const sai_acl_field_data_t& sai_acl_field,
                                                        la_acl_field& sdk_acl_field,
                                                        tos_info_t& tos_info);
    static bool is_acl_entry_field_udf(uint8_t profile_type, const lasai_acl_table_t& table, uint32_t attr_id);
    static sai_status_t build_sdk_ace_field(const sai_attribute_t* attr,
                                            uint8_t profile_type,
                                            const lasai_acl_table_t& table,
                                            const sai_acl_field_data_t& sai_acl_field,
                                            tos_info_t& tos_info,
                                            la_acl_field& sdk_acl_field);
    static void set_default_command(sai_acl_stage_t sai_stage, la_acl_command_action& sdk_acl_command_action);
    static sai_status_t build_new_acl_mirror_action_commands(sai_object_id_t mirror_oid,
                                                             bool is_ingress_stage,
                                                             la_acl_command_actions& acl_commands);
    static sai_status_t build_sdk_action_rule(const sai_attribute_t* attr,
                                              sai_acl_action_data_t sai_acl_action,
                                              lasai_acl_entry_t& acl_entry,
                                              la_acl_command_actions& sdk_acl_commands);
    la_status get_acls_attached_on_bindpoint(const std::shared_ptr<lsai_device>& sdev,
                                             sai_object_id_t oid,
                                             sai_object_id_t& ingress_acl_oid,
                                             sai_object_id_t& egress_acl_oid) const;
    // Update ACL on l3 port. Replace old ACL with new one, attach ACL or detach ACL
    sai_status_t update_acl_on_l3_port(la_l3_port* l3_port,
                                       sai_object_id_t acl_oid,
                                       sai_acl_stage_t stage,
                                       sai_acl_bind_point_type_t bind_point,
                                       sai_object_id_t old_acl_oid);
    // Update ACL on l3 port. Replace old ACL with new one, attach ACL or detach ACL
    sai_status_t update_acl_on_l2_port(la_l2_service_port* l2_port,
                                       sai_object_id_t acl_oid,
                                       sai_acl_stage_t stage,
                                       sai_acl_bind_point_type_t bind_point,
                                       sai_object_id_t old_acl_oid);
    // Bind acl to all logical ports over the ethernet port.
    sai_status_t attach_acl_on_logical_ports(sai_object_id_t acl_oid,
                                             sai_acl_stage_t stage,
                                             la_ethernet_port* eth_port,
                                             sai_acl_bind_point_type_t bind_point,
                                             sai_object_id_t old_acl_oid);
    // Returns true when a ingress/egress stage ACL is attached on any port.
    bool is_acl_set_on_non_switch_bindpoints(sai_acl_stage_t stage) const;
    // Find insertion position in hw table for the ace with ace_priority.
    static sai_status_t find_ace_position(const lasai_acl_table_t& table, uint32_t& ace_position, uint32_t ace_priority);
    // Build a single SDK ACL field from SAI range type and expanded val/mask
    static sai_status_t build_sdk_ace_range_field(const sai_acl_range_type_t type,
                                                  const uint16_t val,
                                                  const uint16_t mask,
                                                  la_acl_field& sdk_acl_field);

    static sai_status_t create_acl_key_list_with_in_ports(lasai_acl_entry_t& entry,
                                                          std::vector<std::vector<la_acl_field>>& key_set);

    static sai_status_t get_sdk_port_field(sai_object_id_t port_oid, la_acl_field& sdk_acl_field);

    // Insert an ACE into an ACL (expand ranges into multiple SDK ACEs)
    static sai_status_t insert_ace_with_range_expansion(lasai_acl_table_t& table,
                                                        lasai_acl_entry_t& entry,
                                                        la_acl* sdk_acl,
                                                        uint32_t position,
                                                        std::vector<std::vector<la_acl_field>>& key_set,
                                                        const la_acl_command_actions& cmd,
                                                        transaction& txn);
    // Collect ACL table match fields, bind points, acl-actions
    static sai_status_t process_acl_table_attributes(const sai_attribute_t* attr_list,
                                                     uint32_t attr_count,
                                                     lasai_acl_table_t& table,
                                                     std::set<uint32_t>& acl_table_fields);
    static sai_status_t process_acl_table_range_type(const sai_s32_list_t& range_list,
                                                     lasai_acl_table_t& table,
                                                     std::set<uint32_t>& acl_table_fields);
    // If acl table field is not part of ip L3 header, then the function
    // return true. This function is used to prepare 2 ACL key schemas
    // one for v4 and v6 using a unified table schema passed to SAI.
    static bool is_non_l3_header_field(uint32_t attr_id);
    // If ACL key schema is not valid, then the function return false.
    static bool is_valid_acl_field_set(const std::set<uint32_t>& table_fields, uint8_t profile_type);
    // Using SAI ACL table key fields, create SDK key profile
    static sai_status_t create_sdk_acl_table_key_profile(const std::shared_ptr<lsai_device>& sdev,
                                                         const std::set<uint32_t>& acl_table_fields,
                                                         uint8_t profile_type,
                                                         lasai_acl_table_t& table,
                                                         la_acl_key_profile*& sdk_acl_key_profile);
    // Using sai acl match table fields, create sdk acl table.
    static sai_status_t create_sdk_acl_table(const std::shared_ptr<lsai_device>& sdev,
                                             la_acl_key_profile* sdk_acl_key_profile,
                                             uint8_t profile_type,
                                             lasai_acl_table_t& table,
                                             la_acl*& sdk_acl_table);
    // Using sai acl match table fields, create sdk acl table key.
    static sai_status_t create_sdk_acl_key(const std::vector<const sai_attribute_t*>& ace_field_attrs,
                                           uint8_t profile_type,
                                           const lasai_acl_table_t& table,
                                           lasai_acl_entry_t& acl_entry,
                                           la_acl_key& sdk_acl_key);
    // Returns true when sai acl table entry field belongs to v4 header
    static bool is_v4_ace_field(uint32_t attr_id);
    // Returns true when sai acl table entry field belongs to v6 header
    static bool is_v6_ace_field(uint32_t attr_id);
    static sai_status_t create_default_sdk_acl_key(uint8_t profile_type,
                                                   const std::set<uint32_t>& acl_table_fields,
                                                   la_acl_key_def_vec_t& sdk_key_vec);
    // Returns true when sdk acl table match field belongs to v6 header
    static bool is_v6_sdk_ace_field(const la_acl_field& sdk_acl_field);
    // Returns true when sdk acl table match field belongs to v4 header
    static bool is_v4_sdk_ace_field(const la_acl_field& sdk_acl_field);
    // Expand a range into a set of masks and values
    static sai_status_t expand_acl_range(lasai_acl_range_t& range);

    static sai_status_t set_acl_entry_action_redirect(la_acl_command_action& sdk_acl_command, sai_object_id_t target_oid);
    static sai_status_t set_acl_entry_action_mirror(sai_object_id_t mirror_oid,
                                                    sai_object_id_t acl_table_oid,
                                                    acl_entry_desc& sdk_entry_desc,
                                                    bool is_ingress);
    static sai_status_t clear_acl_entry_action_mirror(const std::shared_ptr<lsai_device>& sdev,
                                                      sai_object_id_t acl_table_oid,
                                                      acl_entry_desc& sdk_entry_desc,
                                                      bool is_ingress);
    static la_status get_or_create_sdk_acl_meter(const std::shared_ptr<lsai_device>& sdev,
                                                 sai_object_id_t policer_oid,
                                                 lasai_acl_meter_t*& acl_meter);
    static la_status remove_sdk_acl_meter(const std::shared_ptr<lsai_device>& sdev, sai_object_id_t policer_oid);

private:
    std::shared_ptr<lsai_device> m_sdev;

public:
    static constexpr uint8_t SDK_ACL_PROFILE_TYPE_V4 = 1;
    static constexpr uint8_t SDK_ACL_PROFILE_TYPE_V6 = 2;
    static const std::set<sai_acl_action_type_t> supported_ingress_acl_actions_list;
    static const std::set<sai_acl_action_type_t> supported_egress_acl_actions_list;
    obj_db<lasai_acl_table_t> m_acl_table_db;
    obj_db<lasai_acl_entry_t> m_acl_entry_db;
    obj_db<lasai_acl_counter_t> m_acl_counter_db;
    obj_db<lasai_acl_range_t> m_acl_range_db;
    obj_db<lasai_acl_table_group_t> m_acl_table_group_db;
    obj_db<lasai_acl_table_group_member_t> m_acl_table_group_member_db;
    std::unordered_map<sai_object_id_t, lasai_acl_meter_t> m_acl_policers;
    // Object instance used by ACL handler to manage user defined keys and default ACL keys.
    acl_udk m_acl_udk;
};
}
}
#endif // __SAI_ACL_H__
