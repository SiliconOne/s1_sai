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

#include "sai_next_hop_group.h"
#include "api/npu/la_l3_ac_port.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_next_hop.h"
#include "api/npu/la_svi_port.h"
#include "api/npu/la_switch.h"
#include "api/npu/la_vrf.h"
#include "api/system/la_device.h"
#include "api/types/la_ip_types.h"
#include "common/ranged_index_generator.h"
#include "common/transaction.h"
#include "sai_device.h"
#include "sai_logger.h"
#include <map>
#include <cinttypes>

namespace silicon_one
{
namespace sai
{

using namespace std;

static sai_status_t next_hop_group_count_get(_In_ const sai_object_key_t* key,
                                             _Inout_ sai_attribute_value_t* value,
                                             _In_ uint32_t attr_index,
                                             _Inout_ vendor_cache_t* cache,
                                             void* arg);
static sai_status_t next_hop_group_type_get(_In_ const sai_object_key_t* key,
                                            _Inout_ sai_attribute_value_t* value,
                                            _In_ uint32_t attr_index,
                                            _Inout_ vendor_cache_t* cache,
                                            void* arg);
static sai_status_t next_hop_group_hop_list_get(_In_ const sai_object_key_t* key,
                                                _Inout_ sai_attribute_value_t* value,
                                                _In_ uint32_t attr_index,
                                                _Inout_ vendor_cache_t* cache,
                                                void* arg);

// clang-format off
extern const sai_attribute_entry_t next_hop_group_attribs[] = {
    {SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_COUNT, false, false, false, true, "Next hop group entries count", SAI_ATTR_VAL_TYPE_U32},
    {SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_MEMBER_LIST, false, false, false, true, "Next hop group hop list", SAI_ATTR_VAL_TYPE_OBJLIST},
    {SAI_NEXT_HOP_GROUP_ATTR_TYPE, true, true, false, true, "Next hop group type", SAI_ATTR_VAL_TYPE_S32},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t next_hop_group_vendor_attribs[] = {
    {SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_COUNT,
     {false, false, false, true},
     {false, false, false, true},
     next_hop_group_count_get, nullptr, nullptr, nullptr},

    {SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_MEMBER_LIST,
     {false, false, false, true},
     {false, false, false, true},
     next_hop_group_hop_list_get, nullptr, nullptr, nullptr},

    {SAI_NEXT_HOP_GROUP_ATTR_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     next_hop_group_type_get, nullptr, nullptr, nullptr},
};
// clang-format on

/* Nexthop-group member attributes */

extern const sai_attribute_entry_t next_hop_group_member_attribs[] = {
    // id, mandatory_on_create, valid_for_create, valid_for_set, valid_for_get
    {SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID, true, true, false, true, "Next hop group oid", SAI_ATTR_VAL_TYPE_OID},
    {SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID, true, true, false, true, "Next hop nexthop oid", SAI_ATTR_VAL_TYPE_OID},
    {SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT, false, true, true, true, "Next hop group member weight", SAI_ATTR_VAL_TYPE_U32},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static sai_status_t next_hop_group_member_attr_get(_In_ const sai_object_key_t* key,
                                                   _Inout_ sai_attribute_value_t* value,
                                                   _In_ uint32_t attr_index,
                                                   _Inout_ vendor_cache_t* cache,
                                                   void* arg);

static sai_status_t next_hop_group_member_weight_set(_In_ const sai_object_key_t* key,
                                                     _In_ const sai_attribute_value_t* value,
                                                     void* arg);

static const sai_vendor_attribute_entry_t next_hop_group_member_vendor_attribs[] = {
    /*
     id,
     {create, remove, set, get}, // implemented
     {create, remove, set, get}, // supported
     getter, getter_arg,
     setter, setter_arg
     */
    {SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID,
     {true, true, false, true},
     {true, true, false, true},
     next_hop_group_member_attr_get,
     (void*)SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID,
     nullptr,
     nullptr},
    {SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID,
     {true, true, false, true},
     {true, true, false, true},
     next_hop_group_member_attr_get,
     (void*)SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID,
     nullptr,
     nullptr},
    {SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT,
     {true, false, true, true},
     {true, false, true, true},
     next_hop_group_member_attr_get,
     (void*)SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT,
     next_hop_group_member_weight_set,
     (void*)SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT},
};

static sai_status_t
next_hop_group_count_get(_In_ const sai_object_key_t* key,
                         _Inout_ sai_attribute_value_t* value,
                         _In_ uint32_t attr_index,
                         _Inout_ vendor_cache_t* cache,
                         void* arg)
{
    lsai_object la_nh_group(key->key.object_id);
    auto sdev = la_nh_group.get_device();
    sai_check_object(la_nh_group, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, sdev, "next hop group", key->key.object_id);

    lsai_next_hop_group* nhg_ptr = sdev->m_next_hop_groups.get_ptr(la_nh_group.index);
    if (nhg_ptr == nullptr || nhg_ptr->m_ecmp_group == nullptr) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "Next hop group does not exist 0x%llx", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_l3_destination_vec_t ecmp_members;
    la_status status = nhg_ptr->m_ecmp_group->get_members(ecmp_members);
    sai_return_on_la_error(status, "Fail to get members for next hop group 0x%lx", key->key.object_id);

    lsai_object la_nh(SAI_OBJECT_TYPE_NEXT_HOP, la_nh_group.switch_id, 0);
    std::vector<sai_object_id_t> output_vec;
    std::transform(ecmp_members.begin(), ecmp_members.end(), back_inserter(output_vec), [&](const la_l3_destination* em) {
        auto nh_ptr = static_cast<const la_next_hop*>(em);
        la_nh.index = nh_ptr->get_gid();
        return la_nh.object_id();
    });
    fill_sai_list(output_vec.begin(), output_vec.end(), value->objlist);
    set_attr_value(SAI_NEXT_HOP_GROUP_ATTR_NEXT_HOP_COUNT, (*value), output_vec.size());
    return SAI_STATUS_SUCCESS;

    // return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
next_hop_group_type_get(_In_ const sai_object_key_t* key,
                        _Inout_ sai_attribute_value_t* value,
                        _In_ uint32_t attr_index,
                        _Inout_ vendor_cache_t* cache,
                        void* arg)
{
    if (key == nullptr || value == nullptr) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "Fail to get next hop group object");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_nh_group(key->key.object_id);
    auto sdev = la_nh_group.get_device();
    sai_check_object(la_nh_group, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, sdev, "next hop group", key->key.object_id);

    lsai_next_hop_group* nhg_ptr = sdev->m_next_hop_groups.get_ptr(la_nh_group.index);
    if (nhg_ptr == nullptr || nhg_ptr->m_ecmp_group == nullptr) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "Next hop group does not exist 0x%llx", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (nhg_ptr->m_ecmp_group != nullptr) {
        set_attr_value(SAI_NEXT_HOP_GROUP_ATTR_TYPE, (*value), SAI_NEXT_HOP_GROUP_TYPE_ECMP);
        return SAI_STATUS_SUCCESS;
    }

    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
next_hop_group_hop_list_get(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg)
{
    lsai_object la_nh_group(key->key.object_id);
    auto sdev = la_nh_group.get_device();
    sai_check_object(la_nh_group, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, sdev, "next hop group", key->key.object_id);

    lsai_next_hop_group* nhg_ptr = sdev->m_next_hop_groups.get_ptr(la_nh_group.index);
    if (nhg_ptr == nullptr || nhg_ptr->m_ecmp_group == nullptr) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "Next hop group does not exist 0x%llx", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return fill_sai_list(nhg_ptr->m_members.begin(), nhg_ptr->m_members.end(), value->objlist);
}

static sai_status_t
next_hop_group_member_attr_get(_In_ const sai_object_key_t* key,
                               _Inout_ sai_attribute_value_t* value,
                               _In_ uint32_t attr_index,
                               _Inout_ vendor_cache_t* cache,
                               void* arg)
{
    if (key == nullptr || value == nullptr) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "Fail to get next hop group object");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_mem(key->key.object_id);
    auto sdev = la_mem.get_device();
    sai_check_object(la_mem, SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER, sdev, "next hop group member", key->key.object_id);

    next_hop_group_member* gm = sdev->m_next_hop_group_members.get_ptr(la_mem.index);
    if (gm == nullptr) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "Next Hop group 0x%llx does not exist.", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch ((int64_t)arg) {
    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID: {
        set_attr_value(SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID, (*value), gm->m_group_oid);
        return SAI_STATUS_SUCCESS;
    }
    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID: {
        set_attr_value(SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID, (*value), gm->m_nexthop_oid);
        return SAI_STATUS_SUCCESS;
    }
    case SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT: {
        set_attr_value(SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT, (*value), gm->m_weight);
        return SAI_STATUS_SUCCESS;
    }
    }

    return SAI_STATUS_NOT_IMPLEMENTED;
}

/// @brief	Set weight of Next Hop member in group by adding multiple ecmp members in ecmp group
static sai_status_t
next_hop_group_member_weight_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "Fail to get next hop group object");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_mem(key->key.object_id);
    auto sdev = la_mem.get_device();
    sai_check_object(la_mem, SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER, sdev, "next hop group member", key->key.object_id);

    auto new_weight = get_attr_value(SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT, (*value));

    next_hop_group_member* gm = sdev->m_next_hop_group_members.get_ptr(la_mem.index);
    if (gm == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_group(gm->m_group_oid);
    lsai_next_hop_group* nhg_ptr = sdev->m_next_hop_groups.get_ptr(la_group.index);
    if (nhg_ptr == nullptr || nhg_ptr->m_ecmp_group == nullptr) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "next hop group 0x%llx does not exist", gm->m_group_oid);
        return SAI_STATUS_FAILURE;
    }

    lsai_object la_nexthop(gm->m_nexthop_oid);
    next_hop_entry* nh_entry = sdev->m_next_hops.get_ptr(la_nexthop.index);
    if (nh_entry == nullptr) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "next hop 0x%llx does not exist", gm->m_nexthop_oid);
        return SAI_STATUS_FAILURE;
    }

    transaction txn{};

    la_l3_destination* nh_entry_member = nullptr;

    if (nh_entry->type == SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "Tunnel next hop as a group member is not supported 0x%x", gm->m_nexthop_oid);
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    if (nh_entry->has_mpls_labels()) {
        nh_entry_member = nh_entry->m_prefix_object;
    } else {
        nh_entry_member = nh_entry->next_hop;
    }

    if (nh_entry_member == nullptr) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    sai_log_debug(SAI_API_NEXT_HOP_GROUP,
                  "Set member weight, member (%s), change weight(%d) to (%d).",
                  to_string(nh_entry_member).c_str(),
                  gm->m_weight,
                  new_weight);

    // removed weight or add weight only if needed.
    if (gm->m_weight > new_weight) {
        // new weight is less than old weight, remove the extra members.
        for (; gm->m_weight > new_weight; gm->m_weight--) {
            nhg_ptr->m_ecmp_group->remove_member(nh_entry_member);
            if (nhg_ptr->m_ecmp_group_stage_2 != nullptr) {
                nhg_ptr->m_ecmp_group_stage_2->remove_member(nh_entry_member);
            }
        }
    } else if (gm->m_weight < new_weight) {
        // new weight is more than old weight, add more members
        for (; gm->m_weight < new_weight; ++gm->m_weight) {
            txn.status = nhg_ptr->m_ecmp_group->add_member(nh_entry_member);
            sai_return_on_la_error(
                txn.status, "Failed adding (%s) ecmp group member at weight %d", to_string(nh_entry_member).c_str(), gm->m_weight);
            txn.on_fail([=]() { nhg_ptr->m_ecmp_group->remove_member(nh_entry_member); });
            if (nhg_ptr->m_ecmp_group_stage_2 != nullptr) {
                txn.status = nhg_ptr->m_ecmp_group_stage_2->add_member(nh_entry_member);
                sai_return_on_la_error(txn.status,
                                       "Failed adding (%s) stage 2 ecmp group member at weight %d",
                                       to_string(nh_entry_member).c_str(),
                                       gm->m_weight);
                txn.on_fail([=]() { nhg_ptr->m_ecmp_group_stage_2->remove_member(nh_entry_member); });
            }
        }
    } // else, no need to do anything

    sai_log_debug(SAI_API_NEXT_HOP_GROUP, "next hop group member 0x%lx, weight is set to (%d).", key->key.object_id, gm->m_weight);
    return SAI_STATUS_SUCCESS;
}

static std::string
nexthopgroup_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_next_hop_group_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static std::string
nexthopgroupmem_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_next_hop_group_member_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

/*
 * create a new stage2 ecmp group and add all members of existing group to it
 */
sai_status_t
lsai_next_hop_group::create_tunnel_next_hop_group(std::shared_ptr<lsai_device> sdev)
{
    la_ecmp_group* ecmp_group_stage_2 = nullptr;

    transaction txn{};

    txn.status = sdev->m_dev->create_ecmp_group(la_ecmp_group::level_e::LEVEL_2, ecmp_group_stage_2);
    if (txn.status) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "Fail to create ecmp group %s", txn.status.message().c_str());
        return to_sai_status(txn.status);
    }
    txn.on_fail([=]() { sdev->m_dev->destroy(ecmp_group_stage_2); });

    sai_log_debug(SAI_API_NEXT_HOP_GROUP, "Creating level2 ecmp group for Tunnel NH");
    for (auto nhm_it : m_members) {
        lsai_object la_nhm(nhm_it);
        next_hop_group_member* nhg_mem_ptr = sdev->m_next_hop_group_members.get_ptr(la_nhm.index);
        lsai_object la_nexthop(nhg_mem_ptr->m_nexthop_oid);
        next_hop_entry* nh_entry = sdev->m_next_hops.get_ptr(la_nexthop.index);
        if (nh_entry == nullptr || nh_entry->next_hop == nullptr) {
            sai_log_error(SAI_API_NEXT_HOP_GROUP, "next hop 0x%" PRIx64 " does not exist", nhg_mem_ptr->m_nexthop_oid);
            return SAI_STATUS_FAILURE;
        }

        for (sai_uint32_t idx = 0; idx < nhg_mem_ptr->m_weight; ++idx) {
            txn.status = ecmp_group_stage_2->add_member(nh_entry->next_hop);
            sai_return_on_la_error(
                txn.status, "Failed adding (%s) ecmp group member at weight %d", to_string(nh_entry->next_hop).c_str(), idx);
        }
    }

    m_ecmp_group_stage_2 = ecmp_group_stage_2;
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
create_next_hop_group(sai_object_id_t* next_hop_group_id,
                      sai_object_id_t obj_switch_id,
                      uint32_t attr_count,
                      const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_NEXT_HOP_GROUP, SAI_OBJECT_TYPE_SWITCH, obj_switch_id, &nexthopgroup_to_string, obj_switch_id, attrs);

    sai_next_hop_group_type_t nh_group_type{};
    {
        get_attrs_value(SAI_NEXT_HOP_GROUP_ATTR_TYPE, attrs, nh_group_type, true);
    }

    if (nh_group_type != SAI_NEXT_HOP_GROUP_TYPE_ECMP) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "Only support the ecmp for nexthop group");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    transaction txn{};

    la_ecmp_group* ecmp_group = nullptr;
    txn.status = sdev->m_dev->create_ecmp_group(la_ecmp_group::level_e::LEVEL_1, ecmp_group);
    if (txn.status) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "Fail to create ecmp group %s", txn.status.message().c_str());
        return to_sai_status(txn.status);
    }
    txn.on_fail([=]() { sdev->m_dev->destroy(ecmp_group); });

    uint32_t index = 0;
    txn.status = sdev->m_next_hop_groups.allocate_id(index);
    sai_return_on_la_error(txn.status, "Fail to allocate ecmp group id");
    txn.on_fail([=]() { sdev->m_next_hop_groups.release_id(index); });

    lsai_object la_group(SAI_OBJECT_TYPE_NEXT_HOP_GROUP, la_obj.index, index);
    lsai_next_hop_group nhg_entry(ecmp_group);

    txn.status = sdev->m_next_hop_groups.set(*next_hop_group_id, nhg_entry, la_group);
    sai_return_on_la_error(txn.status);
    sai_log_debug(SAI_API_NEXT_HOP_GROUP, "next hop group 0x%lx created", *next_hop_group_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_next_hop_group(sai_object_id_t next_hop_group_id)
{
    sai_start_api(
        SAI_API_NEXT_HOP_GROUP, SAI_OBJECT_TYPE_NEXT_HOP_GROUP, next_hop_group_id, &nexthopgroup_to_string, next_hop_group_id);

    lsai_next_hop_group* nhg_ptr = sdev->m_next_hop_groups.get_ptr(la_obj.index);
    if (nhg_ptr == nullptr || nhg_ptr->m_ecmp_group == nullptr) {
        // next hop group already removed.
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "next hop group 0x%llx does not exist", next_hop_group_id);
        return SAI_STATUS_SUCCESS;
    }

    for (auto nhm_it = nhg_ptr->m_members.begin(); nhm_it != nhg_ptr->m_members.end(); nhm_it++) {
        lsai_object la_nhm(*nhm_it);
        if (la_nhm.type != SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER) {
            sai_log_error(SAI_API_NEXT_HOP_GROUP, "invalid next hop group member 0x%llx", *nhm_it);
            return SAI_STATUS_FAILURE;
        }
        next_hop_group_member* nhg_mem_ptr = sdev->m_next_hop_group_members.get_ptr(la_nhm.index);
        if (nhg_ptr->m_ecmp_group != nullptr && nhg_mem_ptr != nullptr) {
            lsai_object la_nexthop(nhg_mem_ptr->m_nexthop_oid);
            next_hop_entry* nh_entry = sdev->m_next_hops.get_ptr(la_nexthop.index);
            if (nh_entry == nullptr || nh_entry->next_hop == nullptr) {
                sai_log_error(SAI_API_NEXT_HOP_GROUP, "next hop 0x%llx does not exist", nhg_mem_ptr->m_nexthop_oid);
                return SAI_STATUS_FAILURE;
            }
            nhg_ptr->m_ecmp_group->remove_member(nh_entry->next_hop);
            if (nhg_ptr->m_ecmp_group_stage_2 != nullptr) {
                nhg_ptr->m_ecmp_group_stage_2->remove_member(nh_entry->next_hop);
            }
        }
        nhg_ptr->m_members.erase(*nhm_it);
    }

    la_status status;

    // delete the ecmp group
    if (nhg_ptr->m_ecmp_group != nullptr) {
        status = sdev->m_dev->destroy(nhg_ptr->m_ecmp_group);
        sai_return_on_la_error(status, "Fail to destroy ecmp_group 0x%lx", next_hop_group_id);
    }

    if (nhg_ptr->m_ecmp_group_stage_2 != nullptr) {
        status = sdev->m_dev->destroy(nhg_ptr->m_ecmp_group_stage_2);
        sai_return_on_la_error(status, "Fail to destroy stage 2 ecmp_group 0x%lx", next_hop_group_id);
    }

    status = sdev->m_next_hop_groups.remove(next_hop_group_id);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_next_hop_group_attribute(sai_object_id_t next_hop_group_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = next_hop_group_id;

    sai_start_api(SAI_API_NEXT_HOP_GROUP,
                  SAI_OBJECT_TYPE_NEXT_HOP_GROUP,
                  next_hop_group_id,
                  &nexthopgroup_to_string,
                  next_hop_group_id,
                  *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "next hop group 0x%lx", next_hop_group_id);
    return sai_set_attribute(&key, key_str, next_hop_group_attribs, next_hop_group_vendor_attribs, attr);
}

static sai_status_t
get_next_hop_group_attribute(sai_object_id_t next_hop_group_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = next_hop_group_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_NEXT_HOP_GROUP,
                  SAI_OBJECT_TYPE_NEXT_HOP_GROUP,
                  next_hop_group_id,
                  &nexthopgroup_to_string,
                  next_hop_group_id,
                  attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "next hop group 0x%lx", next_hop_group_id);
    return sai_get_attributes(&key, key_str, next_hop_group_attribs, next_hop_group_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
create_next_hop_group_member_internal(sai_object_id_t* next_hop_group_member_id,
                                      const std::unordered_map<sai_attr_id_t, sai_attribute_value_t>& attrs,
                                      uint32_t switch_id,
                                      std::shared_ptr<silicon_one::sai::lsai_device>& sdev)
{
    sai_object_id_t obj_nexthopgroup_id{};
    get_attrs_value(SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID, attrs, obj_nexthopgroup_id, true);

    lsai_object la_grp(obj_nexthopgroup_id);
    if (la_grp.type != SAI_OBJECT_TYPE_NEXT_HOP_GROUP) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP,
                      "Object 0x%llx provided as SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID is not next hop group",
                      obj_nexthopgroup_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    lsai_next_hop_group* nhg_ptr = sdev->m_next_hop_groups.get_ptr(la_grp.index);
    if (nhg_ptr == nullptr || nhg_ptr->m_ecmp_group == nullptr) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "next hop group 0x%llx does not exist", obj_nexthopgroup_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_object_id_t obj_nexthop_id{};
    get_attrs_value(SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID, attrs, obj_nexthop_id, true);
    lsai_object la_nh(obj_nexthop_id);
    if (la_nh.type != SAI_OBJECT_TYPE_NEXT_HOP) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP,
                      "Object 0x%llx provided as SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID is not next hop group",
                      obj_nexthop_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    next_hop_entry* nh_entry = sdev->m_next_hops.get_ptr(la_nh.index);
    if (nh_entry == nullptr) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "next hop 0x%llx does not exist", obj_nexthop_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_uint32_t nh_mem_weight = 1;
    get_attrs_value(SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT, attrs, nh_mem_weight, false);

    transaction txn{};

    la_l3_destination* nh_entry_member = nullptr;

    /* 210719 16:31
     * this support has been added recently.. so condition can be removed after validating
     */
    if (nh_entry->type == SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "Tunnel next hop as a group member is not supported 0x%x", obj_nexthop_id);
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    // If we have labels, it is an MPLS next hop
    if (nh_entry->has_mpls_labels()) {
        if (nh_entry->m_prefix_object == nullptr) {
            txn.status = sdev->alloc_prefix_object(la_nh.index, *nh_entry);
            sai_return_on_la_error(txn.status, "Failed allocating prefix object");
            txn.on_fail([=]() { sdev->release_prefix_object(la_nh.index, *nh_entry); });
        }

        txn.status = nh_entry->m_prefix_object->set_nh_lsp_properties(
            nh_entry->next_hop, nh_entry->m_labels, nullptr, la_prefix_object::lsp_counter_mode_e::LABEL);
        sai_return_on_la_error(txn.status, "Failed setting lsp properties for next hop group member");
        txn.on_fail([=]() { nh_entry->m_prefix_object->clear_nh_lsp_properties(nh_entry->next_hop); });

        nh_entry_member = nh_entry->m_prefix_object;
    } else {
        nh_entry_member = nh_entry->next_hop;
    }

    if (nh_entry_member == nullptr) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    // Add multiple ecmp member in ecmp group as increasing weight of the Next Hop Group member
    // Weight of Next Hop Group member == Number of duplicated members in ecmp group.
    sai_log_debug(
        SAI_API_NEXT_HOP_GROUP, "Set member weight, member (%s), to (%d).", to_string(nh_entry_member).c_str(), nh_mem_weight);
    for (sai_uint32_t idx = 0; idx < nh_mem_weight; ++idx) {
        txn.status = nhg_ptr->m_ecmp_group->add_member(nh_entry_member);
        sai_return_on_la_error(
            txn.status, "Failed adding (%s) ecmp group member at weight %d", to_string(nh_entry_member).c_str(), idx);
        txn.on_fail([=]() { nhg_ptr->m_ecmp_group->remove_member(nh_entry_member); });
        if (nhg_ptr->m_ecmp_group_stage_2 != nullptr) {
            txn.status = nhg_ptr->m_ecmp_group_stage_2->add_member(nh_entry_member);
            sai_return_on_la_error(
                txn.status, "Failed adding (%s) stage 2 ecmp group member at weight %d", to_string(nh_entry_member).c_str(), idx);
            txn.on_fail([=]() { nhg_ptr->m_ecmp_group_stage_2->remove_member(nh_entry_member); });
        }
    }

    uint32_t la_mem_id;
    txn.status = sdev->m_next_hop_group_members.allocate_id(la_mem_id);
    sai_return_on_la_error(txn.status, "Fail to allocate group member id");
    txn.on_fail([=]() { sdev->m_next_hop_group_members.release_id(la_mem_id); });

    lsai_object la_mem(SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER, switch_id, la_mem_id);
    next_hop_group_member gm;
    gm.m_group_oid = obj_nexthopgroup_id;
    gm.m_nexthop_oid = obj_nexthop_id;
    gm.m_weight = nh_mem_weight;
    txn.status = sdev->m_next_hop_group_members.set(*next_hop_group_member_id, gm, la_mem);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_next_hop_group_members.remove(*next_hop_group_member_id); });

    nhg_ptr->m_members.insert(*next_hop_group_member_id);

    sai_log_info(SAI_API_NEXT_HOP_GROUP, "next hop group member 0x%lx created", *next_hop_group_member_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
create_next_hop_group_member(sai_object_id_t* next_hop_group_member_id,
                             sai_object_id_t switch_id,
                             uint32_t attr_count,
                             const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_NEXT_HOP_GROUP, SAI_OBJECT_TYPE_SWITCH, switch_id, &nexthopgroupmem_to_string, attrs);

    return create_next_hop_group_member_internal(next_hop_group_member_id, attrs, la_obj.index, sdev);
}

static sai_status_t
remove_next_hop_group_member_internal(sai_object_id_t next_hop_group_member_id,
                                      std::shared_ptr<silicon_one::sai::lsai_device>& sdev)
{
    lsai_object la_obj(next_hop_group_member_id);

    next_hop_group_member* gm = sdev->m_next_hop_group_members.get_ptr(la_obj.index);
    if (gm == nullptr) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "next hop group member 0x%llx does not exist", next_hop_group_member_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_group(gm->m_group_oid);
    lsai_next_hop_group* nhg_ptr = sdev->m_next_hop_groups.get_ptr(la_group.index);
    if (nhg_ptr == nullptr || nhg_ptr->m_ecmp_group == nullptr) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "next hop group 0x%llx does not exist", gm->m_group_oid);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_nexthop(gm->m_nexthop_oid);
    next_hop_entry* nh_entry = sdev->m_next_hops.get_ptr(gm->m_nexthop_oid);
    if (nh_entry == nullptr) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "next hop 0x%llx does not exist", gm->m_nexthop_oid);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (nh_entry->type == SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP) {
        sai_log_error(SAI_API_NEXT_HOP_GROUP, "Tunnel next hop as a group member is not supported 0x%x", gm->m_nexthop_oid);
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    la_l3_destination* nh_entry_member = nullptr;
    if (nh_entry->has_mpls_labels()) {
        nh_entry_member = nh_entry->m_prefix_object;
    } else {
        nh_entry_member = nh_entry->next_hop;
    }

    if (nh_entry_member == nullptr) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    sai_log_debug(SAI_API_NEXT_HOP_GROUP, "Remove member (%s), weight (%d).", to_string(nh_entry_member).c_str(), gm->m_weight);

    // remove all entries in ecmp_group. Note: weight == number of entries
    for (; gm->m_weight > 0; gm->m_weight--) {
        nhg_ptr->m_ecmp_group->remove_member(nh_entry_member);
        if (nhg_ptr->m_ecmp_group_stage_2 != nullptr) {
            nhg_ptr->m_ecmp_group_stage_2->remove_member(nh_entry_member);
        }
    }
    nhg_ptr->m_members.erase(next_hop_group_member_id);

    // not clearing below, because it might be needed by other group member. Maybe need reference count?
    // nh_entry.m_prefix_object->clear_nh_lsp_properties(nh_entry.next_hop);

    la_status status = sdev->m_next_hop_group_members.remove(next_hop_group_member_id);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_next_hop_group_member(sai_object_id_t next_hop_group_member_id)
{
    sai_start_api(SAI_API_NEXT_HOP_GROUP,
                  SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER,
                  next_hop_group_member_id,
                  &nexthopgroupmem_to_string,
                  next_hop_group_member_id);

    return remove_next_hop_group_member_internal(next_hop_group_member_id, sdev);
}

static sai_status_t
set_next_hop_group_member_attribute(sai_object_id_t next_hop_group_member_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = next_hop_group_member_id;

    sai_start_api(SAI_API_NEXT_HOP_GROUP,
                  SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER,
                  next_hop_group_member_id,
                  &nexthopgroupmem_to_string,
                  next_hop_group_member_id,
                  *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "next hop group member 0x%lx", next_hop_group_member_id);
    return sai_set_attribute(&key, key_str, next_hop_group_member_attribs, next_hop_group_member_vendor_attribs, attr);
}

static sai_status_t
get_next_hop_group_member_attribute(sai_object_id_t next_hop_group_member_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = next_hop_group_member_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_NEXT_HOP_GROUP,
                  SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER,
                  next_hop_group_member_id,
                  &nexthopgroupmem_to_string,
                  next_hop_group_member_id,
                  attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "next hop group member 0x%lx", next_hop_group_member_id);

    return sai_get_attributes(
        &key, key_str, next_hop_group_member_attribs, next_hop_group_member_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
create_next_hop_group_members(_In_ sai_object_id_t switch_id,
                              _In_ uint32_t object_count,
                              _In_ const uint32_t* attr_count,
                              _In_ const sai_attribute_t** attr_list,
                              _In_ sai_bulk_op_error_mode_t mode,
                              _Out_ sai_object_id_t* object_ids,
                              _Out_ sai_status_t* object_statuses)
{
    sai_status_t ret_status = SAI_STATUS_SUCCESS;
    sai_status_t status;

    sai_start_api_no_log(SAI_API_NEXT_HOP_GROUP, SAI_OBJECT_TYPE_SWITCH, switch_id);

    for (uint32_t i = 0; i < object_count; i++) {
        auto attrs = sai_parse_attributes(attr_count[i], attr_list[i]);
        sai_bulk_api_log(SAI_API_NEXT_HOP_GROUP, &nexthopgroupmem_to_string, attrs);
        status = create_next_hop_group_member_internal(&object_ids[i], attrs, la_obj.index, sdev);
        object_statuses[i] = status;
        if (status != SAI_STATUS_SUCCESS) {
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                for (uint32_t j = i + 1; j < object_count; j++) {
                    object_statuses[j] = SAI_STATUS_NOT_EXECUTED;
                }
                return SAI_STATUS_FAILURE;
            } else {
                ret_status = SAI_STATUS_FAILURE;
            }
        }
    }

    return ret_status;
}

static sai_status_t
remove_next_hop_group_members(_In_ uint32_t object_count,
                              _In_ const sai_object_id_t* object_ids,
                              _In_ sai_bulk_op_error_mode_t mode,
                              _Out_ sai_status_t* object_statuses)

{
    sai_start_api_no_log(SAI_API_NEXT_HOP_GROUP, SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER, object_ids[0]);

    sai_status_t ret_status = SAI_STATUS_SUCCESS;
    sai_status_t status;

    for (uint32_t i = 0; i < object_count; i++) {
        sai_log_message(SAI_API_NEXT_HOP_GROUP, SAI_LOG_LEVEL_INFO, "remove_next_hop_group_members %d %lx", i, object_ids[i]);
        status = remove_next_hop_group_member_internal(object_ids[i], sdev);
        object_statuses[i] = status;

        if (status != SAI_STATUS_SUCCESS) {
            if (mode == SAI_BULK_OP_ERROR_MODE_STOP_ON_ERROR) {
                for (uint32_t j = i + 1; j < object_count; j++) {
                    object_statuses[j] = SAI_STATUS_NOT_EXECUTED;
                }
                return SAI_STATUS_FAILURE;
            } else {
                ret_status = SAI_STATUS_FAILURE;
            }
        }
    }

    return ret_status;
}

const sai_next_hop_group_api_t next_hop_group_api = {create_next_hop_group,
                                                     remove_next_hop_group,
                                                     set_next_hop_group_attribute,
                                                     get_next_hop_group_attribute,
                                                     create_next_hop_group_member,
                                                     remove_next_hop_group_member,
                                                     set_next_hop_group_member_attribute,
                                                     get_next_hop_group_member_attribute,
                                                     create_next_hop_group_members,
                                                     remove_next_hop_group_members};
};
}
