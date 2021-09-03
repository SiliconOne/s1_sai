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

#include "sai_mpls.h"

#include "common/ranged_index_generator.h"
#include "api/npu/la_lsr.h"
#include "api/system/la_device.h"
#include "api/types/la_mpls_types.h"
#include "sai_device.h"
#include "sai_logger.h"

namespace silicon_one
{
namespace sai
{

// clang-format off
extern const sai_attribute_entry_t inseg_attribs[] = {
    // id; mandatory_on_create; valid_for_create; valid_for_set; valid_for_get
    // *attrib_name; type;
    {SAI_INSEG_ENTRY_ATTR_NUM_OF_POP, false, true, true, true, "Inseg number of pops", SAI_ATTR_VAL_TYPE_U8},
    {SAI_INSEG_ENTRY_ATTR_PACKET_ACTION, false, false, true, true, "Inseg packet action", SAI_ATTR_VAL_TYPE_S32},
    {SAI_INSEG_ENTRY_ATTR_TRAP_PRIORITY, false, false, false, true, "Inseg trap priority", SAI_ATTR_VAL_TYPE_U8},
    {SAI_INSEG_ENTRY_ATTR_NEXT_HOP_ID, false, true, true, true, "Inseg next hop ID", SAI_ATTR_VAL_TYPE_OID},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t inseg_vendor_attribs[] = {
    /* create, remove, set, get */
    {SAI_INSEG_ENTRY_ATTR_NUM_OF_POP,
     {true, false, true, true}, /* implemented */
     {true, false, true, true}, /* supported */
     mpls_handler::inseg_entry_attrib_get, (void *)SAI_INSEG_ENTRY_ATTR_NUM_OF_POP, mpls_handler::inseg_entry_attrib_set, (void *)SAI_INSEG_ENTRY_ATTR_NUM_OF_POP},

    {SAI_INSEG_ENTRY_ATTR_PACKET_ACTION,
     {true, false, true, true},
     {true, false, true, true},
     mpls_handler::inseg_entry_attrib_get, (void *)SAI_INSEG_ENTRY_ATTR_PACKET_ACTION, nullptr, nullptr},

    {SAI_INSEG_ENTRY_ATTR_TRAP_PRIORITY,
     {false, false, false, true},
     {false, false, false, true},
     mpls_handler::inseg_entry_attrib_get, (void *)SAI_INSEG_ENTRY_ATTR_TRAP_PRIORITY, nullptr, nullptr},

    {SAI_INSEG_ENTRY_ATTR_NEXT_HOP_ID,
     {true, false, true, true},
     {true, false, true, true},
     mpls_handler::inseg_entry_attrib_get, (void *)SAI_INSEG_ENTRY_ATTR_NEXT_HOP_ID, mpls_handler::inseg_entry_attrib_set, (void *)SAI_INSEG_ENTRY_ATTR_NEXT_HOP_ID}
};
// clang-format on

static std::string
inseg_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_inseg_entry_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

sai_status_t
mpls_handler::inseg_entry_attrib_get(_In_ const sai_object_key_t* key,
                                     _Inout_ sai_attribute_value_t* value,
                                     _In_ uint32_t attr_index,
                                     _Inout_ vendor_cache_t* cache,
                                     void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    const sai_inseg_entry_t* inseg_entry = &key->key.inseg_entry;
    lsai_object la_sw(inseg_entry->switch_id);
    auto sdev = la_sw.get_device();
    sai_check_object(la_sw, SAI_OBJECT_TYPE_SWITCH, sdev, "switch", inseg_entry->switch_id);
    inseg_params inseg;

    auto exist_inseg = sdev->m_mpls_handler->m_label_map.find(inseg_entry->label);
    if (exist_inseg != sdev->m_mpls_handler->m_label_map.end()) {
        inseg = exist_inseg->second;
    } else {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch ((int64_t)arg) {
    case SAI_INSEG_ENTRY_ATTR_NEXT_HOP_ID:
        set_attr_value(SAI_INSEG_ENTRY_ATTR_NEXT_HOP_ID, (*value), inseg.m_next_hop);
        break;
    case SAI_INSEG_ENTRY_ATTR_PACKET_ACTION:
        set_attr_value(SAI_INSEG_ENTRY_ATTR_PACKET_ACTION, (*value), inseg.m_packet_action);
        break;
    case SAI_INSEG_ENTRY_ATTR_TRAP_PRIORITY:
        set_attr_value(SAI_INSEG_ENTRY_ATTR_TRAP_PRIORITY, (*value), 0);
        break;
    case SAI_INSEG_ENTRY_ATTR_NUM_OF_POP:
        set_attr_value(SAI_INSEG_ENTRY_ATTR_NUM_OF_POP, (*value), inseg.m_num_of_pop);
        break;
    }

    return SAI_STATUS_SUCCESS;
}

la_status
mpls_handler::initialize(transaction& txn, std::shared_ptr<lsai_device> sdev)
{
    sdev->m_dev->set_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e::UNIFORM);
    return LA_STATUS_SUCCESS;
}

la_status
mpls_handler::allocate_gid(uint32_t& out_idx)
{
    out_idx = UINT32_MAX;
    // INVALID_INDEX is uint64_t, so can't compare it against uint32_t
    auto index = m_prefix_object_ids.allocate();
    if (index == ranged_index_generator::INVALID_INDEX) {
        return LA_STATUS_ERESOURCE;
    }
    out_idx = index;
    return LA_STATUS_SUCCESS;
}

void
mpls_handler::release_gid(uint32_t gid)
{
    m_prefix_object_ids.release(gid);
}

la_status
mpls_handler::clear_inseg_entry(la_lsr* lsr, const sai_inseg_entry_t* inseg_entry, bool erase_label)
{
    auto exist_inseg = m_label_map.find(inseg_entry->label);
    if (exist_inseg == m_label_map.end()) {
        return LA_STATUS_EINVAL;
    }

    inseg_params old_inseg = exist_inseg->second;

    if (old_inseg.m_mpls_vpn_decap) {
        lsr->delete_vpn_decap(old_inseg.m_mpls_vpn_decap);
    }
    la_mpls_label label;
    label.label = inseg_entry->label;
    lsr->delete_route(label);

    if (erase_label) {
        m_label_map.erase(inseg_entry->label);
    }
    return LA_STATUS_SUCCESS;
}

sai_status_t
mpls_handler::inseg_entry_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    const sai_inseg_entry_t* inseg_entry = &key->key.inseg_entry;
    lsai_object la_sw(inseg_entry->switch_id);
    auto sdev = la_sw.get_device();
    sai_check_object(la_sw, SAI_OBJECT_TYPE_SWITCH, sdev, "switch", inseg_entry->switch_id);
    inseg_params new_inseg_params;
    sai_packet_action_t action;

    auto exist_inseg = sdev->m_mpls_handler->m_label_map.find(inseg_entry->label);
    if (exist_inseg != sdev->m_mpls_handler->m_label_map.end()) {
        new_inseg_params = exist_inseg->second;
    } else {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_status status;
    switch ((int64_t)arg) {
    case SAI_INSEG_ENTRY_ATTR_NEXT_HOP_ID:
        new_inseg_params.m_next_hop = value->oid;
        break;
    case SAI_INSEG_ENTRY_ATTR_NUM_OF_POP:
        new_inseg_params.m_num_of_pop = value->u32;
        break;
    case SAI_INSEG_ENTRY_ATTR_PACKET_ACTION:
        action = get_attr_value(SAI_INSEG_ENTRY_ATTR_PACKET_ACTION, (*value));
        /* Just stick with the action that was supported till now */
        if (action != SAI_PACKET_ACTION_FORWARD) {
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
        new_inseg_params.m_packet_action = action;
        break;
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    status = sdev->m_mpls_handler->inseg_next_hop_id_set_internal(sdev, inseg_entry, new_inseg_params, false);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

la_status
mpls_handler::inseg_next_hop_id_set_internal(std::shared_ptr<lsai_device> sdev,
                                             const sai_inseg_entry_t* inseg_entry,
                                             inseg_params& new_inseg,
                                             bool erase_label)
{
    la_lsr* lsr;
    bool update_entry = false;
    bool first_time_entry = true;

    // do we already have object in the db?
    inseg_params old_inseg;
    auto exist_inseg = sdev->m_mpls_handler->m_label_map.find(inseg_entry->label);
    if (exist_inseg != sdev->m_mpls_handler->m_label_map.end()) {
        old_inseg = exist_inseg->second;
        first_time_entry = false;
    }

    if (old_inseg.m_num_of_pop != new_inseg.m_num_of_pop) {
        // currently only supported value is 1.
        // only exception is that We allow creating with 0, and later setting to 1.
        if (new_inseg.m_num_of_pop != 1) {
            la_return_on_error_log(LA_STATUS_ENOTIMPLEMENTED, "num of pops must equal 1");
        }
        update_entry = true;
    }

    la_mpls_label la_label;
    la_label.label = inseg_entry->label & 0xfffff;

    la_status status = sdev->m_dev->get_lsr(lsr);
    la_return_on_error(status, "Failed getting lsr");

    transaction txn{};

    if (old_inseg.m_next_hop != new_inseg.m_next_hop) {
        // inserting new entry, or replacing old one
        switch (sai_object_type_query(new_inseg.m_next_hop)) {
        // inseg pointing to router interface. Pop operation.
        case SAI_OBJECT_TYPE_ROUTER_INTERFACE: {
            rif_entry my_rif_entry;
            status = sdev->m_l3_ports.get(new_inseg.m_next_hop, my_rif_entry);
            la_return_on_error(status);

            if (my_rif_entry.type != SAI_ROUTER_INTERFACE_TYPE_MPLS_ROUTER) {
                la_return_on_error(LA_STATUS_EINVAL, "Trying to set inseg entry pointing to wrong router interface type");
            }

            vrf_entry my_vrf_entry{};
            status = sdev->m_vrfs.get(my_rif_entry.vrf_obj, my_vrf_entry);
            la_return_on_error(status);

            if (old_inseg.m_mpls_vpn_decap != nullptr) {
                status = lsr->delete_vpn_decap(old_inseg.m_mpls_vpn_decap);
                la_return_on_error(status, "Failed deleting vpn decap for label %ld", inseg_entry->label);
                // in case add_vpn_encap fail, make sure we are not left with inconsistent state
                new_inseg.m_mpls_vpn_decap = nullptr;
                sdev->m_mpls_handler->m_label_map[inseg_entry->label] = new_inseg;
            }

            status = lsr->add_vpn_decap(la_label, my_vrf_entry.vrf, new_inseg.m_mpls_vpn_decap);
            la_return_on_error(status, "Failed adding vpn decap for label %ld", inseg_entry->label);

            update_entry = true;
        } break;
        case SAI_OBJECT_TYPE_NEXT_HOP: {
            next_hop_entry nh_entry{};
            lsai_object la_obj(new_inseg.m_next_hop);
            la_status status = sdev->m_next_hops.get(la_obj.index, nh_entry);
            la_return_on_error(status, "Failed geting next hop for inseg entry %lx", new_inseg.m_next_hop);

            transaction pref_obj_txn{};

            if (nh_entry.m_prefix_object == nullptr) {
                sdev->alloc_prefix_object(la_obj.index, nh_entry);

                pref_obj_txn.status = sdev->m_next_hops.set(new_inseg.m_next_hop, nh_entry);
                la_return_on_error(status, "Failed changing next hop for inseg entry %lx", new_inseg.m_next_hop);
            }

            if (nh_entry.type == SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP) {
                sai_log_error(SAI_API_MPLS, "TUNNEL next hop has not yet supported 0x%x", new_inseg.m_next_hop);
                return LA_STATUS_EINVAL;
            }

            // if m_labels.size != 0, this is swap, otherwise this is PHP
            txn.status = nh_entry.m_prefix_object->set_nh_lsp_properties(
                nh_entry.next_hop, nh_entry.m_labels, nullptr, la_prefix_object::lsp_counter_mode_e::LABEL);
            la_return_on_error(txn.status, "Failed setting lsp properties for inseg next hop");
            txn.on_fail([=]() { nh_entry.m_prefix_object->clear_nh_lsp_properties(nh_entry.next_hop); });

            la_user_data_t user_data{};
            txn.status = lsr->add_route(la_label, nh_entry.m_prefix_object, user_data);
            la_return_on_error(txn.status, "Failed adding lsr route for inseg next hop");
            txn.on_fail([=]() { lsr->delete_route(la_label); });
            update_entry = true;
            break;
        }
        case SAI_OBJECT_TYPE_NEXT_HOP_GROUP: {
            la_user_data_t user_data{};
            lsai_next_hop_group* nhg_ptr = sdev->m_next_hop_groups.get_ptr(new_inseg.m_next_hop);
            if (nhg_ptr == nullptr || nhg_ptr->m_ecmp_group == nullptr) {
                sai_log_error(SAI_API_MPLS, "Failed geting next hop group for inseg entry %lx", new_inseg.m_next_hop);
                return LA_STATUS_EINVAL;
            }

            clear_inseg_entry(lsr, inseg_entry, erase_label);
            txn.status = lsr->add_route(la_label, nhg_ptr->m_ecmp_group, user_data);
            la_return_on_error(txn.status, "Failed adding lsr route for inseg next hop");
            update_entry = true;
            break;
        }

        case SAI_OBJECT_TYPE_NULL:
            clear_inseg_entry(lsr, inseg_entry, erase_label);
            update_entry = true;
            break;
        default:
            la_return_on_error(LA_STATUS_EINVAL, "unsupported next hop type for inseg entry");
            break;
        }
    }

    if (update_entry || first_time_entry) {
        sdev->m_mpls_handler->m_label_map[inseg_entry->label] = new_inseg;
    }

    return LA_STATUS_SUCCESS;
}

sai_status_t
mpls_handler::create_inseg_entry(const sai_inseg_entry_t* inseg_entry, uint32_t attr_count, const sai_attribute_t* attr_list)
{
    if (!inseg_entry) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_MPLS, SAI_OBJECT_TYPE_SWITCH, inseg_entry->switch_id, &inseg_to_string, inseg_entry, "attrs", attrs);

    sai_object_id_t next_hop_obj{SAI_NULL_OBJECT_ID};
    get_attrs_value(SAI_INSEG_ENTRY_ATTR_NEXT_HOP_ID, attrs, next_hop_obj, false);

    uint8_t num_of_pop = 0;
    get_attrs_value(SAI_INSEG_ENTRY_ATTR_NUM_OF_POP, attrs, num_of_pop, false);

    sai_packet_action_t action{SAI_PACKET_ACTION_FORWARD};
    get_attrs_value(SAI_INSEG_ENTRY_ATTR_PACKET_ACTION, attrs, action, false);

    inseg_params new_inseg(next_hop_obj, num_of_pop, action);

    la_status status = sdev->m_mpls_handler->inseg_next_hop_id_set_internal(sdev, inseg_entry, new_inseg, true);
    sai_return_on_la_error(status);

    sai_log_info(SAI_API_MPLS, "inseg entry 0x%0lx created", inseg_entry);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
mpls_handler::remove_inseg_entry(const sai_inseg_entry_t* inseg_entry)
{
    if (!inseg_entry) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_start_api(SAI_API_MPLS, SAI_OBJECT_TYPE_SWITCH, inseg_entry->switch_id, &inseg_to_string, inseg_entry);

    la_lsr* lsr;
    la_status status = sdev->m_dev->get_lsr(lsr);
    sai_return_on_la_error(status, "Failed getting lsr");

    status = sdev->m_mpls_handler->clear_inseg_entry(lsr, inseg_entry, true);
    sai_return_on_la_error_no_log(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
mpls_handler::set_inseg_entry_attribute(const sai_inseg_entry_t* inseg_entry, const sai_attribute_t* attr)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    if (nullptr == inseg_entry) {
        sai_log_error(SAI_API_MPLS, "NULL inseg_entry param");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    key.key.inseg_entry = *inseg_entry;

    sai_start_api(SAI_API_MPLS, SAI_OBJECT_TYPE_SWITCH, inseg_entry->switch_id, &inseg_to_string, inseg_entry, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "label 0x%0x", inseg_entry->label);
    return sai_set_attribute(&key, key_str, inseg_attribs, inseg_vendor_attribs, attr);
}

sai_status_t
mpls_handler::get_inseg_entry_attribute(const sai_inseg_entry_t* inseg_entry, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    if (nullptr == inseg_entry) {
        sai_log_error(SAI_API_MPLS, "NULL inseg_entry param");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    key.key.inseg_entry = *inseg_entry;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_MPLS, SAI_OBJECT_TYPE_SWITCH, inseg_entry->switch_id, &inseg_to_string, inseg_entry, "attrs", attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "label 0x%0x", inseg_entry->label);
    return sai_get_attributes(&key, key_str, inseg_attribs, inseg_vendor_attribs, attr_count, attr_list);
}

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 8, 0)
//
// Bulk entry support
//

sai_status_t
mpls_handler::create_inseg_entries(uint32_t object_count,
                                   const sai_inseg_entry_t* inseg_entry,
                                   const uint32_t* attr_count,
                                   const sai_attribute_t** attr_list,
                                   sai_bulk_op_error_mode_t mode,
                                   sai_status_t* object_statuses)
{
    bool any_fail = false;
    uint32_t i;

    if (object_count == 0) {
        return SAI_STATUS_SUCCESS;
    }

    if (!inseg_entry || !object_statuses) {
        sai_log_error(SAI_API_MPLS, "create inseg entries: invalid entry or object_status");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (!attr_count || !attr_list) {
        sai_log_error(SAI_API_MPLS, "create inseg entries: invalid attribute count or list");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < object_count; i++) {
        object_statuses[i] = create_inseg_entry(&inseg_entry[i], attr_count[i], attr_list[i]);
        if (object_statuses[i] == SAI_STATUS_SUCCESS) {
            continue;
        }
        any_fail = true;
        if (!continue_on_failure(i + 1, object_count, mode, object_statuses)) {
            break;
        }
    }

    if (any_fail) {
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
mpls_handler::remove_inseg_entries(uint32_t object_count,
                                   const sai_inseg_entry_t* inseg_entry,
                                   sai_bulk_op_error_mode_t mode,
                                   sai_status_t* object_statuses)
{
    bool any_fail = false;
    uint32_t i;

    if (object_count == 0) {
        return SAI_STATUS_SUCCESS;
    }

    if (!inseg_entry || !object_statuses) {
        sai_log_error(SAI_API_MPLS, "remove inseg entries: invalid entry or object_status");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < object_count; i++) {
        object_statuses[i] = remove_inseg_entry(&inseg_entry[i]);
        if (object_statuses[i] == SAI_STATUS_SUCCESS) {
            continue;
        }

        any_fail = true;
        if (!continue_on_failure(i + 1, object_count, mode, object_statuses)) {
            break;
        }
    }

    if (any_fail) {
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
mpls_handler::set_inseg_entries_attribute(uint32_t object_count,
                                          const sai_inseg_entry_t* inseg_entry,
                                          const sai_attribute_t* attr_list,
                                          sai_bulk_op_error_mode_t mode,
                                          sai_status_t* object_statuses)
{
    bool any_fail = false;
    uint32_t i;

    if (object_count == 0) {
        return SAI_STATUS_SUCCESS;
    }

    if (!inseg_entry || !attr_list || !object_statuses) {
        sai_log_error(SAI_API_MPLS, "set inseg entries: invalid entry, list or object_status");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < object_count; i++) {
        object_statuses[i] = set_inseg_entry_attribute(&inseg_entry[i], &attr_list[i]);
        if (object_statuses[i] == SAI_STATUS_SUCCESS) {
            continue;
        }

        any_fail = true;
        if (!continue_on_failure(i + 1, object_count, mode, object_statuses)) {
            break;
        }
    }

    if (any_fail) {
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
mpls_handler::get_inseg_entries_attribute(uint32_t object_count,
                                          const sai_inseg_entry_t* inseg_entry,
                                          const uint32_t* attr_count,
                                          sai_attribute_t** attr_list,
                                          sai_bulk_op_error_mode_t mode,
                                          sai_status_t* object_statuses)
{
    bool any_fail = false;
    uint32_t i;

    if (object_count == 0) {
        sai_log_error(SAI_API_MPLS, "get inseg entries: invalid object count");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (!inseg_entry || !object_statuses) {
        sai_log_error(SAI_API_MPLS, "get inseg entries: invalid entry or object_status");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (!attr_count || !attr_list || !(*attr_list)) {
        sai_log_error(SAI_API_MPLS, "get inseg entries: invalid attribute count or list");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < object_count; i++) {
        object_statuses[i] = get_inseg_entry_attribute(&inseg_entry[i], attr_count[i], attr_list[i]);
        if (object_statuses[i] == SAI_STATUS_SUCCESS) {
            continue;
        }

        any_fail = true;
        if (!continue_on_failure(i + 1, object_count, mode, object_statuses)) {
            break;
        }
    }

    if (any_fail) {
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}
#endif

const sai_mpls_api_t mpls_api = {
    mpls_handler::create_inseg_entry,
    mpls_handler::remove_inseg_entry,
    mpls_handler::set_inseg_entry_attribute,
    mpls_handler::get_inseg_entry_attribute,

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 8, 0)
    mpls_handler::create_inseg_entries,
    mpls_handler::remove_inseg_entries,
    mpls_handler::set_inseg_entries_attribute,
    mpls_handler::get_inseg_entries_attribute,
#endif
};
}
}
