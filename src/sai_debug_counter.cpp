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

#include "api/types/la_event_types.h"
#include "api/npu/la_counter_set.h"
#include "api/types/la_limit_types.h"
#include "api/types/la_common_types.h"
#include "sai_device.h"
#include "sai_logger.h"

#include "sai_debug_counter.h"

namespace silicon_one
{
namespace sai
{

debug_counter_manager::debug_counter_manager(std::shared_ptr<lsai_device> sai_dev) : m_sai_device(sai_dev)
{
}

extern const sai_attribute_entry_t debug_counter_attribs[] = {
    // id; mandatory_on_create; valid_for_create; valid_for_set; valid_for_get
    // *attrib_name; type;
    {SAI_DEBUG_COUNTER_ATTR_INDEX, false, false, false, true, "debug counter index", SAI_ATTR_VAL_TYPE_U32},
    {SAI_DEBUG_COUNTER_ATTR_TYPE, true, true, false, true, "debug counter type", SAI_ATTR_VAL_TYPE_S32},
    {SAI_DEBUG_COUNTER_ATTR_BIND_METHOD, false, true, false, true, "debug counter bind method", SAI_ATTR_VAL_TYPE_S32},
    {SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST,
     false,
     true,
     true,
     true,
     "debug counter in drop reason",
     SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_DEBUG_COUNTER_ATTR_OUT_DROP_REASON_LIST,
     false,
     true,
     true,
     true,
     "debug counter out drop reason",
     SAI_ATTR_VAL_TYPE_S32LIST},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t debug_counter_vendor_attribs[] = {
    /* create, remove, set, get */
    {SAI_DEBUG_COUNTER_ATTR_INDEX,
     {false, false, false, true}, /* implemented */
     {false, false, false, true}, /* supported */
     debug_counter_manager::debug_counter_attr_get,
     (void*)SAI_DEBUG_COUNTER_ATTR_INDEX,
     nullptr,
     nullptr},
    {SAI_DEBUG_COUNTER_ATTR_TYPE,
     {true, false, false, true}, /* implemented */
     {true, false, false, true}, /* supported */
     debug_counter_manager::debug_counter_attr_get,
     (void*)SAI_DEBUG_COUNTER_ATTR_TYPE,
     nullptr,
     nullptr},
    {SAI_DEBUG_COUNTER_ATTR_BIND_METHOD,
     {true, false, false, true}, /* implemented */
     {true, false, false, true}, /* supported */
     debug_counter_manager::debug_counter_attr_get,
     (void*)SAI_DEBUG_COUNTER_ATTR_BIND_METHOD,
     nullptr,
     nullptr},
    {SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST,
     {true, false, true, true}, /* implemented */
     {true, false, true, true}, /* supported */
     debug_counter_manager::debug_counter_attr_get,
     (void*)SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST,
     debug_counter_manager::debug_counter_attr_set,
     (void*)SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST},
    {SAI_DEBUG_COUNTER_ATTR_OUT_DROP_REASON_LIST,
     {true, false, true, true}, /* implemented */
     {true, false, true, true}, /* supported */
     debug_counter_manager::debug_counter_attr_get,
     (void*)SAI_DEBUG_COUNTER_ATTR_OUT_DROP_REASON_LIST,
     debug_counter_manager::debug_counter_attr_set,
     (void*)SAI_DEBUG_COUNTER_ATTR_OUT_DROP_REASON_LIST}};

std::string
debug_counter_manager::debug_counter_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_debug_counter_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

std::set<la_event_e> debug_counter_val_getter::m_la_event_names;

sai_status_t
debug_counter_val_getter::default_counter_val_getter(std::shared_ptr<lsai_device> sdev,
                                                     const std::vector<la_event_e>& arg_list,
                                                     sai_stats_mode_t mode,
                                                     uint64_t& out_val,
                                                     bool is_port_count,
                                                     la_slice_ifg slice_ifg)
{
    out_val = 0;
    uint64_t one_out_val;
    la_status status;

    for (auto one_arg : arg_list) {
        status = sdev->m_debug_counter_handler->get_sdk_counter_val(sdev, one_arg, mode, one_out_val, is_port_count, slice_ifg);
        sai_return_on_la_error(status);

        out_val += one_out_val;
    }

    return SAI_STATUS_SUCCESS;
}

void
debug_counter_entry::update_drop_reason_list(const sai_s32_list_t& drop_reason_list)
{
    m_drop_reason_list.clear();

    for (uint32_t i = 0; i < drop_reason_list.count; i++) {
        m_drop_reason_list.push_back(drop_reason_list.list[i]);
    }
}

la_status
debug_counter_manager::get_sdk_counter_val(const std::shared_ptr<lsai_device>& sdev,
                                           uint32_t sdk_event,
                                           sai_stats_mode_t mode,
                                           uint64_t& out_val,
                                           bool is_port_count,
                                           la_slice_ifg slice_ifg)
{
    la_counter_set* counter_set = m_sai_device->m_event_counters[(la_event_e)sdk_event];
    size_t out_bytes;
    bool clear_on_read = mode == SAI_STATS_MODE_READ_AND_CLEAR ? true : false;
    out_val = 0;
    la_status status;
    for (la_uint_t i = 0; i < counter_set->get_set_size(); i++) {
        size_t curr_out_val = 0;
        if (is_port_count) {
            status = counter_set->read(
                slice_ifg, i, sdev->m_force_update /* force_update */, clear_on_read /* clear_on_read */, curr_out_val, out_bytes);
        } else {
            status = counter_set->read(
                i, sdev->m_force_update /* force_update */, clear_on_read /* clear_on_read */, curr_out_val, out_bytes);
        }
        la_return_on_error(status);
        out_val += curr_out_val;
    }
    return status;
}

sai_status_t
debug_counter_manager::get_counter_value(sai_stat_id_t idx,
                                         sai_stats_mode_t mode,
                                         uint64_t& out_val,
                                         bool is_port_count,
                                         la_slice_ifg slice_ifg)
{
    out_val = 0;
    debug_counter_entry counter_entry;
    if (is_port_count) {
        if (idx <= SAI_PORT_STAT_IN_DROP_REASON_RANGE_END && idx >= SAI_PORT_STAT_IN_DROP_REASON_RANGE_BASE) {
            idx -= SAI_PORT_STAT_IN_DROP_REASON_RANGE_BASE;
        } else {
            if (idx <= SAI_PORT_STAT_OUT_DROP_REASON_RANGE_END && idx >= SAI_PORT_STAT_OUT_DROP_REASON_RANGE_BASE) {
                idx -= SAI_PORT_STAT_OUT_DROP_REASON_RANGE_BASE;
            } else {
                sai_log_error(SAI_API_DEBUG_COUNTER, "counter index %lu not in supported range", idx);
                return SAI_STATUS_INVALID_PARAMETER;
            }
        }
    } else {
        if (idx <= SAI_SWITCH_STAT_IN_DROP_REASON_RANGE_END && idx >= SAI_SWITCH_STAT_IN_DROP_REASON_RANGE_BASE) {
            idx -= SAI_SWITCH_STAT_IN_DROP_REASON_RANGE_BASE;
        } else {
            if (idx <= SAI_SWITCH_STAT_OUT_DROP_REASON_RANGE_END && idx >= SAI_SWITCH_STAT_OUT_DROP_REASON_RANGE_BASE) {
                idx -= SAI_SWITCH_STAT_OUT_DROP_REASON_RANGE_BASE;
            } else {
                sai_log_error(SAI_API_DEBUG_COUNTER, "counter index %lu not in supported range", idx);
                return SAI_STATUS_INVALID_PARAMETER;
            }
        }
    }

    la_status status = m_debug_counter_db.get(idx, counter_entry);
    sai_return_on_la_error(status, "Failed finding debug counter with index %ld", idx);

    debug_counter_val_getter val_getter;
    for (auto drop_reason : counter_entry.m_drop_reason_list) {
        uint64_t one_out_val = 0;

        switch (counter_entry.m_type) {
        case SAI_DEBUG_COUNTER_TYPE_SWITCH_IN_DROP_REASONS:
        case SAI_DEBUG_COUNTER_TYPE_PORT_IN_DROP_REASONS:
            val_getter = m_sai_to_la_counter_translation_in.at(drop_reason);
            break;
        case SAI_DEBUG_COUNTER_TYPE_SWITCH_OUT_DROP_REASONS:
        case SAI_DEBUG_COUNTER_TYPE_PORT_OUT_DROP_REASONS:
            val_getter = m_sai_to_la_counter_translation_out.at(drop_reason);
            break;
        default:
            return SAI_STATUS_INVALID_PARAMETER;
        }

        if (val_getter.m_get_val_func != nullptr) {
            sai_status_t sstatus
                = val_getter.m_get_val_func(m_sai_device, val_getter.m_arg, mode, one_out_val, is_port_count, slice_ifg);
            sai_return_on_error(sstatus, "Failed getting debug counter for index lu", idx);
        } else {
            return SAI_STATUS_INVALID_PARAMETER;
        }

        out_val += one_out_val;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
debug_counter_manager::query_attribute_enum_values_capability(sai_attr_id_t attr_id, sai_s32_list_t* enum_values_capability)
{
    auto list_size = m_sai_to_la_counter_translation_in.size();
    auto iter_start = m_sai_to_la_counter_translation_in.cbegin();
    auto iter_end = m_sai_to_la_counter_translation_in.cend();

    switch (attr_id) {
    case SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST:
        // Initiated at start for the 'auto' to work
        break;
    case SAI_DEBUG_COUNTER_ATTR_OUT_DROP_REASON_LIST:
        list_size = m_sai_to_la_counter_translation_out.size();
        iter_start = m_sai_to_la_counter_translation_out.cbegin();
        iter_end = m_sai_to_la_counter_translation_out.cend();
        break;
    default:
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (enum_values_capability->count < list_size) {
        enum_values_capability->count = list_size;
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    enum_values_capability->count = list_size;

    int index = 0;
    for (auto& iter = iter_start; iter != iter_end; iter++) {
        enum_values_capability->list[index++] = iter->first;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
debug_counter_manager::debug_counter_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object debug_counter_obj(key->key.object_id);
    auto sdev = debug_counter_obj.get_device();

    sai_check_object(debug_counter_obj, SAI_OBJECT_TYPE_DEBUG_COUNTER, sdev, "debug counter", key->key.object_id);

    debug_counter_entry counter_entry;
    la_status status = sdev->m_debug_counter_handler->m_debug_counter_db.get(debug_counter_obj.index, counter_entry);
    sai_return_on_la_error(status, "Failed finding debug counter with object id %ld", key->key.object_id);

    switch ((int64_t)arg) {
    case SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST:
    case SAI_DEBUG_COUNTER_ATTR_OUT_DROP_REASON_LIST:
        if (!sdev->m_debug_counter_handler->are_supported_drop_reasons(value->s32list)) {
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
        counter_entry.update_drop_reason_list(value->s32list);
        status = sdev->m_debug_counter_handler->m_debug_counter_db.set(debug_counter_obj.index, counter_entry);
        sai_return_on_la_error(status, "Failed updating drop reason list for debug counter %ld", key->key.object_id);
        break;
    default:
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
debug_counter_manager::debug_counter_attr_get(_In_ const sai_object_key_t* key,
                                              _Inout_ sai_attribute_value_t* value,
                                              _In_ uint32_t attr_index,
                                              _Inout_ vendor_cache_t* cache,
                                              void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object debug_counter_obj(key->key.object_id);
    auto sdev = debug_counter_obj.get_device();

    sai_check_object(debug_counter_obj, SAI_OBJECT_TYPE_DEBUG_COUNTER, sdev, "debug counter", key->key.object_id);

    debug_counter_entry counter_entry;
    la_status status = sdev->m_debug_counter_handler->m_debug_counter_db.get(debug_counter_obj.index, counter_entry);
    sai_return_on_la_error(status, "Failed finding debug counter with object id %ld", key->key.object_id);

    switch ((int64_t)arg) {
    case SAI_DEBUG_COUNTER_ATTR_INDEX:
        set_attr_value(SAI_DEBUG_COUNTER_ATTR_INDEX, *value, debug_counter_obj.index);
        break;
    case SAI_DEBUG_COUNTER_ATTR_TYPE:
        set_attr_value(SAI_DEBUG_COUNTER_ATTR_TYPE, *value, counter_entry.m_type);
        break;
    case SAI_DEBUG_COUNTER_ATTR_BIND_METHOD:
        set_attr_value(SAI_DEBUG_COUNTER_ATTR_BIND_METHOD, *value, SAI_DEBUG_COUNTER_BIND_METHOD_AUTOMATIC);
        break;
    case SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST:
    case SAI_DEBUG_COUNTER_ATTR_OUT_DROP_REASON_LIST:
        return fill_sai_list(counter_entry.m_drop_reason_list.begin(), counter_entry.m_drop_reason_list.end(), value->s32list);
        break;
    default:
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

bool
debug_counter_manager::is_supported_drop_reason(sai_in_drop_reason_t reason) const
{
    return m_sai_to_la_counter_translation_in.count(reason) > 0;
}

bool
debug_counter_manager::are_supported_drop_reasons(const sai_s32_list_t& drop_reasons) const
{
    return std::all_of(drop_reasons.list, drop_reasons.list + drop_reasons.count, [this](int32_t reason) {
        return is_supported_drop_reason(static_cast<sai_in_drop_reason_t>(reason));
    });
}

sai_status_t
debug_counter_manager::create_debug_counter(_Out_ sai_object_id_t* out_debug_counter_id,
                                            _In_ sai_object_id_t switch_id,
                                            _In_ uint32_t attr_count,
                                            _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_DEBUG_COUNTER, SAI_OBJECT_TYPE_SWITCH, switch_id, &debug_counter_to_string, "attrs", attrs);

    debug_counter_entry counter_entry;
    get_attrs_value(SAI_DEBUG_COUNTER_ATTR_TYPE, attrs, counter_entry.m_type, true);

    sai_s32_list_t drop_reason_list{};
    get_attrs_value(SAI_DEBUG_COUNTER_ATTR_IN_DROP_REASON_LIST, attrs, drop_reason_list, false);

    if (!sdev->m_debug_counter_handler->are_supported_drop_reasons(drop_reason_list)) {
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    counter_entry.update_drop_reason_list(drop_reason_list);

    sai_debug_counter_bind_method_t bind_method = SAI_DEBUG_COUNTER_BIND_METHOD_AUTOMATIC;
    get_attrs_value(SAI_DEBUG_COUNTER_ATTR_BIND_METHOD, attrs, bind_method, false);
    if (bind_method != SAI_DEBUG_COUNTER_BIND_METHOD_AUTOMATIC) {
        sai_log_error(SAI_API_DEBUG_COUNTER,
                      "Only supported option for debug counter bind method is SAI_DEBUG_COUNTER_BIND_METHOD_AUTOMATIC");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    uint32_t new_index;
    la_status status = sdev->m_debug_counter_handler->m_debug_counter_db.insert(counter_entry, new_index);
    sai_return_on_la_error(status, "Failed inserting debug counter to db");

    lsai_object ret_obj(SAI_OBJECT_TYPE_DEBUG_COUNTER, sdev->m_switch_id, new_index);

    *out_debug_counter_id = ret_obj.object_id();

    sai_log_info(SAI_API_DEBUG_COUNTER, "debug counter id 0x%0lx created", *out_debug_counter_id);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
debug_counter_manager::remove_debug_counter(_In_ sai_object_id_t debug_counter_id)
{
    sai_start_api(
        SAI_API_DEBUG_COUNTER, SAI_OBJECT_TYPE_DEBUG_COUNTER, debug_counter_id, &debug_counter_to_string, debug_counter_id);

    la_status status = sdev->m_debug_counter_handler->m_debug_counter_db.remove(debug_counter_id);
    sai_return_on_la_error(status, "Failed removing debug counter %ld", debug_counter_id);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
debug_counter_manager::set_debug_counter_attribute(_In_ sai_object_id_t debug_counter_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = debug_counter_id;

    sai_start_api(SAI_API_DEBUG_COUNTER,
                  SAI_OBJECT_TYPE_DEBUG_COUNTER,
                  debug_counter_id,
                  &debug_counter_to_string,
                  "debug counter",
                  debug_counter_id,
                  *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "debug counter 0x%lx", debug_counter_id);
    return sai_set_attribute(&key, key_str, debug_counter_attribs, debug_counter_vendor_attribs, attr);
}

sai_status_t
debug_counter_manager::get_debug_counter_attribute(_In_ sai_object_id_t debug_counter_id,
                                                   _In_ uint32_t attr_count,
                                                   _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = debug_counter_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_DEBUG_COUNTER,
                  SAI_OBJECT_TYPE_DEBUG_COUNTER,
                  debug_counter_id,
                  &debug_counter_to_string,
                  "debug counter",
                  debug_counter_id,
                  "attrs",
                  attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "debug counter 0x%lx", debug_counter_id);
    return sai_get_attributes(&key, key_str, debug_counter_attribs, debug_counter_vendor_attribs, attr_count, attr_list);
}

const sai_debug_counter_api_t debug_counter_api = {debug_counter_manager::create_debug_counter,
                                                   debug_counter_manager::remove_debug_counter,
                                                   debug_counter_manager::set_debug_counter_attribute,
                                                   debug_counter_manager::get_debug_counter_attribute};
}
}
