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

#include "api/system/la_device.h"
#include "sai_device.h"
#include "la_sai_object.h"
#include "sai_stats_shadow.h"
#include "sai_pfc.h"
#include "sai_qos.h"
#include "sai_buffer.h"

namespace silicon_one
{
namespace sai
{

static uint8_t threshold_percentage_to_set(sai_int8_t dynamic_thresh);

static sai_status_t buffer_profile_attr_get(_In_ const sai_object_key_t* key,
                                            _Inout_ sai_attribute_value_t* value,
                                            _In_ uint32_t attr_index,
                                            _Inout_ vendor_cache_t* cache,
                                            void* arg);

static sai_status_t buffer_profile_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static lsai_stats_shadow<la_device::la_cgm_watermarks> cgm_watermarks_shadow;
static lsai_stats_shadow<la_uint64_t> curr_occ_bytes_shadow;

static sai_uint64_t
get_egress_dynamic_buffer_pool_size(lsai_object obj)
{
    auto sdev = obj.get_device();
    return (sdev->m_dev_params.sms_packet_buffer_memory);
}

static sai_status_t
buffer_pool_attr_get(_In_ const sai_object_key_t* key,
                     _Inout_ sai_attribute_value_t* value,
                     _In_ uint32_t attr_index,
                     _Inout_ vendor_cache_t* cache,
                     void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_buf_pool(key->key.object_id);
    if (la_buf_pool.type != SAI_OBJECT_TYPE_BUFFER_POOL) {
        sai_log_error(SAI_API_BUFFER, "Invalid buffer pool for get attribute 0x%lx", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto sdev = la_buf_pool.get_device();
    uint32_t index = sdev->m_buffer_pools.get_id(key->key.object_id);
    buffer_pool_entry* buffer_pool_ptr = sdev->m_buffer_pools.get_ptr(index);
    if (buffer_pool_ptr == nullptr) {
        sai_log_error(SAI_API_BUFFER, "buffer_pool_attr_get - pool for id 0x%lx not found", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch ((int64_t)arg) {
    // TODO how does this differ from SIZE?
    case SAI_BUFFER_POOL_ATTR_SHARED_SIZE:
        set_attr_value(SAI_BUFFER_POOL_ATTR_SHARED_SIZE, *value, get_egress_dynamic_buffer_pool_size(la_buf_pool));
        break;
    case SAI_BUFFER_POOL_ATTR_TYPE:
        set_attr_value(SAI_BUFFER_POOL_ATTR_TYPE, *value, buffer_pool_ptr->type);
        break;
    case SAI_BUFFER_POOL_ATTR_SIZE:
        set_attr_value(SAI_BUFFER_POOL_ATTR_SIZE, *value, get_egress_dynamic_buffer_pool_size(la_buf_pool));
        break;
    case SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE:
        set_attr_value(SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE, *value, buffer_pool_ptr->mode);
        break;
    case SAI_BUFFER_POOL_ATTR_TAM:
        value->objlist.count = 0;
        break;
    case SAI_BUFFER_POOL_ATTR_XOFF_SIZE:
        set_attr_value(SAI_BUFFER_POOL_ATTR_XOFF_SIZE, *value, 0);
        break;
    case SAI_BUFFER_POOL_ATTR_WRED_PROFILE_ID:
        set_attr_value(SAI_BUFFER_POOL_ATTR_WRED_PROFILE_ID, *value, SAI_NULL_OBJECT_ID);
        break;
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    return SAI_STATUS_SUCCESS;
}

// clang format-off

static const sai_attribute_entry_t buffer_profile_attribs[] = {
    /* id, m-create?, create?, set?, get?, *name, type */
    {SAI_BUFFER_PROFILE_ATTR_POOL_ID, true, true, false, true, "Buffer profile id", SAI_ATTR_VAL_TYPE_OID},
    {SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE, true, true, true, true, "Buffer profile rsvd size", SAI_ATTR_VAL_TYPE_U64},
    {SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE, true, true, false, true, "Buffer profile threshold mode", SAI_ATTR_VAL_TYPE_U8},
    {SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH, true, true, true, true, "Buffer profile dynamic threshold", SAI_ATTR_VAL_TYPE_S8},
    {SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH, true, true, true, true, "Buffer profile static threshold", SAI_ATTR_VAL_TYPE_U64},
    {SAI_BUFFER_PROFILE_ATTR_XOFF_TH, false, true, true, true, "Buffer profile xoff threshold", SAI_ATTR_VAL_TYPE_U64},
    {SAI_BUFFER_PROFILE_ATTR_XON_TH, false, true, true, true, "Buffer profile xon threshold", SAI_ATTR_VAL_TYPE_U64},
    {SAI_BUFFER_PROFILE_ATTR_XON_OFFSET_TH, false, true, true, true, "Buffer profile xon offset threshold", SAI_ATTR_VAL_TYPE_U64},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t buffer_profile_vendor_attribs[]
    = {SAI_ATTR_CREATE_ONLY(SAI_BUFFER_PROFILE_ATTR_POOL_ID, buffer_profile_attr_get),
       SAI_ATTR_CREATE_AND_SET(SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE, buffer_profile_attr_get, buffer_profile_attr_set),
       SAI_ATTR_CREATE_ONLY(SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE, buffer_profile_attr_get),
       SAI_ATTR_CREATE_AND_SET(SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH, buffer_profile_attr_get, buffer_profile_attr_set),
       SAI_ATTR_CREATE_AND_SET(SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH, buffer_profile_attr_get, buffer_profile_attr_set),
       SAI_ATTR_CREATE_AND_SET(SAI_BUFFER_PROFILE_ATTR_XOFF_TH, buffer_profile_attr_get, buffer_profile_attr_set),
       SAI_ATTR_CREATE_AND_SET(SAI_BUFFER_PROFILE_ATTR_XON_TH, buffer_profile_attr_get, buffer_profile_attr_set),
       SAI_ATTR_CREATE_AND_SET(SAI_BUFFER_PROFILE_ATTR_XON_OFFSET_TH, buffer_profile_attr_get, buffer_profile_attr_set)};

static const sai_attribute_entry_t buffer_pool_attribs[]
    = {{SAI_BUFFER_POOL_ATTR_SHARED_SIZE, false, false, true, true, "Buffer pool shared size", SAI_ATTR_VAL_TYPE_U64},
       {SAI_BUFFER_POOL_ATTR_TYPE, true, true, true, true, "Buffer pool type", SAI_ATTR_VAL_TYPE_U8},
       {SAI_BUFFER_POOL_ATTR_SIZE, true, true, true, true, "Buffer pool size", SAI_ATTR_VAL_TYPE_U64},
       {SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE, false, true, true, true, "Buffer pool threshold mode", SAI_ATTR_VAL_TYPE_U8},
       {SAI_BUFFER_POOL_ATTR_TAM, false, true, true, true, "Buffer pool TAM id", SAI_ATTR_VAL_TYPE_OID},
       {SAI_BUFFER_POOL_ATTR_XOFF_SIZE, false, true, true, true, "Buffer pool shared headroom pool size", SAI_ATTR_VAL_TYPE_U64},
       {SAI_BUFFER_POOL_ATTR_WRED_PROFILE_ID, false, true, true, true, "Buffer pool WRED profile id", SAI_ATTR_VAL_TYPE_OID},
       {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static sai_status_t
buffer_pool_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    sai_log_info(SAI_API_BUFFER, "Buffer pool attribute set is not supported id 0x%lx", *key);
    return SAI_STATUS_SUCCESS;
}

static const sai_vendor_attribute_entry_t buffer_pool_vendor_attribs[]
    = {SAI_ATTR_READ_ONLY(SAI_BUFFER_POOL_ATTR_SHARED_SIZE, buffer_pool_attr_get),
       SAI_ATTR_CREATE_ONLY(SAI_BUFFER_POOL_ATTR_TYPE, buffer_pool_attr_get),
       SAI_ATTR_CREATE_AND_SET(SAI_BUFFER_POOL_ATTR_SIZE, buffer_pool_attr_get, buffer_pool_attr_set),
       SAI_ATTR_CREATE_ONLY(SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE, buffer_pool_attr_get),
       SAI_ATTR_CREATE_AND_SET(SAI_BUFFER_POOL_ATTR_TAM, buffer_pool_attr_get, buffer_pool_attr_set),
       SAI_ATTR_CREATE_AND_SET(SAI_BUFFER_POOL_ATTR_XOFF_SIZE, buffer_pool_attr_get, buffer_pool_attr_set),
       SAI_ATTR_CREATE_AND_SET(SAI_BUFFER_POOL_ATTR_WRED_PROFILE_ID, buffer_pool_attr_get, buffer_pool_attr_set)};

// clang format-on

static sai_status_t
create_ingress_priority_group(_Out_ sai_object_id_t* ingress_priority_group_id,
                              _In_ sai_object_id_t switch_id,
                              _In_ uint32_t attr_count,
                              _In_ const sai_attribute_t* attr_list)
{
    lsai_object la_sw(switch_id);
    auto sdev = la_sw.get_device();
    lsai_object la_ppg(SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP, sdev->m_switch_id, 0);
    *ingress_priority_group_id = la_ppg.object_id();
    sai_log_info(SAI_API_BUFFER, "create_ingress_priority_group, id 0x%lx", *ingress_priority_group_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_ingress_priority_group(_In_ sai_object_id_t ingress_priority_group_id)
{
    // TODO
    return SAI_STATUS_SUCCESS;
}

static std::string
buffer_ingress_priority_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_buffer_profile_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
set_ingress_priority_group_attribute(_In_ sai_object_id_t ingress_priority_group_id, _In_ const sai_attribute_t* attr)
{
    la_status status = LA_STATUS_SUCCESS;
    sai_object_id_t profile_id = SAI_NULL_OBJECT_ID;
    sai_uint8_t ipg = ingress_priority_group_id & 0x7;
    lsai_object ipg_obj(ingress_priority_group_id);
    shared_ptr<lsai_device> sdev = ipg_obj.get_device();

    // ingress_priority_group_id encodes TC and port.index*8
    lsai_object port_id(SAI_OBJECT_TYPE_PORT, sdev->m_switch_id, (ingress_priority_group_id >> 3) & 0xfffff);
    if (attr == nullptr) {
        sai_log_error(SAI_API_BUFFER, "set_ingress_priority_group_attribute - attr is not set");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_ingress_priority_group_attr_t attr_id = (sai_ingress_priority_group_attr_t)attr->id;
    switch (attr_id) {
    case SAI_INGRESS_PRIORITY_GROUP_ATTR_BUFFER_PROFILE:
        sai_log_info(SAI_API_BUFFER,
                     "set_ingress_priority_group_attribute - set buffer_profile 0x%lx oid 0x%lx",
                     attr->value,
                     attr->value.oid);
        profile_id = attr->value.oid;
        break;
    default:
        sai_log_error(SAI_API_BUFFER, "set_ingress_priority_group_attribute - unsupported %d", attr_id);
        return SAI_STATUS_NOT_SUPPORTED;
    }

    port_entry* pentry = nullptr;
    status = sdev->m_ports.get_ptr(port_id.index, pentry);
    sai_return_on_la_error(
        status, "set_ingress_priority_group failed to find pentry by index %d rc %s", port_id.index, status.message().c_str());

    if (profile_id != SAI_NULL_OBJECT_ID) {
        lsai_object la_obj_profile(profile_id);
        buffer_profile* buffer_profile_ptr = sdev->m_buffer_profiles.get_ptr(la_obj_profile.index);
        if (buffer_profile_ptr == nullptr) {
            sai_log_error(SAI_API_BUFFER, "set_ingress_priority_group_attribute - no such buffer profile 0x%lx", profile_id);
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    status = pentry->ingress_priority_group_entries[ipg].set_tc_profile(pentry, profile_id);
    sai_return_on_la_error(status);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_ingress_priority_group_attribute(_In_ sai_object_id_t ingress_priority_group_id,
                                     _In_ uint32_t attr_count,
                                     _Inout_ sai_attribute_t* attr_list)
{
    // TODO
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_ingress_priority_group_stats_ext(_In_ sai_object_id_t ingress_priority_group_id,
                                     _In_ uint32_t number_of_counters,
                                     _In_ const sai_stat_id_t* counter_ids,
                                     _In_ sai_stats_mode_t mode,
                                     _Out_ uint64_t* counters)
{
    lsai_object la_ingress_priority(ingress_priority_group_id);
    auto sdev = la_ingress_priority.get_device();
    sai_start_api_counter(sdev);

    // TODO fetch and set counters
    la_status status = LA_STATUS_SUCCESS;
    for (uint32_t i = 0; i < number_of_counters; ++i) {
        switch (counter_ids[i]) {
        case SAI_INGRESS_PRIORITY_GROUP_STAT_PACKETS:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_CURR_OCCUPANCY_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_WATERMARK_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_CURR_OCCUPANCY_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_SHARED_WATERMARK_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_CURR_OCCUPANCY_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_XOFF_ROOM_WATERMARK_BYTES:
        case SAI_INGRESS_PRIORITY_GROUP_STAT_DROPPED_PACKETS:
            counters[i] = 0;
            break;
        default:
            sai_log_error(SAI_API_BUFFER, "get_ingress_priority_group_stats unknown counter %d", counter_ids[i]);
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_ingress_priority_group_stats(_In_ sai_object_id_t ingress_priority_group_id,
                                 _In_ uint32_t number_of_counters,
                                 _In_ const sai_stat_id_t* counter_ids,
                                 _Out_ uint64_t* counters)
{
    return get_ingress_priority_group_stats_ext(
        ingress_priority_group_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ, counters);
}

static sai_status_t
clear_ingress_priority_group_stats(_In_ sai_object_id_t ingress_priority_group_id,
                                   _In_ uint32_t number_of_counters,
                                   _In_ const sai_stat_id_t* counter_ids)
{
    uint64_t counters[number_of_counters];
    return get_ingress_priority_group_stats_ext(
        ingress_priority_group_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ_AND_CLEAR, counters);
}

static std::string
buffer_profile_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_buffer_profile_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
buffer_profile_attr_get(_In_ const sai_object_key_t* key,
                        _Inout_ sai_attribute_value_t* value,
                        _In_ uint32_t attr_index,
                        _Inout_ vendor_cache_t* cache,
                        void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_buf_profile(key->key.object_id);
    if (la_buf_profile.type != SAI_OBJECT_TYPE_BUFFER_PROFILE) {
        sai_log_error(SAI_API_BUFFER, "Invalid buffer profile for get attribute 0x%lx", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto sdev = la_buf_profile.get_device();

    buffer_profile* buffer_prof = sdev->m_buffer_profiles.get_ptr(la_buf_profile.index);
    if (buffer_prof == nullptr) {
        sai_log_error(SAI_API_BUFFER, "Buffer profile 0x%llx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    switch ((int64_t)arg) {
    case SAI_BUFFER_PROFILE_ATTR_POOL_ID:
        set_attr_value(SAI_BUFFER_PROFILE_ATTR_POOL_ID, *value, buffer_prof->buffer_pool_id);
        break;
    case SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE:
        set_attr_value(SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE, *value, buffer_prof->reserved_buffer_size);
        break;
    case SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE:
        set_attr_value(SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE, *value, buffer_prof->mode);
        break;
    case SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH:
        set_attr_value(SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH, *value, buffer_prof->dynamic_thresh);
        break;
    case SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH:
        set_attr_value(SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH, *value, buffer_prof->static_thresh);
        break;
    case SAI_BUFFER_PROFILE_ATTR_XOFF_TH:
        set_attr_value(SAI_BUFFER_PROFILE_ATTR_XOFF_TH, *value, buffer_prof->xoff_th);
        break;
    case SAI_BUFFER_PROFILE_ATTR_XON_TH:
        set_attr_value(SAI_BUFFER_PROFILE_ATTR_XON_TH, *value, buffer_prof->xon_th);
        break;
    case SAI_BUFFER_PROFILE_ATTR_XON_OFFSET_TH:
        set_attr_value(SAI_BUFFER_PROFILE_ATTR_XON_OFFSET_TH, *value, buffer_prof->xon_offset_th);
        break;
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
buffer_profile_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    la_status status = LA_STATUS_SUCCESS;
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_buf_profile(key->key.object_id);
    if (la_buf_profile.type != SAI_OBJECT_TYPE_BUFFER_PROFILE) {
        sai_log_error(SAI_API_BUFFER, "Invalid buffer profile for set attribute 0x%lx", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto sdev = la_buf_profile.get_device();

    buffer_profile* buffer_prof = sdev->m_buffer_profiles.get_ptr(la_buf_profile.index);
    if (buffer_prof == nullptr) {
        sai_log_error(SAI_API_BUFFER, "Buffer profile 0x%llx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    switch ((int64_t)arg) {
    case SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE:
        buffer_prof->reserved_buffer_size = get_attr_value(SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE, *value);
        break;
    case SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH:
        if (buffer_prof->mode == SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC) {
            buffer_prof->dynamic_thresh = get_attr_value(SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH, *value);
            uint8_t percent_to_set = threshold_percentage_to_set(buffer_prof->dynamic_thresh);
            status = configure_lossless_profile(buffer_prof->rx_cgm_sq_profile,
                                                buffer_prof->xoff_th,
                                                (buffer_prof->reserved_buffer_size - buffer_prof->xoff_th),
                                                sdev->m_dev_params.pfc_head_room_max,
                                                percent_to_set);
            sai_return_on_la_error(status, "buffer_profile_attr_set set dynamic_thresh failed, rc %s", status.message().c_str());
        } else {
            sai_log_error(SAI_API_BUFFER, "cannot set dynamic_thresh on static profile 0x%lx", key->key.object_id);
            return SAI_STATUS_INVALID_PARAMETER;
        }
        break;
    case SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH:
        if (buffer_prof->mode == SAI_BUFFER_PROFILE_THRESHOLD_MODE_STATIC) {
            buffer_prof->static_thresh = get_attr_value(SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH, *value);
            status = configure_lossy_user_profile(buffer_prof->rx_cgm_sq_profile, buffer_prof->static_thresh);
            sai_return_on_la_error(
                status, "set_ingress_priority_group failed to set lossy profile rc %s", status.message().c_str());
        } else {
            sai_log_error(SAI_API_BUFFER, "cannot set static_thresh on dynamic profile 0x%lx", key->key.object_id);
            return SAI_STATUS_INVALID_PARAMETER;
        }
        break;
    case SAI_BUFFER_PROFILE_ATTR_XOFF_TH:
        if (buffer_prof->mode == SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC) {
            buffer_prof->xoff_th = get_attr_value(SAI_BUFFER_PROFILE_ATTR_XOFF_TH, *value);
            uint8_t percent_to_set = threshold_percentage_to_set(buffer_prof->dynamic_thresh);
            status = configure_lossless_profile(buffer_prof->rx_cgm_sq_profile,
                                                buffer_prof->xoff_th,
                                                (buffer_prof->reserved_buffer_size - buffer_prof->xoff_th),
                                                sdev->m_dev_params.pfc_head_room_max,
                                                percent_to_set);
            sai_return_on_la_error(status, "buffer_profile_attr_set set xoff_th failed, rc %s", status.message().c_str());
        } else {
            sai_log_error(SAI_API_BUFFER, "cannot set xoff_th for static profile 0x%lx", key->key.object_id);
            return SAI_STATUS_INVALID_PARAMETER;
        }
        break;
    case SAI_BUFFER_PROFILE_ATTR_XON_TH:
    case SAI_BUFFER_PROFILE_ATTR_XON_OFFSET_TH:
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    return SAI_STATUS_SUCCESS;
}

/* convert the dynamic_thresh to a number to set as threshold in percentage */
/* dynamic_thresh can go from -128 to 127
 * if      < -8 return   0
 * else if >  8 return   100
 * else         add 8 and return value from array
 * values are precomputed. For "a" using: 2^a / (1 + 2^a)
 */
static uint8_t
threshold_percentage_to_set(sai_int8_t dynamic_thresh)
{
    uint8_t percent, index = 0;
    uint8_t threshold_range[17] = {0, 1, 2, 4, 6, 12, 20, 34, 50, 66, 80, 88, 94, 96, 98, 99, 100};

    if (dynamic_thresh < -8) {
        percent = 0;
    } else if (dynamic_thresh > 8) {
        percent = 100;
    } else {
        index = dynamic_thresh + 8;
        percent = threshold_range[index];
    }
    return (percent);
}

static sai_status_t
create_buffer_profile(_Out_ sai_object_id_t* buffer_profile_id,
                      _In_ sai_object_id_t switch_id,
                      _In_ uint32_t attr_count,
                      _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_BUFFER, SAI_OBJECT_TYPE_SWITCH, switch_id, &buffer_profile_to_string, "buffer profile", switch_id, attrs);

    buffer_profile profile_attrs;

    get_attrs_value(SAI_BUFFER_PROFILE_ATTR_POOL_ID, attrs, profile_attrs.buffer_pool_id, true);
    lsai_object pool_obj_id(profile_attrs.buffer_pool_id);

    buffer_pool_entry* buffer_pool_ptr = sdev->m_buffer_pools.get_ptr(profile_attrs.buffer_pool_id);
    if (buffer_pool_ptr == nullptr) {
        sai_log_error(SAI_API_BUFFER, "create_buffer_profile, pool for id 0x%lx not found", profile_attrs.buffer_pool_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    sai_buffer_pool_type_t pool_type = buffer_pool_ptr->type;
    sai_buffer_pool_threshold_mode_t pool_mode = buffer_pool_ptr->mode;

    get_attrs_value(SAI_BUFFER_PROFILE_ATTR_RESERVED_BUFFER_SIZE, attrs, profile_attrs.reserved_buffer_size, true);
    get_attrs_value(SAI_BUFFER_PROFILE_ATTR_THRESHOLD_MODE, attrs, profile_attrs.mode, true);
    get_attrs_value(SAI_BUFFER_PROFILE_ATTR_SHARED_DYNAMIC_TH, attrs, profile_attrs.dynamic_thresh, false);
    get_attrs_value(SAI_BUFFER_PROFILE_ATTR_SHARED_STATIC_TH, attrs, profile_attrs.static_thresh, false);
    get_attrs_value(SAI_BUFFER_PROFILE_ATTR_XOFF_TH, attrs, profile_attrs.xoff_th, false);
    get_attrs_value(SAI_BUFFER_PROFILE_ATTR_XON_TH, attrs, profile_attrs.xon_th, false);
    get_attrs_value(SAI_BUFFER_PROFILE_ATTR_XON_OFFSET_TH, attrs, profile_attrs.xon_offset_th, false);

    if (pool_type == SAI_BUFFER_POOL_TYPE_EGRESS && profile_attrs.xoff_th != 0) {
        sai_log_error(
            SAI_API_BUFFER, "create_buffer_profile profile on egress pool cannot have non-zero xoff_th %d", profile_attrs.xoff_th);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (profile_attrs.xoff_th > profile_attrs.reserved_buffer_size) {
        sai_log_error(SAI_API_BUFFER,
                      "create_buffer_profile xoff_th %llu must be less and reserved buffer size %llu",
                      profile_attrs.xoff_th,
                      profile_attrs.reserved_buffer_size);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (profile_attrs.xon_th != profile_attrs.xoff_th) {
        sai_log_error(SAI_API_BUFFER,
                      "create_buffer_profile xoff_th %llu must match xon_th %llu",
                      profile_attrs.xoff_th,
                      profile_attrs.xon_th);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    uint8_t percent_to_set = sdev->m_dev_params.pfc_scaled_thr_percent;
    if (profile_attrs.mode == SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC) {
        percent_to_set = threshold_percentage_to_set(profile_attrs.dynamic_thresh);
    }

    if ((sai_uint8_t)pool_mode != (sai_uint8_t)profile_attrs.mode) {
        sai_log_error(SAI_API_BUFFER,
                      "create_buffer_profile pool id 0x%lx profile mode %d does not match pool mode %d",
                      profile_attrs.buffer_pool_id,
                      profile_attrs.mode,
                      pool_mode);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    if (profile_attrs.reserved_buffer_size > buffer_pool_ptr->size) {
        sai_log_error(SAI_API_BUFFER,
                      "create_buffer_profile, profile size %d greater than pool size %d",
                      profile_attrs.reserved_buffer_size,
                      buffer_pool_ptr->size);
        return SAI_STATUS_INSUFFICIENT_RESOURCES;
    }

    la_status status = LA_STATUS_SUCCESS;

    status = sdev->m_dev->set_pfc_headroom_mode(la_rx_cgm_headroom_mode_e::THRESHOLD);
    sai_return_on_la_error(status, "create_buffer_profile set headroom mode failed, rc %s", status.message().c_str());

    if (pool_type == SAI_BUFFER_POOL_TYPE_INGRESS) {
        status = sdev->m_dev->create_rx_cgm_sq_profile(profile_attrs.rx_cgm_sq_profile);
        sai_return_on_la_error(status, "create_buffer_profile create sq profile failed, rc %s", status.message().c_str());

        // lossless
        if (profile_attrs.mode == SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC) {
            status = configure_lossless_policy(profile_attrs.rx_cgm_sq_profile);
            sai_return_on_la_error(status, "create_buffer_profile set policy failed rc %s", status.message().c_str());

            sai_log_info(SAI_API_BUFFER, "create_buffer_profile setting xoff_threshold percent to set %d", percent_to_set);
            status = configure_lossless_profile(profile_attrs.rx_cgm_sq_profile,
                                                profile_attrs.xoff_th,
                                                (profile_attrs.reserved_buffer_size - profile_attrs.xoff_th),
                                                sdev->m_dev_params.pfc_head_room_max,
                                                percent_to_set);
            sai_return_on_la_error(status, "create_buffer_profile set pfc profile failed, rc %s", status.message().c_str());
        } else { // lossy
            sai_log_info(SAI_API_BUFFER, "create_buffer_profile lossy profile size %lu", profile_attrs.static_thresh);

            status = configure_lossy_user_policy(profile_attrs.rx_cgm_sq_profile);
            sai_return_on_la_error(status, "create_buffer_profile set lossy policy failed rc %s", status.message().c_str());
            status = configure_lossy_user_profile(profile_attrs.rx_cgm_sq_profile, profile_attrs.static_thresh);
            sai_return_on_la_error(
                status, "set_ingress_priority_group failed to set lossy profile rc %s", status.message().c_str());
        }
    } else { // TODO for egress pool, create voq-cgm profile
        sai_log_info(SAI_API_BUFFER,
                     "create_buffer_profile egress on pool id 0x%lx, not creating rx_cgm_profile",
                     profile_attrs.buffer_pool_id);
    }

    transaction txn;
    txn.status = LA_STATUS_SUCCESS;
    uint32_t index = 0;
    txn.status = sdev->m_buffer_profiles.allocate_id(index);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_buffer_profiles.release_id(index); });

    txn.status = sdev->m_buffer_profiles.set(index, profile_attrs);
    sai_return_on_la_error(txn.status);

    lsai_object la_buffer_profile(SAI_OBJECT_TYPE_BUFFER_PROFILE, sdev->m_switch_id, index);
    *buffer_profile_id = la_buffer_profile.object_id();

    sai_log_info(SAI_API_BUFFER,
                 "Buffer Profile 0x%lx created on pool 0x%lx, size %llu xoff_th %llu mode %llu. %s",
                 *buffer_profile_id,
                 profile_attrs.buffer_pool_id,
                 profile_attrs.reserved_buffer_size,
                 profile_attrs.xoff_th,
                 profile_attrs.mode,
                 (pool_type == SAI_BUFFER_POOL_TYPE_INGRESS) ? " rx_cgm_profile created." : "");

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_buffer_profile(_In_ sai_object_id_t buffer_profile_id)
{
    sai_start_api(SAI_API_BUFFER, SAI_OBJECT_TYPE_BUFFER_PROFILE, buffer_profile_id, &buffer_profile_to_string, buffer_profile_id);

    buffer_profile entry{};
    la_status status = sdev->m_buffer_profiles.get(la_obj.index, entry);
    sai_return_on_la_error(status);

    bool rx_cgm_profile_removed = false;
    if (entry.rx_cgm_sq_profile != nullptr) {
        if (entry.ref_count != 0) {
            sai_log_error(
                SAI_API_BUFFER, "Cannot remove in-use buffer profile 0x%lx, ref-count %d", buffer_profile_id, entry.ref_count);
            return SAI_STATUS_OBJECT_IN_USE;
        }
        status = sdev->m_dev->destroy(entry.rx_cgm_sq_profile);
        if (status != LA_STATUS_SUCCESS) {
            sai_log_error(
                SAI_API_BUFFER, "Failed to remove rx cgm profile. Cannot remove buffer profile 0x%lx ", buffer_profile_id);
            return SAI_STATUS_INVALID_PARAMETER;
        }
        entry.rx_cgm_sq_profile = nullptr;
        rx_cgm_profile_removed = true;
    }

    status = sdev->m_buffer_profiles.remove(la_obj.index);
    sai_log_info(SAI_API_BUFFER,
                 "Buffer Profile id 0x%lx removed. %s",
                 buffer_profile_id,
                 rx_cgm_profile_removed ? "rx_cgm_profile removed" : "");
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_buffer_profile_attribute(_In_ sai_object_id_t buffer_profile_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = buffer_profile_id;

    sai_start_api(SAI_API_HOSTIF, SAI_OBJECT_TYPE_BUFFER_PROFILE, buffer_profile_id, &buffer_profile_to_string, "attr", *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "buffer profile 0x%lx", buffer_profile_id);
    return sai_set_attribute(&key, key_str, buffer_profile_attribs, buffer_profile_vendor_attribs, attr);
}

static sai_status_t
get_buffer_profile_attribute(_In_ sai_object_id_t buffer_profile_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = buffer_profile_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_BUFFER,
                  SAI_OBJECT_TYPE_BUFFER_PROFILE,
                  buffer_profile_id,
                  &buffer_profile_to_string,
                  "buffer profile",
                  buffer_profile_id,
                  attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "buffer profile 0x%0lx", buffer_profile_id);
    return sai_get_attributes(&key, key_str, buffer_profile_attribs, buffer_profile_vendor_attribs, attr_count, attr_list);
}

static std::string
buffer_pool_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_buffer_pool_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
get_buffer_pool_attribute(_In_ sai_object_id_t buffer_pool_id, _In_ uint32_t attr_count, _Out_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = buffer_pool_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_BUFFER, SAI_OBJECT_TYPE_BUFFER_POOL, buffer_pool_id, &buffer_pool_to_string, "buffer pool", buffer_pool_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "buffer pool 0x%0lx", buffer_pool_id);
    return sai_get_attributes(&key, key_str, buffer_pool_attribs, buffer_pool_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
create_buffer_pool(_Out_ sai_object_id_t* buffer_pool_id,
                   _In_ sai_object_id_t switch_id,
                   _In_ uint32_t attr_count,
                   _In_ const sai_attribute_t* attr_list)
{
    buffer_pool_entry pool_attrs;
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_BUFFER, SAI_OBJECT_TYPE_SWITCH, switch_id, &buffer_pool_to_string, "buffer pool", attrs);

    lsai_object la_sw(switch_id);

    get_attrs_value(SAI_BUFFER_POOL_ATTR_TYPE, attrs, pool_attrs.type, true);
    get_attrs_value(SAI_BUFFER_POOL_ATTR_THRESHOLD_MODE, attrs, pool_attrs.mode, true);
    get_attrs_value(SAI_BUFFER_POOL_ATTR_SIZE, attrs, pool_attrs.size, true);

    switch (pool_attrs.type) {
    case SAI_BUFFER_POOL_TYPE_INGRESS:
    case SAI_BUFFER_POOL_TYPE_EGRESS:
        break;
    default:
        sai_log_error(SAI_API_BUFFER, "create_buffer_pool - unsupported pool type %d", pool_attrs.type);
        return SAI_STATUS_NOT_SUPPORTED;
    }

    switch (pool_attrs.mode) {
    case SAI_BUFFER_POOL_THRESHOLD_MODE_STATIC:
    case SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC:
        break;
    default:
        sai_log_error(SAI_API_BUFFER, "create_buffer_pool - unsupported threshold mode %d", pool_attrs.mode);
        return SAI_STATUS_NOT_SUPPORTED;
    }

    if (pool_attrs.size != sdev->m_dev_params.sms_packet_buffer_memory) {
        sai_log_error(SAI_API_BUFFER,
                      "buffer pool size 0x%llu does not match device memory 0x%llu",
                      pool_attrs.size,
                      sdev->m_dev_params.sms_packet_buffer_memory);
        return SAI_STATUS_NOT_SUPPORTED;
    }

    transaction txn;
    txn.status = LA_STATUS_SUCCESS;

    uint32_t index = 0;
    txn.status = sdev->m_buffer_pools.allocate_id(index);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_buffer_pools.release_id(index); });

    txn.status = sdev->m_buffer_pools.set(index, pool_attrs);
    sai_return_on_la_error(txn.status);

    lsai_object la_buffer_pool(SAI_OBJECT_TYPE_BUFFER_POOL, sdev->m_switch_id, index);
    *buffer_pool_id = la_buffer_pool.object_id();

    sai_log_info(SAI_API_BUFFER,
                 "create_buffer_pool - id 0x%lx type %s mode %d size 0x%lx created successfully",
                 *buffer_pool_id,
                 pool_attrs.type == SAI_BUFFER_POOL_TYPE_EGRESS ? "egress" : "ingress",
                 pool_attrs.mode,
                 pool_attrs.size);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_buffer_pool(_In_ sai_object_id_t buffer_pool_id)
{
    sai_start_api(SAI_API_BUFFER, SAI_OBJECT_TYPE_BUFFER_POOL, buffer_pool_id, &buffer_pool_to_string, buffer_pool_id);

    buffer_pool_entry entry{};
    la_status status = sdev->m_buffer_pools.get(la_obj.index, entry);
    sai_return_on_la_error(status);

    // verify no profile is using this pool
    uint32_t profile_count;
    sdev->m_buffer_profiles.get_object_count(sdev, &profile_count);
    sai_object_key_t profile_list[profile_count];
    buffer_profile prof_entry{};
    sdev->m_buffer_profiles.get_object_keys(sdev, &profile_count, profile_list);
    for (uint32_t num = 0; num < profile_count; num++) {
        lsai_object la_obj_profile(profile_list[num].key.object_id);
        sdev->m_buffer_profiles.get(la_obj_profile.index, prof_entry);
        if (prof_entry.buffer_pool_id == buffer_pool_id) {
            sai_log_error(SAI_API_BUFFER,
                          "remove_buffer_pool oid 0x%lx in use by profile oid 0x%lx, cannot remove",
                          buffer_pool_id,
                          la_obj_profile.object_id());
            return (SAI_STATUS_INVALID_PARAMETER);
        }
    }

    status = sdev->m_buffer_pools.remove(la_obj.index);
    sai_return_on_la_error(status);
    sai_log_info(SAI_API_BUFFER, "buffer pool id 0x%lx removed successfully", buffer_pool_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_buffer_pool_stats_ext(_In_ sai_object_id_t buffer_pool_id,
                          _In_ uint32_t number_of_counters,
                          _In_ const sai_stat_id_t* counter_ids,
                          _In_ sai_stats_mode_t mode,
                          _Out_ uint64_t* counters)
{
    lsai_object la_buffer_pool(buffer_pool_id);
    auto sdev = la_buffer_pool.get_device();
    sai_start_api_counter(sdev);
    la_uint64_t free_buffer_count;
    la_uint64_t* free_buffer_count_ptr = &free_buffer_count;

    la_status status = LA_STATUS_SUCCESS;
    for (uint32_t i = 0; i < number_of_counters; ++i) {
        switch (counter_ids[i]) {
        case SAI_BUFFER_POOL_STAT_WATERMARK_BYTES: {
            la_device::la_cgm_watermarks* wmk_ptr = nullptr;

            status = cgm_watermarks_shadow.get_data(sdev, wmk_ptr, SAI_STATS_MODE_READ);
            if (status != LA_STATUS_SUCCESS) {
                la_device::la_cgm_watermarks wmk;

                status = sdev->m_dev->get_cgm_watermarks(wmk);
                if (status == LA_STATUS_SUCCESS) {
                    counters[i] = std::max(wmk.uc_wmk, wmk.mc_wmk) * BUFFER_POOL_ENTRY_SIZE;
                    cgm_watermarks_shadow.set_data(wmk, SAI_STATS_MODE_READ);
                } else {
                    sai_return_on_la_error(status, "Failed to get CGM watermarks, rc %s", status.message().c_str());
                }
            } else {
                counters[i] = std::max(wmk_ptr->uc_wmk, wmk_ptr->mc_wmk) * BUFFER_POOL_ENTRY_SIZE;
            }
            break;
        }
        case SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES:
            status = curr_occ_bytes_shadow.get_data(sdev, free_buffer_count_ptr, SAI_STATS_MODE_READ);
            if (status != LA_STATUS_SUCCESS) {
                status = sdev->m_dev->get_sms_total_free_buffer_summary(false, free_buffer_count);
                if (status == LA_STATUS_SUCCESS) {
                    curr_occ_bytes_shadow.set_data(free_buffer_count, SAI_STATS_MODE_READ);
                } else {
                    sai_return_on_la_error(
                        status, "Failed to get SAI_BUFFER_POOL_STAT_CURR_OCCUPANCY_BYTES, rc %s", status.message().c_str());
                }
            }
            counters[i] = get_egress_dynamic_buffer_pool_size(la_buffer_pool) - *free_buffer_count_ptr * BUFFER_POOL_ENTRY_SIZE;
            break;
        case SAI_BUFFER_POOL_STAT_DROPPED_PACKETS:
        case SAI_BUFFER_POOL_STAT_GREEN_WRED_DROPPED_PACKETS:
        case SAI_BUFFER_POOL_STAT_GREEN_WRED_DROPPED_BYTES:
        case SAI_BUFFER_POOL_STAT_YELLOW_WRED_DROPPED_PACKETS:
        case SAI_BUFFER_POOL_STAT_YELLOW_WRED_DROPPED_BYTES:
        case SAI_BUFFER_POOL_STAT_GREEN_WRED_ECN_MARKED_PACKETS:
        case SAI_BUFFER_POOL_STAT_GREEN_WRED_ECN_MARKED_BYTES:
        case SAI_BUFFER_POOL_STAT_YELLOW_WRED_ECN_MARKED_PACKETS:
        case SAI_BUFFER_POOL_STAT_YELLOW_WRED_ECN_MARKED_BYTES:
        case SAI_BUFFER_POOL_STAT_WRED_ECN_MARKED_PACKETS:
        case SAI_BUFFER_POOL_STAT_WRED_ECN_MARKED_BYTES:
        case SAI_BUFFER_POOL_STAT_XOFF_ROOM_CURR_OCCUPANCY_BYTES:
        case SAI_BUFFER_POOL_STAT_XOFF_ROOM_WATERMARK_BYTES:
            // TODO
            counters[i] = 0;
            break;

        default:
            sai_log_error(SAI_API_BUFFER, "get_buffer_pool_stats unknown counter %d", counter_ids[i]);
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_buffer_pool_stats(_In_ sai_object_id_t buffer_pool_id,
                      _In_ uint32_t number_of_counters,
                      _In_ const sai_stat_id_t* counter_ids,
                      _Out_ uint64_t* counters)
{
    return get_buffer_pool_stats_ext(buffer_pool_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ, counters);
}

static sai_status_t
clear_buffer_pool_stats(_In_ sai_object_id_t pool_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t* counter_ids)
{
    uint64_t counters[number_of_counters];
    return get_buffer_pool_stats_ext(pool_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ_AND_CLEAR, counters);
}

static sai_status_t
set_buffer_pool_attribute(_In_ sai_object_id_t buffer_pool_id, _In_ const sai_attribute_t* attr)
{
    // TODO
    return SAI_STATUS_SUCCESS;
}

ingress_priority_group_entry::ingress_priority_group_entry(uint8_t ipg) : m_ipg(ipg), m_buffer_profile_oid(SAI_NULL_OBJECT_ID)
{
}

sai_object_id_t
ingress_priority_group_entry::get_buffer_profile_oid() const
{
    return m_buffer_profile_oid;
}

// Update the SQG for the given pentry/tc combination
la_status
ingress_priority_group_entry::set_tc_sqg(port_entry* pentry, la_traffic_class_t tc, la_uint_t sqg_to_set)
{
    la_status status;
    lsai_object port_obj(pentry->service.oid);
    shared_ptr<lsai_device> sdev = port_obj.get_device();
    la_mac_port* mac_port = get_mac_port_by_eth_obj(port_obj.object_id());
    if (mac_port == nullptr) {
        sai_log_error(SAI_API_BUFFER, "sai_object_id(0x%lx): Not a mac_port.", port_obj.object_id());
        return LA_STATUS_EINVAL;
    }

    la_uint_t cntr, current_sqg_type;
    la_rx_cgm_sq_profile* current_profile = nullptr;
    status = mac_port->get_tc_rx_cgm_sq_mapping(tc, current_profile, current_sqg_type, cntr);
    la_return_on_error(status);
    status = mac_port->set_tc_rx_cgm_sq_mapping(tc, current_profile, sqg_to_set, tc);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ingress_priority_group_entry::set_tc_profile(port_entry* pentry, sai_object_id_t buffer_profile_oid)
{
    la_status status;
    lsai_object port_obj(pentry->service.oid);
    shared_ptr<lsai_device> sdev = port_obj.get_device();
    la_mac_port* mac_port = get_mac_port_by_eth_obj(port_obj.object_id());
    if (mac_port == nullptr) {
        sai_log_error(SAI_API_BUFFER, "sai_object_id(0x%lx): Not a mac_port.", port_obj.object_id());
        return LA_STATUS_EINVAL;
    }

    la_rx_cgm_sq_profile* default_profile = nullptr;
    status = sdev->m_dev->get_default_rx_cgm_sq_profile(default_profile);
    la_return_on_error(status);

    la_rx_cgm_sq_profile* profile_to_set = nullptr;
    buffer_profile* new_buffer_profile_ptr = nullptr;

    if (buffer_profile_oid == SAI_NULL_OBJECT_ID) {
        profile_to_set = default_profile;
    } else {
        lsai_object la_obj_profile(buffer_profile_oid);
        new_buffer_profile_ptr = sdev->m_buffer_profiles.get_ptr(la_obj_profile.index);
        if (new_buffer_profile_ptr == nullptr) {
            sai_log_error(SAI_API_BUFFER, "No buffer profile for profile oid 0x%lx", buffer_profile_oid);
            return LA_STATUS_EINVAL;
        }
        profile_to_set = new_buffer_profile_ptr->rx_cgm_sq_profile;
        if (profile_to_set == nullptr) {
            sai_log_error(SAI_API_BUFFER, "rx-cgm profile is null for profile id 0x%lx", buffer_profile_oid);
            return LA_STATUS_EINVAL;
        }
    }

    // Given the IPG being updated, apply the new profile to each
    // TC based on the corresponding QOS MAP mapping.
    {
        la_uint_t cntr, old_sqg_type;
        la_rx_cgm_sq_profile* old_profile = nullptr;
        std::vector<sai_uint8_t> tc_list = lasai_qos::get_pg_to_tc_list(sdev, m_ipg, pentry->tc_priogroup_oid);
        for (auto& tc : tc_list) {
            status = mac_port->get_tc_rx_cgm_sq_mapping(tc, old_profile, old_sqg_type, cntr);
            la_return_on_error(status);
            status = mac_port->set_tc_rx_cgm_sq_mapping(tc, profile_to_set, old_sqg_type, tc);
            la_return_on_error(status);
        }
    }

    // Decrement old buffer profile ref count
    if (m_buffer_profile_oid != SAI_NULL_OBJECT_ID) {
        lsai_object la_obj_cached_profile(m_buffer_profile_oid);
        buffer_profile* cached_buffer_profile_ptr = sdev->m_buffer_profiles.get_ptr(la_obj_cached_profile.index);
        if (cached_buffer_profile_ptr == nullptr) {
            sai_log_error(SAI_API_BUFFER, "No buffer profile for non-default cached profile oid 0x%lx", m_buffer_profile_oid);
            return LA_STATUS_EINVAL;
        }
        cached_buffer_profile_ptr->ref_count--;
    }

    // Increment new buffer profile ref count
    if (buffer_profile_oid != SAI_NULL_OBJECT_ID) {
        new_buffer_profile_ptr->ref_count++;
    }

    m_buffer_profile_oid = buffer_profile_oid;
    return LA_STATUS_SUCCESS;
}

const sai_buffer_api_t buffer_api = {
    create_buffer_pool,
    remove_buffer_pool,
    set_buffer_pool_attribute,
    get_buffer_pool_attribute,
    get_buffer_pool_stats,
    get_buffer_pool_stats_ext,
    clear_buffer_pool_stats,
    create_ingress_priority_group,
    remove_ingress_priority_group,
    set_ingress_priority_group_attribute,
    get_ingress_priority_group_attribute,
    get_ingress_priority_group_stats,
    get_ingress_priority_group_stats_ext,
    clear_ingress_priority_group_stats,
    create_buffer_profile,
    remove_buffer_profile,
    set_buffer_profile_attribute,
    get_buffer_profile_attribute,
};
}
}
