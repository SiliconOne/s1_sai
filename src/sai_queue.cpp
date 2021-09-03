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
#include "api/tm/la_interface_scheduler.h"
#include "api/tm/la_system_port_scheduler.h"
#include "api/tm/la_voq_set.h"
#include "common/ranged_index_generator.h"
#include "port_helper.h"
#include "sai_constants.h"
#include "sai_port.h"
#include "sai_queue.h"
#include "sai_logger.h"
#include "sai_stats_shadow.h"

namespace silicon_one
{
namespace sai
{
using namespace std;

static std::unordered_map<sai_object_id_t, lsai_stats_shadow<queue_watermark_stats>> queue_watermark_shadow;

static sai_status_t queue_attrib_get(_In_ const sai_object_key_t* key,
                                     _Inout_ sai_attribute_value_t* value,
                                     _In_ uint32_t attr_index,
                                     _Inout_ vendor_cache_t* cache,
                                     void* arg);

sai_status_t queue_attr_wred_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
sai_status_t queue_attr_buffer_profile_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t read_queue_depth_in_bytes(la_voq_set* voq_set, lsai_object& queue_obj, uint64_t& counter);

static sai_status_t read_egress_congestion_watermark(la_system_port* system_port,
                                                     sai_object_id_t queue_id,
                                                     sai_stats_mode_t mode,
                                                     uint64_t& counter);
static sai_status_t queue_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

// clang-format off
extern const sai_attribute_entry_t queue_attribs[] = {
// id, mandatory_on_create, valid_for_create, valid_for_set, valid_for_get, name
    {SAI_QUEUE_ATTR_TYPE, false, false, false, true, "Queue type", SAI_ATTR_VAL_TYPE_S32},
    {SAI_QUEUE_ATTR_PORT, false, false, false, true, "Queue port", SAI_ATTR_VAL_TYPE_OID},
    {SAI_QUEUE_ATTR_INDEX, true, true, false, true, "Queue Index", SAI_ATTR_VAL_TYPE_U8},
    {SAI_QUEUE_ATTR_PARENT_SCHEDULER_NODE, false, false, false, true, "Queue parent scheduler", SAI_ATTR_VAL_TYPE_OID},
    {SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, false, false, true, true, "Queue scheduler ID", SAI_ATTR_VAL_TYPE_OID},
    {SAI_QUEUE_ATTR_WRED_PROFILE_ID, false, false, true, true, "Queue WRED profile ID", SAI_ATTR_VAL_TYPE_OID},
    {SAI_QUEUE_ATTR_BUFFER_PROFILE_ID, false, false, true, true, "Queue Buffer profile ID", SAI_ATTR_VAL_TYPE_OID},
    {SAI_QUEUE_ATTR_PAUSE_STATUS, false, false, false, true, "Queue PFC Pause status", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_QUEUE_ATTR_ENABLE_PFC_DLDR, false, true, true, true, "Queue enable PFC DLDR", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_QUEUE_ATTR_PFC_DLR_INIT, false, false, true, false, "Queue PFC DLR init", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_QUEUE_ATTR_BUFFER_PROFILE_ID, false, true, true, true, "Queue Buffer Profile", SAI_ATTR_VAL_TYPE_OID},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t queue_vendor_attribs[] = {
    /*
       id,
       {create, remove, set, get}, // implemented
       {create, remove, set, get}, // supported
       getter, getter_arg,
       setter, setter_arg
    */
    {SAI_QUEUE_ATTR_TYPE,
     { false, false, false, true },
     { false, false, false, true },
     queue_attrib_get, (void*)SAI_QUEUE_ATTR_TYPE,
     nullptr, nullptr},
    {SAI_QUEUE_ATTR_PORT,
     { false, false, false, true },
     { false, false, false, true },
     queue_attrib_get, (void*)SAI_QUEUE_ATTR_PORT,
     nullptr, nullptr},
    {SAI_QUEUE_ATTR_INDEX,
     { false, false, false, true },
     { false, false, false, true },
     queue_attrib_get, (void*)SAI_QUEUE_ATTR_INDEX,
     nullptr, nullptr},
    {SAI_QUEUE_ATTR_PARENT_SCHEDULER_NODE,
     { false, false, false, true },
     { false, false, false, true },
     queue_attrib_get, (void*)SAI_QUEUE_ATTR_PARENT_SCHEDULER_NODE,
     nullptr, nullptr},
    {SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID,
     {false, false, true, true},
     {false, false, true, true},
     queue_attr_scheduler_profile_get, nullptr,
     queue_attr_scheduler_profile_set, nullptr},
    {SAI_QUEUE_ATTR_WRED_PROFILE_ID,
     { false, false, true, true },
     { false, false, true, true },
     queue_attrib_get, (void*)SAI_QUEUE_ATTR_WRED_PROFILE_ID,
     queue_attr_wred_set, nullptr},
    {SAI_QUEUE_ATTR_BUFFER_PROFILE_ID,
     { false, false, true, true },
     { false, false, true, true },
     queue_attrib_get, (void*)SAI_QUEUE_ATTR_BUFFER_PROFILE_ID,
     queue_attr_buffer_profile_set, nullptr},
    {SAI_QUEUE_ATTR_PAUSE_STATUS,
     { false, false, false, true },
     { false, false, false, true },
     queue_attr_pause_status_get, nullptr,
     nullptr, nullptr},
    {SAI_QUEUE_ATTR_ENABLE_PFC_DLDR,
     { false, false, true, true },
     { false, false, true, true },
     queue_attr_enable_pfc_dldr_get, nullptr,
     queue_attr_enable_pfc_dldr_set, nullptr},
    {SAI_QUEUE_ATTR_PFC_DLR_INIT,
     { false, false, true, false },
     { false, false, true, false },
     nullptr, nullptr,
     queue_attr_pfc_dlr_init_set, nullptr},
    {SAI_QUEUE_ATTR_BUFFER_PROFILE_ID,
     { false, false, true, true },
     { false, false, true, true },
     queue_attrib_get, (void*)SAI_QUEUE_ATTR_BUFFER_PROFILE_ID,
     queue_attrib_set, (void*)SAI_QUEUE_ATTR_BUFFER_PROFILE_ID},
};
// clang-format on

static std::string
queue_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_queue_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
queue_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_queue(key->key.object_id);
    uint32_t port_index = la_queue.detail.get(lsai_detail_type_e::QUEUE, lsai_detail_field_e::PORT);

    lsai_object la_port(SAI_OBJECT_TYPE_PORT, la_queue.switch_id, port_index);
    auto sdev = la_queue.get_device();

    switch ((int64_t)arg) {
    case SAI_QUEUE_ATTR_BUFFER_PROFILE_ID: {
        auto profile_id = get_attr_value(SAI_QUEUE_ATTR_BUFFER_PROFILE_ID, (*value));
        sai_return_on_la_error(port_buffer_profile_set(la_port, la_queue.index, profile_id));
        break;
    }
    default:
        break;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
queue_attrib_get(_In_ const sai_object_key_t* key,
                 _Inout_ sai_attribute_value_t* value,
                 _In_ uint32_t attr_index,
                 _Inout_ vendor_cache_t* cache,
                 void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_queue(key->key.object_id);
    auto sdev = la_queue.get_device();
    uint32_t port_index = la_queue.detail.get(lsai_detail_type_e::QUEUE, lsai_detail_field_e::PORT);
    lsai_object la_port(SAI_OBJECT_TYPE_PORT, la_queue.switch_id, port_index);
    port_entry port_entry;
    sai_check_object(la_queue, SAI_OBJECT_TYPE_QUEUE, sdev, "queue", key->key.object_id);

    switch ((int64_t)arg) {
    case SAI_QUEUE_ATTR_TYPE:
        set_attr_value(SAI_QUEUE_ATTR_TYPE, *value, SAI_QUEUE_TYPE_ALL);
        return SAI_STATUS_SUCCESS;

    case SAI_QUEUE_ATTR_PARENT_SCHEDULER_NODE:
        la_port.get_device()->m_ports.get(port_index, port_entry);
        set_attr_value(SAI_QUEUE_ATTR_PARENT_SCHEDULER_NODE, *value, port_entry.m_sched_group_oids[la_queue.index + 1]);
        return SAI_STATUS_SUCCESS;

    case SAI_QUEUE_ATTR_PORT:
        set_attr_value(SAI_QUEUE_ATTR_PORT, *value, la_port.object_id());
        return SAI_STATUS_SUCCESS;

    case SAI_QUEUE_ATTR_INDEX:
        set_attr_value(SAI_QUEUE_ATTR_INDEX, *value, la_queue.index);
        return SAI_STATUS_SUCCESS;

    case SAI_QUEUE_ATTR_WRED_PROFILE_ID:
        la_port.get_device()->m_ports.get(port_index, port_entry);
        set_attr_value(SAI_QUEUE_ATTR_WRED_PROFILE_ID, *value, port_entry.wred_oids[la_queue.index]);
        return SAI_STATUS_SUCCESS;
    case SAI_QUEUE_ATTR_BUFFER_PROFILE_ID: {
        sai_object_id_t profile_id;
        sai_return_on_la_error(port_buffer_profile_get(la_port, la_queue.index, profile_id));
        set_attr_value(SAI_QUEUE_ATTR_BUFFER_PROFILE_ID, (*value), profile_id);
        break;
    }
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_queue::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    uint32_t ports_size;
    sdev->m_ports.get_object_count(sdev, &ports_size);

    sai_object_key_t ports_obj_ids[ports_size];
    sai_attribute_value_t num_queues;
    vendor_cache_t cache;
    void* arg = nullptr;
    *count = 0;

    sdev->m_laobj_db_port.get_object_keys(sdev, &ports_size, ports_obj_ids);

    for (uint32_t port_index = 0; port_index < ports_size; port_index++) {
        port_qos_number_of_queues_get(&ports_obj_ids[port_index], &num_queues, 0, &cache, arg);
        *count += num_queues.u32;
    }

    return SAI_STATUS_SUCCESS;
}

// going over all ports. retrieving list of queues for each
sai_status_t
laobj_db_queue::get_object_keys(std::shared_ptr<lsai_device> sdev, uint32_t* object_count, sai_object_key_t* object_list) const
{
    uint32_t ports_size;
    uint32_t requested_object_count = *object_count;
    sdev->m_ports.get_object_count(sdev, &ports_size);

    sai_object_key_t ports_obj_ids[ports_size];
    sai_attribute_value_t queues;
    sai_attribute_value_t num_queues;
    vendor_cache_t cache;
    void* arg = nullptr;
    sai_object_id_t queue_obj_id_list[NUM_QUEUE_PER_PORT];
    sai_status_t status;
    uint32_t object_index = 0;

    queues.objlist.list = queue_obj_id_list;

    sdev->m_laobj_db_port.get_object_keys(sdev, &ports_size, ports_obj_ids);
    *object_count = 0;

    for (uint32_t port_index = 0; port_index < ports_size; port_index++) {
        port_qos_number_of_queues_get(&ports_obj_ids[port_index], &num_queues, 0, &cache, arg);
        *object_count += num_queues.u32;
    }

    if (requested_object_count < *object_count) {
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    for (uint32_t port_index = 0; port_index < ports_size; port_index++) {
        port_qos_number_of_queues_get(&ports_obj_ids[port_index], &num_queues, 0, &cache, arg);

        queues.objlist.count = num_queues.u32;
        status = port_qos_queue_list_get(&ports_obj_ids[port_index], &queues, 0, &cache, arg);
        sai_return_on_error(status);

        for (uint32_t i = 0; i < num_queues.u32; i++) {
            object_list[object_index].key.object_id = queue_obj_id_list[i];
            object_index++;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
create_queue(_Out_ sai_object_id_t* queue_id,
             _In_ sai_object_id_t switch_id,
             _In_ uint32_t attr_count,
             _In_ const sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
remove_queue(_In_ sai_object_id_t queue_id)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
queue_attr_scheduler_profile_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_queue(key->key.object_id);
    uint32_t port_index = la_queue.detail.get(lsai_detail_type_e::QUEUE, lsai_detail_field_e::PORT);
    lsai_object la_port(SAI_OBJECT_TYPE_PORT, la_queue.switch_id, port_index);
    auto sdev = la_queue.get_device();

    auto oid_to_set = value->oid;

    // If setting SAI_NULL_OBJECT_ID, we use the default scheduler
    if (oid_to_set == sdev->m_sched_handler->default_scheduler()) {
        oid_to_set = SAI_NULL_OBJECT_ID;
    }

    sai_return_on_la_error(port_scheduler_config_change(la_port, la_queue.index, oid_to_set));

    return SAI_STATUS_SUCCESS;
}

sai_status_t
queue_attr_scheduler_profile_get(_In_ const sai_object_key_t* key,
                                 _Inout_ sai_attribute_value_t* value,
                                 _In_ uint32_t attr_index,
                                 _Inout_ vendor_cache_t* cache,
                                 void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_queue(key->key.object_id);
    uint32_t port_index = la_queue.detail.get(lsai_detail_type_e::QUEUE, lsai_detail_field_e::PORT);
    lsai_object la_port(SAI_OBJECT_TYPE_PORT, la_queue.switch_id, port_index);
    sai_object_id_t sched_oid;
    auto sdev = la_queue.get_device();

    sai_return_on_la_error(port_scheduler_config_get(la_port, la_queue.index, sched_oid));

    // If queue uses the default scheduler, return SAI_NULL_OBJECT_ID
    if (sched_oid == sdev->m_sched_handler->default_scheduler()) {
        sched_oid = SAI_NULL_OBJECT_ID;
    }

    set_attr_value(SAI_QUEUE_ATTR_SCHEDULER_PROFILE_ID, *value, sched_oid);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
queue_attr_pause_status_get(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_queue(key->key.object_id);
    auto sdev = la_queue.get_device();
    sai_check_object(la_queue, SAI_OBJECT_TYPE_QUEUE, sdev, "queue", key->key.object_id);

    uint32_t port_index = la_queue.detail.get(lsai_detail_type_e::QUEUE, lsai_detail_field_e::PORT);

    port_entry pentry{};
    sai_return_on_la_error(sdev->m_ports.get(port_index, pentry));

    if (!pentry.is_mac() || !pentry.pfc) {
        set_attr_value(SAI_QUEUE_ATTR_PAUSE_STATUS, *value, false);
        return SAI_STATUS_SUCCESS;
    }

    bool paused;
    sai_return_on_la_error(pentry.pfc->get_pfc_pause_status(la_queue.index, paused));
    set_attr_value(SAI_QUEUE_ATTR_PAUSE_STATUS, *value, paused);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
queue_attr_enable_pfc_dldr_get(_In_ const sai_object_key_t* key,
                               _Inout_ sai_attribute_value_t* value,
                               _In_ uint32_t attr_index,
                               _Inout_ vendor_cache_t* cache,
                               void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_queue(key->key.object_id);
    auto sdev = la_queue.get_device();
    sai_check_object(la_queue, SAI_OBJECT_TYPE_QUEUE, sdev, "queue", key->key.object_id);

    if (sdev->m_pfc_handler == nullptr) {
        return SAI_STATUS_UNINITIALIZED;
    }

    uint32_t port_index = la_queue.detail.get(lsai_detail_type_e::QUEUE, lsai_detail_field_e::PORT);
    port_entry pentry{};
    sai_return_on_la_error(sdev->m_ports.get(port_index, pentry));

    bool pfc_wdog_enabled = false;
    if (pentry.is_mac() && pentry.pfc) {
        sai_return_on_la_error(pentry.pfc->get_pfc_watchdog_enabled(la_queue.index, pfc_wdog_enabled));
    }
    set_attr_value(SAI_QUEUE_ATTR_ENABLE_PFC_DLDR, *value, pfc_wdog_enabled);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
queue_attr_enable_pfc_dldr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_queue(key->key.object_id);
    auto sdev = la_queue.get_device();

    uint32_t port_index = la_queue.detail.get(lsai_detail_type_e::QUEUE, lsai_detail_field_e::PORT);
    port_entry pentry{};
    sai_return_on_la_error(sdev->m_ports.get(port_index, pentry));

    // pfc must be initialized to proceed
    if (pentry.pfc == nullptr) {
        return (SAI_STATUS_UNINITIALIZED);
    }

    sai_return_on_la_error(pentry.pfc->set_pfc_watchdog_enabled(la_queue.index, value->booldata));

    return SAI_STATUS_SUCCESS;
}

sai_status_t
queue_attr_pfc_dlr_init_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_queue(key->key.object_id);
    auto sdev = la_queue.get_device();

    uint32_t port_index = la_queue.detail.get(lsai_detail_type_e::QUEUE, lsai_detail_field_e::PORT);
    port_entry pentry{};
    sai_return_on_la_error(sdev->m_ports.get(port_index, pentry));

    // pfc must be initialized to proceed
    if (pentry.pfc == nullptr) {
        return (SAI_STATUS_UNINITIALIZED);
    }

    sai_return_on_la_error(pentry.pfc->init_pfc_watchdog_recovery(la_queue.index, value->booldata));

    return SAI_STATUS_SUCCESS;
}

sai_status_t
queue_attr_buffer_profile_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    // TODO
    return SAI_STATUS_NOT_SUPPORTED;
}

sai_status_t
queue_attr_wred_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_queue(key->key.object_id);
    uint32_t port_index = la_queue.detail.get(lsai_detail_type_e::QUEUE, lsai_detail_field_e::PORT);
    lsai_object la_port(SAI_OBJECT_TYPE_PORT, la_queue.switch_id, port_index);

    la_status status = port_wred_config_change(la_port, la_queue.index, value->oid);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_queue_attribute(_In_ sai_object_id_t queue_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = queue_id;
    sai_start_api(SAI_API_QUEUE, SAI_OBJECT_TYPE_QUEUE, queue_id, &queue_to_string, queue_id, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "queue 0x%0lx", queue_id);

    return sai_set_attribute(&key, key_str, queue_attribs, queue_vendor_attribs, attr);
}

static sai_status_t
get_queue_attribute(_In_ sai_object_id_t queue_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = queue_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_QUEUE, SAI_OBJECT_TYPE_QUEUE, queue_id, &queue_to_string, queue_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "queue 0x%0lx", queue_id);
    return sai_get_attributes(&key, key_str, queue_attribs, queue_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
get_queue_stats_ext(_In_ sai_object_id_t queue_id,
                    _In_ uint32_t number_of_counters,
                    _In_ const sai_stat_id_t* counter_ids,
                    _In_ sai_stats_mode_t mode,
                    _Out_ uint64_t* counters)
{

    lsai_object la_obj(queue_id);
    auto sdev = la_obj.get_device();
    sai_start_api_counter(sdev);

    uint32_t port_index = la_obj.detail.get(lsai_detail_type_e::QUEUE, lsai_detail_field_e::PORT);
    port_entry pentry{};
    la_status status = sdev->m_ports.get(port_index, pentry);
    sai_return_on_la_error(status);

    if (pentry.sys_port == nullptr) {
        return SAI_STATUS_INVALID_PORT_MEMBER;
    }

    auto voq_counter_sets = pentry.get_voq_counter_sets();
    if (voq_counter_sets.size() == 0) {
        sai_log_error(SAI_API_QUEUE, "Failed getting voq counter sets for queue %d", queue_id);
        return SAI_STATUS_FAILURE;
    }

    size_t queue_packets = 0, queue_bytes = 0;
    size_t drop_packets = 0, drop_bytes = 0;
    sai_status_t sstatus;
    bool read_transmit = false;
    bool read_drop = false;

    for (uint32_t i = 0; i < number_of_counters; i++) {
        switch (counter_ids[i]) {
        case SAI_QUEUE_STAT_PACKETS:
            if (!read_transmit) {
                size_t packets = 0, bytes = 0;
                for (auto counter_set : voq_counter_sets) {
                    counter_set->read(
                        la_obj.index * 2, sdev->m_force_update, mode == SAI_STATS_MODE_READ_AND_CLEAR, packets, bytes);
                    queue_bytes += bytes;
                    queue_packets += packets;
                }
                read_transmit = true;
            }
            counters[i] = queue_packets;
            break;
        case SAI_QUEUE_STAT_BYTES:
            if (!read_transmit) {
                size_t packets = 0, bytes = 0;
                for (auto counter_set : voq_counter_sets) {
                    counter_set->read(
                        la_obj.index * 2, sdev->m_force_update, mode == SAI_STATS_MODE_READ_AND_CLEAR, packets, bytes);
                    queue_bytes += bytes;
                    queue_packets += packets;
                }
                read_transmit = true;
            }
            counters[i] = queue_bytes;
            break;
        case SAI_QUEUE_STAT_DROPPED_PACKETS:
            if (!read_drop) {
                size_t packets = 0, bytes = 0;
                for (auto counter_set : voq_counter_sets) {
                    counter_set->read(
                        la_obj.index * 2 + 1, sdev->m_force_update, mode == SAI_STATS_MODE_READ_AND_CLEAR, packets, bytes);
                    drop_bytes += bytes;
                    drop_packets += packets;
                }
                read_drop = true;
            }
            counters[i] = drop_packets;
            break;
        case SAI_QUEUE_STAT_DROPPED_BYTES:
            if (!read_drop) {
                size_t packets = 0, bytes = 0;
                for (auto counter_set : voq_counter_sets) {
                    counter_set->read(
                        la_obj.index * 2 + 1, sdev->m_force_update, mode == SAI_STATS_MODE_READ_AND_CLEAR, packets, bytes);
                    drop_bytes += bytes;
                    drop_packets += packets;
                }
                read_drop = true;
            }
            counters[i] = drop_bytes;
            break;
        case SAI_QUEUE_STAT_WATERMARK_BYTES:
            sstatus = read_egress_congestion_watermark(pentry.sys_port, queue_id, mode, counters[i]);
            sai_return_on_error(sstatus);
            break;
        case SAI_QUEUE_STAT_CURR_OCCUPANCY_BYTES: {
            size_t occupancy_bytes = 0;
            auto voq_sets = pentry.get_voq_sets();
            if (voq_sets.size() == 0) {
                sai_log_error(SAI_API_QUEUE, "Failed getting voq counter sets for queue %d", queue_id);
                return SAI_STATUS_FAILURE;
            }
            for (auto voq_set : voq_sets) {
                size_t depth = 0;
                sstatus = read_queue_depth_in_bytes(voq_set, la_obj, depth);
                sai_return_on_error(sstatus);
                occupancy_bytes += depth;
            }
            counters[i] = occupancy_bytes;
        } break;
        case SAI_QUEUE_STAT_WRED_ECN_MARKED_PACKETS:
            sstatus = read_ecn_marked_packets(sdev, pentry.service.eth_port, la_obj.index, la_obj.index, mode, counters[i]);
            sai_return_on_error(sstatus);
            break;
        default:
            if (counter_ids[i] <= SAI_QUEUE_STAT_WRED_ECN_MARKED_BYTES) {
                sai_log_info(SAI_API_QUEUE, "Queue counter %d (index %u) not implemented\n", counter_ids[i], i);
                return SAI_STATUS_ATTR_NOT_SUPPORTED_0 + i;
            } else {
                sai_log_error(SAI_API_QUEUE, "Invalid queue counter %d (index %u)\n", counter_ids[i], i);
                return SAI_STATUS_INVALID_PARAMETER;
            }

            break;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
read_queue_depth_in_bytes(la_voq_set* voq_set, lsai_object& queue_obj, uint64_t& counter)
{
    la_voq_set::voq_size out_size;
    size_t total_sms_bytes = 0;
    size_t total_hbm_bytes = 0;
    auto sdev = queue_obj.get_device();

    for (la_slice_id_t slice_id = 0; slice_id < sdev->m_dev_params.slices_per_dev; ++slice_id) {
        la_status status = voq_set->get_voq_size(queue_obj.index, slice_id, out_size);
        sai_return_on_la_error(status);

        total_sms_bytes += out_size.sms_bytes;
        total_hbm_bytes += out_size.hbm_bytes;
    }
    counter = total_sms_bytes + total_hbm_bytes;
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
read_egress_congestion_watermark(la_system_port* system_port, sai_object_id_t queue_id, sai_stats_mode_t mode, uint64_t& counter)
{
    lsai_object queue_obj(queue_id);
    la_traffic_class_t tc = queue_obj.index;

    auto sdev = queue_obj.get_device();

    // for pacific return SAI_STATUS_NOT_IMPLEMENTED
    if (sdev->m_hw_device_type == hw_device_type_e::PACIFIC) {
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    tc = queue_obj.index;

    bool update_qwm = false, update_shadow = false;

    lsai_stats_shadow<queue_watermark_stats>* shadow_ptr = nullptr;
    queue_watermark_stats* w_ptr = nullptr;

    auto wstats = queue_watermark_shadow.find(queue_id);
    if (wstats != queue_watermark_shadow.end()) {
        shadow_ptr = &wstats->second;
        if (shadow_ptr != nullptr) {
            la_status status = shadow_ptr->get_data(sdev, w_ptr, SAI_STATS_MODE_READ);
            if (status != LA_STATUS_SUCCESS) {
                update_shadow = true;
            }
        }
    } else {
        update_qwm = true;
    }

    queue_watermark_stats qws;
    if (update_shadow || update_qwm) {
        lsai_stats_shadow<queue_watermark_stats> qw_shadow;
        la_status status
            = system_port->read_egress_congestion_watermark(tc, mode == SAI_STATS_MODE_READ_AND_CLEAR, qws.egress_cgm_watermark);
        sai_return_on_la_error(status);

        status = system_port->read_egress_delay_watermark(tc, mode == SAI_STATS_MODE_READ_AND_CLEAR, qws.egress_delay_watermark);
        sai_return_on_la_error(status);

        if (update_shadow && shadow_ptr != nullptr) {
            shadow_ptr->set_data(qws, SAI_STATS_MODE_READ);
        } else {
            qw_shadow.set_data(qws, SAI_STATS_MODE_READ);
            queue_watermark_shadow[queue_id] = qw_shadow;
        }
        w_ptr = &qws;
    }

    if (w_ptr == nullptr) {
        sai_log_error(SAI_API_QUEUE, "Error in getting Queue water mark shadow");
        return SAI_STATUS_FAILURE;
    }

    la_cgm_congestion_level_t cgm_level = w_ptr->egress_cgm_watermark.max_congestion_level;
    size_t delay = w_ptr->egress_delay_watermark.max_delay;

    if ((cgm_level == 0) && (delay == 0)) {
        // Delay 0 means no packet seen at all, report 0 rather than the lowest level
        counter = 0;
    } else {
        counter = sdev->m_wred_handler->cgm_level_to_bytes(cgm_level);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_queue_stats(_In_ sai_object_id_t queue_id,
                _In_ uint32_t number_of_counters,
                _In_ const sai_stat_id_t* counter_ids,
                _Out_ uint64_t* counters)
{
    return get_queue_stats_ext(queue_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ, counters);
}

static sai_status_t
clear_queue_stats(_In_ sai_object_id_t queue_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t* counter_ids)
{
    uint64_t counters[number_of_counters];
    return get_queue_stats_ext(queue_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ_AND_CLEAR, counters);
}

const sai_queue_api_t queue_api = {create_queue,
                                   remove_queue,
                                   set_queue_attribute,
                                   get_queue_attribute,
                                   get_queue_stats,
                                   get_queue_stats_ext,
                                   clear_queue_stats};
}
}
