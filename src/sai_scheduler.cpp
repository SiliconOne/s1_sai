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

#include "sai_device.h"
#include "sai_logger.h"
#include "sai_port.h"
#include "sai_scheduler.h"

namespace silicon_one
{
namespace sai
{

using namespace std;

//======================================================================
extern const sai_attribute_entry_t scheduler_attribs[] = {
    // id; mandatory_on_create; valid_for_create; valid_for_set; valid_for_get
    // *attrib_name; type;
    {SAI_SCHEDULER_ATTR_SCHEDULING_TYPE, true, true, true, true, "Scheduler, scheduling type", SAI_ATTR_VAL_TYPE_S32},
    {SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT, false, true, true, true, "Scheduler, scheduling wieght", SAI_ATTR_VAL_TYPE_U8},
    {SAI_SCHEDULER_ATTR_METER_TYPE, false, true, true, true, "Scheduler, meter type", SAI_ATTR_VAL_TYPE_S32},
    {SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE, false, false, false, true, "Scheduler, minimum bandwidth rate", SAI_ATTR_VAL_TYPE_U64},
    {SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_BURST_RATE,
     false,
     false,
     false,
     false,
     "Scheduler, minimum bandwidth burst rate",
     SAI_ATTR_VAL_TYPE_U64},
    {SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE, false, true, true, true, "Scheduler, maximum bandwidth rate", SAI_ATTR_VAL_TYPE_U64},
    {SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_BURST_RATE,
     false,
     false,
     false,
     false,
     "Scheduler, maximum bandwidth burst rate",
     SAI_ATTR_VAL_TYPE_U64},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t scheduler_vendor_attribs[] = {
    /* create, remove, set, get */
    {SAI_SCHEDULER_ATTR_SCHEDULING_TYPE,
     {true, false, true, true}, /* implemented */
     {true, false, true, true}, /* supported */
     lsai_sched::sai_scheduler_attr_scheduling_type_get,
     nullptr,
     lsai_sched::sai_scheduler_attr_scheduling_type_set,
     nullptr},

    {SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT,
     {true, false, true, true}, /* implemented */
     {true, false, true, true}, /* supported */
     lsai_sched::sai_scheduler_attr_scheduling_weight_get,
     nullptr,
     lsai_sched::sai_scheduler_attr_scheduling_weight_set,
     nullptr},

    {SAI_SCHEDULER_ATTR_METER_TYPE,
     {true, false, true, true}, /* implemented */
     {true, false, true, true}, /* supported */
     lsai_sched::sai_scheduler_attr_meter_type_get,
     nullptr,
     lsai_sched::sai_scheduler_attr_meter_type_set,
     nullptr},

    {SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE,
     {false, false, false, true}, /* implemented */
     {false, false, false, true}, /* supported */
     lsai_sched::sai_scheduler_attr_min_bandwidth_get,
     nullptr,
     nullptr,
     nullptr},

    {SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_BURST_RATE,
     {false, false, false, false}, /* implemented */
     {false, false, false, false}, /* supported */
     nullptr,
     nullptr,
     nullptr,
     nullptr},

    {SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE,
     {true, false, true, true}, /* implemented */
     {true, false, true, true}, /* supported */
     lsai_sched::sai_scheduler_attr_max_bandwidth_rate_get,
     nullptr,
     lsai_sched::sai_scheduler_attr_max_bandwidth_rate_set,
     nullptr},

    {SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_BURST_RATE,
     {false, false, false, false}, /* implemented */
     {false, false, false, false}, /* supported */
     nullptr,
     nullptr,
     nullptr,
     nullptr},
};

static std::string
scheduler_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_scheduler_attr_t)attr.id;
    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";
    return log_message.str();
}

sai_status_t
lsai_sched::check_and_get_device_and_scheduler_index(_In_ sai_object_id_t obj_id,
                                                     _In_ sai_object_type_t type,
                                                     _Out_ std::shared_ptr<lsai_device>& out_sdev,
                                                     _Out_ uint32_t& out_id)
{
    lsai_object la_obj(obj_id);
    out_sdev = la_obj.get_device();
    if (la_obj.type != type || out_sdev == nullptr || out_sdev->m_dev == nullptr) {
        sai_log_error(SAI_API_SCHEDULER, "Bad scheduler Object id %lu", obj_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    out_id = la_obj.index;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched::get_scheduler_and_check_attr(_In_ const sai_object_key_t* key,
                                         _Inout_ sai_attribute_value_t* attr,
                                         _Out_ lasai_scheduling_params& scheduler)
{
    if (key == nullptr || attr == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status_t sstatus;
    la_status status;
    sai_object_id_t scheduler_id = key->key.object_id;

    std::shared_ptr<lsai_device> sdev;
    uint32_t scheduler_index;
    sstatus = check_and_get_device_and_scheduler_index(scheduler_id, SAI_OBJECT_TYPE_SCHEDULER, sdev, scheduler_index);
    sai_return_on_error(sstatus);

    status = sdev->m_sched_handler->m_scheduler_db.get(scheduler_index, scheduler);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched::get_type(sai_object_id_t oid, sai_scheduling_type_t& type)
{
    lsai_object la_obj(oid);
    lasai_scheduling_params sched_param;

    sai_return_on_la_error(m_scheduler_db.get(la_obj.index, sched_param));

    type = sched_param.type();
    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched::get_weight(sai_object_id_t oid, uint8_t& weight)
{
    lsai_object la_obj(oid);
    lasai_scheduling_params sched_param;

    sai_return_on_la_error(m_scheduler_db.get(la_obj.index, sched_param));

    weight = sched_param.weight();
    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched::get_pir(sai_object_id_t oid, uint64_t& pir)
{
    lsai_object la_obj(oid);
    lasai_scheduling_params sched_param;

    sai_return_on_la_error(m_scheduler_db.get(la_obj.index, sched_param));

    pir = sched_param.pir();

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched::get_meter_type(sai_object_id_t oid, uint32_t& meter_type)
{
    lsai_object la_obj(oid);
    lasai_scheduling_params sched_param;

    sai_return_on_la_error(m_scheduler_db.get(la_obj.index, sched_param));

    meter_type = sched_param.meter_type();
    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched::sai_scheduler_attr_scheduling_type_set(_In_ const sai_object_key_t* key,
                                                   _In_ const sai_attribute_value_t* value,
                                                   void* arg)
{
    sai_status_t sstatus;
    sai_object_id_t scheduler_oid = key->key.object_id;

    std::shared_ptr<lsai_device> sdev;
    uint32_t scheduler_index;
    auto type = get_attr_value(SAI_SCHEDULER_ATTR_SCHEDULING_TYPE, (*value));

    sstatus = check_and_get_device_and_scheduler_index(scheduler_oid, SAI_OBJECT_TYPE_SCHEDULER, sdev, scheduler_index);
    sai_return_on_error(sstatus);

    lasai_scheduling_params* scheduler = sdev->m_sched_handler->m_scheduler_db.get_ptr(scheduler_index);
    if (scheduler == nullptr) {
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    scheduler->set_type(type);
    // when changing type, reset weight to 1
    scheduler->set_weight(1);

    // update all queues using this scheduler
    for (auto port_oid : scheduler->m_using_ports) {
        port_entry port;
        lsai_object la_obj(port_oid);
        sdev->m_ports.get(la_obj.index, port);
        port_scheduling_params_update(port_oid, scheduler_oid);
    }
    // update all scheduler groups using this scheduler

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched::sai_scheduler_attr_scheduling_type_get(_In_ const sai_object_key_t* key,
                                                   _Inout_ sai_attribute_value_t* attr,
                                                   _In_ uint32_t attr_index,
                                                   _Inout_ vendor_cache_t* cache,
                                                   void* arg)
{
    lasai_scheduling_params scheduler;
    sai_status_t sstatus;

    sstatus = get_scheduler_and_check_attr(key, attr, scheduler);
    sai_return_on_error(sstatus);

    set_attr_value(SAI_SCHEDULER_ATTR_SCHEDULING_TYPE, (*attr), scheduler.m_type);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched::sai_scheduler_attr_scheduling_weight_set(_In_ const sai_object_key_t* key,
                                                     _In_ const sai_attribute_value_t* value,
                                                     void* arg)
{
    sai_status_t sstatus;
    sai_object_id_t scheduler_oid = key->key.object_id;

    std::shared_ptr<lsai_device> sdev;
    uint32_t scheduler_index;
    auto weight = get_attr_value(SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT, (*value));

    sstatus = check_and_get_device_and_scheduler_index(scheduler_oid, SAI_OBJECT_TYPE_SCHEDULER, sdev, scheduler_index);
    sai_return_on_error(sstatus);

    lasai_scheduling_params* scheduler = sdev->m_sched_handler->m_scheduler_db.get_ptr(scheduler_index);
    if (scheduler == nullptr) {
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    scheduler->set_weight(weight);

    // update all queues using this scheduler
    for (auto port_oid : scheduler->m_using_ports) {
        port_entry port;
        lsai_object la_obj(port_oid);
        sdev->m_ports.get(la_obj.index, port);
        port_scheduling_params_update(port_oid, scheduler_oid);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched::sai_scheduler_attr_scheduling_weight_get(_In_ const sai_object_key_t* key,
                                                     _Inout_ sai_attribute_value_t* attr,
                                                     _In_ uint32_t attr_index,
                                                     _Inout_ vendor_cache_t* cache,
                                                     void* arg)
{
    lasai_scheduling_params scheduler;
    sai_status_t sstatus;

    sstatus = get_scheduler_and_check_attr(key, attr, scheduler);
    sai_return_on_error(sstatus);

    set_attr_value(SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT, (*attr), scheduler.m_weight);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched::sai_scheduler_attr_max_bandwidth_rate_set(_In_ const sai_object_key_t* key,
                                                      _In_ const sai_attribute_value_t* value,
                                                      void* arg)
{
    sai_status_t sstatus;
    sai_object_id_t scheduler_oid = key->key.object_id;

    std::shared_ptr<lsai_device> sdev;
    uint32_t scheduler_index;
    auto pir = get_attr_value(SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE, (*value));

    sstatus = check_and_get_device_and_scheduler_index(scheduler_oid, SAI_OBJECT_TYPE_SCHEDULER, sdev, scheduler_index);
    sai_return_on_error(sstatus);

    lasai_scheduling_params* scheduler = sdev->m_sched_handler->m_scheduler_db.get_ptr(scheduler_index);
    if (scheduler == nullptr) {
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    scheduler->set_pir(pir);

    // update all queues using this scheduler
    for (auto port_oid : scheduler->m_using_ports) {
        port_entry port;
        lsai_object la_obj(port_oid);
        sdev->m_ports.get(la_obj.index, port);
        port_scheduling_params_update(port_oid, scheduler_oid);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched::sai_scheduler_attr_max_bandwidth_rate_get(_In_ const sai_object_key_t* key,
                                                      _Inout_ sai_attribute_value_t* attr,
                                                      _In_ uint32_t attr_index,
                                                      _Inout_ vendor_cache_t* cache,
                                                      void* arg)
{
    lasai_scheduling_params scheduler;
    sai_status_t sstatus;

    sstatus = get_scheduler_and_check_attr(key, attr, scheduler);
    sai_return_on_error(sstatus);

    uint64_t max_bandwidth_rate;

    // Return max_bandwidth rate in bytes per second
    max_bandwidth_rate = scheduler.m_pir / 8;

    set_attr_value(SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE, (*attr), max_bandwidth_rate);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched::sai_scheduler_attr_meter_type_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    sai_status_t sstatus;
    sai_object_id_t scheduler_oid = key->key.object_id;

    std::shared_ptr<lsai_device> sdev;
    uint32_t scheduler_index;
    auto meter_type = get_attr_value(SAI_SCHEDULER_ATTR_METER_TYPE, (*value));

    sstatus = check_and_get_device_and_scheduler_index(scheduler_oid, SAI_OBJECT_TYPE_SCHEDULER, sdev, scheduler_index);
    sai_return_on_error(sstatus);

    lasai_scheduling_params* scheduler = sdev->m_sched_handler->m_scheduler_db.get_ptr(scheduler_index);
    if (scheduler == nullptr) {
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    if (meter_type != SAI_METER_TYPE_BYTES) {
        return SAI_STATUS_NOT_SUPPORTED;
    }

    scheduler->set_meter_type(meter_type);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched::sai_scheduler_attr_min_bandwidth_get(_In_ const sai_object_key_t* key,
                                                 _Inout_ sai_attribute_value_t* attr,
                                                 _In_ uint32_t attr_index,
                                                 _Inout_ vendor_cache_t* cache,
                                                 void* arg)
{
    set_attr_value(SAI_SCHEDULER_ATTR_MIN_BANDWIDTH_RATE, (*attr), 0);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched::sai_scheduler_attr_meter_type_get(_In_ const sai_object_key_t* key,
                                              _Inout_ sai_attribute_value_t* attr,
                                              _In_ uint32_t attr_index,
                                              _Inout_ vendor_cache_t* cache,
                                              void* arg)
{
    lasai_scheduling_params scheduler;
    sai_status_t sstatus;

    sstatus = get_scheduler_and_check_attr(key, attr, scheduler);
    sai_return_on_error(sstatus);

    set_attr_value(SAI_SCHEDULER_ATTR_METER_TYPE, (*attr), scheduler.m_meter_type);

    return SAI_STATUS_SUCCESS;
}

sai_object_id_t
lsai_sched::default_scheduler()
{
    if (m_default_scheduler == 0) {
        create_default_scheduler();
    }

    return m_default_scheduler;
}

void
lsai_sched::create_default_scheduler()
{
    sai_scheduling_type_t scheduling_type = SAI_SCHEDULING_TYPE_WRR;
    uint8_t scheduling_weight = 1;
    lasai_scheduling_params scheduler(scheduling_type, scheduling_weight);
    uint32_t scheduler_index;

    m_scheduler_db.insert(scheduler, scheduler_index);
    m_scheduler_db.set_ignore_in_get_num(1);
    lsai_object sw_id(m_lsai_device->m_switch_id);
    lsai_object la_scheduler_id(SAI_OBJECT_TYPE_SCHEDULER, sw_id.index, scheduler_index);
    m_default_scheduler = la_scheduler_id.object_id();

    sai_log_debug(SAI_API_SCHEDULER, "default scheduler 0x%lx created", m_default_scheduler);
}

// old_sched_oid, and new_sched_oid must exist in the DB when calling this function
void
lsai_sched::update_scheduler_used_ports(sai_object_id_t port_oid, sai_object_id_t new_sched_oid, sai_object_id_t old_sched_oid)
{
    lsai_object new_sched_la_obj(new_sched_oid);
    lasai_scheduling_params* scheduler = m_scheduler_db.get_ptr(new_sched_la_obj.index);
    scheduler->m_using_ports.insert(port_oid);

    if (old_sched_oid != 0) {
        lsai_object old_sched_la_obj(old_sched_oid);
        lasai_scheduling_params* old_scheduler = m_scheduler_db.get_ptr(old_sched_la_obj.index);
        old_scheduler->m_using_ports.erase(port_oid);
    }
}

/**
 * @brief Create a scheduler
 *
 * @param[out] out_scheduler_id scheduler Id
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t
lsai_sched::create_scheduler(_Out_ sai_object_id_t* out_scheduler_id,
                             _In_ sai_object_id_t switch_id,
                             _In_ uint32_t attr_count,
                             _In_ const sai_attribute_t* attr_list)
{
    transaction txn;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_SCHEDULER, SAI_OBJECT_TYPE_SWITCH, switch_id, &scheduler_to_string, switch_id, attrs);

    sai_scheduling_type_t scheduling_type;
    get_attrs_value(SAI_SCHEDULER_ATTR_SCHEDULING_TYPE, attrs, scheduling_type, true);

    uint8_t scheduling_weight = 1;
    get_attrs_value(SAI_SCHEDULER_ATTR_SCHEDULING_WEIGHT, attrs, scheduling_weight, false);

    uint64_t max_bandwidth = 0;
    get_attrs_value(SAI_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE, attrs, max_bandwidth, false);

    sai_meter_type_t meter_type = SAI_METER_TYPE_BYTES;
    get_attrs_value(SAI_SCHEDULER_ATTR_METER_TYPE, attrs, meter_type, false);

    if (meter_type == SAI_METER_TYPE_BYTES) {
        max_bandwidth = max_bandwidth * 8;
    } else {
        // unsupported
        sai_log_error(SAI_API_SCHEDULER, "Scheduler only supports bytes per second meter type");
        return SAI_STATUS_NOT_SUPPORTED;
    }

    uint32_t scheduler_index = 0;
    lasai_scheduling_params scheduler(scheduling_type, scheduling_weight, max_bandwidth, meter_type);

    la_status status = sdev->m_sched_handler->m_scheduler_db.insert(scheduler, scheduler_index);
    sai_return_on_la_error(status, "Failed allocating scheduler ID");
    lsai_object la_scheduler_id(SAI_OBJECT_TYPE_SCHEDULER, switch_id, scheduler_index);
    *out_scheduler_id = la_scheduler_id.object_id();

    sai_log_info(SAI_API_SCHEDULER, "scheduler 0x%lx created", *out_scheduler_id);

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Remove an existing scheduler
 *
 * @param[in] scheduler_id scheduler Id
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t
lsai_sched::remove_scheduler(_In_ sai_object_id_t scheduler_id)
{
    lasai_scheduling_params scheduler;

    sai_start_api(SAI_API_SCHEDULER, SAI_OBJECT_TYPE_SCHEDULER, scheduler_id, &scheduler_to_string, scheduler_id);

    la_status status = sdev->m_sched_handler->m_scheduler_db.get(la_obj.index, scheduler);
    sai_return_on_la_error(status, "Failed to remove scheduler, %s because it does not exist", status.message().c_str());

    // Can't remove scheduler which is in use by some queue
    if (!scheduler.m_using_ports.empty()) {
        return SAI_STATUS_OBJECT_IN_USE;
    }

    status = sdev->m_sched_handler->m_scheduler_db.remove(la_obj.index);
    sai_return_on_la_error(status, "Failed to remove scheduler, %s", status.message().c_str());

    sai_log_info(SAI_API_SCHEDULER, "scheduler 0x%lx removed", scheduler_id);

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Set an attribute in a scheduler
 *
 * @param[in] scheduler_id scheduler Id
 * @param[in] attr An attribute to set
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t
lsai_sched::set_scheduler_attribute(_In_ sai_object_id_t scheduler_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = scheduler_id;

    sai_start_api(SAI_API_SCHEDULER, SAI_OBJECT_TYPE_SCHEDULER, scheduler_id, &scheduler_to_string, scheduler_id, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "scheduler 0x%0lx", scheduler_id);
    return sai_set_attribute(&key, key_str, scheduler_attribs, scheduler_vendor_attribs, attr);
}

/**
 * @brief Get one or more attributes of a scheduler
 *
 * @param[in] scheduler_id scheduler ID
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t
lsai_sched::get_scheduler_attribute(_In_ sai_object_id_t scheduler_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = scheduler_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_SCHEDULER, SAI_OBJECT_TYPE_SCHEDULER, scheduler_id, &scheduler_to_string, scheduler_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "scheduler 0x%0lx", scheduler_id);
    return sai_get_attributes(&key, key_str, scheduler_attribs, scheduler_vendor_attribs, attr_count, attr_list);
}

void
lsai_sched::dump_json(json_t* parent_json) const
{
    uint32_t obj_count;
    json_t* all_json = json_object();
    json_object_set_new(parent_json, "schedulers", all_json);

    m_scheduler_db.get_object_count(m_lsai_device, &obj_count);

    sai_object_key_t obj_list[obj_count];
    m_scheduler_db.get_object_keys(m_lsai_device, &obj_count, obj_list);

    for (uint32_t i = 0; i < obj_count; i++) {
        std::stringstream ss;
        ss << std::hex << "scheduler 0x" << obj_list[i].key.object_id;
        json_t* one_obj_json = json_object();
        json_object_set_new(all_json, ss.str().c_str(), one_obj_json);

        lasai_scheduling_params sched_params;
        lsai_object la_obj;
        m_scheduler_db.get(obj_list[i].key.object_id, sched_params, la_obj);
        switch (sched_params.m_type) {
        case SAI_SCHEDULING_TYPE_STRICT:
            json_object_set_new(one_obj_json, "type", json_string("STRICT"));
            break;
        case SAI_SCHEDULING_TYPE_WRR:
            json_object_set_new(one_obj_json, "type", json_string("WRR"));
            break;
        case SAI_SCHEDULING_TYPE_DWRR:
            json_object_set_new(one_obj_json, "type", json_string("DWRR"));
            break;
        default:
            json_object_set_new(one_obj_json, "type", json_integer(sched_params.m_type));
            break;
        }
        json_object_set_new(one_obj_json, "weight", json_integer(sched_params.m_weight));

        json_t* array = json_array();
        for (auto port_id : sched_params.m_using_ports) {
            std::stringstream ss;
            ss.str("");
            ss << std::hex << "0x" << port_id;
            json_array_append_new(array, json_string(ss.str().c_str()));
        }
        json_object_set_new(one_obj_json, "using ports", array);
    }

    std::stringstream ss;
    ss << std::hex << "default scheduler 0x" << m_default_scheduler;
    json_t* one_obj_json = json_object();
    json_object_set_new(all_json, ss.str().c_str(), one_obj_json);
}

/**
 * @brief scheduler methods table retrieved with sai_api_query()
 */
const sai_scheduler_api_t scheduler_api = {lsai_sched::create_scheduler,
                                           lsai_sched::remove_scheduler,
                                           lsai_sched::set_scheduler_attribute,
                                           lsai_sched::get_scheduler_attribute};
}
}
