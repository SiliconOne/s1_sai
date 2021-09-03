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

#include <cassert>
#include "api/system/la_device.h"
#include "common/gen_utils.h"
#include "common/ranged_index_generator.h"
#include "sai_config_parser.h"
#include "sai_constants.h"
#include "sai_device.h"
#include "sai_port.h"
#include "sai_scheduler_group.h"

namespace silicon_one
{
namespace sai
{

using namespace std;

// clang-format off

extern const sai_attribute_entry_t scheduler_group_attribs[] = {
    // id; mandatory_on_create; valid_for_create; valid_for_set; valid_for_get;  attrib_name; type;
    {SAI_SCHEDULER_GROUP_ATTR_CHILD_COUNT, false, false, false, true, "Scheduler group, child count", SAI_ATTR_VAL_TYPE_U32},
    {SAI_SCHEDULER_GROUP_ATTR_CHILD_LIST, false, false, false, true, "Scheduler group, child list", SAI_ATTR_VAL_TYPE_OBJLIST},
    {SAI_SCHEDULER_GROUP_ATTR_PORT_ID, true, true, false, true, "Scheduler group, port", SAI_ATTR_VAL_TYPE_OID},
    {SAI_SCHEDULER_GROUP_ATTR_LEVEL, true, true, false, true, "Scheduler group, level", SAI_ATTR_VAL_TYPE_U8},
    {SAI_SCHEDULER_GROUP_ATTR_MAX_CHILDS, true, true, false, true, "Scheduler group, max childs", SAI_ATTR_VAL_TYPE_U8},
    {SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID, true, true, true, true, "Scheduler group, max childs", SAI_ATTR_VAL_TYPE_OID},
    {SAI_SCHEDULER_GROUP_ATTR_PARENT_NODE, true, true, true, true, "Scheduler group, max childs", SAI_ATTR_VAL_TYPE_OID},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t scheduler_group_vendor_attribs[] = {
        SAI_ATTR_READ_ONLY(SAI_SCHEDULER_GROUP_ATTR_CHILD_COUNT, lsai_sched_group::internal_get_attr),
        SAI_ATTR_READ_ONLY(SAI_SCHEDULER_GROUP_ATTR_CHILD_LIST, lsai_sched_group::internal_get_attr),
        SAI_ATTR_CREATE_ONLY(SAI_SCHEDULER_GROUP_ATTR_PORT_ID, lsai_sched_group::internal_get_attr),
        SAI_ATTR_CREATE_ONLY(SAI_SCHEDULER_GROUP_ATTR_LEVEL, lsai_sched_group::internal_get_attr),
        SAI_ATTR_CREATE_ONLY(SAI_SCHEDULER_GROUP_ATTR_MAX_CHILDS, lsai_sched_group::internal_get_attr),
        SAI_ATTR_CREATE_AND_SET(SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID, lsai_sched_group::internal_get_attr, lsai_sched_group::scheduler_group_attr_scheduler_profile_id_set),
        SAI_ATTR_CREATE_AND_SET(SAI_SCHEDULER_GROUP_ATTR_PARENT_NODE, lsai_sched_group::internal_get_attr, lsai_sched_group::internal_set_attr)
};

// clang-format on

static std::string
scheduler_group_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_scheduler_group_attr_t)attr.id;
    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";
    return log_message.str();
}

sai_status_t
laobj_db_scheduler_group::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    // TODO
    uint32_t num = 0;
    *count = num;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_scheduler_group::get_object_keys(std::shared_ptr<lsai_device> sdev,
                                          uint32_t* object_count,
                                          sai_object_key_t* object_list) const
{
    // TODO
    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched_group::set_scheduler_group_attribute(sai_object_id_t sched_group_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = sched_group_id;

    sai_start_api(SAI_API_SCHEDULER_GROUP,
                  SAI_OBJECT_TYPE_SCHEDULER_GROUP,
                  sched_group_id,
                  &scheduler_group_to_string,
                  sched_group_id,
                  *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "scheduler group 0x%0lx", sched_group_id);
    return sai_set_attribute(&key, key_str, scheduler_group_attribs, scheduler_group_vendor_attribs, attr);
}

sai_status_t
lsai_sched_group::get_scheduler_group_attribute(sai_object_id_t sched_group_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = sched_group_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_SCHEDULER_GROUP,
                  SAI_OBJECT_TYPE_SCHEDULER_GROUP,
                  sched_group_id,
                  &scheduler_group_to_string,
                  sched_group_id,
                  attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "scheduler group 0x%0lx", sched_group_id);
    return sai_get_attributes(&key, key_str, scheduler_group_attribs, scheduler_group_vendor_attribs, attr_count, attr_list);
}

sai_status_t
lsai_sched_group::internal_get_attr(_In_ const sai_object_key_t* key,
                                    _Inout_ sai_attribute_value_t* value,
                                    _In_ uint32_t attr_index,
                                    _Inout_ vendor_cache_t* cache,
                                    void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_sch_group(key->key.object_id);
    auto sdev = la_sch_group.get_device();
    uint32_t port_index = la_sch_group.detail.get(lsai_detail_type_e::SCHEDULER_GROUP, lsai_detail_field_e::PORT);
    lsai_object la_port(SAI_OBJECT_TYPE_PORT, la_sch_group.switch_id, port_index);
    sai_check_object(la_sch_group, SAI_OBJECT_TYPE_SCHEDULER_GROUP, sdev, "scheduler group", key->key.object_id);

    port_entry port_entry;
    la_port.get_device()->m_ports.get(la_port.index, port_entry);
    bool is_port_sched = false;
    sai_object_id_t sched_group_obj = la_sch_group.object_id();
    if (sched_group_obj == port_entry.m_sched_group_oids[0]) {
        is_port_sched = true;
    }

    switch ((int64_t)arg) {
    case SAI_SCHEDULER_GROUP_ATTR_CHILD_COUNT:
        // if port sched return 8 otherwise return 0
        if (is_port_sched) {
            set_attr_value(SAI_SCHEDULER_GROUP_ATTR_CHILD_COUNT, *value, 8);
        } else {
            set_attr_value(SAI_SCHEDULER_GROUP_ATTR_CHILD_COUNT, *value, 1);
        }
        break;
    case SAI_SCHEDULER_GROUP_ATTR_CHILD_LIST:
        // for port sched return list with 8 objects
        if (is_port_sched) {
            std::vector<sai_object_id_t> output_vec;

            // start from 1 since index 0 would be the port scheduler
            for (uint32_t i = 1; i < NUM_QUEUE_PER_PORT + 1; i++) {
                output_vec.push_back(port_entry.m_sched_group_oids[i]);
            }
            return fill_sai_list(output_vec.begin(), output_vec.end(), value->objlist);
        } else {
            // get the queues obj ids
            sai_object_key_t port_obj_id;
            port_obj_id.key.object_id = port_entry.service.oid;
            sai_attribute_value_t queues;
            vendor_cache_t cache;
            void* arg = nullptr;
            sai_object_id_t queue_obj_id_list[NUM_QUEUE_PER_PORT];
            queues.objlist.list = queue_obj_id_list;
            queues.objlist.count = NUM_QUEUE_PER_PORT;
            port_qos_queue_list_get(&port_obj_id, &queues, 0, &cache, arg);

            uint32_t scheduler_group_index;
            sai_status_t sstatus = check_and_get_device_and_scheduler_group_index(
                sched_group_obj, SAI_OBJECT_TYPE_SCHEDULER_GROUP, sdev, scheduler_group_index);
            sai_return_on_error(sstatus);

            std::vector<sai_object_id_t> output_vec;
            // queue index is 1 less than the scheduler group index
            output_vec.push_back(queue_obj_id_list[scheduler_group_index - 1]);
            return fill_sai_list(output_vec.begin(), output_vec.end(), value->objlist);
        }

        break;
    case SAI_SCHEDULER_GROUP_ATTR_PORT_ID:
        set_attr_value(SAI_SCHEDULER_GROUP_ATTR_PORT_ID, *value, port_entry.service.oid);
        break;
    case SAI_SCHEDULER_GROUP_ATTR_LEVEL:
        if (is_port_sched) {
            set_attr_value(SAI_SCHEDULER_GROUP_ATTR_LEVEL, *value, 0);
        } else {
            set_attr_value(SAI_SCHEDULER_GROUP_ATTR_LEVEL, *value, 1);
        }
        break;
    case SAI_SCHEDULER_GROUP_ATTR_MAX_CHILDS:
        if (is_port_sched) {
            set_attr_value(SAI_SCHEDULER_GROUP_ATTR_MAX_CHILDS, *value, 8);
        } else {
            set_attr_value(SAI_SCHEDULER_GROUP_ATTR_MAX_CHILDS, *value, 1);
        }
        break;
    case SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID:
        if (is_port_sched) {
            set_attr_value(SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID, *value, port_entry.m_sched_group_sched_profiles[0]);
        } else {
            uint32_t scheduler_group_index;
            sai_status_t sstatus = check_and_get_device_and_scheduler_group_index(
                sched_group_obj, SAI_OBJECT_TYPE_SCHEDULER_GROUP, sdev, scheduler_group_index);
            sai_return_on_error(sstatus);
            set_attr_value(SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID,
                           *value,
                           port_entry.m_sched_group_sched_profiles[scheduler_group_index]);
        }
        break;
    case SAI_SCHEDULER_GROUP_ATTR_PARENT_NODE:
        // if port sched return port oid else return parent obj id
        if (is_port_sched) {
            set_attr_value(SAI_SCHEDULER_GROUP_ATTR_PARENT_NODE, *value, port_entry.service.oid);
        } else {
            // port scheduler group would be the parent
            set_attr_value(SAI_SCHEDULER_GROUP_ATTR_PARENT_NODE, *value, port_entry.m_sched_group_oids[0]);
        }
        break;
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched_group::internal_set_attr(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
lsai_sched_group::check_and_get_device_and_scheduler_group_index(_In_ sai_object_id_t obj_id,
                                                                 _In_ sai_object_type_t type,
                                                                 _Out_ std::shared_ptr<lsai_device>& out_sdev,
                                                                 _Out_ uint32_t& out_id)
{
    lsai_object la_obj(obj_id);
    out_sdev = la_obj.get_device();
    if (la_obj.type != type || out_sdev == nullptr || out_sdev->m_dev == nullptr) {
        sai_log_error(SAI_API_SCHEDULER_GROUP, "Bad scheduler group Object id %lu", obj_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    out_id = la_obj.index;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched_group::scheduler_group_attr_scheduler_profile_id_set(_In_ const sai_object_key_t* key,
                                                                _In_ const sai_attribute_value_t* value,
                                                                void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_sched_group(key->key.object_id);
    uint32_t port_index = la_sched_group.detail.get(lsai_detail_type_e::SCHEDULER_GROUP, lsai_detail_field_e::PORT);
    lsai_object la_port(SAI_OBJECT_TYPE_PORT, la_sched_group.switch_id, port_index);
    auto sdev = la_sched_group.get_device();

    port_entry* port_entry = sdev->m_ports.get_ptr(la_port.index);
    if (port_entry == nullptr) {
        sai_log_error(SAI_API_SCHEDULER_GROUP, "pentry does not exist on the port index 0x%lx", la_port.index);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_object_id_t sched_group_obj = la_sched_group.object_id();
    uint32_t scheduler_group_index;
    auto scheduler_oid = get_attr_value(SAI_SCHEDULER_GROUP_ATTR_SCHEDULER_PROFILE_ID, (*value));

    sai_status_t sstatus = check_and_get_device_and_scheduler_group_index(
        sched_group_obj, SAI_OBJECT_TYPE_SCHEDULER_GROUP, sdev, scheduler_group_index);
    sai_return_on_error(sstatus);

    if (sched_group_obj == port_entry->m_sched_group_oids[0]) {
        // port scheduler, change the interface scheduler configs
        port_entry->m_sched_group_sched_profiles[scheduler_group_index] = scheduler_oid;
        sai_return_on_error(port_scheduler_group_scheduler_config_change(sdev, port_entry->service.oid, scheduler_oid));
    } else {
        port_entry->m_sched_group_sched_profiles[scheduler_group_index] = scheduler_oid;
        uint32_t queue_index = scheduler_group_index - 1;
        // system scheduler for the queues.
        sai_return_on_error(scheduler_group_queue_scheduler_config_change(la_port, queue_index, scheduler_oid));
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_sched_group::create_scheduler_group(sai_object_id_t* out_sch_grp_id,
                                         sai_object_id_t switch_id,
                                         uint32_t attr_count,
                                         const sai_attribute_t* attr_list)
{

    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
lsai_sched_group::remove_scheduler_group(sai_object_id_t obj_id)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

const sai_scheduler_group_api_t sch_group_api = {lsai_sched_group::create_scheduler_group,
                                                 lsai_sched_group::remove_scheduler_group,
                                                 lsai_sched_group::set_scheduler_group_attribute,
                                                 lsai_sched_group::get_scheduler_group_attribute};
}
}
