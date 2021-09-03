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

#ifndef __SAI_SCHEDULER_GROUP_H__
#define __SAI_SCHEDULER_GROUP_H__

#include <jansson.h>
#include <unordered_set>

extern "C" {
#include <sai.h>
}

#include "sai_db.h"
#include "sai_utils.h"
#include "sai_warm_boot.h"
#include "saiobject.h"
#include "saistatus.h"
#include "sai_constants.h"
#include "sai_port.h"

namespace silicon_one
{
namespace sai
{

struct port_entry;

class lsai_sched_group
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    friend class lsai_device;

public:
    lsai_sched_group() = default; // for warm boot
    lsai_sched_group(std::shared_ptr<lsai_device> sai_dev) : m_lsai_device(sai_dev)
    {
    }

    sai_status_t create_default_scheduler_group(std::shared_ptr<lsai_device> sdev, port_entry* port_entry);

    static sai_status_t scheduler_group_attr_scheduler_profile_id_set(_In_ const sai_object_key_t* key,
                                                                      _In_ const sai_attribute_value_t* value,
                                                                      void* arg);

    static sai_status_t internal_set_attr(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

    static sai_status_t internal_get_attr(_In_ const sai_object_key_t* key,
                                          _Inout_ sai_attribute_value_t* value,
                                          _In_ uint32_t attr_index,
                                          _Inout_ vendor_cache_t* cache,
                                          void* arg);

    static sai_status_t create_scheduler_group(_Out_ sai_object_id_t* out_scheduler_id,
                                               _In_ sai_object_id_t switch_id,
                                               _In_ uint32_t attr_count,
                                               _In_ const sai_attribute_t* attr_list);
    static sai_status_t remove_scheduler_group(_In_ sai_object_id_t scheduler_id);
    static sai_status_t set_scheduler_group_attribute(_In_ sai_object_id_t scheduler_id, _In_ const sai_attribute_t* attr);
    static sai_status_t get_scheduler_group_attribute(_In_ sai_object_id_t scheduler_id,
                                                      _In_ uint32_t attr_count,
                                                      _Inout_ sai_attribute_t* attr_list);

private:
    static sai_status_t check_and_get_device_and_scheduler_group_index(_In_ sai_object_id_t obj_id,
                                                                       _In_ sai_object_type_t type,
                                                                       _Out_ std::shared_ptr<lsai_device>& out_sdev,
                                                                       _Out_ uint32_t& out_id);

private:
    std::shared_ptr<lsai_device> m_lsai_device;
};
}
}
#endif
