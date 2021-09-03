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

#ifndef __SAI_QUEUE_H__
#define __SAI_QUEUE_H__

#include "saitypes.h"
#include "saiobject.h"

#include "sai_utils.h"

namespace silicon_one
{
namespace sai
{

struct queue_watermark_stats {
    la_system_port::egress_max_congestion_watermark egress_cgm_watermark;
    la_system_port::egress_max_delay_watermark egress_delay_watermark;
};

sai_status_t queue_attr_scheduler_profile_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
sai_status_t queue_attr_scheduler_profile_get(_In_ const sai_object_key_t* key,
                                              _Inout_ sai_attribute_value_t* attr,
                                              _In_ uint32_t attr_index,
                                              _Inout_ vendor_cache_t* cache,
                                              void* arg);
sai_status_t queue_attr_pause_status_get(_In_ const sai_object_key_t* key,
                                         _Inout_ sai_attribute_value_t* value,
                                         _In_ uint32_t attr_index,
                                         _Inout_ vendor_cache_t* cache,
                                         void* arg);
sai_status_t queue_attr_enable_pfc_dldr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
sai_status_t queue_attr_enable_pfc_dldr_get(_In_ const sai_object_key_t* key,
                                            _Inout_ sai_attribute_value_t* value,
                                            _In_ uint32_t attr_index,
                                            _Inout_ vendor_cache_t* cache,
                                            void* arg);
sai_status_t queue_attr_pfc_dlr_init_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
}
}
#endif
