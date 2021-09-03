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

#ifndef __SAI_TEST_UTILS_H__
#define __SAI_TEST_UTILS_H__
extern "C" {
#include "sai.h"
#include "sai_constants.h"
}
#include <vector>

// the following sai_get_counters are defined for python to use, need to be defined in this file
sai_status_t
sai_get_counters(sai_object_id_t obj, uint32_t size, sai_buffer_pool_stat_t* counter_ids, uint64_t* counters)
{
    sai_buffer_api_t* buffer_api = nullptr;
    sai_api_query(SAI_API_BUFFER, (void**)(&buffer_api));

    return buffer_api->get_buffer_pool_stats(obj, size, (const sai_stat_id_t*)counter_ids, counters);
}

sai_status_t
sai_get_counters(sai_object_id_t obj, uint32_t size, sai_queue_stat_t* counter_ids, uint64_t* counters)
{
    sai_queue_api_t* queue_api = nullptr;
    sai_api_query(SAI_API_QUEUE, (void**)(&queue_api));
    return queue_api->get_queue_stats(obj, size, (const sai_stat_id_t*)counter_ids, counters);
}

sai_status_t
sai_get_counters(sai_object_id_t obj, uint32_t size, sai_bridge_port_stat_t* counter_ids, uint64_t* counters)
{
    sai_bridge_api_t* bridge_api = nullptr;
    sai_api_query(SAI_API_BRIDGE, (void**)(&bridge_api));
    return bridge_api->get_bridge_port_stats(obj, size, (const sai_stat_id_t*)counter_ids, counters);
}

sai_status_t
sai_get_counters(sai_object_id_t obj, uint32_t size, sai_port_stat_t* counter_ids, uint64_t* counters)
{
    sai_port_api_t* port_api = nullptr;
    sai_api_query(SAI_API_PORT, (void**)(&port_api));
    return port_api->get_port_stats(obj, size, (const sai_stat_id_t*)counter_ids, counters);
}

sai_status_t
sai_get_counters(sai_object_id_t obj, uint32_t size, sai_router_interface_stat_t* counter_ids, uint64_t* counters)
{
    sai_router_interface_api_t* rif_api = nullptr;
    sai_api_query(SAI_API_ROUTER_INTERFACE, (void**)(&rif_api));
    return rif_api->get_router_interface_stats(obj, size, (const sai_stat_id_t*)counter_ids, counters);
}

sai_status_t
sai_get_counters(sai_object_id_t obj, uint32_t size, sai_policer_stat_t* counter_ids, uint64_t* counters)
{
    sai_policer_api_t* policer_api = nullptr;

    sai_api_query(SAI_API_POLICER, (void**)(&policer_api));
    return policer_api->get_policer_stats(obj, size, (const sai_stat_id_t*)counter_ids, counters);
}

template <typename StatsIdType>
std::vector<uint64_t>
get_counters(sai_object_id_t obj, std::vector<StatsIdType> ids)
{
    std::vector<uint64_t> counters(ids.size());
    sai_get_counters(obj, ids.size(), ids.data(), counters.data());
    return counters;
}

// the following sai_get_counters are defined for python to use, need to be defined in this file
sai_status_t
sai_get_counters_ext(sai_object_id_t obj, uint32_t size, sai_queue_stat_t* counter_ids, sai_stats_mode_t mode, uint64_t* counters)
{
    sai_queue_api_t* queue_api = nullptr;
    sai_api_query(SAI_API_QUEUE, (void**)(&queue_api));
    return queue_api->get_queue_stats_ext(obj, size, (const sai_stat_id_t*)counter_ids, mode, counters);
}

sai_status_t
sai_get_counters_ext(sai_object_id_t obj,
                     uint32_t size,
                     sai_bridge_port_stat_t* counter_ids,
                     sai_stats_mode_t mode,
                     uint64_t* counters)
{
    sai_bridge_api_t* bridge_api = nullptr;
    sai_api_query(SAI_API_BRIDGE, (void**)(&bridge_api));
    return bridge_api->get_bridge_port_stats_ext(obj, size, (const sai_stat_id_t*)counter_ids, mode, counters);
}

sai_status_t
sai_get_counters_ext(sai_object_id_t obj, uint32_t size, sai_port_stat_t* counter_ids, sai_stats_mode_t mode, uint64_t* counters)
{
    sai_port_api_t* port_api = nullptr;
    sai_api_query(SAI_API_PORT, (void**)(&port_api));
    return port_api->get_port_stats_ext(obj, size, (const sai_stat_id_t*)counter_ids, mode, counters);
}

sai_status_t
sai_get_counters_ext(sai_object_id_t obj,
                     uint32_t size,
                     sai_router_interface_stat_t* counter_ids,
                     sai_stats_mode_t mode,
                     uint64_t* counters)
{
    sai_router_interface_api_t* rif_api = nullptr;
    sai_api_query(SAI_API_ROUTER_INTERFACE, (void**)(&rif_api));
    return rif_api->get_router_interface_stats_ext(obj, size, (const sai_stat_id_t*)counter_ids, mode, counters);
}

sai_status_t
sai_get_counters_ext(sai_object_id_t obj, uint32_t size, sai_switch_stat_t* counter_ids, sai_stats_mode_t mode, uint64_t* counters)
{
    sai_switch_api_t* switch_api = nullptr;
    sai_api_query(SAI_API_SWITCH, (void**)(&switch_api));
    return switch_api->get_switch_stats_ext(obj, size, (const sai_stat_id_t*)counter_ids, mode, counters);
}

sai_status_t
sai_get_counters_ext(sai_object_id_t obj, uint32_t size, sai_policer_stat_t* counter_ids, sai_stats_mode_t mode, uint64_t* counters)
{
    sai_policer_api_t* policer_api = nullptr;
    sai_api_query(SAI_API_POLICER, (void**)(&policer_api));
    return policer_api->get_policer_stats_ext(obj, size, (const sai_stat_id_t*)counter_ids, mode, counters);
}

template <typename StatsIdType>
std::vector<uint64_t>
get_counters_ext(sai_object_id_t obj, std::vector<StatsIdType> ids, sai_stats_mode_t mode)
{
    std::vector<uint64_t> counters(ids.size());
    sai_get_counters_ext(obj, ids.size(), ids.data(), mode, counters.data());
    return counters;
}

namespace silicon_one
{
namespace sai
{
void sai_fdb_evt(uint32_t count, const sai_fdb_event_notification_data_t* data);
void sai_queue_pfc_deadlock_evt(uint32_t count, const sai_queue_deadlock_notification_data_t* data);
sai_status_t sai_test_create_or_remove_route_entries(sai_route_entry_t* route_entry,
                                                     uint32_t attr_count,
                                                     const sai_attribute_t* attr_list,
                                                     const uint32_t num_routes,
                                                     const uint32_t inc_start_bit,
                                                     const bool bulk_operation,
                                                     const bool to_create);
sai_status_t sai_remove_all_routes(sai_object_id_t vrf_id);
std::vector<std::pair<sai_object_id_t, sai_status_t>> sai_create_next_hop_group_members_helper(sai_object_id_t switch_id,
                                                                                               uint32_t total_object_count,
                                                                                               sai_bulk_op_error_mode_t mode,
                                                                                               uint32_t attr_count,
                                                                                               const sai_attribute_t* attr_list);
std::vector<sai_status_t> sai_remove_next_hop_group_members_helper(uint32_t object_count,
                                                                   sai_object_id_t* object_ids,
                                                                   sai_bulk_op_error_mode_t mode);

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 8, 0)
std::vector<sai_status_t> sai_create_inseg_entries_helper(uint32_t object_count,
                                                          const sai_inseg_entry_t* inseg_entry,
                                                          const uint32_t* attr_count,
                                                          const sai_attribute_t** attr_list,
                                                          sai_bulk_op_error_mode_t mode);

std::vector<sai_status_t> sai_remove_inseg_entries_helper(uint32_t object_count,
                                                          const sai_inseg_entry_t* inseg_entry,
                                                          sai_bulk_op_error_mode_t mode);

std::vector<sai_status_t> sai_set_inseg_entries_attribute_helper(uint32_t object_count,
                                                                 const sai_inseg_entry_t* inseg_entry,
                                                                 const sai_attribute_t* attr_list,
                                                                 sai_bulk_op_error_mode_t mode);

// Work in progress
std::vector<sai_status_t> sai_get_inseg_entries_attribute_helper(uint32_t object_count,
                                                                 const sai_inseg_entry_t* inseg_entry,
                                                                 const uint32_t* attr_count,
                                                                 sai_attribute_t** attr_list,
                                                                 sai_bulk_op_error_mode_t mode);
#endif
}
}
#endif
