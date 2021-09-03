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

#ifndef __SAI_LEABA_H__
#define __SAI_LEABA_H__

#include "api/npu/la_l3_ac_port.h"
#include "api/npu/la_next_hop.h"
#include "api/npu/la_switch.h"
#include "api/npu/la_vrf.h"
#include "api/system/la_device.h"
#include "api/system/la_log.h"
#include "api/types/la_ethernet_types.h"
#include "sai_constants.h"
#include <string.h>
#include <string>
#include <unordered_map>
#include <map>

#include "common/transaction.h"

#if CURRENT_SAI_VERSION_CODE == SAI_VERSION_CODE(1, 5, 2)
#define SAI_VERSION_152
#else
#if CURRENT_SAI_VERSION_CODE == SAI_VERSION_CODE(1, 8, 1)
#define SAI_VERSION_181
#else
#define SAI_VERSION_171
#endif
#endif

extern "C" {
#include <sai.h>
#include "sai_attr_ext.h"
#if CURRENT_SAI_VERSION_CODE == SAI_VERSION_CODE(1, 5, 2)
#define SAI_OBJECT_TYPE_SYSTEM_PORT SAI_OBJECT_TYPE_NULL
/**
 * @brief Attribute data for #SAI_SWITCH_ATTR_TYPE
 */
typedef enum _sai_switch_type_t {
    /** Switch type is Switching Network processing unit */
    SAI_SWITCH_TYPE_NPU,

    /** Switch type is PHY */
    SAI_SWITCH_TYPE_PHY,

    /** Switch type is VOQ based NPU */
    SAI_SWITCH_TYPE_VOQ,

    /** Switch type is Fabric switch device */
    SAI_SWITCH_TYPE_FABRIC,

} sai_switch_type_t;

// copied from 1.6.3 for compilation
typedef struct _sai_system_port_config_t {
    /** System Port ID */
    uint32_t port_id;

    /** Switch ID of where the system port exists */
    uint32_t attached_switch_id;

    /** Core associated with the system port */
    uint32_t attached_core_index;

    /** Port Index within the core associated with the system port */
    uint32_t attached_core_port_index;

    /** Speed of the system port */
    uint32_t speed;

    /** Number of Virtual Output Queues associated with the system port */
    uint32_t num_voq;
} sai_system_port_config_t;

/**
 * @brief System port configuration list
 */
typedef struct _sai_system_port_config_list_t {
    /** Number of entries in the list */
    uint32_t count;

    /** System port configuration list */
    sai_system_port_config_t* list;
} sai_system_port_config_list_t;
#endif
}

extern "C" {
#include "sai_attr_ext.h"
}

//#include "sai_device.h"
#include <../../build/src/auto_gen_attr.h>
#include "auto_gen_attr_ext.h"

namespace silicon_one
{
namespace sai
{
class lsai_device;

extern const sai_acl_api_t acl_api;
extern const sai_bridge_api_t bridge_api;
extern const sai_debug_counter_api_t debug_counter_api;
extern const sai_fdb_api_t fdb_api;
extern const sai_hash_api_t hash_api;
extern const sai_hostif_api_t host_interface_api;
extern const sai_samplepacket_api_t samplepacket_api;
extern const sai_lag_api_t lag_api;
extern const sai_mpls_api_t mpls_api;
extern const sai_neighbor_api_t neighbor_api;
extern const sai_next_hop_api_t next_hop_api;
extern const sai_next_hop_group_api_t next_hop_group_api;
extern const sai_port_api_t port_api;
extern const sai_qos_map_api_t qos_map_api;
extern const sai_queue_api_t queue_api;
extern const sai_route_api_t route_api;
extern const sai_router_interface_api_t router_interface_api;
extern const sai_scheduler_api_t scheduler_api;
extern const sai_tunnel_api_t tunnel_api;
extern const sai_switch_api_t switch_api;
extern const sai_virtual_router_api_t router_api;
extern const sai_vlan_api_t vlan_api;
extern const sai_wred_api_t wred_api;
extern const sai_policer_api_t policer_api;
extern const sai_buffer_api_t buffer_api;
extern const sai_scheduler_group_api_t sch_group_api;
extern const sai_mirror_api_t mirror_api;
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
extern const sai_system_port_api_t system_port_api;
#endif
extern const sai_tam_api_t tam_api;

la_next_hop* la_get_next_hop(sai_object_id_t next_hop_id);
la_next_hop* la_get_next_hop(la_uint32_t ipv4_addr);
la_ethernet_port* la_get_port(sai_object_id_t obj_port_id);
la_switch* la_get_switch(sai_object_id_t obj_switch_id);
la_l2_service_port* la_get_l2_port(sai_object_id_t obj_bridge_port);
la_switch* la_get_bridge_by_obj(sai_object_id_t obj);

la_status la_create_svi_port(uint32_t& router_bridge_idx,
                             la_switch* bridge,
                             sai_object_id_t obj_rif_id,
                             uint16_t vlan_id,
                             transaction& txn);
extern la_logger_level_e sai_log_level_to_leaba(sai_log_level_t log_level);

#define SAI_LOG(...)                                                                                                               \
    do {                                                                                                                           \
        fprintf(stderr, __VA_ARGS__);                                                                                              \
        fprintf(stderr, "\n");                                                                                                     \
    } while (false)

std::unordered_map<sai_attr_id_t, sai_attribute_value_t> sai_parse_attributes(uint32_t attr_count,
                                                                              const sai_attribute_t* attr_list);

inline sai_status_t
to_sai_status(const la_status& status)
{
    switch (static_cast<la_status_e>(status.value())) {
    case la_status_e::SUCCESS:
        return SAI_STATUS_SUCCESS;
    case la_status_e::E_RESOURCE:
        return SAI_STATUS_INSUFFICIENT_RESOURCES;
    case la_status_e::E_OUTOFMEMORY:
        return SAI_STATUS_NO_MEMORY;
    case la_status_e::E_INVAL:
        return SAI_STATUS_INVALID_PARAMETER;
    case la_status_e::E_NOTFOUND:
        return SAI_STATUS_ITEM_NOT_FOUND;
    case la_status_e::E_BUSY:
        return SAI_STATUS_OBJECT_IN_USE;
    case la_status_e::E_NOTIMPLEMENTED:
        return SAI_STATUS_NOT_IMPLEMENTED;
    case la_status_e::E_EXIST:
        return SAI_STATUS_ITEM_ALREADY_EXISTS;
    default:
        return SAI_STATUS_FAILURE;
    }
}

inline la_status
to_la_status(sai_status_t status)
{
    switch (status) {
    case SAI_STATUS_SUCCESS:
        return la_status_e::SUCCESS;
    case SAI_STATUS_INSUFFICIENT_RESOURCES:
        return la_status_e::E_RESOURCE;
    case SAI_STATUS_NO_MEMORY:
        return la_status_e::E_OUTOFMEMORY;
    case SAI_STATUS_INVALID_PARAMETER:
        return la_status_e::E_INVAL;
    case SAI_STATUS_ITEM_NOT_FOUND:
        return la_status_e::E_NOTFOUND;
    case SAI_STATUS_OBJECT_IN_USE:
        return la_status_e::E_BUSY;
    case SAI_STATUS_NOT_IMPLEMENTED:
        return la_status_e::E_NOTIMPLEMENTED;
    case SAI_STATUS_ITEM_ALREADY_EXISTS:
        return la_status_e::E_EXIST;
    default:
        return la_status_e::E_UNKNOWN;
    }
}

extern sai_service_method_table_t g_sai_service_method;
}
}
#endif
