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

#include <stdio.h>
#include "common/logger.h"
#include "sai_device.h"

using namespace silicon_one;
using namespace silicon_one::sai;

sai_status_t
sai_api_initialize(_In_ uint64_t flags, _In_ const sai_service_method_table_t* services)
{

    // if ((nullptr == services) || (nullptr == services->profile_get_next_value) || (nullptr == services->profile_get_value))
    if ((nullptr == services) || (nullptr == services->profile_get_value)) {
        fprintf(stderr, "Invalid services handle passed to SAI API initialize\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // copy the function pointers to g_sai_service_method in sai_device.h
    g_sai_service_method = *services;

    if (0 != flags) {
        fprintf(stderr, "Invalid flags passed to SAI API initialize\n");

        return SAI_STATUS_INVALID_PARAMETER;
    }

    // la api is too chatty to report error
    // la_set_logging_level(logger::NO_DEVICE, la_logger_level_e::ERROR);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_api_query(_In_ sai_api_t api, _Out_ void** api_method_table)
{
    if (nullptr == api_method_table) {
        fprintf(stderr, "nullptr method table passed to SAI API initialize\n");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (api) {
    case SAI_API_ACL:
        *const_cast<const void**>(api_method_table) = &acl_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_BRIDGE:
        *const_cast<const void**>(api_method_table) = &bridge_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_BUFFER:
        *const_cast<const void**>(api_method_table) = &buffer_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_DEBUG_COUNTER:
        *(const sai_debug_counter_api_t**)api_method_table = &debug_counter_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_FDB:
        *const_cast<const void**>(api_method_table) = &fdb_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_HASH:
        *const_cast<const void**>(api_method_table) = &hash_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_HOSTIF:
        *const_cast<const void**>(api_method_table) = &host_interface_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_LAG:
        *const_cast<const void**>(api_method_table) = &lag_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_MPLS:
        *(const sai_mpls_api_t**)api_method_table = &mpls_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_MIRROR:
        *const_cast<const void**>(api_method_table) = &mirror_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_NEIGHBOR:
        *const_cast<const void**>(api_method_table) = &neighbor_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_NEXT_HOP:
        *const_cast<const void**>(api_method_table) = &next_hop_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_NEXT_HOP_GROUP:
        *const_cast<const void**>(api_method_table) = &next_hop_group_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_POLICER:
        *const_cast<const void**>(api_method_table) = &policer_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_PORT:
        *const_cast<const void**>(api_method_table) = &port_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_QOS_MAP:
        *const_cast<const void**>(api_method_table) = &qos_map_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_QUEUE:
        *const_cast<const void**>(api_method_table) = &queue_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_ROUTE:
        *const_cast<const void**>(api_method_table) = &route_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_ROUTER_INTERFACE:
        *const_cast<const void**>(api_method_table) = &router_interface_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_SAMPLEPACKET:
        *const_cast<const void**>(api_method_table) = &samplepacket_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_SCHEDULER:
        *const_cast<const void**>(api_method_table) = &scheduler_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_SCHEDULER_GROUP:
        *const_cast<const void**>(api_method_table) = &sch_group_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_STP:
        /* TODO : implement */
        return SAI_STATUS_NOT_IMPLEMENTED;

    case SAI_API_SWITCH:
        *const_cast<const void**>(api_method_table) = &switch_api;
        return SAI_STATUS_SUCCESS;

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 6, 2)
    case SAI_API_SYSTEM_PORT:
        *const_cast<const void**>(api_method_table) = &system_port_api;
        return SAI_STATUS_SUCCESS;
#endif

    case SAI_API_TAM:
        *const_cast<const void**>(api_method_table) = &tam_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_TUNNEL:
        *(const sai_tunnel_api_t**)api_method_table = &tunnel_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_VLAN:
        *const_cast<const void**>(api_method_table) = &vlan_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_VIRTUAL_ROUTER:
        *const_cast<const void**>(api_method_table) = &router_api;
        return SAI_STATUS_SUCCESS;

    case SAI_API_WRED:
        *const_cast<const void**>(api_method_table) = &wred_api;
        return SAI_STATUS_SUCCESS;

    default:
        fprintf(stderr, "Unknown API type %d\n", api);
        return SAI_STATUS_NOT_IMPLEMENTED;
    }
}

sai_status_t
sai_api_uninitialize(void)
{
    g_sai_service_method = {nullptr, nullptr};

    return SAI_STATUS_SUCCESS;
}
