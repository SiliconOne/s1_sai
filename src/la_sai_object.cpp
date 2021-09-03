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
#include "la_sai_object.h"
#include "sai_logger.h"

namespace silicon_one
{
namespace sai
{
lsai_object::lsai_object()
{
}

lsai_object::lsai_object(sai_object_type_t t, uint32_t sw, uint32_t id) : type(t), switch_id(sw), index(id)
{
    sai_get_device(switch_id, m_device);
    detail.value.opaque = 0;
}

lsai_object::lsai_object(sai_object_id_t oid)
    : lsai_object((sai_object_type_t)(((oid >> LA_SAI_TYPE_OFFSET) & LA_SAI_MAX_TYPE) & 0xFFFFFFFF),
                  ((oid >> LA_SAI_SWITCH_ID_OFFSET) & LA_SAI_SWITCH_ID_MASK) & 0xFFFFFFFF,
                  ((oid >> LA_SAI_ID_OFFSET) & LA_SAI_MAX_ID) & 0xFFFFFFFF)
{
    type = (sai_object_type_t)(((oid >> LA_SAI_TYPE_OFFSET) & LA_SAI_MAX_TYPE) & 0xFFFFFFFF);

    switch (type) {
    case SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY: {
        tunnel_map_type = ((oid >> TUNNEL_MAP_TYPE_OFFSET) & TUNNEL_MAP_TYPE_MASK) & 0xFFFFFFFF;
        index = ((oid >> TUNNEL_MAP_INDEX_OFFSET) & TUNNEL_MAP_INDEX_MASK) & 0xFFFFFFFF;
        switch (tunnel_map_type) {
        case SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID:
        case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
        case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID: {
            tunnel_map_entry_key = (oid >> TUNNEL_MAP_ENTRY_VNI_COMP_SIZE) & TUNNEL_MAP_ENTRY_VNI_MASK;
            tunnel_map_entry_value = oid & TUNNEL_MAP_ENTRY_VNI_COMP_MASK;
            break;
        }
        case SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI:
        case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
        case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI: {
            tunnel_map_entry_key = (oid >> TUNNEL_MAP_ENTRY_VNI_SIZE) & TUNNEL_MAP_ENTRY_VNI_COMP_MASK;
            tunnel_map_entry_value = oid & TUNNEL_MAP_ENTRY_VNI_MASK;
            break;
        }
        case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
        case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN: {
            tunnel_map_entry_key = (oid >> TUNNEL_MAP_ENTRY_NOT_VNI_SIZE) & TUNNEL_MAP_ENTRY_NOT_VNI_MASK;
            tunnel_map_entry_value = oid & TUNNEL_MAP_ENTRY_NOT_VNI_MASK;
            break;
        }
        default:
            break;
        }
        break;
    }
    case SAI_OBJECT_TYPE_TUNNEL_MAP: {
        tunnel_map_type = ((oid >> TUNNEL_MAP_TYPE_OFFSET) & TUNNEL_MAP_TYPE_MASK) & 0xFFFFFFFF;
        index = ((oid >> LA_SAI_ID_OFFSET) & LA_SAI_MAX_ID) & 0xFFFFFFFF;
        break;
    }
    default:
        index = ((oid >> LA_SAI_ID_OFFSET) & LA_SAI_MAX_ID) & 0xFFFFFFFF;
        detail.value.opaque = (uint32_t)((oid >> LA_SAI_ATTR_OFFSET) & LA_SAI_MAX_ATTR);
        break;
    }
}

sai_object_id_t
lsai_object::object_id() const
{
    uint64_t obj = 0;

    switch (type) {
    case SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY: {
        switch (tunnel_map_type) {
        case SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID:
        case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF:
        case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID: {
            obj = (((uint64_t)type & (uint64_t)LA_SAI_MAX_TYPE) << LA_SAI_TYPE_OFFSET)
                  | (((uint64_t)(switch_id & LA_SAI_SWITCH_ID_MASK)) << LA_SAI_SWITCH_ID_OFFSET)
                  | (((uint64_t)(tunnel_map_type & TUNNEL_MAP_TYPE_MASK)) << TUNNEL_MAP_TYPE_OFFSET)
                  | (((uint64_t)(index & TUNNEL_MAP_INDEX_MASK)) << TUNNEL_MAP_INDEX_OFFSET)
                  | (((uint64_t)(tunnel_map_entry_key & TUNNEL_MAP_ENTRY_VNI_MASK)) << TUNNEL_MAP_ENTRY_VNI_COMP_SIZE)
                  | (uint64_t)(tunnel_map_entry_value & TUNNEL_MAP_ENTRY_VNI_COMP_MASK);
            break;
        }
        case SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI:
        case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI:
        case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI: {
            obj = (((uint64_t)type & (uint64_t)LA_SAI_MAX_TYPE) << LA_SAI_TYPE_OFFSET)
                  | (((uint64_t)(switch_id & LA_SAI_SWITCH_ID_MASK)) << LA_SAI_SWITCH_ID_OFFSET)
                  | (((uint64_t)(tunnel_map_type & TUNNEL_MAP_TYPE_MASK)) << TUNNEL_MAP_TYPE_OFFSET)
                  | (((uint64_t)(index & TUNNEL_MAP_INDEX_MASK)) << TUNNEL_MAP_INDEX_OFFSET)
                  | (((uint64_t)(tunnel_map_entry_key & TUNNEL_MAP_ENTRY_VNI_COMP_MASK)) << TUNNEL_MAP_ENTRY_VNI_SIZE)
                  | (uint64_t)(tunnel_map_entry_value & TUNNEL_MAP_ENTRY_VNI_MASK);
            break;
        }
        case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
        case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN: {
            obj = (((uint64_t)type & (uint64_t)LA_SAI_MAX_TYPE) << LA_SAI_TYPE_OFFSET)
                  | (((uint64_t)(switch_id & LA_SAI_SWITCH_ID_MASK)) << LA_SAI_SWITCH_ID_OFFSET)
                  | (((uint64_t)(tunnel_map_type & TUNNEL_MAP_TYPE_MASK)) << TUNNEL_MAP_TYPE_OFFSET)
                  | (((uint64_t)(index & TUNNEL_MAP_INDEX_MASK)) << TUNNEL_MAP_INDEX_OFFSET)
                  | (((uint64_t)(tunnel_map_entry_key & TUNNEL_MAP_ENTRY_NOT_VNI_MASK)) << TUNNEL_MAP_ENTRY_NOT_VNI_SIZE)
                  | (uint64_t)(tunnel_map_entry_value & TUNNEL_MAP_ENTRY_NOT_VNI_MASK);
            break;
        }
        default:
            break;
        }
        break;
    }
    case SAI_OBJECT_TYPE_TUNNEL_MAP: {
        obj = (((uint64_t)type & (uint64_t)LA_SAI_MAX_TYPE) << LA_SAI_TYPE_OFFSET)
              | (((uint64_t)(switch_id & LA_SAI_SWITCH_ID_MASK)) << LA_SAI_SWITCH_ID_OFFSET)
              | (((uint64_t)(tunnel_map_type & TUNNEL_MAP_TYPE_MASK)) << TUNNEL_MAP_TYPE_OFFSET)
              | (uint64_t)(index & LA_SAI_MAX_ID);
        break;
    }
    default: {
        obj = (((uint64_t)type & (uint64_t)LA_SAI_MAX_TYPE) << LA_SAI_TYPE_OFFSET)
              | (((uint64_t)(switch_id & LA_SAI_SWITCH_ID_MASK)) << LA_SAI_SWITCH_ID_OFFSET)
              | (((uint64_t)(detail.value.opaque & LA_SAI_MAX_ATTR)) << LA_SAI_ATTR_OFFSET) | (uint64_t)(index & LA_SAI_MAX_ID);
        break;
    }
    }
    return (sai_object_id_t)obj;
}

void
lsai_detail::set(lsai_detail_type_e type, lsai_detail_field_e field, uint32_t v)
{
    switch (type) {
    case lsai_detail_type_e::BRIDGE_PORT:
        if (field == lsai_detail_field_e::TYPE) {
            value.m_bridge_port_detail.type = v;
        } else {
            sai_log_warn(SAI_API_BRIDGE, "Incorrect detail type for bridge %d", type);
        }
        break;

    case lsai_detail_type_e::QUEUE:
        if (field == lsai_detail_field_e::PORT) {
            value.m_queue_detail.port = v;
        } else {
            sai_log_warn(SAI_API_QUEUE, "Incorrect detail type for queue %d", type);
        }
        break;
    case lsai_detail_type_e::LAG_MEMBER:
        if (field == lsai_detail_field_e::LAG) {
            value.m_lag_member_detail.lag = v;
        } else {
            sai_log_warn(SAI_API_LAG, "Incorrect detail type for lag member %d", type);
        }
        break;
    case lsai_detail_type_e::TUNNEL_TERM:
        if (field == lsai_detail_field_e::TYPE) {
            value.m_tunnel_term_detail.type = v;
        } else if (field == lsai_detail_field_e::TUNNEL) {
            value.m_tunnel_term_detail.tunnel_index = v;
        } else {
            sai_log_warn(SAI_API_TUNNEL, "Incorrect detail type for tunnel term %d", type);
        }
        break;
    case lsai_detail_type_e::SCHEDULER_GROUP:
        if (field == lsai_detail_field_e::PORT) {
            value.m_scheduler_group_detail.port = v;
        } else {
            sai_log_warn(SAI_API_SCHEDULER_GROUP, "Incorrect detail type for scheduler group %d", type);
        }
        break;
    default:
        // default do nothing
        break;
    }
}

uint32_t
lsai_detail::get(lsai_detail_type_e type, lsai_detail_field_e field)
{
    uint32_t v = 0;
    switch (type) {
    case lsai_detail_type_e::BRIDGE_PORT:
        if (field == lsai_detail_field_e::TYPE) {
            v = value.m_bridge_port_detail.type;
        }
        break;

    case lsai_detail_type_e::QUEUE:
        if (field == lsai_detail_field_e::PORT) {
            v = value.m_queue_detail.port;
        }
        break;
    case lsai_detail_type_e::LAG_MEMBER:
        if (field == lsai_detail_field_e::LAG) {
            v = value.m_lag_member_detail.lag;
        }
        break;
    case lsai_detail_type_e::TUNNEL_TERM:
        if (field == lsai_detail_field_e::TYPE) {
            v = value.m_tunnel_term_detail.type;
        } else if (field == lsai_detail_field_e::TUNNEL) {
            v = value.m_tunnel_term_detail.tunnel_index;
        }
        break;
    case lsai_detail_type_e::SCHEDULER_GROUP:
        if (field == lsai_detail_field_e::PORT) {
            v = value.m_scheduler_group_detail.port;
        }
        break;
    default:
        // default do nothing
        break;
    }
    return v;
}
}
}
