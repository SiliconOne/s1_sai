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

#include "sai_bridge.h"

#include "api/npu/la_l2_service_port.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_svi_port.h"
#include "api/npu/la_switch.h"
#include "api/system/la_device.h"
#include "api/system/la_spa_port.h"
#include "api/system/la_system_port.h"
#include "common/ranged_index_generator.h"
#include "common/transaction.h"
#include "sai_constants.h"
#include "sai_device.h"
#include "sai_logger.h"
#include <algorithm>
#include "sai_lag.h"

namespace silicon_one
{
namespace sai
{

using namespace std;

// **************************** SAI Bridge  **********************
static sai_status_t sai_bridge_attrib_get(_In_ const sai_object_key_t* key,
                                          _Inout_ sai_attribute_value_t* value,
                                          _In_ uint32_t attr_index,
                                          _Inout_ vendor_cache_t* cache,
                                          void* arg);

static sai_status_t sai_bridge_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t sai_bridge_unknown_flood_get(_In_ const sai_object_key_t* key,
                                                 _Inout_ sai_attribute_value_t* value,
                                                 _In_ uint32_t attr_index,
                                                 _Inout_ vendor_cache_t* cache,
                                                 void* arg);

static sai_status_t sai_bridge_port_attrib_get(_In_ const sai_object_key_t* key,
                                               _Inout_ sai_attribute_value_t* value,
                                               _In_ uint32_t attr_index,
                                               _Inout_ vendor_cache_t* cache,
                                               void* arg);

static sai_status_t sai_bridge_port_attrib_set(_In_ const sai_object_key_t* key,
                                               _In_ const sai_attribute_value_t* value,
                                               void* arg);

static sai_status_t sai_bridge_port_learn_mode_set(_In_ const sai_object_key_t* key,
                                                   _In_ const sai_attribute_value_t* value,
                                                   void* arg);

// clang-format off
// id; mandatory_on_create; valid_for_create; valid_for_set; valid_for_get
// *attrib_name; type;
extern const sai_attribute_entry_t bridge_attribs[] = {
    {SAI_BRIDGE_ATTR_TYPE, true, true, false, true, "bridge type", SAI_ATTR_VAL_TYPE_S32},
    {SAI_BRIDGE_ATTR_PORT_LIST, false, false, false, true, "bridge list", SAI_ATTR_VAL_TYPE_OBJLIST},
    {SAI_BRIDGE_ATTR_MAX_LEARNED_ADDRESSES, false, true, true, true, "Max number of learned MAC addresses", SAI_ATTR_VAL_TYPE_U32},
    {SAI_BRIDGE_ATTR_LEARN_DISABLE, false, true, true, true, "Disable learning", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_BRIDGE_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE, false, true, true, true, "Unknown unicast flood control", SAI_ATTR_VAL_TYPE_U8},
    {SAI_BRIDGE_ATTR_UNKNOWN_UNICAST_FLOOD_GROUP, false, true, true, true, "Unknown unicast flood group", SAI_ATTR_VAL_TYPE_OID},
    {SAI_BRIDGE_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE, false, true, true, true, "Unknown multicast flood control", SAI_ATTR_VAL_TYPE_U8},
    {SAI_BRIDGE_ATTR_UNKNOWN_MULTICAST_FLOOD_GROUP, false, true, true, true, "Unknown multicast flood group", SAI_ATTR_VAL_TYPE_OID},
    {SAI_BRIDGE_ATTR_BROADCAST_FLOOD_CONTROL_TYPE, false, true, true, true, "Unknown broadcast control", SAI_ATTR_VAL_TYPE_U8},
    {SAI_BRIDGE_ATTR_BROADCAST_FLOOD_GROUP, false, true, true, true, "Unknown broadcast group", SAI_ATTR_VAL_TYPE_OID},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t bridge_vendor_attribs[] = {
    {SAI_BRIDGE_ATTR_TYPE,
     /* create, remove, set, get */
     {true, false, false, true}, /* implemented */
     {true, false, false, true}, /* supported */
     sai_bridge_attrib_get, (void*)SAI_BRIDGE_ATTR_TYPE, nullptr, nullptr},

    {SAI_BRIDGE_ATTR_PORT_LIST,
     /* create, remove, set, get */
     {false, false, false, true}, /* implemented */
     {false, false, false, true}, /* supported */
     sai_bridge_attrib_get, (void*)SAI_BRIDGE_ATTR_PORT_LIST, nullptr, nullptr},

    {SAI_BRIDGE_ATTR_MAX_LEARNED_ADDRESSES,
     /* create, remove, set, get */
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     sai_bridge_attrib_get, (void*)SAI_BRIDGE_ATTR_MAX_LEARNED_ADDRESSES, sai_bridge_attrib_set, (void*)SAI_BRIDGE_ATTR_MAX_LEARNED_ADDRESSES},

    {SAI_BRIDGE_ATTR_LEARN_DISABLE,
     /* create, remove, set, get */
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     sai_bridge_attrib_get, (void*)SAI_BRIDGE_ATTR_LEARN_DISABLE, sai_bridge_attrib_set, (void*)SAI_BRIDGE_ATTR_LEARN_DISABLE},

    {SAI_BRIDGE_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE,
     {true, false, true, true},
     {true, false, true, true},
     sai_bridge_attrib_get, (void*)SAI_BRIDGE_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE, sai_bridge_attrib_set, (void*)SAI_BRIDGE_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE},

    {SAI_BRIDGE_ATTR_UNKNOWN_UNICAST_FLOOD_GROUP,
     {true, false, true, true},
     {true, false, true, true},
     sai_bridge_attrib_get, (void*)SAI_BRIDGE_ATTR_UNKNOWN_UNICAST_FLOOD_GROUP, sai_bridge_attrib_set, (void*)SAI_BRIDGE_ATTR_UNKNOWN_UNICAST_FLOOD_GROUP},

    {SAI_BRIDGE_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE,
     {true, false, true, true},
     {true, false, true, true},
     sai_bridge_attrib_get, (void*)SAI_BRIDGE_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE, sai_bridge_attrib_set, (void*)SAI_BRIDGE_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE},

    {SAI_BRIDGE_ATTR_UNKNOWN_MULTICAST_FLOOD_GROUP,
     {true, false, true, true},
     {true, false, true, true},
     sai_bridge_attrib_get, (void*)SAI_BRIDGE_ATTR_UNKNOWN_MULTICAST_FLOOD_GROUP, sai_bridge_attrib_set, (void*)SAI_BRIDGE_ATTR_UNKNOWN_MULTICAST_FLOOD_GROUP},

    {SAI_BRIDGE_ATTR_BROADCAST_FLOOD_CONTROL_TYPE,
     {true, false, true, true},
     {true, false, true, true},
     sai_bridge_attrib_get, (void*)SAI_BRIDGE_ATTR_BROADCAST_FLOOD_CONTROL_TYPE, sai_bridge_attrib_set, (void*)SAI_BRIDGE_ATTR_BROADCAST_FLOOD_CONTROL_TYPE},

    {SAI_BRIDGE_ATTR_BROADCAST_FLOOD_GROUP,
     {true, false, true, true},
     {true, false, true, true},
     sai_bridge_attrib_get, (void*)SAI_BRIDGE_ATTR_BROADCAST_FLOOD_GROUP, sai_bridge_attrib_set, (void*)SAI_BRIDGE_ATTR_BROADCAST_FLOOD_GROUP},
};

// ********************** SAI Bridge Port **********************

// id; mandatory_on_create; valid_for_create; valid_for_set; valid_for_get
// *attrib_name; type;
extern const sai_attribute_entry_t bridge_port_attribs[]
    = {{SAI_BRIDGE_PORT_ATTR_TYPE, true, true, false, true, "Bridge Port type", SAI_ATTR_VAL_TYPE_S32},
       {SAI_BRIDGE_PORT_ATTR_PORT_ID, false, true, false, true, "Port ID", SAI_ATTR_VAL_TYPE_OID},
       {SAI_BRIDGE_PORT_ATTR_VLAN_ID, false, true, false, true, "Vlan ID", SAI_ATTR_VAL_TYPE_S16},
       {SAI_BRIDGE_PORT_ATTR_RIF_ID, false, true, false, true, "RIF ID", SAI_ATTR_VAL_TYPE_OID},
       {SAI_BRIDGE_PORT_ATTR_TUNNEL_ID, false, true, false, true, "Tunnel ID", SAI_ATTR_VAL_TYPE_OID},
       {SAI_BRIDGE_PORT_ATTR_BRIDGE_ID, false, true, false, true, "bridge ID", SAI_ATTR_VAL_TYPE_OID},
       {SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE, false, true, true, true, "Bridge learning mode", SAI_ATTR_VAL_TYPE_S32},
       {SAI_BRIDGE_PORT_ATTR_MAX_LEARNED_ADDRESSES, false, true, true, true, "Max learned mac address", SAI_ATTR_VAL_TYPE_U32},
       {SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_LIMIT_VIOLATION_PACKET_ACTION, false, true, true, true, "learning limit violation packet action", SAI_ATTR_VAL_TYPE_S32},
       {SAI_BRIDGE_PORT_ATTR_ADMIN_STATE, false, true, true, true, "Admin state", SAI_ATTR_VAL_TYPE_BOOL},
       {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t bridge_port_vendor_attribs[] = {
    {SAI_BRIDGE_PORT_ATTR_TYPE,
     /* create, remove, set, get */
     {true, false, false, true}, /* implemented */
     {true, false, false, true}, /* supported */
     sai_bridge_port_attrib_get, (void*)SAI_BRIDGE_PORT_ATTR_TYPE, nullptr, nullptr},

    {SAI_BRIDGE_PORT_ATTR_PORT_ID,
     /* create, remove, set, get */
     {true, false, false, true}, /* implemented */
     {true, false, false, true}, /* supported */
     sai_bridge_port_attrib_get, (void*)SAI_BRIDGE_PORT_ATTR_PORT_ID, nullptr, nullptr},

    {SAI_BRIDGE_PORT_ATTR_VLAN_ID,
     /* create, remove, set, get */
     {true, false, false, true}, /* implemented */
     {true, false, false, true}, /* supported */
     sai_bridge_port_attrib_get, (void*)SAI_BRIDGE_PORT_ATTR_VLAN_ID, nullptr, nullptr},

    {SAI_BRIDGE_PORT_ATTR_RIF_ID,
     /* create, remove, set, get */
     {true, false, false, true}, /* implemented */
     {true, false, false, true}, /* supported */
     sai_bridge_port_attrib_get,
     (void*)SAI_BRIDGE_PORT_ATTR_RIF_ID, nullptr, nullptr}, {SAI_BRIDGE_PORT_ATTR_TUNNEL_ID,

     /* create, remove, set, get */
     {true, false, false, true}, /* implemented */
     {true, false, false, true}, /* supported */
     sai_bridge_port_attrib_get, (void*)SAI_BRIDGE_PORT_ATTR_TUNNEL_ID, nullptr, nullptr},

    {SAI_BRIDGE_PORT_ATTR_BRIDGE_ID,
     /* create, remove, set, get */
     {true, false, true, true}, /* implemented */
     {true, false, true, true}, /* supported */
     sai_bridge_port_attrib_get, (void*)SAI_BRIDGE_PORT_ATTR_BRIDGE_ID, sai_bridge_port_attrib_set, (void*)SAI_BRIDGE_PORT_ATTR_BRIDGE_ID},

    {SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE,
     /* create, remove, set, get */
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     sai_bridge_port_attrib_get, (void*)SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE, sai_bridge_port_learn_mode_set, (void*)SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE},

    {SAI_BRIDGE_PORT_ATTR_MAX_LEARNED_ADDRESSES,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     sai_bridge_port_attrib_get, (void*)SAI_BRIDGE_PORT_ATTR_MAX_LEARNED_ADDRESSES, sai_bridge_port_attrib_set, (void*)SAI_BRIDGE_PORT_ATTR_MAX_LEARNED_ADDRESSES},

    {SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_LIMIT_VIOLATION_PACKET_ACTION,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     sai_bridge_port_attrib_get, (void*)SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_LIMIT_VIOLATION_PACKET_ACTION, sai_bridge_port_attrib_set, (void*)SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_LIMIT_VIOLATION_PACKET_ACTION},

    {SAI_BRIDGE_PORT_ATTR_ADMIN_STATE,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     sai_bridge_port_attrib_get, (void*)SAI_BRIDGE_PORT_ATTR_ADMIN_STATE, sai_bridge_port_attrib_set, (void*)SAI_BRIDGE_PORT_ATTR_ADMIN_STATE},

};
// clang-format on

// *********************** end of sai bridge port attribute *****************

sai_status_t
laobj_db_bridge_port::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    *count = sdev->m_bridge_port_object_ids.size();
    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_bridge_port::get_object_keys(std::shared_ptr<lsai_device> sdev,
                                      uint32_t* object_count,
                                      sai_object_key_t* object_list) const
{
    uint32_t requested_object_count = *object_count;
    *object_count = sdev->m_bridge_port_object_ids.size();

    if (requested_object_count < *object_count) {
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    uint32_t object_index = 0;
    for (auto object_id : sdev->m_bridge_port_object_ids) {
        object_list[object_index].key.object_id = object_id;
        object_index++;
    }

    return SAI_STATUS_SUCCESS;
}

static std::string
bridge_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_bridge_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static std::string
bridge_port_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_bridge_port_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
sai_bridge_attrib_get(_In_ const sai_object_key_t* key,
                      _Inout_ sai_attribute_value_t* value,
                      _In_ uint32_t attr_index,
                      _Inout_ vendor_cache_t* cache,
                      void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_object_id_t bridge_id = key->key.object_id;
    int32_t attr_id = (uintptr_t)arg;
    sai_status_t sstatus = SAI_STATUS_SUCCESS;

    lsai_object la_bridge(bridge_id);
    auto sdev = la_bridge.get_device();
    lsai_bridge_t* lsaibridge = sdev->m_bridges.get_ptr(la_bridge.index);
    if (lsaibridge == nullptr || lsaibridge->m_sdk_switch == nullptr) {
        sai_return_on_error(SAI_STATUS_INVALID_PARAMETER, "Invalid sai bridge object 0x%lx", bridge_id);
    }

    switch (attr_id) {
    case SAI_BRIDGE_ATTR_TYPE: {
        set_attr_value(SAI_BRIDGE_ATTR_TYPE, (*value), lsaibridge->m_type);
        break;
    }
    case SAI_BRIDGE_ATTR_PORT_LIST: {
        sai_bridge_port_type_t port_type = SAI_BRIDGE_PORT_TYPE_PORT;
        if (bridge_id == sdev->m_default_1q_bridge_id) {
            return fill_sai_list(
                sdev->m_default_1q_bridge_port_ids.begin(), sdev->m_default_1q_bridge_port_ids.end(), value->objlist);
        } else {
            port_type = SAI_BRIDGE_PORT_TYPE_SUB_PORT;
        }

        uint32_t item_count = 0;
        lsai_object la_bport(SAI_OBJECT_TYPE_BRIDGE_PORT, la_bridge.switch_id, 0);
        lsai_detail& bport_detail = la_bport.detail;
        bport_detail.set(lsai_detail_type_e::BRIDGE_PORT, lsai_detail_field_e::TYPE, port_type);

        std::vector<la_object*> deps = sdev->m_dev->get_dependent_objects(lsaibridge->m_sdk_switch);
        for (auto objp : deps) {
            if (objp->type() == la_object::object_type_e::L2_SERVICE_PORT) {
                const la_l2_service_port* l2_port = static_cast<const la_l2_service_port*>(objp);

                la_bport.index = l2_port->get_gid();
                sai_object_id_t obj_id = la_bport.object_id();
                if (item_count >= value->objlist.count) {
                    sstatus = SAI_STATUS_BUFFER_OVERFLOW;
                } else {
                    value->objlist.list[item_count] = obj_id;
                }
                item_count++;
            }
        }
        value->objlist.count = item_count;
        break;
    }
    case SAI_BRIDGE_ATTR_MAX_LEARNED_ADDRESSES: {
        sstatus = SAI_STATUS_NOT_IMPLEMENTED;
        break;
    }
    case SAI_BRIDGE_ATTR_LEARN_DISABLE:
        sstatus = SAI_STATUS_NOT_IMPLEMENTED;
        break;

    case SAI_BRIDGE_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE:
        set_attr_value(SAI_BRIDGE_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE, (*value), lsaibridge->m_mcast_flood_type);
        break;
    case SAI_BRIDGE_ATTR_BROADCAST_FLOOD_CONTROL_TYPE:
        set_attr_value(SAI_BRIDGE_ATTR_BROADCAST_FLOOD_CONTROL_TYPE, (*value), lsaibridge->m_bcast_flood_type);
        break;
    case SAI_BRIDGE_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE:
        set_attr_value(SAI_BRIDGE_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE, (*value), lsaibridge->m_ucast_flood_type);
        break;
    case SAI_BRIDGE_ATTR_UNKNOWN_UNICAST_FLOOD_GROUP:
    case SAI_BRIDGE_ATTR_UNKNOWN_MULTICAST_FLOOD_GROUP:
    case SAI_BRIDGE_ATTR_BROADCAST_FLOOD_GROUP:
        sstatus = SAI_STATUS_NOT_IMPLEMENTED;
        break;

    default:
        sstatus = SAI_STATUS_UNKNOWN_ATTRIBUTE_0;
        break;
    }

    sai_return_on_error(sstatus, "Failed to get attribute\n");

    return sstatus;
}

static sai_status_t
sai_bridge_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_object_id_t bridge_id = key->key.object_id;
    int32_t attr_id = (uintptr_t)arg;

    lsai_object la_bridge(bridge_id);
    auto sdev = la_bridge.get_device();
    lsai_bridge_t* lsaibridge = sdev->m_bridges.get_ptr(la_bridge.index);
    if (lsaibridge == nullptr || lsaibridge->m_sdk_switch == nullptr) {
        sai_return_on_error(SAI_STATUS_INVALID_PARAMETER, "Invalid sai bridge object 0x%lx", bridge_id);
    }

    la_status lstatus = LA_STATUS_SUCCESS;
    bool is_drop = false;
    switch (attr_id) {
    case SAI_BRIDGE_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE: {
        lsaibridge->m_mcast_flood_type = get_attr_value(SAI_BRIDGE_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE, (*value));
        // intentional ignore the is_drop return value, default to false
        miss_packet_action_is_drop(sdev->m_fdb_mcast_miss_action, is_drop);

        if (is_drop || lsaibridge->m_mcast_flood_type == SAI_BRIDGE_FLOOD_CONTROL_TYPE_NONE) {
            lstatus = lsaibridge->m_sdk_switch->set_drop_unknown_mc_enabled(true);
        } else {
            lstatus = lsaibridge->m_sdk_switch->set_drop_unknown_mc_enabled(false);
        }
        return (to_sai_status(lstatus));
    }
    case SAI_BRIDGE_ATTR_BROADCAST_FLOOD_CONTROL_TYPE: {
        lsaibridge->m_bcast_flood_type = get_attr_value(SAI_BRIDGE_ATTR_BROADCAST_FLOOD_CONTROL_TYPE, (*value));
        miss_packet_action_is_drop(sdev->m_fdb_bcast_miss_action, is_drop);

        if (is_drop || lsaibridge->m_bcast_flood_type == SAI_BRIDGE_FLOOD_CONTROL_TYPE_NONE) {
            lstatus = lsaibridge->m_sdk_switch->set_drop_unknown_bc_enabled(true);
        } else {
            lstatus = lsaibridge->m_sdk_switch->set_drop_unknown_bc_enabled(false);
        }
        return (to_sai_status(lstatus));
    }
    case SAI_BRIDGE_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE: {
        lsaibridge->m_ucast_flood_type = get_attr_value(SAI_BRIDGE_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE, (*value));
        miss_packet_action_is_drop(sdev->m_fdb_ucast_miss_action, is_drop);

        if (is_drop || lsaibridge->m_ucast_flood_type == SAI_BRIDGE_FLOOD_CONTROL_TYPE_NONE) {
            lstatus = lsaibridge->m_sdk_switch->set_drop_unknown_uc_enabled(true);
        } else {
            lstatus = lsaibridge->m_sdk_switch->set_drop_unknown_uc_enabled(false);
        }
        return (to_sai_status(lstatus));
    }
    default:
        break;
    }
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
sai_bridge_port_attrib_get(_In_ const sai_object_key_t* key,
                           _Inout_ sai_attribute_value_t* value,
                           _In_ uint32_t attr_index,
                           _Inout_ vendor_cache_t* cache,
                           void* arg)
{
    int32_t attr_id = (uintptr_t)arg;
    sai_status_t sstatus = SAI_STATUS_SUCCESS;
    la_status status;

    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_bridge_port(key->key.object_id);
    auto sdev = la_bridge_port.get_device();
    sai_check_object(la_bridge_port, SAI_OBJECT_TYPE_BRIDGE_PORT, sdev, "bridge port", key->key.object_id);

    auto port_type = (sai_bridge_port_type_t)la_bridge_port.detail.get(lsai_detail_type_e::BRIDGE_PORT, lsai_detail_field_e::TYPE);

    bridge_port_entry entry{};
    rif_entry rif_entry{};
    if (port_type == SAI_BRIDGE_PORT_TYPE_PORT || port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT) {
        status = sdev->m_bridge_ports.get(la_bridge_port.index, entry);
        sai_return_on_la_error(status, "Incorrect bridge port 0x%lx", key->key.object_id);

        if (entry.l2_port == nullptr) {
            return SAI_STATUS_INVALID_OBJECT_ID;
        }
    } else if (port_type == SAI_BRIDGE_PORT_TYPE_1D_ROUTER || port_type == SAI_BRIDGE_PORT_TYPE_1Q_ROUTER) {
        status = sdev->m_l3_ports.get(la_bridge_port.index, rif_entry);
        sai_return_on_la_error(status, "Incorrect svi port 0x%lx", key->key.object_id);

        if (rif_entry.l3_port == nullptr) {
            return SAI_STATUS_INVALID_OBJECT_ID;
        }
    }

    switch (attr_id) {
    case SAI_BRIDGE_PORT_ATTR_TYPE: {
        set_attr_value(SAI_BRIDGE_PORT_ATTR_TYPE, (*value), port_type);
        break;
    }

    case SAI_BRIDGE_PORT_ATTR_PORT_ID: {
        if (port_type == SAI_BRIDGE_PORT_TYPE_PORT || port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT) {
            set_attr_value(SAI_BRIDGE_PORT_ATTR_PORT_ID, (*value), entry.port_obj);
        } else {
            return SAI_STATUS_INVALID_OBJECT_ID;
        }
        break;
    }

    case SAI_BRIDGE_PORT_ATTR_VLAN_ID: {
        if (port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT) {
            set_attr_value(SAI_BRIDGE_PORT_ATTR_VLAN_ID, (*value), entry.vlan_id);
        } else {
            return SAI_STATUS_INVALID_OBJECT_ID;
        }
        break;
    }

    case SAI_BRIDGE_PORT_ATTR_RIF_ID: {
        if (port_type == SAI_BRIDGE_PORT_TYPE_1D_ROUTER) {
            lsai_object la_rif(SAI_OBJECT_TYPE_ROUTER_INTERFACE, la_bridge_port.switch_id, la_bridge_port.index);
            set_attr_value(SAI_BRIDGE_PORT_ATTR_RIF_ID, (*value), (la_rif.object_id()));
        }
        break;
    }
    case SAI_BRIDGE_PORT_ATTR_TUNNEL_ID:
        sstatus = SAI_STATUS_NOT_IMPLEMENTED;
        break;

    case SAI_BRIDGE_PORT_ATTR_BRIDGE_ID: {
        const la_switch* sw = nullptr;
        if (port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT) {
            status = entry.l2_port->get_attached_switch(sw);
            sai_return_on_la_error(status);
        } else if (port_type == SAI_BRIDGE_PORT_TYPE_1D_ROUTER) {
            la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)rif_entry.l3_port);
            status = sviport->get_switch(sw);
            sai_return_on_la_error(status);
        } else if (port_type == SAI_BRIDGE_PORT_TYPE_PORT) {
            set_attr_value(SAI_BRIDGE_PORT_ATTR_BRIDGE_ID, (*value), sdev->m_default_1q_bridge_id);
            return SAI_STATUS_SUCCESS;
        } else {
            return SAI_STATUS_NOT_IMPLEMENTED;
        }

        if (sw == nullptr) {
            return SAI_STATUS_FAILURE;
        }
        int bridge_gid = sw->get_gid();
        lsai_object la_bridge(SAI_OBJECT_TYPE_BRIDGE, la_bridge_port.switch_id, bridge_gid);
        sai_object_id_t obj = la_bridge.object_id();
        set_attr_value(SAI_BRIDGE_PORT_ATTR_BRIDGE_ID, (*value), obj);

        break;
    }
    case SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE: {
        la_device::learn_mode_e cur_learn_mode;
        status = sdev->m_dev->get_learn_mode(cur_learn_mode);
        sai_return_on_la_error(status, "Failed getting device MAC learning mode");

        if (cur_learn_mode == la_device::learn_mode_e::SYSTEM) {
            set_attr_value(SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE, (*value), entry.learn_mode);
        }
        break;
    }
    case SAI_BRIDGE_PORT_ATTR_MAX_LEARNED_ADDRESSES:
        sstatus = SAI_STATUS_NOT_IMPLEMENTED;
        break;
    case SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_LIMIT_VIOLATION_PACKET_ACTION:
        sstatus = SAI_STATUS_NOT_IMPLEMENTED;
        break;
    case SAI_BRIDGE_PORT_ATTR_ADMIN_STATE:
        set_attr_value(SAI_BRIDGE_PORT_ATTR_ADMIN_STATE, (*value), true);
        break;
    }

    return sstatus;
}

static sai_status_t
sai_bridge_unknown_flood_get(_In_ const sai_object_key_t* key,
                             _Inout_ sai_attribute_value_t* value,
                             _In_ uint32_t attr_index,
                             _Inout_ vendor_cache_t* cache,
                             void* arg)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
sai_bridge_port_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    int32_t attr_id = (uintptr_t)arg;
    la_status status;

    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_bridge_port(key->key.object_id);
    auto sdev = la_bridge_port.get_device();
    sai_check_object(la_bridge_port, SAI_OBJECT_TYPE_BRIDGE_PORT, sdev, "bridge port", key->key.object_id);

    auto port_type = (sai_bridge_port_type_t)la_bridge_port.detail.get(lsai_detail_type_e::BRIDGE_PORT, lsai_detail_field_e::TYPE);

    bridge_port_entry* entry = nullptr;
    rif_entry rif_entry{};
    if (port_type == SAI_BRIDGE_PORT_TYPE_PORT || port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT) {
        status = sdev->m_bridge_ports.get_ptr(la_bridge_port.index, entry);
        sai_return_on_la_error(status, "Incorrect bridge port 0x%lx", key->key.object_id);

        if (entry->l2_port == nullptr) {
            return SAI_STATUS_INVALID_OBJECT_ID;
        }
    }

    switch (attr_id) {
    case SAI_BRIDGE_PORT_ATTR_ADMIN_STATE:
        if (entry != nullptr) {
            entry->admin_state = get_attr_value(SAI_BRIDGE_PORT_ATTR_ADMIN_STATE, *value);
        }
        return SAI_STATUS_SUCCESS;
    default:
        break;
    }
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static la_status
sai_learn_mode_set(_In_ la_l2_service_port* l2_port, _In_ sai_bridge_port_fdb_learning_mode_t& mode)
{
    la_status status = LA_STATUS_SUCCESS;
    if (l2_port == nullptr) {
        return LA_STATUS_EINVAL;
    }
    // Retrieve current HW configuration for a L2 port
    la_lp_mac_learning_mode_e cur_mac_learning_mode;
    status = l2_port->get_mac_learning_mode(cur_mac_learning_mode);
    la_return_on_error(status, "Failed getting MAC learning mode");

    switch (mode) {
    case SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW:
    // Use SYSTEM learning mode to process learn and age notifications
    // install/modify/delete MAC entries through SDK APIs

    // Intentionally fall through since both modes are configuring
    // HW the same way
    case SAI_BRIDGE_PORT_FDB_LEARNING_MODE_FDB_NOTIFICATION:
        if (cur_mac_learning_mode != la_lp_mac_learning_mode_e::CPU) {
            status = l2_port->set_mac_learning_mode(la_lp_mac_learning_mode_e::CPU);
            la_return_on_error(status, "Failed setting learn mode on l2 service port 0x%lx", l2_port);
        }
        break;

    case SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DROP:
    case SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DISABLE:
        if (cur_mac_learning_mode != la_lp_mac_learning_mode_e::NONE) {
            status = l2_port->set_mac_learning_mode(la_lp_mac_learning_mode_e::NONE);
            la_return_on_error(status, "Failed disabling learn mode on l2 service port 0x%lx", l2_port);
        }
        break;

    default:
        status = LA_STATUS_ENOTIMPLEMENTED;
        la_return_on_error(status, "Unsupported learning mode on l2 service port 0x%lx", l2_port);
        break;
    }
    return status;
}

static sai_status_t
sai_bridge_port_learn_mode_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    sai_status_t sstatus = SAI_STATUS_SUCCESS;
    la_status status;

    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_bridge_port(key->key.object_id);
    auto sdev = la_bridge_port.get_device();
    sai_check_object(la_bridge_port, SAI_OBJECT_TYPE_BRIDGE_PORT, sdev, "bridge port", key->key.object_id);

    auto port_type = (sai_bridge_port_type_t)la_bridge_port.detail.get(lsai_detail_type_e::BRIDGE_PORT, lsai_detail_field_e::TYPE);

    bridge_port_entry* entry = nullptr;
    if (port_type == SAI_BRIDGE_PORT_TYPE_PORT || port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT) {
        entry = sdev->m_bridge_ports.get_ptr(la_bridge_port.index);

        if (entry == nullptr || entry->l2_port == nullptr) {
            return SAI_STATUS_INVALID_OBJECT_ID;
        }
    } else {
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    // Store desired learning mode
    auto learn_mode = get_attr_value(SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE, (*value));
    entry->learn_mode = learn_mode;

    // Set L2 service port's learning mode
    status = sai_learn_mode_set(entry->l2_port, entry->learn_mode);
    sai_return_on_la_error(status, "Failed setting learn mode on bridge port 0x%lx", key->key.object_id);

    // .1D doesn't need to walk L2 ACs associated with the ethernet port
    if (port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT) {
        return sstatus;
    }
    // Need to walk all .1Q VLAN members and set their L2 service ports' learning mode
    la_ethernet_port* eth_port = nullptr;
    status = sai_port_get_ethernet_port(sdev, entry->port_obj, eth_port);
    sai_return_on_la_error(status, "no eth port ID. 0x%lx", entry->port_obj);

    // update all the logical ports (vlan members) on the same eth port (the .1Q bridge port)
    std::vector<la_object*> deps = sdev->m_dev->get_dependent_objects(eth_port);
    for (auto objp : deps) {
        if (objp->type() == la_object::object_type_e::L2_SERVICE_PORT) {
            la_l2_service_port* l2_port = static_cast<la_l2_service_port*>(objp);
            status = sai_learn_mode_set(l2_port, entry->learn_mode);
            sai_return_on_la_error(status, "Failed disabling learn mode on l2 service port 0x%lx", l2_port);

            if (l2_port != nullptr) {
                bridge_port_entry* tmp_entry = sdev->m_bridge_ports.get_ptr(l2_port->get_gid());
                if (tmp_entry != nullptr) {
                    tmp_entry->learn_mode = learn_mode;
                }
            }
        }
    }
    return sstatus;
}

la_status
create_la_bridge(la_switch*& bridge, std::shared_ptr<lsai_device> sdev, uint32_t bridge_gid, transaction& txn)
{
    txn.status = sdev->m_dev->create_switch(bridge_gid, bridge);
    la_return_on_error(txn.status, "Failed to create la_switch object for bridge, %s", txn.status.message().c_str());
    txn.on_fail([=]() { sdev->m_dev->destroy(bridge); });

    la_l2_multicast_group* flood_group = nullptr;
    txn.status = sdev->m_dev->create_l2_multicast_group(bridge_gid, la_replication_paradigm_e::EGRESS, flood_group);
    la_return_on_error(txn.status, "Failed to create flood group for bridge, rc %s", txn.status.message().c_str());
    txn.on_fail([=]() { sdev->m_dev->destroy(flood_group); });

    txn.status = bridge->set_flood_destination(flood_group);
    la_return_on_error(txn.status, "Failed to set flood group for bridge, rc %s", txn.status.message().c_str());

    // set default values for miss actions
    bool is_drop = false;
    miss_packet_action_is_drop(sdev->m_fdb_ucast_miss_action, is_drop);
    txn.status = bridge->set_drop_unknown_uc_enabled(is_drop);
    la_return_on_error(txn.status, "Failed setting drop unknown uc for bridge, rc %s", txn.status.message().c_str());

    miss_packet_action_is_drop(sdev->m_fdb_bcast_miss_action, is_drop);
    txn.status = bridge->set_drop_unknown_bc_enabled(is_drop);
    la_return_on_error(txn.status, "Failed setting drop unknown bc for bridge, rc %s", txn.status.message().c_str());

    miss_packet_action_is_drop(sdev->m_fdb_mcast_miss_action, is_drop);
    txn.status = bridge->set_drop_unknown_mc_enabled(is_drop);
    la_return_on_error(txn.status, "Failed setting drop unknown mc for bridge, rc %s", txn.status.message().c_str());

    la_l2_service_port* cpu_l2_port = nullptr;
    txn.status = sdev->create_cpu_l2_port(bridge_gid, bridge, cpu_l2_port, txn);
    la_return_on_error(txn.status, "can not create cpu port for bridge, rc %s", txn.status.message().c_str());

    return LA_STATUS_SUCCESS;
}

static sai_status_t
create_bridge(sai_object_id_t* out_bridge_id, sai_object_id_t obj_switch_id, uint32_t attr_count, const sai_attribute_t* attr_list)
{
    transaction txn;
    txn.status = LA_STATUS_SUCCESS;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_BRIDGE, SAI_OBJECT_TYPE_SWITCH, obj_switch_id, &bridge_to_string, "bridge", attrs);

    sai_bridge_type_t btype = SAI_BRIDGE_TYPE_1Q;
    get_attrs_value(SAI_BRIDGE_ATTR_TYPE, attrs, btype, true);

    lsai_object la_bdg(la_obj);
    la_bdg.type = SAI_OBJECT_TYPE_BRIDGE;

    if (btype == SAI_BRIDGE_TYPE_1Q) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    uint32_t bdg_id = 0;
    la_status status = sdev->m_bridges.allocate_id(bdg_id);
    sai_return_on_la_error(status);
    txn.on_fail([=]() { sdev->m_bridges.release_id(bdg_id); });

    la_bdg.index = bdg_id;

    la_switch* bridge = nullptr;
    txn.status = create_la_bridge(bridge, sdev, la_bdg.index, txn);
    sai_return_on_la_error(txn.status);

    lsai_bridge_t lsaibridge{};
    lsaibridge.m_sdk_switch = bridge;
    lsaibridge.m_type = btype;
    *out_bridge_id = la_bdg.object_id();
    lsaibridge.m_oid = *out_bridge_id;

    txn.status = sdev->m_bridges.set(*out_bridge_id, lsaibridge);
    sai_log_info(SAI_API_BRIDGE, "bridge 0x%lx created", *out_bridge_id);

    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];
    key.key.object_id = *out_bridge_id;
    snprintf(key_str, MAX_KEY_STR_LEN, "bridge 0x%0lx", *out_bridge_id);

    // loop for create_and_set attributes
    for (uint32_t i = 0; i < attr_count; i++) {
        // skip attributes are  mandatory or create only
        // Also, skip attribute that have been taken care by above creation process.

        switch (attr_list[i].id) {
        case SAI_BRIDGE_ATTR_TYPE:
            continue;
        default:
            sai_create_and_set_attribute(&key, key_str, bridge_attribs, bridge_vendor_attribs, &attr_list[i]);
            break;
        }
    }

    return to_sai_status(txn.status);
}

static sai_status_t
remove_bridge(sai_object_id_t obj_bridge_id)
{
    la_obj_wrap<la_switch> bridge;

    sai_start_api(SAI_API_BRIDGE, SAI_OBJECT_TYPE_BRIDGE, obj_bridge_id, &bridge_to_string, obj_bridge_id);

    // default_1q bridge always exists
    if (obj_bridge_id == sdev->m_default_1q_bridge_id) {
        return SAI_STATUS_OBJECT_IN_USE;
    }

    lsai_bridge_t* lsaibridge = sdev->m_bridges.get_ptr(la_obj.index);
    if (lsaibridge == nullptr) {
        sai_return_on_error(SAI_STATUS_INVALID_PARAMETER, "Fail to remove bridge object 0x%lx", obj_bridge_id);
    }

    if (lsaibridge->m_sdk_switch != nullptr) {
        la_l2_destination* flood_destination = nullptr;
        lsaibridge->m_sdk_switch->get_flood_destination(flood_destination);
        if (flood_destination) {
            la_status status = lsaibridge->m_sdk_switch->set_flood_destination(nullptr);
            sai_return_on_la_error(status, "Failed to clear flood group for bridge, %s", status.message().c_str());

            status = sdev->m_dev->destroy(flood_destination);
            sai_return_on_la_error(status, "Failed to delete flood destination, %s", status.message().c_str());
        }

        la_status status = sdev->destroy_cpu_l2_port(la_obj.index);
        sai_return_on_la_error(status, "Failed to delete cpu l2 port, %s", status.message().c_str());

        status = sdev->m_dev->destroy(lsaibridge->m_sdk_switch);
        sai_return_on_la_error(status, "Failed to delete bridge, %s", status.message().c_str());

        lsaibridge->m_sdk_switch = nullptr;
    }
    sdev->m_bridges.remove(obj_bridge_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_bridge_attribute(sai_object_id_t obj_bridge_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = obj_bridge_id;
    sai_start_api(SAI_API_BRIDGE, SAI_OBJECT_TYPE_BRIDGE, obj_bridge_id, &bridge_to_string, obj_bridge_id, "attr", *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "bridge 0x%lx", obj_bridge_id);
    return sai_set_attribute(&key, key_str, bridge_attribs, bridge_vendor_attribs, attr);
}

static sai_status_t
get_bridge_attribute(sai_object_id_t obj_bridge_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = obj_bridge_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_BRIDGE, SAI_OBJECT_TYPE_BRIDGE, obj_bridge_id, &bridge_to_string, obj_bridge_id, "attrs", attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "bridge 0x%lx", obj_bridge_id);
    return sai_get_attributes(&key, key_str, bridge_attribs, bridge_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
get_bridge_stats(sai_object_id_t bridge_id, uint32_t number_of_counters, const sai_stat_id_t* counter_ids, uint64_t* counters)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_bridge_stats_ext(sai_object_id_t bridge_id,
                     uint32_t number_of_counters,
                     const sai_stat_id_t* counter_ids,
                     sai_stats_mode_t mode,
                     uint64_t* counters)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
clear_bridge_stats(sai_object_id_t bridge_id, uint32_t number_of_counters, const sai_stat_id_t* counter_ids)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

la_switch*
la_get_bridge_by_obj(sai_object_id_t obj)
{
    lsai_object la_bdg{obj};
    auto sdev = la_bdg.get_device();

    if ((la_bdg.type != SAI_OBJECT_TYPE_BRIDGE && la_bdg.type != SAI_OBJECT_TYPE_VLAN) || sdev == nullptr
        || sdev->m_dev == nullptr) {
        return nullptr;
    }

    return sdev->m_dev->get_switch_by_id(la_bdg.index);
}

static la_status
la_create_eth_port_common(transaction& txn,
                          std::shared_ptr<lsai_device> sdev,
                          la_ethernet_port* eth_port,
                          la_uint_t max_packet_size)
{
    // checking status of txn from calling function
    la_return_on_error(txn.status, "Failed creating ethernet port, %s", txn.status.message().c_str());
    txn.on_fail([=]() { sdev->m_dev->destroy(eth_port); });

    txn.status = eth_port->set_ac_profile(sdev->m_default_ac_profile);
    la_return_on_error(txn.status, "Failed assigning default ac profile, %s", txn.status.message().c_str());

    txn.status = eth_port->set_copc_profile(LSAI_L2CP_PROFILE);
    la_return_on_error(txn.status, "Failed setting l2 lpts profile, %s", txn.status.message().c_str());

    txn.status = eth_port->set_mtu(max_packet_size);
    la_return_on_error(txn.status, "Failed setting mtu, %s", txn.status.message().c_str());

    return LA_STATUS_SUCCESS;
}

static la_status
la_create_eth_port(std::shared_ptr<lsai_device> sdev, port_entry& pentry)
{
    transaction txn;
    la_ethernet_port* eth_port = nullptr;

    txn.status = sdev->m_dev->create_ethernet_port(pentry.sys_port, la_ethernet_port::port_type_e::AC, eth_port);

    txn.status = la_create_eth_port_common(txn, sdev, eth_port, pentry.service.mtu);
    la_return_on_error(txn.status);

    pentry.service.eth_port = eth_port;

    return LA_STATUS_SUCCESS;
}

static la_status
la_create_eth_port(std::shared_ptr<lsai_device> sdev, lag_entry& sentry)
{
    transaction txn;
    la_ethernet_port* eth_port = nullptr;

    txn.status = sdev->m_dev->create_ethernet_port(sentry.spa_port, la_ethernet_port::port_type_e::AC, eth_port);

    txn.status = la_create_eth_port_common(txn, sdev, eth_port, sentry.service.mtu);
    la_return_on_error(txn.status);

    sentry.service.eth_port = eth_port;

    return LA_STATUS_SUCCESS;
}

la_status
sai_port_get_ethernet_port(std::shared_ptr<lsai_device>& sdev, sai_object_id_t port_oid, la_ethernet_port*& eth_port)
{
    sai_object_id_t untagged_oid = SAI_NULL_OBJECT_ID;

    return sai_port_get_ethernet_port_and_untagged(sdev, port_oid, eth_port, untagged_oid);
}

la_status
sai_port_get_ethernet_port_and_untagged(std::shared_ptr<lsai_device>& sdev,
                                        sai_object_id_t port_obj,
                                        la_ethernet_port*& eth_port,
                                        sai_object_id_t& untagged_oid)
{
    la_status status = LA_STATUS_SUCCESS;

    lsai_object la_obj(port_obj);
    if (la_obj.type == SAI_OBJECT_TYPE_PORT) {
        port_entry* pentry = nullptr;
        status = sdev->m_ports.get_ptr(la_obj.index, pentry);
        la_return_on_error(status);
        // check if this is the first service applied to the port
        if (pentry->service.eth_port == nullptr) {
            status = la_create_eth_port(sdev, *pentry);
            la_return_on_error(status);
            // update the eth_port information
            status = sdev->m_ports.set(la_obj.index, *pentry);
            la_return_on_error(status);
        }
        eth_port = pentry->service.eth_port;
        untagged_oid = pentry->service.untagged_bridge_port;
    } else if (la_obj.type == SAI_OBJECT_TYPE_LAG) {
        lag_entry* sentry = nullptr;
        status = sdev->m_lags.get_ptr(la_obj.index, sentry);
        la_return_on_error(status);
        if (sentry->service.eth_port == nullptr) {
            la_create_eth_port(sdev, *sentry);
            status = sdev->m_lags.set(la_obj.index, *sentry);
            la_return_on_error(status);
        }
        eth_port = sentry->service.eth_port;
        untagged_oid = sentry->service.untagged_bridge_port;
    } else {
        sai_log_error(SAI_API_BRIDGE, "Invalid sai port object 0x%lx", port_obj);
        return LA_STATUS_EINVAL;
    }

    return status;
}

la_status
sai_port_get_service(const std::shared_ptr<lsai_device>& sdev, sai_object_id_t port_obj, port_lag_common*& service)
{
    la_status status = LA_STATUS_SUCCESS;

    lsai_object la_obj(port_obj);
    if (la_obj.type == SAI_OBJECT_TYPE_PORT) {
        port_entry* pentry = nullptr;
        status = sdev->m_ports.get_ptr(la_obj.index, pentry);
        la_return_on_error(status);
        // check if this is the first service applied to the port
        service = &(pentry->service);
    } else if (la_obj.type == SAI_OBJECT_TYPE_LAG) {
        lag_entry* lentry = nullptr;
        status = sdev->m_lags.get_ptr(la_obj.index, lentry);
        la_return_on_error(status);
        service = &(lentry->service);
    } else {
        sai_log_error(SAI_API_BRIDGE, "Invalid sai port object 0x%lx", port_obj);
        return LA_STATUS_EINVAL;
    }

    return status;
}

static la_status
add_l2_port_to_flood_destination(std::shared_ptr<lsai_device> sdev,
                                 la_l2_service_port* l2_port,
                                 const la_ethernet_port* eth_port,
                                 la_l2_destination* flood_destination,
                                 transaction& txn)
{
    auto* multicast_group = static_cast<la_l2_multicast_group*>(flood_destination);
    const auto sys_port = eth_port->get_system_port();
    if (sys_port == nullptr) {
        auto spa_port = eth_port->get_spa_port();
        if (spa_port != nullptr) {
            auto gid = spa_port->get_gid();
            lag_entry* lag_entry = sdev->m_lags.get_ptr(gid);
            if (lag_entry != nullptr) {

                if (lag_entry->flood_sys == nullptr) {
                    auto it = lag_entry->members.begin();
                    if (it != lag_entry->members.end()) {
                        lag_entry->flood_sys = static_cast<const la_system_port*>(it->first);
                    }
                }
                if (lag_entry->flood_sys != nullptr) {
                    txn.status = multicast_group->add(l2_port, lag_entry->flood_sys);
                    la_return_on_error(txn.status, "Failed to add port to flood group, %s", txn.status.message().c_str());
                    txn.on_fail([=]() { multicast_group->remove(l2_port); });
                }
            }
        }
    } else {
        txn.status = multicast_group->add(l2_port, sys_port);
        la_return_on_error(txn.status, "Failed to add port to flood group, %s", txn.status.message().c_str());
        txn.on_fail([=]() { multicast_group->remove(l2_port); });
    }

    return LA_STATUS_SUCCESS;
}

//
// la_create_l2_bridge_port is used to create bridge_port_entry
//
// out_object_id is output of this function
//
// la_obj should contains the following from caller:
//      obj type, sub type, detail, switch and sdev
//      This is used to construct out_object_id
//
// entry should contain the following from the caller
//    - vlan_id for .1d bridge port
//    - bridge_port_oid is bridge port obj for vlan member
//    - bridge_obj for bridge port or vlan obj for vlan member
//    - port_obj ether port for bridge port and vlan member
//
la_status
la_create_l2_bridge_port(sai_object_id_t*& out_object_id,
                         lsai_object& la_obj,
                         bridge_port_entry& entry,
                         transaction& txn,
                         bool add_counter = false)
{
    auto sdev = la_obj.get_device();
    la_ethernet_port* eth_port = nullptr;
    *out_object_id = SAI_NULL_OBJECT_ID;
    txn.status = sai_port_get_ethernet_port(sdev, entry.port_obj, eth_port);
    la_return_on_error(txn.status);

    return la_create_l2_bridge_port_on_eth(out_object_id, la_obj, entry, txn, eth_port, add_counter);
}

la_status
la_create_l2_bridge_port_on_eth(sai_object_id_t*& out_object_id,
                                lsai_object& la_obj,
                                bridge_port_entry& entry,
                                transaction& txn,
                                la_ethernet_port* eth_port,
                                bool add_counter = false)
{
    // can not perform further if sdev does not exist
    auto sdev = la_obj.get_device();
    if (sdev == nullptr || sdev->m_dev == nullptr) {
        txn.status = LA_STATUS_EINVAL;
        return txn.status;
    }

    // get la_switch from bridge_obj
    la_switch* bridge = la_get_bridge_by_obj(entry.bridge_obj);
    if (bridge == nullptr) {
        sai_log_error(SAI_API_BRIDGE, "No bridge for bridge id 0x%lx", entry.bridge_obj);
        txn.status = LA_STATUS_ENOTFOUND;
        return txn.status;
    }

    // if it is not tagging mode, then it is access port, do not push or pop vlan
    // assume untagged 1q bridge port created before tagged vlan member
    // this setting will be the one set last one the eth port.
    uint16_t outer_vlan_id = entry.vlan_id;
    if (!entry.is_tagged) {
        eth_port->set_svi_egress_tag_mode(la_ethernet_port::svi_egress_tag_mode_e::STRIP);
    } else {
        eth_port->set_svi_egress_tag_mode(la_ethernet_port::svi_egress_tag_mode_e::KEEP);
    }

    // check if the service port already exists
    const la_object* ac_port{};
    txn.status = eth_port->get_ac_port(outer_vlan_id, 0, ac_port);

    la_l2_service_port* l2_service_port = nullptr;
    bridge_port_entry* old_bpentry = nullptr;
    // the l2 service already exist in the ethernet port
    if (txn.status == LA_STATUS_SUCCESS && ac_port != nullptr) {
        // allow 1q bridge port has the same vlan id as vlan member
        const la_l2_service_port* l2_ac_port = static_cast<const la_l2_service_port*>(ac_port);
        la_obj.index = l2_ac_port->get_gid();
        old_bpentry = sdev->m_bridge_ports.get_ptr(la_obj.index);
        old_bpentry->vlan_member_oid = la_obj.object_id();
        l2_service_port = old_bpentry->l2_port;
    } else {
        // create new l2 service
        lsai_object port_obj(entry.port_obj);
        port_entry* pentry = sdev->m_ports.get_ptr(port_obj.index);
        txn.status = sdev->m_bridge_ports.allocate_id(la_obj.index);
        la_return_on_error(txn.status);
        txn.on_fail([=]() { sdev->m_bridge_ports.release_id(la_obj.index); });

        txn.status = sdev->m_dev->create_ac_l2_service_port(la_obj.index,
                                                            eth_port,
                                                            outer_vlan_id,
                                                            0,
                                                            sdev->m_default_filter_group,
                                                            sdev->get_ingress_qos_profile(pentry),
                                                            sdev->m_qos_handler->get_default_egress_qos_profile(),
                                                            l2_service_port);
        la_return_on_error(txn.status, "Failed to create L2 ac port, %s", txn.status.message().c_str());
        txn.on_fail([=]() { sdev->m_dev->destroy(l2_service_port); });
    }

    if (l2_service_port == nullptr) {
        // this should not happen
        txn.status = LA_STATUS_EINVAL;
        la_return_on_error(txn.status, "Fail to get l2 service for %d vlan %d", la_obj.type, outer_vlan_id);
    }

    if (entry.is_tagged) {
        /* if tagging mode then pop at ingress and push at egress *
         * TODO: tagging mode only worked in bridging only not    *
         *        working in svi. More development is required    */
        la_vlan_tag_t out_tag = {.tpid = 0x8100, .tci = {.fields = {.pcp = 0, .dei = 0, .vid = entry.egr_dot1q_vlan}}};
        la_vlan_edit_command egress_edit_cmd(0 /* num tags to pop */, out_tag);
        txn.status = l2_service_port->set_egress_vlan_edit_command(egress_edit_cmd);
        la_return_on_error(txn.status, "Failed to set l2 ac port egress tagging mode, %s", txn.status.message().c_str());
        la_vlan_edit_command ingress_edit_cmd(1);
        txn.status = l2_service_port->set_ingress_vlan_edit_command(ingress_edit_cmd);
        la_return_on_error(txn.status, "Failed to set l2 ac port egress tagging mode, %s", txn.status.message().c_str());
        if (old_bpentry != nullptr) {
            old_bpentry->is_tagged = true;
        }
    }

    txn.status = l2_service_port->set_egress_feature_mode(la_l2_service_port::egress_feature_mode_e::L2);
    la_return_on_error(txn.status, "Failed to set egress feature mode for bridge port, %s", txn.status.message().c_str());

    la_counter_set* egress_qos_counter_set = nullptr;
    txn.status = sdev->m_dev->create_counter(NUM_QUEUE_PER_PORT, egress_qos_counter_set);
    la_return_on_error(txn.status, "Failed to create egress qos counter set for bridge port, %s", txn.status.message().c_str());
    txn.on_fail([=]() { sdev->m_dev->destroy(egress_qos_counter_set); });

    txn.status = l2_service_port->set_egress_counter(la_counter_set::type_e::QOS, egress_qos_counter_set);
    la_return_on_error(txn.status, "Failed to set egress qos counter set for bridge port, %s", txn.status.message().c_str());

    if (add_counter) {
        la_counter_set* egress_counter_set = nullptr;
        txn.status = sdev->m_dev->create_counter(1, egress_counter_set);
        la_return_on_error(txn.status, "Failed to create egress counter set for bridge port, %s", txn.status.message().c_str());
        txn.on_fail([=]() { sdev->m_dev->destroy(egress_counter_set); });

        txn.status = l2_service_port->set_egress_counter(la_counter_set::type_e::PORT, egress_counter_set);
        la_return_on_error(txn.status, "Failed to set egress counter set for bridge port, %s", txn.status.message().c_str());
    }

    if (outer_vlan_id != 0 && old_bpentry == nullptr) {
        txn.status = l2_service_port->attach_to_switch(bridge);
        la_return_on_error(txn.status, "Failed to attach bridge port to bridge, %s", txn.status.message().c_str());
        txn.on_fail([=]() { l2_service_port->detach(); });

        la_l2_destination* flood_destination = nullptr;
        txn.status = bridge->get_flood_destination(flood_destination);
        la_return_on_error(txn.status, "Failed to get flood destination %s", txn.status.message().c_str());

        txn.status = add_l2_port_to_flood_destination(sdev, l2_service_port, eth_port, flood_destination, txn);
        la_return_on_error(txn.status, "Failed to add port to flood group, %s", txn.status.message().c_str());

        txn.status = l2_service_port->set_stp_state(la_port_stp_state_e::FORWARDING);
        la_return_on_error(txn.status, "Failed to set stp state on bridge port, %s", txn.status.message().c_str());
    }

    entry.l2_port = l2_service_port;

    *out_object_id = la_obj.object_id();

    if (la_obj.type == SAI_OBJECT_TYPE_VLAN_MEMBER) {
        txn.status = sai_learn_mode_set(entry.l2_port, entry.learn_mode);
        la_return_on_error(txn.status, "Failed setting learn mode on VLAN member bridge port 0x%lx", entry.l2_port);
        sai_log_debug(SAI_API_BRIDGE, "VLAN member learn mode set");
        entry.vlan_member_oid = *out_object_id;
    } else {
        entry.bridge_port_oid = *out_object_id;
    }

    txn.status = sdev->m_bridge_ports.set(la_obj.index, entry);
    return txn.status;
}

static la_status
create_l3_bridge_port(sai_object_id_t*& out_bridge_port_id,
                      sai_object_id_t obj_rif_id,
                      bridge_port_entry& entry,
                      lsai_object& la_bport,
                      sai_bridge_port_type_t port_type,
                      transaction& txn)
{
    la_switch* bridge = la_get_bridge_by_obj(entry.bridge_obj);
    if (bridge == nullptr) {
        txn.status = LA_STATUS_EINVAL;
        return txn.status;
    }

    uint32_t svi_port_id = 0;
    if (port_type == SAI_BRIDGE_PORT_TYPE_1D_ROUTER) {
        txn.status = la_create_svi_port(svi_port_id, bridge, obj_rif_id, 0, txn);
        la_bport.index = svi_port_id;
    } else {
        lsai_object la_rif(obj_rif_id);
        la_bport.index = la_rif.index;
    }

    // NOTE: the 1D bridge port id is using index in svi_ports
    *out_bridge_port_id = la_bport.object_id();

    return txn.status;
}

static sai_status_t
create_bridge_port(sai_object_id_t* out_bridge_port_id,
                   sai_object_id_t obj_switch_id,
                   uint32_t attr_count,
                   const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_BRIDGE, SAI_OBJECT_TYPE_SWITCH, obj_switch_id, &bridge_port_to_string, "attrs", attrs);

    lsai_object la_bport(SAI_OBJECT_TYPE_BRIDGE_PORT, la_obj.switch_id, 0);
    la_bport.set_device(la_obj.get_device());

    lsai_detail& bdg_pt_detail = la_bport.detail;

    sai_bridge_port_type_t port_type{SAI_BRIDGE_PORT_TYPE_PORT};
    get_attrs_value(SAI_BRIDGE_PORT_ATTR_TYPE, attrs, port_type, true);
    bdg_pt_detail.set(lsai_detail_type_e::BRIDGE_PORT, lsai_detail_field_e::TYPE, port_type);

    bridge_port_entry bridge_port;

    if (port_type == SAI_BRIDGE_PORT_TYPE_PORT || port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT) {
        sai_object_id_t ether_port_obj{};
        get_attrs_value(SAI_BRIDGE_PORT_ATTR_PORT_ID, attrs, ether_port_obj, true);
        bridge_port.port_obj = ether_port_obj;
    }

    if (port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT || port_type == SAI_BRIDGE_PORT_TYPE_1D_ROUTER
        || port_type == SAI_BRIDGE_PORT_TYPE_TUNNEL) {

        sai_object_id_t bid{};
        get_attrs_value(SAI_BRIDGE_PORT_ATTR_BRIDGE_ID, attrs, bid, true);

        if (bid == sdev->m_default_1q_bridge_id) {
            sai_log_error(SAI_API_BRIDGE, "Incorrect bridge 0x%0lx", bid);
            return SAI_STATUS_FAILURE;
        }
        bridge_port.bridge_obj = bid;
    } else {
        bridge_port.bridge_obj = sdev->m_default_1q_bridge_id;
    }

    sai_bridge_port_tagging_mode_t tag_mode{SAI_BRIDGE_PORT_TAGGING_MODE_UNTAGGED};
    la_vlan_id_t outer_vlan_id{lsai_device::DEFAULT_VLAN_ID}; // only SUB_PORT can have different vlan number
    if (port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT) {
        get_attrs_value(SAI_BRIDGE_PORT_ATTR_TAGGING_MODE, attrs, tag_mode, false);
        get_attrs_value(SAI_BRIDGE_PORT_ATTR_VLAN_ID, attrs, outer_vlan_id, true);
    } else {
        get_attrs_value(SAI_BRIDGE_PORT_ATTR_VLAN_ID, attrs, outer_vlan_id, false);
    }
    bridge_port.vlan_id = outer_vlan_id;
    bridge_port.egr_dot1q_vlan = outer_vlan_id;
    bridge_port.is_tagged = (tag_mode != SAI_BRIDGE_PORT_TAGGING_MODE_UNTAGGED);

    transaction txn{};

    if (port_type == SAI_BRIDGE_PORT_TYPE_PORT || port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT) {
        // bridge_port should contains the following
        //    - vlan_id for .1d bridge port
        //    - bridge_port_obj for vlan member
        //    - bridge_obj for bridge port or vlan obj for vlan member
        //    - port_obj ether port for bridge port and vlan member

        // get la_ethernet_port from port_obj
        la_ethernet_port* eth_port = nullptr;
        *out_bridge_port_id = SAI_NULL_OBJECT_ID;
        txn.status = sai_port_get_ethernet_port(sdev, bridge_port.port_obj, eth_port);
        sai_return_on_la_error(txn.status);

        txn.status = la_create_l2_bridge_port_on_eth(out_bridge_port_id, la_bport, bridge_port, txn, eth_port);
        sai_return_on_la_error(txn.status);

        if (port_type == SAI_BRIDGE_PORT_TYPE_PORT && outer_vlan_id != 0) {
            sdev->m_default_1q_bridge_port_ids.insert(*out_bridge_port_id);
        }

        auto learn_mode = SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW;
        get_attrs_value(SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE, attrs, learn_mode, false);
        sai_object_key_t key{};
        key.key.object_id = *out_bridge_port_id;
        sai_attribute_value_t value{};
        set_attr_value(SAI_BRIDGE_PORT_ATTR_FDB_LEARNING_MODE, value, learn_mode);
        sai_bridge_port_learn_mode_set(&key, &value, nullptr);
    } else if (port_type == SAI_BRIDGE_PORT_TYPE_1D_ROUTER || port_type == SAI_BRIDGE_PORT_TYPE_1Q_ROUTER) {
        sai_object_id_t obj_rif_id{};
        get_attrs_value(SAI_BRIDGE_PORT_ATTR_RIF_ID, attrs, obj_rif_id, true);
        txn.status = create_l3_bridge_port(out_bridge_port_id, obj_rif_id, bridge_port, la_bport, port_type, txn);
        sai_return_on_la_error(txn.status);
    } else {
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    if (outer_vlan_id != 0) {
        sdev->m_bridge_port_object_ids.insert(*out_bridge_port_id);
        txn.on_fail([=]() {
            sdev->m_bridge_port_object_ids.erase(*out_bridge_port_id);
            *out_bridge_port_id = SAI_NULL_OBJECT_ID;
        });
    }

    if (port_type == SAI_BRIDGE_PORT_TYPE_PORT || port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT) {
        sai_status_t sstatus = lsai_bridge_port_update_services(sdev, *out_bridge_port_id, bridge_port.port_obj);
        sai_return_on_error(sstatus);
    }

    sai_log_info(SAI_API_BRIDGE, "bridge port 0x%lx created", *out_bridge_port_id);
    return SAI_STATUS_SUCCESS;
}

sai_object_id_t
create_untagged_bridge_port(std::shared_ptr<lsai_device>& sdev, sai_object_id_t port_oid)
{
    int attr_count = 3;
    sai_object_id_t l2_oid = SAI_NULL_OBJECT_ID;
    sai_attribute_t attr_list[attr_count];
    attr_list[0].id = SAI_BRIDGE_PORT_ATTR_TYPE;
    set_attr_value(SAI_BRIDGE_PORT_ATTR_TYPE, attr_list[0].value, SAI_BRIDGE_PORT_TYPE_PORT);
    attr_list[1].id = SAI_BRIDGE_PORT_ATTR_PORT_ID;
    set_attr_value(SAI_BRIDGE_PORT_ATTR_PORT_ID, attr_list[1].value, port_oid);
    attr_list[2].id = SAI_BRIDGE_PORT_ATTR_VLAN_ID;
    set_attr_value(SAI_BRIDGE_PORT_ATTR_VLAN_ID, attr_list[2].value, 0);
    sai_status_t status = create_bridge_port(&l2_oid, sdev->m_switch_id, attr_count, attr_list);
    if (status == SAI_STATUS_SUCCESS) {
        return l2_oid;
    }

    return SAI_NULL_OBJECT_ID;
}

sai_status_t
lsai_bridge_port_update_services(std::shared_ptr<lsai_device>& sdev, sai_object_id_t bridge_port_id, sai_object_id_t port_obj)
{
    lsai_object underlying_portobj(port_obj);
    if (!IS_SAI_SERVICE_PORT(underlying_portobj)) {
        return SAI_STATUS_SUCCESS;
    }

    // attach ingress and/or egress mirror session if underlying port
    // is already mirroring packets and is port. For LAG port, currently mirror session
    // cannot be attached.
    sai_status_t status = sdev->m_mirror_handler->attach_mirror_sessions(bridge_port_id, port_obj);
    sai_return_on_error(status);

    // Attach sample ingress and/or egress mirror instances from the bridge port if
    // underlying port is already sampling packets using mirror objects.
    status = sdev->m_mirror_handler->attach_sample_mirror_instance_to_logical_port(bridge_port_id, port_obj);
    sai_return_on_error(status);

    lsai_object la_bp(bridge_port_id);
    bridge_port_entry* bpentry = sdev->m_bridge_ports.get_ptr(la_bp.index);
    if (bpentry == nullptr) {
        sai_log_error(SAI_API_BRIDGE, "Incorrect bridge port obj or vlan member 0x%lx", bridge_port_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    // Attach ACL bound to switch or port
    status = sdev->m_acl_handler->attach_acl_on_bridge_port_create(bpentry);
    sai_return_on_error(status);
    return SAI_STATUS_SUCCESS;
}

la_status
detach_bridge_port(std::shared_ptr<lsai_device>& sdev, sai_object_id_t bv_oid, bridge_port_entry* entry)
{
    const la_switch* bridge;
    la_status status = entry->l2_port->get_attached_switch(bridge);
    if (status || bridge == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    la_l2_destination* flood_destination = nullptr;
    status = bridge->get_flood_destination(flood_destination);
    if (status == LA_STATUS_SUCCESS && flood_destination != nullptr) {
        auto* multicast_group = static_cast<la_l2_multicast_group*>(flood_destination);
        status = multicast_group->remove(entry->l2_port);
    }

    status = entry->l2_port->detach();
    la_return_on_error(status, "Can not detach from bridge 0x%lx, %s", entry->bridge_port_oid, status.message().c_str());

    return LA_STATUS_SUCCESS;
}

la_status
attach_bridge_port(std::shared_ptr<lsai_device> sdev, bridge_port_entry& entry, la_switch* bridge, transaction& txn)
{
    if (entry.l2_port == nullptr) {
        txn.status = LA_STATUS_EINVAL;
        return txn.status;
    }

    const la_switch* orig_bridge = nullptr;
    la_status status = entry.l2_port->get_attached_switch(orig_bridge);
    if (status == LA_STATUS_SUCCESS && orig_bridge != nullptr) {
        if (orig_bridge == bridge) {
            return LA_STATUS_SUCCESS;
        } else {
            txn.status = LA_STATUS_EBUSY;
            return txn.status;
        }
    }

    txn.status = entry.l2_port->attach_to_switch(bridge);
    la_return_on_error(txn.status, "Failed to attach bridge port to bridge, %s", txn.status.message().c_str());
    txn.on_fail([=]() { entry.l2_port->detach(); });

    la_l2_destination* flood_destination = nullptr;
    txn.status = bridge->get_flood_destination(flood_destination);
    la_return_on_error(txn.status, "Failed to get flood destination %s", txn.status.message().c_str());

    const la_ethernet_port* ethernet_port = nullptr;
    txn.status = entry.l2_port->get_ethernet_port(ethernet_port);
    la_return_on_error(txn.status);

    txn.status = add_l2_port_to_flood_destination(sdev, entry.l2_port, ethernet_port, flood_destination, txn);
    la_return_on_error(txn.status, "Failed to add port to flood group, %s", txn.status.message().c_str());

    return LA_STATUS_SUCCESS;
}

la_status
la_remove_bridge_port_or_vlan_member(std::shared_ptr<lsai_device>& sdev, sai_object_id_t bv_oid, bridge_port_entry* entry)
{
    lsai_object underlying_portobj(entry->port_obj);
    if (IS_SAI_SERVICE_PORT(underlying_portobj)) {
        // detach regular ingress and/or egress mirror sessions from the brdige port if
        // underlying port is already mirroring packets.
        sai_status_t sstatus = sdev->m_mirror_handler->detach_mirror_sessions(bv_oid, entry->port_obj);
        la_status status = to_la_status(sstatus);
        la_return_on_error(status);

        // detach sample ingress and/or egress mirror instances from the brdige port if
        // underlying port is already sampling packets using mirror objects.
        sstatus = sdev->m_mirror_handler->detach_sample_mirror_instance_from_logical_port(bv_oid, entry->port_obj);
        status = to_la_status(sstatus);
        la_return_on_error(status);

        sstatus = sdev->m_acl_handler->clear_acl_on_bridge_port_removal(*entry);
        status = to_la_status(sstatus);
        la_return_on_error(status);
    }

    // detach the bridge port from original bridge
    detach_bridge_port(sdev, bv_oid, entry);

    if (entry->l2_port != nullptr) {
        la_counter_set* tmp_set;
        la_status status = entry->l2_port->get_ingress_counter(la_counter_set::type_e::PORT, tmp_set);
        if (status == LA_STATUS_SUCCESS && tmp_set != nullptr) {
            entry->l2_port->set_ingress_counter(la_counter_set::type_e::PORT, nullptr);
            sdev->m_dev->destroy(tmp_set);
        }

        status = entry->l2_port->get_egress_counter(la_counter_set::type_e::PORT, tmp_set);
        if (status == LA_STATUS_SUCCESS && tmp_set != nullptr) {
            entry->l2_port->set_egress_counter(la_counter_set::type_e::PORT, nullptr);
            sdev->m_dev->destroy(tmp_set);
        }

        sdev->m_dev->destroy(entry->l2_port);
        entry->l2_port = nullptr;
    }
    la_status status = sdev->m_bridge_ports.remove(bv_oid);

    return status;
}

sai_status_t
do_remove_bridge_port(sai_object_id_t obj_bridge_port_id)
{
    lsai_object la_obj(obj_bridge_port_id);
    auto sdev = la_obj.get_device();

    bridge_port_entry* entry = sdev->m_bridge_ports.get_ptr(la_obj.index);
    if (entry == nullptr) {
        sai_log_error(SAI_API_BRIDGE, "No bridge port entry at index %u", la_obj.index);
        return SAI_STATUS_FAILURE;
    }

    auto port_type = (sai_bridge_port_type_t)la_obj.detail.get(lsai_detail_type_e::BRIDGE_PORT, lsai_detail_field_e::TYPE);
    if (port_type == SAI_BRIDGE_PORT_TYPE_PORT && entry->vlan_id != 0) {
        sdev->m_default_1q_bridge_port_ids.erase(obj_bridge_port_id);
    }

    if (entry->port_obj == SAI_NULL_OBJECT_ID) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (port_type == SAI_BRIDGE_PORT_TYPE_1D_ROUTER || port_type == SAI_BRIDGE_PORT_TYPE_1Q_ROUTER) {
        // do nothing since SAI_BRIDGE_PORT_TYPE_1D/1Q_ROUTER does not allocate resource
    } else {
        la_status status = la_remove_bridge_port_or_vlan_member(sdev, obj_bridge_port_id, entry);
        sai_return_on_la_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_bridge_port(sai_object_id_t obj_bridge_port_id)
{
    sai_start_api(SAI_API_BRIDGE, SAI_OBJECT_TYPE_BRIDGE_PORT, obj_bridge_port_id, &bridge_port_to_string, obj_bridge_port_id);

    sai_status_t sstatus = do_remove_bridge_port(obj_bridge_port_id);
    sai_return_on_error(sstatus);

    sdev->m_bridge_port_object_ids.erase(obj_bridge_port_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_bridge_port_attribute(sai_object_id_t bridge_port_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = bridge_port_id;

    sai_start_api(
        SAI_API_BRIDGE, SAI_OBJECT_TYPE_BRIDGE_PORT, bridge_port_id, &bridge_port_to_string, bridge_port_id, "attr", *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "bridge port 0x%lx", bridge_port_id);
    return sai_set_attribute(&key, key_str, bridge_port_attribs, bridge_port_vendor_attribs, attr);
}

static sai_status_t
get_bridge_port_attribute(sai_object_id_t bridge_port_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = bridge_port_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_BRIDGE, SAI_OBJECT_TYPE_BRIDGE_PORT, bridge_port_id, &bridge_port_to_string, bridge_port_id, "attrs", attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "bridge port 0x%lx", bridge_port_id);
    return sai_get_attributes(&key, key_str, bridge_port_attribs, bridge_port_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
get_bridge_port_stats_ext(sai_object_id_t obj_bridge_port_id,
                          uint32_t number_of_counters,
                          const sai_stat_id_t* counter_ids,
                          sai_stats_mode_t mode,
                          uint64_t* counters)
{

    lsai_object la_obj(obj_bridge_port_id);
    auto sdev = la_obj.get_device();
    sai_start_api_counter(sdev);

    bridge_port_entry entry;

    la_status status = sdev->m_bridge_ports.get(la_obj.index, entry);
    sai_return_on_la_error(status, "No bridge port with id %u", la_obj.index);

    bool read_ingress = std::any_of(counter_ids, counter_ids + number_of_counters, [](sai_stat_id_t id) {
        return (id == SAI_BRIDGE_PORT_STAT_IN_OCTETS) || (id == SAI_BRIDGE_PORT_STAT_IN_PACKETS);
    });

    bool read_egress = std::any_of(counter_ids, counter_ids + number_of_counters, [](sai_stat_id_t id) {
        return (id == SAI_BRIDGE_PORT_STAT_OUT_OCTETS) || (id == SAI_BRIDGE_PORT_STAT_OUT_PACKETS);
    });

    size_t in_packets = -1, in_bytes = -1, out_packets = -1, out_bytes = -1;

    if (read_ingress) {
        la_counter_set* ingress_counter = nullptr;
        la_status status = entry.l2_port->get_ingress_counter(la_counter_set::type_e::PORT, ingress_counter);
        sai_return_on_la_error(status, "Failed to get ingress counter, rc %s", status.message().c_str());

        if (ingress_counter == nullptr) {
            return SAI_STATUS_NOT_SUPPORTED;
        }

        status = ingress_counter->read(0, sdev->m_force_update, mode == SAI_STATS_MODE_READ_AND_CLEAR, in_packets, in_bytes);
        sai_return_on_la_error(status, "Failed to read ingress counter, rc %s", status.message().c_str());
    }

    if (read_egress) {
        la_counter_set* egress_counter = nullptr;
        la_status status = entry.l2_port->get_egress_counter(la_counter_set::type_e::PORT, egress_counter);
        sai_return_on_la_error(status, "Failed to get ingress counter, %s", status.message().c_str());

        if (egress_counter == nullptr) {
            return SAI_STATUS_NOT_SUPPORTED;
        }

        status = egress_counter->read(0, sdev->m_force_update, mode == SAI_STATS_MODE_READ_AND_CLEAR, out_packets, out_bytes);
        sai_return_on_la_error(status, "Failed to read egress counter, %s", status.message().c_str());
    }

    for (uint32_t i = 0; i < number_of_counters; ++i) {
        switch (counter_ids[i]) {
        case SAI_BRIDGE_PORT_STAT_IN_OCTETS:
            counters[i] = in_bytes;
            break;
        case SAI_BRIDGE_PORT_STAT_IN_PACKETS:
            counters[i] = in_packets;
            break;
        case SAI_BRIDGE_PORT_STAT_OUT_OCTETS:
            counters[i] = out_bytes;
            break;
        case SAI_BRIDGE_PORT_STAT_OUT_PACKETS:
            counters[i] = out_packets;
            break;
        default:
            break;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_bridge_port_stats(sai_object_id_t bridge_port_id,
                      uint32_t number_of_counters,
                      const sai_stat_id_t* counter_ids,
                      uint64_t* counters)
{
    return get_bridge_port_stats_ext(bridge_port_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ, counters);
}

static sai_status_t
clear_bridge_port_stats(sai_object_id_t bridge_port_id, uint32_t number_of_counters, const sai_stat_id_t* counter_ids)
{
    uint64_t counters[number_of_counters];
    return get_bridge_port_stats_ext(bridge_port_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ_AND_CLEAR, counters);
}

const sai_bridge_api_t bridge_api = {
    create_bridge,
    remove_bridge,
    set_bridge_attribute,
    get_bridge_attribute,
    get_bridge_stats,
    get_bridge_stats_ext,
    clear_bridge_stats,
    create_bridge_port,
    remove_bridge_port,
    set_bridge_port_attribute,
    get_bridge_port_attribute,
    get_bridge_port_stats,
    get_bridge_port_stats_ext,
    clear_bridge_port_stats,
};
}
}
