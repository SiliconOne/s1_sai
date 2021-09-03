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

#include "sai_vlan.h"

#include "api/npu/la_l2_service_port.h"
#include "api/npu/la_switch.h"
#include "api/system/la_device.h"
#include "api/types/la_object.h"
#include "common/ranged_index_generator.h"
#include "common/transaction.h"
#include "sai_device.h"
#include "sai_logger.h"
#include <algorithm>

namespace silicon_one
{
namespace sai
{

using namespace std;

static sai_status_t sai_vlan_get(_In_ const sai_object_key_t* key,
                                 _Inout_ sai_attribute_value_t* value,
                                 _In_ uint32_t attr_index,
                                 _Inout_ vendor_cache_t* cache,
                                 void* arg);

static sai_status_t vlan_max_learned_addr_get(_In_ const sai_object_key_t* key,
                                              _Inout_ sai_attribute_value_t* value,
                                              _In_ uint32_t attr_index,
                                              _Inout_ vendor_cache_t* cache,
                                              void* arg);

static sai_status_t vlan_max_learned_addr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t vlan_stp_get(_In_ const sai_object_key_t* key,
                                 _Inout_ sai_attribute_value_t* value,
                                 _In_ uint32_t attr_index,
                                 _Inout_ vendor_cache_t* cache,
                                 void* arg);

static sai_status_t sai_vlan_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t sai_vlan_attrib_get(_In_ const sai_object_key_t* key,
                                        _Inout_ sai_attribute_value_t* value,
                                        _In_ uint32_t attr_index,
                                        _Inout_ vendor_cache_t* cache,
                                        void* arg);

static sai_status_t vlan_stp_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t vlan_broadcast_flood_control_type_get(_In_ const sai_object_key_t* key,
                                                          _Inout_ sai_attribute_value_t* value,
                                                          _In_ uint32_t attr_index,
                                                          _Inout_ vendor_cache_t* cache,
                                                          void* arg);

static sai_status_t vlan_broadcast_flood_control_type_set(_In_ const sai_object_key_t* key,
                                                          _In_ const sai_attribute_value_t* value,
                                                          void* arg);

static sai_status_t vlan_get_learn_disable(_In_ const sai_object_key_t* key,
                                           _Inout_ sai_attribute_value_t* value,
                                           _In_ uint32_t attr_index,
                                           _Inout_ vendor_cache_t* cache,
                                           void* arg);

static sai_status_t vlan_set_learn_disable(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t vlan_get_port_list(_In_ const sai_object_key_t* key,
                                       _Inout_ sai_attribute_value_t* value,
                                       _In_ uint32_t attr_index,
                                       _Inout_ vendor_cache_t* cache,
                                       void* arg);

static sai_status_t vlan_member_vlan_id_get(_In_ const sai_object_key_t* key,
                                            _Inout_ sai_attribute_value_t* value,
                                            _In_ uint32_t attr_index,
                                            _Inout_ vendor_cache_t* cache,
                                            void* arg);

static sai_status_t vlan_member_bridge_port_get(_In_ const sai_object_key_t* key,
                                                _Inout_ sai_attribute_value_t* value,
                                                _In_ uint32_t attr_index,
                                                _Inout_ vendor_cache_t* cache,
                                                void* arg);

static sai_status_t vlan_member_tagging_mode_get(_In_ const sai_object_key_t* key,
                                                 _Inout_ sai_attribute_value_t* value,
                                                 _In_ uint32_t attr_index,
                                                 _Inout_ vendor_cache_t* cache,
                                                 void* arg);

static sai_status_t vlan_member_tagging_mode_set(_In_ const sai_object_key_t* key,
                                                 _In_ const sai_attribute_value_t* value,
                                                 _In_ void* arg);

static sai_status_t vlan_member_egr_dot1q_vlan_get(_In_ const sai_object_key_t* key,
                                                   _Inout_ sai_attribute_value_t* value,
                                                   _In_ uint32_t attr_index,
                                                   _Inout_ vendor_cache_t* cache,
                                                   void* arg);

// clang-format off
extern const sai_attribute_entry_t vlan_attribs[] = {
    // id; mandatory_on_create; valid_for_create; valid_for_set; valid_for_get
    // *attrib_name; type;
    {SAI_VLAN_ATTR_VLAN_ID, true, true, false, true, "Vlan Id", SAI_ATTR_VAL_TYPE_U16},
    {SAI_VLAN_ATTR_MEMBER_LIST, false, false, false, true, "Vlan Port List", SAI_ATTR_VAL_TYPE_OBJLIST},
    {SAI_VLAN_ATTR_MAX_LEARNED_ADDRESSES, false, true, true, true, "Vlan Maximum number of learned MAC addresses", SAI_ATTR_VAL_TYPE_U32},
    {SAI_VLAN_ATTR_STP_INSTANCE, false, true, true, true, "Vlan associated STP instance", SAI_ATTR_VAL_TYPE_OID},
    {SAI_VLAN_ATTR_LEARN_DISABLE, false, true, true, true, "Vlan Learning Disabled", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_VLAN_ATTR_IPV4_MCAST_LOOKUP_KEY_TYPE, false, true, true, true, "IPv4 multicast lookup key on a VLAN", SAI_ATTR_VAL_TYPE_U32},
    {SAI_VLAN_ATTR_IPV6_MCAST_LOOKUP_KEY_TYPE, false, true, true, true, "IPv6 multicast lookup key on a VLAN", SAI_ATTR_VAL_TYPE_U32},
    {SAI_VLAN_ATTR_UNKNOWN_NON_IP_MCAST_OUTPUT_GROUP_ID, false, true, true, true, "L2MC Group ID for unknown non-IP MCAST", SAI_ATTR_VAL_TYPE_OID},
    {SAI_VLAN_ATTR_UNKNOWN_IPV4_MCAST_OUTPUT_GROUP_ID, false, true, true, true, "L2MC Group ID for unknown IPv4 MCAST", SAI_ATTR_VAL_TYPE_OID},
    {SAI_VLAN_ATTR_UNKNOWN_IPV6_MCAST_OUTPUT_GROUP_ID, false, true, true, true, "L2MC Group ID for unknown IPv6 MCAST", SAI_ATTR_VAL_TYPE_OID},
    {SAI_VLAN_ATTR_UNKNOWN_LINKLOCAL_MCAST_OUTPUT_GROUP_ID, false, true, true, true, "L2MC Group ID for linklocal IPv6 MCAST", SAI_ATTR_VAL_TYPE_OID},
    {SAI_VLAN_ATTR_INGRESS_ACL, false, true, true, true, "VLAN bind point for ingress ACL object", SAI_ATTR_VAL_TYPE_OID},
    {SAI_VLAN_ATTR_EGRESS_ACL, false, true, true, true, "VLAN bind point for egress ACL object", SAI_ATTR_VAL_TYPE_OID},
    {SAI_VLAN_ATTR_META_DATA, false, true, true, true, "User based Meta Data", SAI_ATTR_VAL_TYPE_U32},
    {SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE, false, true, true, true, "Unknown unicast flood control", SAI_ATTR_VAL_TYPE_U8},
    {SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_GROUP, false, true, true, true, "Unknown unicast flood group", SAI_ATTR_VAL_TYPE_OID},
    {SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE, false, true, true, true, "Unknown multicast flood control", SAI_ATTR_VAL_TYPE_U8},
    {SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_GROUP, false, true, true, true, "Unknown multicast flood group", SAI_ATTR_VAL_TYPE_OID},
    {SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE, false, true, true, true, "Unknown broadcast control", SAI_ATTR_VAL_TYPE_U8},
    {SAI_VLAN_ATTR_BROADCAST_FLOOD_GROUP, false, true, true, true, "Unknown broadcast group", SAI_ATTR_VAL_TYPE_OID},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t vlan_vendor_attribs[] = {
    /* create, remove, set, get */
    {SAI_VLAN_ATTR_VLAN_ID,
     {true, false, false, true}, /* implemented */
     {true, false, false, true}, /* supported */
     sai_vlan_get, nullptr, nullptr, nullptr},

    {SAI_VLAN_ATTR_MEMBER_LIST,
     {false, false, false, true},
     {false, false, false, true},
     vlan_get_port_list, nullptr, nullptr, nullptr},

    {SAI_VLAN_ATTR_MAX_LEARNED_ADDRESSES,
     {false, false, true, true},
     {false, false, true, true},
     vlan_max_learned_addr_get, nullptr, vlan_max_learned_addr_set, nullptr},

    {SAI_VLAN_ATTR_STP_INSTANCE,
     {false, false, true, true},
     {false, false, true, true},
     vlan_stp_get, nullptr, vlan_stp_set, nullptr},

    {SAI_VLAN_ATTR_LEARN_DISABLE,
     {false, true, true, true},
     {false, true, true, true},
     vlan_get_learn_disable, nullptr, vlan_set_learn_disable, nullptr},

    {SAI_VLAN_ATTR_IPV4_MCAST_LOOKUP_KEY_TYPE,
     {false, false, false, true},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    {SAI_VLAN_ATTR_IPV6_MCAST_LOOKUP_KEY_TYPE,
     {false, false, false, true},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    {SAI_VLAN_ATTR_UNKNOWN_NON_IP_MCAST_OUTPUT_GROUP_ID,
     {false, false, false, true},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    {SAI_VLAN_ATTR_UNKNOWN_IPV4_MCAST_OUTPUT_GROUP_ID,
     {false, false, false, true},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    {SAI_VLAN_ATTR_UNKNOWN_IPV6_MCAST_OUTPUT_GROUP_ID,
     {false, false, false, true},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    {SAI_VLAN_ATTR_UNKNOWN_LINKLOCAL_MCAST_OUTPUT_GROUP_ID,
     {false, false, false, true},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    {SAI_VLAN_ATTR_INGRESS_ACL,
     {false, false, false, true},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    {SAI_VLAN_ATTR_EGRESS_ACL,
     {false, false, false, true},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    {SAI_VLAN_ATTR_META_DATA,
     {false, false, false, true},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    SAI_ATTR_CREATE_AND_SET(SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE, sai_vlan_attrib_get, sai_vlan_attrib_set),

    {SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_GROUP,
     {false, false, false, true},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    SAI_ATTR_CREATE_AND_SET(SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE, sai_vlan_attrib_get, sai_vlan_attrib_set),

    {SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_GROUP,
     {false, false, false, true},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    SAI_ATTR_CREATE_AND_SET(SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE, sai_vlan_attrib_get, sai_vlan_attrib_set),

    {SAI_VLAN_ATTR_BROADCAST_FLOOD_GROUP,
     {false, false, false, true},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},
};

// id; mandatory_on_create; valid_for_create; valid_for_set; valid_for_get
// *attrib_name; type;
extern const sai_attribute_entry_t vlan_member_attribs[]
    = {{SAI_VLAN_MEMBER_ATTR_VLAN_ID, true, true, false, true, "Vlan Member Vlan ID", SAI_ATTR_VAL_TYPE_OID},
       {SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID, true, true, false, true, "Vlan Member Bridge Port ID", SAI_ATTR_VAL_TYPE_OID},
       {SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE, false, true, true, true, "Vlan Member Tagging Mode", SAI_ATTR_VAL_TYPE_S32},
       {SAI_VLAN_MEMBER_ATTR_EXT_EGR_DOT1Q_TAG_VLAN, false, true, false, true, "Egress DOT1Q Tag VLAN", SAI_ATTR_VAL_TYPE_U16},
       {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t vlan_member_vendor_attribs[] = {
    /* create, remove, set, get */
    {SAI_VLAN_MEMBER_ATTR_VLAN_ID,
     {true, false, false, true}, /* implemented */
     {true, false, false, true}, /* supported */
     vlan_member_vlan_id_get, nullptr, nullptr, nullptr},

    {SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID,
     {true, false, false, true},
     {true, false, false, true},
     vlan_member_bridge_port_get, nullptr, nullptr, nullptr},

    {SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE,
     {true, false, true, true},
     {true, false, true, true},
     vlan_member_tagging_mode_get, nullptr, vlan_member_tagging_mode_set, nullptr},

    {SAI_VLAN_MEMBER_ATTR_EXT_EGR_DOT1Q_TAG_VLAN,
     {true, false, false, true},
     {true, false, false, true},
     vlan_member_egr_dot1q_vlan_get, nullptr, nullptr, nullptr},
};
// clang-format on

sai_status_t
laobj_db_vlan_member::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    uint32_t i = 0;
    for (const auto& entry : sdev->m_bridge_ports.map()) {
        auto& bpentry = entry.second;
        if (bpentry.vlan_member_oid == SAI_NULL_OBJECT_ID) {
            continue;
        }
        i++;
    }
    *count = i;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_vlan_member::get_object_keys(std::shared_ptr<lsai_device> sdev,
                                      uint32_t* object_count,
                                      sai_object_key_t* object_list) const
{
    uint32_t i = 0;
    for (const auto& entry : sdev->m_bridge_ports.map()) {
        if (i > *object_count) {
            *object_count = i;
            return SAI_STATUS_BUFFER_OVERFLOW;
        }
        auto& bpentry = entry.second;
        if (bpentry.vlan_member_oid == SAI_NULL_OBJECT_ID) {
            continue;
        }
        object_list[i].key.object_id = bpentry.vlan_member_oid;
        i++;
    }
    *object_count = i;
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
sai_vlan_get(_In_ const sai_object_key_t* key,
             _Inout_ sai_attribute_value_t* value,
             _In_ uint32_t attr_index,
             _Inout_ vendor_cache_t* cache,
             void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_object_id_t vlan_id = key->key.object_id;
    lsai_object la_vlan(vlan_id);
    auto sdev = la_vlan.get_device();
    lsai_vlan_t* lsaivlan = sdev->m_vlans.get_ptr(la_vlan.index);
    if (lsaivlan == nullptr || lsaivlan->m_sdk_switch == nullptr) {
        sai_return_on_error(SAI_STATUS_INVALID_PARAMETER, "Invalid sai vlan object 0x%lx", vlan_id);
    }

    uint32_t id = sdev->m_vlans.get_id(vlan_id);
    set_attr_value(SAI_VLAN_ATTR_VLAN_ID, (*value), id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
vlan_max_learned_addr_get(_In_ const sai_object_key_t* key,
                          _Inout_ sai_attribute_value_t* value,
                          _In_ uint32_t attr_index,
                          _Inout_ vendor_cache_t* cache,
                          void* arg)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
sai_vlan_attrib_get(_In_ const sai_object_key_t* key,
                    _Inout_ sai_attribute_value_t* value,
                    _In_ uint32_t attr_index,
                    _Inout_ vendor_cache_t* cache,
                    void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_object_id_t vlan_id = key->key.object_id;
    int32_t attr_id = (uintptr_t)arg;
    sai_status_t sstatus = SAI_STATUS_SUCCESS;

    lsai_object la_vlan(vlan_id);
    auto sdev = la_vlan.get_device();
    lsai_vlan_t* lsaivlan = sdev->m_vlans.get_ptr(la_vlan.index);
    if (lsaivlan == nullptr || lsaivlan->m_sdk_switch == nullptr) {
        sai_return_on_error(SAI_STATUS_INVALID_PARAMETER, "Invalid sai vlan object 0x%lx", vlan_id);
    }

    switch (attr_id) {
    case SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE:
        set_attr_value(SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE, (*value), lsaivlan->m_mcast_flood_type);
        break;
    case SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE:
        set_attr_value(SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE, (*value), lsaivlan->m_bcast_flood_type);
        break;
    case SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE:
        set_attr_value(SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE, (*value), lsaivlan->m_ucast_flood_type);
        break;

    default:
        sstatus = SAI_STATUS_UNKNOWN_ATTRIBUTE_0;
        break;
    }

    sai_return_on_error(sstatus, "Failed to get attribute\n");

    return sstatus;
}

static sai_status_t
sai_vlan_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_object_id_t vlan_id = key->key.object_id;
    int32_t attr_id = (uintptr_t)arg;

    lsai_object la_vlan(vlan_id);
    auto sdev = la_vlan.get_device();
    lsai_vlan_t* lsaivlan = sdev->m_vlans.get_ptr(la_vlan.index);
    if (lsaivlan == nullptr || lsaivlan->m_sdk_switch == nullptr) {
        sai_return_on_error(SAI_STATUS_INVALID_PARAMETER, "Invalid sai vlan object 0x%lx", vlan_id);
    }

    la_status lstatus = LA_STATUS_SUCCESS;
    bool is_drop = false;
    switch (attr_id) {
    case SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE: {
        lsaivlan->m_mcast_flood_type = get_attr_value(SAI_VLAN_ATTR_UNKNOWN_MULTICAST_FLOOD_CONTROL_TYPE, (*value));
        // intentional ignore the is_drop return value, default to false
        miss_packet_action_is_drop(sdev->m_fdb_mcast_miss_action, is_drop);

        if (is_drop || lsaivlan->m_mcast_flood_type == SAI_VLAN_FLOOD_CONTROL_TYPE_NONE) {
            lstatus = lsaivlan->m_sdk_switch->set_drop_unknown_mc_enabled(true);
        } else {
            lstatus = lsaivlan->m_sdk_switch->set_drop_unknown_mc_enabled(false);
        }
        return (to_sai_status(lstatus));
    }
    case SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE: {
        lsaivlan->m_bcast_flood_type = get_attr_value(SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE, (*value));
        miss_packet_action_is_drop(sdev->m_fdb_bcast_miss_action, is_drop);

        if (is_drop || lsaivlan->m_bcast_flood_type == SAI_VLAN_FLOOD_CONTROL_TYPE_NONE) {
            lstatus = lsaivlan->m_sdk_switch->set_drop_unknown_bc_enabled(true);
        } else {
            lstatus = lsaivlan->m_sdk_switch->set_drop_unknown_bc_enabled(false);
        }
        return (to_sai_status(lstatus));
    }
    case SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE: {
        lsaivlan->m_ucast_flood_type = get_attr_value(SAI_VLAN_ATTR_UNKNOWN_UNICAST_FLOOD_CONTROL_TYPE, (*value));
        miss_packet_action_is_drop(sdev->m_fdb_ucast_miss_action, is_drop);

        if (is_drop || lsaivlan->m_ucast_flood_type == SAI_VLAN_FLOOD_CONTROL_TYPE_NONE) {
            lstatus = lsaivlan->m_sdk_switch->set_drop_unknown_uc_enabled(true);
        } else {
            lstatus = lsaivlan->m_sdk_switch->set_drop_unknown_uc_enabled(false);
        }
        return (to_sai_status(lstatus));
    }
    default:
        break;
    }
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
vlan_max_learned_addr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
vlan_stp_get(_In_ const sai_object_key_t* key,
             _Inout_ sai_attribute_value_t* value,
             _In_ uint32_t attr_index,
             _Inout_ vendor_cache_t* cache,
             void* arg)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
vlan_stp_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
vlan_broadcast_flood_control_type_get(_In_ const sai_object_key_t* key,
                                      _Inout_ sai_attribute_value_t* value,
                                      _In_ uint32_t attr_index,
                                      _Inout_ vendor_cache_t* cache,
                                      void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    set_attr_value(SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE, (*value), SAI_VLAN_FLOOD_CONTROL_TYPE_ALL);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
vlan_broadcast_flood_control_type_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto type = get_attr_value(SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE, (*value));
    if (type == SAI_VLAN_FLOOD_CONTROL_TYPE_ALL) {
        return SAI_STATUS_SUCCESS;
    }

    return SAI_STATUS_NOT_SUPPORTED;
}

static sai_status_t
vlan_get_learn_disable(_In_ const sai_object_key_t* key,
                       _Inout_ sai_attribute_value_t* value,
                       _In_ uint32_t attr_index,
                       _Inout_ vendor_cache_t* cache,
                       void* arg)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
vlan_set_learn_disable(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_object_id_t vlan_id = key->key.object_id;
    lsai_object la_vlan(vlan_id);
    auto sdev = la_vlan.get_device();
    lsai_vlan_t* lsaivlan = sdev->m_vlans.get_ptr(la_vlan.index);
    if (lsaivlan == nullptr || lsaivlan->m_sdk_switch == nullptr) {
        sai_return_on_error(SAI_STATUS_INVALID_PARAMETER, "Invalid sai vlan object 0x%lx", vlan_id);
    }

    auto disable = get_attr_value(SAI_VLAN_ATTR_LEARN_DISABLE, (*value));
    la_switch* bridge = lsaivlan->m_sdk_switch;
    la_l2_service_port* l2_cpu_port = sdev->m_cpu_l2_port_map[la_vlan.index].l2_port;
    auto bports = sdev->m_dev->get_dependent_objects(bridge);
    for (const auto bp : bports) {
        if (bp == nullptr || bp->type() != la_object::object_type_e::L2_SERVICE_PORT) {
            continue;
        }

        la_l2_service_port* l2_port = static_cast<la_l2_service_port*>(bp);
        if (l2_port == l2_cpu_port) {
            continue;
        }

        uint32_t index = l2_port->get_gid();

        bridge_port_entry* bpentry = sdev->m_bridge_ports.get_ptr(index);
        if (bpentry == nullptr || bpentry->vlan_member_oid == SAI_NULL_OBJECT_ID) {
            continue;
        }

        la_status status = LA_STATUS_SUCCESS;
        sai_bridge_port_fdb_learning_mode_t mode = disable ? SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DISABLE : bpentry->learn_mode;
        switch (mode) {
        case SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW:
        case SAI_BRIDGE_PORT_FDB_LEARNING_MODE_FDB_NOTIFICATION:
            status = l2_port->set_mac_learning_mode(la_lp_mac_learning_mode_e::CPU);
            sai_return_on_la_error(status, "Failed setting learn mode on l2 service port 0x%lx", l2_port);
            break;

        case SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DROP:
        case SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DISABLE:
            status = l2_port->set_mac_learning_mode(la_lp_mac_learning_mode_e::NONE);
            sai_return_on_la_error(status, "Failed disabling learn mode on l2 service port 0x%lx", l2_port);
            break;

        default:
            status = LA_STATUS_ENOTIMPLEMENTED;
            sai_return_on_la_error(status, "Unsupported learning mode on l2 service port 0x%lx", l2_port);
            break;
        }
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
vlan_get_port_list(_In_ const sai_object_key_t* key,
                   _Inout_ sai_attribute_value_t* value,
                   _In_ uint32_t attr_index,
                   _Inout_ vendor_cache_t* cache,
                   void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status_t sstatus = SAI_STATUS_SUCCESS;

    sai_object_id_t vlan_id = key->key.object_id;
    lsai_object la_vlan(vlan_id);
    auto sdev = la_vlan.get_device();
    lsai_vlan_t* lsaivlan = sdev->m_vlans.get_ptr(la_vlan.index);
    if (lsaivlan == nullptr || lsaivlan->m_sdk_switch == nullptr) {
        sai_return_on_error(SAI_STATUS_INVALID_PARAMETER, "Invalid sai vlan object 0x%lx", vlan_id);
    }

    auto& objlist = value->objlist;
    la_switch* bridge = lsaivlan->m_sdk_switch;

    la_l2_service_port* l2_cpu_port = sdev->m_cpu_l2_port_map[la_vlan.index].l2_port;

    auto bports = sdev->m_dev->get_dependent_objects(bridge);
    uint32_t i = 0;

    la_ethernet_port* recy_injectup_eth = sdev->m_recycle_injectup_eth_port;

    lsai_object la_mem(SAI_OBJECT_TYPE_VLAN_MEMBER, la_vlan.switch_id, 0);
    for (const auto bp : bports) {
        if (bp->type() != la_object::object_type_e::L2_SERVICE_PORT) {
            continue;
        }

        const la_l2_service_port* l2_port = static_cast<const la_l2_service_port*>(bp);
        if (l2_port == nullptr || l2_port == l2_cpu_port) {
            continue;
        }

        const la_ethernet_port* eth_port = nullptr;
        la_status status = l2_port->get_ethernet_port(eth_port);
        if (status == LA_STATUS_SUCCESS && eth_port == recy_injectup_eth) {
            continue;
        }

        la_mem.index = l2_port->get_gid();

        bridge_port_entry* bpentry = sdev->m_bridge_ports.get_ptr(la_mem.index);
        if (bpentry == nullptr || bpentry->vlan_member_oid == SAI_NULL_OBJECT_ID) {
            continue;
        }

        if (i < objlist.count) {
            objlist.list[i] = bpentry->vlan_member_oid;
        } else {
            sstatus = SAI_STATUS_BUFFER_OVERFLOW;
        }
        i++;
    }
    objlist.count = i;

    return sstatus;
}

static sai_status_t
vlan_member_vlan_id_get(_In_ const sai_object_key_t* key,
                        _Inout_ sai_attribute_value_t* value,
                        _In_ uint32_t attr_index,
                        _Inout_ vendor_cache_t* cache,
                        void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_vlan_mem(key->key.object_id);
    auto sdev = la_vlan_mem.get_device();
    sai_check_object(la_vlan_mem, SAI_OBJECT_TYPE_VLAN_MEMBER, sdev, "vlan member", key->key.object_id);

    bridge_port_entry bridge_port;
    la_status status = sdev->m_bridge_ports.get(la_vlan_mem.index, bridge_port);
    sai_return_on_la_error(status);

    set_attr_value(SAI_VLAN_MEMBER_ATTR_VLAN_ID, (*value), bridge_port.bridge_obj);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
vlan_member_bridge_port_get(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_vlan_mem(key->key.object_id);
    auto sdev = la_vlan_mem.get_device();
    sai_check_object(la_vlan_mem, SAI_OBJECT_TYPE_VLAN_MEMBER, sdev, "vlan member", key->key.object_id);

    bridge_port_entry bridge_port;
    la_status status = sdev->m_bridge_ports.get(la_vlan_mem.index, bridge_port);
    sai_return_on_la_error(status);

    set_attr_value(SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID, (*value), bridge_port.bridge_port_oid);
    return SAI_STATUS_SUCCESS;
}
static sai_status_t
vlan_member_tagging_mode_get(_In_ const sai_object_key_t* key,
                             _Inout_ sai_attribute_value_t* value,
                             _In_ uint32_t attr_index,
                             _Inout_ vendor_cache_t* cache,
                             void* arg)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
vlan_member_tagging_mode_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
vlan_member_egr_dot1q_vlan_get(_In_ const sai_object_key_t* key,
                               _Inout_ sai_attribute_value_t* value,
                               _In_ uint32_t attr_index,
                               _Inout_ vendor_cache_t* cache,
                               void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_vlan_mem(key->key.object_id);
    auto sdev = la_vlan_mem.get_device();
    sai_check_object(la_vlan_mem, SAI_OBJECT_TYPE_VLAN_MEMBER, sdev, "vlan member", key->key.object_id);

    bridge_port_entry bridge_port;
    la_status status = sdev->m_bridge_ports.get(la_vlan_mem.index, bridge_port);
    sai_return_on_la_error(status);

    set_attr_value(SAI_VLAN_MEMBER_ATTR_EXT_EGR_DOT1Q_TAG_VLAN, (*value), bridge_port.egr_dot1q_vlan);

    return SAI_STATUS_SUCCESS;
}

static std::string
vlan_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_vlan_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static std::string
vlan_member_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_vlan_member_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

//======================================================================
/**
 * @brief Create a VLAN
 *
 * @param[out] vlan_id VLAN ID
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t
create_vlan(_Out_ sai_object_id_t* vlan_id,
            _In_ sai_object_id_t switch_id,
            _In_ uint32_t attr_count,
            _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_VLAN, SAI_OBJECT_TYPE_SWITCH, switch_id, &vlan_to_string, attrs);

    uint16_t out_vlan_id = 0;
    get_attrs_value(SAI_VLAN_ATTR_VLAN_ID, attrs, out_vlan_id, true);

    if (out_vlan_id >= lsai_device::MAX_VLANS) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (out_vlan_id == lsai_device::DEFAULT_VLAN_ID) {
        *vlan_id = sdev->m_default_vlan_id;
        sai_log_info(SAI_API_VLAN, "default vlan 0x%lx returned", *vlan_id);
        return SAI_STATUS_SUCCESS;
    }

    // check if the vlan object has already been created
    lsai_vlan_t lsaivlan;
    la_status status = sdev->m_vlans.get_by_id(out_vlan_id, lsaivlan);
    if (status == LA_STATUS_SUCCESS) {
        *vlan_id = lsaivlan.m_oid;
        sai_log_info(SAI_API_VLAN, "vlan 0x%lx existed", *vlan_id);
        return SAI_STATUS_SUCCESS;
    }

    transaction txn{};

    uint32_t vlan_index = 0;
    txn.status = sdev->m_vlans.allocate_id(out_vlan_id, vlan_index);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_vlans.release_id(vlan_index); });

    la_switch* bridge = nullptr;
    txn.status = create_la_bridge(bridge, sdev, vlan_index, txn);
    sai_return_on_la_error(txn.status);

    lsaivlan.m_sdk_switch = bridge;

    lsai_object la_vlan(SAI_OBJECT_TYPE_VLAN, la_obj.switch_id, vlan_index);
    *vlan_id = la_vlan.object_id();
    lsaivlan.m_oid = *vlan_id;
    txn.status = sdev->m_vlans.set(*vlan_id, lsaivlan);
    sai_return_on_la_error(txn.status);

    sai_log_info(SAI_API_VLAN, "vlan 0x%lx created", *vlan_id);

    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];
    key.key.object_id = *vlan_id;
    snprintf(key_str, MAX_KEY_STR_LEN, "vlan 0x%0lx", *vlan_id);

    // loop for create_and_set attributes
    for (uint32_t i = 0; i < attr_count; i++) {
        // skip attributes are  mandatory or create only
        // Also, skip attribute that have been taken care by above creation process.

        switch (attr_list[i].id) {
        case SAI_VLAN_ATTR_VLAN_ID:
            continue;
        default:
            sai_create_and_set_attribute(&key, key_str, vlan_attribs, vlan_vendor_attribs, &attr_list[i]);
            break;
        }
    }

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Remove VLAN
 *
 * @param[in] vlan_id VLAN member ID
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t
remove_vlan(_In_ sai_object_id_t vlan_id)
{
    sai_start_api(SAI_API_VLAN, SAI_OBJECT_TYPE_VLAN, vlan_id, &vlan_to_string, vlan_id);

    lsai_vlan_t* lsaivlan = sdev->m_vlans.get_ptr(la_obj.index);
    if (lsaivlan == nullptr) {
        sai_log_info(SAI_API_VLAN, "vlan 0x%lx does not exist", vlan_id);
        return SAI_STATUS_SUCCESS;
    }

    if (lsaivlan->m_sdk_switch != nullptr) {
        if (lsaivlan->m_sdk_switch != sdev->m_default_bridge) {
            la_l2_destination* flood_destination = nullptr;
            lsaivlan->m_sdk_switch->get_flood_destination(flood_destination);
            if (flood_destination) {
                la_status status = lsaivlan->m_sdk_switch->set_flood_destination(nullptr);
                sai_return_on_la_error(status, "Failed to clear flood group for vlan, %s", status.message().c_str());

                status = sdev->m_dev->destroy(flood_destination);
                sai_return_on_la_error(status, "Failed to delete flood destination, %s", status.message().c_str());
            }
            la_status status = sdev->destroy_cpu_l2_port(la_obj.index);
            sai_return_on_la_error(status, "Failed to delete cpu l2 port, %s", status.message().c_str());

            status = sdev->m_dev->destroy(lsaivlan->m_sdk_switch);
            sai_return_on_la_error(status, "Failed to delete bridge, %s", status.message().c_str());
        } else {
            // default bridge is deleted by sai_bridge .1Q
            sai_log_info(SAI_API_VLAN, "can not remove default vlan 0x%lx", vlan_id);
        }
    }

    sdev->m_vlans.remove(la_obj.index);

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Set VLAN Attribute
 *
 * @param[in] vlan_id VLAN ID
 * @param[in] attr Attribute structure containing ID and value
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t
set_vlan_attribute(_In_ sai_object_id_t vlan_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = vlan_id;

    sai_start_api(SAI_API_VLAN, SAI_OBJECT_TYPE_VLAN, vlan_id, &vlan_to_string, vlan_id, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "vlan member 0x%0lx", vlan_id);
    return sai_set_attribute(&key, key_str, vlan_attribs, vlan_vendor_attribs, attr);
}

/**
 * @brief Get VLAN Attribute
 *
 * @param[in] vlan_id VLAN ID
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list List of attribute structures containing ID and value
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t
get_vlan_attribute(_In_ sai_object_id_t vlan_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = vlan_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_VLAN, SAI_OBJECT_TYPE_VLAN, vlan_id, &vlan_to_string, vlan_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "vlan member 0x%0lx", vlan_id);
    return sai_get_attributes(&key, key_str, vlan_attribs, vlan_vendor_attribs, attr_count, attr_list);
}

/**
 * @brief Create VLAN Member
 *
 * @param[out] vlan_member_id VLAN member ID
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t
create_vlan_member(_Out_ sai_object_id_t* vlan_member_id,
                   _In_ sai_object_id_t switch_id,
                   _In_ uint32_t attr_count,
                   _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_VLAN, SAI_OBJECT_TYPE_SWITCH, switch_id, &vlan_member_to_string, attrs);

    // get vlan id, if vlan already defined, then the bridge is not nullptr
    bridge_port_entry vlan_mem_entry{};
    sai_object_id_t vlan_obj = 0;
    get_attrs_value(SAI_VLAN_MEMBER_ATTR_VLAN_ID, attrs, vlan_obj, true);

    lsai_object la_vlan(vlan_obj);
    if (la_vlan.type != SAI_OBJECT_TYPE_VLAN) {
        sai_log_error(SAI_API_VLAN, "Bad switch id %lu", vlan_obj);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    vlan_mem_entry.bridge_obj = vlan_obj;
    vlan_mem_entry.vlan_id = sdev->m_vlans.get_id(vlan_obj);

    // get the bridge port id
    sai_object_id_t bridge_port_obj = 0;
    get_attrs_value(SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID, attrs, bridge_port_obj, true);
    lsai_object la_bport(bridge_port_obj);
    bridge_port_entry* bpentry = sdev->m_bridge_ports.get_ptr(la_bport.index);
    if (bpentry == nullptr || bpentry->l2_port == nullptr) {
        sai_log_error(SAI_API_VLAN, "bridge port does not exist 0x%lu", bridge_port_obj);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    vlan_mem_entry.port_obj = bpentry->port_obj;
    vlan_mem_entry.bridge_port_oid = bridge_port_obj;

    // bridge port type check
    uint32_t port_type = la_bport.detail.get(lsai_detail_type_e::BRIDGE_PORT, lsai_detail_field_e::TYPE);
    if (port_type != SAI_BRIDGE_PORT_TYPE_PORT) {
        sai_log_error(SAI_API_VLAN, "bridge port is not 1Q 0x%lu", bridge_port_obj);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_vlan_tagging_mode_t tag_mode = SAI_VLAN_TAGGING_MODE_UNTAGGED;
    get_attrs_value(SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE, attrs, tag_mode, false);
    vlan_mem_entry.is_tagged = (tag_mode == SAI_VLAN_TAGGING_MODE_UNTAGGED) ? false : true;

    // When entry.is_tagged = true, (SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE is set to SAI_VLAN_TAGGING_MODE_TAGGED)
    //    1) If this attribute is created, rewrite the out tag VLAN ID with this attribute value.
    //    2) If this attribute is not created, out tag VLAN will be equal to SAI_VLAN_MEMBER_ATTR_VLAN_ID
    // default: "out tag VLAN will be equal to SAI_VLAN_MEMBER_ATTR_VLAN_ID"
    sai_uint16_t egr_dot1q_vlan = vlan_mem_entry.vlan_id;
    get_attrs_value(SAI_VLAN_MEMBER_ATTR_EXT_EGR_DOT1Q_TAG_VLAN, attrs, egr_dot1q_vlan, false);
    vlan_mem_entry.egr_dot1q_vlan = egr_dot1q_vlan;

    vlan_mem_entry.learn_mode = bpentry->learn_mode;

    transaction txn{};

    lsai_object la_vlan_mem(SAI_OBJECT_TYPE_VLAN_MEMBER, la_obj.index, 0);

    // bridge_port should contains the following
    //    - vlan_id for .1d bridge port
    //    - bridge_port_oid is bridge port obj for vlan member
    //    - vlan_member_oid is the object id for vlan memeber
    //    - bridge_obj for bridge port or vlan obj for vlan member
    //    - port_obj ether port for bridge port and vlan member
    la_status status = la_create_l2_bridge_port(vlan_member_id, la_vlan_mem, vlan_mem_entry, txn, true);
    sai_return_on_la_error(status);
    sai_log_info(SAI_API_VLAN, "vlan member 0x%lx created", *vlan_member_id);

    // new l2 port created, check underlying port obj
    sai_status_t sstatus = lsai_bridge_port_update_services(sdev, *vlan_member_id, bpentry->port_obj);
    sai_return_on_error(sstatus);

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Remove VLAN Member "and back to vlan 1"
 *
 * @param[in] vlan_member_id VLAN member ID
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t
remove_vlan_member(_In_ sai_object_id_t vlan_member_id)
{
    sai_start_api(SAI_API_VLAN, SAI_OBJECT_TYPE_VLAN_MEMBER, vlan_member_id, &vlan_member_to_string, vlan_member_id);

    bridge_port_entry* entry = sdev->m_bridge_ports.get_ptr(la_obj.index);
    if (entry == nullptr) {
        sai_log_error(SAI_API_VLAN, "Can not get l2 service port 0x%lx", vlan_member_id);
        // already removed
        return SAI_STATUS_SUCCESS;
    }

    lsai_object la_bp(entry->bridge_port_oid);
    if (la_obj.index == la_bp.index) {
        entry->vlan_member_oid = SAI_NULL_OBJECT_ID;
        return SAI_STATUS_SUCCESS;
    }

    la_status status = la_remove_bridge_port_or_vlan_member(sdev, vlan_member_id, entry);
    sai_return_on_la_error(status);

    return (SAI_STATUS_SUCCESS);
}

/**
 * @brief Set VLAN Member Attribute
 *
 * @param[in] vlan_member_id VLAN member ID
 * @param[in] attr Attribute structure containing ID and value
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t
set_vlan_member_attribute(_In_ sai_object_id_t vlan_member_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = vlan_member_id;

    sai_start_api(SAI_API_VLAN, SAI_OBJECT_TYPE_VLAN_MEMBER, vlan_member_id, &vlan_member_to_string, vlan_member_id, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "vlan member 0x%0lx", vlan_member_id);
    return sai_set_attribute(&key, key_str, vlan_member_attribs, vlan_member_vendor_attribs, attr);
}

/**
 * @brief Get VLAN Member Attribute
 *
 * @param[in] vlan_member_id VLAN member ID
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list List of attribute structures containing ID and value
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t
get_vlan_member_attribute(_In_ sai_object_id_t vlan_member_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = vlan_member_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_VLAN, SAI_OBJECT_TYPE_VLAN_MEMBER, vlan_member_id, &vlan_member_to_string, vlan_member_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "vlan member 0x%0lx", vlan_member_id);
    return sai_get_attributes(&key, key_str, vlan_member_attribs, vlan_member_vendor_attribs, attr_count, attr_list);
}

/**
 * @brief Get vlan statistics counters. Deprecated for backward compatibility.
 *
 * @param[in] vlan_id VLAN id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[out] counters Array of resulting counter values.
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t
get_vlan_stats(_In_ sai_object_id_t vlan_id,
               _In_ uint32_t number_of_counters,
               _In_ const sai_stat_id_t* counter_ids,
               _Out_ uint64_t* counters)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Get vlan statistics counters extended.
 *
 * @param[in] vlan_id VLAN id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[in] mode Statistics mode
 * @param[out] counters Array of resulting counter values.
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t
get_vlan_stats_ext(_In_ sai_object_id_t vlan_id,
                   _In_ uint32_t number_of_counters,
                   _In_ const sai_stat_id_t* counter_ids,
                   _In_ sai_stats_mode_t mode,
                   _Out_ uint64_t* counters)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Clear vlan statistics counters.
 *
 * @param[in] vlan_id Vlan id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
static sai_status_t
clear_vlan_stats(_In_ sai_object_id_t vlan_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t* counter_ids)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
create_vlan_members(_In_ sai_object_id_t switch_id,
                    _In_ uint32_t object_count,
                    _In_ const uint32_t* attr_count,
                    _In_ const sai_attribute_t** attr_list,
                    _In_ sai_bulk_op_error_mode_t mode,
                    _Out_ sai_object_id_t* object_id,
                    _Out_ sai_status_t* object_statuses)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
remove_vlan_members(_In_ uint32_t object_count,
                    _In_ const sai_object_id_t* object_id,
                    _In_ sai_bulk_op_error_mode_t mode,
                    _Out_ sai_status_t* object_statuses)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief VLAN methods table retrieved with sai_api_query()
 */
const sai_vlan_api_t vlan_api = {
    create_vlan,
    remove_vlan,
    set_vlan_attribute,
    get_vlan_attribute,
    create_vlan_member,
    remove_vlan_member,
    set_vlan_member_attribute,
    get_vlan_member_attribute,
    create_vlan_members,
    remove_vlan_members,
    get_vlan_stats,
    get_vlan_stats_ext,
    clear_vlan_stats,
};
}
}
