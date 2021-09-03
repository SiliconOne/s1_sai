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

#include "api/npu/la_l2_service_port.h"
#include "api/npu/la_l3_ac_port.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_svi_port.h"
#include "api/npu/la_switch.h"
#include "api/system/la_device.h"
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

// we want to count per l3 protocol
static const uint8_t PORT_COUNTER_SIZE = (int)la_l3_protocol_counter_e::LAST;

static sai_status_t sai_rif_attrib_get(_In_ const sai_object_key_t* key,
                                       _Inout_ sai_attribute_value_t* value,
                                       _In_ uint32_t attr_index,
                                       _Inout_ vendor_cache_t* cache,
                                       void* arg);
static sai_status_t sai_rif_admin_get(_In_ const sai_object_key_t* key,
                                      _Inout_ sai_attribute_value_t* value,
                                      _In_ uint32_t attr_index,
                                      _Inout_ vendor_cache_t* cache,
                                      void* arg);
static sai_status_t sai_rif_acl_get(_In_ const sai_object_key_t* key,
                                    _Inout_ sai_attribute_value_t* value,
                                    _In_ uint32_t attr_index,
                                    _Inout_ vendor_cache_t* cache,
                                    void* arg);
static sai_status_t sai_rif_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
static sai_status_t sai_rif_admin_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
static sai_status_t sai_rif_ingress_acl_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
static sai_status_t sai_rif_egress_acl_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

// clang-format off
extern const sai_attribute_entry_t rif_attribs[] = {
    // id; mandatory_on_create; valid_for_create; valid_for_set; valid_for_get;
    {SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID, true, true, false, true, "Router interface virtual router ID", SAI_ATTR_VAL_TYPE_OID},
    {SAI_ROUTER_INTERFACE_ATTR_TYPE, true, true, false, true, "Router interface type", SAI_ATTR_VAL_TYPE_S32},
    {SAI_ROUTER_INTERFACE_ATTR_PORT_ID, false, true, false, true, "Router interface port ID", SAI_ATTR_VAL_TYPE_OID},
    {SAI_ROUTER_INTERFACE_ATTR_VLAN_ID, false, true, false, true, "Router interface vlan ID", SAI_ATTR_VAL_TYPE_OID},
    {SAI_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID, false, true, false, true, "Router interface outer vlan ID", SAI_ATTR_VAL_TYPE_S16},
    {SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS, false, true, true, true, "Router interface source MAC address", SAI_ATTR_VAL_TYPE_MAC},
    {SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE, false, true, true, true, "Router interface admin v4 state", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE, false, true, true, true, "Router interface admin v6 state", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ROUTER_INTERFACE_ATTR_MTU, false, true, true, true, "Router interface mtu", SAI_ATTR_VAL_TYPE_U32},
    {SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL, false, true, true, true, "Router Interface bind point for ingress ACL object", SAI_ATTR_VAL_TYPE_OID},
    {SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL, false, true, true, true, "Router Interface bind point for Egress ACL object", SAI_ATTR_VAL_TYPE_OID},
    {SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE, false, true, true, true, "Router interface enable v4 multicast", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE, false, true, true, true, "Router interface enable v6 multicast", SAI_ATTR_VAL_TYPE_BOOL},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t rif_vendor_attribs[] = {
    {SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID,
     {true, false, false, true},
     {true, false, false, true},
     sai_rif_attrib_get, (int*)SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID, nullptr, nullptr},

    {SAI_ROUTER_INTERFACE_ATTR_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     sai_rif_attrib_get, (int*)SAI_ROUTER_INTERFACE_ATTR_TYPE, nullptr, nullptr},

    {SAI_ROUTER_INTERFACE_ATTR_PORT_ID,
     {true, false, false, true},
     {true, false, false, true},
     sai_rif_attrib_get, (int*)SAI_ROUTER_INTERFACE_ATTR_PORT_ID, nullptr, nullptr},

    {SAI_ROUTER_INTERFACE_ATTR_VLAN_ID,
     {true, false, false, true},
     {true, false, false, true},
     sai_rif_attrib_get, (int*)SAI_ROUTER_INTERFACE_ATTR_VLAN_ID, nullptr, nullptr},

    {SAI_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID,
     {true, false, false, true},
     {true, false, false, true},
     sai_rif_attrib_get, (int*)SAI_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID, nullptr, nullptr},

    {SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS,
     {true, false, true, true},
     {true, false, true, true},
     sai_rif_attrib_get, (int*)SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS, sai_rif_attrib_set, (int*)SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS},

    {SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE,
     {true, false, true, true},
     {true, false, true, true},
     sai_rif_admin_get, (int*)SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE, sai_rif_admin_set, (int*)SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE},

    {SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE,
     {true, false, true, true},
     {true, false, true, true},
     sai_rif_admin_get, (int*)SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE, sai_rif_admin_set, (int*)SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE},

    {SAI_ROUTER_INTERFACE_ATTR_MTU,
     {true, false, true, true},
     {true, false, true, true},
     sai_rif_attrib_get, (int*)SAI_ROUTER_INTERFACE_ATTR_MTU, sai_rif_attrib_set, (int*)SAI_ROUTER_INTERFACE_ATTR_MTU},

    {SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL,
     {false, false, true, true},
     {false, false, true, true},
     sai_rif_acl_get,
     (void*)SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL,
     sai_rif_ingress_acl_set,
     nullptr},
    {SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL,
     {false, false, true, true},
     {false, false, true, true},
     sai_rif_acl_get,
     (void*)SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL,
     sai_rif_egress_acl_set,
     nullptr},
    {SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE,
     {true, false, true, true},
     {true, false, true, true},
     sai_rif_admin_get, (int*)SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE, sai_rif_admin_set, (int*)SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE},

    {SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE,
     {true, false, true, true},
     {true, false, true, true},
     sai_rif_admin_get, (int*)SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE, sai_rif_admin_set, (int*)SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE},
};
// clang-format on

static sai_status_t
sai_rif_admin_get(_In_ const sai_object_key_t* key,
                  _Inout_ sai_attribute_value_t* value,
                  _In_ uint32_t attr_index,
                  _Inout_ vendor_cache_t* cache,
                  void* arg)
{
    la_status status;

    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_rif(key->key.object_id);
    auto sdev = la_rif.get_device();
    sai_check_object(la_rif, SAI_OBJECT_TYPE_ROUTER_INTERFACE, sdev, "router interface", key->key.object_id);

    rif_entry entry{};
    status = sdev->m_l3_ports.get(la_rif.index, entry);
    sai_return_on_la_error(status);
    if (entry.l3_port == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    bool enb = false;
    switch ((int64_t)arg) {
    case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE:
        set_attr_value(SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE, (*value), entry.m_admin_v4_state);
        break;

    case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE:
        set_attr_value(SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE, (*value), entry.m_admin_v6_state);
        break;

    case SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE:
        status = entry.l3_port->get_protocol_enabled(la_l3_protocol_e::IPV4_MC, enb);
        if (status == LA_STATUS_SUCCESS && enb) {
            set_attr_value(SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE, (*value), enb);
        }
        break;
    case SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE:
        status = entry.l3_port->get_protocol_enabled(la_l3_protocol_e::IPV6_MC, enb);
        if (status == LA_STATUS_SUCCESS && enb) {
            set_attr_value(SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE, (*value), enb);
        }
        break;
    default:
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
sai_rif_admin_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    la_status status;

    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_rif(key->key.object_id);
    auto sdev = la_rif.get_device();
    sai_check_object(la_rif, SAI_OBJECT_TYPE_ROUTER_INTERFACE, sdev, "router interface", key->key.object_id);

    rif_entry* entry = nullptr;
    status = sdev->m_l3_ports.get_ptr(la_rif.index, entry);
    sai_return_on_la_error(status, "Failed finding router interface 0x%lx", key->key.object_id);

    vrf_entry* my_vrf = nullptr;
    lsai_object vrf_obj(entry->vrf_obj);
    status = sdev->m_vrfs.get_ptr(vrf_obj.index, my_vrf);
    sai_return_on_la_error(status, "Invalid virtual router object id 0x%lx in router interface", entry->vrf_obj);

    switch ((int64_t)arg) {
    case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE: {
        auto enb = get_attr_value(SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE, (*value));
        entry->m_admin_v4_state = enb;
        // Only if vrf admin state is up, rif state has influence
        if (my_vrf->m_admin_v4_state) {
            status = entry->l3_port->set_protocol_enabled(la_l3_protocol_e::IPV4_UC, enb);
        }
        break;
    }
    case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE: {
        auto enb = get_attr_value(SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE, (*value));
        entry->m_admin_v6_state = enb;
        // Only if vrf admin state is up, rif state has influence
        if (my_vrf->m_admin_v4_state) {
            status = entry->l3_port->set_protocol_enabled(la_l3_protocol_e::IPV6_UC, enb);
        }

        break;
    }
    case SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE: {
        auto enb = get_attr_value(SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE, (*value));
        status = entry->l3_port->set_protocol_enabled(la_l3_protocol_e::IPV4_MC, enb);
        break;
    }
    case SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE: {
        auto enb = get_attr_value(SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE, (*value));
        status = entry->l3_port->set_protocol_enabled(la_l3_protocol_e::IPV6_MC, enb);
        break;
    }
    default:
        return SAI_STATUS_FAILURE;
    }

    return to_sai_status(status);
}

static sai_status_t
sai_rif_ingress_acl_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_rif(key->key.object_id);
    auto sdev = la_rif.get_device();

    if (la_rif.type != SAI_OBJECT_TYPE_ROUTER_INTERFACE || sdev == nullptr || sdev->m_dev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto acl_obj_id = get_attr_value(SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL, *value);
    rif_entry* rif_entry = sdev->m_l3_ports.get_ptr(la_rif.index);
    if (rif_entry == nullptr) {
        sai_log_error(SAI_API_LAG, "RIF oid 0x%llx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    sai_status_t sstatus = sdev->m_acl_handler->attach_acl_on_rif(acl_obj_id, SAI_ACL_STAGE_INGRESS, rif_entry);
    sai_return_on_error(sstatus);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
sai_rif_egress_acl_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_rif(key->key.object_id);
    auto sdev = la_rif.get_device();

    if (la_rif.type != SAI_OBJECT_TYPE_ROUTER_INTERFACE || sdev == nullptr || sdev->m_dev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto acl_obj_id = get_attr_value(SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL, *value);
    rif_entry* rif_entry = sdev->m_l3_ports.get_ptr(la_rif.index);
    if (rif_entry == nullptr) {
        sai_log_error(SAI_API_LAG, "RIF oid 0x%llx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    sai_status_t sstatus = sdev->m_acl_handler->attach_acl_on_rif(acl_obj_id, SAI_ACL_STAGE_EGRESS, rif_entry);
    sai_return_on_error(sstatus);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
sai_rif_acl_get(_In_ const sai_object_key_t* key,
                _Inout_ sai_attribute_value_t* value,
                _In_ uint32_t attr_index,
                _Inout_ vendor_cache_t* cache,
                void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_rif(key->key.object_id);
    auto sdev = la_rif.get_device();
    sai_check_object(la_rif, SAI_OBJECT_TYPE_ROUTER_INTERFACE, sdev, "router interface", key->key.object_id);

    rif_entry entry{};
    sai_return_on_la_error_no_log(sdev->m_l3_ports.get(la_rif.index, entry));

    switch ((uint64_t)arg) {
    case SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL:
        value->oid = entry.ingress_acl;
        break;
    case SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL:
        value->oid = entry.egress_acl;
        break;
    default:
        return SAI_STATUS_NOT_SUPPORTED;
    }

    return SAI_STATUS_SUCCESS;
}

static void
rif_key_to_str(_In_ sai_object_id_t rif_id, _Out_ char* key_str)
{
    lsai_object la_rif(rif_id);
    auto sdev = la_rif.get_device();
    if (la_rif.type != SAI_OBJECT_TYPE_ROUTER_INTERFACE || sdev == nullptr || sdev->m_dev == nullptr) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid rif");
    } else {
        snprintf(key_str, MAX_KEY_STR_LEN, "rif 0x%0x", la_rif.index);
    }
}

la_status
la_add_prefix_to_router_interface(vrf_entry& vrf_entry, sai_object_id_t obj_rif_id, la_ipv4_prefix_t& ipv4_prefix)
{
    lsai_object la_rif(obj_rif_id);
    auto sdev = la_rif.get_device();
    la_check_object(la_rif, SAI_OBJECT_TYPE_ROUTER_INTERFACE, sdev, "router interface", obj_rif_id);

    rif_entry entry{};
    la_status status = sdev->m_l3_ports.get(la_rif.index, entry);
    la_return_on_error(status, "Fail to get router interface for route, 0x%lx", obj_rif_id);

    if (entry.l3_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
        la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
        status = l3ac->add_ipv4_subnet(ipv4_prefix);
    } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
        la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
        status = sviport->add_ipv4_subnet(ipv4_prefix);
    }
    la_return_on_error(status, "Failed to add subnet to router port, %s", status.message().c_str());
    vrf_entry.m_v4_local_subnets[ipv4_prefix] = obj_rif_id;
    sdev->m_vrfs.set(vrf_entry.vrf->get_gid(), vrf_entry);

    return LA_STATUS_SUCCESS;
}

la_status
la_add_v6prefix_to_router_interface(vrf_entry& vrf_entry, sai_object_id_t obj_rif_id, la_ipv6_prefix_t& ipv6_prefix)
{
    lsai_object la_rif(obj_rif_id);
    auto sdev = la_rif.get_device();
    la_check_object(la_rif, SAI_OBJECT_TYPE_ROUTER_INTERFACE, sdev, "router interface", obj_rif_id);

    rif_entry entry{};
    la_status status = sdev->m_l3_ports.get(la_rif.index, entry);
    la_return_on_error(status, "Fail to get router interface for route, 0x%lx", obj_rif_id);

    if (entry.l3_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
        la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
        status = l3ac->add_ipv6_subnet(ipv6_prefix);
    } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
        la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
        status = sviport->add_ipv6_subnet(ipv6_prefix);
    }
    if (status) {
        sai_log_error(SAI_API_ROUTER_INTERFACE, "Failed to add subnet to router port, %s", status.message().c_str());
        return status;
    }
    vrf_entry.m_v6_local_subnets[ipv6_prefix] = obj_rif_id;
    sdev->m_vrfs.set(vrf_entry.vrf->get_gid(), vrf_entry);

    return LA_STATUS_SUCCESS;
}

la_status
la_remove_prefix_from_router_interface(vrf_entry& vrf_entry, la_ipv4_prefix_t& ipv4_prefix)
{
    auto it = vrf_entry.m_v4_local_subnets.find(ipv4_prefix);
    if (it == vrf_entry.m_v4_local_subnets.end()) {
        // already removed
        return LA_STATUS_SUCCESS;
    }

    lsai_object la_rif(it->second);
    auto sdev = la_rif.get_device();
    la_check_object(la_rif, SAI_OBJECT_TYPE_ROUTER_INTERFACE, sdev, "router interface", it->second);

    rif_entry entry{};
    la_status status = sdev->m_l3_ports.get(la_rif.index, entry);
    la_return_on_error(status, "Fail to get router interface for route, 0x%lx", it->second);

    // ??
    if (entry.l3_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
        la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
        status = l3ac->delete_ipv4_subnet(ipv4_prefix);
    } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
        la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
        status = sviport->delete_ipv4_subnet(ipv4_prefix);
    }
    la_return_on_error(status, "Failed to remove subnet to router port, %s", status.message().c_str());
    vrf_entry.m_v4_local_subnets.erase(it);
    sdev->m_vrfs.set(vrf_entry.vrf->get_gid(), vrf_entry);

    return LA_STATUS_SUCCESS;
}

la_status
la_remove_v6prefix_from_router_interface(vrf_entry& vrf_entry, la_ipv6_prefix_t& ipv6_prefix)
{
    auto it = vrf_entry.m_v6_local_subnets.find(ipv6_prefix);
    if (it == vrf_entry.m_v6_local_subnets.end()) {
        // already removed
        return LA_STATUS_SUCCESS;
    }

    lsai_object la_rif(it->second);
    auto sdev = la_rif.get_device();
    la_check_object(la_rif, SAI_OBJECT_TYPE_ROUTER_INTERFACE, sdev, "router interface", it->second);

    rif_entry entry{};
    la_status status = sdev->m_l3_ports.get(la_rif.index, entry);
    la_return_on_error(status, "Fail to get router interface for route, 0x%lx", it->second);

    if (entry.l3_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
        la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
        status = l3ac->delete_ipv6_subnet(ipv6_prefix);
    } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
        la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
        status = sviport->delete_ipv6_subnet(ipv6_prefix);
    }
    if (status) {
        sai_log_error(SAI_API_ROUTER_INTERFACE, "Failed to remove subnet to router port, %s", status.message().c_str());
        return status;
    }
    vrf_entry.m_v6_local_subnets.erase(it);
    sdev->m_vrfs.set(vrf_entry.vrf->get_gid(), vrf_entry);

    return LA_STATUS_SUCCESS;
}

static la_status
create_recycle_inject_up_port(std::shared_ptr<lsai_device>& sdev,
                              la_svi_port* svi_port,
                              la_switch* bridge,
                              uint16_t vlan_id,
                              transaction& txn)
{
    uint32_t bpindex = 0;
    la_l2_service_port* l2_port = nullptr;

    txn.status = sdev->m_bridge_ports.allocate_id(bpindex);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { sdev->m_bridge_ports.release_id(bpindex); });

    txn.status = sdev->m_dev->create_ac_l2_service_port(bpindex,
                                                        sdev->m_recycle_injectup_eth_port,
                                                        vlan_id,
                                                        0xBE,
                                                        sdev->m_default_filter_group,
                                                        sdev->m_qos_handler->get_default_ingress_qos_profile(),
                                                        sdev->m_qos_handler->get_default_egress_qos_profile(),
                                                        l2_port);
    la_return_on_error(txn.status, "Failed to create svi egress flood port");
    txn.on_fail([=]() { sdev->m_dev->destroy(l2_port); });

    la_vlan_edit_command ingress_edit_cmd(2);
    txn.status = l2_port->set_ingress_vlan_edit_command(ingress_edit_cmd);
    la_return_on_error(txn.status, "Fail to set ingress edit command");

    txn.status = l2_port->attach_to_switch(bridge);
    la_return_on_error(txn.status, "Failed to attach svi egress flood port");
    txn.on_fail([=]() { l2_port->detach(); });

    txn.status = l2_port->set_stp_state(la_port_stp_state_e::FORWARDING);
    la_return_on_error(txn.status, "Failed set port stp state");

    txn.status = svi_port->set_inject_up_source_port(l2_port);

    return txn.status;
}

la_status
la_create_svi_port(uint32_t& svi_idx, la_switch* bridge, sai_object_id_t obj_rif_id, uint16_t vlan_id, transaction& txn)
{
    lsai_object la_rif(obj_rif_id);
    auto sdev = la_rif.get_device();
    if (la_rif.type != SAI_OBJECT_TYPE_ROUTER_INTERFACE || sdev == nullptr || sdev->m_dev == nullptr) {
        txn.status = LA_STATUS_EINVAL;
        sai_log_error(SAI_API_ROUTER_INTERFACE, "Fail to get rif object, 0x%lx", obj_rif_id);
        return txn.status;
    }

    rif_entry entry{};
    la_status status = sdev->m_l3_ports.get(la_rif.index, entry);
    svi_idx = la_rif.index;
    if (status == LA_STATUS_SUCCESS && entry.l3_port != nullptr) {
        txn.status = LA_STATUS_EEXIST;
        sai_log_error(SAI_API_ROUTER_INTERFACE, "svi already exists 0x%lx", obj_rif_id);
        return txn.status;
    }

    lsai_object la_vf{};
    vrf_entry vrf_entry{};
    txn.status = sdev->m_vrfs.get(entry.vrf_obj, vrf_entry, la_vf);
    la_return_on_error(txn.status, "Invalid vrf object id 0x%lx", entry.vrf_obj);

    // create svi
    la_svi_port* svi_port = nullptr;
    txn.status = sdev->m_dev->create_svi_port(la_rif.index,
                                              bridge,
                                              vrf_entry.vrf,
                                              entry.mac_addr,
                                              sdev->m_qos_handler->get_default_ingress_qos_profile(),
                                              sdev->m_qos_handler->get_default_egress_qos_profile(),
                                              svi_port);

    la_return_on_error(txn.status, "Failed to create svi port, %s", txn.status.message().c_str());
    entry.l3_port = svi_port;
    txn.on_fail([=]() { sdev->m_dev->destroy(svi_port); });

    if (vlan_id != 0) {
        // create recycle injectup_ac_port for egress flooding
        txn.status = create_recycle_inject_up_port(sdev, svi_port, bridge, vlan_id, txn);
        la_return_on_error(txn.status);
    }

    txn.status = svi_port->set_protocol_enabled(la_l3_protocol_e::IPV4_UC, vrf_entry.m_admin_v4_state);
    la_return_on_error(txn.status);

    txn.status = svi_port->set_protocol_enabled(la_l3_protocol_e::IPV6_UC, vrf_entry.m_admin_v6_state);
    la_return_on_error(txn.status);

    txn.status = svi_port->set_protocol_enabled(la_l3_protocol_e::MPLS, true);
    la_return_on_error(txn.status);

    txn.status = svi_port->set_ecn_remark_enabled(true);
    la_return_on_error(txn.status);

    txn.status = svi_port->set_ecn_counting_enabled(true);
    la_return_on_error(txn.status);

    la_counter_set* ingress_counter_set = nullptr;
    txn.status = sdev->m_dev->create_counter(PORT_COUNTER_SIZE, ingress_counter_set);
    la_return_on_error(txn.status, "Failed to create ingress counter set for router port, rc %s", txn.status.message().c_str());
    txn.on_fail([=]() { sdev->m_dev->destroy(ingress_counter_set); });

    txn.status = svi_port->set_ingress_counter(la_counter_set::type_e::PORT, ingress_counter_set);
    la_return_on_error(txn.status, "Failed to set ingress counter set for router port, rc %s", txn.status.message().c_str());

    la_counter_set* egress_counter_set = nullptr;
    txn.status = sdev->m_dev->create_counter(PORT_COUNTER_SIZE, egress_counter_set);
    la_return_on_error(txn.status, "Failed to create egress counter set for router port, %s", txn.status.message().c_str());
    txn.on_fail([=]() { sdev->m_dev->destroy(egress_counter_set); });

    txn.status = svi_port->set_egress_counter(la_counter_set::type_e::PORT, egress_counter_set);
    la_return_on_error(txn.status, "Failed to set egress counter set for router port, %s", txn.status.message().c_str());

    la_counter_set* egress_qos_counter_set = nullptr;
    txn.status = sdev->m_dev->create_counter(NUM_QUEUE_PER_PORT, egress_qos_counter_set);
    la_return_on_error(txn.status, "Failed to create egress counter set for router port, %s", txn.status.message().c_str());
    txn.on_fail([=]() { sdev->m_dev->destroy(egress_qos_counter_set); });

    txn.status = svi_port->set_egress_counter(la_counter_set::type_e::QOS, egress_qos_counter_set);
    la_return_on_error(txn.status, "Failed to set egress qos counter set for router port, %s", txn.status.message().c_str());

    sdev->m_l3_ports.set(obj_rif_id, entry, la_rif);

    return txn.status;
}

static la_status
create_l3_ac_port(std::shared_ptr<lsai_device> sdev, lsai_object& la_rif, rif_entry& my_rif_entry)
{
    lsai_object la_vf{};
    vrf_entry vrf_entry{};
    la_status status = sdev->m_vrfs.get(my_rif_entry.vrf_obj, vrf_entry, la_vf);
    la_return_on_error(status, "Invalid vrf object id 0x%lx", my_rif_entry.vrf_obj);

    transaction txn;

    uint32_t router_port_id;
    txn.status = sdev->m_l3_ports.allocate_id(router_port_id);
    la_return_on_error(txn.status, "Can not allocate router port id ether port 0x%lx", my_rif_entry.port_obj);
    la_rif.index = router_port_id;
    txn.on_fail([=]() { sdev->m_l3_ports.release_id(router_port_id); });

    la_ethernet_port* eth_port = nullptr;
    txn.status = sai_port_get_ethernet_port(sdev, my_rif_entry.port_obj, eth_port);
    la_return_on_error(txn.status);

    eth_port->set_ac_profile(sdev->m_default_ac_profile);

    lsai_object la_port(my_rif_entry.port_obj);
    port_entry* pentry = sdev->m_ports.get_ptr(la_port.index);
    la_l3_ac_port* l3_ac_port = nullptr;
    txn.status = sdev->m_dev->create_l3_ac_port(router_port_id,
                                                eth_port,
                                                my_rif_entry.outer_vlan_id,
                                                0,
                                                my_rif_entry.mac_addr,
                                                vrf_entry.vrf,
                                                sdev->get_ingress_qos_profile(pentry),
                                                sdev->m_qos_handler->get_default_egress_qos_profile(),
                                                l3_ac_port);
    la_return_on_error(txn.status, "Failed to create L3 ac port, %s", txn.status.message().c_str());
    txn.on_fail([=]() { sdev->m_dev->destroy(l3_ac_port); });

    my_rif_entry.l3_port = l3_ac_port;
    sdev->m_l3_ports.set(la_rif.index, my_rif_entry);

    txn.status = l3_ac_port->set_protocol_enabled(la_l3_protocol_e::IPV4_UC, vrf_entry.m_admin_v4_state);
    la_return_on_error(txn.status);

    txn.status = l3_ac_port->set_protocol_enabled(la_l3_protocol_e::IPV6_UC, vrf_entry.m_admin_v6_state);
    la_return_on_error(txn.status);

    txn.status = l3_ac_port->set_protocol_enabled(la_l3_protocol_e::MPLS, true);
    la_return_on_error(txn.status);

    txn.status = l3_ac_port->set_ecn_remark_enabled(true);
    la_return_on_error(txn.status);

    txn.status = l3_ac_port->set_ecn_counting_enabled(true);
    la_return_on_error(txn.status);

    la_counter_set* ingress_counter_set = nullptr;
    txn.status = sdev->m_dev->create_counter(PORT_COUNTER_SIZE, ingress_counter_set);
    la_return_on_error(txn.status, "Failed to create ingress counter set for router port, rc %s", txn.status.message().c_str());
    txn.on_fail([=]() { sdev->m_dev->destroy(ingress_counter_set); });

    txn.status = l3_ac_port->set_ingress_counter(la_counter_set::type_e::PORT, ingress_counter_set);
    la_return_on_error(txn.status, "Failed to set ingress counter set for router port, rc %s", txn.status.message().c_str());

    la_counter_set* egress_counter_set = nullptr;
    txn.status = sdev->m_dev->create_counter(PORT_COUNTER_SIZE, egress_counter_set);
    la_return_on_error(txn.status, "Failed to create egress counter set for router port, %s", txn.status.message().c_str());
    txn.on_fail([=]() { sdev->m_dev->destroy(egress_counter_set); });

    txn.status = l3_ac_port->set_egress_counter(la_counter_set::type_e::PORT, egress_counter_set);
    la_return_on_error(txn.status, "Failed to set egress counter set for router port, %s", txn.status.message().c_str());

    la_counter_set* egress_qos_counter_set = nullptr;
    txn.status = sdev->m_dev->create_counter(NUM_QUEUE_PER_PORT, egress_qos_counter_set);
    la_return_on_error(txn.status, "Failed to create egress qos counter set for router port, %s", txn.status.message().c_str());
    txn.on_fail([=]() { sdev->m_dev->destroy(egress_qos_counter_set); });

    txn.status = l3_ac_port->set_egress_counter(la_counter_set::type_e::QOS, egress_qos_counter_set);
    la_return_on_error(txn.status, "Failed to set egress qos counter set for router port, %s", txn.status.message().c_str());

    if (my_rif_entry.outer_vlan_id != 0) {
        la_vlan_tag_t out_tag = {.tpid = 0x8100, .tci = {.fields = {.pcp = 0, .dei = 0, .vid = my_rif_entry.outer_vlan_id}}};
        txn.status = l3_ac_port->set_egress_vlan_tag(out_tag, LA_VLAN_TAG_UNTAGGED);
        eth_port->set_svi_egress_tag_mode(la_ethernet_port::svi_egress_tag_mode_e::KEEP);
    }

    return LA_STATUS_SUCCESS;
}

static std::string
rif_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_router_interface_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
create_router_interface(sai_object_id_t* router_interface_id,
                        sai_object_id_t obj_switch_id,
                        uint32_t attr_count,
                        const sai_attribute_t* attr_list)
{
    if (router_interface_id == nullptr) {
        sai_log_error(SAI_API_ROUTER_INTERFACE, "Bad router interface id pointer");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_ROUTER_INTERFACE, SAI_OBJECT_TYPE_SWITCH, obj_switch_id, &rif_to_string, attrs);

    // initialize lsai_object to collect information
    lsai_object la_rif(SAI_OBJECT_TYPE_ROUTER_INTERFACE, la_obj.index, 0);

    // interface type is recorded in rif lsai_object
    sai_router_interface_type_t intf_type{};
    {
        get_attrs_value(SAI_ROUTER_INTERFACE_ATTR_TYPE, attrs, intf_type, true);
    }

    // initialze rif_entry to collect construction parameter
    rif_entry my_rif_entry{};
    my_rif_entry.type = intf_type;

    // get vrf obj mandatory
    get_attrs_value(SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID, attrs, my_rif_entry.vrf_obj, true);
    lsai_object tmp_la_obj(my_rif_entry.vrf_obj);
    vrf_entry* vrf_entry = nullptr;
    la_status status = sdev->m_vrfs.get_ptr(tmp_la_obj.index, vrf_entry);
    sai_return_on_la_error(status, "Bad virtual router oid:%ld", my_rif_entry.vrf_obj);

    // get mac address
    get_mac_attrs_value(SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS, attrs, my_rif_entry.mac_addr.bytes, false);
    reverse(begin(my_rif_entry.mac_addr.bytes), end(my_rif_entry.mac_addr.bytes));
    if (my_rif_entry.mac_addr.flat == 0) {
        // use vrf mac if present
        la_mac_addr_t vrf_mac;
        reverse_copy(std::begin(vrf_entry->m_vrf_mac), std::end(vrf_entry->m_vrf_mac), vrf_mac.bytes);
        if (vrf_mac.flat != 0) {
            reverse_copy(std::begin(vrf_entry->m_vrf_mac), std::end(vrf_entry->m_vrf_mac), my_rif_entry.mac_addr.bytes);
        } else {
            // else use switch mac as default
            reverse_copy(std::begin(sdev->m_default_switch_mac), std::end(sdev->m_default_switch_mac), my_rif_entry.mac_addr.bytes);
        }
    }

    if (intf_type == SAI_ROUTER_INTERFACE_TYPE_PORT || intf_type == SAI_ROUTER_INTERFACE_TYPE_SUB_PORT) {
        get_attrs_value(SAI_ROUTER_INTERFACE_ATTR_PORT_ID, attrs, my_rif_entry.port_obj, true);
    }

    if (intf_type == SAI_ROUTER_INTERFACE_TYPE_VLAN) {
        get_attrs_value(SAI_ROUTER_INTERFACE_ATTR_VLAN_ID, attrs, my_rif_entry.bridge_obj, true);
    }

    if (intf_type == SAI_ROUTER_INTERFACE_TYPE_SUB_PORT) {
        get_attrs_value(SAI_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID, attrs, my_rif_entry.outer_vlan_id, true);
    }

    switch (intf_type) {
    case SAI_ROUTER_INTERFACE_TYPE_PORT: {
        lsai_object la_obj(my_rif_entry.port_obj);
        if (la_obj.type == SAI_OBJECT_TYPE_PORT) {
            port_entry* pentry = sdev->m_ports.get_ptr(la_obj.index);
            if (pentry == nullptr) {
                sai_log_error(SAI_API_ROUTER_INTERFACE, "Invalid port for router interface 0x%lx", my_rif_entry.port_obj);
                return SAI_STATUS_INVALID_PARAMETER;
            }
            if (pentry->service.untagged_bridge_port != SAI_NULL_OBJECT_ID) {
                do_remove_bridge_port(pentry->service.untagged_bridge_port);
                pentry->service.untagged_bridge_port = SAI_NULL_OBJECT_ID;
            }
        } else if (la_obj.type == SAI_OBJECT_TYPE_LAG) {
            lag_entry* lentry = sdev->m_lags.get_ptr(la_obj.index);
            if (lentry == nullptr) {
                sai_log_error(SAI_API_ROUTER_INTERFACE, "Invalid port for router interface 0x%lx", my_rif_entry.port_obj);
                return SAI_STATUS_INVALID_PARAMETER;
            }
            if (lentry->service.untagged_bridge_port != SAI_NULL_OBJECT_ID) {
                do_remove_bridge_port(lentry->service.untagged_bridge_port);
                lentry->service.untagged_bridge_port = SAI_NULL_OBJECT_ID;
            }
        }
    }
    // Should not have break here. Below directive is to make the compiler happy. Should not change this line.
    // fallthrough
    case SAI_ROUTER_INTERFACE_TYPE_SUB_PORT: {
        // la_rif is filled by create_l3_ac_port
        la_status status = create_l3_ac_port(sdev, la_rif, my_rif_entry);
        sai_return_on_la_error(status);

        lsai_object la_port(my_rif_entry.port_obj);
        if (IS_SAI_SERVICE_PORT(la_port)) {
            // Attach regular mirrors to rif if mirroring object is attached to underlying port
            sai_status_t sstatus = sdev->m_mirror_handler->attach_mirror_sessions(la_rif.object_id(), my_rif_entry.port_obj);
            sai_return_on_error(sstatus);

            // Attach sample mirror instance  to rif if packet sample that uses mirror object is attached to underlying port
            sstatus
                = sdev->m_mirror_handler->attach_sample_mirror_instance_to_logical_port(la_rif.object_id(), my_rif_entry.port_obj);
            sai_return_on_error(sstatus);
        }
        break;
    }

    case SAI_ROUTER_INTERFACE_TYPE_MPLS_ROUTER:
    case SAI_ROUTER_INTERFACE_TYPE_LOOPBACK:
    case SAI_ROUTER_INTERFACE_TYPE_BRIDGE:
    case SAI_ROUTER_INTERFACE_TYPE_VLAN: {
        transaction txn;
        // setting la_rif.index
        txn.status = sdev->m_l3_ports.insert(my_rif_entry, la_rif.index);
        sai_return_on_la_error(txn.status, "Out of L3 router bridge IDs");
        txn.on_fail([=]() { sdev->m_l3_ports.remove(la_rif.index); });

        if (intf_type == SAI_ROUTER_INTERFACE_TYPE_VLAN) {
            lsai_object la_vlan(my_rif_entry.bridge_obj);
            la_switch* bridge = sdev->m_dev->get_switch_by_id(la_vlan.index);
            if (bridge == nullptr) {
                txn.status = LA_STATUS_EINVAL;
                return to_sai_status(txn.status);
            }

            sai_uint16_t vlan_id = sdev->m_vlans.get_id(my_rif_entry.bridge_obj);

            uint32_t svi_port_id;
            txn.status = la_create_svi_port(svi_port_id, bridge, la_rif.object_id(), vlan_id, txn);
            sai_return_on_la_error(txn.status);
            sai_log_debug(SAI_API_ROUTER_INTERFACE, "router interface 0x%lx created", la_rif.object_id());
        }
        break;
    }

    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    if (sdev->m_l3_ports.get_ptr(la_rif.index) != nullptr
        && (intf_type == SAI_ROUTER_INTERFACE_TYPE_PORT || intf_type == SAI_ROUTER_INTERFACE_TYPE_SUB_PORT)) {
        // If there is ACL bound to switch/port, we need to propagate it to logical port created on it.
        // SDK does not support binding to physical port.
        sai_status_t sstatus = sdev->m_acl_handler->attach_acl_on_rif_create(sdev->m_l3_ports.get_ptr(la_rif.index));
        sai_return_on_error(sstatus);
    }

    *router_interface_id = la_rif.object_id();
    vrf_entry->m_router_interfaces.insert(*router_interface_id);
    sai_log_info(SAI_API_ROUTER_INTERFACE, "router interface 0x%lx created", la_rif.object_id());

    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];
    key.key.object_id = *router_interface_id;
    snprintf(key_str, MAX_KEY_STR_LEN, "router interface 0x%0lx", *router_interface_id);

    // loop for create_and_set attributes
    for (uint32_t i = 0; i < attr_count; i++) {
        switch (attr_list[i].id) {
        case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE:
        case SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE:
        case SAI_ROUTER_INTERFACE_ATTR_MTU:
        case SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL:
        case SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL:
        case SAI_ROUTER_INTERFACE_ATTR_V4_MCAST_ENABLE:
        case SAI_ROUTER_INTERFACE_ATTR_V6_MCAST_ENABLE:
            sai_create_and_set_attribute(&key, key_str, rif_attribs, rif_vendor_attribs, &attr_list[i]);
            break;
        default:
            break;
        }
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_router_interface(sai_object_id_t obj_rif_id)
{
    sai_start_api(SAI_API_ROUTER_INTERFACE, SAI_OBJECT_TYPE_ROUTER_INTERFACE, obj_rif_id, &rif_to_string, obj_rif_id);

    rif_entry entry;
    la_status status = sdev->m_l3_ports.get(la_obj.index, entry);
    sai_return_on_la_error(status, "Fail to get router interface for route, 0x%lx", obj_rif_id);

    if (entry.l3_port != nullptr) {
        if (entry.type == SAI_ROUTER_INTERFACE_TYPE_PORT) {
            lsai_object underlying_portobj(entry.port_obj);
            if (IS_SAI_SERVICE_PORT(underlying_portobj)) {
                // detach mirror sessions if present.
                sai_status_t sstatus = sdev->m_mirror_handler->detach_mirror_sessions(obj_rif_id, entry.port_obj);
                sai_return_on_error(sstatus);

                // Detach sample mirror instance from rif if packet sample that uses mirror object is attached to underlying port
                sstatus = sdev->m_mirror_handler->detach_sample_mirror_instance_from_logical_port(obj_rif_id, entry.port_obj);
                sai_return_on_error(sstatus);
            }

            la_ethernet_port* eth_port = nullptr;
            la_status status = sai_port_get_ethernet_port(sdev, entry.port_obj, eth_port);
            sai_return_on_la_error(status);
        } else if (entry.type == SAI_ROUTER_INTERFACE_TYPE_VLAN) {
            la_l3_port* l3_port = entry.l3_port;
            la_svi_port* svi_port = static_cast<la_svi_port*>(l3_port);
            la_l2_service_port* injectup_port = nullptr;

            svi_port->get_inject_up_source_port(injectup_port);
            if (injectup_port != nullptr) {
                injectup_port->detach();
                sdev->m_dev->destroy(injectup_port);
            }
        }
        la_counter_set* tmp_set;
        status = entry.l3_port->get_ingress_counter(la_counter_set::type_e::PORT, tmp_set);
        if (status == LA_STATUS_SUCCESS) {
            entry.l3_port->set_ingress_counter(la_counter_set::type_e::PORT, nullptr);
            sdev->m_dev->destroy(tmp_set);
        }

        status = entry.l3_port->get_egress_counter(la_counter_set::type_e::PORT, tmp_set);
        if (status == LA_STATUS_SUCCESS) {
            entry.l3_port->set_egress_counter(la_counter_set::type_e::PORT, nullptr);
            sdev->m_dev->destroy(tmp_set);
        }

        status = entry.l3_port->get_egress_counter(la_counter_set::type_e::QOS, tmp_set);
        if (status == LA_STATUS_SUCCESS) {
            entry.l3_port->set_egress_counter(la_counter_set::type_e::QOS, nullptr);
            sdev->m_dev->destroy(tmp_set);
        }

        sai_status_t sstatus = sdev->m_acl_handler->clear_acl_on_rif_removal(entry);
        sai_return_on_error(sstatus);

        status = sdev->m_dev->destroy(entry.l3_port);
        sai_return_on_la_error(status, "Failed to detroy the router port, %s", status.message().c_str());
    }

    status = sdev->m_l3_ports.remove(obj_rif_id);
    sai_return_on_la_error(status, "Failed removing l3 port associated with router interface %ld", obj_rif_id);

    if (entry.type == SAI_ROUTER_INTERFACE_TYPE_PORT) {
        // restore physical/lag port back to default untagged bridge port
        lsai_object la_obj(entry.port_obj);
        if (la_obj.type == SAI_OBJECT_TYPE_PORT) {
            port_entry* pentry = sdev->m_ports.get_ptr(la_obj.index);
            if (pentry == nullptr) {
                sai_log_error(SAI_API_ROUTER_INTERFACE, "Invalid port for router interface 0x%lx", entry.port_obj);
                return SAI_STATUS_INVALID_PARAMETER;
            }
            pentry->service.untagged_bridge_port = create_untagged_bridge_port(sdev, entry.port_obj);
        } else if (la_obj.type == SAI_OBJECT_TYPE_LAG) {
            lag_entry* lentry = sdev->m_lags.get_ptr(la_obj.index);
            if (lentry == nullptr) {
                sai_log_error(SAI_API_ROUTER_INTERFACE, "Invalid port for router interface 0x%lx", entry.port_obj);
                return SAI_STATUS_INVALID_PARAMETER;
            }
            lentry->service.untagged_bridge_port = create_untagged_bridge_port(sdev, entry.port_obj);
        }
    }

    lsai_object tmp_la_obj(entry.vrf_obj);
    vrf_entry* vrf_entry = nullptr;
    status = sdev->m_vrfs.get_ptr(tmp_la_obj.index, vrf_entry);
    sai_return_on_la_error(status, "Bad virtual router oid:%ld pointed by router interface %ld", entry.vrf_obj, obj_rif_id);
    vrf_entry->m_router_interfaces.erase(obj_rif_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_router_interface_attribute(sai_object_id_t router_interface_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = router_interface_id;

    sai_start_api(SAI_API_ROUTER_INTERFACE,
                  SAI_OBJECT_TYPE_ROUTER_INTERFACE,
                  router_interface_id,
                  &rif_to_string,
                  router_interface_id,
                  *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "rif 0x%0lx", router_interface_id);
    return sai_set_attribute(&key, key_str, rif_attribs, rif_vendor_attribs, attr);
}

static sai_status_t
get_router_interface_attribute(sai_object_id_t router_interface_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = router_interface_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_ROUTER_INTERFACE,
                  SAI_OBJECT_TYPE_ROUTER_INTERFACE,
                  router_interface_id,
                  &rif_to_string,
                  router_interface_id,
                  attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "rif 0x%0lx", router_interface_id);
    return sai_get_attributes(&key, key_str, rif_attribs, rif_vendor_attribs, attr_count, attr_list);
}

static la_status
sai_rif_set_svi_mtu(std::shared_ptr<lsai_device> sdev, la_svi_port* sviport, sai_uint32_t max_packet_size)
{
    const la_switch* bridge = nullptr;
    la_status status = sviport->get_switch(bridge);
    la_return_on_error(status);

    la_l2_destination* flood_destination = nullptr;
    status = bridge->get_flood_destination(flood_destination);
    la_return_on_error(status);

    if (flood_destination != nullptr) {
        la_l2_destination_vec_t flood_ports;
        auto* multicast_group = static_cast<la_l2_multicast_group*>(flood_destination);
        status = multicast_group->get_members(flood_ports);
        la_return_on_error(status);

        for (auto p : flood_ports) {
            auto l2_port = static_cast<const la_l2_service_port*>(p);
            auto gid = l2_port->get_gid();
            bridge_port_entry bport_entry{};
            status = sdev->m_bridge_ports.get(gid, bport_entry);
            la_return_on_error(status);

            la_ethernet_port* eth_port = nullptr;
            status = sai_port_get_ethernet_port(sdev, bport_entry.port_obj, eth_port);
            // set mtu to eth port only
            if (status == LA_STATUS_SUCCESS && eth_port != nullptr) {
                status = eth_port->set_mtu(max_packet_size);
                la_return_on_error(status);
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

static sai_status_t
sai_rif_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_rif(key->key.object_id);
    auto sdev = la_rif.get_device();
    sai_check_object(la_rif, SAI_OBJECT_TYPE_ROUTER_INTERFACE, sdev, "router interface", key->key.object_id);

    rif_entry* entry = sdev->m_l3_ports.get_ptr(la_rif.index);
    if (entry == nullptr) {
        sai_log_error(SAI_API_ROUTER_INTERFACE, "Invalid router interface 0x%lx", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch ((int64_t)arg) {
    case SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS: {
        la_mac_addr_t mac_addr;
        get_mac_attr_value(SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS, *value, mac_addr.bytes);
        reverse(std::begin(mac_addr.bytes), std::end(mac_addr.bytes));

        la_l3_ac_port* l3ac = nullptr;
        if (entry->l3_port != nullptr && entry->l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
            l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry->l3_port);
        } else {
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
        la_status status = l3ac->set_mac(mac_addr);
        sai_return_on_la_error(status);
        break;
    }

    case SAI_ROUTER_INTERFACE_ATTR_MTU: {
        sai_uint32_t max_packet_size = get_attr_value(SAI_ROUTER_INTERFACE_ATTR_MTU, (*value));
        if (entry->l3_port != nullptr && entry->l3_port->type() == la_object::object_type_e::L3_AC_PORT) {

            la_ethernet_port* eth_port = nullptr;

            la_status status = sai_port_get_ethernet_port(sdev, entry->port_obj, eth_port);
            sai_return_on_la_error(status);

            status = eth_port->set_mtu(max_packet_size);
            sai_return_on_la_error(status);
            entry->mtu = max_packet_size;
            break;
        } else if (entry->l3_port != nullptr && entry->l3_port->type() == la_object::object_type_e::SVI_PORT) {
            la_l3_port* l3_port = entry->l3_port;
            la_status status = sai_rif_set_svi_mtu(sdev, static_cast<la_svi_port*>(l3_port), max_packet_size);
            sai_return_on_la_error(status);
            entry->mtu = max_packet_size;
        } else {
            // dummy allow setting mtu for router interface on loopback port
            entry->mtu = max_packet_size;
        }
    }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
sai_rif_attrib_get(_In_ const sai_object_key_t* key,
                   _Inout_ sai_attribute_value_t* value,
                   _In_ uint32_t attr_index,
                   _Inout_ vendor_cache_t* cache,
                   void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_rif(key->key.object_id);
    auto sdev = la_rif.get_device();
    sai_check_object(la_rif, SAI_OBJECT_TYPE_ROUTER_INTERFACE, sdev, "router interface", key->key.object_id);

    rif_entry* rif_entry = nullptr;
    la_status status = sdev->m_l3_ports.get_ptr(la_rif.index, rif_entry);
    sai_return_on_la_error(status);

    switch ((int64_t)arg) {
    case SAI_ROUTER_INTERFACE_ATTR_PORT_ID: {
        set_attr_value(SAI_ROUTER_INTERFACE_ATTR_PORT_ID, *value, rif_entry->port_obj);
        return SAI_STATUS_SUCCESS;
    }
    case SAI_ROUTER_INTERFACE_ATTR_MTU: {
        set_attr_value(SAI_ROUTER_INTERFACE_ATTR_MTU, (*value), rif_entry->mtu);
        break;
    }
    case SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS: {
        if (rif_entry->l3_port == nullptr) {
            return SAI_STATUS_INVALID_PARAMETER;
        }

        la_mac_addr_t mac_addr;
        if (rif_entry->l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
            la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)rif_entry->l3_port);
            status = l3ac->get_mac(mac_addr);
            sai_return_on_la_error(status);
        } else if (rif_entry->l3_port->type() == la_object::object_type_e::SVI_PORT) {
            la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)rif_entry->l3_port);
            status = sviport->get_mac(mac_addr);
            sai_return_on_la_error(status);
        } else {
            return SAI_STATUS_INVALID_PARAMETER;
        }

        std::reverse(std::begin(mac_addr.bytes), std::end(mac_addr.bytes));
        set_mac_attr_value(SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS, *value, mac_addr.bytes);

        break;
    }
    case SAI_ROUTER_INTERFACE_ATTR_TYPE: {
        set_attr_value(SAI_ROUTER_INTERFACE_ATTR_TYPE, (*value), rif_entry->type);
        break;
    }
    case SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID: {
        set_attr_value(SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID, (*value), rif_entry->vrf_obj);
        break;
    }
    case SAI_ROUTER_INTERFACE_ATTR_VLAN_ID: {
        set_attr_value(SAI_ROUTER_INTERFACE_ATTR_VLAN_ID, (*value), rif_entry->bridge_obj);
        break;
    }
    case SAI_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID: {
        if (rif_entry->l3_port != nullptr && rif_entry->l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
            la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)rif_entry->l3_port);
            sai_uint16_t out_vid1, out_vid2;
            status = l3ac->get_service_mapping_vids(out_vid1, out_vid2);
            set_attr_value(SAI_ROUTER_INTERFACE_ATTR_OUTER_VLAN_ID, (*value), out_vid1);
        }
        break;
    }
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_router_interface_stats_ext(sai_object_id_t obj_router_interface_id,
                               uint32_t number_of_counters,
                               const sai_stat_id_t* counter_ids,
                               sai_stats_mode_t mode,
                               uint64_t* counters)
{

    lsai_object la_obj(obj_router_interface_id);
    auto sdev = la_obj.get_device();
    sai_start_api_counter(sdev);

    rif_entry entry{};
    la_status status = sdev->m_l3_ports.get(la_obj.index, entry);
    sai_return_on_la_error(status, "No router port with id 0x%lx", obj_router_interface_id);

    if (entry.l3_port == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    bool read_ingress = std::any_of(counter_ids, counter_ids + number_of_counters, [](sai_stat_id_t id) {
        return (id == SAI_ROUTER_INTERFACE_STAT_IN_OCTETS) || (id == SAI_ROUTER_INTERFACE_STAT_IN_PACKETS);
    });

    bool read_egress = std::any_of(counter_ids, counter_ids + number_of_counters, [](sai_stat_id_t id) {
        return (id == SAI_ROUTER_INTERFACE_STAT_OUT_OCTETS) || (id == SAI_ROUTER_INTERFACE_STAT_OUT_PACKETS);
    });

    size_t in_packets_sum = 0, in_bytes_sum = 0, out_packets_sum = 0, out_bytes_sum = 0;
    size_t in_packets[PORT_COUNTER_SIZE] = {0};
    size_t in_bytes[PORT_COUNTER_SIZE] = {0};
    size_t out_packets[PORT_COUNTER_SIZE] = {0};
    size_t out_bytes[PORT_COUNTER_SIZE] = {0};

    if (read_ingress) {
        la_counter_set* ingress_counter = nullptr;
        status = entry.l3_port->get_ingress_counter(la_counter_set::type_e::PORT, ingress_counter);
        sai_return_on_la_error(status, "Failed to get ingress counter, rc %s", status.message().c_str());

        for (int i = 0; i < PORT_COUNTER_SIZE; i++) {
            status
                = ingress_counter->read(i, sdev->m_force_update, mode == SAI_STATS_MODE_READ_AND_CLEAR, in_packets[i], in_bytes[i]);
            sai_return_on_la_error(status, "Failed to read ingress counter, rc %s", status.message().c_str());
            in_packets_sum += in_packets[i];
            in_bytes_sum += in_bytes[i];
        }
    }

    if (read_egress) {
        la_counter_set* egress_counter = nullptr;
        status = entry.l3_port->get_egress_counter(la_counter_set::type_e::PORT, egress_counter);
        sai_return_on_la_error(status, "Failed to get egress counter, %s", status.message().c_str());

        for (int i = 0; i < PORT_COUNTER_SIZE; i++) {
            status = egress_counter->read(
                i, sdev->m_force_update, mode == SAI_STATS_MODE_READ_AND_CLEAR, out_packets[i], out_bytes[i]);
            sai_return_on_la_error(status, "Failed to read egress counter, rc %s", status.message().c_str());
            out_packets_sum += out_packets[i];
            out_bytes_sum += out_bytes[i];
        }
    }

    for (uint32_t i = 0; i < number_of_counters; ++i) {
        switch (counter_ids[i]) {
        case SAI_ROUTER_INTERFACE_STAT_IPV4_IN_OCTETS:
            counters[i] = in_bytes[(int)la_l3_protocol_counter_e::IPV4_UC] + in_bytes[(int)la_l3_protocol_counter_e::IPV4_MC];
            break;
        case SAI_ROUTER_INTERFACE_STAT_IPV4_IN_PACKETS:
            counters[i] = in_packets[(int)la_l3_protocol_counter_e::IPV4_UC] + in_packets[(int)la_l3_protocol_counter_e::IPV4_MC];
            break;
        case SAI_ROUTER_INTERFACE_STAT_IPV6_IN_OCTETS:
            counters[i] = in_bytes[(int)la_l3_protocol_counter_e::IPV6_UC] + in_bytes[(int)la_l3_protocol_counter_e::IPV6_MC];
            break;
        case SAI_ROUTER_INTERFACE_STAT_IPV6_IN_PACKETS:
            counters[i] = in_packets[(int)la_l3_protocol_counter_e::IPV6_UC] + in_packets[(int)la_l3_protocol_counter_e::IPV6_MC];
            break;
        case SAI_ROUTER_INTERFACE_STAT_MPLS_IN_OCTETS:
            counters[i] = in_bytes[(int)la_l3_protocol_counter_e::MPLS];
            break;
        case SAI_ROUTER_INTERFACE_STAT_MPLS_IN_PACKETS:
            counters[i] = in_packets[(int)la_l3_protocol_counter_e::MPLS];
            break;
        case SAI_ROUTER_INTERFACE_STAT_IN_OCTETS:
            counters[i] = in_bytes_sum;
            break;
        case SAI_ROUTER_INTERFACE_STAT_IN_PACKETS:
            counters[i] = in_packets_sum;
            break;
        case SAI_ROUTER_INTERFACE_STAT_IPV4_OUT_OCTETS:
            counters[i] = out_bytes[(int)la_l3_protocol_counter_e::IPV4_UC] + out_bytes[(int)la_l3_protocol_counter_e::IPV4_MC];
            break;
        case SAI_ROUTER_INTERFACE_STAT_IPV4_OUT_PACKETS:
            counters[i] = out_packets[(int)la_l3_protocol_counter_e::IPV4_UC] + out_packets[(int)la_l3_protocol_counter_e::IPV4_MC];
            break;
        case SAI_ROUTER_INTERFACE_STAT_IPV6_OUT_OCTETS:
            counters[i] = out_bytes[(int)la_l3_protocol_counter_e::IPV6_UC] + out_bytes[(int)la_l3_protocol_counter_e::IPV6_MC];
            break;
        case SAI_ROUTER_INTERFACE_STAT_IPV6_OUT_PACKETS:
            counters[i] = out_packets[(int)la_l3_protocol_counter_e::IPV6_UC] + out_packets[(int)la_l3_protocol_counter_e::IPV6_MC];
            break;
        case SAI_ROUTER_INTERFACE_STAT_MPLS_OUT_OCTETS:
            counters[i] = out_bytes[(int)la_l3_protocol_counter_e::MPLS];
            break;
        case SAI_ROUTER_INTERFACE_STAT_MPLS_OUT_PACKETS:
            counters[i] = out_packets[(int)la_l3_protocol_counter_e::MPLS];
            break;
        case SAI_ROUTER_INTERFACE_STAT_OUT_OCTETS:
            counters[i] = out_bytes_sum;
            break;
        case SAI_ROUTER_INTERFACE_STAT_OUT_PACKETS:
            counters[i] = out_packets_sum;
            break;
        case SAI_ROUTER_INTERFACE_STAT_IN_ERROR_OCTETS:
        case SAI_ROUTER_INTERFACE_STAT_IN_ERROR_PACKETS:
        case SAI_ROUTER_INTERFACE_STAT_OUT_ERROR_OCTETS:
        case SAI_ROUTER_INTERFACE_STAT_OUT_ERROR_PACKETS:
        default:
            break;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_router_interface_stats(sai_object_id_t router_interface_id,
                           uint32_t number_of_counters,
                           const sai_stat_id_t* counter_ids,
                           uint64_t* counters)
{
    return get_router_interface_stats_ext(router_interface_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ, counters);
}

static sai_status_t
clear_router_interface_stats(sai_object_id_t router_interface_id, uint32_t number_of_counters, const sai_stat_id_t* counter_ids)
{
    uint64_t counters[number_of_counters];
    return get_router_interface_stats_ext(
        router_interface_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ_AND_CLEAR, counters);
}

const sai_router_interface_api_t router_interface_api = {create_router_interface,
                                                         remove_router_interface,
                                                         set_router_interface_attribute,
                                                         get_router_interface_attribute,
                                                         get_router_interface_stats,
                                                         get_router_interface_stats_ext,
                                                         clear_router_interface_stats};
}
}
