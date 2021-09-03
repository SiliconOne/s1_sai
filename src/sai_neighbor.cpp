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

#include "api/npu/la_l3_ac_port.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_next_hop.h"
#include "api/npu/la_svi_port.h"
#include "api/npu/la_switch.h"
#include "api/npu/la_vrf.h"
#include "api/system/la_device.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "common/ranged_index_generator.h"
#include "common/transaction.h"
#include "sai_device.h"
#include "sai_logger.h"
#include <arpa/inet.h>
#include <string>

namespace silicon_one
{
namespace sai
{

using namespace std;

sai_status_t neighbor_mac_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg);
sai_status_t neighbor_action_get(_In_ const sai_object_key_t* key,
                                 _Inout_ sai_attribute_value_t* value,
                                 _In_ uint32_t attr_index,
                                 _Inout_ vendor_cache_t* cache,
                                 void* arg);
sai_status_t neighbor_mac_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
sai_status_t neighbor_action_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
sai_status_t neighbor_no_host_get(_In_ const sai_object_key_t* key,
                                  _Inout_ sai_attribute_value_t* value,
                                  _In_ uint32_t attr_index,
                                  _Inout_ vendor_cache_t* cache,
                                  void* arg);

sai_status_t neighbor_meta_data_get(_In_ const sai_object_key_t* key,
                                    _Inout_ sai_attribute_value_t* value,
                                    _In_ uint32_t attr_index,
                                    _Inout_ vendor_cache_t* cache,
                                    void* arg);
sai_status_t neighbor_no_host_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
sai_status_t neighbor_meta_data_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
static la_status la_add_ipv4_host_to_router_interface(sai_object_id_t obj_rif_id,
                                                      la_ipv4_addr_t& ip_addr,
                                                      la_mac_addr_t& mac_addr,
                                                      la_class_id_t class_id,
                                                      sai_object_id_t& obj_nh,
                                                      transaction& txn);
static la_status la_add_ipv6_host_to_router_interface(sai_object_id_t obj_rif_id,
                                                      la_ipv6_addr_t& ip_addr,
                                                      la_mac_addr_t& mac_addr,
                                                      la_class_id_t class_id,
                                                      sai_object_id_t& obj_nh,
                                                      transaction& txn);

// clang-format off
extern const sai_attribute_entry_t neighbor_attribs[]
    = {{SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS, true, true, true, true, "Neighbor destination MAC", SAI_ATTR_VAL_TYPE_MAC},
       {SAI_NEIGHBOR_ENTRY_ATTR_PACKET_ACTION, false, true, true, true, "Neighbor L3 forwarding action", SAI_ATTR_VAL_TYPE_S32},
       {SAI_NEIGHBOR_ENTRY_ATTR_USER_TRAP_ID, false, true, true, true, "Neighbor Trap ID", SAI_ATTR_VAL_TYPE_OID},
       {SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE, false, true, true, true, "Neighbor not to be programmed as host", SAI_ATTR_VAL_TYPE_BOOL},
       {SAI_NEIGHBOR_ENTRY_ATTR_META_DATA, false, true, true, true, "Neighbor entry user meta", SAI_ATTR_VAL_TYPE_U32},
       {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t neighbor_vendor_attribs[] = {
    {SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS,
     {true, false, true, true},
     {true, false, true, true},
     neighbor_mac_get, nullptr, neighbor_mac_set, nullptr},

    {SAI_NEIGHBOR_ENTRY_ATTR_PACKET_ACTION,
     {true, false, true, true},
     {true, false, true, true},
     neighbor_action_get, nullptr, neighbor_action_set, nullptr},

    {SAI_NEIGHBOR_ENTRY_ATTR_USER_TRAP_ID,
     {false, false, false, false},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    {SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE,
     {true, false, true, true},
     {true, false, true, true},
     neighbor_no_host_get, nullptr, neighbor_no_host_set, nullptr},

    {SAI_NEIGHBOR_ENTRY_ATTR_META_DATA,
     {true, false, true, true},
     {true, false, true, true},
     neighbor_meta_data_get, nullptr, neighbor_meta_data_set, nullptr},
};
// clang-format on

sai_status_t
neighbor_mac_get(_In_ const sai_object_key_t* key,
                 _Inout_ sai_attribute_value_t* value,
                 _In_ uint32_t attr_index,
                 _Inout_ vendor_cache_t* cache,
                 void* arg)
{
    const sai_neighbor_entry_t* neighbor_entry = &key->key.neighbor_entry;
    if (neighbor_entry == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_rif(neighbor_entry->rif_id);
    auto sdev = la_rif.get_device();
    sai_check_object(la_rif, SAI_OBJECT_TYPE_ROUTER_INTERFACE, sdev, "router interface", neighbor_entry->rif_id);

    rif_entry entry{};
    la_status status = sdev->m_l3_ports.get(la_rif.index, entry);
    if (status != LA_STATUS_SUCCESS || entry.l3_port == nullptr) {
        sai_log_error(SAI_API_NEIGHBOR, "can not get la rif 0x%lx for neighbor", neighbor_entry->rif_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_mac_addr_t lmac{};
    if (neighbor_entry->ip_address.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        la_ipv4_addr_t ip_addr;
        ip_addr.s_addr = ntohl(neighbor_entry->ip_address.addr.ip4);

        if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
            la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
            la_class_id_t class_id;
            status = l3ac->get_ipv4_host_and_class_id(ip_addr, lmac, class_id);
        } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
            la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
            la_class_id_t class_id;
            status = sviport->get_ipv4_host_and_class_id(ip_addr, lmac, class_id);
        }
    } else {
        la_ipv6_addr_t ipv6_addr;
        reverse_copy(std::begin(neighbor_entry->ip_address.addr.ip6),
                     std::end(neighbor_entry->ip_address.addr.ip6),
                     std::begin(ipv6_addr.b_addr));
        if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
            la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
            la_class_id_t class_id;
            status = l3ac->get_ipv6_host_and_class_id(ipv6_addr, lmac, class_id);

        } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
            la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
            la_class_id_t class_id;
            status = sviport->get_ipv6_host_and_class_id(ipv6_addr, lmac, class_id);
        }
        if (status != LA_STATUS_SUCCESS) {
            auto it = entry.m_v6_link_locals.find(ipv6_addr);
            if (it != entry.m_v6_link_locals.end()) {
                status = LA_STATUS_SUCCESS;
                lmac = it->second;
            }
        }
    }

    sai_return_on_la_error(status, "Can not get neighbor mac attribute rif 0x%lx", neighbor_entry->rif_id);
    reverse(std::begin(lmac.bytes), std::end(lmac.bytes));
    set_mac_attr_value(SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS, (*value), lmac.bytes);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
neighbor_action_get(_In_ const sai_object_key_t* key,
                    _Inout_ sai_attribute_value_t* value,
                    _In_ uint32_t attr_index,
                    _Inout_ vendor_cache_t* cache,
                    void* arg)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}
sai_status_t
neighbor_mac_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{

    const sai_neighbor_entry_t* neighbor_entry = &key->key.neighbor_entry;
    if (neighbor_entry == nullptr) {
        sai_log_error(SAI_API_NEIGHBOR, "NULL neighbor entry");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_mac_addr_t new_mac_addr;
    get_mac_attr_value(SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS, *value, new_mac_addr.bytes);
    reverse(std::begin(new_mac_addr.bytes), std::end(new_mac_addr.bytes));

    lsai_object la_rif(neighbor_entry->rif_id);
    auto sdev = la_rif.get_device();
    sai_check_object(la_rif, SAI_OBJECT_TYPE_ROUTER_INTERFACE, sdev, "router interface", neighbor_entry->rif_id);

    rif_entry entry{};
    la_status status = sdev->m_l3_ports.get(la_rif.index, entry);
    if (status != LA_STATUS_SUCCESS || entry.l3_port == nullptr) {
        sai_log_error(SAI_API_NEIGHBOR, "can not get la rif 0x%lx", neighbor_entry->rif_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // Update mac if host is present, otherwise create it
    la_mac_addr_t lmac;
    transaction txn{};
    sai_object_id_t obj_nh = SAI_NULL_OBJECT_ID;
    if (neighbor_entry->ip_address.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        la_ipv4_addr_t ip_addr;
        ip_addr.s_addr = ntohl(neighbor_entry->ip_address.addr.ip4);
        if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
            la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
            la_class_id_t class_id;
            status = l3ac->get_ipv4_host_and_class_id(ip_addr, lmac, class_id);
            if (status != LA_STATUS_SUCCESS) {
                status = la_add_ipv4_host_to_router_interface(
                    neighbor_entry->rif_id, ip_addr, new_mac_addr, LA_CLASS_ID_DEFAULT, obj_nh, txn);
                sai_return_on_la_error(status, "Failed to add ipv4 l3ac host for rif_id 0x%lx", neighbor_entry->rif_id);
            } else {
                status = l3ac->modify_ipv4_host(ip_addr, new_mac_addr, class_id);
                sai_return_on_la_error(status, "Failed to modify ipv4 l3ac host for rif_id 0x%lx", neighbor_entry->rif_id);
            }
        } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
            la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
            la_class_id_t class_id;
            status = sviport->get_ipv4_host_and_class_id(ip_addr, lmac, class_id);
            if (status != LA_STATUS_SUCCESS) {
                status = la_add_ipv4_host_to_router_interface(
                    neighbor_entry->rif_id, ip_addr, new_mac_addr, LA_CLASS_ID_DEFAULT, obj_nh, txn);
                sai_return_on_la_error(status, "Failed to add ipv4 svi host for rif_id 0x%lx", neighbor_entry->rif_id);
            } else {
                status = sviport->modify_ipv4_host(ip_addr, new_mac_addr, class_id);
                sai_return_on_la_error(status, "Failed to modify ipv4 svi host for rif_id 0x%lx", neighbor_entry->rif_id);
            }
        }

        auto it = entry.m_v4_neighbors.find(ip_addr);
        if (it != entry.m_v4_neighbors.end()) {
            obj_nh = it->second;
        }
    } else {
        la_ipv6_addr_t ipv6_addr;
        reverse_copy(std::begin(neighbor_entry->ip_address.addr.ip6),
                     std::end(neighbor_entry->ip_address.addr.ip6),
                     std::begin(ipv6_addr.b_addr));
        la_l3_ac_port* l3ac;
        if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
            l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
            la_class_id_t class_id;
            status = l3ac->get_ipv6_host_and_class_id(ipv6_addr, lmac, class_id);
            if (status != LA_STATUS_SUCCESS) {
                status = la_add_ipv6_host_to_router_interface(
                    neighbor_entry->rif_id, ipv6_addr, new_mac_addr, LA_CLASS_ID_DEFAULT, obj_nh, txn);
                sai_return_on_la_error(status, "Failed to add ipv6 l3ac host for rif_id 0x%lx", neighbor_entry->rif_id);
            } else {
                status = l3ac->modify_ipv6_host(ipv6_addr, new_mac_addr, class_id);
                sai_return_on_la_error(status, "Failed to modify ipv6 l3ac host for rif_id 0x%lx", neighbor_entry->rif_id);
            }
        } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
            la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
            la_class_id_t class_id;
            status = sviport->get_ipv6_host_and_class_id(ipv6_addr, lmac, class_id);
            if (status != LA_STATUS_SUCCESS) {
                status = la_add_ipv6_host_to_router_interface(
                    neighbor_entry->rif_id, ipv6_addr, new_mac_addr, LA_CLASS_ID_DEFAULT, obj_nh, txn);
                sai_return_on_la_error(status, "Failed to add ipv6 svi host for rif_id 0x%lx", neighbor_entry->rif_id);
            } else {
                status = sviport->modify_ipv6_host(ipv6_addr, new_mac_addr, class_id);
                sai_return_on_la_error(status, "Failed to modify ipv6 svi host for rif_id 0x%lx", neighbor_entry->rif_id);
            }
        }

        auto it = entry.m_v6_neighbors.find(ipv6_addr);
        if (it != entry.m_v6_neighbors.end()) {
            obj_nh = it->second;
        }
    }

    // neighbor used by nexthop then update the mac for nexthop
    if (obj_nh != SAI_NULL_OBJECT_ID) {
        lsai_object la_nh;
        next_hop_entry nh_entry{};
        status = sdev->m_next_hops.get(obj_nh, nh_entry, la_nh);
        sai_return_on_la_error(status, "Failed to get nh_entry for route, 0x%lx", neighbor_entry->rif_id);

        status = nh_entry.next_hop->set_mac(new_mac_addr);
        sai_return_on_la_error(status, "Failed to set mac for route, 0x%lx", neighbor_entry->rif_id);

        nh_entry.next_hop->set_nh_type(la_next_hop::nh_type_e::NORMAL);
    } else {
        sai_log_debug(SAI_API_NEIGHBOR, "Next hop object id not available for la rif 0x%lx", neighbor_entry->rif_id);
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
neighbor_action_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
neighbor_no_host_get(_In_ const sai_object_key_t* key,
                     _Inout_ sai_attribute_value_t* value,
                     _In_ uint32_t attr_index,
                     _Inout_ vendor_cache_t* cache,
                     void* arg)
{
    bool neighbor_no_host = false;
    const sai_neighbor_entry_t* neighbor_entry = &key->key.neighbor_entry;
    if (neighbor_entry == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_rif(neighbor_entry->rif_id);
    auto sdev = la_rif.get_device();
    sai_check_object(la_rif, SAI_OBJECT_TYPE_ROUTER_INTERFACE, sdev, "router interface", neighbor_entry->rif_id);

    rif_entry entry{};
    la_status status = sdev->m_l3_ports.get(la_rif.index, entry);
    if (status != LA_STATUS_SUCCESS || entry.l3_port == nullptr) {
        sai_log_error(SAI_API_NEIGHBOR, "can not get la rif 0x%lx for neighbor", neighbor_entry->rif_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (neighbor_entry->ip_address.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        set_attr_value(SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE, (*value), neighbor_no_host);
    } else {
        la_ipv6_addr_t ipv6_addr;
        reverse_copy(std::begin(neighbor_entry->ip_address.addr.ip6),
                     std::end(neighbor_entry->ip_address.addr.ip6),
                     std::begin(ipv6_addr.b_addr));
        auto it = entry.m_v6_link_locals.find(ipv6_addr);
        if (it != entry.m_v6_link_locals.end()) {
            neighbor_no_host = true;
            set_attr_value(SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE, (*value), neighbor_no_host);
        } else {
            set_attr_value(SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE, (*value), neighbor_no_host);
        }
    }
    return SAI_STATUS_SUCCESS;
    // return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
neighbor_meta_data_get(_In_ const sai_object_key_t* key,
                       _Inout_ sai_attribute_value_t* value,
                       _In_ uint32_t attr_index,
                       _Inout_ vendor_cache_t* cache,
                       void* arg)
{
    const sai_neighbor_entry_t* neighbor_entry = &key->key.neighbor_entry;
    if (neighbor_entry == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_rif(neighbor_entry->rif_id);
    auto sdev = la_rif.get_device();
    sai_check_object(la_rif, SAI_OBJECT_TYPE_ROUTER_INTERFACE, sdev, "router interface", neighbor_entry->rif_id);

    rif_entry entry{};
    la_status status = sdev->m_l3_ports.get(la_rif.index, entry);
    if (status != LA_STATUS_SUCCESS || entry.l3_port == nullptr) {
        sai_log_error(SAI_API_NEIGHBOR, "can not get la rif 0x%lx for neighbor", neighbor_entry->rif_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_mac_addr_t lmac{};
    la_class_id_t class_id;
    if (neighbor_entry->ip_address.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        la_ipv4_addr_t ip_addr;
        ip_addr.s_addr = ntohl(neighbor_entry->ip_address.addr.ip4);
        if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
            la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
            status = l3ac->get_ipv4_host_and_class_id(ip_addr, lmac, class_id);
        } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
            la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
            status = sviport->get_ipv4_host_and_class_id(ip_addr, lmac, class_id);
        }
    } else {
        la_ipv6_addr_t ipv6_addr;
        reverse_copy(std::begin(neighbor_entry->ip_address.addr.ip6),
                     std::end(neighbor_entry->ip_address.addr.ip6),
                     std::begin(ipv6_addr.b_addr));
        if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
            la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
            status = l3ac->get_ipv6_host_and_class_id(ipv6_addr, lmac, class_id);
        } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
            la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
            status = sviport->get_ipv6_host_and_class_id(ipv6_addr, lmac, class_id);
        }

        if (status != LA_STATUS_SUCCESS) {
            auto it = entry.m_v6_link_locals.find(ipv6_addr);
            if (it != entry.m_v6_link_locals.end()) {
                status = LA_STATUS_SUCCESS;
                class_id = LA_CLASS_ID_DEFAULT;
            }
        }
    }

    sai_return_on_la_error(status, "Can not get neighbor user meta data attribute for rif 0x%lx", neighbor_entry->rif_id);
    set_attr_value(SAI_NEIGHBOR_ENTRY_ATTR_META_DATA, (*value), class_id);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
neighbor_no_host_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
neighbor_meta_data_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    const sai_neighbor_entry_t* neighbor_entry = &key->key.neighbor_entry;
    if (neighbor_entry == nullptr) {
        sai_log_error(SAI_API_NEIGHBOR, "NULL neighbor entry");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    uint32_t new_user_meta = get_attr_value(SAI_NEIGHBOR_ENTRY_ATTR_META_DATA, *value);

    lsai_object la_rif(neighbor_entry->rif_id);
    auto sdev = la_rif.get_device();
    sai_check_object(la_rif, SAI_OBJECT_TYPE_ROUTER_INTERFACE, sdev, "router interface", neighbor_entry->rif_id);

    if (new_user_meta > sdev->m_neighbor_user_meta_max) {
        sai_log_error(SAI_API_NEIGHBOR, "Out of range neighbor user meta data 0x%lx provided", new_user_meta);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    rif_entry entry{};
    la_status status = sdev->m_l3_ports.get(la_rif.index, entry);
    if (status != LA_STATUS_SUCCESS || entry.l3_port == nullptr) {
        sai_log_error(SAI_API_NEIGHBOR, "can not get la rif 0x%lx", neighbor_entry->rif_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // Update host user meta if present, otherwise return error
    la_mac_addr_t lmac;
    transaction txn{};
    if (neighbor_entry->ip_address.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        la_ipv4_addr_t ip_addr;
        ip_addr.s_addr = ntohl(neighbor_entry->ip_address.addr.ip4);
        if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
            la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
            la_class_id_t class_id;
            status = l3ac->get_ipv4_host_and_class_id(ip_addr, lmac, class_id);
            if (status != LA_STATUS_SUCCESS) {
                sai_return_on_la_error(status,
                                       "Missing host entry. Failed to update ipv4 l3ac host user meta data for rif_id 0x%lx",
                                       neighbor_entry->rif_id);
            } else {
                status = l3ac->modify_ipv4_host(ip_addr, lmac, new_user_meta);
                sai_return_on_la_error(
                    status, "Failed to modify ipv4 l3ac host user meta for rif_id 0x%lx", neighbor_entry->rif_id);
            }
        } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
            la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
            la_class_id_t class_id;
            status = sviport->get_ipv4_host_and_class_id(ip_addr, lmac, class_id);
            if (status != LA_STATUS_SUCCESS) {
                sai_return_on_la_error(status,
                                       "Missing host entry. Failed to update svi host user meta data for rif_id 0x%lx",
                                       neighbor_entry->rif_id);
            } else {
                status = sviport->modify_ipv4_host(ip_addr, lmac, new_user_meta);
                sai_return_on_la_error(
                    status, "Failed to modify ipv4 svi host user meta data for rif_id 0x%lx", neighbor_entry->rif_id);
            }
        }
    } else {
        la_ipv6_addr_t ipv6_addr;
        reverse_copy(std::begin(neighbor_entry->ip_address.addr.ip6),
                     std::end(neighbor_entry->ip_address.addr.ip6),
                     std::begin(ipv6_addr.b_addr));
        la_l3_ac_port* l3ac;
        if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
            l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
            la_class_id_t class_id;
            status = l3ac->get_ipv6_host_and_class_id(ipv6_addr, lmac, class_id);
            if (status != LA_STATUS_SUCCESS) {
                sai_return_on_la_error(status,
                                       "Missing host entry. Failed to update ipv4 l3ac host user meta data for rif_id 0x%lx",
                                       neighbor_entry->rif_id);
            } else {
                status = l3ac->modify_ipv6_host(ipv6_addr, lmac, new_user_meta);
                sai_return_on_la_error(
                    status, "Failed to modify ipv6 l3ac host user meta for rif_id 0x%lx", neighbor_entry->rif_id);
            }
        } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
            la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
            la_class_id_t class_id;
            status = sviport->get_ipv6_host_and_class_id(ipv6_addr, lmac, class_id);
            if (status != LA_STATUS_SUCCESS) {
                sai_return_on_la_error(status,
                                       "Missing host entry. Failed to update ipv4 svi host user meta data for rif_id 0x%lx",
                                       neighbor_entry->rif_id);
            } else {
                status = sviport->modify_ipv6_host(ipv6_addr, lmac, new_user_meta);
                sai_return_on_la_error(status, "Failed to modify ipv6 svi host user meta for rif_id 0x%lx", neighbor_entry->rif_id);
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static la_status
la_add_ipv4_host_to_router_interface(sai_object_id_t obj_rif_id,
                                     la_ipv4_addr_t& ip_addr,
                                     la_mac_addr_t& mac_addr,
                                     la_class_id_t class_id,
                                     sai_object_id_t& obj_nh,
                                     transaction& txn)
{
    lsai_object la_rif(obj_rif_id);
    auto sdev = la_rif.get_device();

    if (sdev == nullptr || la_rif.type != SAI_OBJECT_TYPE_ROUTER_INTERFACE) {
        sai_log_error(SAI_API_NEIGHBOR, "Object is not valid rif bridge object id 0x%lx", obj_rif_id);
        return LA_STATUS_EINVAL;
    }

    rif_entry entry{};
    txn.status = sdev->m_l3_ports.get(la_rif.index, entry);
    la_return_on_error(txn.status, "Fail to get router interface for route, 0x%lx", obj_rif_id);

    if (entry.l3_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
        la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
        txn.status = l3ac->add_ipv4_host(ip_addr, mac_addr, class_id);
        la_return_on_error(txn.status, "Failed to add subnet to router port, %s", txn.status.message().c_str());
        txn.on_fail([=]() { l3ac->delete_ipv4_host(ip_addr); });
    } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
        la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
        txn.status = sviport->add_ipv4_host(ip_addr, mac_addr, class_id);
        la_return_on_error(txn.status, "Failed to add subnet to router port, %s", txn.status.message().c_str());
        txn.on_fail([=]() { sviport->delete_ipv4_host(ip_addr); });
    }

    auto it = entry.m_v4_neighbors.find(ip_addr);
    if (it != entry.m_v4_neighbors.end()) {
        obj_nh = it->second;
    }

    return LA_STATUS_SUCCESS;
}

static la_status
la_add_ipv6_link_local_to_router_interface(sai_object_id_t obj_rif_id,
                                           la_ipv6_addr_t& ipv6_addr,
                                           la_mac_addr_t& mac_addr,
                                           sai_object_id_t& obj_nh,
                                           transaction& txn)
{
    lsai_object la_rif(obj_rif_id);
    auto sdev = la_rif.get_device();

    if (sdev == nullptr || la_rif.type != SAI_OBJECT_TYPE_ROUTER_INTERFACE) {
        sai_log_error(SAI_API_NEIGHBOR, "Object is not rif bridge object id 0x%lx", obj_rif_id);
        return LA_STATUS_EINVAL;
    }

    rif_entry entry{};
    txn.status = sdev->m_l3_ports.get(la_rif.index, entry);
    la_return_on_error(txn.status);

    entry.m_v6_link_locals.emplace(ipv6_addr, mac_addr);
    sdev->m_l3_ports.set(la_rif.index, entry);

    return LA_STATUS_SUCCESS;
}

static la_status
la_add_ipv6_host_to_router_interface(sai_object_id_t obj_rif_id,
                                     la_ipv6_addr_t& ip_addr,
                                     la_mac_addr_t& mac_addr,
                                     la_class_id_t class_id,
                                     sai_object_id_t& obj_nh,
                                     transaction& txn)
{
    lsai_object la_rif(obj_rif_id);
    auto sdev = la_rif.get_device();

    if (sdev == nullptr || la_rif.type != SAI_OBJECT_TYPE_ROUTER_INTERFACE) {
        sai_log_error(SAI_API_NEIGHBOR, "Object is not rif bridge object id 0x%lx", obj_rif_id);
        return LA_STATUS_EINVAL;
    }

    rif_entry entry{};
    txn.status = sdev->m_l3_ports.get(la_rif.index, entry);
    la_return_on_error(txn.status, "Fail to get router interface for route, 0x%lx", obj_rif_id);

    if (entry.l3_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
        la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
        txn.status = l3ac->add_ipv6_host(ip_addr, mac_addr, class_id);
        la_return_on_error(txn.status, "Failed to add subnet to router port, %s", txn.status.message().c_str());
        txn.on_fail([=]() { l3ac->delete_ipv6_host(ip_addr); });
    } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
        la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
        txn.status = sviport->add_ipv6_host(ip_addr, mac_addr, class_id);
        la_return_on_error(txn.status, "Failed to add subnet to router port, %s", txn.status.message().c_str());
        txn.on_fail([=]() { sviport->delete_ipv6_host(ip_addr); });
    }
    auto it = entry.m_v6_neighbors.find(ip_addr);
    if (it != entry.m_v6_neighbors.end()) {
        obj_nh = it->second;
    }

    return LA_STATUS_SUCCESS;
}

static std::string
neighbor_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_neighbor_entry_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
create_neighbor_entry(const sai_neighbor_entry_t* neighbor_entry, uint32_t attr_count, const sai_attribute_t* attr_list)
{
    if (neighbor_entry == nullptr) {
        sai_log_error(SAI_API_NEIGHBOR, "NULL neighbor entry");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_NEIGHBOR, SAI_OBJECT_TYPE_SWITCH, neighbor_entry->switch_id, &neighbor_to_string, neighbor_entry, "attrs", attrs);

    la_mac_addr_t mac_addr{};
    get_mac_attrs_value(SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS, attrs, mac_addr.bytes, true);
    reverse(std::begin(mac_addr.bytes), std::end(mac_addr.bytes));

    bool neighbor_no_host = false;
    get_attrs_value(SAI_NEIGHBOR_ENTRY_ATTR_NO_HOST_ROUTE, attrs, neighbor_no_host, false);
    auto class_id = LA_CLASS_ID_DEFAULT;
    get_attrs_value(SAI_NEIGHBOR_ENTRY_ATTR_META_DATA, attrs, class_id, false);

    transaction txn{};
    sai_object_id_t obj_nh = SAI_NULL_OBJECT_ID;
    if (neighbor_entry->ip_address.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {

        la_ipv4_addr_t ip_addr;
        ip_addr.s_addr = ntohl(neighbor_entry->ip_address.addr.ip4);

        txn.status = la_add_ipv4_host_to_router_interface(neighbor_entry->rif_id, ip_addr, mac_addr, class_id, obj_nh, txn);
    } else {
        la_ipv6_addr_t ipv6_addr;
        reverse_copy(std::begin(neighbor_entry->ip_address.addr.ip6),
                     std::end(neighbor_entry->ip_address.addr.ip6),
                     std::begin(ipv6_addr.b_addr));

        if (neighbor_no_host) {
            txn.status = la_add_ipv6_link_local_to_router_interface(neighbor_entry->rif_id, ipv6_addr, mac_addr, obj_nh, txn);
        } else {
            txn.status = la_add_ipv6_host_to_router_interface(neighbor_entry->rif_id, ipv6_addr, mac_addr, class_id, obj_nh, txn);
        }
    }

    // neighbor has not yet been used by nexthop
    if (obj_nh == SAI_NULL_OBJECT_ID) {
        return to_sai_status(txn.status);
    }

    // neighbor used by nexthop then update the mac for nexthop
    lsai_object la_nh;
    next_hop_entry nh_entry{};
    txn.status = sdev->m_next_hops.get(obj_nh, nh_entry, la_nh);
    sai_return_on_la_error(txn.status);

    if (nh_entry.type == SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP) {
        sai_log_error(SAI_API_NEIGHBOR, "Neighbor has not yet implemented for tunnel next hop 0x%x", obj_nh);
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    txn.status = nh_entry.next_hop->set_mac(mac_addr);
    sai_return_on_la_error(txn.status);

    txn.status = nh_entry.next_hop->set_nh_type(la_next_hop::nh_type_e::NORMAL);
    return to_sai_status(txn.status);
}

static sai_status_t
remove_neighbor_entry(const sai_neighbor_entry_t* neighbor_entry)
{
    if (neighbor_entry == nullptr) {
        sai_log_error(SAI_API_NEIGHBOR, "NULL neighbor entry");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_status status;

    sai_start_api(SAI_API_NEIGHBOR, SAI_OBJECT_TYPE_SWITCH, neighbor_entry->switch_id, &neighbor_to_string, neighbor_entry);

    lsai_object la_rif(neighbor_entry->rif_id);
    rif_entry entry{};
    status = sdev->m_l3_ports.get(la_rif.index, entry);
    sai_return_on_la_error(status, "Fail to get router interface for route, 0x%lx", neighbor_entry->rif_id);

    la_ipv4_addr_t ip_addr{};
    la_ipv6_addr_t ipv6_addr{};
    if (neighbor_entry->ip_address.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        ip_addr.s_addr = ntohl(neighbor_entry->ip_address.addr.ip4);
    } else {
        reverse_copy(std::begin(neighbor_entry->ip_address.addr.ip6),
                     std::end(neighbor_entry->ip_address.addr.ip6),
                     std::begin(ipv6_addr.b_addr));

        auto it = entry.m_v6_link_locals.find(ipv6_addr);
        if (it != entry.m_v6_link_locals.end()) {
            entry.m_v6_link_locals.erase(it);
            sdev->m_l3_ports.set(la_rif.index, entry);
            return SAI_STATUS_SUCCESS;
        }
    }

    // l3_port == is local loopback interface. no neighbors
    if (entry.l3_port == nullptr) {
        return SAI_STATUS_FAILURE;
    }

    sai_object_id_t obj_nh = SAI_NULL_OBJECT_ID;
    if (neighbor_entry->ip_address.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
            la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
            status = l3ac->delete_ipv4_host(ip_addr);
        } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
            la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
            status = sviport->delete_ipv4_host(ip_addr);
        }
        auto it = entry.m_v4_neighbors.find(ip_addr);
        if (it != entry.m_v4_neighbors.end()) {
            obj_nh = it->second;
        }
    } else {
        if (entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
            la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)entry.l3_port);
            status = l3ac->delete_ipv6_host(ipv6_addr);
        } else if (entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
            la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)entry.l3_port);
            status = sviport->delete_ipv6_host(ipv6_addr);
        }
        auto it = entry.m_v6_neighbors.find(ipv6_addr);
        if (it != entry.m_v6_neighbors.end()) {
            obj_nh = it->second;
        }
    }

    if (status) {
        sai_log_error(SAI_API_NEIGHBOR, "Failed to delete host from router port, %s", status.message().c_str());
        return to_sai_status(status);
    }

    if (obj_nh != SAI_NULL_OBJECT_ID) {
        lsai_object la_nh;
        next_hop_entry nh_entry{};
        status = sdev->m_next_hops.get(obj_nh, nh_entry, la_nh);
        if (status == LA_STATUS_SUCCESS) {
            nh_entry.next_hop->set_nh_type(la_next_hop::nh_type_e::GLEAN);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_neighbor_entry_attribute(const sai_neighbor_entry_t* neighbor_entry, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    memcpy(&key.key.neighbor_entry, neighbor_entry, sizeof(*neighbor_entry));

    sai_start_api(SAI_API_NEIGHBOR, SAI_OBJECT_TYPE_SWITCH, neighbor_entry->switch_id, &neighbor_to_string, neighbor_entry, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "neighbor 0x%lx 0x%0x", neighbor_entry->rif_id, neighbor_entry->ip_address.addr.ip4);
    return sai_set_attribute(&key, key_str, neighbor_attribs, neighbor_vendor_attribs, attr);
}

static sai_status_t
get_neighbor_entry_attribute(const sai_neighbor_entry_t* neighbor_entry, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    memcpy(&key.key.neighbor_entry, neighbor_entry, sizeof(*neighbor_entry));

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_NEIGHBOR, SAI_OBJECT_TYPE_SWITCH, neighbor_entry->switch_id, &neighbor_to_string, neighbor_entry, "attrs", attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "neighbor 0x%lx 0x%0x", neighbor_entry->rif_id, neighbor_entry->ip_address.addr.ip4);
    return sai_get_attributes(&key, key_str, neighbor_attribs, neighbor_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
remove_all_neighbor_entries(sai_object_id_t obj_switch_id)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
laobj_db_neighbor_entry::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    uint32_t idx = 0;
    auto l3_port_vec = sdev->m_dev->get_objects(la_object::object_type_e::L3_AC_PORT);
    for (auto l3_port : l3_port_vec) {
        auto l3ac = static_cast<la_l3_ac_port*>(l3_port);
        la_mac_addr_vec v4_hosts{};
        la_status status = l3ac->get_ipv4_hosts(v4_hosts);
        if (status == LA_STATUS_SUCCESS) {
            idx += v4_hosts.size();
        }

        la_mac_addr_vec v6_hosts{};
        status = l3ac->get_ipv6_hosts(v6_hosts);
        if (status == LA_STATUS_SUCCESS) {
            idx += v6_hosts.size();
        }
    }

    auto svi_port_vec = sdev->m_dev->get_objects(la_object::object_type_e::SVI_PORT);
    for (auto svi_port : svi_port_vec) {
        auto svip = static_cast<la_svi_port*>(svi_port);
        la_mac_addr_vec v4_hosts{};
        la_status status = svip->get_ipv4_hosts(v4_hosts);
        if (status == LA_STATUS_SUCCESS) {
            idx += v4_hosts.size();
        }

        la_mac_addr_vec v6_hosts{};
        status = svip->get_ipv6_hosts(v6_hosts);
        if (status == LA_STATUS_SUCCESS) {
            idx += v6_hosts.size();
        }
    }

    *count = idx;

    return SAI_STATUS_SUCCESS;
}

static void
construct_v4_neighbor_entry(sai_neighbor_entry_t* neighbor_entry,
                            std::shared_ptr<lsai_device> sdev,
                            la_l3_port_gid_t gid,
                            la_ipv4_addr_t ipv4_addr)
{
    neighbor_entry->switch_id = sdev->m_switch_id;
    lsai_object la_sw(sdev->m_switch_id);
    lsai_object la_rif(SAI_OBJECT_TYPE_ROUTER_INTERFACE, la_sw.index, gid);
    neighbor_entry->rif_id = la_rif.object_id();
    neighbor_entry->ip_address.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    neighbor_entry->ip_address.addr.ip4 = htonl(ipv4_addr.s_addr);
}

static void
construct_v6_neighbor_entry(sai_neighbor_entry_t* neighbor_entry,
                            std::shared_ptr<lsai_device> sdev,
                            la_l3_port_gid_t gid,
                            la_ipv6_addr_t ipv6_addr)
{
    neighbor_entry->switch_id = sdev->m_switch_id;
    lsai_object la_sw(sdev->m_switch_id);
    lsai_object la_rif(SAI_OBJECT_TYPE_ROUTER_INTERFACE, la_sw.index, gid);
    neighbor_entry->rif_id = la_rif.object_id();
    neighbor_entry->ip_address.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
    reverse_copy(std::begin(ipv6_addr.b_addr), std::end(ipv6_addr.b_addr), std::begin(neighbor_entry->ip_address.addr.ip6));
}

sai_status_t
laobj_db_neighbor_entry::get_object_keys(std::shared_ptr<lsai_device> sdev,
                                         uint32_t* object_count,
                                         sai_object_key_t* object_list) const
{
    uint32_t idx = 0;
    get_object_count(sdev, &idx);
    if (idx > *object_count) {
        *object_count = idx;
        return SAI_STATUS_BUFFER_OVERFLOW;
    }
    idx = 0;
    auto l3_port_vec = sdev->m_dev->get_objects(la_object::object_type_e::L3_AC_PORT);
    for (auto l3_port : l3_port_vec) {
        auto l3ac = static_cast<la_l3_ac_port*>(l3_port);
        la_ipv4_addr_vec v4_hosts{};
        la_status status = l3ac->get_ipv4_hosts(v4_hosts);
        if (status == LA_STATUS_SUCCESS) {
            for (auto v4_addr : v4_hosts) {
                construct_v4_neighbor_entry(&object_list[idx].key.neighbor_entry, sdev, l3ac->get_gid(), v4_addr);
                idx++;
            }
        }

        la_ipv6_addr_vec v6_hosts{};
        status = l3ac->get_ipv6_hosts(v6_hosts);
        if (status == LA_STATUS_SUCCESS) {
            for (auto v6_addr : v6_hosts) {
                construct_v6_neighbor_entry(&object_list[idx].key.neighbor_entry, sdev, l3ac->get_gid(), v6_addr);
                idx++;
            }
        }
    }

    auto svi_port_vec = sdev->m_dev->get_objects(la_object::object_type_e::SVI_PORT);
    for (auto svi_port : svi_port_vec) {
        auto svip = static_cast<la_svi_port*>(svi_port);
        la_ipv4_addr_vec v4_hosts{};
        la_status status = svip->get_ipv4_hosts(v4_hosts);
        if (status == LA_STATUS_SUCCESS) {
            for (auto v4_addr : v4_hosts) {
                construct_v4_neighbor_entry(&object_list[idx].key.neighbor_entry, sdev, svip->get_gid(), v4_addr);
                idx++;
            }
        }

        la_ipv6_addr_vec v6_hosts{};
        status = svip->get_ipv6_hosts(v6_hosts);
        if (status == LA_STATUS_SUCCESS) {
            for (auto v6_addr : v6_hosts) {
                construct_v6_neighbor_entry(&object_list[idx].key.neighbor_entry, sdev, svip->get_gid(), v6_addr);
                idx++;
            }
        }
    }

    *object_count = idx;

    return SAI_STATUS_SUCCESS;
}

const sai_neighbor_api_t neighbor_api = {create_neighbor_entry,
                                         remove_neighbor_entry,
                                         set_neighbor_entry_attribute,
                                         get_neighbor_entry_attribute,
                                         remove_all_neighbor_entries};
}
}
