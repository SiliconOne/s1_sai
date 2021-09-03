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

#include "sai_next_hop.h"

#include "api/npu/la_l3_ac_port.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_next_hop.h"
#include "api/npu/la_svi_port.h"
#include "api/npu/la_switch.h"
#include "api/npu/la_vrf.h"
#include "api/system/la_device.h"
#include "api/types/la_ip_types.h"
#include "common/ranged_index_generator.h"
#include "common/transaction.h"
#include "sai_device.h"
#include "sai_logger.h"
#include <arpa/inet.h>
#include <map>

namespace silicon_one
{
namespace sai
{

using namespace std;

sai_status_t next_hop_attr_get(_In_ const sai_object_key_t* key,
                               _Inout_ sai_attribute_value_t* value,
                               _In_ uint32_t attr_index,
                               _Inout_ vendor_cache_t* cache,
                               void* arg);

// clang-format off
extern const sai_attribute_entry_t next_hop_attribs[] = {
    {SAI_NEXT_HOP_ATTR_TYPE, true, true, false, true, "Next hop entry type", SAI_ATTR_VAL_TYPE_S32},
    {SAI_NEXT_HOP_ATTR_IP, true, true, false, true, "Next hop entry IP address", SAI_ATTR_VAL_TYPE_IPADDR},
    {SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID, false, true, false, true, "Next hop entry router interface ID", SAI_ATTR_VAL_TYPE_OID},
    {SAI_NEXT_HOP_ATTR_TUNNEL_ID, false, true, false, true, "Next hop entry tunnel ID", SAI_ATTR_VAL_TYPE_OID},
    {SAI_NEXT_HOP_ATTR_LABELSTACK, false, true, false, true, "Next hop label stack", SAI_ATTR_VAL_TYPE_OID},
    {SAI_NEXT_HOP_ATTR_TUNNEL_MAC, false, true, true, true, "Next hop entry tunnel MAC", SAI_ATTR_VAL_TYPE_MAC},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t next_hop_vendor_attribs[] = {
    {SAI_NEXT_HOP_ATTR_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     next_hop_attr_get, (void*)SAI_NEXT_HOP_ATTR_TYPE, nullptr, nullptr},

    {SAI_NEXT_HOP_ATTR_IP,
     {true, false, false, true},
     {true, false, false, true},
     next_hop_attr_get, (void*)SAI_NEXT_HOP_ATTR_IP, nullptr, nullptr},

    {SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID,
     {true, false, false, true},
     {true, false, false, true},
     next_hop_attr_get, (void*)SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID, nullptr, nullptr},

    {SAI_NEXT_HOP_ATTR_TUNNEL_ID,
     {true, false, false, true},
     {true, false, false, true},
     next_hop_attr_get, (void*)SAI_NEXT_HOP_ATTR_TUNNEL_ID, nullptr, nullptr},

    {SAI_NEXT_HOP_ATTR_LABELSTACK,
     {true, false, false, true},
     {true, false, false, true},
     next_hop_attr_get, (void*)SAI_NEXT_HOP_ATTR_LABELSTACK, nullptr, nullptr},

    {SAI_NEXT_HOP_ATTR_TUNNEL_MAC,
     { true, false, false, true },
     { true, false, false, true },
     next_hop_attr_get, (void *)SAI_NEXT_HOP_ATTR_TUNNEL_MAC, NULL, NULL },

};

// clang-format on

sai_status_t
next_hop_attr_get(_In_ const sai_object_key_t* key,
                  _Inout_ sai_attribute_value_t* value,
                  _In_ uint32_t attr_index,
                  _Inout_ vendor_cache_t* cache,
                  void* arg)
{
    if (key == nullptr || value == nullptr) {
        sai_log_error(SAI_API_NEXT_HOP, "Fail to get next hop");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_nexthop(key->key.object_id);
    auto sdev = la_nexthop.get_device();
    sai_check_object(la_nexthop, SAI_OBJECT_TYPE_NEXT_HOP, sdev, "next hop", key->key.object_id);

    next_hop_entry nh_entry{};
    la_status status = sdev->m_next_hops.get(la_nexthop.index, nh_entry);
    sai_return_on_la_error(status);

    switch ((int64_t)arg) {
    case SAI_NEXT_HOP_ATTR_TYPE: {
        set_attr_value(SAI_NEXT_HOP_ATTR_TYPE, (*value), nh_entry.type);
        return SAI_STATUS_SUCCESS;
    }

    case SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID: {
        if (nh_entry.type == SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP) {
            sai_log_error(SAI_API_NEXT_HOP, "Tunnel Next Hop has no router interface attribute 0x%d", key->key.object_id);
            return SAI_STATUS_INVALID_PARAMETER;
        }

        la_l3_port* l3_port = nullptr;
        status = nh_entry.next_hop->get_router_port(l3_port);
        sai_return_on_la_error(status);

        if (l3_port == nullptr) {
            set_attr_value(SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID, (*value), 0);
        } else {
            lsai_object la_rif(SAI_OBJECT_TYPE_ROUTER_INTERFACE, la_nexthop.switch_id, (l3_port->get_gid()));
            set_attr_value(SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID, (*value), (la_rif.object_id()));
        }
        return SAI_STATUS_SUCCESS;
    }

    case SAI_NEXT_HOP_ATTR_IP: {
        set_attr_value(SAI_NEXT_HOP_ATTR_IP, (*value), nh_entry.ip_addr);
        return SAI_STATUS_SUCCESS;
    }

    case SAI_NEXT_HOP_ATTR_LABELSTACK:
        if (value->u32list.count < nh_entry.m_labels.size()) {
            value->u32list.count = nh_entry.m_labels.size();
            return SAI_STATUS_BUFFER_OVERFLOW;
        }
        value->u32list.count = nh_entry.m_labels.size();
        for (uint32_t i = 0; i < nh_entry.m_labels.size(); i++) {
            value->u32list.list[i] = nh_entry.m_labels[i].label;
        }
        return SAI_STATUS_SUCCESS;

    case SAI_NEXT_HOP_ATTR_TUNNEL_ID: {
        if (nh_entry.type == SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP) {
            set_attr_value(SAI_NEXT_HOP_ATTR_TUNNEL_ID, (*value), nh_entry.rif_tun_oid);
        } else {
            sai_log_error(SAI_API_NEXT_HOP, "Non-Tunnel Next Hop has no tunnel id  attribute 0x%d", key->key.object_id);
            return SAI_STATUS_INVALID_PARAMETER;
        }
        return SAI_STATUS_SUCCESS;
    }

    case SAI_NEXT_HOP_ATTR_TUNNEL_MAC: {
        set_mac_attr_value(SAI_NEXT_HOP_ATTR_TUNNEL_MAC, *value, nh_entry.m_tunnel_mac);
        return SAI_STATUS_SUCCESS;
    }

    case SAI_NEXT_HOP_ATTR_TUNNEL_VNI: {
        if (nh_entry.type == SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP) {
            set_attr_value(SAI_NEXT_HOP_ATTR_TUNNEL_VNI, (*value), nh_entry.m_encap_vni);
            return SAI_STATUS_SUCCESS;
        }
        break;
    }

    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    return SAI_STATUS_NOT_IMPLEMENTED;
}

static std::string
nexthop_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_next_hop_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
create_next_hop(sai_object_id_t* next_hop_id, sai_object_id_t obj_switch_id, uint32_t attr_count, const sai_attribute_t* attr_list)
{
    la_next_hop* nh_ptr = nullptr;
    la_status status;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_NEXT_HOP, SAI_OBJECT_TYPE_SWITCH, obj_switch_id, &nexthop_to_string, obj_switch_id, attrs);

    sai_next_hop_type_t next_hop_type{};
    {
        get_attrs_value(SAI_NEXT_HOP_ATTR_TYPE, attrs, next_hop_type, true);
    }

    sai_object_id_t obj_rif_id{};
    lsai_object la_rif;
    rif_entry rif_entry{};
    if (next_hop_type == SAI_NEXT_HOP_TYPE_IP || next_hop_type == SAI_NEXT_HOP_TYPE_MPLS) {
        get_attrs_value(SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID, attrs, obj_rif_id, true);
        status = sdev->m_l3_ports.get(obj_rif_id, rif_entry, la_rif);
        sai_return_on_la_error(status, "router interface does not exist");
    }

    lsai_object la_nh(SAI_OBJECT_TYPE_NEXT_HOP, la_obj.switch_id, 0);
    la_nh.set_device(sdev);

    sai_u32_list_t label_stack{};
    transaction txn{};
    switch (next_hop_type) {
    case SAI_NEXT_HOP_TYPE_MPLS:
    case SAI_NEXT_HOP_TYPE_IP: {
        if (next_hop_type == SAI_NEXT_HOP_TYPE_MPLS) {
            get_attrs_value(SAI_NEXT_HOP_ATTR_LABELSTACK, attrs, label_stack, true);
        }
        sai_ip_address_t ipaddr{};
        get_attrs_value(SAI_NEXT_HOP_ATTR_IP, attrs, ipaddr, true);
        uint32_t id;

        // loopback port as nexthop is not supported
        if (rif_entry.l3_port == nullptr) {
            sai_log_error(SAI_API_NEXT_HOP, "Use of loopback port interface as next hop is not supported. 0x%x", obj_rif_id);
            return SAI_STATUS_INVALID_PARAMETER;
        }

        txn.status = sdev->m_next_hops.allocate_id(id);
        sai_return_on_la_error(txn.status, "Out of nexthop IDs");
        txn.on_fail([=]() { sdev->m_next_hops.release_id(id); });

        la_nh.index = id;
        la_next_hop::nh_type_e la_nh_type = la_next_hop::nh_type_e::NORMAL;
        la_mac_addr_t mac_addr{};
        la_ipv6_addr_t v6_ip_addr;
        la_ipv4_addr_t v4_ip_addr;

        if (ipaddr.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
            v4_ip_addr.s_addr = ntohl(ipaddr.addr.ip4);

            if (rif_entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
                la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)rif_entry.l3_port);
                la_class_id_t class_id;
                txn.status = l3ac->get_ipv4_host_and_class_id(v4_ip_addr, mac_addr, class_id);
            } else if (rif_entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
                la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)rif_entry.l3_port);
                la_class_id_t class_id;
                txn.status = sviport->get_ipv4_host_and_class_id(v4_ip_addr, mac_addr, class_id);
            }
        } else { // IPV6
            reverse_copy(std::begin(ipaddr.addr.ip6), std::end(ipaddr.addr.ip6), std::begin(v6_ip_addr.b_addr));

            auto it = rif_entry.m_v6_link_locals.find(v6_ip_addr);
            if (it != rif_entry.m_v6_link_locals.end()) {
                mac_addr = it->second;
            } else if (rif_entry.l3_port->type() == la_object::object_type_e::L3_AC_PORT) {
                la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)rif_entry.l3_port);
                la_class_id_t class_id;
                txn.status = l3ac->get_ipv6_host_and_class_id(v6_ip_addr, mac_addr, class_id);
            } else if (rif_entry.l3_port->type() == la_object::object_type_e::SVI_PORT) {
                la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)rif_entry.l3_port);
                la_class_id_t class_id;
                txn.status = sviport->get_ipv6_host_and_class_id(v6_ip_addr, mac_addr, class_id);
            }
        }

        if (txn.status != LA_STATUS_SUCCESS) {
            la_nh_type = la_next_hop::nh_type_e::GLEAN;
        }

        txn.status = sdev->m_dev->create_next_hop(la_nh.index, mac_addr, rif_entry.l3_port, la_nh_type, nh_ptr);
        if (txn.status) {
            sai_log_error(SAI_API_NEXT_HOP, "Failed creating next hop. %s", txn.status.message().c_str());
            return to_sai_status(txn.status);
        }
        txn.on_fail([=]() { sdev->m_dev->destroy(nh_ptr); });

        next_hop_entry nh_entry(nh_ptr, next_hop_type, ipaddr);
        if (next_hop_type == SAI_NEXT_HOP_TYPE_MPLS) {
            for (uint32_t i = 0; i < label_stack.count; i++) {
                la_mpls_label label;
                label.label = label_stack.list[i];
                nh_entry.m_labels.push_back(label);
            }
        }

        nh_entry.rif_tun_oid = obj_rif_id;
        txn.status = sdev->m_next_hops.set(*next_hop_id, nh_entry, la_nh);
        sai_return_on_la_error(txn.status, "Failed setting nexthop in obj db. %s", txn.status.message().c_str());
        sai_log_debug(SAI_API_NEXT_HOP, "next_hop 0x%lx created", *next_hop_id);
        txn.on_fail([=]() { sdev->m_next_hops.remove(*next_hop_id); });

        sai_log_info(SAI_API_NEXT_HOP, "next hop 0x%0lx created", *next_hop_id);

        if (ipaddr.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
            rif_entry.m_v4_neighbors[v4_ip_addr] = *next_hop_id;
        } else {
            rif_entry.m_v6_neighbors[v6_ip_addr] = *next_hop_id;
        }

        txn.status = sdev->m_l3_ports.set(la_rif.index, rif_entry);

        return to_sai_status(txn.status);
    }

    case SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP: {
        next_hop_entry nh_entry(next_hop_type);
        get_attrs_value(SAI_NEXT_HOP_ATTR_IP, attrs, nh_entry.ip_addr, true);
        get_attrs_value(SAI_NEXT_HOP_ATTR_TUNNEL_ID, attrs, nh_entry.rif_tun_oid, true);

        std::copy(std::begin(sdev->m_tunnel_manager->m_vxlan_default_router_mac),
                  std::end(sdev->m_tunnel_manager->m_vxlan_default_router_mac),
                  nh_entry.m_tunnel_mac);
        get_mac_attrs_value(SAI_NEXT_HOP_ATTR_TUNNEL_MAC, attrs, nh_entry.m_tunnel_mac, false);

        get_attrs_value(SAI_NEXT_HOP_ATTR_TUNNEL_VNI, attrs, nh_entry.m_encap_vni, false);

        if (nh_entry.ip_addr.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
            status = sdev->m_tunnel_manager->create_tunnel_next_hop_v4(next_hop_id, nh_entry, txn);
        } else {
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
        return to_sai_status(status);
    }
    default:
        break;
    }

    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
remove_next_hop(sai_object_id_t obj_next_hop_id)
{
    sai_start_api(SAI_API_NEXT_HOP, SAI_OBJECT_TYPE_NEXT_HOP, obj_next_hop_id, &nexthop_to_string, obj_next_hop_id);

    next_hop_entry nh_entry{};
    la_status status = sdev->m_next_hops.get(la_obj.index, nh_entry);
    sai_return_on_la_error(status, "Fail to get nexthop for 0x%lx", obj_next_hop_id);

    if (nh_entry.type == SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP) {
        la_status status = sdev->m_tunnel_manager->remove_tunnel_next_hop(obj_next_hop_id);
        return to_sai_status(status);
    }

    lsai_object la_rif(nh_entry.rif_tun_oid);
    if (nh_entry.type == SAI_NEXT_HOP_TYPE_IP || nh_entry.type == SAI_NEXT_HOP_TYPE_MPLS) {
        rif_entry* rif_entry = sdev->m_l3_ports.get_ptr(la_rif.index);
        if (rif_entry != nullptr) {
            if (nh_entry.ip_addr.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
                la_ipv4_addr_t ip_addr;
                ip_addr.s_addr = ntohl(nh_entry.ip_addr.addr.ip4);

                rif_entry->m_v4_neighbors.erase(ip_addr);
            } else {
                la_ipv6_addr_t ip_addr;
                reverse_copy(
                    std::begin(nh_entry.ip_addr.addr.ip6), std::end(nh_entry.ip_addr.addr.ip6), std::begin(ip_addr.b_addr));

                rif_entry->m_v6_neighbors.erase(ip_addr);
            }
        }
    }

    if (nh_entry.m_prefix_object != nullptr) {
        sdev->m_dev->destroy(nh_entry.m_prefix_object);
    }
    status = sdev->m_dev->destroy(nh_entry.next_hop);
    sdev->m_next_hops.remove(obj_next_hop_id);
    return to_sai_status(status);
}

static sai_status_t
set_next_hop_attribute(sai_object_id_t next_hop_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = next_hop_id;

    sai_start_api(SAI_API_NEXT_HOP, SAI_OBJECT_TYPE_NEXT_HOP, next_hop_id, &nexthop_to_string, next_hop_id, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "next hop 0x%lx", next_hop_id);
    return sai_set_attribute(&key, key_str, next_hop_attribs, next_hop_vendor_attribs, attr);
}

static sai_status_t
get_next_hop_attribute(_In_ sai_object_id_t next_hop_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = next_hop_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_NEXT_HOP, SAI_OBJECT_TYPE_NEXT_HOP, next_hop_id, &nexthop_to_string, "next_hop", next_hop_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "next hop 0x%lx", next_hop_id);
    return sai_get_attributes(&key, key_str, next_hop_attribs, next_hop_vendor_attribs, attr_count, attr_list);
}

const sai_next_hop_api_t next_hop_api = {create_next_hop, remove_next_hop, set_next_hop_attribute, get_next_hop_attribute};
}
}
