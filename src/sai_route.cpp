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

#include "common/ranged_index_generator.h"
#include "sai_device.h"
#include "sai_logger.h"
#include <arpa/inet.h>

namespace silicon_one
{
namespace sai
{

using namespace std;

static sai_status_t route_packet_action_get(_In_ const sai_object_key_t* key,
                                            _Inout_ sai_attribute_value_t* value,
                                            _In_ uint32_t attr_index,
                                            _Inout_ vendor_cache_t* cache,
                                            void* arg);
static sai_status_t route_next_hop_id_get(_In_ const sai_object_key_t* key,
                                          _Inout_ sai_attribute_value_t* value,
                                          _In_ uint32_t attr_index,
                                          _Inout_ vendor_cache_t* cache,
                                          void* arg);
static sai_status_t route_entry_meta_data_get(_In_ const sai_object_key_t* key,
                                              _Inout_ sai_attribute_value_t* value,
                                              _In_ uint32_t attr_index,
                                              _Inout_ vendor_cache_t* cache,
                                              void* arg);
static sai_status_t route_next_hop_id_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
static sai_status_t route_packet_action_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
static sai_status_t route_entry_meta_data_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

// clang-format off
extern const sai_attribute_entry_t route_attribs[]
    = {{SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, true, true, true, true, "Route next hop ID", SAI_ATTR_VAL_TYPE_OID},
       {SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION, false, false, true, true, "Route packet action", SAI_ATTR_VAL_TYPE_S32},
       {SAI_ROUTE_ENTRY_ATTR_USER_TRAP_ID, false, false, false, false, "Route User Def Trap ID for trap log actions", SAI_ATTR_VAL_TYPE_OID},
       {SAI_ROUTE_ENTRY_ATTR_META_DATA, false, false, true, true, "Route entry metadata", SAI_ATTR_VAL_TYPE_U32},
       {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t route_vendor_attribs[] = {
    {SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID,
     {true, false, true, true},
     {true, false, true, true},
     route_next_hop_id_get, nullptr, route_next_hop_id_set, nullptr},

    {SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION,
     {true, false, true, true},
     {true, false, true, true},
     route_packet_action_get, nullptr, route_packet_action_set, nullptr},

    {SAI_ROUTE_ENTRY_ATTR_USER_TRAP_ID,
     {false, false, false, false},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    {SAI_ROUTE_ENTRY_ATTR_META_DATA,
     {true, false, true, true},
     {true, false, true, true},
     route_entry_meta_data_get, nullptr, route_entry_meta_data_set, nullptr},
};
// clang-format on

static la_status
lsai_update_ipv4_route(la_route_entry_action_e action,
                       const std::shared_ptr<lsai_device>& sdev,
                       vrf_entry& ls_vrf,
                       la_ipv4_prefix_t prefix,
                       const la_l3_destination* destination,
                       la_user_data_t user_data,
                       la_class_id_t class_id)
{
    la_ipv4_route_entry_parameters_vec route_entry_vec(1);
    route_entry_vec[0].action = action;
    route_entry_vec[0].prefix = prefix;
    route_entry_vec[0].destination = destination;
    route_entry_vec[0].is_user_data_set = true;
    route_entry_vec[0].user_data = user_data;
    route_entry_vec[0].latency_sensitive = false;
    route_entry_vec[0].class_id = class_id;
    route_entry_vec[0].is_class_id_set = true;
    size_t count;

    la_status status = ls_vrf.vrf->ipv4_route_bulk_updates(route_entry_vec, count);
    la_return_on_error(status, "Failed to modify route, %s", status.message().c_str());

    if (status == LA_STATUS_SUCCESS) {
        status = sdev->m_tunnel_manager->update_remote_loopback_route(ls_vrf, prefix.addr, destination);
        if (status != LA_STATUS_SUCCESS) {
            sai_log_warn(SAI_API_ROUTE, "Failed to update remote loopback route, %s", status.message().c_str());
        }
    }
    return LA_STATUS_SUCCESS;
}

static la_status
lsai_update_ipv6_route(la_route_entry_action_e action,
                       const std::shared_ptr<lsai_device>& sdev,
                       const vrf_entry& ls_vrf,
                       la_ipv6_prefix_t prefix,
                       const la_l3_destination* destination,
                       la_user_data_t user_data,
                       la_class_id_t class_id)
{
    la_ipv6_route_entry_parameters_vec route_entry_vec(1);
    route_entry_vec[0].action = action;
    route_entry_vec[0].prefix = prefix;
    route_entry_vec[0].destination = destination;
    route_entry_vec[0].is_user_data_set = true;
    route_entry_vec[0].user_data = user_data;
    route_entry_vec[0].latency_sensitive = false;
    route_entry_vec[0].class_id = class_id;
    route_entry_vec[0].is_class_id_set = true;
    size_t count;

    la_status status = ls_vrf.vrf->ipv6_route_bulk_updates(route_entry_vec, count);
    la_return_on_error(status, "Failed to modify route, %s", status.message().c_str());
    return LA_STATUS_SUCCESS;
}

static la_status
route_meta_data_set_internal(const sai_route_entry_t* route_entry, uint32_t meta_data)
{
    lsai_object la_sw(route_entry->switch_id);
    auto sdev = la_sw.get_device();
    la_check_object(la_sw, SAI_OBJECT_TYPE_SWITCH, sdev, "switch", route_entry->switch_id);

    if (meta_data > sdev->m_route_user_meta_max) {
        sai_log_error(SAI_API_NEIGHBOR, "Out of range route user meta data 0x%lx provided", meta_data);
        return LA_STATUS_EINVAL;
    }

    vrf_entry vrf_entry{};
    la_status status = sdev->m_vrfs.get(route_entry->vr_id, vrf_entry);
    la_return_on_error(status);
    la_ip_route_info ip_info{};
    if (route_entry->destination.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        la_ipv4_prefix_t ipv4_prefix;
        ipv4_prefix.addr.s_addr = ntohl(route_entry->destination.addr.ip4);
        ipv4_prefix.length = ip_mask_to_length(route_entry->destination.mask.ip4);
        // route meta-data can only be set on existing route
        status = vrf_entry.vrf->get_ipv4_routing_entry(ipv4_prefix, ip_info);
        la_return_on_error(status);
        lsai_update_ipv4_route(
            la_route_entry_action_e::MODIFY, sdev, vrf_entry, ipv4_prefix, ip_info.l3_dest, ip_info.user_data, meta_data);
    } else {
        la_ipv6_prefix_t ipv6_prefix;
        reverse_copy(std::begin(route_entry->destination.addr.ip6),
                     std::end(route_entry->destination.addr.ip6),
                     std::begin(ipv6_prefix.addr.b_addr));
        ipv6_prefix.length = ipv6_mask_to_length(route_entry->destination.mask.ip6);
        // route meta data can only be set on existing route
        status = vrf_entry.vrf->get_ipv6_routing_entry(ipv6_prefix, ip_info);
        la_return_on_error(status);
        status = lsai_update_ipv6_route(
            la_route_entry_action_e::MODIFY, sdev, vrf_entry, ipv6_prefix, ip_info.l3_dest, ip_info.user_data, meta_data);
    }

    la_return_on_error(status, "Failed to set route meta data %d %s", meta_data, status.message().c_str());
    return LA_STATUS_SUCCESS;
}

static la_status
route_packet_action_set_internal(const sai_route_entry_t* route_entry, sai_packet_action_t action)
{
    lsai_object la_sw(route_entry->switch_id);
    auto sdev = la_sw.get_device();
    la_check_object(la_sw, SAI_OBJECT_TYPE_SWITCH, sdev, "switch", route_entry->switch_id);

    vrf_entry vrf_entry{};
    la_status status = sdev->m_vrfs.get(route_entry->vr_id, vrf_entry);
    la_return_on_error(status);

    la_ip_route_info ip_info{};

    if (route_entry->destination.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        la_ipv4_prefix_t ipv4_prefix;
        ipv4_prefix.addr.s_addr = ntohl(route_entry->destination.addr.ip4);
        ipv4_prefix.length = ip_mask_to_length(route_entry->destination.mask.ip4);

        // action can only be set on existing route
        status = vrf_entry.vrf->get_ipv4_routing_entry(ipv4_prefix, ip_info);
        la_return_on_error(status);

        if (ip_info.is_host) {
            // not able to handle the subnet change
            status = LA_STATUS_ENOTIMPLEMENTED;
            la_return_on_error(status, "Can not change subnet action, please remove it, %s", status.message().c_str());
        }

        if (action == SAI_PACKET_ACTION_DROP) {
            // dest = get_drop_destination(); if no nexthop or null nexthop id
            if (ip_info.user_data == lsai_device::ROUTE_NULL_PACKET_FORWARD) {
                // when there is no valid next_hop id, set the user data to SAI_NULL_OBJECT_ID
                return lsai_update_ipv4_route(la_route_entry_action_e::MODIFY,
                                              sdev,
                                              vrf_entry,
                                              ipv4_prefix,
                                              sdev->m_next_hop_drop,
                                              SAI_NULL_OBJECT_ID,
                                              ip_info.class_id);
            }
            // make sure the packet action is drop, ATTR_NEXT_HOP_ID can still be a valid next hop.
            // temp turn off the route to be forwarded.
            return lsai_update_ipv4_route(la_route_entry_action_e::MODIFY,
                                          sdev,
                                          vrf_entry,
                                          ipv4_prefix,
                                          sdev->m_next_hop_drop,
                                          ip_info.user_data,
                                          ip_info.class_id);
        } else if (action == SAI_PACKET_ACTION_TRAP) {
            la_forus_destination* forus_dest = nullptr;
            status = sdev->m_dev->get_forus_destination(forus_dest);
            la_return_on_error(status, "Failed to get forus destination, %s", status.message().c_str());
            // redirect packet to CPU but still keep the nexthop id in user_data (for forward action)
            return lsai_update_ipv4_route(
                la_route_entry_action_e::MODIFY, sdev, vrf_entry, ipv4_prefix, forus_dest, ip_info.user_data, ip_info.class_id);
        } else if (action == SAI_PACKET_ACTION_FORWARD) {
            lsai_object la_nh(ip_info.user_data);
            if (la_nh.type == SAI_OBJECT_TYPE_NEXT_HOP_GROUP) {
                lsai_next_hop_group* nhg_ptr = sdev->m_next_hop_groups.get_ptr(la_nh.index);
                if (nhg_ptr == nullptr || nhg_ptr->m_ecmp_group == nullptr) {
                    sai_log_error(SAI_API_ROUTE, "Failed to get next hop for route, %#llx", ip_info.user_data);
                    return LA_STATUS_EINVAL;
                }
                return lsai_update_ipv4_route(la_route_entry_action_e::MODIFY,
                                              sdev,
                                              vrf_entry,
                                              ipv4_prefix,
                                              nhg_ptr->m_ecmp_group,
                                              ip_info.user_data,
                                              ip_info.class_id);
            } else if (la_nh.type == SAI_OBJECT_TYPE_NEXT_HOP) {
                next_hop_entry nh_entry{};
                status = sdev->m_next_hops.get(la_nh.index, nh_entry);
                la_return_on_error(status, "Failed to get next hop for route, %#llx", ip_info.user_data);

                if (nh_entry.type == SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP) {
                    auto it = vrf_entry.m_vxlan_next_hops.find(ip_info.user_data);
                    if (it == vrf_entry.m_vxlan_next_hops.end()) {
                        sai_log_error(SAI_API_TUNNEL, "Incorrect tunnel next hop 0x%x", ip_info.user_data);
                        return LA_STATUS_EINVAL;
                    }

                    return lsai_update_ipv4_route(la_route_entry_action_e::MODIFY,
                                                  sdev,
                                                  vrf_entry,
                                                  ipv4_prefix,
                                                  it->second,
                                                  ip_info.user_data,
                                                  ip_info.class_id);
                }
                return lsai_update_ipv4_route(la_route_entry_action_e::MODIFY,
                                              sdev,
                                              vrf_entry,
                                              ipv4_prefix,
                                              nh_entry.next_hop,
                                              ip_info.user_data,
                                              ip_info.class_id);
            } else if (la_nh.type == SAI_OBJECT_TYPE_ROUTER_INTERFACE) {
                return la_add_prefix_to_router_interface(vrf_entry, ip_info.user_data, ipv4_prefix);
            } else if (ip_info.user_data == SAI_NULL_OBJECT_ID) {
                if (action == SAI_PACKET_ACTION_FORWARD) {
                    // when there is no next hop id, set the OBJECT_ID to ROUTE_NULL_PACKET_FORWARD
                    return lsai_update_ipv4_route(la_route_entry_action_e::MODIFY,
                                                  sdev,
                                                  vrf_entry,
                                                  ipv4_prefix,
                                                  sdev->m_next_hop_drop,
                                                  lsai_device::ROUTE_NULL_PACKET_FORWARD,
                                                  ip_info.class_id);
                }
                return LA_STATUS_SUCCESS;
            } else {
                return LA_STATUS_SUCCESS;
            }
        }
    } else {
        la_ipv6_prefix_t ipv6_prefix;
        reverse_copy(std::begin(route_entry->destination.addr.ip6),
                     std::end(route_entry->destination.addr.ip6),
                     std::begin(ipv6_prefix.addr.b_addr));
        ipv6_prefix.length = ipv6_mask_to_length(route_entry->destination.mask.ip6);

        // action can only be set on existing route
        status = vrf_entry.vrf->get_ipv6_routing_entry(ipv6_prefix, ip_info);
        la_return_on_error(status);

        if (ip_info.is_host) {
            // not able to handle the subnet change
            status = LA_STATUS_ENOTIMPLEMENTED;
            la_return_on_error(status, "Can not change subnet action, please remove it, %s", status.message().c_str());
        }

        if (action == SAI_PACKET_ACTION_DROP) {
            // dest = get_drop_destination(); if no nexthop or null nexthop id
            return lsai_update_ipv6_route(la_route_entry_action_e::MODIFY,
                                          sdev,
                                          vrf_entry,
                                          ipv6_prefix,
                                          sdev->m_next_hop_drop,
                                          ip_info.user_data,
                                          ip_info.class_id);
        } else if (action == SAI_PACKET_ACTION_TRAP) {
            la_forus_destination* forus_dest = nullptr;
            status = sdev->m_dev->get_forus_destination(forus_dest);
            la_return_on_error(status, "Failed to get forus destination, %s", status.message().c_str());
            return lsai_update_ipv6_route(
                la_route_entry_action_e::MODIFY, sdev, vrf_entry, ipv6_prefix, forus_dest, ip_info.user_data, ip_info.class_id);
        } else if (action == SAI_PACKET_ACTION_FORWARD) {
            lsai_object la_nh(ip_info.user_data);
            if (la_nh.type == SAI_OBJECT_TYPE_NEXT_HOP_GROUP) {
                lsai_next_hop_group* nhg_ptr = sdev->m_next_hop_groups.get_ptr(la_nh.index);
                if (nhg_ptr == nullptr || nhg_ptr->m_ecmp_group == nullptr) {
                    sai_log_error(SAI_API_ROUTE, "Failed to get next hop for route, %#llx", ip_info.user_data);
                    return LA_STATUS_EINVAL;
                }
                return lsai_update_ipv6_route(la_route_entry_action_e::MODIFY,
                                              sdev,
                                              vrf_entry,
                                              ipv6_prefix,
                                              nhg_ptr->m_ecmp_group,
                                              ip_info.user_data,
                                              ip_info.class_id);
            } else if (la_nh.type == SAI_OBJECT_TYPE_NEXT_HOP) {
                next_hop_entry nh_entry{};
                status = sdev->m_next_hops.get(la_nh.index, nh_entry);
                la_return_on_error(status, "Failed to get next hop for route, %#llx", ip_info.user_data);

                if (nh_entry.type == SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP) {
                    auto it = vrf_entry.m_vxlan_next_hops.find(ip_info.user_data);
                    if (it == vrf_entry.m_vxlan_next_hops.end()) {
                        sai_log_error(SAI_API_TUNNEL, "Incorrect tunnel next hop 0x%x", ip_info.user_data);
                        return LA_STATUS_EINVAL;
                    }
                    return lsai_update_ipv6_route(la_route_entry_action_e::MODIFY,
                                                  sdev,
                                                  vrf_entry,
                                                  ipv6_prefix,
                                                  it->second,
                                                  ip_info.user_data,
                                                  ip_info.class_id);
                }
                return lsai_update_ipv6_route(la_route_entry_action_e::MODIFY,
                                              sdev,
                                              vrf_entry,
                                              ipv6_prefix,
                                              nh_entry.next_hop,
                                              ip_info.user_data,
                                              ip_info.class_id);
            } else if (la_nh.type == SAI_OBJECT_TYPE_ROUTER_INTERFACE) {
                return la_add_v6prefix_to_router_interface(vrf_entry, ip_info.user_data, ipv6_prefix);
            } else if (ip_info.user_data == SAI_NULL_OBJECT_ID) {
                if (action == SAI_PACKET_ACTION_FORWARD) {
                    return lsai_update_ipv6_route(la_route_entry_action_e::MODIFY,
                                                  sdev,
                                                  vrf_entry,
                                                  ipv6_prefix,
                                                  sdev->m_next_hop_drop,
                                                  lsai_device::ROUTE_NULL_PACKET_FORWARD,
                                                  ip_info.class_id);
                }
                return LA_STATUS_SUCCESS;
            } else {
                return LA_STATUS_SUCCESS;
            }
        }
    }

    return LA_STATUS_ENOTIMPLEMENTED;
}

static la_status
next_hop_to_l3_destination(const vrf_entry& vrf_entry,
                           sai_object_id_t& next_hop_obj,
                           sai_packet_action_t packet_action,
                           la_l3_destination*& out_l3_destination)
{
    lsai_object la_nh(next_hop_obj);
    auto sdev = la_nh.get_device();
    la_status status;

    switch (packet_action) {
    case SAI_PACKET_ACTION_FORWARD:
        // handled below
        break;

    case SAI_PACKET_ACTION_DROP:
        out_l3_destination = sdev->m_next_hop_drop;
        if (next_hop_obj == lsai_device::ROUTE_NULL_PACKET_FORWARD) {
            next_hop_obj = SAI_NULL_OBJECT_ID;
        }
        return LA_STATUS_SUCCESS;

    case SAI_PACKET_ACTION_TRAP: {
        la_forus_destination* forus_destination = nullptr;
        status = sdev->m_dev->get_forus_destination(forus_destination);
        la_return_on_error(status, "Failed to get forus destination, %s", status.message().c_str());
        out_l3_destination = forus_destination;
        return LA_STATUS_SUCCESS;
    }

    case SAI_PACKET_ACTION_COPY:
    case SAI_PACKET_ACTION_COPY_CANCEL:
    case SAI_PACKET_ACTION_LOG:
    case SAI_PACKET_ACTION_DENY:
    case SAI_PACKET_ACTION_TRANSIT:
        return LA_STATUS_ENOTIMPLEMENTED;

    default:
        return LA_STATUS_EINVAL;
    }

    if (next_hop_obj == SAI_NULL_OBJECT_ID) {
        out_l3_destination = sdev->m_next_hop_drop;
        next_hop_obj = lsai_device::ROUTE_NULL_PACKET_FORWARD;
        return LA_STATUS_SUCCESS;
    }

    switch (la_nh.type) {
    case SAI_OBJECT_TYPE_NEXT_HOP_GROUP: {
        lsai_next_hop_group* nhg_ptr = sdev->m_next_hop_groups.get_ptr(la_nh.index);
        if (nhg_ptr == nullptr || nhg_ptr->m_ecmp_group == nullptr) {
            sai_log_error(SAI_API_ROUTE, "Failed to get next hop group for next_hop_id=%#llx", next_hop_obj);
            return LA_STATUS_EINVAL;
        }
        out_l3_destination = nhg_ptr->m_ecmp_group;
        return LA_STATUS_SUCCESS;
    }

    case SAI_OBJECT_TYPE_NEXT_HOP: {
        next_hop_entry* nh_entry_ptr = nullptr;
        status = sdev->m_next_hops.get_ptr(la_nh.index, nh_entry_ptr);
        la_return_on_error(status, "Failed to get next hop for next_hop_id=%#lx", next_hop_obj);
        next_hop_entry& nh_entry = *nh_entry_ptr;

        if (nh_entry.type == SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP) {
            auto it = vrf_entry.m_vxlan_next_hops.find(next_hop_obj);
            if (it == vrf_entry.m_vxlan_next_hops.end()) {
                sai_log_error(SAI_API_TUNNEL, "Incorrect tunnel next hop next_hop_id=%#lx", next_hop_obj);
                return LA_STATUS_EINVAL;
            }
            out_l3_destination = it->second;
            return LA_STATUS_SUCCESS;
        }

        if (nh_entry.m_labels.size() > 0) {
            // IP route to MPLS, meaning push
            // should be route->prefix object->nh.next_hop
            la_prefix_object* pref_obj = nullptr;

            if (nh_entry.m_prefix_object == nullptr) {
                status = sdev->alloc_prefix_object(la_nh.index, nh_entry);
                la_return_on_error(status, "Failed allocating prefix object for route to next hop %#lx", next_hop_obj);

                status = nh_entry.m_prefix_object->set_destination(nh_entry.next_hop);
                la_return_on_error(status, "Failed setting destination for pref obj for next hop %#lx", next_hop_obj);
            }
            pref_obj = nh_entry.m_prefix_object;

            status = pref_obj->set_nh_lsp_properties(
                nh_entry.next_hop, nh_entry.m_labels, nullptr, la_prefix_object::lsp_counter_mode_e::LABEL);
            la_return_on_error(status, "Failed setting nh lsp properties for next hop %#lx", next_hop_obj);

            out_l3_destination = pref_obj;
            return LA_STATUS_SUCCESS;
        }

        // route directly to next hop
        out_l3_destination = nh_entry.next_hop;
        return LA_STATUS_SUCCESS;
    }

    case SAI_OBJECT_TYPE_PORT: {
        if (next_hop_obj != sdev->m_pci_port_ids[lsai_device::PUNT_SLICE]
            && next_hop_obj != sdev->m_pci_port_ids[lsai_device::INJECTUP_SLICE]) {
            sai_log_error(SAI_API_ROUTE, "NEXT_HOP_ID of type port but id %#lx is not the cpu port", next_hop_obj);
            return LA_STATUS_EINVAL;
        }

        la_forus_destination* forus_destination = nullptr;
        status = sdev->m_dev->get_forus_destination(forus_destination);
        la_return_on_error(status, "Failed to get forus destination, %s", status.message().c_str());
        out_l3_destination = forus_destination;
        return LA_STATUS_SUCCESS;
    }

    default:
        la_return_on_error(status, "Unsupported type %d for next hop %#lx", la_nh.type, next_hop_obj);
        return LA_STATUS_EINVAL;
    }
}

static la_status
route_next_hop_id_set_internal(const sai_route_entry_t* route_entry, sai_object_id_t next_hop_obj)
{
    lsai_object la_sw(route_entry->switch_id);
    lsai_object la_nh(next_hop_obj);
    auto sdev = la_sw.get_device();
    la_check_object(la_sw, SAI_OBJECT_TYPE_SWITCH, sdev, "switch", route_entry->switch_id);

    vrf_entry vrf_entry{};
    lsai_object la_vrf{};
    la_status status = sdev->m_vrfs.get(route_entry->vr_id, vrf_entry, la_vrf);
    la_return_on_error(status);

    lsai_object la_new(next_hop_obj);
    la_ip_route_info ip_info{};

    la_ipv4_prefix_t ipv4_prefix;
    la_ipv6_prefix_t ipv6_prefix;

    if (route_entry->destination.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        ipv4_prefix.addr.s_addr = ntohl(route_entry->destination.addr.ip4);
        ipv4_prefix.length = ip_mask_to_length(route_entry->destination.mask.ip4);
        if (la_new.type == SAI_OBJECT_TYPE_ROUTER_INTERFACE) {
            return la_add_prefix_to_router_interface(vrf_entry, next_hop_obj, ipv4_prefix);
        }
    } else {
        reverse_copy(std::begin(route_entry->destination.addr.ip6),
                     std::end(route_entry->destination.addr.ip6),
                     std::begin(ipv6_prefix.addr.b_addr));
        ipv6_prefix.length = ipv6_mask_to_length(route_entry->destination.mask.ip6);
        if (la_new.type == SAI_OBJECT_TYPE_ROUTER_INTERFACE) {
            return la_add_v6prefix_to_router_interface(vrf_entry, next_hop_obj, ipv6_prefix);
        }
    }

    la_forus_destination* forus_dest = nullptr;
    if (la_new.type == SAI_OBJECT_TYPE_PORT) {
        if (next_hop_obj != sdev->m_pci_port_ids[lsai_device::PUNT_SLICE]
            && next_hop_obj != sdev->m_pci_port_ids[lsai_device::INJECTUP_SLICE]) {
            sai_log_error(SAI_API_ROUTE, "NEXT_HOP_ID of type port but id %#lx is not the cpu port", next_hop_obj);
            return LA_STATUS_EINVAL;
        }
        status = sdev->m_dev->get_forus_destination(forus_dest);
        la_return_on_error(status, "Failed to get forus destination, %s", status.message().c_str());
    }

    if (route_entry->destination.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        status = vrf_entry.vrf->get_ipv4_routing_entry(ipv4_prefix, ip_info);
        la_return_on_error(status);

        if (ip_info.is_host) {
            // not able to handle the subnet change
            status = LA_STATUS_ENOTIMPLEMENTED;
            la_return_on_error(status, "Can not change subnet action, please remove it, %s", status.message().c_str());
        }

        if (la_new.type == SAI_OBJECT_TYPE_PORT) {
            return lsai_update_ipv4_route(
                la_route_entry_action_e::MODIFY, sdev, vrf_entry, ipv4_prefix, forus_dest, next_hop_obj, ip_info.class_id);
        }

        if (next_hop_obj == SAI_NULL_OBJECT_ID) {
            // dest = get_drop_destination(); if no nexthop or null nexthop id
            return lsai_update_ipv4_route(la_route_entry_action_e::MODIFY,
                                          sdev,
                                          vrf_entry,
                                          ipv4_prefix,
                                          sdev->m_next_hop_drop,
                                          next_hop_obj,
                                          ip_info.class_id);
        }

        switch (la_new.type) {
        case SAI_OBJECT_TYPE_NEXT_HOP_GROUP: {
            lsai_next_hop_group* nhg_ptr = sdev->m_next_hop_groups.get_ptr(la_new.index);
            if (nhg_ptr == nullptr || nhg_ptr->m_ecmp_group == nullptr) {
                sai_log_error(SAI_API_ROUTE, "Failed to get next hop for route, %#llx", next_hop_obj);
                return LA_STATUS_EINVAL;
            }

            return lsai_update_ipv4_route(la_route_entry_action_e::MODIFY,
                                          sdev,
                                          vrf_entry,
                                          ipv4_prefix,
                                          nhg_ptr->m_ecmp_group,
                                          next_hop_obj,
                                          ip_info.class_id);
        }

        case SAI_OBJECT_TYPE_NEXT_HOP: {
            next_hop_entry nh_entry{};
            status = sdev->m_next_hops.get(la_new.index, nh_entry);
            la_return_on_error(status, "Failed to get next hop for route, %#lx", next_hop_obj);

            if (nh_entry.type == SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP) {
                auto it = vrf_entry.m_vxlan_next_hops.find(next_hop_obj);
                if (it == vrf_entry.m_vxlan_next_hops.end()) {
                    sai_log_error(SAI_API_TUNNEL, "Incorrect tunnel next hop 0x%x", next_hop_obj);
                    return LA_STATUS_EINVAL;
                }

                return lsai_update_ipv4_route(
                    la_route_entry_action_e::MODIFY, sdev, vrf_entry, ipv4_prefix, it->second, next_hop_obj, ip_info.class_id);
            }

            if (nh_entry.m_labels.size() > 0) {
                // IP route to MPLS, meaning push
                // should be route->prefix object->nh.next_hop
                if (nh_entry.m_prefix_object == nullptr) {
                    status = sdev->alloc_prefix_object(la_new.index, nh_entry);
                    la_return_on_error(status, "Failed allocating prefix object for route to next hop");
                }
                la_prefix_object* pref_obj = nh_entry.m_prefix_object;

                status = pref_obj->set_destination(nh_entry.next_hop);
                la_return_on_error(status, "Failed setting destination for pref obj for next hop %#lx", next_hop_obj);

                status = pref_obj->set_nh_lsp_properties(
                    nh_entry.next_hop, nh_entry.m_labels, nullptr, la_prefix_object::lsp_counter_mode_e::LABEL);
                la_return_on_error(status, "Failed setting nh lsp properties for next hop %#lx", next_hop_obj);

                return lsai_update_ipv4_route(
                    la_route_entry_action_e::MODIFY, sdev, vrf_entry, ipv4_prefix, pref_obj, next_hop_obj, ip_info.class_id);
            }
            return lsai_update_ipv4_route(
                la_route_entry_action_e::MODIFY, sdev, vrf_entry, ipv4_prefix, nh_entry.next_hop, next_hop_obj, ip_info.class_id);
        }

        default:
            return LA_STATUS_ENOTIMPLEMENTED;
        }
    } else {
        status = vrf_entry.vrf->get_ipv6_routing_entry(ipv6_prefix, ip_info);
        la_return_on_error(status);

        if (ip_info.is_host) {
            // not able to handle the subnet change
            status = LA_STATUS_ENOTIMPLEMENTED;
            la_return_on_error(status, "Can not change subnet action, please remove it, %s", status.message().c_str());
        }

        if (la_new.type == SAI_OBJECT_TYPE_PORT) {
            return lsai_update_ipv6_route(
                la_route_entry_action_e::MODIFY, sdev, vrf_entry, ipv6_prefix, forus_dest, next_hop_obj, ip_info.class_id);
        }

        if (next_hop_obj == SAI_NULL_OBJECT_ID) {
            // dest = get_drop_destination(); if no nexthop or null nexthop id
            return lsai_update_ipv6_route(la_route_entry_action_e::MODIFY,
                                          sdev,
                                          vrf_entry,
                                          ipv6_prefix,
                                          sdev->m_next_hop_drop,
                                          next_hop_obj,
                                          ip_info.class_id);
        }

        switch (la_new.type) {
        case SAI_OBJECT_TYPE_NEXT_HOP_GROUP: {
            lsai_next_hop_group* nhg_ptr = sdev->m_next_hop_groups.get_ptr(la_new.index);
            if (nhg_ptr == nullptr || nhg_ptr->m_ecmp_group == nullptr) {
                sai_log_error(SAI_API_ROUTE, "Failed to get next hop for route, %#llx", next_hop_obj);
                return LA_STATUS_EINVAL;
            }

            return lsai_update_ipv6_route(la_route_entry_action_e::MODIFY,
                                          sdev,
                                          vrf_entry,
                                          ipv6_prefix,
                                          nhg_ptr->m_ecmp_group,
                                          next_hop_obj,
                                          ip_info.class_id);
        }
        case SAI_OBJECT_TYPE_NEXT_HOP: {
            next_hop_entry nh_entry{};
            status = sdev->m_next_hops.get(la_new.index, nh_entry);
            la_return_on_error(status, "Failed to get next hop for route, %#lx", next_hop_obj);

            if (nh_entry.type == SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP) {
                auto it = vrf_entry.m_vxlan_next_hops.find(next_hop_obj);
                if (it == vrf_entry.m_vxlan_next_hops.end()) {
                    sai_log_error(SAI_API_TUNNEL, "Incorrect tunnel next hop 0x%x", next_hop_obj);
                    return LA_STATUS_EINVAL;
                }

                return lsai_update_ipv6_route(
                    la_route_entry_action_e::MODIFY, sdev, vrf_entry, ipv6_prefix, it->second, next_hop_obj, ip_info.class_id);
            }

            if (nh_entry.m_labels.size() > 0) {
                // IP route to MPLS, meaning push
                // should be route->prefix object->nh.next_hop
                la_prefix_object* pref_obj = nullptr;

                if (nh_entry.m_prefix_object == nullptr) {
                    status = sdev->alloc_prefix_object(la_nh.index, nh_entry);
                    la_return_on_error(status, "Failed allocating prefix object for route to next hop %#lx", next_hop_obj);

                    status = nh_entry.m_prefix_object->set_destination(nh_entry.next_hop);
                    la_return_on_error(status, "Failed setting destination for pref obj for next hop %#lx", next_hop_obj);
                }
                pref_obj = nh_entry.m_prefix_object;

                status = pref_obj->set_nh_lsp_properties(
                    nh_entry.next_hop, nh_entry.m_labels, nullptr, la_prefix_object::lsp_counter_mode_e::LABEL);
                la_return_on_error(status, "Failed setting nh lsp properties for next hop %#lx", next_hop_obj);

                return lsai_update_ipv6_route(
                    la_route_entry_action_e::MODIFY, sdev, vrf_entry, ipv6_prefix, pref_obj, next_hop_obj, ip_info.class_id);
            }

            return lsai_update_ipv6_route(
                la_route_entry_action_e::MODIFY, sdev, vrf_entry, ipv6_prefix, nh_entry.next_hop, next_hop_obj, ip_info.class_id);
        }

        default:
            return LA_STATUS_ENOTIMPLEMENTED;
        }
    }

    return LA_STATUS_SUCCESS;
}

static sai_status_t
route_next_hop_id_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (!key || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    const sai_route_entry_t* route_entry = &key->key.route_entry;
    auto next_hop_obj = get_attr_value(SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, (*value));

    la_status status = route_next_hop_id_set_internal(route_entry, next_hop_obj);
    if (status == LA_STATUS_SUCCESS || status == LA_STATUS_EEXIST) {
        return SAI_STATUS_SUCCESS;
    }

    return to_sai_status(status);
}

static sai_status_t
route_next_hop_id_get(_In_ const sai_object_key_t* key,
                      _Inout_ sai_attribute_value_t* value,
                      _In_ uint32_t attr_index,
                      _Inout_ vendor_cache_t* cache,
                      void* arg)
{
    if (!key || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    const sai_route_entry_t* route_entry = &key->key.route_entry;

    // route_key_to_str(unicast_route_entry, key_str);

    la_status status = sai_route_get_next_hop_id(route_entry->switch_id, route_entry->vr_id, route_entry->destination, value);

    return to_sai_status(status);
}

la_status
sai_route_get_next_hop_id(sai_object_id_t switch_id,
                          sai_object_id_t vrf_id,
                          const sai_ip_prefix_t& ip_prefix,
                          sai_attribute_value_t* value,
                          bool lpm_lkup)
{
    lsai_object la_sw(switch_id);
    auto sdev = la_sw.get_device();

    vrf_entry vrf_entry{};
    lsai_object la_vf{};
    la_status status = sdev->m_vrfs.get(vrf_id, vrf_entry, la_vf);
    la_return_on_error(status);

    la_ip_route_info route_info{};
    if (ip_prefix.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        la_ipv4_prefix_t ipv4_prefix;
        ipv4_prefix.addr.s_addr = ntohl(ip_prefix.addr.ip4);
        ipv4_prefix.length = ip_mask_to_length(ip_prefix.mask.ip4);
        if (lpm_lkup) {
            la_ipv4_addr_t v4addr;
            v4addr.s_addr = ntohl(ip_prefix.addr.ip4);
            status = vrf_entry.vrf->get_ipv4_route(v4addr, route_info);
            la_return_on_error(status, "LPM route lookup failed, %s", status.message().c_str());
        } else {
            status = vrf_entry.vrf->get_ipv4_routing_entry(ipv4_prefix, route_info);
            la_return_on_error(status, "Failed to get /32 route, %s", status.message().c_str());
        }

        if (route_info.is_host) {
            auto it = vrf_entry.m_v4_local_subnets.find(ipv4_prefix);
            if (it != vrf_entry.m_v4_local_subnets.end()) {
                set_attr_value(SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, (*value), it->second);
                return LA_STATUS_SUCCESS;
            }
        } else if (route_info.user_data == 0 && ipv4_prefix.length == 32 && route_info.l3_dest != nullptr) {
            if (route_info.l3_dest->type() == silicon_one::la_object::object_type_e::NEXT_HOP) {
                const la_next_hop* next_hop = static_cast<const la_next_hop*>(route_info.l3_dest);
                auto nh_gid = next_hop->get_gid();
                lsai_object la_nh(SAI_OBJECT_TYPE_NEXT_HOP, la_sw.index, nh_gid);
                set_attr_value(SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, (*value), la_nh.object_id());
                return LA_STATUS_SUCCESS;
            }
        }
    } else {
        la_ipv6_prefix_t ipv6_prefix;
        reverse_copy(std::begin(ip_prefix.addr.ip6), std::end(ip_prefix.addr.ip6), std::begin(ipv6_prefix.addr.b_addr));
        ipv6_prefix.length = ipv6_mask_to_length(ip_prefix.mask.ip6);

        status = vrf_entry.vrf->get_ipv6_routing_entry(ipv6_prefix, route_info);
        la_return_on_error(status, "Failed to get route, %s", status.message().c_str());
        if (route_info.is_host) {
            auto it = vrf_entry.m_v6_local_subnets.find(ipv6_prefix);
            if (it != vrf_entry.m_v6_local_subnets.end()) {
                set_attr_value(SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, (*value), it->second);
                return LA_STATUS_SUCCESS;
            }
        }
    }

    if (route_info.user_data != SAI_NULL_OBJECT_ID) {
        if (route_info.user_data == lsai_device::ROUTE_NULL_PACKET_FORWARD) {
            set_attr_value(SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, (*value), SAI_NULL_OBJECT_ID);
            return LA_STATUS_SUCCESS;
        }
        lsai_object la_nh(route_info.user_data);
        set_attr_value(SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, (*value), la_nh.object_id());
        return LA_STATUS_SUCCESS;
    } else if (route_info.l3_dest != NULL) {
        if (route_info.l3_dest->type() == la_object::object_type_e::FORUS_DESTINATION) {
            set_attr_value(SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, (*value), sdev->m_pci_port_ids[lsai_device::PUNT_SLICE]);
            return LA_STATUS_SUCCESS;
        }
    }
    return LA_STATUS_SUCCESS;
}

const la_l3_destination*
sai_route_get_la_next_hop(std::shared_ptr<lsai_device> sdev, sai_ip_address_t& ipaddr, sai_object_id_t vrf_oid, bool is_tunnel)
{
    sai_attribute_value_t value;
    sai_ip_prefix_t ip_prefix{};
    ip_prefix.addr_family = ipaddr.addr_family;
    ip_prefix.addr.ip4 = ipaddr.addr.ip4;
    ip_prefix.mask.ip4 = 0xFFFFFFFF;
    la_status status = sai_route_get_next_hop_id(sdev->m_switch_id, vrf_oid, ip_prefix, &value, true);
    if (status != LA_STATUS_SUCCESS) {
        return nullptr;
    }

    lsai_object la_nh(value.oid); // next hop id for remote loopback
    if (la_nh.type == SAI_OBJECT_TYPE_NEXT_HOP) {
        next_hop_entry nh_entry{};
        status = sdev->m_next_hops.get(la_nh.index, nh_entry);
        return nh_entry.next_hop;
    } else if (la_nh.type == SAI_OBJECT_TYPE_NEXT_HOP_GROUP) {
        /*
         * TODO: This logic of getting correct NH should be hidden by the NH
         * group class. sai_route should have no business knowing what is
         * right kind needed for tunnel or otherwise
         * Also one step up, NH or NHG should also be abstracted.
         */
        lsai_next_hop_group* nhg_ptr = sdev->m_next_hop_groups.get_ptr(la_nh.index);
        if (nhg_ptr != nullptr) {
            if (is_tunnel) {
                if (nhg_ptr->m_ecmp_group_stage_2 == nullptr) {
                    // lazy creation of stage 2 ecmp entry for tunnel
                    auto sts = nhg_ptr->create_tunnel_next_hop_group(sdev);
                    if (sts != SAI_STATUS_SUCCESS) {
                        return nullptr;
                    }
                }
                return nhg_ptr->m_ecmp_group_stage_2;
            } else {
                return nhg_ptr->m_ecmp_group;
            }
        }
    }

    return nullptr;
}

static sai_status_t
route_packet_action_get(_In_ const sai_object_key_t* key,
                        _Inout_ sai_attribute_value_t* value,
                        _In_ uint32_t attr_index,
                        _Inout_ vendor_cache_t* cache,
                        void* arg)
{
    if (!key || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    const sai_route_entry_t* route_entry = &key->key.route_entry;

    // route_key_to_str(unicast_route_entry, key_str);

    lsai_object la_sw(route_entry->switch_id);
    auto sdev = la_sw.get_device();
    sai_check_object(la_sw, SAI_OBJECT_TYPE_SWITCH, sdev, "switch", route_entry->switch_id);

    vrf_entry vrf_entry{};
    la_status status = sdev->m_vrfs.get(route_entry->vr_id, vrf_entry);
    sai_return_on_la_error(status);

    la_ip_route_info route_info{};
    if (route_entry->destination.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        la_ipv4_prefix_t ipv4_prefix;
        ipv4_prefix.addr.s_addr = ntohl(route_entry->destination.addr.ip4);
        ipv4_prefix.length = ip_mask_to_length(route_entry->destination.mask.ip4);

        status = vrf_entry.vrf->get_ipv4_routing_entry(ipv4_prefix, route_info);
        sai_return_on_la_error(status, "Failed to get route, %s", status.message().c_str());
    } else {
        la_ipv6_prefix_t ipv6_prefix;
        reverse_copy(std::begin(route_entry->destination.addr.ip6),
                     std::end(route_entry->destination.addr.ip6),
                     std::begin(ipv6_prefix.addr.b_addr));
        ipv6_prefix.length = ipv6_mask_to_length(route_entry->destination.mask.ip6);

        status = vrf_entry.vrf->get_ipv6_routing_entry(ipv6_prefix, route_info);
        sai_return_on_la_error(status, "Failed to get route, %s", status.message().c_str());
    }

    auto action = SAI_PACKET_ACTION_FORWARD;
    lsai_object la_nh(route_info.user_data);

    if (route_info.is_host) {
        set_attr_value(SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION, (*value), action);
        return SAI_STATUS_SUCCESS;
    }

    la_forus_destination* forus_dest = nullptr;
    status = sdev->m_dev->get_forus_destination(forus_dest);
    sai_return_on_la_error(status, "Failed to get forus destination, %s", status.message().c_str());

    if (route_info.l3_dest == sdev->m_next_hop_drop && route_info.user_data != lsai_device::ROUTE_NULL_PACKET_FORWARD) {
        action = SAI_PACKET_ACTION_DROP;
    } else if (route_info.l3_dest == forus_dest) {
        // objecdt type port dest to forus counted as forwarding instead of trap
        if (la_nh.type != SAI_OBJECT_TYPE_PORT) {
            action = SAI_PACKET_ACTION_TRAP;
        }
    }

    set_attr_value(SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION, (*value), action);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
route_entry_meta_data_get(_In_ const sai_object_key_t* key,
                          _Inout_ sai_attribute_value_t* value,
                          _In_ uint32_t attr_index,
                          _Inout_ vendor_cache_t* cache,
                          void* arg)
{
    if (!key || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    const sai_route_entry_t* route_entry = &key->key.route_entry;
    lsai_object la_sw(route_entry->switch_id);
    auto sdev = la_sw.get_device();
    sai_check_object(la_sw, SAI_OBJECT_TYPE_SWITCH, sdev, "switch", route_entry->switch_id);

    vrf_entry vrf_entry{};
    la_status status = sdev->m_vrfs.get(route_entry->vr_id, vrf_entry);
    sai_return_on_la_error(status);

    la_ip_route_info route_info{};
    if (route_entry->destination.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        la_ipv4_prefix_t ipv4_prefix;
        ipv4_prefix.addr.s_addr = ntohl(route_entry->destination.addr.ip4);
        ipv4_prefix.length = ip_mask_to_length(route_entry->destination.mask.ip4);
        status = vrf_entry.vrf->get_ipv4_routing_entry(ipv4_prefix, route_info);
        sai_return_on_la_error(status, "Failed to get route, %s", status.message().c_str());
    } else {
        la_ipv6_prefix_t ipv6_prefix;
        reverse_copy(std::begin(route_entry->destination.addr.ip6),
                     std::end(route_entry->destination.addr.ip6),
                     std::begin(ipv6_prefix.addr.b_addr));
        ipv6_prefix.length = ipv6_mask_to_length(route_entry->destination.mask.ip6);
        status = vrf_entry.vrf->get_ipv6_routing_entry(ipv6_prefix, route_info);
        sai_return_on_la_error(status, "Failed to get route, %s", status.message().c_str());
    }

    uint32_t route_meta_data = (route_info.class_id != LA_CLASS_ID_DEFAULT) ? route_info.class_id : LA_CLASS_ID_DEFAULT;
    set_attr_value(SAI_ROUTE_ENTRY_ATTR_META_DATA, (*value), route_meta_data);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
route_packet_action_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (!key || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    const sai_route_entry_t* route_entry = &key->key.route_entry;
    auto action = get_attr_value(SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION, (*value));

    la_status status = route_packet_action_set_internal(route_entry, action);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
route_entry_meta_data_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (!key || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    const sai_route_entry_t* route_entry = &key->key.route_entry;
    uint32_t meta_data = LA_CLASS_ID_DEFAULT;
    meta_data = get_attr_value(SAI_ROUTE_ENTRY_ATTR_META_DATA, (*value));

    return to_sai_status(route_meta_data_set_internal(route_entry, meta_data));
}

static std::string
route_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_route_entry_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static la_status
route_entry_create_or_prepare(const std::shared_ptr<lsai_device>& sdev,
                              sai_object_id_t vrf_id,
                              const sai_ip_prefix_t& prefix,
                              sai_object_id_t next_hop_obj,
                              sai_packet_action_t packet_action,
                              la_class_id_t class_id,
                              unordered_map<sai_object_id_t, la_ipv4_route_entry_parameters_vec>& ipv4_updates,
                              unordered_map<sai_object_id_t, la_ipv6_route_entry_parameters_vec>& ipv6_updates,
                              uint32_t route_index,
                              unordered_map<sai_object_id_t, vector<uint32_t>>& ipv4_updates_route_indices,
                              unordered_map<sai_object_id_t, vector<uint32_t>>& ipv6_updates_route_indices)
{
    vrf_entry* vrf_entry_ptr = nullptr;
    lsai_object la_vrf(vrf_id);
    la_status status = sdev->m_vrfs.get_ptr(la_vrf.index, vrf_entry_ptr);
    la_return_on_error_log(status, "Wrong virtual router id=%#lx", vrf_id);
    vrf_entry& vrf_entry = *vrf_entry_ptr;

    lsai_object la_nh(next_hop_obj);

    if (prefix.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        la_ipv4_prefix_t ipv4_prefix;
        ipv4_prefix.addr.s_addr = ntohl(prefix.addr.ip4);
        ipv4_prefix.length = ip_mask_to_length(prefix.mask.ip4);

        if (la_nh.type == SAI_OBJECT_TYPE_ROUTER_INTERFACE) {
            return la_add_prefix_to_router_interface(vrf_entry, next_hop_obj, ipv4_prefix);
        }

        la_l3_destination* l3_destination;
        status = next_hop_to_l3_destination(vrf_entry, next_hop_obj, packet_action, l3_destination);
        la_return_on_error(status);

        ipv4_updates[vrf_id].push_back({
            la_route_entry_action_e::ADD,
            ipv4_prefix,
            l3_destination,
            true /*is_class_id_set*/,
            class_id,
            true /*is_user_data_set*/,
            next_hop_obj /*user_data*/,
            false /*latency_sensitive*/
        });
        ipv4_updates_route_indices[vrf_id].push_back(route_index);
    } else {
        la_ipv6_prefix_t ipv6_prefix;
        reverse_copy(std::begin(prefix.addr.ip6), std::end(prefix.addr.ip6), std::begin(ipv6_prefix.addr.b_addr));
        ipv6_prefix.length = ipv6_mask_to_length(prefix.mask.ip6);

        if (la_nh.type == SAI_OBJECT_TYPE_ROUTER_INTERFACE) {
            return la_add_v6prefix_to_router_interface(vrf_entry, next_hop_obj, ipv6_prefix);
        }

        la_l3_destination* l3_destination;
        status = next_hop_to_l3_destination(vrf_entry, next_hop_obj, packet_action, l3_destination);
        la_return_on_error(status);

        ipv6_updates[vrf_id].push_back({
            la_route_entry_action_e::ADD,
            ipv6_prefix,
            l3_destination,
            true /*is_class_id_set*/,
            class_id,
            true /*is_user_data_set*/,
            next_hop_obj /*user_data*/,
            false /*latency_sensitive*/
        });
        ipv6_updates_route_indices[vrf_id].push_back(route_index);
    }

    return LA_STATUS_SUCCESS;
}

static sai_status_t
create_route_entries_internal(const std::shared_ptr<lsai_device>& sdev,
                              uint32_t object_count,
                              const sai_route_entry_t* route_entries,
                              const uint32_t* attr_count,
                              const sai_attribute_t** attr_list,
                              sai_bulk_op_error_mode_t mode,
                              sai_status_t* object_statuses)
{
    sai_status_t total_status = SAI_STATUS_SUCCESS;
    unordered_map<sai_object_id_t, la_ipv4_route_entry_parameters_vec> ipv4_updates;
    unordered_map<sai_object_id_t, la_ipv6_route_entry_parameters_vec> ipv6_updates;
    unordered_map<sai_object_id_t, vector<uint32_t>> ipv4_updates_route_indices;
    unordered_map<sai_object_id_t, vector<uint32_t>> ipv6_updates_route_indices;

    for (uint32_t i = 0; i < object_count; i++) {
        auto attrs = sai_parse_attributes(attr_count[i], attr_list[i]);

        sai_object_id_t next_hop_obj{SAI_NULL_OBJECT_ID};
        get_attrs_value(SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID, attrs, next_hop_obj, false);

        auto class_id = LA_CLASS_ID_DEFAULT;
        get_attrs_value(SAI_ROUTE_ENTRY_ATTR_META_DATA, attrs, class_id, false);

        auto packet_action = SAI_PACKET_ACTION_FORWARD;
        get_attrs_value(SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION, attrs, packet_action, false);

        la_status status = route_entry_create_or_prepare(sdev,
                                                         route_entries[i].vr_id,
                                                         route_entries[i].destination,
                                                         next_hop_obj,
                                                         packet_action,
                                                         class_id,
                                                         ipv4_updates,
                                                         ipv6_updates,
                                                         i,
                                                         ipv4_updates_route_indices,
                                                         ipv6_updates_route_indices);

        object_statuses[i] = to_sai_status(status);

        if (status != LA_STATUS_SUCCESS) {
            total_status = to_sai_status(status);
        }
    }

    for (const auto& vrf_ipv4_updates : ipv4_updates) {
        const sai_object_id_t vfr_id = vrf_ipv4_updates.first;
        vrf_entry* vrf_entry_ptr = nullptr;
        lsai_object la_vrf(vrf_ipv4_updates.first);
        la_status status = sdev->m_vrfs.get_ptr(la_vrf.index, vrf_entry_ptr);
        sai_return_on_la_error(status, "Wrong virtual router id=%#lx", vrf_ipv4_updates.first);
        vrf_entry& vrf_entry = *vrf_entry_ptr;

        const auto& updates = vrf_ipv4_updates.second;
        const uint32_t updates_count = updates.size();
        size_t succeeded_count;
        la_status update_status = vrf_entry.vrf->ipv4_route_bulk_updates(updates, succeeded_count);

        if (update_status == LA_STATUS_SUCCESS && succeeded_count < updates_count) {
            update_status = succeeded_count == 0 ? LA_STATUS_EINVAL : LA_STATUS_ERESOURCE;
        }

        if (update_status != LA_STATUS_SUCCESS) {
            if (total_status == SAI_STATUS_SUCCESS) {
                total_status = to_sai_status(update_status);
            }

            for (uint32_t i = 0; i < updates_count; i++) {
                const auto& update = updates[i];
                const uint32_t route_index = ipv4_updates_route_indices[vfr_id][i];
                la_ip_route_info ip_info;
                auto route_status = vrf_entry.vrf->get_ipv4_routing_entry(update.prefix, ip_info);
                if (route_status != LA_STATUS_SUCCESS || ip_info.l3_dest != update.destination
                    || ip_info.user_data != update.user_data
                    || ip_info.class_id != update.class_id) {

                    object_statuses[route_index] = to_sai_status(update_status);

                    sai_log_debug(SAI_API_ROUTE,
                                  "Failed to create route prefix=%s:"
                                  " desired(la_destination=%s user_data=%#lx class_id=%u)"
                                  " got(la_status=%u la_destination=%s user_data=%#lx class_id=%u)",
                                  silicon_one::to_string(update.prefix).c_str(),
                                  silicon_one::to_string(update.destination).c_str(),
                                  update.user_data,
                                  update.class_id,
                                  route_status.value(),
                                  silicon_one::to_string(ip_info.l3_dest).c_str(),
                                  ip_info.user_data,
                                  ip_info.class_id);
                }
            }
        }

        if (succeeded_count > 0) {
            for (uint32_t i = 0; i < updates_count; i++) {
                const auto& update = updates[i];
                const uint32_t route_index = ipv4_updates_route_indices[vfr_id][i];
                if (object_statuses[route_index] == SAI_STATUS_SUCCESS) {
                    auto tunnel_status
                        = sdev->m_tunnel_manager->update_remote_loopback_route(vrf_entry, update.prefix.addr, update.destination);
                    if (tunnel_status != LA_STATUS_SUCCESS) {
                        sai_log_warn(SAI_API_ROUTE, "Failed to update remote VTEP route: %s", tunnel_status.message().c_str());
                    }
                }
            }
        }
    }

    for (const auto& vrf_ipv6_updates : ipv6_updates) {
        const sai_object_id_t vfr_id = vrf_ipv6_updates.first;
        vrf_entry* vrf_entry_ptr = nullptr;
        lsai_object la_vrf(vrf_ipv6_updates.first);
        la_status status = sdev->m_vrfs.get_ptr(la_vrf.index, vrf_entry_ptr);
        sai_return_on_la_error(status, "Wrong virtual router id=%#lx", vrf_ipv6_updates.first);
        vrf_entry& vrf_entry = *vrf_entry_ptr;

        const auto& updates = vrf_ipv6_updates.second;
        const uint32_t updates_count = updates.size();
        size_t succeeded_count;
        la_status update_status = vrf_entry.vrf->ipv6_route_bulk_updates(updates, succeeded_count);

        if (update_status == LA_STATUS_SUCCESS && succeeded_count < updates_count) {
            update_status = succeeded_count == 0 ? LA_STATUS_EINVAL : LA_STATUS_ERESOURCE;
        }

        if (update_status != LA_STATUS_SUCCESS) {
            if (total_status == SAI_STATUS_SUCCESS) {
                total_status = to_sai_status(update_status);
            }

            for (uint32_t i = 0; i < updates_count; i++) {
                const auto& update = updates[i];
                const uint32_t route_index = ipv6_updates_route_indices[vfr_id][i];
                la_ip_route_info ip_info;
                auto route_status = vrf_entry.vrf->get_ipv6_routing_entry(update.prefix, ip_info);
                if (route_status != LA_STATUS_SUCCESS || ip_info.l3_dest != update.destination
                    || ip_info.user_data != update.user_data
                    || ip_info.class_id != update.class_id) {

                    object_statuses[route_index] = to_sai_status(update_status);

                    sai_log_debug(SAI_API_ROUTE,
                                  "Failed to create route prefix=%s:"
                                  " desired(la_destination=%s user_data=%#lx class_id=%u)"
                                  " got(la_status=%u la_destination=%s user_data=%#lx class_id=%u)",
                                  silicon_one::to_string(update.prefix).c_str(),
                                  silicon_one::to_string(update.destination).c_str(),
                                  update.user_data,
                                  update.class_id,
                                  route_status.value(),
                                  silicon_one::to_string(ip_info.l3_dest).c_str(),
                                  ip_info.user_data,
                                  ip_info.class_id);
                }
            }
        }

        if (succeeded_count > 0) {
            for (uint32_t i = 0; i < updates_count; i++) {
                const auto& update = updates[i];
                const uint32_t route_index = ipv6_updates_route_indices[vfr_id][i];
                if (object_statuses[route_index] == SAI_STATUS_SUCCESS) {
                    auto tunnel_status
                        = sdev->m_tunnel_manager->update_remote_loopback_route(vrf_entry, update.prefix.addr, update.destination);
                    if (tunnel_status != LA_STATUS_SUCCESS) {
                        sai_log_warn(SAI_API_ROUTE, "Failed to update remote loopback route: %s", tunnel_status.message().c_str());
                    }
                }
            }
        }
    }

    return total_status;
}

static sai_status_t
create_route_entry(const sai_route_entry_t* route_entry, uint32_t attr_count, const sai_attribute_t* attr_list)
{
    if (!route_entry) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_ROUTE, SAI_OBJECT_TYPE_SWITCH, route_entry->switch_id, route_to_string, route_entry, attrs);

    sai_status_t object_status_unused;
    return create_route_entries_internal(
        sdev, 1, route_entry, &attr_count, &attr_list, SAI_BULK_OP_ERROR_MODE_IGNORE_ERROR /*mode*/, &object_status_unused);
}

static sai_status_t
remove_route_entries_internal(const std::shared_ptr<lsai_device>& sdev,
                              uint32_t object_count,
                              const sai_route_entry_t* route_entries,
                              sai_bulk_op_error_mode_t mode,
                              sai_status_t* object_statuses)
{
    sai_status_t total_status = SAI_STATUS_SUCCESS;
    unordered_map<sai_object_id_t, la_ipv4_route_entry_parameters_vec> ipv4_updates;
    unordered_map<sai_object_id_t, la_ipv6_route_entry_parameters_vec> ipv6_updates;
    unordered_map<sai_object_id_t, vector<uint32_t>> ipv4_updates_route_indices;
    unordered_map<sai_object_id_t, vector<uint32_t>> ipv6_updates_route_indices;
    la_ip_route_info ip_info{};

    for (uint32_t i = 0; i < object_count; i++) {
        const auto* route_entry = &route_entries[i];
        const sai_object_id_t vfr_id = route_entry->vr_id;
        vrf_entry* vrf_entry_ptr = nullptr;
        lsai_object la_vrf(vfr_id);
        la_status status = sdev->m_vrfs.get_ptr(la_vrf.index, vrf_entry_ptr);
        sai_return_on_la_error(status, "Wrong virtual router id=%#lx", vfr_id);
        vrf_entry& vrf_entry = *vrf_entry_ptr;

        if (route_entry->destination.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
            la_ipv4_prefix_t ipv4_prefix;
            ipv4_prefix.addr.s_addr = ntohl(route_entry->destination.addr.ip4);
            ipv4_prefix.length = ip_mask_to_length(route_entry->destination.mask.ip4);

            status = vrf_entry.vrf->get_ipv4_routing_entry(ipv4_prefix, ip_info);
            if (status == LA_STATUS_SUCCESS && ip_info.is_host) {
                status = la_remove_prefix_from_router_interface(vrf_entry, ipv4_prefix);
                if (status != LA_STATUS_SUCCESS) {
                    object_statuses[i] = to_sai_status(status);
                    total_status = to_sai_status(status);
                    sai_log_error(SAI_API_ROUTE, "Failed to remove route %s", to_string(route_entry).c_str());
                }
            } else {
                ipv4_updates[vfr_id].push_back({
                    la_route_entry_action_e::DELETE,
                    ipv4_prefix,
                    nullptr,
                    false /*is_class_id_set*/,
                    0,
                    false /*is_user_data_set*/,
                    0 /*user_data*/,
                    false /*latency_sensitive*/
                });
                ipv4_updates_route_indices[vfr_id].push_back(i);
            }
        } else {
            la_ipv6_prefix_t ipv6_prefix;
            reverse_copy(std::begin(route_entry->destination.addr.ip6),
                         std::end(route_entry->destination.addr.ip6),
                         std::begin(ipv6_prefix.addr.b_addr));
            ipv6_prefix.length = ipv6_mask_to_length(route_entry->destination.mask.ip6);

            status = vrf_entry.vrf->get_ipv6_routing_entry(ipv6_prefix, ip_info);
            if (status == LA_STATUS_SUCCESS && ip_info.is_host) {
                status = la_remove_v6prefix_from_router_interface(vrf_entry, ipv6_prefix);
                if (status != LA_STATUS_SUCCESS) {
                    object_statuses[i] = to_sai_status(status);
                    total_status = to_sai_status(status);
                    sai_log_error(SAI_API_ROUTE, "Failed to remove route %s", to_string(route_entry).c_str());
                }
            } else {
                ipv6_updates[vfr_id].push_back({
                    la_route_entry_action_e::DELETE,
                    ipv6_prefix,
                    nullptr,
                    false /*is_class_id_set*/,
                    0,
                    false /*is_user_data_set*/,
                    0 /*user_data*/,
                    false /*latency_sensitive*/
                });
                ipv6_updates_route_indices[vfr_id].push_back(i);
            }
        }
    }

    for (const auto& vrf_ipv4_updates : ipv4_updates) {
        const sai_object_id_t vfr_id = vrf_ipv4_updates.first;
        vrf_entry* vrf_entry_ptr = nullptr;
        lsai_object la_vrf(vfr_id);
        la_status status = sdev->m_vrfs.get_ptr(la_vrf.index, vrf_entry_ptr);
        sai_return_on_la_error(status, "Wrong virtual router id=%#lx", vfr_id);
        vrf_entry& vrf_entry = *vrf_entry_ptr;

        const auto& updates = vrf_ipv4_updates.second;
        const uint32_t updates_count = updates.size();
        size_t succeeded_count;
        la_status update_status = vrf_entry.vrf->ipv4_route_bulk_updates(updates, succeeded_count);

        if (update_status == LA_STATUS_SUCCESS && succeeded_count < updates_count) {
            update_status = succeeded_count == 0 ? LA_STATUS_EINVAL : LA_STATUS_ERESOURCE;
        }

        if (update_status != LA_STATUS_SUCCESS) {
            if (total_status == SAI_STATUS_SUCCESS) {
                total_status = to_sai_status(update_status);
            }

            for (uint32_t i = 0; i < updates_count; i++) {
                const auto& update = updates[i];
                const uint32_t route_index = ipv4_updates_route_indices[vfr_id][i];
                la_ip_route_info ip_info;
                auto route_status = vrf_entry.vrf->get_ipv4_routing_entry(update.prefix, ip_info);
                if (route_status == LA_STATUS_SUCCESS) {
                    object_statuses[route_index] = to_sai_status(update_status);

                    sai_log_debug(SAI_API_ROUTE,
                                  "Failed to remove route prefix=%s:"
                                  " got(la_destination=%s user_data=%#lx class_id=%u)",
                                  silicon_one::to_string(update.prefix).c_str(),
                                  silicon_one::to_string(ip_info.l3_dest).c_str(),
                                  ip_info.user_data,
                                  ip_info.class_id);
                }
            }
        }
    }

    for (const auto& vrf_ipv6_updates : ipv6_updates) {
        const sai_object_id_t vfr_id = vrf_ipv6_updates.first;
        vrf_entry* vrf_entry_ptr = nullptr;
        lsai_object la_vrf(vfr_id);
        la_status status = sdev->m_vrfs.get_ptr(la_vrf.index, vrf_entry_ptr);
        sai_return_on_la_error(status, "Wrong virtual router id=%#lx", vfr_id);
        vrf_entry& vrf_entry = *vrf_entry_ptr;

        const auto& updates = vrf_ipv6_updates.second;
        const uint32_t updates_count = updates.size();
        size_t succeeded_count;
        la_status update_status = vrf_entry.vrf->ipv6_route_bulk_updates(updates, succeeded_count);

        if (update_status == LA_STATUS_SUCCESS && succeeded_count < updates_count) {
            update_status = succeeded_count == 0 ? LA_STATUS_EINVAL : LA_STATUS_ERESOURCE;
        }

        if (update_status != LA_STATUS_SUCCESS) {
            if (total_status == SAI_STATUS_SUCCESS) {
                total_status = to_sai_status(update_status);
            }

            for (uint32_t i = 0; i < updates_count; i++) {
                const auto& update = updates[i];
                const uint32_t route_index = ipv6_updates_route_indices[vfr_id][i];
                la_ip_route_info ip_info;
                auto route_status = vrf_entry.vrf->get_ipv6_routing_entry(update.prefix, ip_info);
                if (route_status == LA_STATUS_SUCCESS) {
                    object_statuses[route_index] = to_sai_status(update_status);

                    sai_log_debug(SAI_API_ROUTE,
                                  "Failed to remove route prefix=%s:"
                                  " got(la_destination=%s user_data=%#lx class_id=%u)",
                                  silicon_one::to_string(update.prefix).c_str(),
                                  silicon_one::to_string(ip_info.l3_dest).c_str(),
                                  ip_info.user_data,
                                  ip_info.class_id);
                }
            }
        }
    }

    return total_status;
}

static sai_status_t
remove_route_entry(const sai_route_entry_t* route_entry)
{
    if (!route_entry) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_start_api(SAI_API_ROUTE, SAI_OBJECT_TYPE_SWITCH, route_entry->switch_id, &route_to_string, route_entry);

    sai_status_t object_status_ignored;
    return remove_route_entries_internal(sdev, 1, route_entry, SAI_BULK_OP_ERROR_MODE_IGNORE_ERROR, &object_status_ignored);
}

static sai_status_t
set_route_entry_attribute(const sai_route_entry_t* route_entry, const sai_attribute_t* attr)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.route_entry = *route_entry;

    sai_start_api(SAI_API_ROUTE, SAI_OBJECT_TYPE_SWITCH, route_entry->switch_id, &route_to_string, route_entry, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "route %s", to_string(route_entry->destination.addr.ip6).c_str());
    return sai_set_attribute(&key, key_str, route_attribs, route_vendor_attribs, attr);
}

static sai_status_t
get_route_entry_attribute(const sai_route_entry_t* route_entry, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.route_entry = *route_entry;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_ROUTE, SAI_OBJECT_TYPE_SWITCH, route_entry->switch_id, &route_to_string, route_entry, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "route %s", to_string(route_entry->destination.addr.ip6).c_str());
    return sai_get_attributes(&key, key_str, route_attribs, route_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
create_route_entries(uint32_t object_count,
                     const sai_route_entry_t* route_entry,
                     const uint32_t* attr_count,
                     const sai_attribute_t** attr_list,
                     sai_bulk_op_error_mode_t mode,
                     sai_status_t* object_statuses)
{
    if (object_count == 0) {
        return SAI_STATUS_SUCCESS;
    }

    if (!route_entry || !attr_count || !attr_list || !object_statuses) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto switch_id = route_entry[0].switch_id;
    for (uint32_t i = 1; i < object_count; i++) {
        if (route_entry[i].switch_id != switch_id) {
            sai_log_error(SAI_API_ROUTE, "%s: multiple switches in one operation is not implemented");
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
    }

    sai_start_api(SAI_API_ROUTE, SAI_OBJECT_TYPE_SWITCH, switch_id, route_to_string, "object_count", object_count);

    return create_route_entries_internal(sdev, object_count, route_entry, attr_count, attr_list, mode, object_statuses);
}

static sai_status_t
remove_route_entries(uint32_t object_count,
                     const sai_route_entry_t* route_entry,
                     sai_bulk_op_error_mode_t mode,
                     sai_status_t* object_statuses)
{
    if (object_count == 0) {
        return SAI_STATUS_SUCCESS;
    }

    if (!route_entry) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto switch_id = route_entry[0].switch_id;
    for (uint32_t i = 1; i < object_count; i++) {
        if (route_entry[i].switch_id != switch_id) {
            sai_log_error(SAI_API_ROUTE, "%s: multiple switches in one operation is not implemented");
            return SAI_STATUS_NOT_IMPLEMENTED;
        }
    }

    sai_start_api(SAI_API_ROUTE, SAI_OBJECT_TYPE_SWITCH, switch_id, route_to_string, "object_count", object_count);

    return remove_route_entries_internal(sdev, object_count, route_entry, mode, object_statuses);
}

static sai_status_t
set_route_entries_attribute(uint32_t object_count,
                            const sai_route_entry_t* route_entry,
                            const sai_attribute_t* attr_list,
                            sai_bulk_op_error_mode_t mode,
                            sai_status_t* object_statuses)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_route_entries_attribute(uint32_t object_count,
                            const sai_route_entry_t* route_entry,
                            const uint32_t* attr_count,
                            sai_attribute_t** attr_list,
                            sai_bulk_op_error_mode_t mode,
                            sai_status_t* object_statuses)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
laobj_db_route_entry::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    uint32_t idx = 0;
    for (auto& it : sdev->m_vrfs.map()) {
        la_ipv4_route_entry_vec v4_entries;
        la_status sdk_status = it.second.vrf->get_ipv4_route_entries(v4_entries);
        if (sdk_status != LA_STATUS_SUCCESS) {
            sai_log_error(SAI_API_ROUTE, "Failed to get IPv4 route entries from VRF object index %d", it.first);
        } else {
            for (auto sdk_entry : v4_entries) {
                la_ip_route_info ip_info{};
                // skip some internal entries created by SDK
                sdk_status = it.second.vrf->get_ipv4_routing_entry(sdk_entry.prefix, ip_info);
                if (sdk_status != LA_STATUS_SUCCESS) {
                    continue;
                }
                // Route for dropping all multicast, added internally by SDK
                if ((sdk_entry.prefix.addr.s_addr == LA_IPV4_MC_PREFIX.addr.s_addr)
                    && (sdk_entry.prefix.length == LA_IPV4_MC_PREFIX.length)) {
                    continue;
                }
                idx++;
            }
        }

        la_ipv6_route_entry_vec v6_entries;
        sdk_status = it.second.vrf->get_ipv6_route_entries(v6_entries);
        if (sdk_status != LA_STATUS_SUCCESS) {
            sai_log_error(SAI_API_ROUTE, "Failed to get IPv6 route entries from VRF object index %d", it.first);
        } else {
            for (auto sdk_entry : v6_entries) {
                la_ip_route_info ip_info{};
                // skip some internal entries created by SDK
                sdk_status = it.second.vrf->get_ipv6_routing_entry(sdk_entry.prefix, ip_info);
                if (sdk_status != LA_STATUS_SUCCESS) {
                    continue;
                }
                // Route for dropping all multicast, added internally by SDK
                if ((sdk_entry.prefix.length == LA_IPV6_MC_PREFIX.length)
                    && (sdk_entry.prefix.addr.s_addr == LA_IPV6_MC_PREFIX.addr.s_addr)) {
                    continue;
                }
                idx++;
            }
        }

        *count = idx;
    }
    sai_log_debug(SAI_API_SWITCH, "Total %d route entries retrieved", idx);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_route_entry::get_object_keys(std::shared_ptr<lsai_device> sdev,
                                      uint32_t* object_count,
                                      sai_object_key_t* object_list) const
{
    sai_status_t ret_status = SAI_STATUS_SUCCESS;
    uint32_t idx = 0;
    for (auto& it : sdev->m_vrfs.map()) {
        la_ipv4_route_entry_vec v4_entries;
        la_status sdk_status = it.second.vrf->get_ipv4_route_entries(v4_entries);
        if (sdk_status != LA_STATUS_SUCCESS) {
            sai_log_error(SAI_API_ROUTE, "Failed to get IPv4 route entries from VRF object index %d", it.first);
        } else {
            for (auto sdk_entry : v4_entries) {
                la_ip_route_info ip_info{};
                // skip some internal entries created by SDK
                sdk_status = it.second.vrf->get_ipv4_routing_entry(sdk_entry.prefix, ip_info);
                if (sdk_status != LA_STATUS_SUCCESS) {
                    continue;
                }
                // Route for dropping all multicast, added internally by SDK
                if ((sdk_entry.prefix.addr.s_addr == LA_IPV4_MC_PREFIX.addr.s_addr)
                    && (sdk_entry.prefix.length == LA_IPV4_MC_PREFIX.length)) {
                    continue;
                }

                if (*object_count <= idx) {
                    ret_status = SAI_STATUS_BUFFER_OVERFLOW;
                } else {
                    sai_route_entry_t sai_entry{};
                    sai_entry.switch_id = sdev->m_switch_id;
                    // convert SDK VRF ID to SAI vr_id
                    sai_entry.vr_id = it.second.vrf_oid;
                    // convert SDK route entry to sai_ip_prefix_t
                    sai_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
                    sai_entry.destination.addr.ip4 = htonl(sdk_entry.prefix.addr.s_addr);
                    ipv4_prefix_length_to_mask(sdk_entry.prefix.length, sai_entry.destination.mask.ip4);
                    object_list[idx].key.route_entry = sai_entry;
                }
                idx++;
            }
        }

        la_ipv6_route_entry_vec v6_entries;
        sdk_status = it.second.vrf->get_ipv6_route_entries(v6_entries);
        if (sdk_status != LA_STATUS_SUCCESS) {
            sai_log_error(SAI_API_ROUTE, "Failed to get IPv6 route entries from VRF object index %d", it.first);
        } else {
            for (auto sdk_entry : v6_entries) {
                la_ip_route_info ip_info{};
                // skip some internal entries created by SDK
                sdk_status = it.second.vrf->get_ipv6_routing_entry(sdk_entry.prefix, ip_info);
                if (sdk_status != LA_STATUS_SUCCESS) {
                    continue;
                }
                // Route for dropping all multicast, added internally by SDK
                if ((sdk_entry.prefix.length == LA_IPV6_MC_PREFIX.length)
                    && (sdk_entry.prefix.addr.s_addr == LA_IPV6_MC_PREFIX.addr.s_addr)) {
                    continue;
                }

                if (*object_count <= idx) {
                    ret_status = SAI_STATUS_BUFFER_OVERFLOW;
                } else {
                    sai_route_entry_t sai_entry{};
                    sai_entry.switch_id = sdev->m_switch_id;
                    // convert SDK VRF ID to SAI vr_id
                    sai_entry.vr_id = it.second.vrf_oid;
                    // convert SDK route entry to sai_ip_prefix_t
                    sai_entry.destination.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
                    reverse_copy(std::begin(sdk_entry.prefix.addr.b_addr),
                                 std::end(sdk_entry.prefix.addr.b_addr),
                                 std::begin(sai_entry.destination.addr.ip6));
                    ipv6_prefix_length_to_mask(sdk_entry.prefix.length, sai_entry.destination.mask.ip6);
                    object_list[idx].key.route_entry = sai_entry;
                }
                idx++;
            }
        }

        *object_count = idx;
    }
    sai_log_debug(SAI_API_SWITCH, "Total %d route entries retrieved", idx);

    return ret_status;
}

const sai_route_api_t route_api = {
    create_route_entry,
    remove_route_entry,
    set_route_entry_attribute,
    get_route_entry_attribute,

    create_route_entries,
    remove_route_entries,
    set_route_entries_attribute,
    get_route_entries_attribute,
};
}
}
