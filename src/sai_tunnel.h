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

#ifndef __SAI_TUNNEL_H__
#define __SAI_TUNNEL_H__

#include "sai_db.h"
#include "api/types/la_ethernet_types.h"
#include <memory>
#include <set>
#include "sai_next_hop.h"

namespace silicon_one
{
class la_ip_tunnel_port;

namespace sai
{
class tunnel_manager;
struct vrf_entry;

//
// la l3 tunnel model
//
//            dummy    overlay from tunnel
//    svi_1 - switch_1 (vrf_1/vni_1)  v
//                                     v    (encap vni) - from tunnel
//    svi_2 - switch_2 (vrf_2/vni_2)  ---- la_vxlan_l2_service_port
//                                     ^   (local loopback, remote loopback)
//    svi_3 - switch_3 (vrf_3/vni_3)  ^     from tunnel     from next_hop
//
//
//  * Each overlay vrf has a dummy la_switch, a dummy la_svi_port, a decap vni
//    --> vrf_entry {
//          ...
//          la_switch* vxlan_switch
//          la_svi_port* vxlan_svi
//          uint32_t decap_vni
//          ...
//       }
//
//  * Each (sai tunnel, sai vxlan next hop) pair has one la vxlan port
//    --> next_hop_entry {
//         ...
//            la_vxlan_l2_service_port *vxlan_port
//         ...
//         sai_object_id_t rif_tun_oid // rif or tunnel sai object
//       }
//
//  * Each (dummy switch, la vxlan port) pair has an encap vni, a vxlan_next_hop
//    --> vrf_entry {
//            ...
//            m_vxlan_next_hops[next_hop_obj] = la_vxlan_next_hop
//            ...
//        }
//

struct tunnel_t {
    sai_object_id_t m_obj = SAI_NULL_OBJECT_ID;
    sai_tunnel_type_t m_type = SAI_TUNNEL_TYPE_VXLAN;
    sai_object_id_t m_underlay_oid = SAI_NULL_OBJECT_ID; // underlay router interface id
    sai_object_id_t m_overlay_oid = SAI_NULL_OBJECT_ID;
    sai_ip_address_t m_src_ip{};
    sai_tunnel_ttl_mode_t m_encap_ttl_mode = SAI_TUNNEL_TTL_MODE_UNIFORM_MODEL;
    uint8_t m_ttl = 255;
    sai_tunnel_dscp_mode_t m_encap_dscp_mode = SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL;
    uint8_t m_dscp_val = 0;
    bool m_gre_key_valid = false;
    uint32_t m_gre_key = 0;
    sai_tunnel_encap_ecn_mode_t m_encap_ecn_mode = SAI_TUNNEL_ENCAP_ECN_MODE_STANDARD;
    std::vector<sai_object_id_t> m_encap_mappers;
    sai_tunnel_decap_ecn_mode_t m_decap_ecn_mode = SAI_TUNNEL_DECAP_ECN_MODE_STANDARD;
    std::vector<sai_object_id_t> m_decap_mappers;
    sai_tunnel_ttl_mode_t m_decap_ttl_mode = SAI_TUNNEL_TTL_MODE_UNIFORM_MODEL;
    sai_tunnel_dscp_mode_t m_decap_dscp_mode = SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL;
    std::set<sai_object_id_t> m_tunnel_term_set;

    uint32_t encap_vni = 0;
    bool init_done = false;
};

struct tunnel_term_t {
    sai_object_id_t m_oid = SAI_NULL_OBJECT_ID;
    sai_object_id_t m_vrf_oid = SAI_NULL_OBJECT_ID;
    sai_ip_address_t m_dst_ip{};
    sai_ip_address_t m_src_ip{};
    la_obj_wrap<la_ip_tunnel_port> m_tunnel_term_port;
};

// support the following map
// MAP_T::SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID
// SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY, SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE
//
// MAP_T::SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI,
// SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_KEY, SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE
//
// MAP_T::SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI,
// SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY, SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE
//
// MAP_T::SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID,
// SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY, SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_VALUE
//
// MAP_T::SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI,
// SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_KEY, SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE
//
// MAP_T::SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF,
// SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY, SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_VALUE
//

struct tunnel_map_t {
    sai_object_id_t m_obj = SAI_NULL_OBJECT_ID;
    sai_tunnel_map_type_t m_type = SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID;
    std::set<sai_object_id_t> m_entry_list;

    uint32_t ref_count = 0;
};

class tunnel_manager
{
    friend class lsai_device;

    static constexpr int MAX_TUNNELS = 4096;
    static constexpr int MAX_TUNNEL_TERMS = 4096;
    static constexpr int MAX_TUNNEL_MAPS = 4096;
    static constexpr uint32_t INVALID_VNI = 0xffffffff;
    static constexpr int MAX_INTERNAL_BRIDGES = 1024;
    static constexpr int MAX_L3_INTERNAL_PORTS = 1024;

public:
    tunnel_manager() = default; // for warm boot
    tunnel_manager(std::shared_ptr<lsai_device> sdev);

    std::shared_ptr<lsai_device> m_sdev;

    // sai tunnel can be P2P or P2MP
    obj_db<tunnel_t> m_tunnel_db{SAI_OBJECT_TYPE_TUNNEL, MAX_TUNNELS};
    obj_db<tunnel_map_t> m_tunnel_map_db{SAI_OBJECT_TYPE_TUNNEL_MAP, MAX_TUNNEL_MAPS};
    obj_db<tunnel_term_t> m_tunnel_term_db{SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY, MAX_TUNNEL_TERMS};
    ranged_index_generator m_internal_bridge_ids{0, MAX_INTERNAL_BRIDGES};
    ranged_index_generator m_internal_svi_ids{0, MAX_L3_INTERNAL_PORTS};

    la_status create_tunnel_map(tunnel_map_t& tunnel_map, lsai_object& la_tun_map);
    la_status remove_tunnel_map(sai_object_id_t obj);

    // add tunnel map entry to the map's entry list
    la_status add_tunnel_map_entry(uint32_t map_index, sai_object_id_t obj_entry);

    // remove tunnel map entry from the map's entry list
    la_status remove_tunnel_map_entry(uint32_t map_index, sai_object_id_t obj_entry);

    sai_status_t get_tunnel_map_type(uint32_t map_index, sai_attribute_value_t* value);

    sai_status_t get_tunnel_map_entry_list(uint32_t map_index, sai_attribute_value_t* value);

    // main functions for sai apis
    la_status create_tunnel(tunnel_t& tunnel, sai_object_id_t* tunnel_id);

    la_status remove_tunnel(sai_object_id_t obj);

    sai_status_t get_tunnel_attribute(uint32_t tunnel_index, sai_tunnel_attr_t attr_id, sai_attribute_value_t* value);

    la_status create_tunnel_term(tunnel_term_t& tunnel_term, lsai_object& la_tun_term);
    la_status create_tunnel_port(uint32_t tunnel_index, uint32_t tunnel_term_index);
    la_status destroy_tunnel_port(uint32_t tunnel_term_index);
    la_status remove_tunnel_term(sai_object_id_t obj);

    la_status add_term_to_tunnel(uint32_t tunnel_index, sai_object_id_t tun_term_id);
    la_status remove_term_from_tunnel(uint32_t tunnel_index, sai_object_id_t tun_term_id);

    sai_status_t get_tunnel_term_attribute(lsai_object& la_tun_term,
                                           uint32_t tunnel_index,
                                           sai_tunnel_term_table_entry_attr_t attr_id,
                                           sai_attribute_value_t* value);

    la_status create_tunnel_next_hop_v4(sai_object_id_t* next_hop_id, next_hop_entry& nh_entry, transaction& txn);

    la_status remove_tunnel_next_hop(sai_object_id_t obj_next_hop_id);

    la_status update_remote_loopback_route(vrf_entry& vrf_entry, const la_ipv4_addr_t& addr, const la_l3_destination* l3_dest);
    la_status update_remote_loopback_route(vrf_entry& vrf_entry, const la_ipv6_addr_t& addr, const la_l3_destination* l3_dest);

public:
    // default router mac will be ignored by l3 vxlan npl but require for common api
    sai_mac_t m_vxlan_default_router_mac = {0x00, 0xbe, 0xaf, 0xde, 0xad, 0x00};

    uint16_t m_vxlan_default_port = 4789;

    la_status allocate_dummy_gid(ranged_index_generator& ids, uint32_t& out_idx);
    void release_dummy_gid(ranged_index_generator& ids, uint32_t gid);

private:
    la_status allocate_vxlan_gid(uint32_t& gid);
    void release_vxlan_gid(uint32_t gid);
    la_status allocate_l3_port_gid(uint32_t& gid);
    void release_l3_port_gid(uint32_t gid);

    la_status get_vrf_entry_from_rif(sai_object_id_t oid, vrf_entry*& entry) const;

    la_status remove_dummy_vxlan_switch_svi(sai_object_id_t decap_vrf_obj);
    la_status create_dummy_vxlan_switch_svi(sai_object_id_t decap_vrf_obj, uint32_t decap_vni);

    la_status dettach_decap_mappers(tunnel_t* tun_entry);
    la_status attach_decap_mappers(tunnel_t* tun_entry);

    la_status set_encap_vnis_next_hops(sai_object_id_t next_hop_obj, next_hop_entry& nh_entry, tunnel_t* tun_entry);

    la_status remove_encap_vnis_next_hops(sai_object_id_t next_hop_obj, const tunnel_t* tun_entry);

    la_status find_vrf_tunnel_nexthop(sai_object_id_t* next_hop_id,
                                      sai_object_id_t vrf_obj,
                                      sai_ip_address_t& ipaddr,
                                      sai_object_id_t obj_tunnel);

    la_status vxlan_tunnel_initialization(tunnel_t* tunnel);
    la_status create_vxlan_next_hop_v4(sai_object_id_t* next_hop_id,
                                       next_hop_entry& nh_entry,
                                       tunnel_t*& tun_entry,
                                       transaction& txn);

    la_status configure_ipinip_tunnel_port(la_ip_over_ip_tunnel_port* port, tunnel_t* tunnel);
    la_status set_ttl_mode(la_ip_tunnel_port* port, sai_tunnel_ttl_mode_t sai_ttl_mode, uint8_t ttl_val = 0xFF);
    la_status set_qos_mode(la_ip_tunnel_port* port, sai_tunnel_dscp_mode_t sai_dscp_mode, sai_tunnel_decap_ecn_mode_t sai_ecn_mode);
};
}
}

#endif //__SAI_TUNNEL_H__
