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

#include "api/npu/la_svi_port.h"
#include "api/npu/la_ip_tunnel_port.h"
#include "api/npu/la_ip_over_ip_tunnel_port.h"
#include "sai_device.h"
#include "sai_logger.h"
#include "arpa/inet.h"
#include "sai_db.h"
#include "sai_tunnel.h"

namespace silicon_one
{
namespace sai
{

using namespace std;

tunnel_manager::tunnel_manager(std::shared_ptr<lsai_device> sdev) : m_sdev(sdev)
{
}

la_status
tunnel_manager::create_tunnel_map(tunnel_map_t& tunnel_map, lsai_object& la_tun_map)
{
    transaction txn;

    txn.status = m_tunnel_map_db.allocate_id(la_tun_map.index);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_tunnel_map_db.release_id(la_tun_map.index); });

    la_tun_map.tunnel_map_type = tunnel_map.m_type;

    txn.status = m_tunnel_map_db.set(la_tun_map.index, tunnel_map);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_tunnel_map_db.erase_id(la_tun_map.index); });

    return txn.status;
}

la_status
tunnel_manager::remove_tunnel_map(sai_object_id_t obj)
{
    la_status status = m_tunnel_map_db.remove(obj);
    la_return_on_error(status);

    return status;
}

la_status
tunnel_manager::add_tunnel_map_entry(uint32_t map_index, sai_object_id_t tun_map_entry_obj)
{
    tunnel_map_t* tun_map = m_tunnel_map_db.get_ptr(map_index);
    if (tun_map == nullptr) {
        return LA_STATUS_EINVAL;
    }

    tun_map->m_entry_list.emplace(tun_map_entry_obj);

    return LA_STATUS_SUCCESS;
    ;
}

la_status
tunnel_manager::remove_tunnel_map_entry(uint32_t map_index, sai_object_id_t tun_map_entry_oid)
{
    tunnel_map_t* tun_map = m_tunnel_map_db.get_ptr(map_index);
    if (tun_map == nullptr) {
        return LA_STATUS_EINVAL;
    }

    tun_map->m_entry_list.erase(tun_map_entry_oid);

    return LA_STATUS_SUCCESS;
}

sai_status_t
tunnel_manager::get_tunnel_map_type(uint32_t map_index, sai_attribute_value_t* value)
{
    tunnel_map_t* tun_map = m_tunnel_map_db.get_ptr(map_index);
    if (tun_map == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    set_attr_value(SAI_TUNNEL_MAP_ATTR_TYPE, *value, tun_map->m_type);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
tunnel_manager::get_tunnel_map_entry_list(uint32_t map_index, sai_attribute_value_t* value)
{
    tunnel_map_t* tun_map = m_tunnel_map_db.get_ptr(map_index);
    if (tun_map == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return fill_sai_list(tun_map->m_entry_list.begin(), tun_map->m_entry_list.end(), value->objlist);
}

// NOTE: All sai_tunnel_attr_t are create only or read only
//       There is not tunnel update.
la_status
tunnel_manager::create_tunnel(tunnel_t& tunnel, sai_object_id_t* tunnel_id)
{
    transaction txn;

    lsai_object la_tun(m_sdev->m_switch_id);
    la_tun.type = SAI_OBJECT_TYPE_TUNNEL;

    txn.status = m_tunnel_db.allocate_id(la_tun.index);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_tunnel_db.release_id(la_tun.index); });

    tunnel.m_obj = la_tun.object_id();
    *tunnel_id = tunnel.m_obj;

    txn.status = m_tunnel_db.set(la_tun.index, tunnel);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_tunnel_db.erase_id(la_tun.index); });

    return txn.status;
}

la_status
tunnel_manager::vxlan_tunnel_initialization(tunnel_t* tunnel)
{
    for (auto it = tunnel->m_encap_mappers.begin(); it != tunnel->m_encap_mappers.end(); ++it) {
        lsai_object la_encap(*it);
        tunnel_map_t* tun_map = m_tunnel_map_db.get_ptr(la_encap.index);
        if (tun_map != nullptr) {
            tun_map->ref_count++;
        }
    }

    // dummy switches are created while the tunnel/tunnel map associated
    return attach_decap_mappers(tunnel);
}

la_status
tunnel_manager::remove_tunnel(sai_object_id_t obj)
{
    lsai_object la_tun(obj);
    tunnel_t* tunnel = m_tunnel_db.get_ptr(la_tun.index);
    if (tunnel == nullptr) {
        // tunnel does not exist
        return LA_STATUS_SUCCESS;
    }

    la_status status = dettach_decap_mappers(tunnel);

    if (tunnel->m_tunnel_term_set.size() > 0) {
        sai_log_error(SAI_API_TUNNEL, "Cannot remove tunnel, tunnel_term used count %d", tunnel->m_tunnel_term_set.size());
        return LA_STATUS_EBUSY;
    }

    for (auto it = tunnel->m_encap_mappers.begin(); it != tunnel->m_encap_mappers.end(); ++it) {
        lsai_object la_encap(*it);
        tunnel_map_t* tun_map = m_tunnel_map_db.get_ptr(la_encap.index);
        if (tun_map != nullptr) {
            tun_map->ref_count--;
        }
    }

    for (auto it = tunnel->m_decap_mappers.begin(); it != tunnel->m_decap_mappers.end(); ++it) {
        lsai_object la_decap(*it);
        tunnel_map_t* tun_map = m_tunnel_map_db.get_ptr(la_decap.index);
        if (tun_map == nullptr) {
            tun_map->ref_count--;
        }
    }

    status = m_tunnel_db.remove(obj);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

sai_status_t
tunnel_manager::get_tunnel_attribute(uint32_t index, sai_tunnel_attr_t attr_id, sai_attribute_value_t* value)
{
    tunnel_t* tunnel = m_tunnel_db.get_ptr(index);
    if (tunnel == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (attr_id) {
    case SAI_TUNNEL_ATTR_TYPE:
        set_attr_value(SAI_TUNNEL_ATTR_TYPE, *value, tunnel->m_type);
        break;
    case SAI_TUNNEL_ATTR_OVERLAY_INTERFACE:
        set_attr_value(SAI_TUNNEL_ATTR_OVERLAY_INTERFACE, *value, tunnel->m_overlay_oid);
        break;
    case SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE:
        set_attr_value(SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE, *value, tunnel->m_underlay_oid);
        break;
    case SAI_TUNNEL_ATTR_ENCAP_SRC_IP:
        set_attr_value(SAI_TUNNEL_ATTR_ENCAP_SRC_IP, *value, tunnel->m_src_ip);
        break;
    case SAI_TUNNEL_ATTR_ENCAP_TTL_MODE:
        set_attr_value(SAI_TUNNEL_ATTR_ENCAP_TTL_MODE, *value, tunnel->m_encap_ttl_mode);
        break;
    case SAI_TUNNEL_ATTR_ENCAP_TTL_VAL:
        set_attr_value(SAI_TUNNEL_ATTR_ENCAP_TTL_VAL, *value, tunnel->m_ttl);
        break;
    case SAI_TUNNEL_ATTR_ENCAP_DSCP_MODE:
        set_attr_value(SAI_TUNNEL_ATTR_ENCAP_DSCP_MODE, *value, tunnel->m_encap_dscp_mode);
        break;
    case SAI_TUNNEL_ATTR_ENCAP_DSCP_VAL:
        set_attr_value(SAI_TUNNEL_ATTR_ENCAP_DSCP_VAL, *value, tunnel->m_dscp_val);
        break;
    case SAI_TUNNEL_ATTR_ENCAP_GRE_KEY_VALID:
        set_attr_value(SAI_TUNNEL_ATTR_ENCAP_GRE_KEY_VALID, *value, tunnel->m_gre_key_valid);
        break;
    case SAI_TUNNEL_ATTR_ENCAP_GRE_KEY:
        set_attr_value(SAI_TUNNEL_ATTR_ENCAP_GRE_KEY, *value, tunnel->m_gre_key);
        break;
    case SAI_TUNNEL_ATTR_ENCAP_ECN_MODE:
        set_attr_value(SAI_TUNNEL_ATTR_ENCAP_ECN_MODE, *value, tunnel->m_encap_ecn_mode);
        break;
    case SAI_TUNNEL_ATTR_ENCAP_MAPPERS: {
        uint32_t index = 0;
        if (value->objlist.count < tunnel->m_encap_mappers.size()) {
            return SAI_STATUS_BUFFER_OVERFLOW;
        } else {
            value->objlist.count = tunnel->m_encap_mappers.size();
        }

        for (; index < value->objlist.count; index++) {
            value->objlist.list[index] = tunnel->m_encap_mappers[index];
        }
        break;
    }
    case SAI_TUNNEL_ATTR_DECAP_ECN_MODE:
        set_attr_value(SAI_TUNNEL_ATTR_DECAP_ECN_MODE, *value, tunnel->m_decap_ecn_mode);
        break;
    case SAI_TUNNEL_ATTR_DECAP_MAPPERS: {
        uint32_t index = 0;
        if (value->objlist.count < tunnel->m_decap_mappers.size()) {
            return SAI_STATUS_BUFFER_OVERFLOW;
        } else {
            value->objlist.count = tunnel->m_decap_mappers.size();
        }

        for (; index < value->objlist.count; index++) {
            value->objlist.list[index] = tunnel->m_decap_mappers[index];
        }
        break;
    }
    case SAI_TUNNEL_ATTR_DECAP_TTL_MODE:
        set_attr_value(SAI_TUNNEL_ATTR_DECAP_TTL_MODE, *value, tunnel->m_decap_ttl_mode);
        break;
    case SAI_TUNNEL_ATTR_DECAP_DSCP_MODE:
        set_attr_value(SAI_TUNNEL_ATTR_DECAP_DSCP_MODE, *value, tunnel->m_decap_dscp_mode);
        break;
    case SAI_TUNNEL_ATTR_TERM_TABLE_ENTRY_LIST:
        return fill_sai_list(tunnel->m_tunnel_term_set.begin(), tunnel->m_tunnel_term_set.end(), value->objlist);
    default:
        break;
    }

    return SAI_STATUS_SUCCESS;
}

la_status
tunnel_manager::create_tunnel_term(tunnel_term_t& tunnel_term, lsai_object& la_tun_term)
{
    transaction txn;

    txn.status = m_tunnel_term_db.insert(tunnel_term, la_tun_term.index);
    la_return_on_error(txn.status);
    txn.on_fail([&]() { m_tunnel_term_db.remove(la_tun_term.index); });

    auto tunnel_index = (uint32_t)la_tun_term.detail.get(lsai_detail_type_e::TUNNEL_TERM, lsai_detail_field_e::TUNNEL);

    txn.status = add_term_to_tunnel(tunnel_index, la_tun_term.object_id());
    la_return_on_error(txn.status);
    txn.on_fail([&]() { remove_term_from_tunnel(tunnel_index, la_tun_term.object_id()); });

    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::remove_tunnel_term(sai_object_id_t oid)
{
    lsai_object la_tun_term(oid);
    auto tunnel_index = (uint32_t)la_tun_term.detail.get(lsai_detail_type_e::TUNNEL_TERM, lsai_detail_field_e::TUNNEL);
    remove_term_from_tunnel(tunnel_index, oid);
    la_status status = m_tunnel_term_db.remove(la_tun_term.index);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::create_tunnel_port(uint32_t tunnel_index, uint32_t tunnel_term_index)
{
    uint32_t tunnel_port_id = 0;
    transaction txn;
    txn.status = allocate_l3_port_gid(tunnel_port_id);
    la_return_on_error(txn.status);
    txn.on_fail([&]() { release_l3_port_gid(tunnel_port_id); });

    tunnel_t* tunnel = m_tunnel_db.get_ptr(tunnel_index);
    if (tunnel == nullptr) {
        txn.status = LA_STATUS_EINVAL;
        la_return_on_error(txn.status);
    }

    tunnel_term_t* tunnel_term = m_tunnel_term_db.get_ptr(tunnel_term_index);
    if (tunnel_term == nullptr) {
        txn.status = LA_STATUS_EINVAL;
        la_return_on_error(txn.status);
    }

    vrf_entry* underlay_vrf = nullptr;
    txn.status = get_vrf_entry_from_rif(tunnel->m_underlay_oid, underlay_vrf);
    la_return_on_error(txn.status);

    vrf_entry* overlay_vrf = nullptr;
    txn.status = get_vrf_entry_from_rif(tunnel->m_overlay_oid, overlay_vrf);
    la_return_on_error(txn.status);

    la_ipv4_addr_t local_ip;
    la_ipv4_addr_t remote_ip;
    la_ipv4_prefix_t local_prefix;
    if (tunnel_term->m_dst_ip.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
        local_ip.s_addr = ntohl(tunnel_term->m_dst_ip.addr.ip4);

        if (tunnel_term->m_src_ip.addr.ip4) {
            // For Point-to-Point tunnels
            remote_ip.s_addr = ntohl(tunnel_term->m_src_ip.addr.ip4);
        } else {
            // For Point-to-Multipoint tunnels
            remote_ip = LA_IPV4_ANY_IP;
        }
        local_prefix = {.addr = local_ip, .length = 32};
    } else {
        txn.status = LA_STATUS_ENOTIMPLEMENTED;
        la_return_on_error(txn.status);
    }

    la_ingress_qos_profile* ingress_profile = m_sdev->m_qos_handler->get_default_ingress_qos_profile();
    txn.status = ingress_profile->set_qos_tag_mapping_enabled(true);
    la_return_on_error(txn.status);

    if (tunnel->m_type == SAI_TUNNEL_TYPE_IPINIP) {
        la_ip_over_ip_tunnel_port* tunnel_port = nullptr;

        txn.status = m_sdev->m_dev->create_ip_over_ip_tunnel_port(tunnel_port_id,
                                                                  underlay_vrf->vrf,
                                                                  local_prefix,
                                                                  remote_ip,
                                                                  overlay_vrf->vrf,
                                                                  ingress_profile,
                                                                  m_sdev->m_qos_handler->get_default_egress_qos_profile(),
                                                                  tunnel_port);
        la_return_on_error(txn.status);
        txn.on_fail([=]() { m_sdev->m_dev->destroy(tunnel_port); });

        txn.status = configure_ipinip_tunnel_port(tunnel_port, tunnel);
        la_return_on_error(txn.status);

        tunnel_term->m_tunnel_term_port = tunnel_port;
    } else {
        txn.status = LA_STATUS_ENOTIMPLEMENTED;
        la_return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::destroy_tunnel_port(uint32_t tunnel_term_index)
{
    tunnel_term_t* tunnel_term = m_tunnel_term_db.get_ptr(tunnel_term_index);
    if (tunnel_term == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (tunnel_term->m_tunnel_term_port != nullptr) {
        m_sdev->m_dev->destroy(tunnel_term->m_tunnel_term_port);
        tunnel_term->m_tunnel_term_port = nullptr;
    }

    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::add_term_to_tunnel(uint32_t tunnel_index, sai_object_id_t tun_term_id)
{
    tunnel_t* tunnel = m_tunnel_db.get_ptr(tunnel_index);
    if (tunnel == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (tunnel->m_type == SAI_TUNNEL_TYPE_IPINIP) {
        lsai_object la_tun_term(tun_term_id);

        la_status status = create_tunnel_port(tunnel_index, la_tun_term.index);
        la_return_on_error(status);
    }

    tunnel->m_tunnel_term_set.emplace(tun_term_id);

    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::remove_term_from_tunnel(uint32_t tunnel_index, sai_object_id_t tun_term_id)
{
    tunnel_t* tunnel = m_tunnel_db.get_ptr(tunnel_index);
    if (tunnel == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (tunnel->m_type == SAI_TUNNEL_TYPE_IPINIP) {
        lsai_object la_tun_term(tun_term_id);
        destroy_tunnel_port(la_tun_term.index);
    }

    tunnel->m_tunnel_term_set.erase(tun_term_id);

    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::configure_ipinip_tunnel_port(la_ip_over_ip_tunnel_port* port, tunnel_t* tunnel)
{
    la_status status;

    status = port->set_lp_attribute_inheritance_mode(la_lp_attribute_inheritance_mode_e::PORT);
    la_return_on_error(status);

    status = set_ttl_mode(port, tunnel->m_decap_ttl_mode, tunnel->m_ttl);
    la_return_on_error(status);

    status = set_qos_mode(port, tunnel->m_decap_dscp_mode, tunnel->m_decap_ecn_mode);
    la_return_on_error(status);

    status = port->set_protocol_enabled(la_l3_protocol_e::IPV4_UC, true);
    status = port->set_protocol_enabled(la_l3_protocol_e::IPV6_UC, true);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::set_qos_mode(la_ip_tunnel_port* port,
                             sai_tunnel_dscp_mode_t sai_dscp_mode,
                             sai_tunnel_decap_ecn_mode_t sai_ecn_mode)
{
    la_mpls_qos_inheritance_mode_e qos_mode;
    switch (sai_dscp_mode) {
    case SAI_TUNNEL_DSCP_MODE_PIPE_MODEL:
        if (sai_ecn_mode == SAI_TUNNEL_DECAP_ECN_MODE_STANDARD) {
            return LA_STATUS_ENOTIMPLEMENTED;
        }
        qos_mode = la_mpls_qos_inheritance_mode_e::PIPE;
        break;
    case SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL:
        if (sai_ecn_mode != SAI_TUNNEL_DECAP_ECN_MODE_COPY_FROM_OUTER) {
            return LA_STATUS_ENOTIMPLEMENTED;
        }
        qos_mode = la_mpls_qos_inheritance_mode_e::UNIFORM;
        break;
    default:
        return LA_STATUS_EINVAL;
    }

    auto status = port->set_qos_inheritance_mode(qos_mode);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::set_ttl_mode(la_ip_tunnel_port* port, sai_tunnel_ttl_mode_t sai_ttl_mode, uint8_t ttl_val)
{
    la_ip_tunnel_port::la_ttl_inheritance_mode_e ttl_mode;
    switch (sai_ttl_mode) {
    case SAI_TUNNEL_TTL_MODE_PIPE_MODEL:
        ttl_mode = la_ip_tunnel_port::la_ttl_inheritance_mode_e::PIPE;
        break;
    case SAI_TUNNEL_TTL_MODE_UNIFORM_MODEL:
        ttl_mode = la_ip_tunnel_port::la_ttl_inheritance_mode_e::UNIFORM;
        break;
    default:
        return LA_STATUS_EINVAL;
    }
    auto status = port->set_ttl_inheritance_mode(ttl_mode);
    la_return_on_error(status);

    status = port->set_ttl(ttl_val);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

sai_status_t
tunnel_manager::get_tunnel_term_attribute(lsai_object& la_tun_term,
                                          uint32_t tunnel_index,
                                          sai_tunnel_term_table_entry_attr_t attr_id,
                                          sai_attribute_value_t* value)
{
    tunnel_t* tunnel = m_tunnel_db.get_ptr(tunnel_index);
    if (tunnel == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    tunnel_term_t* tunnel_term = m_tunnel_term_db.get_ptr(la_tun_term.index);
    if (tunnel_term == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch (attr_id) {
    case SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID:
        set_attr_value(SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID, *value, tunnel_term->m_vrf_oid);
        break;
    case SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP:
        set_attr_value(SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP, *value, tunnel_term->m_dst_ip);
        break;
    case SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_SRC_IP:
        set_attr_value(SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_SRC_IP, *value, tunnel_term->m_src_ip);
        break;
    case SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE:
        set_attr_value(SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE, *value, tunnel->m_type);
        break;
    case SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID:
        set_attr_value(SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID, *value, tunnel->m_obj);
        break;
    case SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE: {
        auto tun_term_type = la_tun_term.detail.get(lsai_detail_type_e::TUNNEL_TERM, lsai_detail_field_e::TYPE);
        set_attr_value(
            SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE, *value, static_cast<sai_tunnel_term_table_entry_type_t>(tun_term_type));
        break;
    }
    default:
        break;
    }
    return SAI_STATUS_SUCCESS;
}

la_status
tunnel_manager::allocate_vxlan_gid(uint32_t& gid)
{
    m_sdev->m_bridge_ports.allocate_id(gid);
    return LA_STATUS_SUCCESS;
}

void
tunnel_manager::release_vxlan_gid(uint32_t gid)
{
    m_sdev->m_bridge_ports.release_id(gid);
}

la_status
tunnel_manager::allocate_l3_port_gid(uint32_t& gid)
{
    m_sdev->m_l3_ports.allocate_id(gid);
    return LA_STATUS_SUCCESS;
}

void
tunnel_manager::release_l3_port_gid(uint32_t gid)
{
    m_sdev->m_l3_ports.release_id(gid);
}

la_status
tunnel_manager::get_vrf_entry_from_rif(sai_object_id_t oid, vrf_entry*& entry) const
{
    lsai_object la_rif(oid);
    rif_entry* rif = m_sdev->m_l3_ports.get_ptr(la_rif.index);
    if (rif == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    lsai_object la_vrf(rif->vrf_obj);
    entry = m_sdev->m_vrfs.get_ptr(la_vrf.index);
    if (entry == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::remove_dummy_vxlan_switch_svi(sai_object_id_t decap_vrf_obj)
{
    lsai_object la_vf(decap_vrf_obj);

    vrf_entry* overlay_vrf_ptr = m_sdev->m_vrfs.get_ptr(la_vf.index);
    if (overlay_vrf_ptr == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    if (overlay_vrf_ptr->vxlan_switch == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    if (overlay_vrf_ptr->vxlan_switch_refcount > 1) {
        overlay_vrf_ptr->vxlan_switch_refcount--;
        return LA_STATUS_SUCCESS;
    }

    // no more referencing object, remove dummy switch and svi
    if (overlay_vrf_ptr->vxlan_svi != nullptr) {
        auto gid = overlay_vrf_ptr->vxlan_svi->get_gid();
        la_status status = m_sdev->m_dev->destroy(overlay_vrf_ptr->vxlan_svi);
        la_return_on_error(status);
        overlay_vrf_ptr->vxlan_svi = nullptr;
        release_dummy_gid(m_internal_svi_ids, gid);
    }

    if (overlay_vrf_ptr->vxlan_switch != nullptr) {
        auto gid = overlay_vrf_ptr->vxlan_switch->get_gid();
        la_status status = overlay_vrf_ptr->vxlan_switch->clear_decap_vni();
        la_return_on_error(status);
        status = m_sdev->m_dev->destroy(overlay_vrf_ptr->vxlan_switch);
        la_return_on_error(status);
        overlay_vrf_ptr->vxlan_switch = nullptr;
        release_dummy_gid(m_internal_bridge_ids, gid);
    }
    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::create_dummy_vxlan_switch_svi(sai_object_id_t decap_vrf_obj, uint32_t decap_vni)
{
    lsai_object la_vf(decap_vrf_obj);

    transaction txn;
    vrf_entry* overlay_vrf_ptr = m_sdev->m_vrfs.get_ptr(la_vf.index);
    if (overlay_vrf_ptr == nullptr) {
        sai_log_error(SAI_API_TUNNEL, "invalid over lay vrf, 0x%lx", decap_vrf_obj);
        return LA_STATUS_EINVAL;
    }

    if (overlay_vrf_ptr->vxlan_switch == nullptr) {
        // create vxlan switch and return not found
        uint32_t bdg_id = 0xa0c;

        txn.status = allocate_dummy_gid(m_internal_bridge_ids, bdg_id);
        la_return_on_error(txn.status);
        txn.on_fail([=]() { release_dummy_gid(m_internal_bridge_ids, bdg_id); });

        // create per vrf dummy switch for l3 vxlan tunnel
        txn.status = m_sdev->m_dev->create_switch(bdg_id, overlay_vrf_ptr->vxlan_switch);
        la_return_on_error(txn.status);
        txn.on_fail([=]() { m_sdev->m_dev->destroy(overlay_vrf_ptr->vxlan_switch); });

        // set decap vni profile to skip Inner mac lookup
        txn.status = overlay_vrf_ptr->vxlan_switch->set_decap_vni_profile(la_switch::vxlan_termination_mode_e::IGNORE_DMAC);

        // set decap vni
        txn.status = overlay_vrf_ptr->vxlan_switch->set_decap_vni(decap_vni);
        la_return_on_error(txn.status);
        txn.on_fail([=]() { overlay_vrf_ptr->vxlan_switch->clear_decap_vni(); });

        overlay_vrf_ptr->decap_vni = decap_vni;
        overlay_vrf_ptr->vxlan_switch_refcount = 1;
    } else {
        if (overlay_vrf_ptr->decap_vni != decap_vni) {
            sai_log_error(SAI_API_TUNNEL, "Can not set decap vni %d, %d already exist", decap_vni, overlay_vrf_ptr->decap_vni);
            return LA_STATUS_EBUSY;
        }
        overlay_vrf_ptr->vxlan_switch_refcount++;
        return LA_STATUS_SUCCESS;
    }

    if (overlay_vrf_ptr->vxlan_svi == nullptr) {
        uint32_t svi_idx = 0;
        txn.status = allocate_dummy_gid(m_internal_svi_ids, svi_idx);
        la_return_on_error(txn.status);
        txn.on_fail([=]() { release_dummy_gid(m_internal_svi_ids, svi_idx); });

        la_mac_addr_t sw_mac;
        reverse_copy(std::begin(m_sdev->m_default_switch_mac), std::end(m_sdev->m_default_switch_mac), sw_mac.bytes);
        txn.status = m_sdev->m_dev->create_svi_port(svi_idx,
                                                    overlay_vrf_ptr->vxlan_switch,
                                                    overlay_vrf_ptr->vrf,
                                                    sw_mac,
                                                    m_sdev->m_qos_handler->get_default_ingress_qos_profile(),
                                                    m_sdev->m_qos_handler->get_default_egress_qos_profile(),
                                                    overlay_vrf_ptr->vxlan_svi);
        la_return_on_error(txn.status);
        txn.on_fail([=]() { m_sdev->m_dev->destroy(overlay_vrf_ptr->vxlan_svi); });

        txn.status = overlay_vrf_ptr->vxlan_svi->set_protocol_enabled(la_l3_protocol_e::IPV4_UC, true);
        la_return_on_error(txn.status);

        txn.status = overlay_vrf_ptr->vxlan_svi->set_protocol_enabled(la_l3_protocol_e::IPV6_UC, true);
        la_return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::set_encap_vnis_next_hops(sai_object_id_t next_hop_obj, next_hop_entry& nh_entry, tunnel_t* tun_entry)
{
    if (tun_entry == nullptr || tun_entry->m_encap_mappers.size() == 0) {
        return LA_STATUS_SUCCESS;
    }

    if (nh_entry.m_vxlan_port == nullptr) {
        sai_log_error(SAI_API_TUNNEL, "Invalid LA Tunnel port");
        return LA_STATUS_EINVAL;
    }
    tun_entry->encap_vni = 0;
    la_mac_addr_t dummy_nh_mac;
    reverse_copy(std::begin(nh_entry.m_tunnel_mac), std::end(nh_entry.m_tunnel_mac), dummy_nh_mac.bytes);

    for (auto it = tun_entry->m_encap_mappers.begin(); it != tun_entry->m_encap_mappers.end(); ++it) {
        lsai_object la_encap(*it);
        if (la_encap.tunnel_map_type != (uint32_t)SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI) {
            continue;
        }

        tunnel_map_t* tun_map = m_tunnel_map_db.get_ptr(la_encap.index);
        if (tun_map == nullptr) {
            sai_log_warn(SAI_API_TUNNEL, "Encap tunnel map 0x%llx undefined", *it);
            continue;
        }

        for (auto entry_itr = tun_map->m_entry_list.begin(); entry_itr != tun_map->m_entry_list.end(); ++entry_itr) {
            lsai_object la_map_entry(*entry_itr);
            vrf_entry* overlay_vrf_ptr = m_sdev->m_vrfs.get_ptr(la_map_entry.tunnel_map_entry_key);
            if (overlay_vrf_ptr == nullptr) {
                sai_log_error(SAI_API_TUNNEL, "vrf does not exist 0x%x", la_map_entry.tunnel_map_entry_key);
                continue;
            }

            if (overlay_vrf_ptr->vxlan_switch == nullptr) {
                sai_log_error(SAI_API_TUNNEL,
                              "overlap vrf has no decap vni (0x%x,  %d)",
                              la_map_entry.tunnel_map_entry_key,
                              la_map_entry.tunnel_map_entry_value);
                return LA_STATUS_EINVAL;
            }

            la_status status = LA_STATUS_SUCCESS;
            if (nh_entry.m_encap_vni == 0) {
                status = nh_entry.m_vxlan_port->set_encap_vni(overlay_vrf_ptr->vxlan_switch, la_map_entry.tunnel_map_entry_value);
            } else {
                status = nh_entry.m_vxlan_port->set_encap_vni(overlay_vrf_ptr->vxlan_switch, nh_entry.m_encap_vni);
            }
            la_return_on_error_log(status, "set_encap_vni %s", status.message().c_str());

            la_obj_wrap<la_vxlan_next_hop> vxlan_next_hop = nullptr;

            status = m_sdev->m_dev->create_vxlan_next_hop(
                dummy_nh_mac, overlay_vrf_ptr->vxlan_svi, nh_entry.m_vxlan_port, vxlan_next_hop);
            la_return_on_error_log(status, "create_vxlan_next_hop %s", status.message().c_str());

            overlay_vrf_ptr->m_vxlan_next_hops[next_hop_obj] = vxlan_next_hop;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::dettach_decap_mappers(tunnel_t* tun_entry)
{
    if (tun_entry->m_decap_mappers.size() == 0) {
        return LA_STATUS_SUCCESS;
    }

    for (auto it = tun_entry->m_decap_mappers.begin(); it != tun_entry->m_decap_mappers.end(); ++it) {
        lsai_object la_decap(*it);
        if (la_decap.tunnel_map_type != (uint32_t)SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID) {
            continue;
        }

        tunnel_map_t* tun_map = m_tunnel_map_db.get_ptr(la_decap.index);
        if (tun_map == nullptr) {
            continue;
        }
        tun_map->ref_count--;

        for (auto entry_itr = tun_map->m_entry_list.begin(); entry_itr != tun_map->m_entry_list.end(); ++entry_itr) {
            lsai_object la_map_entry(*entry_itr);
            lsai_object la_vf(SAI_OBJECT_TYPE_VIRTUAL_ROUTER, la_decap.switch_id, la_map_entry.tunnel_map_entry_value);
            sai_object_id_t decap_vrf_obj = la_vf.object_id();
            la_status status = remove_dummy_vxlan_switch_svi(decap_vrf_obj);
            if (status != LA_STATUS_SUCCESS) {
                return status;
            }
        }
    }

    tun_entry->m_decap_mappers.clear();
    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::attach_decap_mappers(tunnel_t* tun_entry)
{
    if (tun_entry->m_decap_mappers.size() == 0) {
        return LA_STATUS_EINVAL;
    }

    for (auto it = tun_entry->m_decap_mappers.begin(); it != tun_entry->m_decap_mappers.end(); ++it) {
        lsai_object la_decap(*it);
        if (la_decap.tunnel_map_type != (uint32_t)SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID) {
            continue;
        }

        tunnel_map_t* tun_map = m_tunnel_map_db.get_ptr(la_decap.index);
        if (tun_map == nullptr) {
            continue;
        }
        tun_map->ref_count++;

        for (auto entry_itr = tun_map->m_entry_list.begin(); entry_itr != tun_map->m_entry_list.end(); ++entry_itr) {
            lsai_object la_map_entry(*entry_itr);
            uint32_t decap_vni = la_map_entry.tunnel_map_entry_key;
            lsai_object la_vf(SAI_OBJECT_TYPE_VIRTUAL_ROUTER, la_decap.switch_id, la_map_entry.tunnel_map_entry_value);
            sai_object_id_t decap_vrf_obj = la_vf.object_id();

            la_status status = create_dummy_vxlan_switch_svi(decap_vrf_obj, decap_vni);
            if (status != LA_STATUS_SUCCESS && status != LA_STATUS_EEXIST) {
                return status;
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::find_vrf_tunnel_nexthop(sai_object_id_t* next_hop_id,
                                        sai_object_id_t vrf_obj,
                                        sai_ip_address_t& ipaddr,
                                        sai_object_id_t obj_tunnel)
{
    vrf_entry vrf_entry{};
    lsai_object la_vf(vrf_obj);
    auto sdev = la_vf.get_device();
    la_status status = sdev->m_vrfs.get(la_vf.index, vrf_entry);
    la_return_on_error(status);

    la_ipv4_addr_t ip_addr;
    ip_addr.s_addr = ntohl(ipaddr.addr.ip4);

    auto it = vrf_entry.m_remote_loopback_nexthops.find(ip_addr);
    if (it != vrf_entry.m_remote_loopback_nexthops.end()) {
        auto tun_nh = it->second.begin();
        for (; tun_nh != it->second.end(); ++tun_nh) {
            lsai_object la_tnh(*tun_nh);
            next_hop_entry nh_entry{};
            la_status status = sdev->m_next_hops.get(la_tnh.index, nh_entry);
            if (status != LA_STATUS_SUCCESS) {
                continue;
            }
            if (nh_entry.rif_tun_oid == obj_tunnel) {
                *next_hop_id = *tun_nh;
                return LA_STATUS_SUCCESS;
            }
        }
    }
    return LA_STATUS_ENOTFOUND;
}

// Vxlan v4 next hop creation
//     NOTE: due to sdk API require both encap/decap information together to create
//     tunnel, the whole  tunnel creation will not happen until nexthop creation is called.
//
// NextHop attributes: next_hop_type (TUNNEL_ENCAP),
//                     ipaddr (remote loopback ip address)
//                     and the tunnel id for local loopback
//                     ?? ttl pipemode, ttl#
//
// Tunnel attributes(tunnel from nexthop): local loopback ip address
//                    underlay_vrf,
//                    encap vni per vxlan_port
//                    decap vni per overlay_vrf/dummy_switch
//
//
la_status
tunnel_manager::create_tunnel_next_hop_v4(sai_object_id_t* next_hop_id, next_hop_entry& nh_entry, transaction& txn)
{
    lsai_object la_tun(nh_entry.rif_tun_oid);

    // get tunnel entry for attributes:
    //     local loopback ip address,
    //     underlay_vrf,
    //     decap vni -> overlay_vrf, (multiple entry, one per overlay_vrf)
    //     encap overlay_vrf -> vni (limited to one, per tunnel)
    tunnel_t* tun_entry = m_tunnel_db.get_ptr(la_tun.index);
    if (tun_entry == nullptr) {
        sai_log_error(SAI_API_TUNNEL, "Invalid tunnel object", nh_entry.rif_tun_oid);
        return LA_STATUS_EINVAL;
    }

    switch (tun_entry->m_type) {
    case SAI_TUNNEL_TYPE_VXLAN:
        if (!tun_entry->init_done) {
            la_status status = vxlan_tunnel_initialization(tun_entry);
            la_return_on_error(status);
            tun_entry->init_done = true;
        }

        return create_vxlan_next_hop_v4(next_hop_id, nh_entry, tun_entry, txn);
    default:
        break;
    }

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
tunnel_manager::create_vxlan_next_hop_v4(sai_object_id_t* next_hop_id,
                                         next_hop_entry& nh_entry,
                                         tunnel_t*& tun_entry,
                                         transaction& txn)
{
    // get underlay rif
    // from underlay rif to get underlay vrf
    lsai_object la_under_rif(tun_entry->m_underlay_oid);
    rif_entry* underlay_rif = m_sdev->m_l3_ports.get_ptr(la_under_rif.index);
    if (underlay_rif == nullptr) {
        sai_log_error(SAI_API_TUNNEL, "Invalid underlay router interface 0x%0x", tun_entry->m_underlay_oid);
        txn.status = LA_STATUS_EINVAL;
        return txn.status;
    }

    // remote ip from nexthop
    la_ipv4_addr_t remote_addr, local_addr;
    remote_addr.s_addr = ntohl(nh_entry.ip_addr.addr.ip4);

    // local ip from tunnel
    local_addr.s_addr = ntohl(tun_entry->m_src_ip.addr.ip4);

    // vxlan port share with l2 service port space,
    // la vxlan is always p2p, manage the vxlan gid in tunnel manager
    lsai_object la_underlay_vrf(underlay_rif->vrf_obj);
    vrf_entry* underlay_vrf = m_sdev->m_vrfs.get_ptr(la_underlay_vrf.index);
    if (underlay_vrf == nullptr) {
        sai_log_error(SAI_API_TUNNEL, "Underlay Vrf is invalid 0x%0x", underlay_rif->vrf_obj);
        txn.status = LA_STATUS_EINVAL;
        return txn.status;
    }

    // per underlay_vrf, remote loopback address and obj_tunnel there is only one nexthop
    txn.status = find_vrf_tunnel_nexthop(next_hop_id, underlay_rif->vrf_obj, nh_entry.ip_addr, tun_entry->m_obj);
    if (txn.status == LA_STATUS_SUCCESS) {
        /* TODO Must check nh_entry.m_encap_vni is non-zero.
         *     If so, update the NH. See tunnel_manager::set_encap_vnis_next_hops
         *  status = nh_entry.m_vxlan_port->set_encap_vni(overlay_vrf_ptr->vxlan_switch, nh_entry.m_encap_vni);
         *  la_obj_wrap<la_vxlan_next_hop> vxlan_next_hop = nullptr;
         *  status = m_sdev->m_dev->create_vxlan_next_hop(
         *      dummy_nh_mac, overlay_vrf_ptr->vxlan_svi, nh_entry.m_vxlan_port, vxlan_next_hop);
         *  la_return_on_error(status);
         *  overlay_vrf_ptr->m_vxlan_next_hops[next_hop_obj] = vxlan_next_hop;
         */
        return LA_STATUS_EEXIST;
    }

    uint32_t vxlan_gid = 0;
    txn.status = allocate_vxlan_gid(vxlan_gid);
    la_return_on_error(txn.status);

    // create vxlan tunnel l2 service port
    la_l2_service_port* vxlan_port = nullptr;
    txn.status = m_sdev->m_dev->create_vxlan_l2_service_port(vxlan_gid, local_addr, remote_addr, underlay_vrf->vrf, vxlan_port);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_sdev->m_dev->destroy(vxlan_port); });

    // Apply tunnel properties.
    la_ttl_inheritance_mode_e ttl_mode;
    switch (tun_entry->m_encap_ttl_mode) {
    case SAI_TUNNEL_TTL_MODE_PIPE_MODEL:
        ttl_mode = la_ttl_inheritance_mode_e::PIPE;
        break;
    case SAI_TUNNEL_TTL_MODE_UNIFORM_MODEL:
        ttl_mode = la_ttl_inheritance_mode_e::UNIFORM;
        break;
    default:
        return LA_STATUS_EINVAL;
    }
    auto status = vxlan_port->set_ttl_inheritance_mode(ttl_mode);
    la_return_on_error(status);

    status = vxlan_port->set_ttl(tun_entry->m_ttl);
    la_return_on_error(status);

    // get route next_hop of the remote loopback ip
    //  If the NH is ECMP, we need Stage 1 type.
    const la_l3_destination* remote_l3_dest
        = sai_route_get_la_next_hop(m_sdev, nh_entry.ip_addr, underlay_rif->vrf_obj, true /*is_tunnel*/);

    // TODO possible allow adjusted later when route updated
    if (remote_l3_dest != nullptr) {
        txn.status = vxlan_port->set_l3_destination(remote_l3_dest);
        la_return_on_error(txn.status);
    }

    // create next hop object id for this tunnel next hoj
    uint32_t id;
    txn.status = m_sdev->m_next_hops.allocate_id(id);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_sdev->m_next_hops.release_id(id); });

    // create next hop object id for this tunnel next hop obj
    nh_entry.m_vxlan_port = vxlan_port;

    txn.status = m_sdev->m_next_hops.set(id, nh_entry);
    la_return_on_error(txn.status, "Fail to set nexthop in obj db. %s", txn.status.message().c_str());
    txn.on_fail([=]() { m_sdev->m_next_hops.erase_id(*next_hop_id); });
    sai_log_debug(SAI_API_NEXT_HOP, "next_hop 0x%lx created", *next_hop_id);

    lsai_object la_nh(SAI_OBJECT_TYPE_NEXT_HOP, la_underlay_vrf.switch_id, id);
    *next_hop_id = la_nh.object_id();

    // set encap vni on l2 vxlan port
    txn.status = set_encap_vnis_next_hops(*next_hop_id, nh_entry, tun_entry);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { remove_encap_vnis_next_hops(*next_hop_id, tun_entry); });

    underlay_vrf->m_remote_loopback_nexthops[remote_addr].insert(*next_hop_id);

    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::remove_encap_vnis_next_hops(sai_object_id_t next_hop_obj, const tunnel_t* tun_entry)
{
    if (tun_entry == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    lsai_object la_nh(next_hop_obj);
    next_hop_entry* nh_entry = m_sdev->m_next_hops.get_ptr(la_nh.index);
    if (nh_entry == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    for (auto it = tun_entry->m_encap_mappers.begin(); it != tun_entry->m_encap_mappers.end(); ++it) {
        lsai_object la_encap(*it);
        if (la_encap.tunnel_map_type != (uint32_t)SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI) {
            continue;
        }

        tunnel_map_t* tun_map = m_tunnel_map_db.get_ptr(la_encap.index);
        if (tun_map == nullptr) {
            continue;
        }

        // remove all la_vxlan_next_hop from the map
        for (auto entry_itr = tun_map->m_entry_list.begin(); entry_itr != tun_map->m_entry_list.end(); ++entry_itr) {
            lsai_object la_map_entry(*entry_itr);
            vrf_entry* overlay_vrf_ptr = m_sdev->m_vrfs.get_ptr(la_map_entry.tunnel_map_entry_key);
            if (overlay_vrf_ptr == nullptr) {
                continue;
            }

            auto it = overlay_vrf_ptr->m_vxlan_next_hops.find(next_hop_obj);
            if (it == overlay_vrf_ptr->m_vxlan_next_hops.end()) {
                continue;
            }
            m_sdev->m_dev->destroy(it->second);
            overlay_vrf_ptr->m_vxlan_next_hops.erase(it);

            la_status status = nh_entry->m_vxlan_port->clear_encap_vni(overlay_vrf_ptr->vxlan_switch);
            la_return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::remove_tunnel_next_hop(sai_object_id_t obj_next_hop_id)
{
    lsai_object la_nh(obj_next_hop_id);
    auto sdev = la_nh.get_device();

    next_hop_entry* nh_entry = sdev->m_next_hops.get_ptr(la_nh.index);
    if (nh_entry == nullptr) {
        // already removed
        return LA_STATUS_SUCCESS;
    }

    lsai_object la_tun(nh_entry->rif_tun_oid);
    tunnel_t* tun_entry = m_tunnel_db.get_ptr(la_tun.index);
    if (tun_entry == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = remove_encap_vnis_next_hops(obj_next_hop_id, tun_entry);
    la_return_on_error(status);

    if (nh_entry->m_vxlan_port != nullptr) {
        status = m_sdev->m_dev->destroy(nh_entry->m_vxlan_port);
        la_return_on_error(status);
        nh_entry->m_vxlan_port = nullptr;
    }

    m_sdev->m_next_hops.remove(la_nh.index);

    // get underlay rif from tunnel entry
    lsai_object la_under(tun_entry->m_underlay_oid);
    rif_entry* underlay_rif = sdev->m_l3_ports.get_ptr(la_under.index);
    if (underlay_rif == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    // get underlay vrf
    lsai_object la_vf(underlay_rif->vrf_obj);
    vrf_entry* underlay_vrf = sdev->m_vrfs.get_ptr(la_vf.index);
    if (underlay_vrf == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    // remove the nexthop from the underlay vrf
    la_ipv4_addr_t remote_addr;
    remote_addr.s_addr = ntohl(nh_entry->ip_addr.addr.ip4);
    auto rl = underlay_vrf->m_remote_loopback_nexthops.find(remote_addr);
    if (rl != underlay_vrf->m_remote_loopback_nexthops.end()) {
        rl->second.erase(obj_next_hop_id);
        if (rl->second.size() == 0) {
            underlay_vrf->m_remote_loopback_nexthops.erase(rl);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::update_remote_loopback_route(vrf_entry& vrf_entry, const la_ipv4_addr_t& addr, const la_l3_destination* l3_dest)
{
    auto tnhs = vrf_entry.m_remote_loopback_nexthops.find(addr);
    if (tnhs == vrf_entry.m_remote_loopback_nexthops.end()) {
        return LA_STATUS_SUCCESS;
    }

    if (l3_dest && l3_dest->type() != la_object::object_type_e::NEXT_HOP
        && l3_dest->type() != la_object::object_type_e::ECMP_GROUP) {
        // only next hop and ecmp group are supported
        l3_dest = nullptr;
    }

    for (auto tnh = tnhs->second.begin(); tnh != tnhs->second.end(); tnh++) {
        lsai_object la_tun_nh(*tnh);
        next_hop_entry* tun_nh_entry = m_sdev->m_next_hops.get_ptr(la_tun_nh.index);
        if (tun_nh_entry == nullptr) {
            // protective checker for parallel processing.
            continue;
        }

        if (tun_nh_entry->m_vxlan_port != nullptr) {
            la_status status = tun_nh_entry->m_vxlan_port->set_l3_destination(l3_dest);
            if (status != LA_STATUS_SUCCESS) {
                sai_log_debug(SAI_API_TUNNEL, "Can not set tunnel l3 destination 0x%lx", tun_nh_entry->rif_tun_oid);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::update_remote_loopback_route(vrf_entry& vrf_entry, const la_ipv6_addr_t& addr, const la_l3_destination* l3_dest)
{
    return LA_STATUS_SUCCESS;
}

la_status
tunnel_manager::allocate_dummy_gid(ranged_index_generator& ids, uint32_t& out_idx)
{
    out_idx = UINT32_MAX;
    // INVALID_INDEX is uint64_t, so can't compare it against uint32_t
    auto index = ids.allocate();
    if (index == ranged_index_generator::INVALID_INDEX) {
        return LA_STATUS_ERESOURCE;
    }
    out_idx = index;
    return LA_STATUS_SUCCESS;
}

void
tunnel_manager::release_dummy_gid(ranged_index_generator& ids, uint32_t gid)
{
    ids.release(gid);
}
}
}
