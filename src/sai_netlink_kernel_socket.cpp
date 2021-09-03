// BEGIN_LEGAL
//
// Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco").
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

#include "sai_netlink_kernel_socket.h"
#include "sai_netlink_kernel_msg.h"

#include <linux/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/mngt.h>
#include <string>
#include <iostream>
#include <unistd.h>
#include <memory>

namespace silicon_one
{
namespace sai
{

sai_status_t
sai_netlink_kernel_socket::open(const std::string& family)
{
    sai_status_t status;
    auto sock = sai_netlink_sock_wrapper::new_sock();
    if (sock == nullptr) {
        return SAI_STATUS_FAILURE;
    }

    status = sock->open(family);
    sai_return_on_error(status);

    m_sock = std::move(sock);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_netlink_kernel_socket::open(la_device_id_t dev_id)
{
    std::string family_str;
    m_device_id = dev_id;
    family_str = "lb_genl_family" + to_string(dev_id);
    return open(family_str);
}

sai_status_t
sai_netlink_kernel_socket::sai_netlink_kernel_wait_status()
{
    static sai_status_t status = SAI_STATUS_FAILURE;
    static constexpr int poll_max = 10000;

    nl_recvmsg_msg_cb_t stat_rx = ([](struct nl_msg* msg, void* arg) -> int {
        struct nlmsghdr* hdr;
        hdr = nlmsg_hdr(msg);

        struct genlmsghdr* gnlh = (struct genlmsghdr*)nlmsg_data(hdr);
        if (gnlh->cmd != NL_KERNEL_LAST_CMD_STATUS) {
            return NL_OK;
        }
        struct nlattr* tb_msg[MAX_ATTR_CNT + 1];
        nla_parse(tb_msg, MAX_ATTR_CNT, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
        if (tb_msg[DEFAULT_ATTR_ID]) {
            struct kernel_cmd_status* stat_cmd = (kernel_cmd_status*)nla_data(tb_msg[DEFAULT_ATTR_ID]);
            status = (stat_cmd->status == NL_KERNEL_STATUS_OK) ? SAI_STATUS_SUCCESS : SAI_STATUS_FAILURE;
        }
        return NL_OK;
    });

    if (nl_socket_modify_cb(m_sock->sock_ptr(), NL_CB_VALID, NL_CB_CUSTOM, stat_rx, NULL)) {
        return SAI_STATUS_FAILURE;
    }

    for (int i = 0; i < poll_max; i++) {
        if (m_sock->recv() == SAI_STATUS_SUCCESS) {
            break;
        }
        std::this_thread::yield();
    };

    return status;
}

sai_status_t
sai_netlink_kernel_socket::send_add_hostif(la_system_port_gid_t port_gid,
                                           std::string name,
                                           sai_mac_t mac,
                                           sai_hostif_vlan_tag_t vtag)
{
    return send_set<sai_kernel_add_netdev>(m_device_id, port_gid, name, mac, vtag, DEFAULT_NIC, 0, 0);
}

sai_status_t
sai_netlink_kernel_socket::send_add_hostif(la_system_port_gid_t port_gid,
                                           std::string name,
                                           sai_mac_t mac,
                                           sai_hostif_vlan_tag_t vtag,
                                           hostif_nic_t nic)
{
    return send_set<sai_kernel_add_netdev>(m_device_id, port_gid, name, mac, vtag, nic, 0, 0);
}

sai_status_t
sai_netlink_kernel_socket::send_add_hostif(la_system_port_gid_t port_gid,
                                           std::string name,
                                           sai_mac_t mac,
                                           sai_hostif_vlan_tag_t vlan_tag,
                                           hostif_nic_t nic,
                                           uint16_t vlan_tag_id,
                                           uint8_t pkt_class)
{
    return send_set<sai_kernel_add_netdev>(m_device_id, port_gid, name, mac, vlan_tag, nic, vlan_tag_id, pkt_class);
}

sai_status_t
sai_netlink_kernel_socket::send_remove_hostif(std::string name, bool force)
{
    return send_set<sai_kernel_remove_netdev>(m_device_id, name, 0, force);
}

sai_status_t
sai_netlink_kernel_socket::send_remove_hostif(la_system_port_gid_t port_gid, bool force)
{
    return send_set<sai_kernel_remove_netdev>(m_device_id, "", port_gid, force);
}

sai_status_t
sai_netlink_kernel_socket::send_update_port_vlan_id(la_system_port_gid_t port_gid, uint16_t vlan_tag_id)
{
    // TODO: API to change vlan_tag_id of a port
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_netlink_kernel_socket::send_set_trap_type(trap_source_t source, trap_type_t type, trap_id_t trap_id)
{
    return send_set<sai_kernel_set_trap_type>(m_device_id, source, type, trap_id);
}

sai_status_t
sai_netlink_kernel_socket::send_remove_trap_type(trap_source_t source)
{
    return send_set<sai_kernel_remove_trap_type>(m_device_id, source);
}

sai_status_t
sai_netlink_kernel_socket::send_set_trap(trap_code_t code, trap_id_t trap_id, trap_type_t trap_type)
{
    if (trap_type == TRAP_TYPE_DIRECT) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    return send_set<sai_kernel_set_trap>(m_device_id, code, trap_id, trap_type);
}

sai_status_t
sai_netlink_kernel_socket::send_remove_trap(trap_code_t code, trap_type_t trap_type)
{
    if (trap_type == TRAP_TYPE_DIRECT) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    return send_set<sai_kernel_remove_trap>(m_device_id, code, trap_type);
}

sai_status_t
sai_netlink_kernel_socket::send_add_trap_action(trap_map_types_t type,
                                                trap_id_t trap_id,
                                                la_system_port_gid_t port_id,
                                                trap_action_t action)
{
    return send_set<sai_kernel_add_trap_action>(m_device_id, type, trap_id, port_id, action);
}

sai_status_t
sai_netlink_kernel_socket::send_remove_trap_action(trap_map_types_t type, trap_id_t trap_id, la_system_port_gid_t port_id)
{
    return send_set<sai_kernel_add_trap_action>(m_device_id, type, trap_id, port_id, TRAP_ACTION_NOT_SET);
}

sai_status_t
sai_netlink_kernel_socket::send_add_trap_global_action(trap_id_t trap_id, trap_action_t action)
{
    return send_set<sai_kernel_add_trap_action>(m_device_id, TRAP_MAP_ID_ONLY, trap_id, 0, action);
}

sai_status_t
sai_netlink_kernel_socket::send_remove_trap_global_action(trap_id_t trap_id)
{
    return send_set<sai_kernel_add_trap_action>(m_device_id, TRAP_MAP_ID_ONLY, trap_id, 0, TRAP_ACTION_NOT_SET);
}

sai_status_t
sai_netlink_kernel_socket::send_add_trap_hostif_action(la_system_port_gid_t port_id, trap_id_t trap_id, trap_action_t action)
{
    return send_set<sai_kernel_add_trap_action>(m_device_id, TRAP_MAP_ID_AND_SRC, trap_id, port_id, action);
}

sai_status_t
sai_netlink_kernel_socket::send_remove_trap_hostif_action(la_system_port_gid_t port_id, trap_id_t trap_id)
{
    return send_set<sai_kernel_add_trap_action>(m_device_id, TRAP_MAP_ID_AND_SRC, trap_id, port_id, TRAP_ACTION_NOT_SET);
}

sai_status_t
sai_netlink_kernel_socket::send_set_default_action(trap_action_t action)
{
    if (action == TRAP_ACTION_DEFAULT) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    return send_set<sai_kernel_set_default_action>(m_device_id, action);
}

sai_status_t
sai_netlink_kernel_socket::send_register_sample_netlink(std::string family_name, std::vector<std::string> groups)
{
    return send_set<sai_kernel_set_sampling_slots>(m_device_id, family_name, groups);
}

sai_status_t
sai_netlink_kernel_socket::send_set_sample_rate(trap_code_t code, uint32_t sample_rate)
{
    return send_set<sai_kernel_set_sampling_rate>(m_device_id, code, sample_rate);
}

sai_status_t
sai_netlink_kernel_socket::send_set_vlan_config(la_system_port_gid_t port_gid, sai_hostif_vlan_tag_t tag, uint16_t vlan_tag_id)
{
    return send_set<sai_kernel_change_vlan_config>(m_device_id, port_gid, tag, vlan_tag_id);
}

sai_status_t
sai_netlink_kernel_socket::send_remove_sample_rate(trap_code_t code)
{
    return send_set_sample_rate(code, 1);
}

sai_status_t
sai_netlink_kernel_socket::send_set_sample_parameters(trap_code_t code, trap_id_t trap_id, uint32_t sample_rate)
{
    auto status = send_set_trap(code, trap_id, TRAP_TYPE_TABLE3);
    sai_return_on_error(status);

    return send_set_sample_rate(code, sample_rate);
}

sai_status_t
sai_netlink_kernel_socket::send_get_module_satus(bool& dirty)
{
    sai_status_t status;
    kernel_module_status module_status;
    module_status.dirty = false;
    status = send_get<sai_kernel_get_module_status>(m_device_id);

    status = sai_netlink_kernel_wait_response<kernel_module_status>(NL_KERNEL_MODULE_STATUS, &module_status);

    dirty = module_status.dirty;

    return status;
}

sai_status_t
sai_netlink_kernel_socket::send_clear_kernel()
{
    return send_set<sai_kernel_clear>(m_device_id);
}
}
}
