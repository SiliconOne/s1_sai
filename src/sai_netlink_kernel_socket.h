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

#ifndef __SAI_NETLINK_KERNEL_SOCKET__
#define __SAI_NETLINK_KERNEL_SOCKET__

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

#include "sai_netlink_sock_wrapper.h"
#include "sai_netlink_kernel_msg.h"
#include "saistatus.h"
#include "sai_utils.h"

namespace silicon_one
{
namespace sai
{

class sai_netlink_kernel_socket
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS;

public:
    sai_netlink_kernel_socket() : m_device_id(0), m_seqnum(0){};
    sai_status_t open(const std::string& family);
    sai_status_t open(la_device_id_t dev_id);
    sai_netlink_kernel_socket(const sai_netlink_kernel_socket&) = delete;

    sai_status_t send_add_hostif(la_system_port_gid_t port_gid, std::string name, sai_mac_t mac, sai_hostif_vlan_tag_t vlan_tag);
    sai_status_t send_add_hostif(la_system_port_gid_t port_gid,
                                 std::string name,
                                 sai_mac_t mac,
                                 sai_hostif_vlan_tag_t vlan_tag,
                                 hostif_nic_t nic);

    sai_status_t send_add_hostif(la_system_port_gid_t port_gid,
                                 std::string name,
                                 sai_mac_t mac,
                                 sai_hostif_vlan_tag_t vlan_tag,
                                 hostif_nic_t nic,
                                 uint16_t vlan_tag_id,
                                 uint8_t pkt_class);

    sai_status_t send_remove_hostif(std::string name, bool force);
    sai_status_t send_remove_hostif(la_system_port_gid_t port_gid, bool force);

    sai_status_t send_update_port_vlan_id(la_system_port_gid_t port_gid, uint16_t vlan_id);

    sai_status_t send_set_trap_type(trap_source_t source, trap_type_t type, trap_id_t trap_id);
    sai_status_t send_remove_trap_type(trap_source_t source);

    sai_status_t send_set_trap(trap_code_t code, trap_id_t trap_id, trap_type_t trap_type);
    sai_status_t send_remove_trap(trap_code_t code, trap_type_t trap_type);

    sai_status_t send_add_trap_action(trap_map_types_t type, trap_id_t trap_id, la_system_port_gid_t port_id, trap_action_t action);
    sai_status_t send_add_trap_global_action(trap_id_t trap_id, trap_action_t action);
    sai_status_t send_add_trap_hostif_action(la_system_port_gid_t port_id, trap_id_t trap_id, trap_action_t action);

    sai_status_t send_remove_trap_action(trap_map_types_t type, trap_id_t trap_id, la_system_port_gid_t port_id);
    sai_status_t send_remove_trap_global_action(trap_id_t trap_id);
    sai_status_t send_remove_trap_hostif_action(la_system_port_gid_t port_id, trap_id_t trap_id);

    sai_status_t send_register_sample_netlink(std::string family_name, std::vector<std::string> groups);

    sai_status_t send_set_sample_rate(trap_code_t code, uint32_t sample_rate);
    sai_status_t send_remove_sample_rate(trap_code_t code);

    sai_status_t send_set_vlan_config(la_system_port_gid_t port_gid, sai_hostif_vlan_tag_t tag, uint16_t vlan_tag_id);

    sai_status_t send_clear_kernel();

    sai_status_t send_set_default_action(trap_action_t action);
    sai_status_t send_get_module_satus(bool& dirty);

    sai_status_t send_set_sample_parameters(trap_code_t code, trap_id_t trap_id, uint32_t sample_rate);

private:
    la_device_id_t m_device_id;
    std::unique_ptr<sai_netlink_sock_wrapper> m_sock;
    std::atomic<uint32_t> m_seqnum;
    template <typename T, typename... Args>
    sai_status_t send_set(Args&&... args)
    {
        T msg(std::forward<Args>(args)...);
        sai_status_t status;
        status = m_sock->send(msg);

        if (status == SAI_STATUS_SUCCESS) {
            return sai_netlink_kernel_wait_status();
        }

        return status;
    }

    template <typename _ReqMsg, typename... Args>
    sai_status_t send_get(Args&&... args)
    {
        _ReqMsg msg(std::forward<Args>(args)...);
        sai_status_t status;
        status = m_sock->send(msg);

        return status;
    }

    template <typename _RespMsg>
    sai_status_t sai_netlink_kernel_wait_response(uint16_t command, _RespMsg* response)
    {
        static sai_status_t status = SAI_STATUS_FAILURE;
        constexpr int poll_max = 10000;
        static struct nlattr* tb_msg[MAX_ATTR_CNT + 1];
        static uint16_t cmd;

        nl_recvmsg_msg_cb_t stat_rx = ([](struct nl_msg* msg, void* arg) -> int {
            struct nlmsghdr* hdr;
            hdr = nlmsg_hdr(msg);

            struct genlmsghdr* gnlh = (struct genlmsghdr*)nlmsg_data(hdr);
            cmd = gnlh->cmd;
            nla_parse(tb_msg, MAX_ATTR_CNT, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
            status = NL_OK;
            return status;
        });

        if (nl_socket_modify_cb(m_sock->sock_ptr(), NL_CB_VALID, NL_CB_CUSTOM, stat_rx, NULL)) {
            return SAI_STATUS_FAILURE;
        }

        for (int i = 0; i < poll_max; i++) {
            if (m_sock->recv() == SAI_STATUS_SUCCESS) {
                break;
            }
            std::this_thread::yield();
        }

        sai_return_on_error(status);

        if (cmd == command) {
            if (tb_msg[DEFAULT_ATTR_ID]) {
                memcpy(response, (_RespMsg*)nla_data(tb_msg[DEFAULT_ATTR_ID]), sizeof(_RespMsg));
            } else {
                status = SAI_STATUS_FAILURE;
            }
        }

        return status;
    }

    sai_status_t sai_netlink_kernel_wait_status();
};
}
}
#endif //__SAI_NETLINK_KERNEL_SOCKET__
