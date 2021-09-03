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

#ifndef __SAI_NETLINK_SOCK_WRAPPER_H__
#define __SAI_NETLINK_SOCK_WRAPPER_H__

#include "sai_netlink_msg.h"
#include <iostream>
#include <memory>
#include <linux/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/mngt.h>
#include "sai_utils.h"

namespace silicon_one
{

namespace sai
{

class sai_netlink_sock_wrapper
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS;

public:
    static std::unique_ptr<sai_netlink_sock_wrapper> new_sock()
    {
        auto sock = std::unique_ptr<sai_netlink_sock_wrapper>(new sai_netlink_sock_wrapper());
        if (sock == nullptr or sock->sock_ptr() == nullptr) {
            return nullptr;
        }
        return sock;
    }

    int family() const
    {
        return m_family;
    }
    int group() const
    {
        return m_group;
    }

    ~sai_netlink_sock_wrapper()
    {
        close();
    }

    void close()
    {
        if (m_sock != nullptr) {
            nl_socket_free(m_sock); // this also closes the socket
            m_sock = nullptr;
        }
    }

    sai_status_t send(sai_netlink_msg& msg_builder)
    {
        if (m_sock == nullptr) {
            return SAI_STATUS_FAILURE;
        }

        auto msg = msg_builder.message(m_family);
        if (msg == nullptr) {
            return SAI_STATUS_FAILURE;
        }

        int ret = nl_send_auto(m_sock, msg->msg_ptr());

        if (ret <= 0) {
            return SAI_STATUS_FAILURE;
        }
        return SAI_STATUS_SUCCESS;
    }

    sai_status_t recv()
    {
        int ret = nl_recvmsgs_default(m_sock);
        if (ret) {
            sai_log_error(SAI_API_SWITCH, "netlink recieve failed");
            return SAI_STATUS_FAILURE;
        }
        return SAI_STATUS_SUCCESS;
    }

    struct nl_sock* sock_ptr()
    {
        return m_sock;
    }

    sai_status_t open(std::string family)
    {
        nl_socket_disable_seq_check(m_sock);
        nl_socket_disable_auto_ack(m_sock);

        if (genl_connect(m_sock) < 0) {
            sai_log_error(SAI_API_SWITCH, "genl_connect failed");
            nl_socket_free(m_sock);
            m_sock = nullptr;
            return SAI_STATUS_INVALID_PARAMETER;
        }

        if ((m_family = genl_ctrl_resolve(m_sock, family.c_str())) < 0) {
            sai_log_error(SAI_API_SWITCH, "genl_ctrl_resolve failed family=%s", family.c_str());
            nl_socket_free(m_sock);
            m_sock = nullptr;
            return SAI_STATUS_INVALID_PARAMETER;
        }

        return SAI_STATUS_SUCCESS;
    }

    sai_status_t open(std::string family, std::string group)
    {
        // nl_socket_disable_seq_check(m_sock);

        // if (genl_connect(m_sock) < 0) {
        //     sai_log_error(SAI_API_SWITCH, "genl_connect failed");
        //     nl_socket_free(m_sock);
        //     m_sock = nullptr;
        //     return SAI_STATUS_INVALID_PARAMETER;
        // }

        // if ((m_family = genl_ctrl_resolve(m_sock, family.c_str())) < 0) {
        //     sai_log_error(SAI_API_SWITCH, "genl_ctrl_resolve failed");
        //     nl_socket_free(m_sock);
        //     m_sock = nullptr;
        //     return SAI_STATUS_INVALID_PARAMETER;
        // }

        sai_status_t stat = open(family);

        if (stat == SAI_STATUS_SUCCESS) {
            m_group = genl_ctrl_resolve_grp(m_sock, family.c_str(), group.c_str());
            nl_socket_set_peer_groups(m_sock, 1 << (m_group - 1));
            return SAI_STATUS_SUCCESS;
        } else {
            return stat;
        }
    }

    sai_status_t connect(int protocol)
    {
        int res = nl_connect(m_sock, protocol);
        if (res < 0) {
            sai_log_error(SAI_API_SWITCH, "Can't connect socket protocol=%d res=%d: %s\n", protocol, res, nl_geterror(res));
            return SAI_STATUS_FAILURE;
        }

        return SAI_STATUS_SUCCESS;
    }

private:
    sai_netlink_sock_wrapper()
    {
        m_sock = nl_socket_alloc();
    }
    int m_family = -1;
    int m_group = -1;
    struct nl_sock* m_sock = nullptr;
};
}
}

#endif //__SAI_NETLINK_SOCK_WRAPPER_H__
