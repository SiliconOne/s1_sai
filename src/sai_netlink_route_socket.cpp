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

#include "sai_netlink_route_socket.h"

namespace silicon_one
{
namespace sai
{

sai_status_t
sai_netlink_route_socket::connect()
{
    sai_status_t status;
    auto sock = sai_netlink_sock_wrapper::new_sock();
    if (sock == nullptr) {
        return SAI_STATUS_FAILURE;
    }

    status = sock->connect(NETLINK_ROUTE);
    sai_return_on_error(status);

    m_sock = std::move(sock);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_netlink_route_socket::send_change_carrier(int if_index, bool new_carrier)
{
    struct nl_msg* msg = nlmsg_alloc_simple(RTM_SETLINK, 0);
    if (!msg) {
        sai_log_error(SAI_API_SWITCH, "Failed to allocate netlink message");
        return SAI_STATUS_FAILURE;
    }

    struct ifinfomsg ifi;
    ifi.ifi_family = AF_UNSPEC;
    ifi.ifi_index = if_index;
    ifi.ifi_flags = 0;
    ifi.ifi_change = 0;

    int res = nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO);
    if (res < 0) {
        sai_log_error(SAI_API_SWITCH, "Failed to append main header to the message res=%d: %s\n", res, nl_geterror(res));
        nlmsg_free(msg);
        return SAI_STATUS_FAILURE;
    }

    res = nla_put_u8(msg, IFLA_CARRIER, (uint8_t)new_carrier);
    if (res < 0) {
        sai_log_error(SAI_API_SWITCH, "Failed to add IFLA_CARRIER attribute to the message res=%d: %s", res, nl_geterror(res));
        nlmsg_free(msg);
        return SAI_STATUS_FAILURE;
    }

    res = nl_send_sync(m_sock->sock_ptr(), msg);
    if (res < 0) {
        sai_log_error(SAI_API_SWITCH, "Failed to send message res=%d: %s\n", res, nl_geterror(res));
    }

    return SAI_STATUS_SUCCESS;
}
}
}
