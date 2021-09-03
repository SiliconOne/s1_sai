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

#include "sai_netlink_socket.h"
#include "sai_netlink_msg.h"

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
sai_netlink_socket::open(const std::string& family, const std::string& group)
{
    sai_status_t status;
    auto sock = sai_netlink_sock_wrapper::new_sock();
    if (sock == nullptr) {
        return SAI_STATUS_FAILURE;
    }

    status = sock->open(family, group);
    sai_return_on_error(status);

    m_sock = std::move(sock);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_netlink_socket::send_sample(uint16_t iif, uint16_t oif, uint32_t samplerate, uint32_t origsize, uint8_t* data, uint32_t size)
{
    return send<sai_psample>(iif, oif, samplerate, origsize, m_seqnum++, data, size);
}
}
}
