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

#ifndef __SAI_NETLINK_SOCKET__
#define __SAI_NETLINK_SOCKET__

#include <string>
#include <cstdint>
#include <atomic>
#include <memory>

#include "sai_netlink_sock_wrapper.h"
#include "sai_netlink_msg.h"
#include "saistatus.h"
#include "sai_utils.h"

namespace silicon_one
{
namespace sai
{

class sai_netlink_socket
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS;

public:
    sai_netlink_socket() : m_seqnum(0){};
    sai_status_t open(const std::string& family, const std::string& group);
    sai_status_t send_sample(uint16_t iif, uint16_t oif, uint32_t samplerate, uint32_t origsize, uint8_t* data, uint32_t size);
    sai_netlink_socket(const sai_netlink_socket&) = delete;

private:
    std::unique_ptr<sai_netlink_sock_wrapper> m_sock;
    std::atomic<uint32_t> m_seqnum;
    template <typename T, typename... Args>
    sai_status_t send(Args&&... args)
    {
        T msg(std::forward<Args>(args)...);
        return m_sock->send(msg);
    }
};
}
}
#endif //__SAI_NETLINK_SOCKET__
