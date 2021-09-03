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

#ifndef __SAI_NETLINK_ROUTE_SOCKET__
#define __SAI_NETLINK_ROUTE_SOCKET__

#include "sai_netlink_sock_wrapper.h"

namespace silicon_one
{
namespace sai
{

class sai_netlink_route_socket
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS;

public:
    sai_netlink_route_socket() = default;
    sai_status_t connect();
    sai_status_t send_change_carrier(int if_index, bool new_carrier);

private:
    std::unique_ptr<sai_netlink_sock_wrapper> m_sock;
};
}
}

#endif
