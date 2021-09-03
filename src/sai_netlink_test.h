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

#ifndef SAI_NETLINK_TEST_H
#define SAI_NETLINK_TEST_H

#include "sai_netlink_sock_wrapper.h"
#include <unistd.h>
#include <linux/netlink.h>
#include <string.h>
#include <vector>

namespace silicon_one
{

namespace sai
{

struct NlPsample {
    uint16_t iif_idx = 0;
    uint16_t oif_idx = 0;
    uint32_t orig_size = 0;
    uint32_t group = 0;
    uint32_t seq = 0;
    uint32_t rate = 0;
    uint32_t data_size = 0;
    std::vector<uint8_t> data;
};

class sai_netlink_test_socket
{

public:
    sai_netlink_test_socket() = default;
    sai_netlink_test_socket(const sai_netlink_test_socket&) = delete;
    sai_netlink_test_socket(const sai_netlink_test_socket&&) = delete;

    int open(const std::string& family, const std::string& group, int timeout_sec);
    int recv(NlPsample& sample);

private:
    int _open(int timeout_sec);
    std::unique_ptr<sai_netlink_sock_wrapper> m_sock;
    static int recv_callback(struct nl_msg* msg, void* arg);
};

std::vector<NlPsample> receive_psample_test(const std::string& family,
                                            const std::string& group,
                                            uint32_t num_samples,
                                            int timeout_sec = 1);
}
}

#endif
