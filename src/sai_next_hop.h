// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco").
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

#ifndef __SAI_NEXT_HOP_H__
#define __SAI_NEXT_HOP_H__

extern "C" {
#include <sai.h>
}

#include "api/types/la_mpls_types.h"
#include "api/npu/la_l2_service_port.h"

#include "sai_warm_boot.h"

namespace silicon_one
{
namespace sai
{
class next_hop_entry
{
public:
    la_obj_wrap<la_next_hop> next_hop;
    sai_next_hop_type_t type = SAI_NEXT_HOP_TYPE_IP;
    sai_ip_address_t ip_addr{};
    sai_object_id_t rif_tun_oid = SAI_NULL_OBJECT_ID; // RIF or TUNNEL
    la_mpls_label_vec_t m_labels;                     // For SAI_NEXT_HOP_TYPE_MPLS
    la_obj_wrap<la_prefix_object> m_prefix_object;

    // tunnel next hop, TODO la next hop id/gid holes by tunnel next hop
    la_obj_wrap<la_l2_service_port> m_vxlan_port;
    sai_mac_t m_tunnel_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint32_t m_encap_vni = 0;

    bool has_mpls_labels()
    {
        return m_labels.size() != 0;
    }

    next_hop_entry()
    {
    }

    next_hop_entry(la_next_hop* nh, sai_next_hop_type_t t, sai_ip_address_t ipaddr) : next_hop(nh), type(t), ip_addr(ipaddr)
    {
    }

    explicit next_hop_entry(sai_next_hop_type_t t) : type(t)
    {
    }
};
}
}
#endif
