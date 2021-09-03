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

#ifndef __SAI_NEXT_HOP_GROUP_H__
#define __SAI_NEXT_HOP_GROUP_H__

#include <string>
#include <memory>
#include <set>

extern "C" {
#include <sai.h>
}

#include "api/npu/la_ecmp_group.h"
#include "la_sai_object.h"
#include "sai_warm_boot.h"

namespace silicon_one
{
namespace sai
{
class next_hop_group_member
{
    friend class lsai_next_hop_group;

public:
    next_hop_group_member()
    {
    }

    next_hop_group_member(sai_object_id_t nh_oid, sai_object_id_t group_oid) : m_nexthop_oid(nh_oid), m_group_oid(nh_oid)
    {
    }

public:
    sai_object_id_t m_nexthop_oid = 0;
    sai_object_id_t m_group_oid = 0;
    sai_uint32_t m_weight = 1; // SAI_NEXT_HOP_GROUP_MEMBER_ATTR_WEIGHT
};

class lsai_next_hop_group
{
public:
    lsai_next_hop_group()
    {
    }

    lsai_next_hop_group(la_ecmp_group* ecmp_ptr) : m_ecmp_group(ecmp_ptr), m_ecmp_group_stage_2(nullptr)
    {
    }

    sai_status_t create_tunnel_next_hop_group(std::shared_ptr<lsai_device> sdev); // Make Level2 (stage2) entry
    la_l3_destination* get_tunnel_next_hop_group() const
    {
        return m_ecmp_group_stage_2;
    }

public:
    la_obj_wrap<la_ecmp_group> m_ecmp_group;
    std::set<sai_object_id_t> m_members;
    la_obj_wrap<la_ecmp_group> m_ecmp_group_stage_2 = nullptr;
    /* add_member(); */
    /* remove_member(); */
};
}
}
#endif
