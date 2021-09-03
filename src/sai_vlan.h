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

#ifndef __SAI_VLAN_H__
#define __SAI_VLAN_H__

extern "C" {
#include "sai.h"
}

#include "api/npu/la_switch.h"
#include "sai_warm_boot.h"

namespace silicon_one
{
namespace sai
{

struct lsai_vlan_t {
    sai_object_id_t m_oid = SAI_NULL_OBJECT_ID;
    la_obj_wrap<la_switch> m_sdk_switch;
    sai_vlan_flood_control_type_t m_ucast_flood_type = SAI_VLAN_FLOOD_CONTROL_TYPE_ALL;
    sai_vlan_flood_control_type_t m_mcast_flood_type = SAI_VLAN_FLOOD_CONTROL_TYPE_ALL;
    sai_vlan_flood_control_type_t m_bcast_flood_type = SAI_VLAN_FLOOD_CONTROL_TYPE_ALL;
};
}
}
#endif
