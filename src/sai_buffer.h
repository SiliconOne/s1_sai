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

#ifndef __SAI_BUFFER_H__
#define __SAI_BUFFER_H__

namespace silicon_one
{
namespace sai
{

// Class to configure ingress priority group (IPG). A mac_port has 8
// SAI IPG's. TCs are mapped to IPGs via the QOS map
// SAI_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP.
class ingress_priority_group_entry
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    ingress_priority_group_entry() = default;
    explicit ingress_priority_group_entry(uint8_t ipg);
    sai_object_id_t get_buffer_profile_oid() const;
    static la_status set_tc_sqg(port_entry* pentry, la_traffic_class_t tc, la_uint_t sqg_to_set);
    la_status set_tc_profile(port_entry* pentry, sai_object_id_t buffer_profile_oid = SAI_NULL_OBJECT_ID);
    ~ingress_priority_group_entry() = default;

private:
    uint8_t m_ipg;
    sai_object_id_t m_buffer_profile_oid = SAI_NULL_OBJECT_ID;
};
}
}

#endif
