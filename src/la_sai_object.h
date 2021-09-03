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

#ifndef __LA_SAI_OBJECT_H__
#define __LA_SAI_OBJECT_H__

#include <tuple>

#include "common/ranged_index_generator.h"
#include "common/cereal_utils.h"

#include "saiobject.h"
#include "saistatus.h"
#include "saitypes.h"

#include "sai_utils.h"

namespace silicon_one

{
namespace sai
{
class lsai_device;

//
// 64 bits sai_object_id_t is encoded as the following
// The 64 bits are formatted as the following:
// -----------------------------------------------------------------
// |       8b          | 4b    |   8b     |  24b        |  20b     |
// -----------------------------------------------------------------
// | sai_object_type_t |sw_idx |  unused  | detail      |  index   |
// -----------------------------------------------------------------
// class lsai_object is used to perform the encoding and decoding.
//
// Tunnel Map object
// ---------------------------------------------------------------
// |       8b          | 4b    |  4b   |    28b         |  20    |
// ---------------------------------------------------------------
// | sai_object_type_t |sw_idx | tunnel|                |        |
// | TUNNEL_MAP        |       | type  |    unused      | index  |
// ---------------------------------------------------------------
//
// when key type is vni
// -------------------------------------------------------------
// |       8b          | 4b    |  4b   |  8b   |  24    |  16   |
// --------------------------------------------------------------
// | sai_object_type_t |sw_idx | tunnel| tunnel|        |       |
// | TUNNEL_MAP_ENTRY  |       | type  | map   |  key   | value |
// --------------------------------------------------------------
//
// when value type is vni
// -------------------------------------------------------------
// |       8b          | 4b    |  4b   |  8b   |  16   |  24   |
// -------------------------------------------------------------
// | sai_object_type_t |sw_idx | tunnel| tunnel|       |       |
// | TUNNEL_MAP_ENTRY  |       | type  | map   |  key  | value |
// -------------------------------------------------------------
//
// no vni in key or value
// -------------------------------------------------------------
// |       8b          | 4b    |  4b   |  8b   |  20   |  20   |
// -------------------------------------------------------------
// | sai_object_type_t |sw_idx | tunnel| tunnel|       |       |
// | TUNNEL_MAP_ENTRY  |       | type  | map   |  key  | value |
// -------------------------------------------------------------
//
// sai_object_type_t is the object type of this object id
//
// sw_idx is the la_device of this object belongs to.
//
// detail is used for different purpose depending on which sai_object
//        *  for bridge_port, the same la_l2_service_port, can be
//           SAI_OBJCECT_TYPE_BRIDGE_PORT or SAI_OBJECT_TYPE_VLAN_MEMBER
//        *  for route, since there is no SAI object id, we need to store
//           the action in the route's "NEXT HOP ID" which can be the sai
//           object in SAI_OBJECT_TYPE_NEXT_HOP, SAI_OBJECT_TYPE_NEXT_HOP_GROUP,
//           SAI_OBJECT_TYPE_ROUTER_INTERFACE, SAI_OBJECT_TYPE_PORT
//           (so there is no detail for those objects itself)
//
// index is the index of the corresponding obj_db
//
#define LA_SAI_TYPE_SIZE 8L
#define LA_SAI_SUB_TYPE_SIZE 8L
#define LA_SAI_SWITCH_ID_SIZE 4L
#define LA_SAI_ATTR_SIZE 24L
#define LA_SAI_ID_SIZE 20L
#define LA_SAI_SWITCH_ID_MASK ((1L << LA_SAI_SWITCH_ID_SIZE) - 1)
#define LA_SAI_MAX_TYPE ((1L << LA_SAI_TYPE_SIZE) - 1)
#define LA_SAI_MAX_SUB_TYPE ((1L << LA_SAI_SUB_TYPE_SIZE) - 1)
#define LA_SAI_MAX_ATTR ((1L << LA_SAI_ATTR_SIZE) - 1)
#define LA_SAI_MAX_ID ((1L << LA_SAI_ID_SIZE) - 1)
#define LA_SAI_TYPE_OFFSET (64 - LA_SAI_TYPE_SIZE)
#define LA_SAI_SWITCH_ID_OFFSET (64 - LA_SAI_TYPE_SIZE - LA_SAI_SWITCH_ID_SIZE)
#define LA_SAI_SUB_TYPE_OFFSET (LA_SAI_ID_SIZE + LA_SAI_ATTR_SIZE)
#define LA_SAI_ATTR_OFFSET LA_SAI_ID_SIZE
#define LA_SAI_ID_OFFSET 0L

enum class lsai_detail_field_e {
    NONE = 0,
    TYPE = 1,
    PORT = 2,
    LAG = 3,
    TUNNEL = 4,
    MAX,
};

enum class lsai_detail_type_e {
    BRIDGE_PORT = 0,
    QUEUE = 1,
    LAG_MEMBER = 2,
    TUNNEL_TERM = 3,
    SCHEDULER_GROUP = 4,
    MAX,
};

struct bridge_port_detail_t {
    uint32_t type : 4;
    uint32_t unused : 20;
    uint32_t reserved : 8;
};

//
// the route detail action is co-exist with
// next hop object and stored in the user data of a route.
//
// So the object type is next hop, index is for next hop
// but the detail is defined for route action as below:
//
struct queue_detail_t {
    uint32_t port : 8;
    uint32_t unused : 16;
    uint32_t reserved : 8;
};

struct lag_member_detail_t {
    uint32_t lag : 8;
    uint32_t unused : 16;
    uint32_t reserved : 8;
};

struct tunnel_term_detail_t {
    uint32_t type : 4;
    uint32_t tunnel_index : 20;
    uint32_t reserved : 8;
};

struct scheduler_group_detail_t {
    uint32_t port : 8;
    uint32_t unused : 16;
    uint32_t reserved : 8;
};

union lsai_detail_value_t {
    bridge_port_detail_t m_bridge_port_detail;
    queue_detail_t m_queue_detail;
    lag_member_detail_t m_lag_member_detail;
    tunnel_term_detail_t m_tunnel_term_detail;
    scheduler_group_detail_t m_scheduler_group_detail;
    uint32_t opaque;
};

class lsai_detail
{
public:
    lsai_detail_value_t value{};

    bool operator==(lsai_detail& detail)
    {
        lsai_detail_value_t v = detail.value;
        if (v.opaque == value.opaque) {
            return true;
        }
        return false;
    }

    bool operator!=(lsai_detail& detail)
    {
        return !(*this == detail);
    }

    void set(lsai_detail_type_e type, lsai_detail_field_e field, uint32_t v);

    void set(uint32_t x)
    {
        value.opaque = x;
    }

    uint32_t get(lsai_detail_type_e type, lsai_detail_field_e field);
};

//
// sai_object_id_t decoding data structure
//
class lsai_object
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

#define TUNNEL_MAP_TYPE_OFFSET 48
#define TUNNEL_MAP_TYPE_SIZE 4
#define TUNNEL_MAP_TYPE_MASK ((1L << TUNNEL_MAP_TYPE_SIZE) - 1)
#define TUNNEL_MAP_INDEX_OFFSET 40
#define TUNNEL_MAP_INDEX_SIZE 8
#define TUNNEL_MAP_INDEX_MASK ((1L << TUNNEL_MAP_INDEX_SIZE) - 1)
#define TUNNEL_MAP_ENTRY_VNI_SIZE 24
#define TUNNEL_MAP_ENTRY_VNI_MASK ((1L << TUNNEL_MAP_ENTRY_VNI_SIZE) - 1)
#define TUNNEL_MAP_ENTRY_VNI_COMP_SIZE 16
#define TUNNEL_MAP_ENTRY_VNI_COMP_MASK ((1L << TUNNEL_MAP_ENTRY_VNI_COMP_SIZE) - 1)
#define TUNNEL_MAP_ENTRY_NOT_VNI_SIZE 20
#define TUNNEL_MAP_ENTRY_NOT_VNI_MASK ((1L << TUNNEL_MAP_ENTRY_NOT_VNI_SIZE) - 1)

public:
    sai_object_type_t type = SAI_OBJECT_TYPE_NULL;
    uint32_t switch_id = 0;
    lsai_detail detail{};
    uint32_t index = 0;
    uint32_t tunnel_map_type = 0;
    uint32_t tunnel_map_entry_key = 0;
    uint32_t tunnel_map_entry_value = 0;

public:
    lsai_object();
    explicit lsai_object(sai_object_id_t oid);
    lsai_object(sai_object_type_t t, uint32_t sw, uint32_t id);

    std::shared_ptr<lsai_device> get_device() const
    {
        return m_device;
    }
    void set_device(std::shared_ptr<lsai_device> device)
    {
        m_device = device;
    }
    /// @brief      Compare if lsai_object is equal to another object.
    bool operator==(lsai_object& obj)
    {
        return std::tie(type, switch_id, index, detail.value.opaque)
               == std::tie(obj.type, obj.switch_id, obj.index, obj.detail.value.opaque);
    }

    bool operator!=(lsai_object& obj)
    {
        return !(*this == obj);
    }

    sai_object_id_t object_id() const;

private:
    std::shared_ptr<lsai_device> m_device;
};
}
}
#endif
