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

#ifndef __SAI_HOSTIF_H__
#define __SAI_HOSTIF_H__

#include <string>
#include "la_sai_object.h"
#include "sai_netlink_socket.h"

namespace silicon_one
{
namespace sai
{

struct port_entry;

// sai hostif interface related  information.
struct lsai_hostif {
    sai_object_id_t oid;
    sai_hostif_type_t hostif_attr_type; // netdev or fd etc
    sai_object_type_t port_type;
    std::string ifname;
    std::string multicast_group;
    bool oper_status = false;
    sai_object_id_t port_lag_id;
    uint16_t vid;
    int netdev_fd; // fd obtained when netdev intf is created.
    sai_hostif_vlan_tag_t tag_mode;
    uint32_t q_index; // queue index for packets egress out through the hostif intf
    std::shared_ptr<sai_netlink_socket> nl_sock;
    uint32_t genetlink_knet_index;
};

struct lsai_hostif_table_entry {
    sai_object_id_t oid;
    sai_hostif_table_entry_type_t type;
    sai_object_id_t port_id;
    sai_object_id_t trap_id;
    sai_hostif_table_entry_channel_type_t channel_type;
    sai_object_id_t host_if;
};

class sai_hostif
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS;

public:
    sai_hostif() = default;
    sai_hostif(std::shared_ptr<lsai_device> sdev) : m_sdev(sdev){};
    ~sai_hostif() = default;
    sai_status_t create_netdev(lsai_hostif& hostif);
    sai_status_t set_netdev_oper_status(lsai_hostif& hostif, bool oper_state);
    sai_status_t set_knet_netdev_set_oper(lsai_hostif& hostif, bool oper_state);
    sai_status_t add_knet_action(const lsai_hostif_table_entry& hostif_entry);
    sai_status_t initialize_knet_genetlinks();
    sai_status_t update_knet_genetlinks();
    sai_status_t create_knet_genetlink(lsai_hostif& hostif);
    sai_status_t remove_knet_genetlink(lsai_hostif& hostif);
    sai_status_t update_knet_port_vlan_id(port_entry* pentry);
    sai_status_t update_vlan_tag_handling(lsai_hostif& hostif);

private:
    sai_status_t set_dev_mac_address(const std::string& ifname, const sai_mac_t& mac);
    sai_status_t create_knet_netdev(lsai_hostif& hostif);
    sai_status_t create_tap_device(lsai_hostif& hostif);

    std::shared_ptr<lsai_device> m_sdev;
    static const uint8_t INVALID_GENETLINK_KNET_SLOTS = -1;
    // TODO: support updating group list for existing genetlink family
    static const uint8_t MAX_GENETLINK_KNET_SLOTS = 1;
    sai_object_id_t m_genetlink_knet_slots[MAX_GENETLINK_KNET_SLOTS];
};

class lsai_hostif_table_entry_key_t
{
public:
    lsai_hostif_table_entry_key_t() : lsai_hostif_table_entry_key_t(0, 0)
    {
    }
    lsai_hostif_table_entry_key_t(sai_object_id_t p, sai_object_id_t t) : port_id(p), trap_id(t)
    {
    }
    bool operator<(const lsai_hostif_table_entry_key_t& other) const
    {
        return std::tie(port_id, trap_id) < std::tie(other.port_id, other.trap_id);
    }

    sai_object_id_t port_id;
    sai_object_id_t trap_id;
};
}
}
#endif
