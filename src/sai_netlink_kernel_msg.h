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

#ifndef __SAI_NETLINK_KERNEL_MSG__
#define __SAI_NETLINK_KERNEL_MSG__

#include <linux/netlink.h>
#include <netlink/types.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/mngt.h>
#include <memory>
#include <vector>
#include <cassert>
#include "common/cereal_utils.h"

namespace silicon_one
{

namespace sai
{

constexpr uint32_t SAI_NETLINK_KERNEL_VERSION = 1;

enum sample_nl_params { MAX_SAMPLING_GROUPS = 4, GROUP_NAME_SIZE = 16 };

typedef uint8_t trap_source_t;
typedef uint8_t trap_code_t;
typedef uint32_t trap_id_t;
typedef char group_names_t[MAX_SAMPLING_GROUPS][GROUP_NAME_SIZE];
typedef uint8_t leaba_netlink_enum_t;

enum trap_type_t { TRAP_TYPE_DIRECT = 0, TRAP_TYPE_TABLE1 = 1, TRAP_TYPE_TABLE2 = 2, TRAP_TYPE_TABLE3 = 3 };
enum trap_map_types_t { TRAP_MAP_ID_ONLY, TRAP_MAP_ID_AND_SRC };
enum trap_action_t {
    TRAP_ACTION_NOT_SET = 0,
    TRAP_ACTION_SEND_TO_NETDEV,
    TRAP_ACTION_SEND_TO_SAI,
    TRAP_ACTION_SEND_TO_GROUP1,
    TRAP_ACTION_SEND_TO_GROUP2,
    TRAP_ACTION_SEND_TO_GROUP3,
    TRAP_ACTION_SEND_TO_GROUP4,
    TRAP_ACTION_DEFAULT
};

enum gen_nl_params { NET_DEV_NAME_SIZE = 16, MAX_ATTR_CNT = 3, DEFAULT_ATTR_ID = 2 };

enum hostif_nic_t { DEFAULT_NIC = 0, NIC1, NIC2, NIC3, NIC4, NIC5, NIC6, NIC7, NIC8 };

enum gen_nl_kernel_comands {
    /* SAI -> kernel module */
    NL_KERNEL_MSG_STRING = 1,
    NL_KERNEL_MSG_BIN,
    NL_KERNEL_ADD_NETDEV,
    NL_KERNEL_REMOVE_NETDEV,

    NL_KERNEL_SET_TRAP_TYPE,
    NL_KERNEL_REMOVE_TRAP_TYPE,

    NL_KERNEL_SET_TRAP,
    NL_KERNEL_REMOVE_TRAP,

    NL_KERNEL_SET_TRAP_ACTION,

    NL_KERNEL_SET_DEFAULT_ACTION,

    NL_KERNEL_CLEAR,

    NL_KERNEL_CREATE_SAMPLING_NL,

    NL_KERNEL_SET_SAMPLE_RATE,

    NL_KERNEL_CHANGE_VLAN_CONFIG,

    /* kernel module -> SAI */
    NL_KERNEL_LAST_CMD_STATUS,
    NL_KERNEL_MODULE_STATUS // dirty or not
};

enum gen_nl_kernel_cmd_status { NL_KERNEL_STATUS_OK, NL_KERNEL_STATUS_FAIL };

enum sai_kernel_attributes { SAI_KERNEL_DEV_UID_ATTRIBUTE = 1, SAI_KERNEL_GENERIC_DATA_ATTRIBUTE };

struct LA_PACKED sai_kernel_add_netdev_msg {
    la_system_port_gid_t sys_port_gid;
    char ifname[NET_DEV_NAME_SIZE];
    sai_mac_t mac;
    leaba_netlink_enum_t vlan_tag; // sai_hostif_vlan_tag_t
    leaba_netlink_enum_t nic;
    uint16_t vlan_tag_id;
    uint8_t pkt_class;
};

struct LA_PACKED sai_kernel_remove_netdev_msg {
    char ifname[NET_DEV_NAME_SIZE];    // name of the net dev interface to remove from kernel
    la_system_port_gid_t sys_port_gid; // if ifname is empty string, port is used as deletion criteria
    bool force;                        // if true, remove device from the system even if not registered by module
};

struct LA_PACKED sai_kernel_change_vlan_config_msg {
    la_system_port_gid_t sys_port_gid;
    leaba_netlink_enum_t vlan_tag; // hostif_vlan_tag_t
    uint16_t vlan_tag_id;
};

struct LA_PACKED sai_set_trap_type_msg {
    trap_source_t source;
    leaba_netlink_enum_t type; // (trap_type_t)
    trap_id_t trap_id;
};

struct LA_PACKED sai_remove_trap_type_msg {
    trap_source_t source;
};

struct LA_PACKED sai_set_trap_msg {
    trap_code_t code;
    trap_id_t trap_id;
    leaba_netlink_enum_t trap_type; // defines table1 or table2 (trap_type_t)
};

struct LA_PACKED sai_remove_trap_msg {
    trap_code_t code;
    leaba_netlink_enum_t type; // (trap_type_t)
};

/* TRAP MAP API */
struct LA_PACKED sai_set_trap_action_msg {
    leaba_netlink_enum_t type; // (trap_map_types_t)
    trap_id_t trap_id;
    la_system_port_gid_t port_id;
    leaba_netlink_enum_t action; // (trap_action_t)
};

/* SET NETLINK GROUPS FOR PSAMPLE */
struct LA_PACKED sai_kernel_set_sampling_slots_msg {
    char family_name[GENL_NAMSIZ];
    uint16_t groups_cnt;
    group_names_t groups_names;
};

/* SET SAMPLE RATE FOR PSAMPLE */
struct LA_PACKED sai_kernel_set_sample_rate_msg {
    trap_code_t code;
    uint32_t sample_rate;
};

/* SET DEFAULT ACTION */
struct LA_PACKED sai_set_default_action_msg {
    leaba_netlink_enum_t action; // (trap_action_t)
};

struct LA_PACKED kernel_cmd_status {
    leaba_netlink_enum_t status; // (gen_nl_kernel_cmd_status)
};

struct LA_PACKED kernel_module_status {
    bool dirty;
};

class sai_kernel_netlink_msg : public sai_netlink_msg
{
public:
    sai_kernel_netlink_msg(la_device_id_t dev_id, uint32_t command) : sai_netlink_msg(command)
    {
        m_device_id = dev_id;
        m_attributes.push_back(
            sai_netlink_msgAttribute{.attr = (int32_t)SAI_KERNEL_DEV_UID_ATTRIBUTE, .type = nl_attr_type::U16, {.u16 = dev_id}});
    };

private:
    la_device_id_t m_device_id;
};

class sai_kernel_get_module_status : public sai_kernel_netlink_msg
{
public:
    sai_kernel_get_module_status(la_device_id_t dev_id) : sai_kernel_netlink_msg(dev_id, NL_KERNEL_MODULE_STATUS){};

    uint32_t version() const override
    {
        return SAI_NETLINK_KERNEL_VERSION;
    }

protected:
    void add_attributes() override
    {
    }
};

class sai_kernel_remove_netdev : public sai_kernel_netlink_msg
{
public:
    sai_kernel_remove_netdev(la_device_id_t dev_id, std::string name, la_system_port_gid_t sys_port_gid, bool force)
        : sai_kernel_netlink_msg(dev_id, NL_KERNEL_REMOVE_NETDEV)
    {
        strncpy(m_data.ifname, name.c_str(), NET_DEV_NAME_SIZE - 1);
        m_data.force = force;
        m_data.sys_port_gid = sys_port_gid;
    };

    uint32_t version() const override
    {
        return SAI_NETLINK_KERNEL_VERSION;
    }

protected:
    void add_attributes() override
    {
        m_attributes.push_back(sai_netlink_msgAttribute{.attr = (int32_t)SAI_KERNEL_GENERIC_DATA_ATTRIBUTE,
                                                        .type = nl_attr_type::DATA,
                                                        {.packet_data = (uint8_t*)&m_data},
                                                        .size = sizeof(sai_kernel_remove_netdev_msg)});
    }

    sai_kernel_remove_netdev_msg m_data;
};

class sai_kernel_add_netdev : public sai_kernel_netlink_msg
{

public:
    sai_kernel_add_netdev(la_device_id_t dev_id,
                          la_system_port_gid_t port_gid,
                          std::string name,
                          sai_mac_t mac,
                          sai_hostif_vlan_tag_t vtag,
                          hostif_nic_t nic,
                          uint16_t vlan_tag_id,
                          uint8_t pkt_class)

        : sai_kernel_netlink_msg(dev_id, NL_KERNEL_ADD_NETDEV)
    {
        m_data.sys_port_gid = port_gid;
        m_data.vlan_tag = vtag;
        m_data.nic = nic;
        m_data.vlan_tag_id = vlan_tag_id;
        m_data.pkt_class = pkt_class;
        strncpy(m_data.ifname, name.c_str(), NET_DEV_NAME_SIZE - 1);
        memcpy(m_data.mac, mac, sizeof(sai_mac_t));
    };

    uint32_t version() const override
    {
        return SAI_NETLINK_KERNEL_VERSION;
    }

protected:
    void add_attributes() override
    {
        m_attributes.push_back(sai_netlink_msgAttribute{.attr = (int32_t)SAI_KERNEL_GENERIC_DATA_ATTRIBUTE,
                                                        .type = nl_attr_type::DATA,
                                                        {.packet_data = (uint8_t*)&m_data},
                                                        .size = sizeof(sai_kernel_add_netdev_msg)});
    }

    sai_kernel_add_netdev_msg m_data;
};

/* TRAP TYPE COMMANDS */

class sai_kernel_set_trap_type : public sai_kernel_netlink_msg
{
public:
    sai_kernel_set_trap_type(la_device_id_t dev_id, trap_source_t source, trap_type_t type, trap_id_t trap_id)
        : sai_kernel_netlink_msg(dev_id, NL_KERNEL_SET_TRAP_TYPE)
    {
        m_data.source = source;
        m_data.type = type;
        m_data.trap_id = trap_id;
    };

    uint32_t version() const override
    {
        return SAI_NETLINK_KERNEL_VERSION;
    }

protected:
    void add_attributes() override
    {
        m_attributes.push_back(sai_netlink_msgAttribute{.attr = (int32_t)SAI_KERNEL_GENERIC_DATA_ATTRIBUTE,
                                                        .type = nl_attr_type::DATA,
                                                        {.packet_data = (uint8_t*)&m_data},
                                                        .size = sizeof(sai_set_trap_type_msg)});
    }

    sai_set_trap_type_msg m_data;
};

class sai_kernel_remove_trap_type : public sai_kernel_netlink_msg
{
public:
    sai_kernel_remove_trap_type(la_device_id_t dev_id, trap_source_t source)
        : sai_kernel_netlink_msg(dev_id, NL_KERNEL_REMOVE_TRAP_TYPE)
    {
        m_data.source = source;
    };

    uint32_t version() const override
    {
        return SAI_NETLINK_KERNEL_VERSION;
    }

protected:
    void add_attributes() override
    {
        m_attributes.push_back(sai_netlink_msgAttribute{.attr = (int32_t)SAI_KERNEL_GENERIC_DATA_ATTRIBUTE,
                                                        .type = nl_attr_type::DATA,
                                                        {.packet_data = (uint8_t*)&m_data},
                                                        .size = sizeof(sai_remove_trap_type_msg)});
    }

    sai_remove_trap_type_msg m_data;
};

/* TRAP COMMANDS */

class sai_kernel_set_trap : public sai_kernel_netlink_msg
{
public:
    sai_kernel_set_trap(la_device_id_t dev_id, trap_code_t code, trap_id_t trap_id, trap_type_t type)
        : sai_kernel_netlink_msg(dev_id, NL_KERNEL_SET_TRAP)
    {
        m_data.code = code;
        m_data.trap_id = trap_id;
        m_data.trap_type = type;
    };

    uint32_t version() const override
    {
        return SAI_NETLINK_KERNEL_VERSION;
    }

protected:
    void add_attributes() override
    {
        m_attributes.push_back(sai_netlink_msgAttribute{.attr = (int32_t)SAI_KERNEL_GENERIC_DATA_ATTRIBUTE,
                                                        .type = nl_attr_type::DATA,
                                                        {.packet_data = (uint8_t*)&m_data},
                                                        .size = sizeof(sai_set_trap_msg)});
    }

    sai_set_trap_msg m_data;
};

class sai_kernel_remove_trap : public sai_kernel_netlink_msg
{
public:
    sai_kernel_remove_trap(la_device_id_t dev_id, trap_code_t code, trap_type_t type)
        : sai_kernel_netlink_msg(dev_id, NL_KERNEL_REMOVE_TRAP)
    {
        m_data.code = code;
        m_data.type = type;
    };

    uint32_t version() const override
    {
        return SAI_NETLINK_KERNEL_VERSION;
    }

protected:
    void add_attributes() override
    {
        m_attributes.push_back(sai_netlink_msgAttribute{.attr = (int32_t)SAI_KERNEL_GENERIC_DATA_ATTRIBUTE,
                                                        .type = nl_attr_type::DATA,
                                                        {.packet_data = (uint8_t*)&m_data},
                                                        .size = sizeof(sai_remove_trap_msg)});
    }

    sai_remove_trap_msg m_data;
};

class sai_kernel_add_trap_action : public sai_kernel_netlink_msg
{
public:
    sai_kernel_add_trap_action(la_device_id_t dev_id,
                               trap_map_types_t type,
                               trap_id_t trap_id,
                               la_system_port_gid_t port_id,
                               trap_action_t action)
        : sai_kernel_netlink_msg(dev_id, NL_KERNEL_SET_TRAP_ACTION)
    {
        m_data.type = type;
        m_data.trap_id = trap_id;
        m_data.port_id = port_id;
        m_data.action = action;
    };

    uint32_t version() const override
    {
        return SAI_NETLINK_KERNEL_VERSION;
    }

protected:
    void add_attributes() override
    {
        m_attributes.push_back(sai_netlink_msgAttribute{.attr = (int32_t)SAI_KERNEL_GENERIC_DATA_ATTRIBUTE,
                                                        .type = nl_attr_type::DATA,
                                                        {.packet_data = (uint8_t*)&m_data},
                                                        .size = sizeof(sai_set_trap_action_msg)});
    }

    sai_set_trap_action_msg m_data;
};

class sai_kernel_set_default_action : public sai_kernel_netlink_msg
{
public:
    sai_kernel_set_default_action(la_device_id_t dev_id, trap_action_t action)
        : sai_kernel_netlink_msg(dev_id, NL_KERNEL_SET_DEFAULT_ACTION)
    {
        m_data.action = action;
    };

    uint32_t version() const override
    {
        return SAI_NETLINK_KERNEL_VERSION;
    }

protected:
    void add_attributes() override
    {
        m_attributes.push_back(sai_netlink_msgAttribute{.attr = (int32_t)SAI_KERNEL_GENERIC_DATA_ATTRIBUTE,
                                                        .type = nl_attr_type::DATA,
                                                        {.packet_data = (uint8_t*)&m_data},
                                                        .size = sizeof(sai_set_trap_action_msg)});
    }

    sai_set_default_action_msg m_data;
};

class sai_kernel_set_sampling_slots : public sai_kernel_netlink_msg
{
public:
    sai_kernel_set_sampling_slots(la_device_id_t dev_id, std::string family_name, std::vector<std::string> groups)
        : sai_kernel_netlink_msg(dev_id, NL_KERNEL_CREATE_SAMPLING_NL)
    {
        strncpy(m_data.family_name, family_name.c_str(), 16);

        for (size_t i = 0; i < groups.size(); i++) {
            strncpy(m_data.groups_names[i], groups[i].c_str(), GROUP_NAME_SIZE);
        }

        m_data.groups_cnt = groups.size();
    };

    uint32_t version() const override
    {
        return SAI_NETLINK_KERNEL_VERSION;
    }

protected:
    void add_attributes() override
    {
        m_attributes.push_back(sai_netlink_msgAttribute{.attr = (int32_t)SAI_KERNEL_GENERIC_DATA_ATTRIBUTE,
                                                        .type = nl_attr_type::DATA,
                                                        {.packet_data = (uint8_t*)&m_data},
                                                        .size = sizeof(sai_kernel_set_sampling_slots_msg)});
    }

    sai_kernel_set_sampling_slots_msg m_data;
};

class sai_kernel_set_sampling_rate : public sai_kernel_netlink_msg
{
public:
    sai_kernel_set_sampling_rate(la_device_id_t dev_id, trap_code_t code, uint32_t sample_rate)
        : sai_kernel_netlink_msg(dev_id, NL_KERNEL_SET_SAMPLE_RATE)
    {
        m_data.code = code;
        m_data.sample_rate = sample_rate;
    };

    uint32_t version() const override
    {
        return SAI_NETLINK_KERNEL_VERSION;
    }

protected:
    void add_attributes() override
    {
        m_attributes.push_back(sai_netlink_msgAttribute{.attr = (int32_t)SAI_KERNEL_GENERIC_DATA_ATTRIBUTE,
                                                        .type = nl_attr_type::DATA,
                                                        {.packet_data = (uint8_t*)&m_data},
                                                        .size = sizeof(sai_kernel_set_sample_rate_msg)});
    }

    sai_kernel_set_sample_rate_msg m_data;
};

class sai_kernel_change_vlan_config : public sai_kernel_netlink_msg
{
public:
    sai_kernel_change_vlan_config(la_device_id_t dev_id,
                                  la_system_port_gid_t port_gid,
                                  sai_hostif_vlan_tag_t tag,
                                  uint16_t vlan_tag_id)
        : sai_kernel_netlink_msg(dev_id, NL_KERNEL_CHANGE_VLAN_CONFIG)
    {
        m_data.sys_port_gid = port_gid;
        m_data.vlan_tag = tag;
        m_data.vlan_tag_id = vlan_tag_id;
    };

    uint32_t version() const override
    {
        return SAI_NETLINK_KERNEL_VERSION;
    }

protected:
    void add_attributes() override
    {
        m_attributes.push_back(sai_netlink_msgAttribute{.attr = (int32_t)SAI_KERNEL_GENERIC_DATA_ATTRIBUTE,
                                                        .type = nl_attr_type::DATA,
                                                        {.packet_data = (uint8_t*)&m_data},
                                                        .size = sizeof(sai_kernel_change_vlan_config_msg)});
    }

    sai_kernel_change_vlan_config_msg m_data;
};

class sai_kernel_clear : public sai_kernel_netlink_msg
{
public:
    sai_kernel_clear(la_device_id_t dev_id) : sai_kernel_netlink_msg(dev_id, NL_KERNEL_CLEAR){};

    uint32_t version() const override
    {
        return SAI_NETLINK_KERNEL_VERSION;
    }

protected:
    void add_attributes() override
    {
    }
};
}
}

#endif //__SAI_NETLINK_KERNEL_MSG__
