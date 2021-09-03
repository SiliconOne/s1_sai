// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco").
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

#ifndef __SAI_TRAP_H__
#define __SAI_TRAP_H__

#include <map>
#include <memory>

#include "common/weak_ptr_unsafe.h"
#include "api/types/la_qos_types.h"
#include "api/types/la_event_types.h"
#include "api/qos/la_meter_action_profile.h"
#include "api/qos/la_meter_profile.h"
#include "api/qos/la_meter_set.h"
#include "api/types/la_lpts_types.h"

#include "sai_db.h"
#include "sai_mirror.h"
#include "sai_policer.h"
#include "sai_warm_boot.h"
#include <memory>

using namespace std;

namespace silicon_one
{
namespace sai
{

class trap_manager;
class trap_base;

//
// class event_trap by SAI_OBJECT_TYPE_HOSTIF_TRAP
// This is used in traps obj_db, the index is actually sai_hostif_trap_type_t
// This object will never call allocate, remove and  release object id.
// It will always use set and erase member functions in obj_db.

enum class punt_code_e {
    IP2ME, // 0
    V6_NEIGHBOR_DISCOVERY,
    BGP,
    BGPV6,
    DHCP,
    DHCPV6,
    SNMP,
    SSH,
    BGP_KEEPALIVE,
    BGPV6_KEEPALIVE,
    LAST
};

enum class trap_config_type_e {
    EVENT = 0,
    L2CP,
    IPV4,
    IPV6,
    IPV4_IPV6,
};

struct trap_config {
    trap_config_type_e config_type;
    std::unique_ptr<trap_base> trap;
};

class trap_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    friend class trap_group;
    friend class trap_event;

public:
    trap_base() = default; // for warm boot
    trap_base(sai_object_id_t oid) : m_oid(oid)
    {
    }

    virtual la_status initialize(sai_packet_action_t a, uint32_t p, sai_object_id_t g) = 0;

    virtual trap_config_type_e type() const = 0;
    virtual ~trap_base();

    virtual la_status update_action(sai_packet_action_t a) = 0;
    virtual la_status update_priority(uint32_t p) = 0;

    sai_packet_action_t get_action() const;
    uint32_t get_priority() const;

    sai_object_id_t get_group() const;
    virtual la_status update_group(sai_object_id_t group_id) = 0;

    inline bool operator==(const trap_base& e) const
    {
        return ((m_oid == e.m_oid) && (m_action == e.m_action) && (m_priority == e.m_priority));
    }

    virtual void cleanup_snoop_configurations() = 0;
    virtual void cleanup_trap_configurations() = 0;

protected:
    sai_object_id_t m_oid = SAI_NULL_OBJECT_ID;
    sai_packet_action_t m_action = SAI_PACKET_ACTION_DROP;
    uint32_t m_priority = 0; // sai priority, 0 lowest
    sai_object_id_t m_group_id = SAI_NULL_OBJECT_ID;
    uint32_t m_mirror_id = INVALID_MIRROR_ID;
};

class trap_event : public trap_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    trap_event() = default; // for warm boot
    trap_event(sai_object_id_t oid) : trap_base(oid)
    {
    }

    ~trap_event();

    la_status initialize(sai_packet_action_t a, uint32_t p, sai_object_id_t g) override;

    la_status update_action(sai_packet_action_t a) override;

    la_status update_priority(uint32_t p) override;

    la_status update_group(sai_object_id_t group_id) override;

    trap_config_type_e type() const override
    {
        return trap_config_type_e::EVENT;
    }

    void cleanup_snoop_configurations() override;
    void cleanup_trap_configurations() override;

protected:
    la_status update();
    la_status create_mirror_cmd();
    la_uint_t get_la_priority();
    void set_priority(uint32_t priority);
};

class trap_l2cp : public trap_event
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    trap_l2cp() = default; // for warm boot
    trap_l2cp(sai_object_id_t oid) : trap_event(oid)
    {
    }

    ~trap_l2cp();

    la_status initialize(sai_packet_action_t a, uint32_t p, sai_object_id_t g) override;

    trap_config_type_e type() const override
    {
        return trap_config_type_e::L2CP;
    }

private:
    la_control_plane_classifier::key m_key;
};

class trap_lpts : public trap_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    trap_lpts() = default; // for warm boot
    trap_lpts(sai_object_id_t oid) : trap_base(oid)
    {
    }

    ~trap_lpts()
    {
    }

    virtual la_status initialize(sai_packet_action_t a, uint32_t p, sai_object_id_t g) override = 0;

    virtual la_status update_action(sai_packet_action_t a) override = 0;

    virtual la_status update_priority(uint32_t p) override = 0;

    virtual la_status update_group(sai_object_id_t group_id) override = 0;

    virtual trap_config_type_e type() const override = 0;

    void cleanup_snoop_configurations() override
    {
    }

    void cleanup_trap_configurations() override
    {
    }

protected:
    la_status initialize(sai_packet_action_t a, uint32_t p, lpts_type_e ip_type, sai_object_id_t g);

    la_status update_action(sai_packet_action_t a, lpts_type_e ip_type, la_l2_punt_destination* punt_dest);

    la_status update_priority(uint32_t p, lpts_type_e ip_type);

    la_status update_group(sai_object_id_t obj, lpts_type_e ip_type);

    la_status get_punt_dest(sai_packet_action_t action, la_l2_punt_destination*& l2_punt_dest) const;

    la_status insert_tcam(lpts_type_e ip_type, la_uint_t hw_dist, la_lpts_result& result);

    void remove_tcam(lpts_type_e ip_type, la_uint_t hw_dist);

    void remove(lpts_type_e ip_type);

    la_status insert(lpts_type_e ip_type);

    la_status find_lpts(lpts_type_e ip_type, uint32_t& pos, uint32_t& hw_dist);

    void set_action(sai_packet_action_t a)
    {
        m_action = a;
    }

    void set_priority(uint32_t p)
    {
        m_priority = p;
    }

    void set_group_id(sai_object_id_t g);

    la_obj_wrap<la_l2_punt_destination> m_punt_dest;
};

class trap_lpts_v4 : public trap_lpts
{
public:
    trap_lpts_v4() = default; // for warm boot
    trap_lpts_v4(sai_object_id_t oid) : trap_lpts(oid)
    {
    }

    ~trap_lpts_v4();

    la_status initialize(sai_packet_action_t a, uint32_t p, sai_object_id_t g) override;

    la_status update_action(sai_packet_action_t a) override;

    la_status update_priority(uint32_t p) override;

    la_status update_group(sai_object_id_t group_id) override;

    trap_config_type_e type() const override
    {
        return trap_config_type_e::IPV4;
    }
};

class trap_lpts_v6 : public trap_lpts
{
public:
    trap_lpts_v6() = default; // for warm boot
    trap_lpts_v6(sai_object_id_t oid) : trap_lpts(oid)
    {
    }

    ~trap_lpts_v6();

    la_status initialize(sai_packet_action_t a, uint32_t p, sai_object_id_t g) override;

    la_status update_action(sai_packet_action_t a) override;

    la_status update_priority(uint32_t p) override;

    la_status update_group(sai_object_id_t group_id) override;

    trap_config_type_e type() const override
    {
        return trap_config_type_e::IPV6;
    }
};

class trap_lpts_v4_v6 : public trap_lpts
{
public:
    trap_lpts_v4_v6() = default; // for warm boot
    trap_lpts_v4_v6(sai_object_id_t oid) : trap_lpts(oid)
    {
    }

    ~trap_lpts_v4_v6();

    la_status initialize(sai_packet_action_t a, uint32_t p, sai_object_id_t g) override;

    la_status update_action(sai_packet_action_t a) override;

    la_status update_priority(uint32_t p) override;

    la_status update_group(sai_object_id_t group_id) override;

    trap_config_type_e type() const override
    {
        return trap_config_type_e::IPV4_IPV6;
    }
};

class trap_group
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    friend class trap_base;
    friend class trap_event;
    friend class trap_l2cp;
    friend class trap_lpts;
    friend class trap_manager;

public:
    trap_group(weak_ptr_unsafe<trap_manager> t, bool a, uint32_t q, sai_object_id_t p)
        : m_trap_manager(t), m_admin_state(a), m_tc(q), m_policer_id(p)
    {
    }

    trap_group() = default; // for warm boot
    trap_group(trap_group&) = delete;

    ~trap_group();

    la_status initialize(std::shared_ptr<lsai_device>& sdev);

    bool get_admin_state() const
    {
        return m_admin_state;
    }

    uint32_t get_queue() const
    {
        return m_tc;
    }

    sai_object_id_t get_policer()
    {
        return m_policer_id;
    }

    la_status update_queue(uint32_t queue_index);

    la_status set_policer(sai_object_id_t policer_id);

    la_status update_policer(lasai_policer* new_policer);

    void set_id(sai_object_id_t obj_id)
    {
        m_group_id = obj_id;
    }

    sai_object_id_t get_id() const
    {
        return m_group_id;
    }

    void clear();

    void get_meters(std::vector<la_meter_set*>& meters);

    void get_lpts_meter(lpts_type_e ip_type, la_counter_or_meter_set*& counter_meter, la_meter_set*& meter)
    {
        if (ip_type == lpts_type_e::LPTS_TYPE_IPV4) {
            counter_meter = static_cast<la_counter_or_meter_set*>(m_lpts_ipv4_meters[0]);
            meter = m_lpts_ipv4_meters[1];
        } else {
            counter_meter = static_cast<la_counter_or_meter_set*>(m_lpts_ipv6_meters[0]);
            meter = m_lpts_ipv6_meters[1];
        }
    }

    la_status remove_meters();

private:
    std::vector<la_obj_wrap<la_meter_set>> m_lpts_ipv4_meters{2, nullptr};
    std::vector<la_obj_wrap<la_meter_set>> m_lpts_ipv6_meters{2, nullptr};

    weak_ptr_unsafe<trap_manager> m_trap_manager;

    // trap attributes
    bool m_admin_state = true;
    la_traffic_class_t m_tc = 0;
    sai_object_id_t m_policer_id = SAI_NULL_OBJECT_ID;
    sai_object_id_t m_group_id = SAI_NULL_OBJECT_ID;

    // list of traps belongs to this group
    std::vector<sai_hostif_trap_type_t> m_trap_list;

    la_status add_trap(sai_hostif_trap_type_t trap_type);
    void remove_trap(sai_hostif_trap_type_t trap_type);
};

class trap_manager : public std::enable_shared_from_this<trap_manager>
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    friend class trap_base;
    friend class trap_event;
    friend class trap_l2cp;
    friend class trap_lpts;
    friend class trap_group;
    friend class lsai_device; // need access to m_groups for get_object_key/count APIs

public:
    trap_manager() = default; // for warm boot
    trap_manager(std::shared_ptr<lsai_device> sdev) : m_sdev(sdev)
    {
    }
    ~trap_manager();
    void initialize_warm();
    la_status initialize();

    punt_code_e trap_type_to_punt_code(sai_hostif_trap_type_t trap_type);

    la_status packet_action_to_lpts_punt_dest(sai_packet_action_t action, la_l2_punt_destination*& l2_punt_dest);

    la_status get_trap_base_id(uint32_t sw_id, uint8_t code, uint8_t source, sai_object_id_t& trap_obj, bool& action_cont);

    la_status create_trap(sai_object_id_t oid, sai_packet_action_t pkt_action, la_uint_t priority, sai_object_id_t group_id);
    la_status remove_trap(sai_hostif_trap_type_t trap_type);
    la_status update_trap_action(sai_hostif_trap_type_t trap_type, sai_packet_action_t pkt_action);
    la_status add_mirror_id_to_type_map(uint32_t id, sai_hostif_trap_type_t trap_type);
    la_status remove_mirror_id_from_type_map(uint32_t id);
    uint8_t trap_knet_index_from_trap(sai_hostif_trap_type_t trap_type);
    la_status update_trap_priority(sai_hostif_trap_type_t trap_type, la_uint_t priority);
    la_status update_trap_group(sai_hostif_trap_type_t trap_type, sai_object_id_t group);
    la_status get_trap_action(sai_hostif_trap_type_t trap_type, sai_packet_action_t& pkt_action) const;
    la_status get_trap_priority(sai_hostif_trap_type_t trap_type, la_uint_t& priority) const;
    la_status get_trap_group(sai_hostif_trap_type_t trap_type, sai_object_id_t& group) const;

    la_status create_trap_group(sai_object_id_t& trap_group_id, bool admin_state, uint32_t queue_index, sai_object_id_t policer_id);
    la_status remove_trap_group(uint32_t group_idx);
    la_status get_trap_group_admin_state(uint32_t group_index, bool& admin_state);
    la_status get_trap_group_queue(uint32_t group_index, uint32_t& queue_index);
    la_status get_trap_group_policer(uint32_t group_index, sai_object_id_t& policer);
    la_status set_trap_group_admin_state(uint32_t group_index, bool admin_state);
    la_status set_trap_group_queue(uint32_t group_index, uint32_t queue_index);
    la_status set_trap_group_policer(uint32_t group_index, sai_object_id_t policer);
    la_status update_trap_group_policer(uint32_t group_index, lasai_policer* new_policer);
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev, uint32_t* object_count, sai_object_key_t* object_list) const;
    std::vector<la_meter_set*> get_trap_group_meters(sai_object_id_t oid);
    la_status dump_default_trap_meter_stats();

    // SAI_SWITCH_ATTR_DEFAULT_TRAP_GROUP initialized in trap_manager
    sai_object_id_t m_default_trap_group_id;
    lasai_policer m_default_policer;

    // sdk does not support meter sharing between events
    std::map<la_event_e, la_obj_wrap<la_meter_set>> m_event_meters;

    la_status create_statistical_policer(la_meter_set*& meter, lasai_policer* new_policer);

private:
    static constexpr int MAX_TRAP_GROUP = 32;

    std::shared_ptr<lsai_device> m_sdev;

    // manage event sequence
    std::vector<sai_hostif_trap_type_t> m_event_vec;

    // static map contains lpts trap the keylist
    std::map<sai_hostif_trap_type_t, std::vector<la_lpts_key>> m_lpts_info_map[(int)lpts_type_e::LAST];

    // static vector from punt code to trap type
    std::vector<sai_hostif_trap_type_t> m_trap_type_by_punt_code;

    // static map from trap type to punt code
    std::map<sai_hostif_trap_type_t, punt_code_e> m_punt_code_by_trap_type;

    // static map from event code to trap type
    std::map<la_event_e, sai_hostif_trap_type_t> m_trap_type_by_event_code;

    // static map from trap_base_type to list of event codes
    std::map<sai_hostif_trap_type_t, std::vector<la_event_e>> m_events_by_trap;

    // static map from trap type to index configured to kernel
    std::map<sai_hostif_trap_type_t, uint8_t> m_trap_to_knet_index;

    // map from trap type to configuration type
    std::map<sai_hostif_trap_type_t, trap_config> m_config_map;

    // sdk la_lpts one for v4 and one for v6
    la_obj_wrap<la_lpts> m_lpts_ptrs[(int)lpts_type_e::LAST] = {};

    // manage v4/v6 lpts traps sequence
    std::vector<sai_hostif_trap_type_t> m_lpts_vec[(int)lpts_type_e::LAST];

    obj_db<std::shared_ptr<trap_group>> m_groups{SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP, MAX_TRAP_GROUP};

    // map from mirror id to trap type
    std::map<uint32_t, sai_hostif_trap_type_t> m_trap_type_by_mirror_id;

    std::map<uint32_t, la_obj_wrap<la_l2_mirror_command>> m_snoop_l2_mirror_cmd;

    std::map<sai_hostif_trap_type_t, la_obj_wrap<la_meter_set>> m_default_meter_sets[(int)lpts_type_e::LAST];

    void initialize_config_map();
    void initialize_events_by_trap();
    void initialize_trap_type_punt_code_map();
    void initialize_trap_type_event_code_map();
    void initialize_lpts_info_map();
    sai_status_t initialize_kernel_trap_tables();

    la_status create_default_meter(la_meter_set*& meter);
};
}
}
#endif
