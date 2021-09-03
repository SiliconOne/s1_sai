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

#ifndef __SAI_DEVICE_H__
#define __SAI_DEVICE_H__

#include "api/npu/la_ac_profile.h"
#include "api/npu/la_l2_service_port.h"
#include "api/npu/la_l3_port.h"
#include "api/qos/la_egress_qos_profile.h"
#include "api/qos/la_ingress_qos_profile.h"
#include "api/system/la_device.h"
#include "api/system/la_pci_port.h"
#include "api/system/la_recycle_port.h"
#include "api/tm/la_ifg_scheduler.h"
#include "api/tm/la_unicast_tc_profile.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_qos_types.h"
#include "api/types/la_mpls_types.h"
#include "common/math_utils.h"
#include "common/ranged_index_generator.h"
#include "common/transaction.h"
#include "sai_constants.h"
#include "device_params.h"
#include "sai_leaba.h"
#include "la_sai_board.h"
#include "sai_utils.h"
#include "la_sai_object.h"
#include "sai_acl.h"
#include "sai_debug_counter.h"
#include "sai_trap.h"
#include "sai_db.h"
#include "sai_qos.h"
#include "sai_pfc.h"
#include "sai_hostif.h"
#include "sai_scheduler.h"
#include "sai_tunnel.h"
#include "sai_mpls.h"
#include "sai_warm_boot.h"
#include "sai_wred.h"
#include "sai_policer.h"
#include "sai_bridge.h"
#include "sai_vlan.h"
#include "sai_next_hop.h"
#include "sai_next_hop_group.h"
#include "sai_netlink_kernel_socket.h"
#include "sai_mirror.h"
#include "sai_system_port.h"
#include "sai_tam.h"
#include "sai_samplepacket.h"
#include "sai_scheduler_group.h"
#include "sai_buffer.h"
#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <tuple>
#include <vector>
#include <set>
#include <chrono>
#include <netinet/in.h>
#include <linux/kernel.h>

namespace silicon_one
{
namespace sai
{
constexpr std::chrono::milliseconds MAX_FDB_NOTIFICAITON_WAIT_TIME{50};

class lasai_qos;
class lsai_logger_throttled;

struct ipv4_addr_less {
    inline bool operator()(const la_ipv4_addr_t& lhs, const la_ipv4_addr_t& rhs) const
    {
        return lhs.s_addr < rhs.s_addr;
    }
};

struct ipv6_addr_less {
    inline bool operator()(const la_ipv6_addr_t& lhs, const la_ipv6_addr_t& rhs) const
    {
        return lhs.s_addr < rhs.s_addr;
    }
};

//
//
// router interface construction info
// vrf is mandatory for sai router interface
// mac_address is mandatory for la api but not sai
// bridge is mandatory for la svi but for sai is in bridge api
//
struct rif_entry {
    la_obj_wrap<la_l3_port> l3_port;
    sai_object_id_t vrf_obj = 0;
    la_mac_addr_t mac_addr{};
    sai_object_id_t bridge_obj = 0;
    sai_object_id_t port_obj = 0;
    sai_router_interface_type_t type = SAI_ROUTER_INTERFACE_TYPE_PORT;

    sai_object_id_t ingress_acl = 0;
    sai_object_id_t egress_acl = 0;

    uint16_t outer_vlan_id = 0;
    uint32_t mtu = 1514;
    bool m_admin_v4_state = true;
    bool m_admin_v6_state = true;

    // ip to next hop obj id
    std::map<la_ipv4_addr_t, sai_object_id_t, ipv4_addr_less> m_v4_neighbors;
    std::map<la_ipv6_addr_t, sai_object_id_t, ipv6_addr_less> m_v6_neighbors;
    std::map<la_ipv6_addr_t, la_mac_addr_t, ipv6_addr_less> m_v6_link_locals;
};

struct ipv4_prefix_less {
    inline bool operator()(const la_ipv4_prefix_t& lhs, const la_ipv4_prefix_t& rhs) const
    {
        return std::tie(lhs.addr.s_addr, lhs.length) < std::tie(rhs.addr.s_addr, rhs.length);
    }
};

struct ipv6_prefix_less {
    inline bool operator()(const la_ipv6_prefix_t& lhs, const la_ipv6_prefix_t& rhs) const
    {
        return std::tie(lhs.addr.s_addr, lhs.length) < std::tie(rhs.addr.s_addr, rhs.length);
    }
};

// vrf structure holds all the locally
struct vrf_entry {
    sai_object_id_t vrf_oid = SAI_NULL_OBJECT_ID;
    la_obj_wrap<la_vrf> vrf;
    la_obj_wrap<la_switch> vxlan_switch;
    la_obj_wrap<la_svi_port> vxlan_svi;
    std::set<sai_object_id_t> m_router_interfaces; // router interfaces belonging to this vrf
    uint32_t vxlan_switch_refcount = 0;
    uint32_t decap_vni = 0;
    // ip subnet to router interface id
    std::map<la_ipv4_prefix_t, sai_object_id_t, ipv4_prefix_less> m_v4_local_subnets;
    std::map<la_ipv6_prefix_t, sai_object_id_t, ipv6_prefix_less> m_v6_local_subnets;

    // sai vxlan tunnel next hop object id to la vxlan next hop per overlay vrf
    std::map<sai_object_id_t, la_obj_wrap<la_vxlan_next_hop>> m_vxlan_next_hops;

    // holds all the tunnel next hops to the same remote address for this underlay vrf
    std::map<la_ipv4_addr_t, std::set<sai_object_id_t>, ipv4_addr_less> m_remote_loopback_nexthops;

    // holds the vrf mac address
    sai_mac_t m_vrf_mac;
    bool m_admin_v4_state = true;
    bool m_admin_v6_state = true;
};

struct mac_and_src_port_entry {
    sai_object_id_t switch_id;
    sai_mac_t mac_address;
    sai_object_id_t bv_id;
    sai_object_id_t port_id;
};

//
// bridge_port_entry
// The bridge port entry is used to support bridge port or vlan member.
// The creation sequence is according to the following:
//
// .1D bridge port (bridge_port_type == SAI_BRIDGE_PORT_TYPE_SUB_PORT)
// 1. untagged
//    a. if does not exist in the ether port, then add a new l2 service port
//       (noted, even there is a tagged service port for the same bridge on
//        the same ethernet port, this untagged port is still created)
//    b. if exist in the ether port, then do nothing. "return error" ?
// 2. tagged
//    a. if does not exist in the ether port, then add a new l2 service port
//       (noted, even there is a untagged service port for the same bridge
//        on the same ethernet port, this untagged port is still created)
//    b. if exist in the ether port, then do nothing. "return error"
//
//.1Q bridge port (bridge_port_type == SAI_BRIDGE_PORT_TYPE_PORT)
// ==> create untagged L2 service port for vlan 1
//    1. create vlan member when vlan == 1
//       a. vlan member is untagged
//          same l2_service_port as .1Q bridge port (same index)
//
//       b. vlan member is tagged
//          i) if does not exist in the etherport
//             create a new l2 service port
//          ii) if exist in the etherport, "return error"
//
//    2. create vlan member when vlan != 1
//       a. vlan member is untagged
//          same l2_service_port as .1Q bridge port (same index)
//          detach from previous bridge
//          attach to the new bridge
//
//       b. vlan member is tagged
//          add new l2_service_port for the .1Q bridge port
//
//
// "la_create_l2_bridge_port" is used to create bridge_port_entry
//
// bridge port entry is used by the following bridge port types
//     SAI_BRIDGE_PORT_TYPE_PORT
//     SAI_BRIDGE_PORT_TYPE_SUB_PORT
//
// bridge port object is composed by
//        sai object type + bridge port type + bp_index
// vlan member object is composed by
//        sai object type + vm_index
//
// bp_index and vm_index are the indexes managed by bridge_ports obj_db.
//
// 1.  When the bridge_port_entry is untagged, then
//   a. for .1q bridge port,
//         bp_index == vm_index
// .    1q bridge port and vlan member point to the same la_l2_service_port.
//
//   b. for .1d bridge port
//      the bp_index for this bridge port entry should be unique.
//
// 2.  When the bridge_port_entry is tagged, then
//   a. for vlan member
//      the vm_index for this vlan memeber entry should be unique.
//
//   b. for .1d bridge port (never be .1q bridge port)
//      the bp_index for this bridge port entry should be unique.
//
// ****
// For untagged bridge entry in .1Q case,
//    since both bridge port and vlan member share  the same
//    bridge port entry, the bridge port entry will be the following:
//
// l2_port *-- the same for both .1q bridge port and vlan member
// vlan_member_oid  *-- vlan_member_oid
// bridge_port_oid  *-- bridge_port_oid
// vlan_id -- vlan to be tagged.
// bridge_obj -- vlan obj if vlan member exist, else default bridge
// port_obj *-- ether port for bridge port, bridge port for vlan mem
// is_tagged *-- false
// *-- means no change when vlan member create with the bridge port
//
struct bridge_port_entry {
    la_obj_wrap<la_l2_service_port> l2_port; // for bridge port or vlan member
    sai_object_id_t vlan_member_oid = 0;     // vlan member object id
    sai_object_id_t bridge_port_oid = 0;     // bridge port object id
    uint16_t vlan_id = 0;                    // used for .1d bridge port or vlan member tagging
    sai_object_id_t bridge_obj = 0;          // for vlan member, this vlan_obj
    sai_object_id_t port_obj = 0;            // for vlan member, this is bridge_port_obj
    bool is_tagged = false;                  // for .1d bridge port or vlan member tagging info
    sai_uint16_t egr_dot1q_vlan = 0;         // for egress .1q tag vlan rewrite. (snake function test)
    sai_bridge_port_fdb_learning_mode_t learn_mode = SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DROP; // for caching upper layer config
    sai_object_id_t ingress_acl_oid = 0;
    sai_object_id_t egress_acl_oid = 0;

    bool admin_state = true;

    bridge_port_entry()
    {
    }

    bridge_port_entry(la_l2_service_port* l2port,
                      sai_object_id_t vm_obj,
                      sai_object_id_t bp_obj,
                      uint16_t vid,
                      sai_object_id_t bobj,
                      sai_object_id_t pobj,
                      bool tmode)
        : l2_port(l2port),
          vlan_member_oid(vm_obj),
          bridge_port_oid(bp_obj),
          vlan_id(vid),
          bridge_obj(bobj),
          port_obj(pobj),
          is_tagged(tmode)
    {
    }
};

// cpu_l2_port_entry is used to l2 port created on cpu ports on which ACLs can be attached, detached.
struct cpu_l2_port_entry {
    la_obj_wrap<la_l2_service_port> l2_port;
    sai_object_id_t ingress_acl_oid = 0;
    sai_object_id_t egress_acl_oid = 0;
};

enum class warm_boot_type_e { FULL = 0, SAI_ONLY = 1, FAKE = 2 };

enum class punt_process_status_e {
    // Error encounted during punt packet header processing
    INCOMPLETE = 0,
    // Punt packet header processed, continue punting to upper layer
    DONE = 1,
    // Punt packet header processed, terminate punt at current layer
    TERMINATED = 2,
    // Processing failed
    INVALID = 3
};

struct serdes_entry {
    sai_uint32_t preemphasis = SERDES_PREEMPHASIS_DEFAULT_VALUE;
};

// This common data structure stores
// Port and LAG common logical services, this is similar to sdk
// la_ethernet_port. SAI vs sdk object mapping as the following:
// ----------------------------------------
// |       SAI        |         SDK       |
// ========================================
// |       PORT       | system port (SP)  |
// ----------------------------------------
// |        LAG       |       SPA         |
// ----------------------------------------
// |  port_lag_common |  la_ethernet_port |
// ----------------------------------------
struct port_lag_common {
    sai_object_id_t oid = SAI_NULL_OBJECT_ID;
    uint16_t port_vlan_id = 1;
    sai_object_id_t untagged_bridge_port = SAI_NULL_OBJECT_ID;

    la_obj_wrap<la_ethernet_port> eth_port;
    bool disable_decrement_ttl = false;

    uint32_t mtu = SAI_DEFAULT_MTU_SIZE;

    sai_object_id_t ingress_acl = SAI_NULL_OBJECT_ID;
    sai_object_id_t egress_acl = SAI_NULL_OBJECT_ID;

    std::set<sai_object_id_t> ingress_mirror_oids;        // oids of ingress attached mirror-session
    std::set<sai_object_id_t> egress_mirror_oids;         // oids of egress attached mirror-session
    sai_object_id_t ingress_packet_sample_oid;            // single ingress packet sampler per port
    sai_object_id_t egress_packet_sample_oid;             // single egress packet sampler per port
    std::set<sai_object_id_t> ingress_sample_mirror_oids; // oids of mirror-session to used on ingress with packet-sampling alone.
    std::set<sai_object_id_t> egress_sample_mirror_oids;  // oids of mirror-session to used on egress with packet-sampling alone.
};

//
// port_entry used by SAI_OBJECT_TYPE_PORT and it creates sys_port
// first SAI_OBJECT_TYPE_BRIDGE_PORT OR SAI_OBJECT_TYPE_ROUTER_INTERFACE
// created, then the eth_port is created.
// The eth port can be deleted right before it joins a spa port or the
// port is removed if there is no logical port using it.
struct port_entry {
    port_lag_common service;

    std::shared_ptr<lasai_to_sdk_qos_ingress> ingress_qos_profile;
    std::shared_ptr<lasai_to_sdk_tc_profile> tc_profile;
    sai_object_id_t tc_priogroup_oid = SAI_NULL_OBJECT_ID;
    sai_object_id_t pfcprio_queue_oid = SAI_NULL_OBJECT_ID;

    la_system_port_gid_t sp_gid = 0;

    sai_object_id_t sp_oid = SAI_NULL_OBJECT_ID; // In VOQ switch mode, track the system port SAI OID
    sai_object_id_t lag_oid = SAI_NULL_OBJECT_ID;

    la_obj_wrap<la_system_port> sys_port;

    // Port location
    la_slice_id_t slice_id;
    la_ifg_id_t ifg_id;
    la_uint_t pif;

    // MAC : SAI_PORT_TYPE_LOGICAL PCI : SAI_PORT_TYPE_CPU RECYCLE : NONE
    port_entry_type_e type = port_entry_type_e::MAC;

    bool admin_state = false; // SAI_PORT_ATTR_ADMIN_STATE attribute
    sai_port_media_type_t media_type = sai_port_media_type_t::SAI_PORT_MEDIA_TYPE_NOT_PRESENT; // SAI_PORT_ATTR_MEDIA_TYPE attribute
#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 7, 0)
    sai_port_interface_type_t if_type
        = sai_port_interface_type_t::SAI_PORT_INTERFACE_TYPE_NONE; // SAI_PORT_ATTR_INTERFACE_TYPE attribute
#endif

    std::array<sai_object_id_t, NUM_QUEUE_PER_PORT> buffer_profile_oids;
    std::array<sai_object_id_t, NUM_QUEUE_PER_PORT> scheduling_oids;
    std::array<sai_object_id_t, NUM_QUEUE_PER_PORT> wred_oids;
    // scheduler profile ids for the scheduler groups
    std::array<sai_object_id_t, NUM_QUEUE_PER_PORT + 1> m_sched_group_sched_profiles;
    // scheduler group ids
    std::array<sai_object_id_t, NUM_QUEUE_PER_PORT + 1> m_sched_group_oids;

    std::shared_ptr<lasai_port_pfc> pfc;
    la_voq_gid_t base_voq = 0;

    la_obj_wrap<la_rate_limiter_set> rate_limiter_set;

    // vector of sai serdes entries
    std::vector<serdes_entry> serdes_entry_vec;
    std::vector<ingress_priority_group_entry> ingress_priority_group_entries;

    bool is_internal() const
    {
        return (type == port_entry_type_e::INTERNAL_PCI) || (type == port_entry_type_e::RECYCLE);
    }

    bool is_mac() const
    {
        return (type == port_entry_type_e::MAC);
    }

    bool is_lag_member() const
    {
        return (lag_oid != SAI_NULL_OBJECT_ID);
    }

    std::vector<la_counter_set*> get_voq_counter_sets();
    std::vector<la_voq_set*> get_voq_sets();
};

struct system_port_entry {
    sai_object_id_t sp_oid = 0;
    sai_object_id_t port_oid = 0;

    sai_system_port_config_t config_info = {0, 0, 0, 0, 0, 0};
};

//
// port_serdes_entry is used by SAI_OBJECT_TYPE_PORT_SERDES.
// It creates port_serdes object only corresponding to port_entry which is port_entry_type_e::MAC.
struct port_serdes_entry {
    sai_object_id_t port_oid = 0; // port oid
};

//
// lag_entry used by SAI_OBJECT_TYPE_LAG  and it creates spa_port
// first SAI_OBJECT_TYPE_BRIDGE_PORT OR SAI_OBJECT_TYPE_ROUTER_INTERFACE
// created, then the eth_port is created.
struct lag_entry {
    port_lag_common service;
    la_obj_wrap<la_spa_port> spa_port;
    const_la_obj_wrap<la_system_port> flood_sys;
    std::map<const_la_obj_wrap<la_system_port>, uint32_t> members; // uint32_t is == port index
    std::map<uint32_t, bool> ingress_disable;                      // uint32_t is == port index
    string lag_label;
};

struct switch_notification_callbacks {
    void switch_state_change_cb_set(sai_switch_state_change_notification_fn cb)
    {
        std::lock_guard<std::mutex> lock(m_switch_state_change_cb_lock);
        m_callbacks.on_switch_state_change = cb;
    }
    void switch_shutdown_request_cb_set(sai_switch_shutdown_request_notification_fn cb)
    {
        std::lock_guard<std::mutex> lock(m_switch_shutdown_request_cb_lock);
        m_callbacks.on_switch_shutdown_request = cb;
    }
    void fdb_event_cb_set(sai_fdb_event_notification_fn cb)
    {
        std::lock_guard<std::mutex> lock(m_fdb_event_cb_lock);
        m_callbacks.on_fdb_event = cb;
    }
    void port_state_change_cb_set(sai_port_state_change_notification_fn cb)
    {
        std::lock_guard<std::mutex> lock(m_port_state_change_cb_lock);
        m_callbacks.on_port_state_change = cb;
    }
    void packet_event_cb_set(sai_packet_event_notification_fn cb)
    {
        std::lock_guard<std::mutex> lock(m_packet_event_cb_lock);
        m_callbacks.on_packet_event = cb;
    }
    void tam_event_cb_set(sai_tam_event_notification_fn cb)
    {
        std::lock_guard<std::mutex> lock(m_tam_event_cb_lock);
        m_callbacks.on_tam_event = cb;
    }
    void queue_pfc_deadlock_cb_set(sai_queue_pfc_deadlock_notification_fn cb)
    {
        std::lock_guard<std::mutex> lock(m_queue_pfc_deadlock_cb_lock);
        m_callbacks.on_queue_pfc_deadlock = cb;
    }
    // add mutex for each callback function. Hold per callback mutex/lock
    // before invoking callback or when reset callback function pointer.
    std::mutex m_switch_state_change_cb_lock;
    std::mutex m_switch_shutdown_request_cb_lock;
    std::mutex m_fdb_event_cb_lock;
    std::mutex m_port_state_change_cb_lock;
    std::mutex m_packet_event_cb_lock;
    std::mutex m_tam_event_cb_lock;
    std::mutex m_queue_pfc_deadlock_cb_lock;
    sai_switch_notification_t m_callbacks{};
};

struct buffer_pool_entry {
    sai_uint64_t shared_size = 0;
    sai_buffer_pool_type_t type = SAI_BUFFER_POOL_TYPE_EGRESS;
    sai_uint64_t size = 0;
    sai_buffer_pool_threshold_mode_t mode = SAI_BUFFER_POOL_THRESHOLD_MODE_DYNAMIC;
    sai_uint64_t xoff_size = 0;
    sai_object_id_t wred_profile_id = SAI_NULL_OBJECT_ID;
};

struct buffer_profile {
    sai_object_id_t buffer_pool_id = SAI_NULL_OBJECT_ID;
    sai_buffer_profile_threshold_mode_t mode = SAI_BUFFER_PROFILE_THRESHOLD_MODE_DYNAMIC;
    sai_uint64_t reserved_buffer_size = 0;
    sai_int8_t dynamic_thresh = 0;

    sai_uint64_t static_thresh = 0;
    sai_uint64_t xoff_th = 0;
    sai_uint64_t xon_th = 0;
    sai_uint64_t xon_offset_th = 0;
    la_obj_wrap<la_rx_cgm_sq_profile> rx_cgm_sq_profile = nullptr;
    sai_uint32_t ref_count = 0;
};

//
// class lsai_device
//
// Each lsai_device instance defines one saiswitch.
// The following data structure contains mapper mapping
// from sai object to la object and vice versa.
//

class lsai_device : public std::enable_shared_from_this<lsai_device>
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    lsai_device() = default;
    lsai_device(uint32_t sw_id, uint32_t hw_dev_id, la_device* la_dev, bool sim);
    ~lsai_device();
    lsai_device(const lsai_device&) = delete;
    void clean();
    la_status initialize(transaction& txn, const sai_attribute_t* attr_list, uint32_t attr_count);
    la_status initialize_warm_before_reconnect(transaction& txn, warm_boot_type_e is_warm_boot_mode, uint32_t base_wb_revision);
    la_status initialize_warm_after_reconnect(transaction& txn, warm_boot_type_e is_warm_boot_mode);
    void dump_event_counters();
    la_status allocate_port(uint32_t lane,
                            port_entry_type_e type,
                            uint32_t& port_index,
                            port_entry*& out_pentry_ptr,
                            transaction& txn);
    la_status setup_sp_voq_and_cgm(la_uint_t vsc_offset,
                                   const port_entry* pentry,
                                   la_vsc_gid_vec_t& vsc_vec,
                                   la_vsc_gid_vec_t& vsc_vec_ecn,
                                   la_voq_set*& voq_set,
                                   la_voq_set*& voq_set_ecn,
                                   transaction& txn);
    la_status setup_sp_tm_defaults(la_voq_set* voq_set,
                                   la_voq_set* voq_set_ecn,
                                   la_vsc_gid_vec_t& vsc_vec,
                                   la_vsc_gid_vec_t& vsc_vec_ecn,
                                   uint64_t port_mbps,
                                   port_entry* pentry,
                                   la_interface_scheduler* scheduler,
                                   transaction& txn);
    la_status setup_npuh_port(uint32_t speed, port_entry* pentry, transaction& txn);

    la_tc_profile* get_tc_profile(const port_entry* pentry);
    la_ingress_qos_profile* get_ingress_qos_profile(const port_entry* pentry);

    // return m_hw_device_type in string
    std::string get_hw_device_type_str();
    la_status alloc_prefix_object(uint32_t nh_index, next_hop_entry& nh_entry);
    void release_prefix_object(uint32_t nh_index, const next_hop_entry& nh_entry);
    la_status get_router_interface(sai_object_id_t obj_rif_id, la_l3_port*& l3port, lsai_object& la_rif);
    la_status get_la2sai_port(la_system_port_gid_t gid, sai_object_id_t& obj);
    la_status set_la2sai_port(la_system_port_gid_t sp_gid, sai_object_id_t obj_id);
    la_status remove_la2sai_port(la_system_port_gid_t gid);
    la_status get_lane_to_port(uint32_t lane, sai_object_id_t& port_oid) const;
    la_status set_lane_to_port(uint32_t lane, sai_object_id_t port_oid);
    la_status remove_lane_to_port(uint32_t lane);
    void sai_trim_internal_header(uint8_t* pkt_ptr, size_t* pkt_offset);
    punt_process_status_e sai_process_initial_eth_headers(uint8_t* pkt_hdr, uint32_t len, size_t* offset, uint16_t* eth_type);
    punt_process_status_e sai_process_punt_header(uint8_t* pkt_hdr,
                                                  uint32_t len,
                                                  uint32_t* attr_count,
                                                  sai_attribute_t* attr_list,
                                                  size_t* offset,
                                                  sai_object_id_t& src_port_oid,
                                                  sai_object_id_t& dst_port_oid,
                                                  sai_object_id_t& trap_oid,
                                                  uint32_t& mirror_id);
    punt_process_status_e sai_process_learn_header(uint8_t* pkt_hdr, uint32_t len, size_t* offset);
    la_status sai_process_learn_notification(uint8_t* pkt_ptr, size_t* pkt_offset);
    sai_status_t sai2la_inject_header(uint8_t* pkt_hdr,
                                      uint64_t dscp,
                                      la_traffic_class_t out_tc,
                                      la_qos_color_e out_color,
                                      int* p_size,
                                      int* sock_ptr,
                                      uint32_t attr_count,
                                      const sai_attribute_t* attr_list);
    sai_status_t sai2la_inject_packet(uint8_t* pkt_ptr, int* p_size, uint32_t attr_count, const sai_attribute_t* attr_list);
    la_status create_cpu_l3_port(sai_object_id_t obj_vrf_id, la_l3_ac_port*& l3_port, transaction& txn);
    la_status create_cpu_l2_port(uint16_t vlan_id, la_switch* bridge, la_l2_service_port*& l2_port, transaction& txn);
    la_status destroy_cpu_l2_port(uint16_t bridge_gid);
    la_status create_acl_mirror_command();

    // hostif listener thread using tap interface fd.
    sai_status_t switchport_hostif_tx_listener_start();
    sai_status_t switchport_hostif_socket_fd_set(const lsai_hostif& hostif, int fd);
    std::vector<port_entry*> get_mac_ports();
    std::vector<system_port_entry*> get_system_ports();
    void close_threads();
    bool sdk_operations_allowed();
    void destroy_la_object(la_object* obj);

public:
    struct dot1q_hdr {
        uint16_t tpid;
        uint16_t vid;
    };

    struct ether_hdr_1q_t {
        uint8_t daddr[6];
        uint8_t saddr[6];
        struct dot1q_hdr q_hdr;
        uint16_t type_or_len;
    };

    enum class eth_type_e {
        // ethernet type in the punted packet
        PUNT = 0x7102,
        // ethernet type in the inject up packet
        INJECTUP = 0x7103,
        // ethernet type in the inject down packet
        INJECTDOWN = 0x7102,
        // dot1q
        DOT1Q = 0x8100,
        IPV4 = 0x0800,
        IPV6 = 0x86dd,
        MPLS = 0x8847,
        PFC = 0x8808,
    };

    struct ipv6 {
#if __BYTE_ORDER == __LITTLE_ENDIAN
        sai_uint8_t traffic_class_hi : 4, version : 4;
        sai_uint8_t flow_label_hi : 4, traffic_class_lo : 4;
        sai_uint16_t flow_label_lo;
#elif __BYTE_ORDER == __BIG_ENDIAN
        sai_uint8_t version : 4, traffic_class_hi : 4;
        sai_uint8_t traffic_class_lo : 4, flow_label_hi : 4;
        sai_uint16_t flow_label_lo;
#else
#error "Please fix endianness defines"
#endif

        sai_uint16_t payload_len;
        sai_uint8_t next_header;
        sai_uint8_t hop_limit;

        struct in6_addr src_ip;
        struct in6_addr dst_ip;
    };

    struct mpls {
        sai_uint32_t entry;
    };

    enum mpls_header_e {
        MPLS_LABEL_MASK = 0xfffff000, /* label */
        MPLS_LABEL_SHIFT = 12,
        MPLS_TC_MASK = 0x00000e00, /* traffic class */
        MPLS_TC_SHIFT = 9,
        MPLS_STACK_MASK = 0x00000100, /* is stack bottom? */
        MPLS_STACK_SHIFT = 8,
        MPLS_TTL_MASK = 0x000000ff, /* time to live */
        MPLS_TTL_SHIFT = 0,
    };

    // npl_l2_relay_id_t : 14 bits, which means that the max id number we can get
    // is 16k, there are limitation in real la_switch entries limited to 4k
    // that can coexist (TB clarified)
    // Partition the ids according to 16k
    static constexpr int MAX_BRIDGES = 3072;
    static constexpr int MAX_VLANS = 4096;
    static constexpr int DEFAULT_VLAN_ID = 1;
    // npl_l3_dlp_t : 15 bits
    static constexpr int MAX_L3_PORTS = 4096;
    // npl_l2_dlp_t : 18 bits
    // Change l2 service port to 4096 due to la_vrf_port forwarding to l2 from svi limited to 12 bits
    static constexpr int MAX_BRIDGE_PORTS = 4096;
    static constexpr int MAX_BRIDGE_PORTS_MASK = MAX_BRIDGE_PORTS - 1;
    // npl_l3_relay_id_t : 11 bits
    static constexpr int MAX_VRF_IDS = 2048;
    // max user created rx-cgm profiles that can be applied on a slice
    static constexpr int MAX_BUFFER_PROFILE_COUNT = 15;
    static constexpr int MAX_NEXT_HOPS = 4096;
    static constexpr int MAX_PORTS = 256;
    static constexpr int MAX_SYSTEM_PORTS = 8192; // TODO: Calculate appropriate max for system ports
    static constexpr int MAX_NEXT_HOP_GROUP_MEMBERS = 32768;
    static constexpr int NUM_QUEUE_PER_PORT = 8;
    static constexpr int MAX_LAG = 32;
    static constexpr int MAX_BUFFER_POOLS = 4;
    static constexpr int MAX_TRAP_PRIORITY = 255;
    static constexpr int SAI_VOQ_BASE = 176;
    static constexpr int SAI_VSC_BASE = 192;
    static constexpr int SAI_VSC_PCI_INDEX = 0;
    static constexpr int SAI_VSC_NPUH_INDEX = 1;
    static constexpr int SAI_VSC_RECYCLE_INDEX = 2;
    static constexpr int SAI_VSC_PORT_BASE = 4;
    static constexpr int SAI_ACL_ENTRY_MIN_PRIO = 0;
    static constexpr int SAI_ACL_ENTRY_MAX_PRIO = 10000;
    static constexpr int SAI_AVAILABLE_FDB_ENTRY = 1024;
    static constexpr int SAI_AVAILABLE_IPV4_NEIGHBOR_ENTRY = 1024;
    static constexpr int SAI_AVAILABLE_IPV4_NH_ENTRY = 1024;
    static constexpr int SAI_AVAILABLE_IPV4_ROUTE_ENTRY = 1024;
    static constexpr int SAI_AVAILABLE_IPV6_NEIGHBOR_ENTRY = 1024;
    static constexpr int SAI_AVAILABLE_IPV6_NH_ENTRY = 1024;
    static constexpr int SAI_AVAILABLE_IPV6_ROUTE_ENTRY = 1024;
    static constexpr int SAI_AVAILABLE_NH_GROUP_ENTRY = 1024;
    static constexpr int SAI_AVAILABLE_NH_GROUP_MEMBER_ENTRY = 16;
    static constexpr int SAI_MAX_HOSTIF = 256;
    static constexpr int INVALID_PUNT_SYS = 0xffff;
    static constexpr int PUNT_SLICE = 0;
    static constexpr int INJECTUP_SLICE = 2;
    static constexpr int LEARN_PUNT_SLICE = 4;
    static constexpr int SAI_NUMBER_OF_UNICAST_QUEUES = 0;
    static constexpr int SAI_NUMBER_OF_MULTICAST_QUEUES = 0;
    static constexpr int SAI_NUMBER_OF_QUEUES = 8;
    static constexpr int SAI_NUMBER_OF_CPU_QUEUES = 8;
    static constexpr uint64_t ROUTE_NULL_PACKET_FORWARD = 0xffffffff;
    static constexpr int MAX_FDB_ENTRY_PROCESSING_ENTRIES = 20;
    static constexpr int MAX_PUNT_PACKET_DEBUG_SUPRESSED = 1000;
    static constexpr std::chrono::seconds MAX_PUNT_PACKET_DEBUG_WAIT_TIME{10};
    static constexpr la_slice_id_t INJECT_UP_RECYCLE_SLICE = 1;

    int m_vsc_port_base = 0;
    laobj_db_base* m_per_obj_info[SAI_OBJECT_TYPE_MAX] = {nullptr};
    laobj_db_bridge_port m_laobj_db_bridge_port;
    laobj_db_hash m_laobj_db_hash;
    laobj_db_hostif_trap m_laobj_db_hostif_trap;
    laobj_db_ingress_priority_group m_laobj_db_ingress_priority_group;
    laobj_db_lag_member m_laobj_db_lag_member;
    laobj_db_port m_laobj_db_port;
    laobj_db_queue m_laobj_db_queue;
    laobj_db_scheduler_group m_laobj_db_scheduler_group;
    laobj_db_switch m_laobj_db_switch;
    laobj_db_vlan_member m_laobj_db_vlan_member;
    laobj_db_tunnel_map_entry m_laobj_db_tunnel_map_entry;
    laobj_db_fdb_entry m_laobj_db_fdb_entries;
    laobj_db_route_entry m_laobj_db_route_entries;
    laobj_db_neighbor_entry m_laobj_db_neighbor_entries;
    laobj_db_mirror m_laobj_db_mirror_entries;
    // la_switch gid is 14 bits (16k) wide
    // first 1k is used by internal bridge ex. vxlan per vrf svi. (due to vni to vlan table has only 12 bits)
    // and then 3k for .1D bridge
    // then .1q vlan allocate 4k
    obj_db<lsai_bridge_t> m_bridges{SAI_OBJECT_TYPE_BRIDGE, MAX_BRIDGES, 0, tunnel_manager::MAX_INTERNAL_BRIDGES};
    obj_db<lsai_vlan_t> m_vlans{SAI_OBJECT_TYPE_VLAN, MAX_VLANS, 0, (tunnel_manager::MAX_INTERNAL_BRIDGES + MAX_BRIDGES)};

    obj_db<bridge_port_entry> m_bridge_ports{SAI_OBJECT_TYPE_BRIDGE_PORT, MAX_BRIDGE_PORTS, 0, 0};
    obj_db<next_hop_entry> m_next_hops{SAI_OBJECT_TYPE_NEXT_HOP, MAX_NEXT_HOPS};
    obj_db<port_entry> m_ports{SAI_OBJECT_TYPE_PORT, MAX_PORTS};
    obj_db<port_serdes_entry> m_port_serdes{SAI_OBJECT_TYPE_PORT_SERDES, MAX_PORTS};
    obj_db<system_port_entry> m_system_ports{SAI_OBJECT_TYPE_SYSTEM_PORT, MAX_SYSTEM_PORTS};
    obj_db<rif_entry> m_l3_ports{SAI_OBJECT_TYPE_ROUTER_INTERFACE, MAX_L3_PORTS, 0, tunnel_manager::MAX_L3_INTERNAL_PORTS};
    obj_db<vrf_entry> m_vrfs{SAI_OBJECT_TYPE_VIRTUAL_ROUTER, MAX_VRF_IDS};
    obj_db<lsai_next_hop_group> m_next_hop_groups{SAI_OBJECT_TYPE_NEXT_HOP_GROUP, LSAI_MAX_ECMP_GROUPS};
    obj_db<next_hop_group_member> m_next_hop_group_members{SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER, MAX_NEXT_HOP_GROUP_MEMBERS};
    obj_db<lag_entry> m_lags{SAI_OBJECT_TYPE_LAG, MAX_LAG};
    obj_db<buffer_pool_entry> m_buffer_pools{SAI_OBJECT_TYPE_BUFFER_POOL, MAX_BUFFER_POOLS};
    obj_db<buffer_profile> m_buffer_profiles{SAI_OBJECT_TYPE_BUFFER_PROFILE, MAX_BUFFER_PROFILE_COUNT};
    std::map<uint16_t, cpu_l2_port_entry> m_cpu_l2_port_map;
    std::set<sai_object_id_t> m_bridge_port_object_ids;
    bool m_is_sim = false;
    bool m_is_hw_test = false;
    int m_punt_fd = -1;
    int m_inject_fd = -1;
    int m_crit_fd = -1;   // critical notification descriptor
    int m_normal_fd = -1; // normal notification descriptor
    int m_learn_fd = -1;
    std::thread m_punt_thread;
    std::thread m_learn_thread;
    std::thread m_notification_thread;
    std::thread m_netdev_thread;
    std::atomic<bool> m_threads_should_exit{false};
    uint32_t m_hw_dev_id;
    la_device* m_dev;
    la_obj_wrap<la_next_hop> m_next_hop_drop;
    la_obj_wrap<la_ac_profile> m_default_ac_profile;
    la_obj_wrap<la_ac_profile> m_pvlan_ac_profile;
    la_obj_wrap<la_filter_group> m_default_filter_group;
    sai_hash_algorithm_t m_ecmp_default_hash_algorithm = SAI_HASH_ALGORITHM_CRC;
    bool m_restart_warm = false;
    warm_boot_type_e m_warm_boot_mode = warm_boot_type_e::FULL;
    std::vector<la_obj_wrap<la_system_port>> m_pci_sys_ports;
    std::vector<sai_object_id_t> m_pci_port_ids;
    std::vector<la_obj_wrap<la_pci_port>> m_pci_ports;
    std::vector<la_obj_wrap<la_recycle_port>> m_recycle_ports;
    la_obj_wrap<la_system_port> m_npuh_sys_port; // slice0 ifg1
    la_obj_wrap<la_npu_host_port> m_npuh_port;   // slice0 ifg1
    la_obj_wrap<la_npu_host_destination> m_npuh_dest;
    sai_object_id_t m_npuh_port_id{};
    la_obj_wrap<la_ethernet_port> m_recycle_injectup_eth_port; // slice1
    la_obj_wrap<la_ethernet_port> m_injectup_eth_port;         // slice2
    la_obj_wrap<la_l3_ac_port> m_l3_inject_up_port;
    la_obj_wrap<la_l2_service_port> m_l2_inject_up_port;
    la_obj_wrap<la_punt_inject_port> m_punt_inject_port{nullptr}; // slice0
    la_obj_wrap<la_l2_punt_destination> m_punt_dest;              // slice0
    la_obj_wrap<la_punt_inject_port> m_learn_punt_port{nullptr};  // slice4
    la_obj_wrap<la_l2_punt_destination> m_learn_punt_dest;        // slice4
    la_obj_wrap<la_switch> m_default_bridge;
    la_obj_wrap<la_control_plane_classifier> m_copc_mac;
    la_obj_wrap<la_control_plane_classifier> m_copc_ipv4;
    la_obj_wrap<la_control_plane_classifier> m_copc_ipv6;
    std::vector<la_obj_wrap<la_l2_mirror_command>> m_acl_mirror_cmds;
    std::unique_ptr<sai_acl> m_acl_handler;
    std::unique_ptr<debug_counter_manager> m_debug_counter_handler;
    std::unique_ptr<lsai_sched> m_sched_handler;
    std::unique_ptr<lsai_sched_group> m_sched_group_handler;
    std::shared_ptr<trap_manager> m_trap_manager;
    std::unique_ptr<lasai_qos> m_qos_handler;
    std::unique_ptr<tunnel_manager> m_tunnel_manager;
    std::unique_ptr<lsai_wred_manager_base> m_wred_handler;
    std::unique_ptr<policer_manager> m_policer_manager;
    std::unique_ptr<mpls_handler> m_mpls_handler;
    std::unique_ptr<sai_mirror> m_mirror_handler;
    std::shared_ptr<lasai_pfc_base> m_pfc_handler;
    std::unique_ptr<voq_cfg_manager> m_voq_cfg_manager;
    std::unique_ptr<sai_samplepacket> m_samplepacket_handler;
    std::unique_ptr<sai_hostif> m_hostif_handler;
    uint32_t m_switch_profile_id = 0;
    sai_object_id_t m_switch_id;
    sai_object_id_t m_default_vlan_id{};
    sai_object_id_t m_default_1q_bridge_id{};
    sai_object_id_t m_default_vrf_id{};
    sai_object_id_t m_next_hop_drop_id{};
    bool m_ecn_ect = false;
    bool m_force_update = false;
    uint32_t m_counter_refresh_interval = 1000; // in millisecond

    // hostif info
    obj_db<lsai_hostif> m_hostifs{SAI_OBJECT_TYPE_HOSTIF, SAI_MAX_HOSTIF};
    bool m_netdev_listen_thread_started = false;
    std::mutex m_hostif_lock;
    std::vector<int> m_frontport_netdev_sock_fds;
    std::unordered_map<int, const lsai_hostif> m_netdev_sock_fd_to_hostif;
    std::unordered_map<sai_object_id_t, sai_object_id_t> m_port_hostif_map;
    std::unordered_map<sai_object_id_t, uint16_t> m_port_hostif_index_map;
    // hostif table entry
    static constexpr int MAX_HOSTIF_TABLE_ENTRY = 256;
    obj_db<lsai_hostif_table_entry> m_hostif_table{SAI_OBJECT_TYPE_HOSTIF_TABLE_ENTRY, MAX_HOSTIF_TABLE_ENTRY};
    // map for hostif table entry
    std::map<lsai_hostif_table_entry_key_t, lsai_hostif_table_entry> m_hostif_table_entry_map;
    // knet
    bool m_use_knet = false;
    sai_netlink_kernel_socket m_knet_sock;
    // holding 1q bridge ports for fake 1q bridge
    std::set<sai_object_id_t> m_default_1q_bridge_port_ids;
    sai_mac_t m_default_switch_mac = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    switch_notification_callbacks m_notification_callbacks{};
    uint32_t aging_time = 0;
    uint8_t m_bulk_fdb_notification_count;
    sai_fdb_event_notification_data_t m_bulk_fdb_notifications[MAX_FDB_ENTRY_PROCESSING_ENTRIES];
    sai_attribute_t m_bulk_fdb_notification_attrs[MAX_FDB_ENTRY_PROCESSING_ENTRIES];
    sai_object_id_t m_bulk_fdb_notification_prev_bridge_port_id{};
    std::chrono::steady_clock::time_point m_bulk_fdb_notification_last_sent;

    // tam related entries
    obj_db<lsai_tam_report_entry_ptr> m_tam_report{SAI_OBJECT_TYPE_TAM_REPORT, SAI_MAX_TAM_REPORT};
    obj_db<lsai_tam_event_action_entry_ptr> m_tam_event_action{SAI_OBJECT_TYPE_TAM_EVENT_ACTION, SAI_MAX_TAM_EVENT_ACTION};
    obj_db<lsai_tam_transport_entry_ptr> m_tam_transport{SAI_OBJECT_TYPE_TAM_TRANSPORT, SAI_MAX_TAM_TRANSPORT};
    obj_db<lsai_tam_collector_entry_ptr> m_tam_collector{SAI_OBJECT_TYPE_TAM_COLLECTOR, SAI_MAX_TAM_COLLECTOR};
    obj_db<lsai_tam_event_entry_ptr> m_tam_event{SAI_OBJECT_TYPE_TAM_EVENT, SAI_MAX_TAM_EVENT};
    obj_db<lsai_tam_entry_ptr> m_tam{SAI_OBJECT_TYPE_TAM, SAI_MAX_TAM};
    std::vector<lsai_tam_entry_ptr> m_tam_registry; // vector of bound tam object pointers

    // hardware info
    uint32_t m_hw_device_id = 0; // Hardware ID or ASIC ID on board, default to 0 for single ASIC in system
    hw_device_type_e m_hw_device_type = hw_device_type_e::NONE;
    device_params m_dev_params;
    std::map<la_event_e, la_obj_wrap<la_counter_set>> m_event_counters;
    la_uint64_t counter_set_max_size;
    la_uint64_t counter_set_default_size;

    // board configuration
    lsai_sai_board_cfg_t m_board_cfg;
    // Extended device properties
    lsai_extended_property_bool_map_t m_ext_properties_bool;
    // port mix configuration map from json file
    lsai_port_mix_map_t m_port_mix_map;
    lsai_sw_init_mode_e m_sw_init_mode = lsai_sw_init_mode_e::NONE;
    /// SAI API lock
    std::recursive_mutex m_mutex;
    std::mutex m_hostif_inject_mutex;
    // An ACL table or table group attached at switch level in ingress direction.
    sai_object_id_t switch_ingress_acl_oid = SAI_NULL_OBJECT_ID;
    // An ACL table or table group attached at switch level in egress direction.
    sai_object_id_t switch_egress_acl_oid = SAI_NULL_OBJECT_ID;
    uint32_t m_route_user_meta_max = 255;
    uint32_t m_fdb_user_meta_max = 255;
    uint32_t m_neighbor_user_meta_max = 15;
    std::string m_hw_info;
    bool m_hw_info_attr;
    // bool m_init_pfc = false; // is pfc initialized?
    bool is_sw_pfc = false; // is sw_pfc configured via json later. false for now
    // Whether to forward the following setters/getters to the
    // corresponding switch setters/getters:
    //  SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP -> SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP
    //  SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP -> SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP
    bool m_push_port_qos_to_switch = false;
    sai_packet_action_t m_fdb_ucast_miss_action = SAI_PACKET_ACTION_FORWARD;
    sai_packet_action_t m_fdb_bcast_miss_action = SAI_PACKET_ACTION_FORWARD;
    sai_packet_action_t m_fdb_mcast_miss_action = SAI_PACKET_ACTION_FORWARD;

private:
    void dump_cpu_port_stats() const;
    void initialize_obj_ext_info();
    la_status initialize_default_ac_profile(transaction& txn);
    la_status initialize_default_filter_group(transaction& txn);
    la_status initialize_default_cgm_profile(transaction& txn);
    la_status initialize_tm_schedulers(transaction& txn);
    la_status initialize_serdes_parameters();
    la_status create_recycle_ports(transaction& txn);
    la_status create_npuh_port(transaction& txn);
    la_status create_pci_ports(transaction& txn);
    la_status create_punt_port(transaction& txn);
    la_status create_learn_punt_port(transaction& txn);
    la_status create_default_vrf(transaction& txn);
    la_status create_injectup_port(transaction& txn);
    la_status create_mc_lpts_mirror_cmd();
    la_status configure_default_traps(transaction& txn);
    la_status initialize_misc_defaults(transaction& txn);
    la_status initialize_logger_throttled(transaction& txn);
    la_status initialize_kernel_conn_fd(transaction& txn);
    la_status initialize_knet(transaction& txn);
    la_status initialize_kernel_start_threads(transaction& txn);
    la_status reinitialize_hostif_genetlinks(transaction& txn);
    la_status reinitialize_hostif_tap_devices(transaction& txn);
    la_status reinitialize_knet_samplepackets(transaction& txn);
    la_status reinitialize_knet(transaction& txn);
    la_status pre_initialize_notification_thread(transaction& txn);
    la_status initialize_notification_thread(transaction& txn);
    la_status open_hw_socket(la_slice_id_t slice_id, int& sock);
    la_status create_trap_manager(transaction& txn);
    la_status create_tunnel_manager(transaction& txn);
    la_status gibraltar_mbist_repair();
    la_status setup_defaults(transaction& txn);
    sai_status_t link_notification_handler(const la_notification_desc& link_desc, const std::string& notification_str);
    sai_status_t tam_notification_handler(const la_notification_desc& desc, const std::string& notification_str);
    la_status create_pfc_handler(bool sw_pfc);
    sai_status_t pfc_watchdog_notification_handler(const la_notification_desc& desc, const std::string& notification_str);
    la_status send_samplepacket(const sai_object_id_t& hostif_oid,
                                sai_object_id_t& src_port_oid,
                                sai_object_id_t& dst_port_oid,
                                uint32_t mirror_id,
                                uint8_t* packet_buffer,
                                size_t& pkt_offset,
                                int len);
    void notification_listen();
    uint32_t receive_pkt_from_simulator(int socket_fd, uint8_t* packet_buffer, size_t packet_buffer_size);
    void punt_listen();
    void learn_yield();
    void learn_listen();
    void netdev_listen();
    sai_status_t prepare_netdev_inject_packet_down(const lsai_hostif& hostif,
                                                   uint8_t* packet_buffer,
                                                   int pkt_size,
                                                   uint8_t* pkt_with_punt_header,
                                                   size_t* new_buffer_size);
    void sai_prepend_inject_header(uint8_t* packet_buffer, uint8_t* packet_ptr, size_t inject_header_size, int packet_size);
    la_status learn_record_conversion(uint8_t* lr_ptr, sai_fdb_event_notification_data_t* fdb_entry_ptr);
    la_status learn_notification_process_entry(const sai_fdb_event_notification_data_t* data,
                                               sai_bridge_port_fdb_learning_mode_t& learn_mode);
    void learn_notification_handler(uint32_t count, const sai_fdb_event_notification_data_t* data);
    la_status mac_entry_conversion(sai_object_type_t obj_type,
                                   sai_object_key_t* obj_ids,
                                   uint32_t count,
                                   std::vector<mac_and_src_port_entry>& out_mac_entries);

private:
    std::map<la_system_port_gid_t, sai_object_id_t> m_la2sai_port_map;
    std::unordered_map<uint32_t, sai_object_id_t> m_lane_to_port_map;
    uint64_t m_total_punt_processed = 0;
    uint64_t m_total_punt_process_failed = 0;
    uint64_t m_total_learn_processed = 0;
    uint64_t m_total_learn_process_failed = 0;
    uint64_t m_total_fdb_notifications_sent;
    std::unique_ptr<lsai_logger_throttled> m_punt_debugs;
    std::unique_ptr<lsai_logger_throttled> m_mac_learn_debugs;
    std::unique_ptr<lsai_logger_throttled> m_fdb_notification_debugs;
};

extern la_status sai_get_device(uint32_t switch_id, std::shared_ptr<lsai_device>& sdev);
extern la_status la_create_l2_bridge_port(sai_object_id_t*& out_bridge_port_id,
                                          lsai_object& la_bport,
                                          bridge_port_entry& bridge_port,
                                          transaction& txn,
                                          bool add_counter);
extern la_status la_create_l2_bridge_port_on_eth(sai_object_id_t*& out_bridge_port_id,
                                                 lsai_object& la_bport,
                                                 bridge_port_entry& bridge_port,
                                                 transaction& txn,
                                                 la_ethernet_port* eth_port,
                                                 bool add_counter);
extern la_status attach_bridge_port(std::shared_ptr<lsai_device> sdev,
                                    bridge_port_entry& entry,
                                    la_switch* bridge,
                                    transaction& txn);
extern la_status detach_bridge_port(std::shared_ptr<lsai_device>& sdev, sai_object_id_t bv_oid, bridge_port_entry* entry);
extern la_status create_la_bridge(la_switch*& bridge, std::shared_ptr<lsai_device> sdev, uint32_t bridge_gid, transaction& txn);
extern la_status sai_port_get_ethernet_port(std::shared_ptr<lsai_device>& sdev,
                                            sai_object_id_t port_obj,
                                            la_ethernet_port*& eth_port);
extern la_status sai_port_get_ethernet_port_and_untagged(std::shared_ptr<lsai_device>& sdev,
                                                         sai_object_id_t port_obj,
                                                         la_ethernet_port*& eth_port,
                                                         sai_object_id_t& untagged_oid);
extern la_status get_sys_from_sys_or_spa(sai_object_id_t obj_port, const la_system_port*& sys_port);

extern la_status la_add_prefix_to_router_interface(vrf_entry& vrf_entry, sai_object_id_t obj_rif, la_ipv4_prefix_t& ipv4_prefix);
extern la_status la_add_v6prefix_to_router_interface(vrf_entry& vrf_entry, sai_object_id_t obj_rif, la_ipv6_prefix_t& ipv6_prefix);
extern la_status sai_route_get_next_hop_id(sai_object_id_t switch_id,
                                           sai_object_id_t vrf_id,
                                           const sai_ip_prefix_t& ip_prefix,
                                           sai_attribute_value_t* val,
                                           bool use_lpm = false);

const la_l3_destination* sai_route_get_la_next_hop(std::shared_ptr<lsai_device> sdev,
                                                   sai_ip_address_t& ipaddr,
                                                   sai_object_id_t vrf_obj,
                                                   bool is_tunnel = false);

extern la_status la_remove_prefix_from_router_interface(vrf_entry& vrf_entry, la_ipv4_prefix_t& ipv4_prefix);
extern la_status la_remove_v6prefix_from_router_interface(vrf_entry& vrf_entry, la_ipv6_prefix_t& ipv6_prefix);

extern la_status la_remove_bridge_port_or_vlan_member(std::shared_ptr<lsai_device>& sdev,
                                                      sai_object_id_t bv_oid,
                                                      bridge_port_entry* entry);

extern sai_status_t lsai_bridge_port_update_services(std::shared_ptr<lsai_device>& sdev,
                                                     sai_object_id_t bridge_port_id,
                                                     sai_object_id_t port_obj);

bool lsai_device_serialize_save(std::shared_ptr<silicon_one::sai::lsai_device> lsai_sptr, const char* serialization_file);
bool lsai_device_serialize_load(std::shared_ptr<silicon_one::sai::lsai_device>& inout, const char* serialization_file);
la_status warm_boot_apply_upgrade_patches(std::shared_ptr<lsai_device> sdev, uint32_t base_wb_revision);
sai_object_id_t create_untagged_bridge_port(std::shared_ptr<lsai_device>& sdev, sai_object_id_t port_oid);
sai_status_t do_remove_bridge_port(sai_object_id_t obj_bridge_port_id);
sai_status_t miss_packet_action_is_drop(sai_packet_action_t action, bool& is_drop);
la_status sai_port_get_service(const std::shared_ptr<lsai_device>& sdev, sai_object_id_t port_obj, port_lag_common*& service);
}
}

#ifdef ENABLE_SERIALIZATION
namespace cereal
{
template <class Archive>
void save(Archive& archive, const silicon_one::sai::lsai_device& m);
template <class Archive>
void load(Archive& archive, silicon_one::sai::lsai_device& m);
}
#endif

#endif
