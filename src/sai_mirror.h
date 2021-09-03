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

#ifndef __SAI_MIRROR_H__
#define __SAI_MIRROR_H__

extern "C" {
#include <sai.h>
}

#include "api/system/la_device.h"
#include "api/system/la_l2_mirror_command.h"
#include "api/system/la_erspan_mirror_command.h"
#include "common/cereal_utils.h"
#include "common/ranged_index_generator.h"
#include "sai_constants.h"
#include "sai_db.h"
#include "sai_utils.h"

namespace silicon_one
{
namespace sai
{

struct port_lag_common;
struct port_entry;
struct lag_entry;

// Used for RSPAN
struct lasai_vlan_tag_t {
    uint16_t tpid;
    uint16_t id;
    uint8_t pri;
    uint8_t cfi;
};

// Header fields required for erspan and sflow.
struct lasai_mirror_headers_t {
    uint8_t iphdr_ver;
    uint8_t tos;
    uint8_t ttl;
    sai_ip_address_t sip;
    sai_ip_address_t dip;
    sai_mac_t sa;
    sai_mac_t da;
    uint16_t gre_proto_type;
    sai_erspan_encapsulation_type_t erspan_encap_type;
    uint16_t udp_sport;
    uint16_t udp_dport;
};

static constexpr uint32_t INVALID_MIRROR_ID = 0xFFFF;

// From SAI_SWITCH_ATTR_MIRROR_TC, 255 is to ignore the global TC attr and
// derive from packet.
static constexpr uint8_t SAI_MIRROR_TC_VAL_DISABLED = 255;

// Contains device mirror command created for packet samping purposes
// that uses mirror objects to sample.
struct lasai_sample_mirror_t {
    // Regular mirror session object whose encap attributes are used for sampling.
    sai_object_id_t session_oid = SAI_NULL_OBJECT_ID;
    // Device/sdk mirror command created with all encaps matching
    // mirror-session object used for creating sample-mirror-session.
    la_obj_wrap<la_mirror_command> sample_mirror_cmd;
    // SDK/Device Mirror command id
    uint32_t mirror_command_instance_id = INVALID_MIRROR_ID;
    // Starts with sample rate matching mirror session used for
    // creating sample mirror session. This rate is changed
    // to match packet-sampling object's sample rate when
    // sample-mirror is bound to same port where packet-sampling
    // object is also bound to.
    uint32_t sample_rate;
};

struct lasai_mirror_session_t {
    sai_object_id_t session_oid = SAI_NULL_OBJECT_ID; // valid OID on a successfull mirror session creation
    sai_object_id_t switch_oid = SAI_NULL_OBJECT_ID;
    sai_object_id_t policer_oid = SAI_NULL_OBJECT_ID;
    sai_mirror_session_type_t type = SAI_MIRROR_SESSION_TYPE_LOCAL;
    bool vlan_hdr_valid;  // set to true, when mirrored packet is to be tagged
    bool port_list_valid; // if true, mirrored to all destination ports in the list.
    // mirrored packet size
    uint16_t truncate_size;
    // sample rate programmed as 1/sample-rate
    uint32_t sample_rate;
    sai_mirror_session_congestion_mode_t congestion_mode;
    uint8_t tc;
    bool tc_set = false; // True if TC is explicitly configured using SAI_MIRROR_SESSION_ATTR_TC
    lasai_vlan_tag_t tag;
    lasai_mirror_headers_t headers; // Eth, L3 header fields used in mirror session
    // Mirror destination port / monitor port.
    sai_object_id_t destport_oid = SAI_NULL_OBJECT_ID;
    // List of ports on which mirror session is attached for mirroring ingress traffic
    std::set<sai_object_id_t> ingress_mirrored_port_oids;
    // List of ports on which mirror session is attached for mirroring egress traffic
    std::set<sai_object_id_t> egress_mirrored_port_oids;
    // sdk mirror command associated with mirror session on ingress
    la_obj_wrap<la_mirror_command> mirror_cmd_ingress;
    // sdk mirror command associated with mirror session on egress
    la_obj_wrap<la_mirror_command> mirror_cmd_egress;
    // Ref count maintained to recognize across ACL tables, number of ACEs have put this
    // mirror session to use.
    uint32_t ingress_ace_ref_count = 0;
    uint32_t egress_ace_ref_count = 0;
    // List of sample-mirrors that can be used with packet-sampling object.
    // Key is port oid that maps to list of sample-mirror sessions.
    std::map<sai_object_id_t, lasai_sample_mirror_t> per_port_ingress_sample_mirrors;
    std::map<sai_object_id_t, lasai_sample_mirror_t> per_port_egress_sample_mirrors;
};

class sai_mirror
{
public:
    CEREAL_SUPPORT_PRIVATE_MEMBERS

    sai_mirror();
    sai_mirror(std::shared_ptr<lsai_device> sai_dev);
    ~sai_mirror();
    la_status allocate_mirror_session_instance(uint32_t& mirror_instance_id);
    void free_mirror_session_instance(uint32_t mirror_instance_id);
    la_mirror_gid_t mirror_session_instance_to_gid(uint32_t mirror_instance_id, bool is_ingress_stage);
    uint32_t mirror_session_gid_to_instance(la_mirror_gid_t mirror_gid, bool is_ingress_stage);
    static sai_status_t mirror_attrib_get(_In_ const sai_object_key_t* key,
                                          _Inout_ sai_attribute_value_t* value,
                                          _In_ uint32_t attr_index,
                                          _Inout_ vendor_cache_t* cache,
                                          void* arg);
    static sai_status_t mirror_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
    static sai_status_t create_mirror_session(_Out_ sai_object_id_t* mirror_session_id,
                                              _In_ sai_object_id_t switch_id,
                                              _In_ uint32_t attr_count,
                                              _In_ const sai_attribute_t* attr_list);
    static sai_status_t remove_mirror_session(_In_ sai_object_id_t mirror_session_id);
    static sai_status_t set_mirror_session_attribute(_In_ sai_object_id_t mirror_session_id, _In_ const sai_attribute_t* attr);
    static sai_status_t get_mirror_session_attribute(_In_ sai_object_id_t mirror_session_id,
                                                     _In_ uint32_t attr_count,
                                                     _Inout_ sai_attribute_t* attr_list);
    static std::string mirror_session_attr_to_string(sai_attribute_t& attr);
    sai_status_t detach_mirror_sessions(sai_object_id_t port_oid, bool is_ingress_stage);
    sai_status_t detach_mirror_sessions(sai_object_id_t port_oid, sai_object_id_t underlying_port_oid);
    sai_status_t attach_mirror_sessions(sai_object_id_t port_oid,
                                        bool is_ingress_stage,
                                        const std::vector<sai_object_id_t>& mirror_session_oids);
    sai_status_t attach_mirror_sessions(sai_object_id_t port_oid, sai_object_id_t underlying_port_oid);
    void get_all_mirror_sessions_on_port(port_lag_common* service,
                                         bool is_ingress_stage,
                                         std::vector<sai_object_id_t>& mirror_sessions);
    // When an ACE uses mirror object, the API helps to keep track of this fact.
    static sai_status_t set_mirror_session_used_by_ace(const std::shared_ptr<lsai_device>& sdev,
                                                       uint32_t mirror_session_instance,
                                                       bool is_ingress);
    // When an ACE relinquishes mirror object, the API helps to keep track of this fact.
    static sai_status_t clear_mirror_session_used_by_ace(const std::shared_ptr<lsai_device>& sdev,
                                                         uint32_t mirror_session_instance,
                                                         bool is_ingress);
    sai_status_t update_mirror_command_on_port(sai_object_id_t port_oid,
                                               bool is_ingress_stage,
                                               la_mirror_command* mirror_cmd,
                                               bool is_acl_conditioned);
    // Attach slow path packet sampler either ingress/egress direction. Initiated by SAI PORT API enable packet sampling.
    sai_status_t attach_slow_path_packet_sampling(sai_object_id_t port_oid,
                                                  bool is_ingress_stage,
                                                  sai_object_id_t slow_path_sampling_mirror_session_oid);
    // Detach slow path packet sampler either ingress/egress direction. Initiated by SAI PORT API enable packet sampling.
    sai_status_t detach_slow_path_packet_sampling(sai_object_id_t port_oid,
                                                  bool is_ingress_stage,
                                                  sai_object_id_t slow_path_sampling_mirror_session_oid);
    // This function creates mirror session instance/sdk mirror command with same attributes as mirror_session_oid
    // and exclusively used on one port alone identified by port_oid
    sai_status_t create_sample_mirror_instance_for_port(sai_object_id_t port_oid,
                                                        sai_object_id_t mirror_session_oid,
                                                        bool is_ingress_stage);
    // Detaches device mirror command associated with sample mirror instance from all logical
    // ports persent on port_oid. The function also releases device mirror command.
    sai_status_t detach_and_delete_sample_mirror_instance_from_port(sai_object_id_t port_oid,
                                                                    sai_object_id_t mirror_session_oid,
                                                                    bool is_ingress_stage);
    // Detaches device mirror command associated with sample mirror instance from all logical ports.
    sai_status_t detach_sample_mirror_instance_from_port(sai_object_id_t port_oid,
                                                         sai_object_id_t mirror_session_oid,
                                                         bool is_ingress_stage);
    // Detaches device mirror command associated with sample mirror instance from single logical port.
    sai_status_t detach_sample_mirror_instance_from_logical_port(sai_object_id_t logical_port_oid,
                                                                 sai_object_id_t underlying_port_oid);
    // Attaches device mirror command associated with sample mirror instance from single logical port.
    sai_status_t attach_sample_mirror_instance_to_logical_port(sai_object_id_t logical_port_oid,
                                                               sai_object_id_t underlying_port_oid);
    // Returns mirror context created based on mirror oid and attached to the port
    sai_status_t get_sample_mirror_context(sai_object_id_t port_oid,
                                           sai_object_id_t mirror_oid,
                                           bool is_ingress_stage,
                                           lasai_sample_mirror_t& sample_mirror_ctx);
    // Programs sample-rate of device mirror command created for each sampled mirror instance of a port.
    static sai_status_t set_sampling_rate_on_sample_mirror_instance(sai_object_id_t port_oid,
                                                                    sai_object_id_t mirror_oid,
                                                                    bool is_ingress_stage,
                                                                    uint32_t sample_rate);
    // Set the default TC value for mirror session
    sai_status_t switch_mirror_tc_attr_val_set(uint8_t tc);

private:
    static sai_status_t parse_session_attributes(const std::shared_ptr<lsai_device>& sdev,
                                                 const std::unordered_map<sai_attr_id_t, sai_attribute_value_t>& attrs,
                                                 lasai_mirror_session_t& session);
    static sai_status_t parse_tag_attributes(const std::unordered_map<sai_attr_id_t, sai_attribute_value_t>& attrs,
                                             lasai_vlan_tag_t& session);
    static sai_status_t parse_erspan_attributes(const std::unordered_map<sai_attr_id_t, sai_attribute_value_t>& attrs,
                                                lasai_mirror_headers_t& session);
    static sai_status_t parse_sflow_attributes(const std::unordered_map<sai_attr_id_t, sai_attribute_value_t>& attrs,
                                               lasai_mirror_headers_t& session);
    static sai_status_t get_mirror_destination_port_details(sai_object_id_t mirror_dest_port_oid,
                                                            la_ethernet_port*& eth_port,
                                                            la_system_port*& sys_port);
    static sai_status_t create_device_mirror_command(const lasai_mirror_session_t& session,
                                                     uint32_t session_instance,
                                                     bool is_ingress_stage,
                                                     la_mirror_command*& device_mirror_cmd);

    sai_status_t validate_mirror_session_oid(sai_object_id_t port_oid,
                                             sai_object_id_t mirror_session_oid,
                                             lasai_mirror_session_t& session);

    sai_status_t update_mirror_command_on_port(la_object* la_port,
                                               bool is_ingress_stage,
                                               la_mirror_command* mirror_cmd,
                                               bool is_acl_conditioned);

    sai_status_t do_attach_mirror_session(sai_object_id_t port_oid, sai_object_id_t mirror_session_oid, bool is_ingress_stage);
    sai_status_t do_detach_mirror_session(sai_object_id_t port_oid, sai_object_id_t mirror_session_oid, bool is_ingress_stage);

    // Returns mirror sessions ids associated with slow path packet sampling
    sai_status_t get_slow_path_packet_sample_mirror_session(const std::shared_ptr<lsai_device>& sdev,
                                                            const port_lag_common* service,
                                                            sai_object_id_t& ingress_psample_mirror_oid,
                                                            sai_object_id_t& egress_psample_mirror_oid);
    // The functions helps to either attach or detach device mirror command created for packet
    // sampling using sample mirror session.
    sai_status_t update_sample_mirror_instance_from_logical_port(sai_object_id_t logical_port_oid,
                                                                 sai_object_id_t underlying_port_oid,
                                                                 sai_object_id_t mirror_session_oid,
                                                                 bool is_ingress_stage,
                                                                 bool do_detach);
    static sai_status_t mirror_command_attribute_set(uint32_t attr_id,
                                                     lasai_mirror_session_t* session,
                                                     la_mirror_command* mirror_cmd,
                                                     const sai_attribute_value_t* value);
    static la_vlan_tag_t convert_vlan_tag_info(const lasai_mirror_session_t& session);

    template <typename Encaps>
    static Encaps fill_erspan_encaps(const lasai_mirror_session_t& session, uint32_t session_instance);

    static bool mirror_session_is_local(sai_mirror_session_type_t stype)
    {
        return (stype == SAI_MIRROR_SESSION_TYPE_LOCAL);
    }
    static bool mirror_session_is_remote(sai_mirror_session_type_t stype)
    {
        switch (stype) {
        case SAI_MIRROR_SESSION_TYPE_ENHANCED_REMOTE:
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
        case SAI_MIRROR_SESSION_TYPE_SFLOW:
#endif
            return true;
        default:
            return false;
        }
    }

private:
    std::shared_ptr<lsai_device> m_sdev;

    // mirror session offsets
    la_uint64_t m_ingress_gid_offset;
    la_uint64_t m_egress_gid_offset;

public:
    obj_db<lasai_mirror_session_t> m_mirror_db;
    std::set<sai_object_id_t> m_mirror_session_oids;
    uint8_t m_switch_attr_mirror_tc_val = SAI_MIRROR_TC_VAL_DISABLED; // SAI_SWITCH_ATTR_MIRROR_TC
};
}
}

#endif //__SAI_MIRROR_H__
