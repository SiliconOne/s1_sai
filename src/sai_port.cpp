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

// -----------------------------------------
// Some portions are also:
//
// Copyright (C) 2014 Mellanox Technologies, Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License); You may
// Obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//
// -----------------------------------------
//

#include <cassert>
#include "api/system/la_device.h"
#include "api/tm/la_interface_scheduler.h"
#include "api/tm/la_system_port_scheduler.h"
#include "api/tm/la_voq_set.h"
#include "api/npu/la_l2_service_port.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_gre_port.h"
#include "api/npu/la_gue_port.h"
#include "api/npu/la_svi_port.h"
#include "common/gen_utils.h"
#include "common/math_utils.h"
#include "common/ranged_index_generator.h"
#include "sai_constants.h"
#include "sai_device.h"
#include "port_helper.h"
#include "sai_config_parser.h"
#include "sai_qos.h"
#include "sai_system_port.h"
#include "sai_stats_shadow.h"
#include "sai_port.h"
#include "sai_buffer.h"

namespace silicon_one
{
namespace sai
{

using namespace std;

static std::unordered_map<sai_object_id_t, lsai_stats_shadow<la_mac_port::mib_counters>> port_mibs_shadow;

la_status port_system_port_scheduler_dynamic_config(std::shared_ptr<lsai_device> sdev,
                                                    const port_entry& port_entry,
                                                    std::vector<uint32_t>& queue_list,
                                                    uint64_t port_mbps,
                                                    bool is_sched_group_sched_obj);

sai_status_t port_interface_scheduler_dynamic_config(std::shared_ptr<lsai_device> sdev,
                                                     const port_entry& port_entry,
                                                     la_interface_scheduler* ifc_sch,
                                                     uint64_t port_mbps,
                                                     sai_object_id_t sched_oid);

la_status port_system_port_scheduler_static_config(const port_entry* port_entry, uint64_t port_mbps);

sai_status_t port_acl_get(_In_ const sai_object_key_t* key,
                          _Inout_ sai_attribute_value_t* value,
                          _In_ uint32_t attr_index,
                          _Inout_ vendor_cache_t* cache,
                          void* arg);

sai_status_t port_acl_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
sai_status_t port_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_qos_queue_list_get(_In_ const sai_object_key_t* key,
                                     _Inout_ sai_attribute_value_t* value,
                                     _In_ uint32_t attr_index,
                                     _Inout_ vendor_cache_t* cache,
                                     void* arg);

sai_status_t port_qos_number_of_queues_get(_In_ const sai_object_key_t* key,
                                           _Inout_ sai_attribute_value_t* value,
                                           _In_ uint32_t attr_index,
                                           _Inout_ vendor_cache_t* cache,
                                           void* arg);
sai_status_t port_hw_lanes_get(_In_ const sai_object_key_t* key,
                               _Inout_ sai_attribute_value_t* value,
                               _In_ uint32_t attr_index,
                               _Inout_ vendor_cache_t* cache,
                               void* arg);

la_status port_speed_get(sai_object_id_t port_obj_id, uint32_t& speed);
sai_status_t port_speed_get(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg);

sai_status_t port_oper_status_get(_In_ const sai_object_key_t* key,
                                  _Inout_ sai_attribute_value_t* value,
                                  _In_ uint32_t attr_index,
                                  _Inout_ vendor_cache_t* cache,
                                  void* arg);

sai_status_t port_attr_get(_In_ const sai_object_key_t* key,
                           _Inout_ sai_attribute_value_t* value,
                           _In_ uint32_t attr_index,
                           _Inout_ vendor_cache_t* cache,
                           void* arg);

sai_status_t port_state_get(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg);

sai_status_t port_media_get(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg);

sai_status_t port_lpbk_get(_In_ const sai_object_key_t* key,
                           _Inout_ sai_attribute_value_t* value,
                           _In_ uint32_t attr_index,
                           _Inout_ vendor_cache_t* cache,
                           void* arg);

sai_status_t port_fec_get(_In_ const sai_object_key_t* key,
                          _Inout_ sai_attribute_value_t* value,
                          _In_ uint32_t attr_index,
                          _Inout_ vendor_cache_t* cache,
                          void* arg);

sai_status_t port_autoneg_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg);

sai_status_t port_mtu_get(_In_ const sai_object_key_t* key,
                          _Inout_ sai_attribute_value_t* value,
                          _In_ uint32_t attr_index,
                          _Inout_ vendor_cache_t* cache,
                          void* arg);

sai_status_t port_fc_get(_In_ const sai_object_key_t* key,
                         _Inout_ sai_attribute_value_t* value,
                         _In_ uint32_t attr_index,
                         _Inout_ vendor_cache_t* cache,
                         void* arg);

sai_status_t port_pfc_mode_get(_In_ const sai_object_key_t* key,
                               _Inout_ sai_attribute_value_t* value,
                               _In_ uint32_t attr_index,
                               _Inout_ vendor_cache_t* cache,
                               void* arg);

sai_status_t port_pfc_get(_In_ const sai_object_key_t* key,
                          _Inout_ sai_attribute_value_t* value,
                          _In_ uint32_t attr_index,
                          _Inout_ vendor_cache_t* cache,
                          void* arg);

sai_status_t port_serdes_port_id_get(_In_ const sai_object_key_t* key,
                                     _Inout_ sai_attribute_value_t* value,
                                     _In_ uint32_t attr_index,
                                     _Inout_ vendor_cache_t* cache,
                                     void* arg);

sai_status_t serdes_preem_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg);

sai_status_t serdes_param_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg);

sai_status_t port_type_get(_In_ const sai_object_key_t* key,
                           _Inout_ sai_attribute_value_t* value,
                           _In_ uint32_t attr_index,
                           _Inout_ vendor_cache_t* cache,
                           void* arg);

sai_status_t port_supported_speed_get(_In_ const sai_object_key_t* key,
                                      _Inout_ sai_attribute_value_t* value,
                                      _In_ uint32_t attr_index,
                                      _Inout_ vendor_cache_t* cache,
                                      void* arg);

sai_status_t port_supported_fec_get(_In_ const sai_object_key_t* key,
                                    _Inout_ sai_attribute_value_t* value,
                                    _In_ uint32_t attr_index,
                                    _Inout_ vendor_cache_t* cache,
                                    void* arg);

sai_status_t port_supported_half_duplex_speed_get(_In_ const sai_object_key_t* key,
                                                  _Inout_ sai_attribute_value_t* value,
                                                  _In_ uint32_t attr_index,
                                                  _Inout_ vendor_cache_t* cache,
                                                  void* arg);

sai_status_t port_supported_an_get(_In_ const sai_object_key_t* key,
                                   _Inout_ sai_attribute_value_t* value,
                                   _In_ uint32_t attr_index,
                                   _Inout_ vendor_cache_t* cache,
                                   void* arg);

sai_status_t port_supported_fc_get(_In_ const sai_object_key_t* key,
                                   _Inout_ sai_attribute_value_t* value,
                                   _In_ uint32_t attr_index,
                                   _Inout_ vendor_cache_t* cache,
                                   void* arg);

sai_status_t port_supported_asym_pause_get(_In_ const sai_object_key_t* key,
                                           _Inout_ sai_attribute_value_t* value,
                                           _In_ uint32_t attr_index,
                                           _Inout_ vendor_cache_t* cache,
                                           void* arg);

sai_status_t port_supported_media_type_get(_In_ const sai_object_key_t* key,
                                           _Inout_ sai_attribute_value_t* value,
                                           _In_ uint32_t attr_index,
                                           _Inout_ vendor_cache_t* cache,
                                           void* arg);

sai_status_t port_number_of_scheduler_groups_get(_In_ const sai_object_key_t* key,
                                                 _Inout_ sai_attribute_value_t* value,
                                                 _In_ uint32_t attr_index,
                                                 _Inout_ vendor_cache_t* cache,
                                                 void* arg);

sai_status_t port_qos_scheduler_group_list_get(_In_ const sai_object_key_t* key,
                                               _Inout_ sai_attribute_value_t* value,
                                               _In_ uint32_t attr_index,
                                               _Inout_ vendor_cache_t* cache,
                                               void* arg);

sai_status_t port_dot1p_tc_map_get(_In_ const sai_object_key_t* key,
                                   _Inout_ sai_attribute_value_t* value,
                                   _In_ uint32_t attr_index,
                                   _Inout_ vendor_cache_t* cache,
                                   void* arg);

sai_status_t port_tc_pg_map_get(_In_ const sai_object_key_t* key,
                                _Inout_ sai_attribute_value_t* value,
                                _In_ uint32_t attr_index,
                                _Inout_ vendor_cache_t* cache,
                                void* arg);

sai_status_t port_dscp_tc_map_get(_In_ const sai_object_key_t* key,
                                  _Inout_ sai_attribute_value_t* value,
                                  _In_ uint32_t attr_index,
                                  _Inout_ vendor_cache_t* cache,
                                  void* arg);

sai_status_t port_tc_queue_map_get(_In_ const sai_object_key_t* key,
                                   _Inout_ sai_attribute_value_t* value,
                                   _In_ uint32_t attr_index,
                                   _Inout_ vendor_cache_t* cache,
                                   void* arg);

sai_status_t port_default_vlan_get(_In_ const sai_object_key_t* key,
                                   _Inout_ sai_attribute_value_t* value,
                                   _In_ uint32_t attr_index,
                                   _Inout_ vendor_cache_t* cache,
                                   void* arg);

sai_status_t port_default_vlan_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_pfc_queue_map_get(_In_ const sai_object_key_t* key,
                                    _Inout_ sai_attribute_value_t* value,
                                    _In_ uint32_t attr_index,
                                    _Inout_ vendor_cache_t* cache,
                                    void* arg);

sai_status_t port_mirror_session_get(_In_ const sai_object_key_t* key,
                                     _Inout_ sai_attribute_value_t* value,
                                     _In_ uint32_t attr_index,
                                     _Inout_ vendor_cache_t* cache,
                                     void* arg);

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 7, 0)
sai_status_t port_sample_mirror_session_get(_In_ const sai_object_key_t* key,
                                            _Inout_ sai_attribute_value_t* value,
                                            _In_ uint32_t attr_index,
                                            _Inout_ vendor_cache_t* cache,
                                            void* arg);
#endif

sai_status_t port_samplepacket_get(_In_ const sai_object_key_t* key,
                                   _Inout_ sai_attribute_value_t* value,
                                   _In_ uint32_t attr_index,
                                   _Inout_ vendor_cache_t* cache,
                                   void* arg);

sai_status_t port_speed_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_state_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_media_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_lpbk_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_fec_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_autoneg_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_mtu_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_fc_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_pfc_mode_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_pfc_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_mirror_session_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 7, 0)
sai_status_t port_sample_mirror_session_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
#endif

sai_status_t port_samplepacket_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t serdes_preem_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t serdes_param_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_dot1p_tc_map_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_tc_pg_map_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_dscp_tc_map_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_tc_queue_map_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_pfc_pg_map_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_pfc_queue_map_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 7, 0)
sai_status_t decrement_ttl_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t decrement_ttl_get(_In_ const sai_object_key_t* key,
                               _Inout_ sai_attribute_value_t* value,
                               _In_ uint32_t attr_index,
                               _Inout_ vendor_cache_t* cache,
                               void* arg);
#endif
#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 6, 2)
sai_status_t port_system_port_get(_In_ const sai_object_key_t* key,
                                  _Inout_ sai_attribute_value_t* value,
                                  _In_ uint32_t attr_index,
                                  _Inout_ vendor_cache_t* cache,
                                  void* arg);
#endif

sai_status_t get_system_port_id(_In_ const sai_object_key_t* key,
                                _Inout_ sai_attribute_value_t* value,
                                _In_ uint32_t attr_index,
                                _Inout_ vendor_cache_t* cache,
                                void* arg);

sai_status_t port_adv_speed_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_adv_fec_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 7, 0)
sai_status_t port_if_type_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg);

sai_status_t port_if_type_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

sai_status_t port_adv_if_type_get(_In_ const sai_object_key_t* key,
                                  _Inout_ sai_attribute_value_t* value,
                                  _In_ uint32_t attr_index,
                                  _Inout_ vendor_cache_t* cache,
                                  void* arg);

sai_status_t port_adv_if_type_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
#endif

static sai_status_t read_wred_port_counters(std::shared_ptr<lsai_device> sdev,
                                            la_system_port* system_port,
                                            sai_stats_mode_t mode,
                                            uint32_t& wred_dropped_pkt_cnt,
                                            uint32_t& wred_dropped_byte_cnt);

// clang-format off

extern const sai_attribute_entry_t port_attribs[] = {
    {SAI_PORT_ATTR_TYPE, false, false, false, true, "Port type", SAI_ATTR_VAL_TYPE_S32},
    {SAI_PORT_ATTR_OPER_STATUS, false, false, false, true, "Port operational status", SAI_ATTR_VAL_TYPE_S32},
    {SAI_PORT_ATTR_HW_LANE_LIST, true, true, false, true, "Port HW lane list", SAI_ATTR_VAL_TYPE_U32LIST},
    {SAI_PORT_ATTR_SPEED, true, true, true, true, "Port speed", SAI_ATTR_VAL_TYPE_U32},
    {SAI_PORT_ATTR_SUPPORTED_SPEED, false, false, false, true, "Port supported speed", SAI_ATTR_VAL_TYPE_U32LIST},
    {SAI_PORT_ATTR_SUPPORTED_FEC_MODE, false, false, false, true, "Port supported FEC", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_ATTR_SUPPORTED_HALF_DUPLEX_SPEED, false, false, false, true, "Port supported Duplex speed", SAI_ATTR_VAL_TYPE_U32LIST},
    {SAI_PORT_ATTR_SUPPORTED_AUTO_NEG_MODE, false, false, false, true, "Port supported auto-neg mode", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_PORT_ATTR_SUPPORTED_FLOW_CONTROL_MODE, false, false, false, true, "Port supported Flow control mode", SAI_ATTR_VAL_TYPE_S32},
    {SAI_PORT_ATTR_SUPPORTED_ASYMMETRIC_PAUSE_MODE, false, false, false, true, "Port supported asymmetric pause mode", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_PORT_ATTR_SUPPORTED_MEDIA_TYPE, false, false, false, true, "Port supported speed", SAI_ATTR_VAL_TYPE_S32},
    {SAI_PORT_ATTR_AUTO_NEG_MODE, false, true, true, true, "Port auto-neg mode", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_PORT_ATTR_ADMIN_STATE, false, true, true, true, "Port admin state", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_PORT_ATTR_MEDIA_TYPE, false, true, true, true, "Port media type", SAI_ATTR_VAL_TYPE_S32},
    {SAI_PORT_ATTR_PORT_VLAN_ID, false, true, true, true, "Port vlan ID", SAI_ATTR_VAL_TYPE_U16},
    {SAI_PORT_ATTR_DEFAULT_VLAN_PRIORITY, false, true, true, true, "Port default vlan priority", SAI_ATTR_VAL_TYPE_U8},
    {SAI_PORT_ATTR_DROP_UNTAGGED, false, true, true, true, "Port drop untageed", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_PORT_ATTR_DROP_TAGGED, false, true, true, true, "Port drop tageed", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE, false, true, true, true, "Port internal loopback", SAI_ATTR_VAL_TYPE_S32},
    {SAI_PORT_ATTR_UPDATE_DSCP, false, true, true, true, "Port update DSCP", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_PORT_ATTR_FEC_MODE, false, false, true, true, "Port FEC setting", SAI_ATTR_VAL_TYPE_S32},
    {SAI_PORT_ATTR_MTU, false, true, true, true, "Port mtu", SAI_ATTR_VAL_TYPE_U32},
    {SAI_PORT_ATTR_FLOOD_STORM_CONTROL_POLICER_ID, false, true, true, true, "Port flood storm control", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_PORT_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID, false, true, true, true, "Port broadcast storm control", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_PORT_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID, false, true, true, true, "Port multicast storm control", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE, false, true, true, true, "Port global flow control", SAI_ATTR_VAL_TYPE_S32},
    {SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE, false, true, true, true, "Port priority flow control mode", SAI_ATTR_VAL_TYPE_S32},
    {SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, false, true, true, true, "PFC combined mode bit 0 - 7", SAI_ATTR_VAL_TYPE_S8},
    {SAI_PORT_ATTR_INGRESS_MIRROR_SESSION, false, true, true, true, "Port ingress mirror session", SAI_ATTR_VAL_TYPE_OBJLIST},
    {SAI_PORT_ATTR_EGRESS_MIRROR_SESSION, false, true, true, true, "Port egress mirror session", SAI_ATTR_VAL_TYPE_OBJLIST},
#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 7, 0)
    {SAI_PORT_ATTR_INGRESS_SAMPLE_MIRROR_SESSION, false, true, true, true, "Port ingress sample mirror session", SAI_ATTR_VAL_TYPE_OBJLIST},
    {SAI_PORT_ATTR_EGRESS_SAMPLE_MIRROR_SESSION, false, true, true, true, "Port egress sample mirror session", SAI_ATTR_VAL_TYPE_OBJLIST},
#endif
    {SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE, false, true, true, true, "Port ingress samplepacket enable", SAI_ATTR_VAL_TYPE_OID},
    {SAI_PORT_ATTR_EGRESS_SAMPLEPACKET_ENABLE, false, true, true, true, "Port egress samplepacket enable", SAI_ATTR_VAL_TYPE_OID},
    {SAI_PORT_ATTR_QOS_NUMBER_OF_QUEUES, false, false, false, true, "Number of Queues on the Port", SAI_ATTR_VAL_TYPE_U32},
    {SAI_PORT_ATTR_QOS_QUEUE_LIST, false, false, false, true, "List of Queues on the Port", SAI_ATTR_VAL_TYPE_OBJLIST},
    {SAI_PORT_ATTR_INGRESS_ACL, false, false, true, true, "Port bind point for ingress ACL object", SAI_ATTR_VAL_TYPE_OID},
    {SAI_PORT_ATTR_EGRESS_ACL, false, false, true, true, "Port bind point for ingress ACL object", SAI_ATTR_VAL_TYPE_OID},
    {SAI_PORT_ATTR_SERDES_PREEMPHASIS, false, true, true, true, "Per-lanes Port serdes control pre-emphasis", SAI_ATTR_VAL_TYPE_U32LIST},
    {SAI_PORT_ATTR_QOS_NUMBER_OF_SCHEDULER_GROUPS, false, false, false, true, "Number of port qos scheduler groups", SAI_ATTR_VAL_TYPE_U32},
    {SAI_PORT_ATTR_QOS_SCHEDULER_GROUP_LIST, false, false, true, true, "Port qos scheduler group list", SAI_ATTR_VAL_TYPE_OID},
    {SAI_PORT_ATTR_NUMBER_OF_INGRESS_PRIORITY_GROUPS, false, false, false, true, "Numnber of ingress priority groups supported", SAI_ATTR_VAL_TYPE_U32},
    {SAI_PORT_ATTR_INGRESS_PRIORITY_GROUP_LIST, false, false, false, true, "List ingress priority groups", SAI_ATTR_VAL_TYPE_OBJLIST},
    {SAI_PORT_ATTR_QOS_DOT1P_TO_TC_MAP, false, false, true , true, "dot1p to tc map on the Port", SAI_ATTR_VAL_TYPE_OID},
    {SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP, false, true, true, true, "TC to Priority Group map", SAI_ATTR_VAL_TYPE_OID},
    {SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP, false, true, true, true, "Port dscp to tc map", SAI_ATTR_VAL_TYPE_OID},
    {SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP, false, true, true, true, "Port tc to queue map", SAI_ATTR_VAL_TYPE_OID},
    {SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP, false, false, true, true, "PFC to Queue map", SAI_ATTR_VAL_TYPE_OID},
#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 7, 0)
    {SAI_PORT_ATTR_DISABLE_DECREMENT_TTL, false, true, true, true, "Decrement TTL", SAI_ATTR_VAL_TYPE_BOOL},
#endif
#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 6, 2)
    {SAI_PORT_ATTR_SYSTEM_PORT, false, false, false, true, "System port SAI object ID attached to this port", SAI_ATTR_VAL_TYPE_OID},
#endif
    {SAI_PORT_ATTR_EXT_SYSTEM_PORT_ID, false, false, false, true, "System Port Global ID for this port", SAI_ATTR_VAL_TYPE_U16},
    {SAI_PORT_ATTR_ADVERTISED_SPEED, false, true, true, true, "Advertised Port Speeds.", SAI_ATTR_VAL_TYPE_U32LIST},
    {SAI_PORT_ATTR_ADVERTISED_FEC_MODE, false, true, true, true, "Advertised Port Speeds.", SAI_ATTR_VAL_TYPE_S32LIST},
#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 7, 0)
    {SAI_PORT_ATTR_INTERFACE_TYPE, false, true, true, true, "Port Interface Type.", SAI_ATTR_VAL_TYPE_S32},
    {SAI_PORT_ATTR_ADVERTISED_INTERFACE_TYPE, false, true, true, true, "Advertised Port Interface Types.", SAI_ATTR_VAL_TYPE_S32LIST},
#endif
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t port_vendor_attribs[] = {
    {SAI_PORT_ATTR_TYPE,
     {false, false, false, true},
     {false, false, false, true},
     port_type_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_OPER_STATUS,
     {false, false, false, true},
     {false, false, false, true},
     port_oper_status_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_HW_LANE_LIST,
     {true, false, false, true},
     {true, false, false, true},
     port_hw_lanes_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_SPEED,
     {true, false, true, true},
     {true, false, true, true},
     port_speed_get, (void*)SAI_PORT_ATTR_SPEED, port_speed_set, (void*)SAI_PORT_ATTR_SPEED},

    {SAI_PORT_ATTR_SUPPORTED_SPEED,
     {true, false, false, true},
     {true, false, false, true},
     port_supported_speed_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_SUPPORTED_FEC_MODE,
     {true, false, false, true},
     {true, false, false, true},
     port_supported_fec_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_SUPPORTED_HALF_DUPLEX_SPEED,
     {true, false, false, true},
     {true, false, false, true},
     port_supported_half_duplex_speed_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_SUPPORTED_AUTO_NEG_MODE,
     {true, false, false, true},
     {true, false, false, true},
     port_supported_an_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_SUPPORTED_FLOW_CONTROL_MODE,
     {true, false, false, true},
     {true, false, false, true},
     port_supported_fc_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_SUPPORTED_ASYMMETRIC_PAUSE_MODE,
     {true, false, false, true},
     {true, false, false, true},
     port_supported_asym_pause_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_SUPPORTED_MEDIA_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     port_supported_media_type_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_AUTO_NEG_MODE,
     {true, false, true, true},
     {true, false, true, true},
     port_autoneg_get, nullptr, port_autoneg_set, nullptr},

    {SAI_PORT_ATTR_ADMIN_STATE,
     {true, false, true, true},
     {true, false, true, true},
     port_state_get, nullptr, port_state_set, nullptr},

    {SAI_PORT_ATTR_MEDIA_TYPE,
     {true, false, true, true},
     {true, false, true, true},
     port_media_get, nullptr, port_media_set, nullptr},

    {SAI_PORT_ATTR_PORT_VLAN_ID,
     {true, false, true, true},
     {true, false, true, true},
     port_default_vlan_get, nullptr,
     port_default_vlan_set, nullptr},

    {SAI_PORT_ATTR_DEFAULT_VLAN_PRIORITY,
     {false, false, false, false},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_DROP_UNTAGGED,
     {false, false, false, false},
     {false, false, false, false},
     nullptr, (void*)SAI_PORT_ATTR_DROP_UNTAGGED, nullptr, (void*)SAI_PORT_ATTR_DROP_UNTAGGED},

    {SAI_PORT_ATTR_DROP_TAGGED,
     {false, false, false, false},
     {false, false, false, false},
     nullptr, (void*)SAI_PORT_ATTR_DROP_TAGGED, nullptr, (void*)SAI_PORT_ATTR_DROP_TAGGED},

    {SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE,
     {true, false, true, true},
     {true, false, true, true},
     port_lpbk_get, nullptr, port_lpbk_set, nullptr},

    {SAI_PORT_ATTR_UPDATE_DSCP,
     {false, false, false, false},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_FEC_MODE,
     {true, false, true, true},
     {true, false, true, true},
     port_fec_get, (void*)SAI_PORT_ATTR_FEC_MODE, port_fec_set, (void*)SAI_PORT_ATTR_FEC_MODE},

    {SAI_PORT_ATTR_MTU,
     {true, false, true, true},
     {true, false, true, true},
     port_mtu_get, nullptr, port_mtu_set, nullptr},

    {SAI_PORT_ATTR_FLOOD_STORM_CONTROL_POLICER_ID,
     {false, false, false, false},
     {false, false, false, false},
     nullptr, (void*)SAI_PORT_ATTR_FLOOD_STORM_CONTROL_POLICER_ID, nullptr, (void*)SAI_PORT_ATTR_FLOOD_STORM_CONTROL_POLICER_ID},

    {SAI_PORT_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID,
     {false, false, false, false},
     {false, false, false, false},
     nullptr, (void*)SAI_PORT_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID, nullptr, (void*)SAI_PORT_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID},

    {SAI_PORT_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID,
     {false, false, false, false},
     {false, false, false, false},
     nullptr, (void*)SAI_PORT_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID, nullptr, (void*)SAI_PORT_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID},

    {SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE,
     {true, false, true, true},
     {true, false, true, true},
     port_fc_get, nullptr, port_fc_set, nullptr},

    {SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE,
     {false, false, true, true},
     {false, false, true, true},
     port_pfc_mode_get, nullptr, port_pfc_mode_set, nullptr},

    {SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL,
     {true, false, true, true},
     {true, false, true, true},
     port_pfc_get, nullptr, port_pfc_set, nullptr},

    {SAI_PORT_ATTR_INGRESS_MIRROR_SESSION,
     {true, false, true, true},
     {true, false, true, true},
     port_mirror_session_get,(void*)SAI_PORT_ATTR_INGRESS_MIRROR_SESSION, port_mirror_session_set, (void*)SAI_PORT_ATTR_INGRESS_MIRROR_SESSION},

    {SAI_PORT_ATTR_EGRESS_MIRROR_SESSION,
     {false, false, true, true},
     {false, false, true, true},
     port_mirror_session_get,(void*)SAI_PORT_ATTR_EGRESS_MIRROR_SESSION, port_mirror_session_set, (void*)SAI_PORT_ATTR_EGRESS_MIRROR_SESSION},

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 7, 0)
    {SAI_PORT_ATTR_INGRESS_SAMPLE_MIRROR_SESSION,
     {true, false, true, true},
     {true, false, true, true},
     port_sample_mirror_session_get, (void*)SAI_PORT_ATTR_INGRESS_SAMPLE_MIRROR_SESSION, port_sample_mirror_session_set, (void*)SAI_PORT_ATTR_INGRESS_SAMPLE_MIRROR_SESSION},

    {SAI_PORT_ATTR_EGRESS_SAMPLE_MIRROR_SESSION,
     {false, false, true, true},
     {false, false, true, true},
     port_sample_mirror_session_get, (void*)SAI_PORT_ATTR_EGRESS_SAMPLE_MIRROR_SESSION, port_sample_mirror_session_set, (void*)SAI_PORT_ATTR_EGRESS_SAMPLE_MIRROR_SESSION},
#endif

    {SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE,
     {false, false, true, true},
     {false, false, true, true},
     port_samplepacket_get,(void*)SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE, port_samplepacket_set, (void*)SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE},

    {SAI_PORT_ATTR_EGRESS_SAMPLEPACKET_ENABLE,
     {false, false, true, true},
     {false, false, true, true},
     port_samplepacket_get,(void*)SAI_PORT_ATTR_EGRESS_SAMPLEPACKET_ENABLE, port_samplepacket_set, (void*)SAI_PORT_ATTR_EGRESS_SAMPLEPACKET_ENABLE},

    {SAI_PORT_ATTR_QOS_NUMBER_OF_QUEUES,
     {false, false, false, true},
     {false, false, false, true},
     port_qos_number_of_queues_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_QOS_QUEUE_LIST,
     {false, false, false, true},
     {false, false, false, true},
     port_qos_queue_list_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_INGRESS_ACL,
     {false, false, true, true},
     {false, false, true, true},
     port_acl_get,
     (void*)SAI_PORT_ATTR_INGRESS_ACL,
     port_acl_set,
     (void*)SAI_PORT_ATTR_INGRESS_ACL},

    {SAI_PORT_ATTR_EGRESS_ACL,
     {false, false, true, true},
     {false, false, true, true},
     port_acl_get,
     (void*)SAI_PORT_ATTR_EGRESS_ACL,
     port_acl_set,
     (void*)SAI_PORT_ATTR_EGRESS_ACL},

    {SAI_PORT_ATTR_SERDES_PREEMPHASIS,
     {true, false, true, true},
     {true, false, true, true},
     serdes_preem_get, nullptr, serdes_preem_set, nullptr},

    {SAI_PORT_ATTR_QOS_NUMBER_OF_SCHEDULER_GROUPS,
     {false, false, false, true},
     {false, false, false, true},
     port_number_of_scheduler_groups_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_QOS_SCHEDULER_GROUP_LIST,
     {false, false, false, true},
     {false, false, false, true},
      port_qos_scheduler_group_list_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_NUMBER_OF_INGRESS_PRIORITY_GROUPS,
     {false, false, false, true},
     {false, false, false, true},
     port_ingress_number_of_priority_groups_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_INGRESS_PRIORITY_GROUP_LIST,
     {false, false, false, true},
     {false, false, false, true},
     port_priority_group_list_get, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_QOS_DOT1P_TO_TC_MAP,
     {false, false, true, true},
     {false, false, true, true},
     port_dot1p_tc_map_get,
     (void*)SAI_PORT_ATTR_QOS_DOT1P_TO_TC_MAP,
     port_dot1p_tc_map_set,
     (void*)SAI_PORT_ATTR_QOS_DOT1P_TO_TC_MAP},

    {SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP,
     {false, false, true, true},
     {false, false, true, true},
     port_tc_pg_map_get,
     nullptr,
     port_tc_pg_map_set,
     nullptr},

    {SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP,
     {false, false, true, true},
     {false, false, true, true},
     port_dscp_tc_map_get, nullptr, port_dscp_tc_map_set, nullptr},

    {SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP,
     {false, false, true, true},
     {false, false, true, true},
     port_tc_queue_map_get, nullptr, port_tc_queue_map_set, nullptr},

    {SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP,
     {false, false, true, true},
     {false, false, true, true},
     port_pfc_queue_map_get, nullptr, port_pfc_queue_map_set, nullptr},

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 7, 0)
    {SAI_PORT_ATTR_DISABLE_DECREMENT_TTL,
     {true, false, true, true},
     {true, false, true, true},
     decrement_ttl_get, nullptr, decrement_ttl_set, nullptr},
#endif
#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 6, 2)
    {SAI_PORT_ATTR_SYSTEM_PORT,
     {false, false, false, true},
     {false, false, false, true},
     port_system_port_get, nullptr, nullptr, nullptr},
#endif

    {SAI_PORT_ATTR_EXT_SYSTEM_PORT_ID,
     {false, false, false, true},
     {false, false, false, true},
     get_system_port_id, nullptr, nullptr, nullptr},

    {SAI_PORT_ATTR_ADVERTISED_SPEED,
     {true, false, true, true},
     {true, false, true, true},
     port_speed_get, (void*)SAI_PORT_ATTR_ADVERTISED_SPEED, port_adv_speed_set, nullptr},

    {SAI_PORT_ATTR_ADVERTISED_FEC_MODE,
     {true, false, true, true},
     {true, false, true, true},
     port_fec_get, (void*)SAI_PORT_ATTR_ADVERTISED_FEC_MODE, port_adv_fec_set, nullptr},

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 7, 0)
    {SAI_PORT_ATTR_INTERFACE_TYPE,
     {true, false, true, true},
     {true, false, true, true},
     port_if_type_get, nullptr, port_if_type_set, nullptr},

    {SAI_PORT_ATTR_ADVERTISED_INTERFACE_TYPE,
     {true, false, true, true},
     {true, false, true, true},
     port_adv_if_type_get, nullptr, port_adv_if_type_set, nullptr},
#endif
};

extern const sai_attribute_entry_t port_serdes_attribs[] = {
    {SAI_PORT_SERDES_ATTR_PORT_ID, true, true, false, true, "SAI Port ID", SAI_ATTR_VAL_TYPE_OID},
    {SAI_PORT_SERDES_ATTR_PREEMPHASIS, false, true, true, true, "Per-lanes Port serdes control pre-emphasis", SAI_ATTR_VAL_TYPE_U32LIST},
    {SAI_PORT_SERDES_ATTR_TX_FIR_PRE1, false, true, true, true, "Serdes TX Precursor 1", SAI_ATTR_VAL_TYPE_U32LIST},
    {SAI_PORT_SERDES_ATTR_TX_FIR_PRE2, false, true, true, true, "Serdes TX Precursor 2", SAI_ATTR_VAL_TYPE_U32LIST},
    {SAI_PORT_SERDES_ATTR_TX_FIR_PRE3, false, true, true, true, "Serdes TX Precursor 3", SAI_ATTR_VAL_TYPE_U32LIST},
    {SAI_PORT_SERDES_ATTR_TX_FIR_MAIN, false, true, true, true, "Serdes TX Main-cursor", SAI_ATTR_VAL_TYPE_U32LIST},
    {SAI_PORT_SERDES_ATTR_TX_FIR_POST1, false, true, true, true, "Serdes TX Post-cursor 1", SAI_ATTR_VAL_TYPE_U32LIST},
    {SAI_PORT_SERDES_ATTR_TX_FIR_POST2, false, true, true, true, "Serdes TX Post-cursor 2", SAI_ATTR_VAL_TYPE_U32LIST},
    {SAI_PORT_SERDES_ATTR_TX_FIR_POST3, false, true, true, true, "Serdes TX Post-cursor 3", SAI_ATTR_VAL_TYPE_U32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_CTLE_TUNE, false, true, true, true, "Serdes CTLE Tune Enable", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_TX_LUT_MODE, false, true, true, true, "Serdes TX LUT Mode", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_TX_PRE1, false, true, true, true, "Serdes TX Precursor 1", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_TX_PRE2, false, true, true, true, "Serdes TX Precursor 2", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_TX_PRE3, false, true, true, true, "Serdes TX Precursor 3", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_TX_MAIN, false, true, true, true, "Serdes TX Main-cursor", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_TX_POST, false, true, true, true, "Serdes TX Post-cursor 1", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_TX_POST2, false, true, true, true, "Serdes TX Post-cursor 2", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_TX_POST3, false, true, true, true, "Serdes TX Post-cursor 3", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE1, false, true, true, true, "Serdes TX Inner Eye1", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE2, false, true, true, true, "Serdes TX Inner Eye2", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_RX_CTLE_CODE, false, true, true, true, "Serdes RX CTLE Code", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_RX_DSP_MODE, false, true, true, true, "Serdes RX DSP Mode", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_RX_AFE_TRIM, false, true, true, true, "Serdes RX AFE Trim", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_RX_VGA_TRACKING, false, true, true, true, "Serdes RX VGA Tracking", SAI_ATTR_VAL_TYPE_S32LIST},
    {SAI_PORT_SERDES_ATTR_EXT_RX_AC_COUPLING_BYPASS, false, true, true, true, "Serdes RX AC Coupling Bypass", SAI_ATTR_VAL_TYPE_S32LIST},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t port_serdes_vendor_attribs[] = {
    {SAI_PORT_SERDES_ATTR_PORT_ID,           {true, false, false, true}, {true, false, false, true},
        port_serdes_port_id_get, nullptr, nullptr, nullptr},
    {SAI_PORT_SERDES_ATTR_PREEMPHASIS,       {true, false, true, true}, {true, false, true, true},
        serdes_preem_get, nullptr, serdes_preem_set, nullptr},
    {SAI_PORT_SERDES_ATTR_TX_FIR_PRE1,       {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_TX_FIR_PRE1, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_TX_FIR_PRE1},
    {SAI_PORT_SERDES_ATTR_TX_FIR_PRE2,       {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_TX_FIR_PRE2, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_TX_FIR_PRE2},
    {SAI_PORT_SERDES_ATTR_TX_FIR_PRE3,       {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_TX_FIR_PRE3, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_TX_FIR_PRE3},
    {SAI_PORT_SERDES_ATTR_TX_FIR_MAIN,       {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_TX_FIR_MAIN, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_TX_FIR_MAIN},
    {SAI_PORT_SERDES_ATTR_TX_FIR_POST1,      {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_TX_FIR_POST1, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_TX_FIR_POST1},
    {SAI_PORT_SERDES_ATTR_TX_FIR_POST2,      {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_TX_FIR_POST2, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_TX_FIR_POST2},
    {SAI_PORT_SERDES_ATTR_TX_FIR_POST3,      {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_TX_FIR_POST3, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_TX_FIR_POST3},
    {SAI_PORT_SERDES_ATTR_EXT_CTLE_TUNE,     {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_CTLE_TUNE, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_CTLE_TUNE},
    {SAI_PORT_SERDES_ATTR_EXT_TX_LUT_MODE,   {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_LUT_MODE, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_LUT_MODE},
    {SAI_PORT_SERDES_ATTR_EXT_TX_PRE1,       {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_PRE1, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_PRE1},
    {SAI_PORT_SERDES_ATTR_EXT_TX_PRE2,       {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_PRE2, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_PRE2},
    {SAI_PORT_SERDES_ATTR_EXT_TX_PRE3,       {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_PRE3, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_PRE3},
    {SAI_PORT_SERDES_ATTR_EXT_TX_MAIN,       {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_MAIN, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_MAIN},
    {SAI_PORT_SERDES_ATTR_EXT_TX_POST,       {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_POST, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_POST},
    {SAI_PORT_SERDES_ATTR_EXT_TX_POST2,      {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_POST2, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_POST2},
    {SAI_PORT_SERDES_ATTR_EXT_TX_POST3,      {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_POST3, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_POST3},
    {SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE1, {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE1, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE1},
    {SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE2, {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE2, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE2},
    {SAI_PORT_SERDES_ATTR_EXT_RX_CTLE_CODE,  {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_RX_CTLE_CODE, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_RX_CTLE_CODE},
    {SAI_PORT_SERDES_ATTR_EXT_RX_DSP_MODE,   {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_RX_DSP_MODE, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_RX_DSP_MODE},
    {SAI_PORT_SERDES_ATTR_EXT_RX_AFE_TRIM,   {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_RX_AFE_TRIM, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_RX_AFE_TRIM},
    {SAI_PORT_SERDES_ATTR_EXT_RX_VGA_TRACKING, {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_RX_VGA_TRACKING, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_RX_VGA_TRACKING},
    {SAI_PORT_SERDES_ATTR_EXT_RX_AC_COUPLING_BYPASS, {true, false, true, true}, {true, false, true, true},
        serdes_param_get, (void*)SAI_PORT_SERDES_ATTR_EXT_RX_AC_COUPLING_BYPASS, serdes_param_set, (void*)SAI_PORT_SERDES_ATTR_EXT_RX_AC_COUPLING_BYPASS}
};

// clang-format on

static la_status setup_mac_port_serdes_params(la_mac_port* mac_port,
                                              const sai_port_media_type_t& media_type,
                                              const std::shared_ptr<lsai_device> sdev);

sai_status_t
laobj_db_port::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    uint32_t num = 0;

    for (auto& p : sdev->m_ports.map()) {
        if (!p.second.is_mac()) {
            continue;
        }
        num++;
    }
    *count = num;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_port::get_object_keys(std::shared_ptr<lsai_device> sdev, uint32_t* object_count, sai_object_key_t* object_list) const
{
    uint32_t port_num = 0;
    get_object_count(sdev, &port_num);
    uint32_t requested_object_count = *object_count;
    *object_count = port_num;

    if (requested_object_count < port_num) {
        *object_count = port_num;
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    uint32_t idx = 0;
    for (auto& p : sdev->m_ports.map()) {
        if (p.second.is_mac()) {
            object_list[idx++].key.object_id = p.second.service.oid;
        }
    }
    *object_count = idx;
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
to_port_obj_id(const sai_object_id_t& port_serdes_obj_id, sai_object_id_t& port_obj_id)
{
    lsai_object la_port_serdes(port_serdes_obj_id);
    if (la_port_serdes.type != sai_object_type_t::SAI_OBJECT_TYPE_PORT_SERDES) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_port_serdes.type = sai_object_type_t::SAI_OBJECT_TYPE_PORT;
    port_obj_id = la_port_serdes.object_id();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
to_port_serdes_obj_id(const sai_object_id_t& port_obj_id, sai_object_id_t& port_serdes_obj_id)
{
    lsai_object la_port(port_obj_id);
    if (la_port.type != sai_object_type_t::SAI_OBJECT_TYPE_PORT) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_port.type = sai_object_type_t::SAI_OBJECT_TYPE_PORT_SERDES;
    port_serdes_obj_id = la_port.object_id();
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_port_ptrs_by_oid(sai_object_id_t sai_port_oid,
                     port_entry*& out_entry_ptr,
                     la_mac_port*& out_mac_port_ptr,
                     std::shared_ptr<lsai_device>& out_sdev)
{
    lsai_object port_obj(sai_port_oid);
    out_sdev = port_obj.get_device();
    sai_check_object(port_obj, SAI_OBJECT_TYPE_PORT, out_sdev, "port", sai_port_oid);
    out_entry_ptr = out_sdev->m_ports.get_ptr(port_obj.index);
    if (out_entry_ptr == nullptr) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    auto status
        = out_sdev->m_dev->get_mac_port(out_entry_ptr->slice_id, out_entry_ptr->ifg_id, out_entry_ptr->pif, out_mac_port_ptr);
    sai_return_on_la_error(status, "Port Entry has invalid Slice/IFG/Serdes ID.");

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_port_entry_by_eth_obj(sai_object_id_t eth_port_obj,
                          std::shared_ptr<lsai_device>& out_sdev,
                          uint32_t& out_port_idx,
                          port_entry& out_pentry)
{
    lsai_object la_port(eth_port_obj);
    out_sdev = la_port.get_device();
    sai_check_object(la_port, SAI_OBJECT_TYPE_PORT, out_sdev, "port", eth_port_obj);

    out_pentry = port_entry{};
    out_port_idx = la_port.index;
    la_status status = out_sdev->m_ports.get(out_port_idx, out_pentry);
    if (status != LA_STATUS_SUCCESS) {
        sai_log_error(SAI_API_PORT, "Can not get port 0x%lx", eth_port_obj);
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_mac_port_by_port_entry(std::shared_ptr<lsai_device> sdev, port_entry pentry, la_mac_port*& out_mac_port)
{
    if (!pentry.is_mac()) {
        sai_log_error(SAI_API_PORT, "Cannot get mac_port on non-mac port ID 0x%lx", pentry.service.oid);
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    la_status status = sdev->m_dev->get_mac_port(pentry.slice_id, pentry.ifg_id, pentry.pif, out_mac_port);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_mac_port_by_eth_obj(sai_object_id_t eth_port_obj,
                        std::shared_ptr<lsai_device>& out_sdev,
                        uint32_t& out_port_idx,
                        port_entry& out_pentry,
                        la_mac_port*& out_mac_port)
{
    out_mac_port = nullptr;

    sai_status_t sai_status = get_port_entry_by_eth_obj(eth_port_obj, out_sdev, out_port_idx, out_pentry);
    sai_return_on_error(sai_status);

    sai_status = get_mac_port_by_port_entry(out_sdev, out_pentry, out_mac_port);
    sai_return_on_error(sai_status);

    return SAI_STATUS_SUCCESS;
}

la_mac_port*
get_mac_port_by_eth_obj(sai_object_id_t eth_port_obj)
{
    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    la_mac_port* mac_port = nullptr;
    sai_status_t sai_status = get_mac_port_by_eth_obj(eth_port_obj, sdev, port_idx, pentry, mac_port);
    if (sai_status != SAI_STATUS_SUCCESS) {
        mac_port = nullptr;
    }

    return mac_port;
}

static sai_status_t
get_port_entry_by_srds_obj_id(sai_object_id_t srds_obj_id,
                              std::shared_ptr<lsai_device>& out_sdev,
                              uint32_t& out_port_idx,
                              port_entry& out_pentry)
{
    lsai_object la_port(srds_obj_id);

    // First, check for port_serde_entry.
    sai_object_id_t ps_oid = srds_obj_id;
    uint32_t ps_idx = la_port.index;
    std::shared_ptr<lsai_device> sdev = la_port.get_device();
    sai_check_object(la_port, SAI_OBJECT_TYPE_PORT_SERDES, sdev, "port_serdes", ps_oid);

    port_serdes_entry ps_entry;
    la_status status = sdev->m_port_serdes.get(ps_idx, ps_entry);

    if (status != LA_STATUS_SUCCESS) {
        sai_log_error(SAI_API_PORT, "Cannot get port serdes entry, 0x%lx", ps_oid);
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    // Change to Port Object and check if port_serdes_entry has the correct port_oid.
    la_port.type = sai_object_type_t::SAI_OBJECT_TYPE_PORT;
    sai_object_id_t port_oid = la_port.object_id();
    sai_status_t sai_status = get_port_entry_by_eth_obj(port_oid, out_sdev, out_port_idx, out_pentry);
    if (ps_entry.port_oid != port_oid || sdev != out_sdev || ps_idx != out_port_idx) {
        sai_log_error(SAI_API_PORT, "SAI port object(0x%lx) and port_serdes object(0x%lx) mismatched.", port_oid, ps_oid);
        return SAI_STATUS_FAILURE;
    }

    return sai_status;
}

static sai_status_t
get_mac_port_by_srds_obj_id(sai_object_id_t srds_obj_id,
                            std::shared_ptr<lsai_device>& out_sdev,
                            uint32_t& out_port_idx,
                            port_entry& out_pentry,
                            la_mac_port*& out_mac_port)
{
    out_mac_port = nullptr;

    sai_status_t sai_status = get_port_entry_by_srds_obj_id(srds_obj_id, out_sdev, out_port_idx, out_pentry);
    sai_return_on_error(sai_status);

    sai_status = get_mac_port_by_port_entry(out_sdev, out_pentry, out_mac_port);
    sai_return_on_error(sai_status);

    return SAI_STATUS_SUCCESS;
}

// return speed in Mbps
uint32_t
sdk_to_sai_speed(la_mac_port::port_speed_e la_speed)
{
    switch (la_speed) {
    case la_mac_port::port_speed_e::E_10G:
        return 10000;
    case la_mac_port::port_speed_e::E_25G:
        return 25000;
    case la_mac_port::port_speed_e::E_40G:
        return 40000;
    case la_mac_port::port_speed_e::E_50G:
        return 50000;
    case la_mac_port::port_speed_e::E_100G:
        return 100000;
    case la_mac_port::port_speed_e::E_200G:
        return 200000;
    case la_mac_port::port_speed_e::E_400G:
        return 400000;
    case la_mac_port::port_speed_e::E_800G:
        return 800000;
    default:
        return 0;
    }
}

// return prot_speed_e enum in given Mbps
la_mac_port::port_speed_e
sai_to_sdk_speed(uint32_t speed_in_mbps)
{
    switch (speed_in_mbps) {
    case 10000:
        return la_mac_port::port_speed_e::E_10G;
    case 25000:
        return la_mac_port::port_speed_e::E_25G;
    case 40000:
        return la_mac_port::port_speed_e::E_40G;
    case 50000:
        return la_mac_port::port_speed_e::E_50G;
    case 100000:
        return la_mac_port::port_speed_e::E_100G;
    case 200000:
        return la_mac_port::port_speed_e::E_200G;
    case 400000:
        return la_mac_port::port_speed_e::E_400G;
    case 800000:
        return la_mac_port::port_speed_e::E_800G;
    default:
        return static_cast<la_mac_port::port_speed_e>(-1);
    }
}

static sai_port_internal_loopback_mode_t
sdk_to_sai_lpbk_mode(la_mac_port::loopback_mode_e la_lpbk_mode)
{
    switch (la_lpbk_mode) {
    case la_mac_port::loopback_mode_e::NONE:
        return SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE;
    case la_mac_port::loopback_mode_e::MII_CORE_CLK:
        return SAI_PORT_INTERNAL_LOOPBACK_MODE_MAC;
    case la_mac_port::loopback_mode_e::SERDES:
        return SAI_PORT_INTERNAL_LOOPBACK_MODE_PHY;
    default:
        sai_log_error(SAI_API_PORT, "Invalid loopback mode value, la_mac_port::loopback_mode_e(%d)", la_lpbk_mode);
        return SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE;
    }
}

static la_mac_port::loopback_mode_e
sai_to_sdk_lpbk_mode(sai_port_internal_loopback_mode_t sai_lpbk_mode)
{
    switch (sai_lpbk_mode) {
    case SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE:
        return la_mac_port::loopback_mode_e::NONE;
    case SAI_PORT_INTERNAL_LOOPBACK_MODE_PHY:
        return la_mac_port::loopback_mode_e::SERDES;
    case SAI_PORT_INTERNAL_LOOPBACK_MODE_MAC:
        return la_mac_port::loopback_mode_e::MII_CORE_CLK;
    default:
        sai_log_error(SAI_API_PORT, "Invalid loopback mode value, sai_port loopback_mode(%d).", sai_lpbk_mode);
        return la_mac_port::loopback_mode_e::NONE;
    }
}

static sai_port_fec_mode_t
sdk_to_sai_fec_mode(la_mac_port::fec_mode_e fec_mode)
{
    switch (fec_mode) {
    case la_mac_port::fec_mode_e::RS_KP4: // 200G and 400G
    case la_mac_port::fec_mode_e::RS_KR4:
        return SAI_PORT_FEC_MODE_RS;
    case la_mac_port::fec_mode_e::KR:
        return SAI_PORT_FEC_MODE_FC;
    case la_mac_port::fec_mode_e::NONE:
        return SAI_PORT_FEC_MODE_NONE;
    default:
        sai_log_error(SAI_API_PORT, "la_mac_port::fec_mode_e (%d) is not support. return NONE.", fec_mode);
        return SAI_PORT_FEC_MODE_NONE;
    }
}

static la_mac_port::fec_mode_e
sai_to_sdk_fec_mode(sai_port_fec_mode_t fec_mode, la_mac_port::port_speed_e la_speed, uint32_t num_of_serdes)
{
    uint32_t port_speed = sdk_to_sai_speed(la_speed);
    bool serdes_is_50G = ((port_speed / num_of_serdes) >= 50000) ? true : false;
    bool port_is_200Gup = (la_speed >= la_mac_port::port_speed_e::E_200G);
    switch (fec_mode) {
    case SAI_PORT_FEC_MODE_RS:
        if (serdes_is_50G || port_is_200Gup) {
            // Use KP4 if serdes_is_50G or port_is_200Gup.
            return la_mac_port::fec_mode_e::RS_KP4;
        } else {
            return la_mac_port::fec_mode_e::RS_KR4;
        }
    case SAI_PORT_FEC_MODE_FC:
        return la_mac_port::fec_mode_e::KR;
    case SAI_PORT_FEC_MODE_NONE:
        return la_mac_port::fec_mode_e::NONE;
    default:
        sai_log_error(SAI_API_PORT, "sai_port_fec_mode_t (%d) is not support. return NONE.", fec_mode);
        return la_mac_port::fec_mode_e::NONE;
    }
}

static sai_port_flow_control_mode_t
sdk_to_sai_fc_mode(la_mac_port::fc_mode_e tx_fc, la_mac_port::fc_mode_e rx_fc)
{
    if (tx_fc == la_mac_port::fc_mode_e::PAUSE && rx_fc == la_mac_port::fc_mode_e::PAUSE) {
        return SAI_PORT_FLOW_CONTROL_MODE_BOTH_ENABLE;
    } else if (tx_fc == la_mac_port::fc_mode_e::PAUSE) {
        return SAI_PORT_FLOW_CONTROL_MODE_TX_ONLY;
    } else if (rx_fc == la_mac_port::fc_mode_e::PAUSE) {
        return SAI_PORT_FLOW_CONTROL_MODE_RX_ONLY;
    } else {
        return SAI_PORT_FLOW_CONTROL_MODE_DISABLE;
    }
}

static std::pair<la_mac_port::fc_mode_e, la_mac_port::fc_mode_e>
sai_to_sdk_fc_mode(sai_port_flow_control_mode_t sai_fc_mode)
{
    switch (sai_fc_mode) {
    case SAI_PORT_FLOW_CONTROL_MODE_BOTH_ENABLE:
        return std::make_pair(la_mac_port::fc_mode_e::PAUSE, la_mac_port::fc_mode_e::PAUSE);
    case SAI_PORT_FLOW_CONTROL_MODE_TX_ONLY:
        return std::make_pair(la_mac_port::fc_mode_e::PAUSE, la_mac_port::fc_mode_e::NONE);
    case SAI_PORT_FLOW_CONTROL_MODE_RX_ONLY:
        return std::make_pair(la_mac_port::fc_mode_e::NONE, la_mac_port::fc_mode_e::PAUSE);
    default:
        return std::make_pair(la_mac_port::fc_mode_e::NONE, la_mac_port::fc_mode_e::NONE);
    }
}

static lsai_serdes_media_type_e
sai_to_lsai_media_type(sai_port_media_type_t sai_media_type)
{
    switch (sai_media_type) {
    case SAI_PORT_MEDIA_TYPE_COPPER:
        return lsai_serdes_media_type_e::COPPER; // cable wire or front panel port
    case SAI_PORT_MEDIA_TYPE_FIBER:
        return lsai_serdes_media_type_e::OPTIC; // optic/fiber module connection
    case SAI_PORT_MEDIA_TYPE_UNKNOWN:
        return lsai_serdes_media_type_e::CHIP2CHIP; // if some unknow value is set to media type... (temporary)
    case SAI_PORT_MEDIA_TYPE_NOT_PRESENT:
        return lsai_serdes_media_type_e::NOT_PRESENT; // SDK default parameters
    default:
        return lsai_serdes_media_type_e::CHIP2CHIP;
    }
}

static la_mac_port::serdes_ctrl_e
to_serdes_ctrl(uint32_t preemp_value)
{
    // check serdes lane's pre-emphasis value is set to 0, control will be enable squelch.
    if (preemp_value == PORT_SERDES_ENABLE_SQUELCH_PREEM_VAL) {
        return la_mac_port::serdes_ctrl_e::ENABLE_SQUELCH;
    }
    return la_mac_port::serdes_ctrl_e::DISABLE_SQUELCH;
}

static std::string
to_serdes_prop_defines_key(int64_t port_serdes_attr_id)
{
    switch (port_serdes_attr_id) {
    case SAI_PORT_SERDES_ATTR_EXT_CTLE_TUNE:
        return "CTLE_TUNE";
        break;
    case SAI_PORT_SERDES_ATTR_EXT_TX_LUT_MODE:
        return "TX_LUT_MODE";
        break;
    case SAI_PORT_SERDES_ATTR_TX_FIR_PRE1:
    case SAI_PORT_SERDES_ATTR_EXT_TX_PRE1:
        return "TX_PRE1";
        break;
    case SAI_PORT_SERDES_ATTR_TX_FIR_PRE2:
    case SAI_PORT_SERDES_ATTR_EXT_TX_PRE2:
        return "TX_PRE2";
        break;
    case SAI_PORT_SERDES_ATTR_TX_FIR_PRE3:
    case SAI_PORT_SERDES_ATTR_EXT_TX_PRE3:
        return "TX_PRE3";
        break;
    case SAI_PORT_SERDES_ATTR_TX_FIR_MAIN:
    case SAI_PORT_SERDES_ATTR_EXT_TX_MAIN:
        return "TX_MAIN";
        break;
    case SAI_PORT_SERDES_ATTR_TX_FIR_POST1:
    case SAI_PORT_SERDES_ATTR_EXT_TX_POST:
        return "TX_POST";
        break;
    case SAI_PORT_SERDES_ATTR_TX_FIR_POST2:
    case SAI_PORT_SERDES_ATTR_EXT_TX_POST2:
        return "TX_POST2";
        break;
    case SAI_PORT_SERDES_ATTR_TX_FIR_POST3:
    case SAI_PORT_SERDES_ATTR_EXT_TX_POST3:
        return "TX_POST3";
        break;
    case SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE1:
        return "TX_INNER_EYE1";
        break;
    case SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE2:
        return "TX_INNER_EYE2";
        break;
    case SAI_PORT_SERDES_ATTR_EXT_RX_CTLE_CODE:
        return "RX_CTLE_CODE";
        break;
    case SAI_PORT_SERDES_ATTR_EXT_RX_DSP_MODE:
        return "RX_DSP_MODE";
        break;
    case SAI_PORT_SERDES_ATTR_EXT_RX_AFE_TRIM:
        return "RX_AFE_TRIM";
        break;
    case SAI_PORT_SERDES_ATTR_EXT_RX_VGA_TRACKING:
        return "RX_VGA_TRACKING";
        break;
    case SAI_PORT_SERDES_ATTR_EXT_RX_AC_COUPLING_BYPASS:
        return "RX_AC_COUPLING_BYPASS";
        break;
    default:
        return "UNKNOWN";
    }
}

sai_status_t
to_phy_lanes(port_phy_loc& phy_loc, const sai_u32_list_t& lane, std::shared_ptr<lsai_device> sdev)
{
    // lane definition: 16bit values: [31:8]-ifg index, [7:0]-serdes lane.
    // Note: ifg index = slice id * 2 + ifg id;
    if (lane.count <= 0 || lane.list == nullptr) {
        sai_log_error(SAI_API_PORT, "Bad lane setting: lane.count is 0 or lane.list is null.");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    uint32_t pif_id = lane.list[0] & HW_LANE_PIF_MASK;
    uint32_t ifg_idx = lane.list[0] >> 8;
    uint32_t slice_id = ifg_idx / IFGS_PER_SLICE;
    uint32_t ifg_id = ifg_idx % IFGS_PER_SLICE;
    uint32_t num_of_serdes_per_ifg = sdev->m_dev_params.serdes_per_ifg[ifg_idx];

    // mac_pool specific check
    // can't group serdes from different ifg/pool.
    // only can group with 1, 2, 4, 8 serdes, and has to be contiguous.
    if (lane.count != 8 && lane.count != 4 && lane.count != 2 && lane.count != 1) {
        sai_log_error(SAI_API_PORT, "Bad lane count %d", lane.count);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    for (uint32_t i = 0; i < lane.count; i++) {
        if ((lane.list[i] - lane.list[0]) != i) // contiguous in same IFG check
        {
            sai_log_error(SAI_API_PORT, "Bad lane setting: Not contiguous; lane[%d]", lane.list[i]);
            return SAI_STATUS_INVALID_PARAMETER;
        }
        if ((lane.list[i] & HW_LANE_PIF_MASK) >= num_of_serdes_per_ifg) {
            sai_log_error(SAI_API_PORT, "Bad lane setting: Exceeded serdes per IFG, lane(%d)", lane.list[i]);
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }
    // TODO: current mac_pool size is 8 and we can't use lane across mac_pool to create a port.
    //       If this is changed, we need to update this check.
    if (lane.list[0] / 8 != lane.list[lane.count - 1] / 8) // same mac_pool check.
    {
        sai_log_error(SAI_API_PORT,
                      "Bad lane setting: Not in same MAC Pool; lane[%d]:pool(%d), lane[%d]:pool(%d)",
                      lane.list[0],
                      lane.list[0] / 8,
                      lane.list[lane.count - 1],
                      lane.list[lane.count - 1] / 8);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    phy_loc.slice = slice_id;
    phy_loc.ifg = ifg_id;
    phy_loc.pif = pif_id;
    phy_loc.pif_last = pif_id + lane.count - 1;
    phy_loc.num_of_serdes = lane.count;

    return SAI_STATUS_SUCCESS;
}

uint32_t
to_sai_lanes(const port_phy_loc& phy_loc)
{
    // lane definition: 16bit values: [31:8]-ifg index, [7:0]-serdes lane.
    uint32_t ifg_idx = phy_loc.slice * IFGS_PER_SLICE + phy_loc.ifg;
    return ((ifg_idx << 8) + phy_loc.pif);
}

sai_status_t
get_port_phy_loc(sai_object_id_t eth_port_obj, port_phy_loc& phy_loc)
{
    la_mac_port* mac_port = get_mac_port_by_eth_obj(eth_port_obj);
    if (mac_port == nullptr) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    phy_loc.slice = mac_port->get_slice();
    phy_loc.ifg = mac_port->get_ifg();
    phy_loc.pif = mac_port->get_first_serdes_id();
    phy_loc.num_of_serdes = mac_port->get_num_of_serdes();
    phy_loc.pif_last = phy_loc.pif + phy_loc.num_of_serdes - 1;

    return SAI_STATUS_SUCCESS;
}

static la_status
stop_mac_port(la_mac_port* mac_port, const port_entry& pentry)
{
    la_status status = mac_port->stop();
    la_return_on_error(status, "Failed to stop mac_port. sai_object_id(0x%lx)", pentry.service.oid);
    return LA_STATUS_SUCCESS;
}

static la_status
activate_mac_port(la_mac_port* mac_port, const port_entry& pentry)
{
    transaction txn{};

    txn.status = mac_port->activate();
    la_return_on_error(txn.status);
    txn.on_fail([=]() { mac_port->stop(); });

    // admin_state is changed from false to true, re-apply preemphasis setting.
    la_mac_port::serdes_ctrl_e new_control, cur_control;
    uint32_t num_of_serdes = mac_port->get_num_of_serdes();

    // Re-apply the preemphasis setting
    for (la_uint_t idx = 0; idx < num_of_serdes; idx++) {
        cur_control = la_mac_port::serdes_ctrl_e::DISABLE_SQUELCH; // Always disable when serdes re-init.
        new_control = to_serdes_ctrl(pentry.serdes_entry_vec[idx].preemphasis);

        if (new_control != cur_control) {
            txn.status = mac_port->set_serdes_signal_control(idx, la_serdes_direction_e::TX, new_control);
            la_return_on_error(txn.status,
                               "Fail to set serdes signal control. sai_object_id(0x%lx) %s",
                               pentry.service.oid,
                               txn.status.message().c_str());
            txn.on_fail([=]() { mac_port->set_serdes_signal_control(idx, la_serdes_direction_e::TX, cur_control); });
            sai_log_debug(
                SAI_API_PORT, "Port(0x%lx) serdes(%d) signal control set to %d", pentry.service.oid, idx, int(new_control));
        }
    }

    return LA_STATUS_SUCCESS;
}

static la_status
sys_port_to_mac_port(const la_system_port* sys_port, la_mac_port*& mac_port)
{
    // return if underlying port is not a mac_port
    if (sys_port->get_underlying_port()->type() != la_object::object_type_e::MAC_PORT) {
        return LA_STATUS_ENOTFOUND;
    }

    la_status status
        = sys_port->get_device()->get_mac_port(sys_port->get_slice(), sys_port->get_ifg(), sys_port->get_base_serdes(), mac_port);
    la_return_on_error(status, "Failed getting mac_port from system port location, %s", status.message().c_str());

    return LA_STATUS_SUCCESS;
}

static la_status
port_entry_to_mac_port(const port_entry& pentry, la_mac_port*& mac_port)
{
    shared_ptr<lsai_device> sdev;
    lsai_object port_obj(pentry.service.oid);
    sai_get_device(port_obj.switch_id, sdev);

    la_status status = sdev->m_dev->get_mac_port(pentry.slice_id, pentry.ifg_id, pentry.pif, mac_port);
    la_return_on_error(status, "Failed getting mac_port from port location, %s", status.message().c_str());
    return LA_STATUS_SUCCESS;
}

sai_status_t
lsai_set_mac_port_mtu(const la_system_port* sys_port, la_uint_t mtu_value)
{

    la_mac_port* mac_port = nullptr;
    la_status status = sys_port_to_mac_port(sys_port, mac_port);
    sai_return_on_la_error(status, "Failed getting mac_port, %s", status.message().c_str());

    // Set mac_port MTU value
    status = mac_port->set_max_packet_size(mtu_value);
    sai_return_on_la_error(status, "Failed to set MTU(%d) on mac_port, %s.", mtu_value, status.message().c_str());

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_qos_number_of_queues_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg)
{
    set_attr_value(SAI_PORT_ATTR_QOS_NUMBER_OF_QUEUES, *value, NUM_QUEUE_PER_PORT);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_acl_get(_In_ const sai_object_key_t* key,
             _Inout_ sai_attribute_value_t* value,
             _In_ uint32_t attr_index,
             _Inout_ vendor_cache_t* cache,
             void* arg)
{
    la_status status;
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();

    port_entry pentry;
    status = sdev->m_ports.get(la_port.index, pentry);
    sai_return_on_la_error(status);

    switch ((int64_t)arg) {
    case SAI_PORT_ATTR_INGRESS_ACL:
        set_attr_value(SAI_PORT_ATTR_INGRESS_ACL, *value, pentry.service.ingress_acl);
        return SAI_STATUS_SUCCESS;
    case SAI_PORT_ATTR_EGRESS_ACL:
        set_attr_value(SAI_PORT_ATTR_EGRESS_ACL, *value, pentry.service.egress_acl);
        return SAI_STATUS_SUCCESS;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_acl_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    la_status status;
    sai_status_t sstatus;
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();

    port_entry* pentry;
    pentry = sdev->m_ports.get_ptr(la_port.index);
    if (pentry == nullptr) {
        sai_log_error(SAI_API_PORT, "Unknown port oid 0x%llx", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    sai_acl_stage_t stage;
    sai_object_id_t acl_obj_id;
    switch ((int64_t)arg) {
    case SAI_PORT_ATTR_INGRESS_ACL:
        stage = SAI_ACL_STAGE_INGRESS;
        acl_obj_id = get_attr_value(SAI_PORT_ATTR_INGRESS_ACL, *value);
        break;
    case SAI_PORT_ATTR_EGRESS_ACL:
        stage = SAI_ACL_STAGE_EGRESS;
        acl_obj_id = get_attr_value(SAI_PORT_ATTR_EGRESS_ACL, *value);
        break;
    default:
        return SAI_STATUS_FAILURE;
    }

    auto switch_acl = (stage == SAI_ACL_STAGE_INGRESS) ? sdev->switch_ingress_acl_oid : sdev->switch_egress_acl_oid;
    if (switch_acl != SAI_NULL_OBJECT_ID) {
        sai_log_error(SAI_API_PORT, "ACL configured at switch level. A new ACL cannot be attach to port");
        return SAI_STATUS_FAILURE;
    }

    sstatus = sdev->m_acl_handler->attach_acl_on_port(acl_obj_id, stage, pentry, SAI_ACL_BIND_POINT_TYPE_PORT);
    sai_return_on_error(sstatus);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_default_vlan_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();

    port_entry* pentry = sdev->m_ports.get_ptr(la_port.index);
    if (pentry != nullptr) {
        pentry->service.port_vlan_id = get_attr_value(SAI_PORT_ATTR_PORT_VLAN_ID, *value);

        la_ethernet_port* eth_port = nullptr;
        la_status status = sai_port_get_ethernet_port(sdev, key->key.object_id, eth_port);
        sai_return_on_la_error(status);

        status = eth_port->set_port_vid(pentry->service.port_vlan_id);
        sai_return_on_la_error(status);

        auto default_vid = sdev->m_vlans.get_id(sdev->m_default_vlan_id);
        if (pentry->service.port_vlan_id == default_vid) {
            // default vlan id 1
            eth_port->set_ac_profile(sdev->m_default_ac_profile);
        } else {
            // allow user defined untagged vlan id
            eth_port->set_ac_profile(sdev->m_pvlan_ac_profile);
        }

        auto sstatus = sdev->m_hostif_handler->update_knet_port_vlan_id(pentry);
        sai_return_on_error(sstatus);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_default_vlan_get(_In_ const sai_object_key_t* key,
                      _Inout_ sai_attribute_value_t* value,
                      _In_ uint32_t attr_index,
                      _Inout_ vendor_cache_t* cache,
                      void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();
    sai_check_object(la_port, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);

    port_entry* pentry = sdev->m_ports.get_ptr(la_port.index);
    if (pentry != nullptr) {
        set_attr_value(SAI_PORT_ATTR_PORT_VLAN_ID, *value, pentry->service.port_vlan_id);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_qos_queue_list_get(_In_ const sai_object_key_t* key,
                        _Inout_ sai_attribute_value_t* value,
                        _In_ uint32_t attr_index,
                        _Inout_ vendor_cache_t* cache,
                        void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();
    sai_check_object(la_port, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);

    port_entry pentry{};
    la_status status = sdev->m_ports.get(la_port.index, pentry);
    sai_return_on_la_error(status);

    lsai_object la_queue(SAI_OBJECT_TYPE_QUEUE, la_port.switch_id, 0);
    la_queue.detail.set(lsai_detail_type_e::QUEUE, lsai_detail_field_e::PORT, la_port.index);
    std::vector<sai_object_id_t> output_vec;

    for (uint32_t i = 0; i < NUM_QUEUE_PER_PORT; i++) {
        la_queue.index = i;
        output_vec.push_back(la_queue.object_id());
    }
    return fill_sai_list(output_vec.begin(), output_vec.end(), value->objlist);
}

sai_status_t
port_hw_lanes_get(_In_ const sai_object_key_t* key,
                  _Inout_ sai_attribute_value_t* value,
                  _In_ uint32_t attr_index,
                  _Inout_ vendor_cache_t* cache,
                  void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    la_mac_port* mac_port = nullptr;
    sai_status_t sai_status = get_mac_port_by_eth_obj(key->key.object_id, sdev, port_idx, pentry, mac_port);
    if (sai_status != SAI_STATUS_SUCCESS || mac_port == nullptr) {
        value->u32list.count = 0;
        return SAI_STATUS_SUCCESS;
    }

    port_phy_loc phy_loc;
    phy_loc.slice = mac_port->get_slice();
    phy_loc.ifg = mac_port->get_ifg();
    phy_loc.pif = mac_port->get_first_serdes_id();
    phy_loc.num_of_serdes = mac_port->get_num_of_serdes();
    uint32_t sai_lane = to_sai_lanes(phy_loc);
    std::vector<uint32_t> sai_lane_vec;

    for (uint32_t i = 0; i < phy_loc.num_of_serdes; i++) {
        sai_lane_vec.push_back(sai_lane + i);
    }
    return fill_sai_list(sai_lane_vec.begin(), sai_lane_vec.end(), value->u32list);
}

la_status
port_speed_get(std::shared_ptr<lsai_device> sdev, sai_object_id_t port_obj_id, uint32_t& speed, la_mac_port*& mac_port)
{
    if (port_obj_id == sdev->m_pci_port_ids[lsai_device::PUNT_SLICE]) {
        speed = PUNT_PORT_SPEED;
        return LA_STATUS_SUCCESS;
    }

    if (port_obj_id == sdev->m_pci_port_ids[lsai_device::INJECTUP_SLICE]) {
        speed = INJECT_PORT_SPEED;
        return LA_STATUS_SUCCESS;
    }

    mac_port = get_mac_port_by_eth_obj(port_obj_id);
    if (mac_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_mac_port::port_speed_e la_speed;
    la_status status = mac_port->get_speed(la_speed);
    la_return_on_error(status);

    speed = sdk_to_sai_speed(la_speed); // in Mbps

    return LA_STATUS_SUCCESS;
}

la_status
port_speed_get(std::shared_ptr<lsai_device> sdev, sai_object_id_t port_obj_id, uint32_t& speed)
{
    la_mac_port* mac_port = nullptr;
    return port_speed_get(sdev, port_obj_id, speed, mac_port);
}

sai_status_t
port_speed_get(_In_ const sai_object_key_t* key,
               _Inout_ sai_attribute_value_t* value,
               _In_ uint32_t attr_index,
               _Inout_ vendor_cache_t* cache,
               void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    sai_check_object(la_port, SAI_OBJECT_TYPE_PORT, la_port.get_device(), "port", key->key.object_id);

    uint32_t speed;
    la_status status = port_speed_get(la_port.get_device(), key->key.object_id, speed); // in Mbps
    sai_return_on_la_error(status);

    switch ((int64_t)arg) {
    case SAI_PORT_ATTR_SPEED:
        set_attr_value(SAI_PORT_ATTR_SPEED, *value, speed);
        break;
    case SAI_PORT_ATTR_ADVERTISED_SPEED: {
        std::vector<uint32_t> speed_vec{speed};
        return fill_sai_list(speed_vec.begin(), speed_vec.end(), value->u32list);
        break;
    }
    default:
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_oper_status_get(_In_ const sai_object_key_t* key,
                     _Inout_ sai_attribute_value_t* value,
                     _In_ uint32_t attr_index,
                     _Inout_ vendor_cache_t* cache,
                     void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_mac_port* mac_port = get_mac_port_by_eth_obj(key->key.object_id);
    if (mac_port == nullptr) {
        set_attr_value(SAI_PORT_ATTR_OPER_STATUS, (*value), SAI_PORT_OPER_STATUS_UP);
        return SAI_STATUS_SUCCESS;
    }

    la_mac_port::state_e link_state;
    la_status status = mac_port->get_state(link_state);
    sai_return_on_la_error(status);

    sai_log_debug(SAI_API_PORT,
                  "Port sai_port_obj_id:(0x%lx) la_mac_port oid:(%d) state:(%s)\n",
                  key->key.object_id,
                  mac_port->oid(),
                  to_string(link_state).c_str());

    switch (link_state) {
    case la_mac_port::state_e::LINK_UP:
        set_attr_value(SAI_PORT_ATTR_OPER_STATUS, (*value), SAI_PORT_OPER_STATUS_UP);
        break;
    default:
        set_attr_value(SAI_PORT_ATTR_OPER_STATUS, (*value), SAI_PORT_OPER_STATUS_DOWN);
        break;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_state_get(_In_ const sai_object_key_t* key,
               _Inout_ sai_attribute_value_t* value,
               _In_ uint32_t attr_index,
               _Inout_ vendor_cache_t* cache,
               void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    sai_status_t sai_status = get_port_entry_by_eth_obj(key->key.object_id, sdev, port_idx, pentry);
    sai_return_on_error(sai_status);

    set_attr_value(SAI_PORT_ATTR_ADMIN_STATE, (*value), pentry.admin_state);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_media_get(_In_ const sai_object_key_t* key,
               _Inout_ sai_attribute_value_t* value,
               _In_ uint32_t attr_index,
               _Inout_ vendor_cache_t* cache,
               void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    sai_status_t sai_status = get_port_entry_by_eth_obj(key->key.object_id, sdev, port_idx, pentry);
    sai_return_on_error(sai_status);

    set_attr_value(SAI_PORT_ATTR_MEDIA_TYPE, (*value), pentry.media_type);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_lpbk_get(_In_ const sai_object_key_t* key,
              _Inout_ sai_attribute_value_t* value,
              _In_ uint32_t attr_index,
              _Inout_ vendor_cache_t* cache,
              void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_mac_port* mac_port = get_mac_port_by_eth_obj(key->key.object_id);
    if (mac_port == nullptr) {
        set_attr_value(SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE, *value, SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE);
        return SAI_STATUS_SUCCESS;
    }

    la_mac_port::loopback_mode_e la_loopback_mode;
    la_status status = mac_port->get_loopback_mode(la_loopback_mode);
    sai_return_on_la_error(status);

    sai_port_internal_loopback_mode_t sai_lpbk_mode = sdk_to_sai_lpbk_mode(la_loopback_mode);

    set_attr_value(SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE, *value, sai_lpbk_mode);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_fec_get(_In_ const sai_object_key_t* key,
             _Inout_ sai_attribute_value_t* value,
             _In_ uint32_t attr_index,
             _Inout_ vendor_cache_t* cache,
             void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_mac_port* mac_port = get_mac_port_by_eth_obj(key->key.object_id);

    sai_port_fec_mode_t sai_fec_mode;
    if (mac_port == nullptr) {
        sai_fec_mode = SAI_PORT_FEC_MODE_NONE;
    } else {
        la_mac_port::fec_mode_e la_fec_mode;
        la_status status = mac_port->get_fec_mode(la_fec_mode);
        sai_return_on_la_error(status);
        sai_fec_mode = sdk_to_sai_fec_mode(la_fec_mode);
    }

    switch ((int64_t)arg) {
    case SAI_PORT_ATTR_FEC_MODE:
        set_attr_value(SAI_PORT_ATTR_FEC_MODE, *value, sai_fec_mode);
        break;
    case SAI_PORT_ATTR_ADVERTISED_FEC_MODE: {
        std::vector<sai_port_fec_mode_t> fec_vec{sai_fec_mode};
        return fill_sai_list(fec_vec.begin(), fec_vec.end(), value->u32list);
        break;
    }
    default:
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_autoneg_get(_In_ const sai_object_key_t* key,
                 _Inout_ sai_attribute_value_t* value,
                 _In_ uint32_t attr_index,
                 _Inout_ vendor_cache_t* cache,
                 void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_mac_port* mac_port = get_mac_port_by_eth_obj(key->key.object_id);
    if (mac_port == nullptr) {
        set_attr_value(SAI_PORT_ATTR_AUTO_NEG_MODE, *value, false);
        return SAI_STATUS_SUCCESS;
    }

    bool an_enable = false;
    la_status status = mac_port->get_an_enabled(an_enable);
    sai_return_on_la_error(status);

    set_attr_value(SAI_PORT_ATTR_AUTO_NEG_MODE, *value, an_enable);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_mtu_get(_In_ const sai_object_key_t* key,
             _Inout_ sai_attribute_value_t* value,
             _In_ uint32_t attr_index,
             _Inout_ vendor_cache_t* cache,
             void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object port_obj(key->key.object_id);
    auto sdev = port_obj.get_device();
    sai_check_object(port_obj, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);
    port_entry* pentry = sdev->m_ports.get_ptr(port_obj.index);
    if (pentry == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    set_attr_value(SAI_PORT_ATTR_MTU, *value, pentry->service.mtu);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_fc_get(_In_ const sai_object_key_t* key,
            _Inout_ sai_attribute_value_t* value,
            _In_ uint32_t attr_index,
            _Inout_ vendor_cache_t* cache,
            void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_mac_port* mac_port = get_mac_port_by_eth_obj(key->key.object_id);
    if (mac_port == nullptr) {
        set_attr_value(SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE, *value, SAI_PORT_FLOW_CONTROL_MODE_DISABLE);
        return SAI_STATUS_SUCCESS;
    }

    la_mac_port::fc_mode_e tx_fc, rx_fc;
    la_status status = mac_port->get_fc_mode(la_mac_port::fc_direction_e::RX, rx_fc);
    sai_return_on_la_error(status);
    status = mac_port->get_fc_mode(la_mac_port::fc_direction_e::TX, tx_fc);
    sai_return_on_la_error(status);

    sai_port_flow_control_mode_t fc_mode = sdk_to_sai_fc_mode(tx_fc, rx_fc);

    set_attr_value(SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE, *value, fc_mode);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_pfc_mode_get(_In_ const sai_object_key_t* key,
                  _Inout_ sai_attribute_value_t* value,
                  _In_ uint32_t attr_index,
                  _Inout_ vendor_cache_t* cache,
                  void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // need la_mac_port
    la_mac_port* mac_port = get_mac_port_by_eth_obj(key->key.object_id);
    if (mac_port == nullptr) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    // leaba only support combined mode
    set_attr_value(SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE, *value, SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_COMBINED);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_pfc_get(_In_ const sai_object_key_t* key,
             _Inout_ sai_attribute_value_t* value,
             _In_ uint32_t attr_index,
             _Inout_ vendor_cache_t* cache,
             void* arg)
{
    la_status status;
    bool pfc_enabled;
    la_uint8_t pfc_set;

    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_mac_port* mac_port = get_mac_port_by_eth_obj(key->key.object_id);
    if (mac_port == nullptr) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    // get current PFC status
    status = mac_port->get_pfc_enabled(pfc_enabled, pfc_set);
    sai_return_on_la_error(status);

    // return bitmap
    set_attr_value(SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, *value, pfc_set);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_serdes_port_id_get(_In_ const sai_object_key_t* key,
                        _Inout_ sai_attribute_value_t* value,
                        _In_ uint32_t attr_index,
                        _Inout_ vendor_cache_t* cache,
                        void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    sai_status_t sai_status = get_port_entry_by_srds_obj_id(key->key.object_id, sdev, port_idx, pentry);
    sai_return_on_error(sai_status);

    set_attr_value(SAI_PORT_SERDES_ATTR_PORT_ID, *value, pentry.service.oid);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
serdes_preem_get(_In_ const sai_object_key_t* key,
                 _Inout_ sai_attribute_value_t* value,
                 _In_ uint32_t attr_index,
                 _Inout_ vendor_cache_t* cache,
                 void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    sai_status_t sai_status;
    if (la_port.type == sai_object_type_t::SAI_OBJECT_TYPE_PORT_SERDES) {
        sai_status = get_port_entry_by_srds_obj_id(la_port.object_id(), sdev, port_idx, pentry);
    } else {
        sai_status = get_port_entry_by_eth_obj(la_port.object_id(), sdev, port_idx, pentry);
    }
    sai_return_on_error(sai_status);

    // Return pre-emphasis values to all lanes.
    return fill_sai_list(pentry.serdes_entry_vec.begin(), pentry.serdes_entry_vec.end(), value->u32list, [](serdes_entry x) {
        return x.preemphasis;
    });
}

sai_status_t
serdes_param_get(_In_ const sai_object_key_t* key,
                 _Inout_ sai_attribute_value_t* value,
                 _In_ uint32_t attr_index,
                 _Inout_ vendor_cache_t* cache,
                 void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    la_mac_port* mac_port = nullptr;
    sai_status_t sai_status = get_mac_port_by_srds_obj_id(key->key.object_id, sdev, port_idx, pentry, mac_port);
    sai_return_on_error(sai_status);

    // First, get la_mac_port::serdes_param_e from SAI serdes_prop definitions.
    string param_key = to_serdes_prop_defines_key((int64_t)arg);
    auto found_iter = serdes_prop_defines.find(param_key);
    if (found_iter == serdes_prop_defines.end()) {
        // Not found
        sai_log_error(
            SAI_API_PORT, "Error: SerDes parameter (\"%s\"), attr_id(%d) is not supported.", param_key.c_str(), (int64_t)arg);
        return SAI_STATUS_NOT_SUPPORTED;
    }

    // read the parameter from mac_port
    la_mac_port::serdes_param_mode_e param_mode;
    int32_t param_value;
    std::vector<int32_t> param_value_vec;
    la_status status;

    for (uint32_t serdes_idx = 0; serdes_idx < mac_port->get_num_of_serdes(); serdes_idx++) {
        status = mac_port->get_serdes_parameter(
            serdes_idx, found_iter->second[0].stage, found_iter->second[0].parameter, param_mode, param_value);
        sai_return_on_la_error(
            status, "Failed to get serdes parameter (%s), %s", to_string(found_iter->second[0]).c_str(), status.message().c_str());
        param_value_vec.push_back(param_value);
    }

    // Return pre-emphasis values to all lanes.
    return fill_sai_list(param_value_vec.begin(), param_value_vec.end(), value->s32list);
}

sai_status_t
port_type_get(_In_ const sai_object_key_t* key,
              _Inout_ sai_attribute_value_t* value,
              _In_ uint32_t attr_index,
              _Inout_ vendor_cache_t* cache,
              void* arg)
{
    lsai_object la_obj(key->key.object_id);
    auto sdev = la_obj.get_device();
    sai_check_object(la_obj, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);

    port_entry pentry{};
    sdev->m_ports.get(la_obj.index, pentry);

    if (pentry.is_mac()) {
        set_attr_value(SAI_PORT_ATTR_TYPE, *value, SAI_PORT_TYPE_LOGICAL);
    } else {
        set_attr_value(SAI_PORT_ATTR_TYPE, *value, SAI_PORT_TYPE_CPU);
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_supported_speed_get(_In_ const sai_object_key_t* key,
                         _Inout_ sai_attribute_value_t* value,
                         _In_ uint32_t attr_index,
                         _Inout_ vendor_cache_t* cache,
                         void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    sai_check_object(la_port, SAI_OBJECT_TYPE_PORT, la_port.get_device(), "port", key->key.object_id);

    la_mac_port* mac_port = nullptr;

    uint32_t speed;
    la_status status = port_speed_get(la_port.get_device(), key->key.object_id, speed, mac_port);
    sai_return_on_la_error(status);

    if (mac_port == nullptr) {
        // when mac_port is null and no status error, this is punt port.
        // Just return the speed as single item array.
        std::vector<uint32_t> speed_vec{speed};

        return fill_sai_list(speed_vec.begin(), speed_vec.end(), value->u32list);
    }

    // get valid configurations
    la_mac_port::mac_config_vec valid_config_list;
    status = la_port.get_device()->m_dev->get_valid_mac_port_configs(valid_config_list);
    sai_return_on_la_error(status);

    // get serdes lanes
    uint32_t num_of_serdes = mac_port->get_num_of_serdes();

    // Use map to get a list of supported speed (no-duplication) with num_of_serdes constraint
    std::map<uint32_t, bool> supported_speed_map;
    for (auto config : valid_config_list) {
        if (config.serdes_count == num_of_serdes) {
            supported_speed_map[sdk_to_sai_speed(config.port_speed)] = true;
        }
    }

    return fill_sai_list(supported_speed_map.begin(), supported_speed_map.end(), value->u32list, [](std::pair<uint32_t, bool> x) {
        return x.first;
    });
}

sai_status_t
port_supported_fec_get(_In_ const sai_object_key_t* key,
                       _Inout_ sai_attribute_value_t* value,
                       _In_ uint32_t attr_index,
                       _Inout_ vendor_cache_t* cache,
                       void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    la_mac_port* mac_port = nullptr;
    sai_status_t sai_status = get_mac_port_by_eth_obj(key->key.object_id, sdev, port_idx, pentry, mac_port);
    sai_return_on_error(sai_status);

    // check the current port speed and num_of_serdes to get supported FEC mode.
    la_mac_port::port_speed_e la_speed;
    la_status status = mac_port->get_speed(la_speed);
    sai_return_on_la_error(status);
    uint32_t num_of_serdes = mac_port->get_num_of_serdes();
    la_mac_port::mac_config_vec valid_config_list;
    status = sdev->m_dev->get_valid_mac_port_configs(valid_config_list);
    sai_return_on_la_error(status);

    // Use map to get a list of supported FEC (no-duplication) with num_of_serdes constraint
    std::map<sai_port_fec_mode_t, bool> supported_fec_map;
    for (auto config : valid_config_list) {
        if ((config.serdes_count == num_of_serdes) && (config.port_speed == la_speed)) {
            // supported fec are based only current serdes lanes and port speed used.
            supported_fec_map[sdk_to_sai_fec_mode(config.fec_mode)] = true;
        }
    }

    return fill_sai_list(
        supported_fec_map.begin(), supported_fec_map.end(), value->s32list, [](std::pair<uint32_t, bool> x) { return x.first; });
}

sai_status_t
port_supported_half_duplex_speed_get(_In_ const sai_object_key_t* key,
                                     _Inout_ sai_attribute_value_t* value,
                                     _In_ uint32_t attr_index,
                                     _Inout_ vendor_cache_t* cache,
                                     void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // Always full duplex.
    value->u32list.count = 0;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_supported_an_get(_In_ const sai_object_key_t* key,
                      _Inout_ sai_attribute_value_t* value,
                      _In_ uint32_t attr_index,
                      _Inout_ vendor_cache_t* cache,
                      void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_mac_port* mac_port = get_mac_port_by_eth_obj(key->key.object_id);
    if (mac_port == nullptr) {
        set_attr_value(SAI_PORT_ATTR_SUPPORTED_AUTO_NEG_MODE, *value, false);
    } else {
        set_attr_value(SAI_PORT_ATTR_SUPPORTED_AUTO_NEG_MODE, *value, mac_port->is_an_capable());
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_supported_fc_get(_In_ const sai_object_key_t* key,
                      _Inout_ sai_attribute_value_t* value,
                      _In_ uint32_t attr_index,
                      _Inout_ vendor_cache_t* cache,
                      void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    set_attr_value(SAI_PORT_ATTR_SUPPORTED_FLOW_CONTROL_MODE, *value, SAI_PORT_FLOW_CONTROL_MODE_BOTH_ENABLE);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_supported_asym_pause_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    set_attr_value(SAI_PORT_ATTR_SUPPORTED_ASYMMETRIC_PAUSE_MODE, *value, true);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_supported_media_type_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // return current setting for now.
    return port_media_get(key, value, attr_index, cache, arg);
}

sai_status_t
port_number_of_scheduler_groups_get(_In_ const sai_object_key_t* key,
                                    _Inout_ sai_attribute_value_t* value,
                                    _In_ uint32_t attr_index,
                                    _Inout_ vendor_cache_t* cache,
                                    void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // return all scheduler groups. 1 root and 8 level 1 scheduler groups
    set_attr_value(SAI_PORT_ATTR_QOS_NUMBER_OF_SCHEDULER_GROUPS, *value, 9);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_qos_scheduler_group_list_get(_In_ const sai_object_key_t* key,
                                  _Inout_ sai_attribute_value_t* value,
                                  _In_ uint32_t attr_index,
                                  _Inout_ vendor_cache_t* cache,
                                  void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();
    sai_check_object(la_port, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);

    port_entry* pentry = sdev->m_ports.get_ptr(la_port.index);
    if (pentry == nullptr) {
        sai_log_error(SAI_API_PORT, "pentry does not exist on the port index 0x%lx", la_port.index);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    std::vector<sai_object_id_t> output_vec;

    for (uint32_t i = 0; i < NUM_QUEUE_PER_PORT + 1; i++) {
        output_vec.push_back(pentry->m_sched_group_oids[i]);
    }

    return fill_sai_list(output_vec.begin(), output_vec.end(), value->objlist);
}

sai_status_t
port_ingress_number_of_priority_groups_get(_In_ const sai_object_key_t* key,
                                           _Inout_ sai_attribute_value_t* value,
                                           _In_ uint32_t attr_index,
                                           _Inout_ vendor_cache_t* cache,
                                           void* arg)
{
    set_attr_value(SAI_PORT_ATTR_NUMBER_OF_INGRESS_PRIORITY_GROUPS, *value, 8);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_priority_group_list_get(_In_ const sai_object_key_t* key,
                             _Inout_ sai_attribute_value_t* value,
                             _In_ uint32_t attr_index,
                             _Inout_ vendor_cache_t* cache,
                             void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();

    if (value->objlist.count < 8) {
        return SAI_STATUS_BUFFER_OVERFLOW;
    }
    for (size_t i = 0; i < 8; ++i) {
        // Make IDs unique across all ports.
        lsai_object la_ppg(SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP, sdev->m_switch_id, i + (la_port.index * 8));
        value->objlist.list[i] = la_ppg.object_id();
    }
    // API invoker can  pass object list buffer with more than 8 elements. Set the size.
    value->objlist.count = 8;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_dot1p_tc_map_get(_In_ const sai_object_key_t* key,
                      _Inout_ sai_attribute_value_t* value,
                      _In_ uint32_t attr_index,
                      _Inout_ vendor_cache_t* cache,
                      void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();
    sai_check_object(la_port, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);
    // TODO remove this check once port level QOS has completed full devtest cycle.
    if (sdev->m_push_port_qos_to_switch) {
        sai_object_key_t switch_key;
        switch_key.key.object_id = sdev->m_switch_id;
        sai_status_t sai_status
            = lasai_qos::switch_attr_qos_map_get(&switch_key, value, attr_index, cache, (void*)SAI_SWITCH_ATTR_QOS_DOT1P_TO_TC_MAP);
        sai_return_on_error(sai_status, "%s: Fail to get qos map switch");
    } else {
        la_status status;
        port_entry pentry{};
        sai_object_id_t ret_obj_id;
        status = sdev->m_ports.get(la_port.index, pentry);
        sai_return_on_la_error(status, "%s: Fail to get pentry port_index(%d)", la_port.index);
        if (pentry.ingress_qos_profile == nullptr) {
            ret_obj_id = SAI_NULL_OBJECT_ID;
        } else {
            ret_obj_id = lasai_qos::get_qos_map(
                sdev, pentry.ingress_qos_profile, SAI_QOS_MAP_TYPE_DOT1P_TO_TC, pentry.ingress_qos_profile->m_pcpdei_to_tc);
        }
        set_attr_value(SAI_PORT_ATTR_QOS_DOT1P_TO_TC_MAP, *value, ret_obj_id);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_tc_pg_map_get(_In_ const sai_object_key_t* key,
                   _Inout_ sai_attribute_value_t* value,
                   _In_ uint32_t attr_index,
                   _Inout_ vendor_cache_t* cache,
                   void* arg)
{
    la_status status;

    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();

    port_entry pentry;
    status = sdev->m_ports.get(la_port.index, pentry);
    sai_return_on_la_error(status);

    set_attr_value(SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP, *value, pentry.tc_priogroup_oid);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_dscp_tc_map_get(_In_ const sai_object_key_t* key,
                     _Inout_ sai_attribute_value_t* value,
                     _In_ uint32_t attr_index,
                     _Inout_ vendor_cache_t* cache,
                     void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();
    sai_check_object(la_port, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);
    // TODO remove this check once port level QOS has completed full devtest cycle.
    if (sdev->m_push_port_qos_to_switch) {
        sai_object_key_t switch_key;
        switch_key.key.object_id = sdev->m_switch_id;
        sai_status_t sai_status
            = lasai_qos::switch_attr_qos_map_get(&switch_key, value, attr_index, cache, (void*)SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP);
        sai_return_on_error(sai_status, "%s: Fail to get qos map switch");
    } else {
        la_status status;
        port_entry pentry{};
        sai_object_id_t ret_obj_id;
        status = sdev->m_ports.get(la_port.index, pentry);
        sai_return_on_la_error(status, "%s: Fail to get pentry port_index(%d)", la_port.index);
        if (pentry.ingress_qos_profile == nullptr) {
            ret_obj_id = SAI_NULL_OBJECT_ID;
        } else {
            ret_obj_id = lasai_qos::get_qos_map(
                sdev, pentry.ingress_qos_profile, SAI_QOS_MAP_TYPE_DSCP_TO_TC, pentry.ingress_qos_profile->m_dscp_to_tc);
        }
        set_attr_value(SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP, *value, ret_obj_id);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_tc_queue_map_get(_In_ const sai_object_key_t* key,
                      _Inout_ sai_attribute_value_t* value,
                      _In_ uint32_t attr_index,
                      _Inout_ vendor_cache_t* cache,
                      void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();
    sai_check_object(la_port, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);
    // TODO remove this check once port level QOS has completed full devtest cycle.
    if (sdev->m_push_port_qos_to_switch) {
        sai_object_key_t switch_key;
        switch_key.key.object_id = sdev->m_switch_id;
        sai_status_t sai_status = lasai_qos::switch_attr_tc_map_get(&switch_key, value, attr_index, cache, arg);
        sai_return_on_error(sai_status, "%s: Fail to get qos map switch");
    } else {
        la_status status;
        port_entry pentry{};
        sai_object_id_t ret_obj_id;
        status = sdev->m_ports.get(la_port.index, pentry);
        sai_return_on_la_error(status, "%s: Fail to get pentry port_index(%d)", la_port.index);
        if (pentry.tc_profile == nullptr) {
            ret_obj_id = SAI_NULL_OBJECT_ID;
        } else {
            ret_obj_id = lasai_qos::get_qos_tc_map(sdev, pentry.tc_profile);
        }
        set_attr_value(SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP, *value, ret_obj_id);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_pfc_queue_map_get(_In_ const sai_object_key_t* key,
                       _Inout_ sai_attribute_value_t* value,
                       _In_ uint32_t attr_index,
                       _Inout_ vendor_cache_t* cache,
                       void* arg)
{
    la_status status;

    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();

    port_entry pentry;
    status = sdev->m_ports.get(la_port.index, pentry);
    sai_return_on_la_error(status);

    sai_object_id_t qos_map_oid = SAI_NULL_OBJECT_ID;
    qos_map_oid = pentry.pfcprio_queue_oid;

    set_attr_value(SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP, *value, qos_map_oid);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
do_port_mirror_get(const sai_object_key_t* key,
                   bool is_ingress_stage,
                   sai_object_type_t sai_obj_type,
                   std::vector<sai_object_id_t>& mirror_session_oids)
{
    lsai_object port_obj(key->key.object_id);
    auto sdev = port_obj.get_device();
    sai_check_object(port_obj, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);
    port_entry* pentry = sdev->m_ports.get_ptr(port_obj.index);
    if (pentry == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    std::set<sai_object_id_t>* mirror_oid_set = nullptr;
    if (is_ingress_stage) {
        mirror_oid_set = &(pentry->service.ingress_mirror_oids);
    } else {
        mirror_oid_set = &(pentry->service.egress_mirror_oids);
    }

    for (auto oid : *mirror_oid_set) {
        lsai_object laobj(oid);
        if (laobj.type == sai_obj_type) {
            mirror_session_oids.push_back(oid);
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_mirror_session_get(_In_ const sai_object_key_t* key,
                        _Inout_ sai_attribute_value_t* value,
                        _In_ uint32_t attr_index,
                        _Inout_ vendor_cache_t* cache,
                        void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    bool is_ingress_stage = ((uintptr_t)arg == SAI_PORT_ATTR_INGRESS_MIRROR_SESSION) ? true : false;
    std::vector<sai_object_id_t> mirror_session_oids;
    sai_status_t status = do_port_mirror_get(key, is_ingress_stage, SAI_OBJECT_TYPE_MIRROR_SESSION, mirror_session_oids);
    sai_return_on_error(status);

    if (mirror_session_oids.empty()) {
        value->objlist.count = 0;
    } else {
        return fill_sai_list(mirror_session_oids.begin(), mirror_session_oids.end(), value->objlist);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
do_port_sample_mirror_get(const sai_object_key_t* key,
                          bool is_ingress_stage,
                          sai_object_type_t sai_obj_type,
                          std::vector<sai_object_id_t>& mirror_session_oids)
{
    lsai_object port_obj(key->key.object_id);
    auto sdev = port_obj.get_device();
    sai_check_object(port_obj, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);
    port_entry* pentry = sdev->m_ports.get_ptr(port_obj.index);
    if (pentry == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    std::set<sai_object_id_t>* mirror_oid_set = nullptr;
    if (is_ingress_stage) {
        mirror_oid_set = &(pentry->service.ingress_sample_mirror_oids);
    } else {
        mirror_oid_set = &(pentry->service.egress_sample_mirror_oids);
    }

    for (auto oid : *mirror_oid_set) {
        lsai_object laobj(oid);
        if (laobj.type == sai_obj_type) {
            mirror_session_oids.push_back(oid);
        }
    }

    return SAI_STATUS_SUCCESS;
}

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 7, 0)
sai_status_t
port_sample_mirror_session_get(_In_ const sai_object_key_t* key,
                               _Inout_ sai_attribute_value_t* value,
                               _In_ uint32_t attr_index,
                               _Inout_ vendor_cache_t* cache,
                               void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    bool is_ingress_stage = ((uintptr_t)arg == SAI_PORT_ATTR_INGRESS_SAMPLE_MIRROR_SESSION) ? true : false;
    std::vector<sai_object_id_t> sample_mirror_session_oids;
    sai_status_t status
        = do_port_sample_mirror_get(key, is_ingress_stage, SAI_OBJECT_TYPE_MIRROR_SESSION, sample_mirror_session_oids);
    sai_return_on_error(status);

    if (sample_mirror_session_oids.empty()) {
        value->objlist.count = 0;
    } else {
        return fill_sai_list(sample_mirror_session_oids.begin(), sample_mirror_session_oids.end(), value->objlist);
    }

    return SAI_STATUS_SUCCESS;
}
#endif

sai_status_t
port_samplepacket_get(_In_ const sai_object_key_t* key,
                      _Inout_ sai_attribute_value_t* value,
                      _In_ uint32_t attr_index,
                      _Inout_ vendor_cache_t* cache,
                      void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object port_obj(key->key.object_id);
    auto sdev = port_obj.get_device();
    sai_check_object(port_obj, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);
    port_entry* pentry = sdev->m_ports.get_ptr(port_obj.index);
    if (pentry == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch ((uintptr_t)arg) {
    case SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE:
        value->oid = pentry->service.ingress_packet_sample_oid;
        break;
    case SAI_PORT_ATTR_EGRESS_SAMPLEPACKET_ENABLE:
        value->oid = pentry->service.egress_packet_sample_oid;
        break;
    default:
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_speed_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    la_mac_port* mac_port = nullptr;
    sai_status_t sai_status = get_mac_port_by_eth_obj(key->key.object_id, sdev, port_idx, pentry, mac_port);

    if (sai_status == SAI_STATUS_ITEM_NOT_FOUND) {
        // this is not a mac_port, can't change speed
        sai_return_on_error(
            SAI_STATUS_INVALID_PARAMETER, "sai_object_id(0x%lx): Not a mac_port. Cannot change speed.", key->key.object_id)
    }
    // check if there are other errors
    sai_return_on_error(sai_status);

    // requested speed change.
    sai_uint32_t req_sai_speed = get_attr_value(SAI_PORT_ATTR_SPEED, (*value));
    la_mac_port::port_speed_e req_la_speed = sai_to_sdk_speed(req_sai_speed);

    // Get current fec and serdes lane setting
    uint32_t num_of_serdes = mac_port->get_num_of_serdes();
    la_mac_port::fec_mode_e req_la_fec_mode;
    la_status status = mac_port->get_fec_mode(req_la_fec_mode);
    sai_return_on_la_error(status);

    bool req_an_enabled;
    status = mac_port->get_an_enabled(req_an_enabled);
    sai_return_on_la_error(status);
    bool save_an_enabled = req_an_enabled;

    // Validating requested speed for this port.
    la_mac_port::mac_config_vec valid_config_list;
    status = sdev->m_dev->get_valid_mac_port_configs(valid_config_list);
    sai_return_on_la_error(status);

    // Use map to get a list of supported speed (no-duplication) with num_of_serdes constraint
    std::map<la_mac_port::fec_mode_e, bool> supported_fec_map;
    for (auto config : valid_config_list) {
        if (config.serdes_count == num_of_serdes && config.port_speed == req_la_speed) {
            supported_fec_map[config.fec_mode] = config.an_capable;
        }
    }

    // Check if requested speed supported.
    if (supported_fec_map.size() == 0) {
        sai_return_on_error(
            SAI_STATUS_INVALID_PARAMETER, "sai_object_id(0x%lx): Speed (%d) not supported.", key->key.object_id, req_sai_speed);
    }

    // Check if requested speed and fec are matching...
    auto it = supported_fec_map.find(req_la_fec_mode);
    if (it != supported_fec_map.end()) {
        // mask off the an_enable if the request speed and fec doesn't support AN.
        req_an_enabled = it->second & req_an_enabled;
    } else {
        // if no fec match, just use the first FEC and an_enabled in list
        it = supported_fec_map.begin();
        req_la_fec_mode = it->first;
        req_an_enabled = it->second & req_an_enabled;
    }

    // get the current FC setting
    la_mac_port::fc_mode_e tx_fc, rx_fc;
    status = mac_port->get_fc_mode(la_mac_port::fc_direction_e::RX, rx_fc);
    sai_return_on_la_error(status);
    status = mac_port->get_fc_mode(la_mac_port::fc_direction_e::TX, tx_fc);
    sai_return_on_la_error(status);

    transaction txn{};

    if (pentry.admin_state) {
        txn.status = stop_mac_port(mac_port, pentry);
        sai_return_on_la_error(txn.status);
        txn.on_fail([=]() { activate_mac_port(mac_port, pentry); });
    }

    txn.status = mac_port->set_an_enabled(false);
    sai_return_on_la_error(txn.status, txn.status.message().c_str());
    txn.on_fail([=]() { mac_port->set_an_enabled(save_an_enabled); });

    // MTU, loopback_mode setting will be saved and restored in reconfigure.
    txn.status = mac_port->reconfigure(num_of_serdes, req_la_speed, rx_fc, tx_fc, req_la_fec_mode);
    sai_return_on_la_error(txn.status, txn.status.message().c_str());

    // restore PFC if enabled
    if (pentry.pfc) {
        txn.status = pentry.pfc->handle_port_speed_change(pentry.service.oid);
        sai_return_on_la_error(txn.status, txn.status.message().c_str());
    }

    // restore an setting.
    txn.status = mac_port->set_an_enabled(req_an_enabled);
    sai_return_on_la_error(txn.status, txn.status.message().c_str());

    if (pentry.admin_state) {
        txn.status = activate_mac_port(mac_port, pentry);
        sai_return_on_la_error(txn.status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_state_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    la_mac_port* mac_port = nullptr;
    sai_status_t sai_status = get_mac_port_by_eth_obj(key->key.object_id, sdev, port_idx, pentry, mac_port);
    sai_return_on_error(sai_status);

    auto admin_state = get_attr_value(SAI_PORT_ATTR_ADMIN_STATE, (*value));

    if (pentry.admin_state == admin_state) {
        return SAI_STATUS_SUCCESS;
    }

    if (admin_state) {
        la_status status = activate_mac_port(mac_port, pentry);
        sai_return_on_la_error(status);
    } else {
        la_status status = stop_mac_port(mac_port, pentry);
        sai_return_on_la_error(status);
    }

    pentry.admin_state = admin_state;
    sdev->m_ports.set(port_idx, pentry);
    sai_log_debug(SAI_API_PORT, "Port(0x%lx) admin_state changed to %s", key->key.object_id, to_string(admin_state).c_str());

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_media_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    la_mac_port* mac_port = nullptr;
    sai_status_t sai_status = get_mac_port_by_eth_obj(key->key.object_id, sdev, port_idx, pentry, mac_port);
    sai_return_on_error(sai_status);

    transaction txn{};

    if (pentry.admin_state) {
        txn.status = stop_mac_port(mac_port, pentry);
        sai_return_on_la_error(txn.status);
        txn.on_fail([=]() { activate_mac_port(mac_port, pentry); });
    }

    auto media_type = get_attr_value(SAI_PORT_ATTR_MEDIA_TYPE, (*value));

    // TODO if media_type == SAI_PORT_MEDIA_TYPE_NOT_PRESENT, we should erase all SI parameter using
    // populate_default_serdes_parameters()
    // This will allow us to use SDK default parameters. Currently, populate_default_serdes_parameters() is not available in
    // la_mac_port.

    // setup SI parameters for this mac_port
    txn.status = setup_mac_port_serdes_params(mac_port, media_type, sdev);
    sai_return_on_la_error(txn.status, "Failed to set SI parameters. sai_object_id(0x%lx)", key->key.object_id);

    pentry.media_type = media_type;
    sdev->m_ports.set(port_idx, pentry);

    if (pentry.admin_state) {
        txn.status = activate_mac_port(mac_port, pentry);
        sai_return_on_la_error(txn.status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_lpbk_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    la_mac_port* mac_port = nullptr;
    sai_status_t sai_status = get_mac_port_by_eth_obj(key->key.object_id, sdev, port_idx, pentry, mac_port);
    sai_return_on_error(sai_status);

    transaction txn{};

    if (pentry.admin_state) {
        txn.status = stop_mac_port(mac_port, pentry);
        sai_return_on_la_error(txn.status);
        txn.on_fail([=]() { activate_mac_port(mac_port, pentry); });
    }

    auto sai_lpbk_mode = get_attr_value(SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE, (*value));

    auto la_loopback_mode = sai_to_sdk_lpbk_mode(sai_lpbk_mode);

    txn.status = mac_port->set_loopback_mode(la_loopback_mode);
    sai_return_on_la_error(txn.status,
                           "Failed to set loopback mode on mac_port. sai_object_id(0x%lx), SAI_PORT_INTERNAL_LOOPBACK_MODE(%d).",
                           key->key.object_id,
                           sai_lpbk_mode);

    if (pentry.admin_state) {
        txn.status = activate_mac_port(mac_port, pentry);
        sai_return_on_la_error(txn.status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_fec_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    la_mac_port* mac_port = nullptr;
    sai_status_t sai_status = get_mac_port_by_eth_obj(key->key.object_id, sdev, port_idx, pentry, mac_port);
    sai_return_on_error(sai_status);

    la_mac_port::port_speed_e la_speed;
    la_status status = mac_port->get_speed(la_speed);
    sai_return_on_la_error(status);
    uint32_t num_of_serdes = mac_port->get_num_of_serdes();

    auto req_fec_mode = get_attr_value(SAI_PORT_ATTR_FEC_MODE, (*value));
    la_mac_port::fec_mode_e req_la_fec_mode = sai_to_sdk_fec_mode(req_fec_mode, la_speed, num_of_serdes);

    transaction txn{};

    if (pentry.admin_state) {
        txn.status = stop_mac_port(mac_port, pentry);
        sai_return_on_la_error(txn.status);
        txn.on_fail([=]() { activate_mac_port(mac_port, pentry); });
    }

    txn.status = mac_port->set_fec_mode(req_la_fec_mode);
    sai_return_on_la_error(txn.status,
                           "Failed to set FEC mode on mac_port. sai_object_id(0x%lx), fec(%s).",
                           key->key.object_id,
                           to_string(req_la_fec_mode).c_str());

    if (pentry.admin_state) {
        txn.status = activate_mac_port(mac_port, pentry);
        sai_return_on_la_error(txn.status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_autoneg_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    la_mac_port* mac_port = nullptr;
    sai_status_t sai_status = get_mac_port_by_eth_obj(key->key.object_id, sdev, port_idx, pentry, mac_port);
    sai_return_on_error(sai_status);

    transaction txn{};

    if (pentry.admin_state) {
        txn.status = stop_mac_port(mac_port, pentry);
        sai_return_on_la_error(txn.status);
        txn.on_fail([=]() { activate_mac_port(mac_port, pentry); });
    }

    bool an_enable = get_attr_value(SAI_PORT_ATTR_AUTO_NEG_MODE, (*value));

    txn.status = mac_port->set_an_enabled(an_enable);
    sai_return_on_la_error(
        txn.status, "Failed to set auto_neg on mac_port. sai_object_id(0x%lx), auto_neg(%d)", key->key.object_id, an_enable);

    if (pentry.admin_state) {
        txn.status = activate_mac_port(mac_port, pentry);
        sai_return_on_la_error(txn.status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_mtu_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    port_entry* pentry{nullptr};
    la_mac_port* mac_port{nullptr};
    std::shared_ptr<lsai_device> sdev{nullptr};
    sai_status_t sai_status = get_port_ptrs_by_oid(key->key.object_id, pentry, mac_port, sdev);
    sai_return_on_error(sai_status);

    sai_uint32_t max_packet_size = get_attr_value(SAI_PORT_ATTR_MTU, (*value));
    if (max_packet_size > SAI_MAC_MAX_MTU_SIZE) {
        sai_return_on_error(
            SAI_STATUS_INVALID_ATTR_VALUE_0 + SAI_PORT_ATTR_MTU, "Maximum MTU size of a SAI_PORT is %d.", SAI_MAC_MAX_MTU_SIZE);
    }

    pentry->service.mtu = max_packet_size;
    if (!pentry->is_lag_member()) {
        // Set mac_port MTU value
        la_status status = mac_port->set_max_packet_size(max_packet_size);
        sai_return_on_la_error(status, "Failed to set MTU(%d) on mac_port, %s.", max_packet_size, status.message().c_str());
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_fc_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_mac_port* mac_port = get_mac_port_by_eth_obj(key->key.object_id);
    if (mac_port == nullptr) {
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    sai_port_flow_control_mode_t sai_fc_mode = get_attr_value(SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE, (*value));

    la_mac_port::fc_mode_e tx_fc, rx_fc;
    std::tie(tx_fc, rx_fc) = sai_to_sdk_fc_mode(sai_fc_mode);

    la_status status = mac_port->set_fc_mode(la_mac_port::fc_direction_e::TX, tx_fc);
    sai_return_on_la_error(status);
    status = mac_port->set_fc_mode(la_mac_port::fc_direction_e::RX, rx_fc);
    return to_sai_status(status);
}

sai_status_t
port_pfc_mode_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    sai_status_t sai_status;

    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // prepare working instances - lsai_device, port_entry, and mac_port
    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    la_mac_port* mac_port = nullptr;
    sai_status = get_mac_port_by_eth_obj(key->key.object_id, sdev, port_idx, pentry, mac_port);
    sai_return_on_error(sai_status);

    // only COMBINED mode supported - the set is a no-op
    size_t pfc_mode = get_attr_value(SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE, (*value));
    if (pfc_mode != SAI_PORT_PRIORITY_FLOW_CONTROL_MODE_COMBINED) {
        return SAI_STATUS_NOT_SUPPORTED;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_pfc_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    sai_uint8_t new_pfc_set;

    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // prepare working instances - lsai_device, port_entry, and mac_port
    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    la_mac_port* mac_port = nullptr;
    sai_status_t sai_status = get_mac_port_by_eth_obj(key->key.object_id, sdev, port_idx, pentry, mac_port);
    sai_return_on_error(sai_status);

    // each bit represent PFC priority traffic class
    new_pfc_set = get_attr_value(SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, (*value));

    lsai_object la_port(key->key.object_id);
    la_status status = sdev->m_pfc_handler->set_tc(mac_port, new_pfc_set, la_port);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
do_port_mirror_set(const sai_object_key_t* key, bool is_ingress_stage, std::vector<sai_object_id_t>& mirror_session_oids)
{

    lsai_object port_obj(key->key.object_id);
    auto sdev = port_obj.get_device();
    sai_check_object(port_obj, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);
    port_entry* pentry = sdev->m_ports.get_ptr(port_obj.index);
    if (pentry == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status_t status;
    auto gress = is_ingress_stage ? "ingress" : "egress";
    if (mirror_session_oids.empty()) {
        // Detach mirror sessions on this port.
        status = sdev->m_mirror_handler->detach_mirror_sessions(key->key.object_id, is_ingress_stage);
        sai_return_on_error(status);
        sai_log_debug(SAI_API_PORT, "Detached all %s mirror sessions from port 0x%lx", gress, key->key.object_id);
    } else {
        status = sdev->m_mirror_handler->attach_mirror_sessions(key->key.object_id, is_ingress_stage, mirror_session_oids);
        sai_return_on_error(status);
        sai_log_debug(SAI_API_PORT, "Attached %s mirror session/s to port 0x%lx", gress, key->key.object_id);
    }

    // update port entry to reflect changes related to mirroring.
    std::set<sai_object_id_t>* mirror_oid_set = nullptr;
    if (is_ingress_stage) {
        mirror_oid_set = &(pentry->service.ingress_mirror_oids);
    } else {
        mirror_oid_set = &(pentry->service.egress_mirror_oids);
    }

    if (mirror_session_oids.empty()) {
        // clear mirror-oid set since all mirrors are detached.
        mirror_oid_set->clear();
    } else {
        // add new mirror-oids to port entry that the port is mirroring.
        for (auto oid : mirror_session_oids) {
            mirror_oid_set->insert(oid);
        }
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_mirror_session_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status_t status;
    uint32_t attr_id = (uintptr_t)arg;
    bool is_ingress_stage = (attr_id == SAI_PORT_ATTR_INGRESS_MIRROR_SESSION) ? true : false;
    std::vector<sai_object_id_t> mirror_session_oids{};

    // Detach mirror sessions on this port. Per SAI spec, count == 0 is used
    // to remove mirror session/s off the port.
    if (value->objlist.count != 0) {
        // SAI specification allows to attach one or more mirror sessions on the port.
        if (value->objlist.list == nullptr) {
            return SAI_STATUS_INVALID_PARAMETER;
        }

        for (size_t i = 0; i < value->objlist.count; ++i) {
            mirror_session_oids.push_back(value->objlist.list[i]);
        }
    }

    status = do_port_mirror_set(key, is_ingress_stage, mirror_session_oids);
    sai_return_on_error(status);

    return SAI_STATUS_SUCCESS;
}

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 7, 0)
sai_status_t
port_sample_mirror_session_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    lsai_object port_obj(key->key.object_id);
    auto sdev = port_obj.get_device();
    sai_check_object(port_obj, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);

    sai_status_t status;
    uint32_t attr_id = (uintptr_t)arg;
    bool is_ingress_stage = (attr_id == SAI_PORT_ATTR_INGRESS_SAMPLE_MIRROR_SESSION) ? true : false;
    std::vector<sai_object_id_t> mirror_session_oids{};

    // Detach mirror sessions on this port. Per SAI spec, count == 0 is used
    // to remove mirror session/s off the port.
    if (value->objlist.count != 0) {
        // SAI specification allows to attach one or more sample mirror sessions on the port.
        if (value->objlist.list == nullptr) {
            return SAI_STATUS_INVALID_PARAMETER;
        }

        for (size_t i = 0; i < value->objlist.count; ++i) {
            lsai_object packetsample_obj(value->objlist.list[i]);
            if (packetsample_obj.type != SAI_OBJECT_TYPE_MIRROR_SESSION) {
                sai_log_error(SAI_API_PORT,
                              "Invalid mirror session packet object 0x%lx provided during sample mirror session",
                              value->objlist.list[i]);
                return SAI_STATUS_FAILURE;
            }
            mirror_session_oids.push_back(value->objlist.list[i]);
        }
    }

    status = sdev->m_samplepacket_handler->port_sample_mirror_session_set(key, is_ingress_stage, mirror_session_oids);
    sai_return_on_error(status);

    return SAI_STATUS_SUCCESS;
}
#endif

sai_status_t
port_samplepacket_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    lsai_object port_obj(key->key.object_id);
    auto sdev = port_obj.get_device();
    sai_check_object(port_obj, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);

    sai_status_t status;
    uint32_t attr_id = (uintptr_t)arg;
    bool is_ingress_stage = (attr_id == SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE) ? true : false;
    if (value->oid != SAI_NULL_OBJECT_ID) {
        lsai_object packetsample_obj(value->oid);
        if (packetsample_obj.type != SAI_OBJECT_TYPE_SAMPLEPACKET) {
            sai_log_error(SAI_API_PORT, "Invalid sample packet object 0x%lx", value->oid);
            return SAI_STATUS_FAILURE;
        }

        lasai_samplepacket_t* packet_sample = sdev->m_samplepacket_handler->m_samplepacket_db.get_ptr(packetsample_obj.index);
        if (packet_sample == nullptr) {
            sai_log_error(
                SAI_API_PORT, "Unable to set packet sampling 0x%lx object to port. Unknown packet sampling oid", value->oid);
            return SAI_STATUS_FAILURE;
        }
    }

    status = sdev->m_samplepacket_handler->port_packet_sampling_set(key, is_ingress_stage, value->oid);
    sai_return_on_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
serdes_preem_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    la_mac_port* mac_port = nullptr;
    sai_status_t sai_status;
    if (la_port.type == sai_object_type_t::SAI_OBJECT_TYPE_PORT_SERDES) {
        sai_status = get_mac_port_by_srds_obj_id(la_port.object_id(), sdev, port_idx, pentry, mac_port);
    } else {
        sai_status = get_mac_port_by_eth_obj(la_port.object_id(), sdev, port_idx, pentry, mac_port);
    }
    sai_return_on_error(sai_status);

    uint32_t num_of_serdes = mac_port->get_num_of_serdes();

    if (value->u32list.count != num_of_serdes || value->u32list.list == nullptr) {
        sai_log_error(SAI_API_PORT, "Bad u32list: u32list.count is not %d or u32list.list is null.", num_of_serdes);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // tx squelch need to be set after admin_state is set to true.
    // if admin_state is not true, save the preemphasis. And, set them during port_state_set().
    if (pentry.admin_state == false) {
        for (uint32_t idx = 0; idx < num_of_serdes; idx++) {
            pentry.serdes_entry_vec[idx].preemphasis = value->u32list.list[idx];
        }
        sdev->m_ports.set(port_idx, pentry);
        return SAI_STATUS_SUCCESS;
    }

    transaction txn{};
    la_mac_port::serdes_ctrl_e new_control, cur_control;

    // Change the control for all serdes lanes within this mac_port.
    for (la_uint_t idx = 0; idx < num_of_serdes; idx++) {
        // check serdes lane's pre-emphasis value is set to 0, enable squelch for this lane.
        new_control = to_serdes_ctrl(value->u32list.list[idx]);
        cur_control = to_serdes_ctrl(pentry.serdes_entry_vec[idx].preemphasis);

        if (new_control != cur_control) {
            txn.status = mac_port->set_serdes_signal_control(idx, la_serdes_direction_e::TX, new_control);
            sai_return_on_la_error(txn.status,
                                   "Fail to set serdes signal control. sai_object_id(0x%lx) %s",
                                   key->key.object_id,
                                   txn.status.message().c_str());
            txn.on_fail([=]() { mac_port->set_serdes_signal_control(idx, la_serdes_direction_e::TX, cur_control); });
            sai_log_debug(
                SAI_API_PORT, "Port(0x%lx) serdes(%d) signal control set to %d", key->key.object_id, idx, int(new_control));
        }
    }

    // copy all serdes pre-emphasis values to port_entry and save
    for (uint32_t idx = 0; idx < num_of_serdes; idx++) {
        pentry.serdes_entry_vec[idx].preemphasis = value->u32list.list[idx];
    }
    sdev->m_ports.set(port_idx, pentry);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
serdes_param_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    la_mac_port* mac_port = nullptr;
    sai_status_t sai_status = get_mac_port_by_srds_obj_id(key->key.object_id, sdev, port_idx, pentry, mac_port);
    sai_return_on_error(sai_status);

    // First, get la_mac_port::serdes_param_e from SAI serdes_prop definitions.
    string param_key = to_serdes_prop_defines_key((int64_t)arg);
    auto found_iter = serdes_prop_defines.find(param_key);
    if (found_iter == serdes_prop_defines.end()) {
        // Not found
        sai_log_error(
            SAI_API_PORT, "Error: SerDes parameter (\"%s\"), attr_id(%d) is not supported.", param_key.c_str(), (int64_t)arg);
        return SAI_STATUS_NOT_SUPPORTED;
    }

    // Check the value array
    uint32_t num_of_serdes = mac_port->get_num_of_serdes();
    if (value->s32list.count != num_of_serdes || value->s32list.list == nullptr) {
        sai_log_error(SAI_API_PORT, "Bad u32list: s32list.count is not %d or s32list.list is null.", num_of_serdes);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // load serdes parameter to mac_port
    la_status status;
    for (uint32_t serdes_idx = 0; serdes_idx < num_of_serdes; serdes_idx++) {
        sai_int32_t param_value = value->s32list.list[serdes_idx];
        for (const auto& serdes_prop : found_iter->second) {
            sai_log_debug(SAI_API_PORT, "serdes_idx(%d) <- %s (%d)", serdes_idx, to_string(serdes_prop).c_str(), param_value);
            status = mac_port->set_serdes_parameter(
                serdes_idx, serdes_prop.stage, serdes_prop.parameter, serdes_prop.mode, param_value);
            sai_return_on_la_error(status, "Failed to set serdes parameter");
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_set_sdk_ingress_qos_profile(std::shared_ptr<lsai_device> sdev,
                                 _In_ la_ethernet_port* eth_port,
                                 _In_ la_ingress_qos_profile* qos_profile)
{
    la_status status = LA_STATUS_SUCCESS;
    std::vector<la_object*> vec = sdev->m_dev->get_dependent_objects(eth_port);
    for (la_object* elem : vec) {
        switch (elem->type()) {
        case la_object::object_type_e::L3_AC_PORT: {
            la_l3_ac_port* l3_ac_port = static_cast<la_l3_ac_port*>(elem);
            status = l3_ac_port->set_ingress_qos_profile(qos_profile);
            break;
        }
        case la_object::object_type_e::L2_SERVICE_PORT: {
            la_l2_service_port* l2_port = static_cast<la_l2_service_port*>(elem);
            status = l2_port->set_ingress_qos_profile(qos_profile);
            break;
        }
        default:
            break;
        }
    }

    return to_sai_status(status);
}

sai_status_t
port_set_sdk_tc_profile(const std::shared_ptr<lsai_device> sdev,
                        _In_ port_entry* pentry,
                        _In_ la_ethernet_port* eth_port,
                        la_tc_profile* tc_profile)
{
    la_status status = LA_STATUS_SUCCESS;
    if (eth_port) {
        std::vector<la_object*> vec = sdev->m_dev->get_dependent_objects(eth_port);
        for (la_object* elem : vec) {
            switch (elem->type()) {
            case la_object::object_type_e::L3_AC_PORT: {
                la_l3_ac_port* l3_ac_port = static_cast<la_l3_ac_port*>(elem);
                status = l3_ac_port->set_tc_profile(tc_profile);
                break;
            }
            default:
                break;
            }
        }
    } else if (pentry && pentry->sys_port) {
        status = pentry->sys_port->set_tc_profile(tc_profile);
    }

    return to_sai_status(status);
}

static sai_status_t
port_setup_ingress_qos_profile(std::shared_ptr<lsai_device> sdev,
                               _In_ port_entry* pentry,
                               _In_ la_ethernet_port* eth_port,
                               _In_ const sai_attribute_value_t* value,
                               _In_ sai_qos_map_type_t map_type)
{
    sai_status_t sai_status;
    std::shared_ptr<lasai_to_sdk_qos_ingress> out_qos_profile = nullptr;
    std::shared_ptr<lasai_to_sdk_qos_ingress> in_qos_profile = pentry->ingress_qos_profile;
    bool using_default = false;
    sai_status
        = sdev->m_qos_handler->setup_ingress_qos_profile(sdev, value, map_type, in_qos_profile, out_qos_profile, using_default);
    sai_return_on_error(sai_status);

    if (in_qos_profile == out_qos_profile) {
        sai_log_debug(SAI_API_PORT, "No change to ingress QOS profile on port %lx", pentry->service.oid);
        return SAI_STATUS_SUCCESS;
    }

    // Do not set port to this profile if it is the default.
    if (using_default) {
        pentry->ingress_qos_profile = nullptr;
    } else {
        pentry->ingress_qos_profile = out_qos_profile;
    }

    return port_set_sdk_ingress_qos_profile(sdev, eth_port, out_qos_profile->m_sdk_profile);
}

sai_status_t
port_dot1p_tc_map_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    la_status status;
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status_t sai_status;
    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();
    sai_check_object(la_port, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);
    // TODO remove this check once port level QOS has completed full devtest cycle.
    if (sdev->m_push_port_qos_to_switch) {
        sai_object_key_t switch_key;
        switch_key.key.object_id = sdev->m_switch_id;
        sai_status = lasai_qos::switch_attr_qos_map_set(&switch_key, value, (void*)SAI_QOS_MAP_TYPE_DOT1P_TO_TC);
    } else {
        port_entry* pentry = sdev->m_ports.get_ptr(la_port.index);
        if (pentry == nullptr) {
            return SAI_STATUS_INVALID_PARAMETER;
        }

        la_ethernet_port* eth_port;
        if (pentry->lag_oid != SAI_NULL_OBJECT_ID) {
            lsai_object la_lag(pentry->lag_oid);
            lag_entry* lag_entry = sdev->m_lags.get_ptr(la_lag.index);
            eth_port = lag_entry->service.eth_port;
        } else {
            eth_port = pentry->service.eth_port;
        }

        sai_status = port_setup_ingress_qos_profile(sdev, pentry, eth_port, value, SAI_QOS_MAP_TYPE_DOT1P_TO_TC);
        sai_return_on_error(sai_status);
    }
    return sai_status;
}

sai_status_t
port_tc_pg_map_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();
    sai_check_object(la_port, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);

    port_entry* pentry;
    la_status status = sdev->m_ports.get_ptr(la_port.index, pentry);
    sai_return_on_la_error(status);

    sai_object_id_t new_map_oid = value->oid;
    sai_status_t sai_status = lasai_qos::update_qos_map_ref_count(sdev, pentry->tc_priogroup_oid, new_map_oid);
    sai_return_on_error(sai_status);

    pentry->tc_priogroup_oid = new_map_oid;
    // apply the new mapping each ingress_priority_group on pentry
    for (auto& ipg : pentry->ingress_priority_group_entries) {
        status = ipg.set_tc_profile(pentry, ipg.get_buffer_profile_oid());
        sai_return_on_la_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_dscp_tc_map_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    la_status status;
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status_t sai_status;
    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();
    sai_check_object(la_port, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);
    // TODO remove this check once port level QOS has completed full devtest cycle.
    if (sdev->m_push_port_qos_to_switch) {
        sai_object_key_t switch_key;
        switch_key.key.object_id = sdev->m_switch_id;
        sai_status = lasai_qos::switch_attr_qos_map_set(&switch_key, value, (void*)SAI_QOS_MAP_TYPE_DSCP_TO_TC);
    } else {
        port_entry* pentry = sdev->m_ports.get_ptr(la_port.index);
        if (pentry == nullptr) {
            return SAI_STATUS_INVALID_PARAMETER;
        }

        la_ethernet_port* eth_port;
        if (pentry->lag_oid != SAI_NULL_OBJECT_ID) {
            lsai_object la_lag(pentry->lag_oid);
            lag_entry* lag_entry = sdev->m_lags.get_ptr(la_lag.index);
            eth_port = lag_entry->service.eth_port;
        } else {
            eth_port = pentry->service.eth_port;
        }

        sai_status = port_setup_ingress_qos_profile(sdev, pentry, eth_port, value, SAI_QOS_MAP_TYPE_DSCP_TO_TC);
        sai_return_on_error(sai_status);
    }
    return sai_status;
}

sai_status_t
port_tc_queue_map_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status_t sai_status;
    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();
    sai_check_object(la_port, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);
    // TODO remove this check once port level QOS has completed full devtest cycle.
    if (sdev->m_push_port_qos_to_switch) {
        sai_object_key_t switch_key;
        switch_key.key.object_id = sdev->m_switch_id;
        sai_status = lasai_qos::switch_attr_tc_map_set(&switch_key, value, arg);
        sai_return_on_error(sai_status);
    } else {
        port_entry* pentry = sdev->m_ports.get_ptr(la_port.index);
        if (pentry == nullptr) {
            return SAI_STATUS_INVALID_PARAMETER;
        }

        la_ethernet_port* eth_port;
        if (pentry->lag_oid != SAI_NULL_OBJECT_ID) {
            lsai_object la_lag(pentry->lag_oid);
            lag_entry* lag_entry = sdev->m_lags.get_ptr(la_lag.index);
            eth_port = lag_entry->service.eth_port;
        } else {
            eth_port = pentry->service.eth_port;
        }
        std::shared_ptr<lasai_to_sdk_tc_profile> out_tc_profile = nullptr;
        std::shared_ptr<lasai_to_sdk_tc_profile> in_tc_profile = pentry->tc_profile;
        bool using_default = false;
        sai_status = sdev->m_qos_handler->setup_tc_profile(sdev, value, in_tc_profile, out_tc_profile, using_default);
        sai_return_on_error(sai_status);

        if (using_default) {
            pentry->tc_profile = nullptr;
        } else {
            pentry->tc_profile = out_tc_profile;
        }

        if (in_tc_profile == out_tc_profile) {
            sai_log_debug(SAI_API_PORT, "No change to TC queue profile on port %lx", pentry->service.oid);
            return SAI_STATUS_SUCCESS;
        }

        sai_return_on_error(port_set_sdk_tc_profile(
            sdev, (pentry->lag_oid != SAI_NULL_OBJECT_ID) ? nullptr : pentry, eth_port, out_tc_profile->m_sdk_profile));
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_pfc_queue_map_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();
    sai_check_object(la_port, SAI_OBJECT_TYPE_PORT, sdev, "port", key->key.object_id);

    port_entry* pentry;
    la_status status = sdev->m_ports.get_ptr(la_port.index, pentry);
    sai_return_on_la_error(status);

    sai_object_id_t new_map_oid = value->oid;
    sai_status_t sai_status = lasai_qos::update_qos_map_ref_count(sdev, pentry->pfcprio_queue_oid, new_map_oid);
    sai_return_on_error(sai_status);

    pentry->pfcprio_queue_oid = new_map_oid;

    return SAI_STATUS_SUCCESS;
}

la_voq_gid_t
get_base_voq(int port_id)
{
    return lsai_device::SAI_VOQ_BASE + (port_id * 16);
}

la_status
get_vsc_vec(la_uint_t vsc_offset, const std::shared_ptr<lsai_device> sdev, la_vsc_gid_vec_t& vec, la_vsc_gid_vec_t& vec_2)

{

    la_uint_t vsc_base = lsai_device::SAI_VSC_BASE + (vsc_offset * 16 * sdev->m_dev_params.slices_per_dev);

    for (la_slice_id_t i = 0; i < sdev->m_dev_params.slices_per_dev; ++i) {
        vec[i] = vsc_base + (i * NUM_QUEUE_PER_PORT * 2);
        vec_2[i] = vsc_base + (i * NUM_QUEUE_PER_PORT * 2) + (NUM_QUEUE_PER_PORT);
    }

    return LA_STATUS_SUCCESS;
}

static la_status
setup_mac_port_serdes_params(la_mac_port* mac_port,
                             const sai_port_media_type_t& media_type,
                             const std::shared_ptr<lsai_device> sdev)
{
    if (media_type == sai_port_media_type_t::SAI_PORT_MEDIA_TYPE_NOT_PRESENT) {
        // TODO if media_type == SAI_PORT_MEDIA_TYPE_NOT_PRESENT, we should erase all SI parameter using
        // populate_default_serdes_parameters()
        // This will allow us to use SDK default parameters. Currently, populate_default_serdes_parameters() is not available in
        // la_mac_port.
        return LA_STATUS_SUCCESS;
    }

    la_status status = mac_port->reset();
    la_return_on_error(status, "Failed to reset mac port");

    lsai_serdes_params_t props;
    lsai_serdes_params_map_key_t serdes_key{};
    la_status found_status;

    serdes_key.slice_id = (uint8_t)mac_port->get_slice();
    serdes_key.ifg_id = (uint8_t)mac_port->get_ifg();
    serdes_key.serdes_id = (uint8_t)mac_port->get_first_serdes_id();
    serdes_key.media_type = sai_to_lsai_media_type(media_type);

    la_mac_port::port_speed_e serdes_speed;
    if (mac_port->get_serdes_speed(serdes_speed) == LA_STATUS_SUCCESS) {
        serdes_key.serdes_speed = (uint16_t)(sdk_to_sai_speed(serdes_speed) / 1000);
    } else {
        serdes_key.serdes_speed = 50;
    }

    lsai_serdes_params_map_key_t ifg_key = lsai_serdes_params_map_key_t(serdes_key);
    // for ifg_key, serdes id must be 0.
    ifg_key.serdes_id = 0;

    for (uint32_t serdes_num = 0; serdes_num < mac_port->get_num_of_serdes(); ++serdes_num) {
        // Get the serdes parameters from map
        serdes_key.serdes_id = (uint8_t)(mac_port->get_first_serdes_id() + serdes_num);

        found_status = sai_json_find_serdes_params(sdev->m_board_cfg.serdes_params_map, serdes_key, props);
        if (found_status != LA_STATUS_SUCCESS) {
            sai_log_debug(SAI_API_PORT,
                          "serdes_num(%d), key=\"%s\", missed in serdes_params_map.",
                          serdes_num,
                          to_string(serdes_key).c_str());
        } else {
            sai_log_debug(
                SAI_API_PORT, "serdes_num(%d), key=\"%s\", found in serdes_params_map", serdes_num, to_string(serdes_key).c_str());
        }

        if (found_status != LA_STATUS_SUCCESS) {
            // if fail to find the serdes_key, try ifg_key...
            found_status = sai_json_find_serdes_params(sdev->m_board_cfg.ifg_default_params_map, ifg_key, props);
            if (found_status != LA_STATUS_SUCCESS) {
                sai_log_debug(SAI_API_PORT,
                              "serdes_num(%d), key=\"%s\", missed in ifg_default_params_map.",
                              serdes_num,
                              to_string(ifg_key).c_str());
            } else {
                sai_log_debug(SAI_API_PORT,
                              "serdes_num(%d), key=\"%s\", found in ifg_default_params_map.",
                              serdes_num,
                              to_string(ifg_key).c_str());
            }
        }

        // To complete the full list of props for this serdes,
        // insert default pll parameters at the beginning of vector.
        props.insert(props.begin(), sdev->m_board_cfg.serdes_default_pll.begin(), sdev->m_board_cfg.serdes_default_pll.end());

        if (found_status != LA_STATUS_SUCCESS) {
            // if not found, props is only contains default_pll at this moment.
            // put default_param at the end of vector.
            props.insert(
                props.end(), sdev->m_board_cfg.serdes_default_params.begin(), sdev->m_board_cfg.serdes_default_params.end());
        }

        // Load all serdes property to mac_port (only this serdes macro)
        for (const auto& prop : props) {
            sai_log_debug(SAI_API_PORT, "serdes_num(%d) <- %s", serdes_num, to_string(prop).c_str());
            status = mac_port->set_serdes_parameter(serdes_num, prop.stage, prop.parameter, prop.mode, prop.value);
            la_return_on_error(status, "Failed to set serdes parameter");
        }
    }

    for (uint32_t serdes_num = 0; serdes_num < mac_port->get_num_of_serdes(); ++serdes_num) {
        serdes_key.serdes_id = (uint8_t)(mac_port->get_first_serdes_id() + serdes_num);
        la_mac_port::serdes_param_array lane_params;
        found_status = mac_port->get_serdes_parameters(serdes_num, lane_params);
        std::string key_name = std::to_string(serdes_key.slice_id) + "," + std::to_string(serdes_key.ifg_id) + ","
                               + std::to_string(serdes_key.serdes_id) + "," + std::to_string(serdes_key.serdes_speed) + ","
                               + to_string(media_type);
        sai_log_debug(SAI_API_PORT, "serdes_num(%d), key=\"%s\"", serdes_num, key_name.c_str());
        for (const auto& param : lane_params) {
            sai_log_debug(SAI_API_PORT, "%s", to_string(param).c_str());
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
port_scheduling_params_update(sai_object_id_t port_oid, sai_object_id_t sched_oid)
{
    std::vector<uint32_t> queue_list;
    lsai_object la_port(port_oid);
    port_entry port_entry;

    la_return_on_error(la_port.get_device()->m_ports.get(la_port.index, port_entry));

    for (uint32_t index = 0; index < NUM_QUEUE_PER_PORT; index++) {
        if (port_entry.scheduling_oids[index] == sched_oid) {
            queue_list.push_back(index);
        }
    }

    sai_uint32_t port_mbps;
    la_return_on_error(port_speed_get(la_port.get_device(), port_oid, port_mbps));
    la_return_on_error(port_system_port_scheduler_dynamic_config(la_port.get_device(), port_entry, queue_list, port_mbps, false));

    return LA_STATUS_SUCCESS;
}

la_status
port_buffer_profile_set(const lsai_object& la_port, uint32_t queue_index, sai_object_id_t profile_id)
{
    port_entry* port_entry = nullptr;

    la_return_on_error(la_port.get_device()->m_ports.get_ptr(la_port.index, port_entry));
    port_entry->buffer_profile_oids[queue_index] = profile_id;

    return LA_STATUS_SUCCESS;
}

la_status
port_buffer_profile_get(const lsai_object& la_port, uint32_t queue_index, sai_object_id_t& out_profile_oid)
{
    port_entry* port_entry = nullptr;

    la_return_on_error(la_port.get_device()->m_ports.get_ptr(la_port.index, port_entry));
    out_profile_oid = port_entry->buffer_profile_oids[queue_index];

    return LA_STATUS_SUCCESS;
}

la_status
port_scheduler_config_get(const lsai_object& la_port, uint32_t queue_index, sai_object_id_t& out_sched_oid)
{
    port_entry port_entry;

    la_return_on_error(la_port.get_device()->m_ports.get(la_port.index, port_entry));
    out_sched_oid = port_entry.scheduling_oids[queue_index];

    return LA_STATUS_SUCCESS;
}

la_status
port_scheduler_config_change(const lsai_object& la_port, uint32_t queue_index, sai_object_id_t sched_oid)
{
    port_entry port_entry;

    la_return_on_error(la_port.get_device()->m_ports.get(la_port.index, port_entry));
    sai_object_id_t old_sched_oid = port_entry.scheduling_oids[queue_index];
    port_entry.scheduling_oids[queue_index] = sched_oid;

    // check if old_sched_oid is still used on other queue in this port
    bool need_to_remove = true;
    for (sai_object_id_t oid : port_entry.scheduling_oids) {
        if (oid == old_sched_oid) {
            need_to_remove = false;
            break;
        }
    }

    std::vector<uint32_t> queue_list = {queue_index};
    sai_object_id_t port_oid = la_port.object_id();
    sai_uint32_t port_mbps;

    la_status status = port_speed_get(la_port.get_device(), port_oid, port_mbps);
    if (status != LA_STATUS_SUCCESS) {
        // If this is recycle port, or something else we don't support a speed get for, do nothing
        return LA_STATUS_SUCCESS;
    }

    la_return_on_error(port_system_port_scheduler_dynamic_config(la_port.get_device(), port_entry, queue_list, port_mbps, false));

    la_port.get_device()->m_sched_handler->update_scheduler_used_ports(port_oid, sched_oid, need_to_remove ? old_sched_oid : 0);

    la_port.get_device()->m_ports.set(la_port.index, port_entry);

    return LA_STATUS_SUCCESS;
}

sai_status_t
scheduler_group_queue_scheduler_config_change(const lsai_object& la_port, uint32_t queue_index, sai_object_id_t sched_oid)
{
    port_entry port_entry;
    auto sdev = la_port.get_device();
    sai_return_on_la_error(la_port.get_device()->m_ports.get(la_port.index, port_entry));

    sai_object_id_t old_sched_oid = port_entry.m_sched_group_sched_profiles[queue_index + 1];
    port_entry.scheduling_oids[queue_index + 1] = sched_oid;

    // check if old_sched_oid is still used on other queue in this port
    bool need_to_remove = true;
    for (sai_object_id_t oid : port_entry.m_sched_group_sched_profiles) {
        if (oid == old_sched_oid) {
            need_to_remove = false;
            break;
        }
    }

    std::vector<uint32_t> queue_list = {queue_index};
    sai_object_id_t port_oid = la_port.object_id();
    sai_uint32_t port_mbps;

    la_status status = port_speed_get(la_port.get_device(), port_oid, port_mbps);
    if (status != LA_STATUS_SUCCESS) {
        // If this is recycle port, or something else we don't support a speed get for, do nothing
        return SAI_STATUS_SUCCESS;
    }

    sai_return_on_la_error(
        port_system_port_scheduler_dynamic_config(la_port.get_device(), port_entry, queue_list, port_mbps, true));

    la_port.get_device()->m_sched_handler->update_scheduler_used_ports(port_oid, sched_oid, need_to_remove ? old_sched_oid : 0);

    la_port.get_device()->m_ports.set(la_port.index, port_entry);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_scheduler_group_scheduler_config_change(std::shared_ptr<lsai_device>& out_sdev,
                                             sai_object_id_t port_oid,
                                             sai_object_id_t sched_oid)
{

    lsai_object la_port(port_oid);
    port_entry port_entry;
    la_mac_port* out_mac_port;

    sai_return_on_la_error(la_port.get_device()->m_ports.get(la_port.index, port_entry));

    sai_status_t sai_status = get_mac_port_by_port_entry(out_sdev, port_entry, out_mac_port);
    sai_return_on_error(sai_status);

    la_interface_scheduler* ifc_sch = out_mac_port->get_scheduler();

    if (sched_oid == SAI_NULL_OBJECT_ID) {
        // default interface scheduler setting
        return SAI_STATUS_SUCCESS;
    }

    sai_uint32_t port_mbps;

    sai_return_on_la_error(port_speed_get(la_port.get_device(), port_oid, port_mbps));

    sai_return_on_error(port_interface_scheduler_dynamic_config(la_port.get_device(), port_entry, ifc_sch, port_mbps, sched_oid));

    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_interface_scheduler_dynamic_config(std::shared_ptr<lsai_device> sdev,
                                        const port_entry& port_entry,
                                        la_interface_scheduler* ifc_sch,
                                        uint64_t port_mbps,
                                        sai_object_id_t sched_oid)
{

    uint64_t bps, pir_bps, max_bps;
    uint8_t weight;
    sai_scheduling_type_t sched_type;

    sdev->m_sched_handler->get_type(sched_oid, sched_type);

    max_bps = LA_RATE_UNLIMITED;
    sdev->m_sched_handler->get_pir(sched_oid, pir_bps);
    if (pir_bps == 0) {
        pir_bps = max_bps;
    } else if (pir_bps == 1) {
        // Since 0 means "unlimited", special handling for 1 bps to allow a
        // way to configure true 0.
        pir_bps = 0;
    }

    if (sched_type == SAI_SCHEDULING_TYPE_STRICT) {
        bps = max_bps;
        weight = 1;
    } else {
        bps = port_mbps;
        sdev->m_sched_handler->get_weight(sched_oid, weight);
    }

    // interface scheduler
    ifc_sch->set_credit_cir(bps);
    ifc_sch->set_transmit_cir(bps);
    ifc_sch->set_credit_eir_or_pir(pir_bps, false);
    ifc_sch->set_transmit_eir_or_pir(pir_bps, false);
    ifc_sch->set_cir_weight(weight);
    ifc_sch->set_eir_weight(weight);

    return SAI_STATUS_SUCCESS;
}

// la_port - port to configure
// queue_index - index of queue in port to configure (0 - 7)
// wred_oid - Object id of WRED to set
la_status
port_wred_config_change(const lsai_object& la_port, uint32_t queue_index, sai_object_id_t new_wred_oid)
{
    port_entry port_entry;
    auto sdev = la_port.get_device();

    la_status status = la_port.get_device()->m_ports.get(la_port.index, port_entry);
    la_return_on_error(status);

    if (port_entry.sys_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_voq_set* voq_set = port_entry.sys_port->get_voq_set();
    if (voq_set == nullptr) {
        return LA_STATUS_EINVAL;
    }
    la_voq_set* voq_set_ecn = nullptr;

    la_voq_cgm_profile* cgm_prof;
    la_voq_cgm_profile* cgm_prof_ecn;
    status = la_port.get_device()->m_wred_handler->cgm_prof_from_oid(new_wred_oid, cgm_prof, cgm_prof_ecn);
    la_return_on_error(status);

    status = voq_set->set_cgm_profile(queue_index, cgm_prof);
    la_return_on_error(status);

    if (port_entry.type == port_entry_type_e::MAC && sdev->m_hw_device_type == hw_device_type_e::GIBRALTAR) {
        voq_set_ecn = port_entry.sys_port->get_ect_voq_set();
        if (voq_set_ecn == nullptr) {
            return LA_STATUS_EINVAL;
        }

        if (cgm_prof_ecn != nullptr) {
            // apply ecn cgm profile to the ecn capable queue
            status = voq_set_ecn->set_cgm_profile(queue_index, cgm_prof_ecn);
            la_return_on_error(status);
        }
    }

    // increase ref count for new wred oid. Decrease for old wred oid
    sai_object_id_t old_wred_oid = port_entry.wred_oids[queue_index];

    la_port.get_device()->m_wred_handler->inc_ref_count(new_wred_oid);
    la_port.get_device()->m_wred_handler->dec_ref_count(old_wred_oid);

    port_entry.wred_oids[queue_index] = new_wred_oid;

    la_port.get_device()->m_ports.set(la_port.index, port_entry);

    return LA_STATUS_SUCCESS;
}

la_status
port_system_port_scheduler_static_config(const port_entry& port_entry, uint64_t port_mbps)
{
    uint64_t bps = port_mbps * UNITS_IN_MEGA * lasai_scheduling_params::SYSTEM_PORT_SPEEDUP;
    la_system_port_scheduler* sp_sch = port_entry.sys_port->get_scheduler();

    sp_sch->set_priority_propagation(false);
    sp_sch->set_logical_port_enabled(false);

    for (int queue = 0; queue < NUM_QUEUE_PER_PORT; ++queue) {
        la_return_on_error(sp_sch->set_credit_pir(queue, bps));
        la_return_on_error(sp_sch->set_transmit_pir(queue, bps));
        la_return_on_error(sp_sch->set_transmit_uc_mc_weight(queue, 1, 1));
    }

    return LA_STATUS_SUCCESS;
}

la_status
port_system_port_scheduler_dynamic_config(std::shared_ptr<lsai_device> sdev,
                                          const port_entry& port_entry,
                                          std::vector<uint32_t>& queue_list,
                                          uint64_t port_mbps,
                                          bool is_sched_group_sched_obj)
{
    la_system_port_scheduler::priority_group_e all_prio[NUM_QUEUE_PER_PORT] = {la_system_port_scheduler::priority_group_e::SINGLE0,
                                                                               la_system_port_scheduler::priority_group_e::SINGLE1,
                                                                               la_system_port_scheduler::priority_group_e::SINGLE2,
                                                                               la_system_port_scheduler::priority_group_e::SINGLE3,
                                                                               la_system_port_scheduler::priority_group_e::SP2,
                                                                               la_system_port_scheduler::priority_group_e::SP4,
                                                                               la_system_port_scheduler::priority_group_e::SP6,
                                                                               la_system_port_scheduler::priority_group_e::SP8};

    uint64_t bps, pir_bps, max_bps;
    la_system_port_scheduler* sp_sch = port_entry.sys_port->get_scheduler();
    uint8_t weight;
    sai_scheduling_type_t sched_type;
    sai_object_id_t sched_oid;

    for (auto queue : queue_list) {
        if (is_sched_group_sched_obj) {
            sched_oid = port_entry.m_sched_group_sched_profiles[queue + 1];
        } else {
            sched_oid = port_entry.scheduling_oids[queue];
        }

        sdev->m_sched_handler->get_type(sched_oid, sched_type);
        // something is really wrong if we have bad sched_oid in port_entry;
        // assert(status == SAI_STATUS_SUCCESS);

        la_system_port_scheduler::priority_group_e prio_group;

        max_bps = LA_RATE_UNLIMITED;
        sdev->m_sched_handler->get_pir(sched_oid, pir_bps);
        if (pir_bps == 0) {
            pir_bps = max_bps;
        } else if (pir_bps == 1) {
            // Since 0 means "unlimited", special handling for 1 bps to allow a
            // way to configure true 0.
            pir_bps = 0;
        }

        if (sched_type == SAI_SCHEDULING_TYPE_STRICT) {
            prio_group = la_system_port_scheduler::priority_group_e::SP8;
            bps = max_bps;
            weight = 1;
        } else {
            prio_group = all_prio[queue];
            bps = 0;
            sdev->m_sched_handler->get_weight(sched_oid, weight);
        }

        la_return_on_error(sp_sch->set_oq_priority_group(queue, prio_group));
        la_return_on_error(sp_sch->set_priority_group_credit_cir(prio_group, bps));
        la_return_on_error(sp_sch->set_priority_group_transmit_cir(prio_group, bps));
        la_return_on_error(sp_sch->set_priority_group_eir_weight(prio_group, weight));
        la_return_on_error(sp_sch->set_credit_pir(queue, pir_bps));
        la_return_on_error(sp_sch->set_transmit_pir(queue, pir_bps));
    }

    return LA_STATUS_SUCCESS;
}

la_status
port_scheduler_default_config(std::shared_ptr<lsai_device> sdev,
                              port_entry& port_entry,
                              la_interface_scheduler* ifc_sch,
                              uint64_t port_mbps,
                              la_vsc_gid_vec_t vsc_vec,
                              la_vsc_gid_vec_t vsc_vec_ecn)
{
    uint64_t bps = port_mbps * UNITS_IN_MEGA * lasai_scheduling_params::SYSTEM_PORT_SPEEDUP;
    la_system_port_scheduler* sp_sch = port_entry.sys_port->get_scheduler();

    // interface scheduler
    ifc_sch->set_credit_cir(bps);
    ifc_sch->set_transmit_cir(bps);
    ifc_sch->set_credit_eir_or_pir(bps, false);
    ifc_sch->set_transmit_eir_or_pir(bps, false);
    ifc_sch->set_cir_weight(1);
    ifc_sch->set_eir_weight(1);

    // system port scheduler
    // default values
    std::vector<uint32_t> queue_list;
    for (int queue = 0; queue < NUM_QUEUE_PER_PORT; ++queue) {
        port_entry.scheduling_oids[queue] = sdev->m_sched_handler->default_scheduler();
        queue_list.push_back(queue);
    }

    // initialize the scheduler groups hierarchy
    lsai_object la_port(port_entry.service.oid);

    lsai_object la_sched_group(SAI_OBJECT_TYPE_SCHEDULER_GROUP, la_port.switch_id, 0);
    la_sched_group.detail.set(lsai_detail_type_e::SCHEDULER_GROUP, lsai_detail_field_e::PORT, la_port.index);

    for (uint32_t i = 0; i < NUM_QUEUE_PER_PORT + 1; i++) {
        la_sched_group.index = i;
        port_entry.m_sched_group_oids[i] = la_sched_group.object_id();
    }

    // scheduler group default scheduler obj ids as SAI_NULL_OBJECT_ID
    for (int i = 0; i < NUM_QUEUE_PER_PORT + 1; ++i) {
        port_entry.m_sched_group_sched_profiles[i] = SAI_NULL_OBJECT_ID;
    }

    la_status status = port_system_port_scheduler_static_config(port_entry, port_mbps);
    la_return_on_error(status);

    status = port_system_port_scheduler_dynamic_config(sdev, port_entry, queue_list, port_mbps, false);
    la_return_on_error(status);

    // output queue scheduler
    for (int oq_id = 0; oq_id < NUM_QUEUE_PER_PORT; ++oq_id) {
        la_output_queue_scheduler* oq_sch = nullptr;
        status = sp_sch->get_output_queue_scheduler(oq_id, oq_sch);
        la_return_on_error(status);

        oq_sch->set_scheduling_mode(la_output_queue_scheduler::scheduling_mode_e::DIRECT_2SP_3WFQ);
        for (int group = 0; group < 4; ++group) {
            oq_sch->set_group_weight(group, 1);
        }

        for (size_t slice = 0; slice < vsc_vec.size(); ++slice) {
            status
                = oq_sch->attach_vsc(vsc_vec[slice] + oq_id, la_oq_vsc_mapping_e::RR1_RR3, 0, slice, port_entry.base_voq + oq_id);
            la_return_on_error(status);

            status = oq_sch->set_vsc_pir(vsc_vec[slice] + oq_id, LA_RATE_UNLIMITED);
            la_return_on_error(status);
        }
        for (size_t slice = 0; slice < vsc_vec_ecn.size(); ++slice) {
            status = oq_sch->attach_vsc(vsc_vec_ecn[slice] + oq_id,
                                        la_oq_vsc_mapping_e::RR1_RR3,
                                        0,
                                        slice,
                                        port_entry.base_voq + oq_id + NUM_QUEUE_PER_PORT);
            la_return_on_error(status);

            status = oq_sch->set_vsc_pir(vsc_vec_ecn[slice] + oq_id, LA_RATE_UNLIMITED);
            la_return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

static std::string
port_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_port_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
create_port(sai_object_id_t* out_port_id, sai_object_id_t obj_switch_id, uint32_t attr_count, const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_PORT, SAI_OBJECT_TYPE_SWITCH, obj_switch_id, &port_to_string, obj_switch_id, attrs);

    sai_u32_list_t lane{};
    get_attrs_value(SAI_PORT_ATTR_HW_LANE_LIST, attrs, lane, true);

    sai_uint32_t sai_speed = 0;
    get_attrs_value(SAI_PORT_ATTR_SPEED, attrs, sai_speed, true);

    // SAI PORT default attribute values at port creation.
    sai_port_media_type_t media_type = sai_port_media_type_t::SAI_PORT_MEDIA_TYPE_NOT_PRESENT;
    get_attrs_value(SAI_PORT_ATTR_MEDIA_TYPE, attrs, media_type, false);

    sai_port_internal_loopback_mode_t ilb_mode = sai_port_internal_loopback_mode_t::SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE;
    get_attrs_value(SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE, attrs, ilb_mode, false);

    // Set to FEC mode and MTU size to NONE, and 1514 as SAI default.
    sai_port_fec_mode_t fec_mode = sai_port_fec_mode_t::SAI_PORT_FEC_MODE_NONE;
    get_attrs_value(SAI_PORT_ATTR_FEC_MODE, attrs, fec_mode, false);

    sai_uint32_t mtu = SAI_DEFAULT_MTU_SIZE;
    get_attrs_value(SAI_PORT_ATTR_MTU, attrs, mtu, false);

    bool an_enable = false;
    get_attrs_value(SAI_PORT_ATTR_AUTO_NEG_MODE, attrs, an_enable, false);

    // convert to physical location.
    port_phy_loc phy_loc{};
    sai_status_t sai_status = to_phy_lanes(phy_loc, lane, sdev);
    sai_return_on_error(sai_status);

    auto port_speed = sai_to_sdk_speed(sai_speed);

    transaction txn{};

    la_mac_port* mac_port = nullptr;
    la_status status = sdev->m_dev->create_mac_port(phy_loc.slice,
                                                    phy_loc.ifg,
                                                    phy_loc.pif,
                                                    phy_loc.pif_last,
                                                    port_speed,
                                                    la_mac_port::fc_mode_e::NONE,
                                                    sai_to_sdk_fec_mode(fec_mode, port_speed, lane.count),
                                                    mac_port);
    sai_return_on_la_error(status, "Failed to create mac_port.");

    txn.on_fail([=]() { sdev->m_dev->destroy(mac_port); });

    // mac_pool register default is 9600B for MTU, 64B for min_size.
    txn.status = mac_port->set_max_packet_size(mtu);
    sai_return_on_la_error(txn.status, txn.status.message().c_str());

    if (an_enable) {
        txn.status = mac_port->set_an_enabled(an_enable);
        sai_return_on_la_error(txn.status, txn.status.message().c_str());
    }

    auto la_loopback_mode = sai_to_sdk_lpbk_mode(ilb_mode);
    if (la_loopback_mode != la_mac_port::loopback_mode_e::NONE) {
        txn.status = mac_port->set_loopback_mode(la_loopback_mode);
        sai_return_on_la_error(txn.status, txn.status.message().c_str());
    }

    txn.status = setup_mac_port_serdes_params(mac_port, media_type, sdev);
    sai_return_on_la_error(txn.status, "Fail to set (%s) serdes parameters.", mac_port->to_string().c_str());

    uint32_t port_index;
    port_entry* pentry{nullptr};
    txn.status = sdev->allocate_port(lane.list[0], port_entry_type_e::MAC, port_index, pentry, txn);
    sai_return_on_la_error(txn.status, "Failed allocating new port entry.");

    // create PFC port object
    status = sdev->m_pfc_handler->pfc_create_port(mac_port, pentry);
    sai_return_on_la_error(status);

    // Since this is a mac_port, initialize serdes entry for each
    // lane.
    serdes_entry sentry{};
    pentry->serdes_entry_vec = std::vector<silicon_one::sai::serdes_entry>(mac_port->get_num_of_serdes(), sentry);

    // update port_entry::media_type, mtu
    pentry->media_type = media_type;
    pentry->service.mtu = mtu;

    if (sdev->m_voq_cfg_manager->is_npu_switch()) {
        constexpr la_system_port_gid_t no_val = -1;

        la_system_port_gid_t system_port_gid = no_val;
        get_attrs_value(SAI_PORT_ATTR_EXT_SYSTEM_PORT_ID, attrs, system_port_gid, false);

        // Only NPU switch auto-creates the la_system_port, VOQ switch
        // goes through SAI API.
        txn.status = setup_la_system_port(mac_port,
                                          phy_loc.pif + lsai_device::SAI_VSC_PORT_BASE,
                                          sai_speed,
                                          pentry,
                                          sdev,
                                          txn,
                                          (system_port_gid == no_val) ? nullptr : &system_port_gid);
        sai_return_on_la_error(txn.status);
    }

    // setup port vlan id default to be 1
    if (pentry->service.untagged_bridge_port == SAI_NULL_OBJECT_ID) {
        pentry->service.untagged_bridge_port = create_untagged_bridge_port(sdev, pentry->service.oid);
    }

    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];
    key.key.object_id = pentry->service.oid;
    snprintf(key_str, MAX_KEY_STR_LEN, "port 0x%0lx", pentry->service.oid);

    // loop for create_and_set attributes
    bool attr_admin_state_present = false;
    uint32_t attr_admin_state_idx = 0;
    for (uint32_t i = 0; i < attr_count; i++) {
        // skip attributes are  mandatory or create only
        // Also, skip attribute that have been taken care by above creation process.

        switch (attr_list[i].id) {
        case SAI_PORT_ATTR_HW_LANE_LIST:
        case SAI_PORT_ATTR_SPEED:
        case SAI_PORT_ATTR_MEDIA_TYPE:
        case SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE:
        case SAI_PORT_ATTR_FEC_MODE:
        case SAI_PORT_ATTR_MTU:
        case SAI_PORT_ATTR_AUTO_NEG_MODE:
            continue;
            break;
        case SAI_PORT_ATTR_ADMIN_STATE:
            attr_admin_state_present = true;
            attr_admin_state_idx = i;
            continue;
            break;
        default:
            sai_create_and_set_attribute(&key, key_str, port_attribs, port_vendor_attribs, &attr_list[i]);
            break;
        }
    }

    if (attr_admin_state_present) {
        sai_create_and_set_attribute(&key, key_str, port_attribs, port_vendor_attribs, &attr_list[attr_admin_state_idx]);
    }

    *out_port_id = pentry->service.oid;

    if (sdev->m_hw_device_type == hw_device_type_e::GIBRALTAR) {
        if (pentry->sys_port != nullptr) {
            txn.status = sdev->m_dev->create_rate_limiter(pentry->sys_port, pentry->rate_limiter_set);
            sai_return_on_la_error(txn.status);
        }
    }

    sai_log_debug(SAI_API_PORT,
                  "sai_port(0x%lx) created: [%d/%d/%d](%d), speed(%s)",
                  *out_port_id,
                  phy_loc.slice,
                  phy_loc.ifg,
                  phy_loc.pif,
                  mac_port->get_num_of_serdes(),
                  to_string(port_speed).c_str());

    sai_log_info(SAI_API_PORT, "port id 0x%0lx created", pentry->service.oid);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_port(sai_object_id_t obj_port_id)
{
    port_entry pentry{};
    uint32_t port_idx;
    la_mac_port* mac_port = nullptr;

    sai_start_api(SAI_API_PORT, SAI_OBJECT_TYPE_PORT, obj_port_id, &port_to_string, obj_port_id);
    sai_status_t sai_status = get_mac_port_by_eth_obj(obj_port_id, sdev, port_idx, pentry, mac_port);
    sai_return_on_error(sai_status);

    la_status status;

    if (pentry.service.untagged_bridge_port != SAI_NULL_OBJECT_ID) {
        do_remove_bridge_port(pentry.service.untagged_bridge_port);
        pentry.service.untagged_bridge_port = SAI_NULL_OBJECT_ID;
    }

    if (pentry.service.eth_port != nullptr) {
        status = sdev->m_dev->destroy(pentry.service.eth_port);
        sai_return_on_la_error(status, "Fail to remove ether port for 0x%lx %s", obj_port_id, status.message().c_str());
        pentry.service.eth_port = nullptr;
    }

    if (sdev->m_hw_device_type == hw_device_type_e::GIBRALTAR) {
        if (pentry.rate_limiter_set != nullptr) {
            status = sdev->m_dev->destroy(pentry.rate_limiter_set);
            sai_return_on_la_error(status, "Fail to remove rate limiter for 0x%lx %s", obj_port_id, status.message().c_str());
            pentry.rate_limiter_set = nullptr;
        }
    }

    if (sdev->m_voq_cfg_manager->is_npu_switch()) {
        // Teardown system port directly
        sai_status = teardown_system_port_for_port_entry(sdev, &pentry);
        sai_return_on_error(sai_status);
    } else if (sdev->m_voq_cfg_manager->is_voq_switch()) {
        // In VOQ switch mode, the system port must have been
        // explicitly removed via the SAI API.
        if (pentry.sp_oid != 0) {
            sai_log_error(SAI_API_PORT,
                          "Cannot remove port (ID 0x%0lx) because its system port (ID 0x%0lx) is still active",
                          pentry.service.oid,
                          pentry.sp_oid);
            return SAI_STATUS_OBJECT_IN_USE;
        }
    }

    if (sdev->m_voq_cfg_manager->is_voq_switch()) {
        // Remove lane to port translation for VOQ switch
        uint32_t lane = to_sai_lane(pentry.slice_id, pentry.ifg_id, pentry.pif);
        status = sdev->remove_lane_to_port(lane);
        sai_return_on_la_error(status, "Failed to remove sai lane 0x%lx map for port ID 0x%lx", lane, pentry.service.oid);
    }

    sdev->m_ports.set(port_idx, pentry);

    status = sdev->m_dev->destroy(mac_port);
    sai_return_on_la_error(status);

    status = sdev->m_ports.remove(obj_port_id);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_port_attribute(sai_object_id_t obj_port_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = obj_port_id;
    sai_start_api(SAI_API_PORT, SAI_OBJECT_TYPE_PORT, obj_port_id, &port_to_string, obj_port_id, *attr);
    snprintf(key_str, MAX_KEY_STR_LEN, "port 0x%0lx", obj_port_id);
    return sai_set_attribute(&key, key_str, port_attribs, port_vendor_attribs, attr);
}

static sai_status_t
get_port_attribute(sai_object_id_t obj_port_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = obj_port_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_PORT, SAI_OBJECT_TYPE_PORT, obj_port_id, &port_to_string, obj_port_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "port 0x%0lx", obj_port_id);
    return sai_get_attributes(&key, key_str, port_attribs, port_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
get_port_stats_from_queue(std::shared_ptr<lsai_device>& sdev,
                          la_system_port* system_port,
                          uint32_t number_of_counters,
                          const sai_stat_id_t* counter_ids,
                          sai_stats_mode_t mode,
                          uint64_t* counters)
{
    if (system_port == nullptr) {
        for (uint32_t i = 0; i < number_of_counters; ++i) {
            counters[i] = 0;
        }
        return SAI_STATUS_SUCCESS;
    }

    la_voq_set* voq_set = system_port->get_voq_set();
    if (voq_set == nullptr) {
        return SAI_STATUS_FAILURE;
    }

    la_counter_set* voq_counter_set = nullptr;
    size_t queue_packets = -1, queue_bytes = -1;
    size_t size = 0;
    la_voq_set::voq_counter_type_e type = la_voq_set::voq_counter_type_e::BOTH;
    la_status status = voq_set->get_counter(type, size, voq_counter_set);
    sai_return_on_la_error(status);
    size_t pcount = 0, bcount = 0;

    for (uint32_t i = 0; i < NUM_QUEUE_PER_PORT; i++) {
        voq_counter_set->read(i * 2, sdev->m_force_update, mode == SAI_STATS_MODE_READ_AND_CLEAR, queue_packets, queue_bytes);
        pcount += queue_packets;
        bcount += queue_bytes;
    }

    for (uint32_t i = 0; i < number_of_counters; ++i) {
        switch (counter_ids[i]) {
        // Mac frames counters
        case SAI_PORT_STAT_ETHER_STATS_TX_NO_ERRORS:
            counters[i] = pcount;
            break;
        case SAI_PORT_STAT_IF_OUT_UCAST_PKTS:
            counters[i] = pcount;
            break;
        case SAI_PORT_STAT_IF_OUT_OCTETS:
            counters[i] = bcount;
            break;
        default:
            break;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
pfc_priority_enum_to_priority_value(sai_stat_id_t stat_id, size_t& byte)
{
    switch (stat_id) {
    case SAI_PORT_STAT_PFC_0_RX_PKTS:
    case SAI_PORT_STAT_PFC_0_TX_PKTS:
        byte = 0;
        break;
    case SAI_PORT_STAT_PFC_1_RX_PKTS:
    case SAI_PORT_STAT_PFC_1_TX_PKTS:
        byte = 1;
        break;
    case SAI_PORT_STAT_PFC_2_RX_PKTS:
    case SAI_PORT_STAT_PFC_2_TX_PKTS:
        byte = 2;
        break;
    case SAI_PORT_STAT_PFC_3_RX_PKTS:
    case SAI_PORT_STAT_PFC_3_TX_PKTS:
        byte = 3;
        break;
    case SAI_PORT_STAT_PFC_4_RX_PKTS:
    case SAI_PORT_STAT_PFC_4_TX_PKTS:
        byte = 4;
        break;
    case SAI_PORT_STAT_PFC_5_RX_PKTS:
    case SAI_PORT_STAT_PFC_5_TX_PKTS:
        byte = 5;
        break;
    case SAI_PORT_STAT_PFC_6_RX_PKTS:
    case SAI_PORT_STAT_PFC_6_TX_PKTS:
        byte = 6;
        break;
    case SAI_PORT_STAT_PFC_7_RX_PKTS:
    case SAI_PORT_STAT_PFC_7_TX_PKTS:
        byte = 7;
        break;
    default:
        return SAI_STATUS_INVALID_PARAMETER;
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_port_stats_ext(sai_object_id_t obj_port_id,
                   uint32_t number_of_counters,
                   const sai_stat_id_t* counter_ids,
                   sai_stats_mode_t mode,
                   uint64_t* counters)
{
    size_t priority = 0;
    sai_status_t sai_status;
    lsai_object la_obj(obj_port_id);
    auto sdev = la_obj.get_device();
    sai_check_object(la_obj, SAI_OBJECT_TYPE_PORT, sdev, "port", obj_port_id);
    sai_start_api_counter(sdev);
    std::chrono::nanoseconds time;

    port_entry pentry{};
    la_status status = sdev->m_ports.get(la_obj.index, pentry);
    sai_return_on_la_error(status);

    if (!pentry.is_mac()) {
        return get_port_stats_from_queue(sdev, pentry.sys_port, number_of_counters, counter_ids, mode, counters);
    }

    la_mac_port* mac_port = nullptr;
    status = port_entry_to_mac_port(pentry, mac_port);

    if (mac_port == nullptr) {
        // We handle not mac ports above. Should not get here if mac_port is nullptr
        return SAI_STATUS_INVALID_PARAMETER;
    }

    size_t bytes_cnt;
    bool pfc_enabled;
    la_uint8_t pfc_set;
    const la_meter_set* pfc_meters = nullptr;
    const la_counter_set* pfc_counters = nullptr;

    // if PFC is enabled then get its counters
    status = mac_port->get_pfc_enabled(pfc_enabled, pfc_set);
    sai_return_on_la_error(status);

    if (pfc_enabled) {
        status = mac_port->get_pfc_counter(pfc_counters);
        sai_return_on_la_error(status);

        // SW-PFC meters
        if (pfc_set == 0) {
            status = mac_port->get_pfc_meter(pfc_meters);
            sai_return_on_la_error(status);
        }
    }

    // read mib counters (atomic counters); using sai_stats_mode_t mode for clear-on-read
    bool update_shadow = false, update_mib = false;
    lsai_stats_shadow<la_mac_port::mib_counters>* shadow_ptr = nullptr;
    la_mac_port::mib_counters* mib_ptr = nullptr;

    auto pmib = port_mibs_shadow.find(obj_port_id);
    if (pmib != port_mibs_shadow.end()) {
        shadow_ptr = &pmib->second;
        la_status status = shadow_ptr->get_data(sdev, mib_ptr, mode);
        if (status != LA_STATUS_SUCCESS) {
            update_shadow = true;
        }
    } else {
        update_mib = true;
    }

    la_mac_port::mib_counters out_mib_counters;
    bool clear_on_read = (mode == SAI_STATS_MODE_READ_AND_CLEAR);
    if (update_shadow || update_mib) {

        status = mac_port->read_mib_counters(clear_on_read, out_mib_counters);
        sai_return_on_la_error(status, "Fail to read mib counter from mac port, ID 0x%lx", obj_port_id);

        if (update_shadow && shadow_ptr == nullptr) {
            shadow_ptr->set_data(out_mib_counters, mode);
        } else {
            lsai_stats_shadow<la_mac_port::mib_counters> mib_shadow;

            mib_shadow.set_data(out_mib_counters, mode);
            port_mibs_shadow[obj_port_id] = std::move(mib_shadow);
        }
        mib_ptr = &out_mib_counters;
    }

    // don't do anything if number_of_counters is 0. (for clear status function)
    if (number_of_counters == 0) {
        return SAI_STATUS_SUCCESS;
    }

    // Convert from la_mac_port::mib_counters to port_counters structure
    port_counters mac_counters{};
    if (mib_ptr != nullptr) {
        mac_counters = *mib_ptr;
    }

    la_slice_ifg slice_ifg{pentry.sys_port->get_slice(), pentry.sys_port->get_ifg()};
    uint32_t pif = pentry.sys_port->get_base_serdes();

    uint32_t wred_dropped_pkt_cnt = 0;
    uint32_t wred_dropped_byte_cnt = 0;
    bool wred_counters_read = false;

    // build return counters structure
    for (uint32_t i = 0; i < number_of_counters; ++i) {
        switch (counter_ids[i]) {
        // Mac frames counters
        case SAI_PORT_STAT_ETHER_STATS_RX_NO_ERRORS:
            counters[i] = mac_counters.ether_stats_rx_no_errors;
            break;
        case SAI_PORT_STAT_IF_IN_UCAST_PKTS: {
            if (sdev->m_hw_device_type == hw_device_type_e::GIBRALTAR) {
                uint64_t count_uc = 0, bytes_uc = 0;

                status = pentry.rate_limiter_set->get_pass_count(
                    la_rate_limiters_packet_type_e::UC, false /*clear_on_read*/, count_uc, bytes_uc);
                sai_return_on_la_error(status, "Failed to read rate limiter set for UC");
                counters[i] = count_uc;

                status = pentry.rate_limiter_set->get_pass_count(
                    la_rate_limiters_packet_type_e::UNKNOWN_UC, false /*clear_on_read*/, count_uc, bytes_uc);
                sai_return_on_la_error(status, "Failed to read rate limiter set for unknown UC");
                counters[i] += count_uc;
            } else {
                counters[i] = mac_counters.ether_stats_rx_no_errors;
            }
            break;
        }
        case SAI_PORT_STAT_ETHER_STATS_TX_NO_ERRORS:
        case SAI_PORT_STAT_IF_OUT_UCAST_PKTS:
            counters[i] = mac_counters.ether_stats_tx_no_errors;
            break;
        case SAI_PORT_STAT_ETHER_IN_PKTS_64_OCTETS:
            counters[i] = mac_counters.ether_in_pkts_64_octets;
            break;
        case SAI_PORT_STAT_ETHER_IN_PKTS_65_TO_127_OCTETS:
            counters[i] = mac_counters.ether_in_pkts_65_to_127_octets;
            break;
        case SAI_PORT_STAT_ETHER_IN_PKTS_128_TO_255_OCTETS:
            counters[i] = mac_counters.ether_in_pkts_128_to_255_octets;
            break;
        case SAI_PORT_STAT_ETHER_IN_PKTS_256_TO_511_OCTETS:
            counters[i] = mac_counters.ether_in_pkts_256_to_511_octets;
            break;
        case SAI_PORT_STAT_ETHER_IN_PKTS_512_TO_1023_OCTETS:
            counters[i] = mac_counters.ether_in_pkts_512_to_1023_octets;
            break;
        case SAI_PORT_STAT_ETHER_IN_PKTS_1024_TO_1518_OCTETS:
            counters[i] = mac_counters.ether_in_pkts_1024_to_1518_octets;
            break;
        case SAI_PORT_STAT_ETHER_IN_PKTS_1519_TO_2047_OCTETS:
            counters[i] = mac_counters.ether_in_pkts_1519_to_2047_octets;
            break;
        case SAI_PORT_STAT_ETHER_OUT_PKTS_64_OCTETS:
            counters[i] = mac_counters.ether_out_pkts_64_octets;
            break;
        case SAI_PORT_STAT_ETHER_OUT_PKTS_65_TO_127_OCTETS:
            counters[i] = mac_counters.ether_out_pkts_65_to_127_octets;
            break;
        case SAI_PORT_STAT_ETHER_OUT_PKTS_128_TO_255_OCTETS:
            counters[i] = mac_counters.ether_out_pkts_128_to_255_octets;
            break;
        case SAI_PORT_STAT_ETHER_OUT_PKTS_256_TO_511_OCTETS:
            counters[i] = mac_counters.ether_out_pkts_256_to_511_octets;
            break;
        case SAI_PORT_STAT_ETHER_OUT_PKTS_512_TO_1023_OCTETS:
            counters[i] = mac_counters.ether_out_pkts_512_to_1023_octets;
            break;
        case SAI_PORT_STAT_ETHER_OUT_PKTS_1024_TO_1518_OCTETS:
            counters[i] = mac_counters.ether_out_pkts_1024_to_1518_octets;
            break;
        case SAI_PORT_STAT_ETHER_OUT_PKTS_1519_TO_2047_OCTETS:
            counters[i] = mac_counters.ether_out_pkts_1519_to_2047_octets;
            break;
        case SAI_PORT_STAT_PAUSE_RX_PKTS:
            counters[i] = mac_counters.pause_rx_pkts;
            break;
        case SAI_PORT_STAT_PAUSE_TX_PKTS:
            counters[i] = mac_counters.pause_tx_pkts;
            break;
        case SAI_PORT_STAT_PFC_0_RX_PKTS:
        case SAI_PORT_STAT_PFC_1_RX_PKTS:
        case SAI_PORT_STAT_PFC_2_RX_PKTS:
        case SAI_PORT_STAT_PFC_3_RX_PKTS:
        case SAI_PORT_STAT_PFC_4_RX_PKTS:
        case SAI_PORT_STAT_PFC_5_RX_PKTS:
        case SAI_PORT_STAT_PFC_6_RX_PKTS:
        case SAI_PORT_STAT_PFC_7_RX_PKTS:
            sai_status = pfc_priority_enum_to_priority_value(counter_ids[i], priority);
            sai_return_on_error(sai_status, "Invalid priority %u for pfc rx packet stats", priority);
            if (pfc_enabled && pfc_counters) {
                status
                    = ((la_counter_set*)pfc_counters)->read(priority, sdev->m_force_update, clear_on_read, counters[i], bytes_cnt);
                sai_return_on_la_error(status, "Failed to read PFC %u RX packet counter", priority);
            } else {
                counters[i] = 0;
            }
            break;
        // SW-PFC meter counters
        case SAI_PORT_STAT_PFC_0_TX_PKTS:
        case SAI_PORT_STAT_PFC_1_TX_PKTS:
        case SAI_PORT_STAT_PFC_2_TX_PKTS:
        case SAI_PORT_STAT_PFC_3_TX_PKTS:
        case SAI_PORT_STAT_PFC_4_TX_PKTS:
        case SAI_PORT_STAT_PFC_5_TX_PKTS:
        case SAI_PORT_STAT_PFC_6_TX_PKTS:
        case SAI_PORT_STAT_PFC_7_TX_PKTS:
            sai_status = pfc_priority_enum_to_priority_value(counter_ids[i], priority);
            sai_return_on_error(sai_status, "Invalid priority %u for pfc tx packet stats", priority);
            if (pfc_enabled && pfc_meters) {
                status = ((la_meter_set*)pfc_meters)
                             ->read(priority, sdev->m_force_update, clear_on_read, la_qos_color_e::GREEN, counters[i], bytes_cnt);
                sai_return_on_la_error(status, "Failed to read PFC %u TX packet counter", priority);
            } else if (pfc_enabled && !pfc_meters) {
                // per TC counters are not maintained for hw-pfc, return port counter
                counters[i] = mac_counters.pause_tx_pkts;
            } else {
                counters[i] = 0;
            }
            break;
        case SAI_PORT_STAT_PFC_0_TX_PAUSE_DURATION:
        case SAI_PORT_STAT_PFC_1_TX_PAUSE_DURATION:
        case SAI_PORT_STAT_PFC_2_TX_PAUSE_DURATION:
        case SAI_PORT_STAT_PFC_3_TX_PAUSE_DURATION:
        case SAI_PORT_STAT_PFC_4_TX_PAUSE_DURATION:
        case SAI_PORT_STAT_PFC_5_TX_PAUSE_DURATION:
        case SAI_PORT_STAT_PFC_6_TX_PAUSE_DURATION:
        case SAI_PORT_STAT_PFC_7_TX_PAUSE_DURATION:
            status = mac_port->get_pfc_quanta(time);
            sai_return_on_la_error(status, "Failed to get PFC TX quanta on port");
            counters[i] = time.count();
            break;
        // IF counters, bytes and total errors only
        case SAI_PORT_STAT_IF_IN_OCTETS:
            counters[i] = mac_counters.if_in_octets;
            break;
        case SAI_PORT_STAT_IF_IN_ERRORS:
            counters[i] = mac_counters.if_in_errors;
            break;
        case SAI_PORT_STAT_IF_OUT_OCTETS:
            counters[i] = mac_counters.if_out_octets;
            break;
        case SAI_PORT_STAT_IF_OUT_ERRORS:
            counters[i] = mac_counters.if_out_errors;
            break;

        // Error counters
        case SAI_PORT_STAT_ETHER_STATS_UNDERSIZE_PKTS:
            counters[i] = mac_counters.ether_stats_undersize_pkts;
            break;
        case SAI_PORT_STAT_ETHER_STATS_OVERSIZE_PKTS:
            counters[i] = mac_counters.ether_stats_oversize_pkts;
            break;
        case SAI_PORT_STAT_ETHER_RX_OVERSIZE_PKTS:
            counters[i] = mac_counters.ether_rx_oversize_pkts;
            break;
        case SAI_PORT_STAT_ETHER_STATS_CRC_ALIGN_ERRORS:
            counters[i] = mac_counters.ether_stats_crc_align_errors;
            break;

        // Discard counters
        case SAI_PORT_STAT_IF_IN_DISCARDS: {
            counters[i] = mac_counters.if_in_discards;
            la_trap_priority_t out_priority;
            la_counter_or_meter_set* out_counter_or_meter = nullptr;
            const la_punt_destination* out_destination = nullptr;
            bool out_skip_inject_up_packets = false;
            bool out_skip_p2p_packets = false;
            bool overwrite_phb = false;
            la_traffic_class_t out_tc;

            size_t trap_drop_packets = 0;
            for (auto ec : sdev->m_event_counters) {
                la_counter_set* counter_set = ec.second;
                sdev->m_dev->get_trap_configuration(ec.first,
                                                    out_priority,
                                                    out_counter_or_meter,
                                                    out_destination,
                                                    out_skip_inject_up_packets,
                                                    out_skip_p2p_packets,
                                                    overwrite_phb,
                                                    out_tc);
                // Limit to drop traps with per-port counting
                if ((out_destination != nullptr) || (counter_set == nullptr) || (counter_set->get_set_size() == 1)) {
                    continue;
                }

                size_t curr_drop_packets = 0, curr_drop_bytes = 0;
                auto status = counter_set->read(slice_ifg,
                                                pif,
                                                sdev->m_force_update /* force_update */,
                                                mode == SAI_STATS_MODE_READ_AND_CLEAR,
                                                curr_drop_packets,
                                                curr_drop_bytes);
                sai_return_on_la_error(status);
                trap_drop_packets += curr_drop_packets;
            }
            counters[i] += trap_drop_packets;
        } break;
        case SAI_PORT_STAT_IF_OUT_DISCARDS:
            counters[i] = mac_counters.if_out_discards;
            break;

        case SAI_PORT_STAT_ECN_MARKED_PACKETS: {
            sai_status_t sstatus
                = read_ecn_marked_packets(sdev, pentry.service.eth_port, 0, NUM_QUEUE_PER_PORT - 1, mode, counters[i]);
            sai_return_on_error(sstatus);
            break;
        }

        case SAI_PORT_STAT_WRED_DROPPED_PACKETS: {
            // both need to be read together.
            if (!wred_counters_read) {
                sai_status_t sstatus
                    = read_wred_port_counters(sdev, pentry.sys_port, mode, wred_dropped_pkt_cnt, wred_dropped_byte_cnt);
                sai_return_on_error(sstatus);
                wred_counters_read = true;
            }
            counters[i] = wred_dropped_pkt_cnt;
            break;
        }

        case SAI_PORT_STAT_WRED_DROPPED_BYTES: {
            // both need to be read together.
            if (!wred_counters_read) {
                sai_status_t sstatus
                    = read_wred_port_counters(sdev, pentry.sys_port, mode, wred_dropped_pkt_cnt, wred_dropped_byte_cnt);
                sai_return_on_error(sstatus);
                wred_counters_read = true;
            }
            counters[i] = wred_dropped_byte_cnt;

            break;
        }

        // TODO: will support soon.
        case SAI_PORT_STAT_IF_IN_BROADCAST_PKTS: {
            if (sdev->m_hw_device_type == hw_device_type_e::GIBRALTAR) {
                uint64_t count_bc = 0, bytes_bc = 0;

                status = pentry.rate_limiter_set->get_pass_count(
                    la_rate_limiters_packet_type_e::BC, false /*clear_on_read*/, count_bc, bytes_bc);
                sai_return_on_la_error(status, "Failed to read rate limiter set for BC");
                counters[i] = count_bc;
            } else {
                counters[i] = 0;
            }
            break;
        }
        case SAI_PORT_STAT_IF_IN_MULTICAST_PKTS: {
            if (sdev->m_hw_device_type == hw_device_type_e::GIBRALTAR) {
                uint64_t count_mc = 0, bytes_mc = 0;

                status = pentry.rate_limiter_set->get_pass_count(
                    la_rate_limiters_packet_type_e::MC, false /*clear_on_read*/, count_mc, bytes_mc);
                sai_return_on_la_error(status, "Failed to read rate limiter set for MC");
                counters[i] = count_mc;
            } else {
                counters[i] = 0;
            }
            break;
        }
        case SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS: {
            if (sdev->m_hw_device_type == hw_device_type_e::GIBRALTAR) {
                uint64_t count_bc = 0, bytes_bc = 0, count_mc = 0, bytes_mc = 0;

                status = pentry.rate_limiter_set->get_pass_count(
                    la_rate_limiters_packet_type_e::BC, false /*clear_on_read*/, count_bc, bytes_bc);
                sai_return_on_la_error(status, "Failed to read rate limiter set for BC");
                counters[i] = count_bc;

                status = pentry.rate_limiter_set->get_pass_count(
                    la_rate_limiters_packet_type_e::MC, false /*clear_on_read*/, count_mc, bytes_mc);
                sai_return_on_la_error(status, "Failed to read rate limiter set for MC");
                counters[i] += count_mc;
            } else {
                counters[i] = 0;
            }
            break;
        }
        case SAI_PORT_STAT_IF_OUT_BROADCAST_PKTS:
        case SAI_PORT_STAT_IF_OUT_MULTICAST_PKTS:
        case SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS:
            counters[i] = 0;
            break;
        default:
            if (counter_ids[i] < SAI_PORT_STAT_IN_DROP_REASON_RANGE_END
                && counter_ids[i] >= SAI_PORT_STAT_IN_DROP_REASON_RANGE_BASE) {
                sai_status_t sstatus = sdev->m_debug_counter_handler->get_counter_value(
                    counter_ids[i], mode, counters[i], true /* is_port_count */, slice_ifg);
                sai_return_on_error(sstatus, "Failed getting value of counter %ld", counter_ids[i]);
            } else if (counter_ids[i] <= SAI_PORT_STAT_EEE_RX_DURATION) {
                sai_log_info(SAI_API_PORT, "Port counter %d (index %u) not implemented\n", counter_ids[i], i);
                return SAI_STATUS_NOT_SUPPORTED;
            } else {
                sai_log_error(SAI_API_PORT, "Invalid port counter %d (index %u)\n", counter_ids[i], i);
                return SAI_STATUS_INVALID_PARAMETER;
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
read_ecn_marked_packets(std::shared_ptr<lsai_device>& sdev,
                        la_ethernet_port* eth_port,
                        uint32_t first_index,
                        uint32_t last_index,
                        sai_stats_mode_t mode,
                        uint64_t& out_packets)
{
    std::vector<la_object*> vec = sdev->m_dev->get_dependent_objects(eth_port);
    for (la_object* elem : vec) {
        la_counter_set* egress_qos_counter_set = nullptr;
        if (elem->type() == la_object::object_type_e::L3_AC_PORT) {
            la_l3_port* l3_port = static_cast<la_l3_ac_port*>(elem);
            la_status status = l3_port->get_egress_counter(la_counter_set::type_e::QOS, egress_qos_counter_set);
            sai_return_on_la_error(status, "Failed to get egress counter");

        } else if (elem->type() == la_object::object_type_e::L2_SERVICE_PORT) {
            la_l2_service_port* l2_port = static_cast<la_l2_service_port*>(elem);
            la_status status = l2_port->get_egress_counter(la_counter_set::type_e::QOS, egress_qos_counter_set);
            sai_return_on_la_error(status, "Failed to get egress counter");
        }

        if (!egress_qos_counter_set) {
            continue;
        }

        if (last_index + 1 > egress_qos_counter_set->get_set_size()) {
            sai_log_error(SAI_API_PORT,
                          "read_ecn_marked_packets: internal error index %d larger than max allowed %d",
                          last_index + 1,
                          egress_qos_counter_set->get_set_size());
            return SAI_STATUS_INVALID_PARAMETER;
        }
        for (size_t cnt_idx = first_index; cnt_idx < last_index + 1; cnt_idx++) {
            size_t out_pkt_elem = -1, out_bytes_elem = -1;
            la_status status = egress_qos_counter_set->read(
                cnt_idx, sdev->m_force_update, mode == SAI_STATS_MODE_READ_AND_CLEAR, out_pkt_elem, out_bytes_elem);
            sai_return_on_la_error(status, "Failed to read egress qos counter set, %s", status.message().c_str());
            out_packets += out_pkt_elem;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
read_wred_port_counters(std::shared_ptr<lsai_device> sdev,
                        la_system_port* system_port,
                        sai_stats_mode_t mode,
                        uint32_t& wred_dropped_pkt_cnt,
                        uint32_t& wred_dropped_byte_cnt)
{
    la_voq_set* voq_set = system_port->get_voq_set();

    la_counter_set* voq_counter_set = nullptr;
    size_t size = 0;
    la_voq_set::voq_counter_type_e type = la_voq_set::voq_counter_type_e::BOTH;

    la_status status = voq_set->get_counter(type, size, voq_counter_set);

    uint32_t total_drop_voq_pkts = 0, total_drop_voq_bytes = 0;
    for (uint64_t voq_idx = 0, voq_max = voq_set->get_set_size(); voq_idx < voq_max; voq_idx += 2) {
        size_t voq_pkts = -1, voq_bytes = -1;
        status = voq_counter_set->read(voq_idx, sdev->m_force_update, mode == SAI_STATS_MODE_READ_AND_CLEAR, voq_pkts, voq_bytes);
        sai_return_on_la_error(status);

        total_drop_voq_pkts += voq_pkts;
        total_drop_voq_bytes += voq_bytes;
    }
    // read the drops from the ecn enabled queues.
    la_voq_set* voq_set_ecn = system_port->get_ect_voq_set();

    if (voq_set_ecn != nullptr) {
        la_counter_set* voq_counter_set_ecn = nullptr;
        size_t size_ecn = 0;

        status = voq_set_ecn->get_counter(type, size_ecn, voq_counter_set_ecn);

        for (uint64_t voq_idx = 0, voq_max = voq_set_ecn->get_set_size(); voq_idx < voq_max; voq_idx += 2) {
            size_t voq_pkts = -1, voq_bytes = -1;
            status = voq_counter_set_ecn->read(
                voq_idx, sdev->m_force_update, mode == SAI_STATS_MODE_READ_AND_CLEAR, voq_pkts, voq_bytes);
            sai_return_on_la_error(status);

            total_drop_voq_pkts += voq_pkts;
            total_drop_voq_bytes += voq_bytes;
        }
    }

    wred_dropped_pkt_cnt = total_drop_voq_pkts;
    wred_dropped_byte_cnt = total_drop_voq_bytes;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_port_stats(sai_object_id_t obj_port_id, uint32_t number_of_counters, const sai_stat_id_t* counter_ids, uint64_t* counters)
{
    return get_port_stats_ext(obj_port_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ, counters);
}

static sai_status_t
clear_port_stats(sai_object_id_t obj_port_id, uint32_t number_of_counters, const sai_stat_id_t* counter_ids)
{
    uint64_t counters[number_of_counters];
    return get_port_stats_ext(obj_port_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ_AND_CLEAR, counters);
}

static sai_status_t
clear_port_all_stats(sai_object_id_t obj_port_id)
{
    return get_port_stats_ext(obj_port_id, 0, nullptr, SAI_STATS_MODE_READ_AND_CLEAR, nullptr);
}

static sai_status_t
create_port_pool(sai_object_id_t* port_pool_id,
                 sai_object_id_t obj_switch_id,
                 uint32_t attr_count,
                 const sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
remove_port_pool(sai_object_id_t obj_port_pool_id)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
set_port_pool_attribute(sai_object_id_t obj_port_pool_id, const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_port_pool_attribute(sai_object_id_t obj_port_pool_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_port_pool_stats_ext(sai_object_id_t obj_port_pool_id,
                        uint32_t number_of_counters,
                        const sai_stat_id_t* counter_ids,
                        sai_stats_mode_t mode,
                        uint64_t* counters)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_port_pool_stats(sai_object_id_t obj_port_pool_id,
                    uint32_t number_of_counters,
                    const sai_stat_id_t* counter_ids,
                    uint64_t* counters)
{
    return get_port_pool_stats_ext(obj_port_pool_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ, counters);
}

static sai_status_t
clear_port_pool_stats(sai_object_id_t obj_port_pool_id, uint32_t number_of_counters, const sai_stat_id_t* counter_ids)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static std::string
port_serdes_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;

    if ((sai_port_serdes_attr_t)attr.id > sai_port_serdes_attr_t::SAI_PORT_SERDES_ATTR_END) {
        auto attrid = (sai_port_serdes_attr_ext_t)attr.id;

        log_message << to_string(attrid) << " ";
        log_message << to_string(attrid, attr.value) << " ";
    } else {
        auto attrid = (sai_port_serdes_attr_t)attr.id;

        log_message << to_string(attrid) << " ";
        log_message << to_string(attrid, attr.value) << " ";
    }

    return log_message.str();
}

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 6, 0)
static sai_status_t
create_port_connector(sai_object_id_t* out_port_connector_id,
                      sai_object_id_t switch_id,
                      uint32_t attr_count,
                      const sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
remove_port_connector(sai_object_id_t port_connector_id)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
set_port_connector_attribute(sai_object_id_t port_connector_id, const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_port_connector_attribute(sai_object_id_t port_connector_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
create_port_serdes(sai_object_id_t* out_port_serdes_id,
                   sai_object_id_t obj_switch_id,
                   uint32_t attr_count,
                   const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_PORT, SAI_OBJECT_TYPE_SWITCH, obj_switch_id, &port_serdes_to_string, obj_switch_id, attrs);

    // Check if port_id exists and mac_port are valid.
    sai_object_id_t port_obj_id = 0;
    get_attrs_value(SAI_PORT_SERDES_ATTR_PORT_ID, attrs, port_obj_id, true);

    port_entry pentry{};
    uint32_t port_idx;
    la_mac_port* mac_port = nullptr;
    sai_status_t sai_status = get_mac_port_by_eth_obj(port_obj_id, sdev, port_idx, pentry, mac_port);
    sai_return_on_error(sai_status);

    transaction txn;
    txn.status = LA_STATUS_SUCCESS;

    // create port_serdes_id
    uint32_t ps_idx = 0;
    txn.status = sdev->m_port_serdes.allocate_id(port_idx, ps_idx);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_port_serdes.release_id(ps_idx); });

    // create entry
    lsai_object ps_obj(SAI_OBJECT_TYPE_PORT_SERDES, la_obj.index, ps_idx);
    port_serdes_entry ps_entry{};
    ps_entry.port_oid = port_obj_id;
    txn.status = sdev->m_port_serdes.set(ps_idx, ps_entry);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_port_serdes.remove(ps_idx); });
    *out_port_serdes_id = ps_obj.object_id();

    // Setup the serdes parameters if any...
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];
    key.key.object_id = *out_port_serdes_id;
    snprintf(key_str, MAX_KEY_STR_LEN, "port_serdes 0x%0lx", *out_port_serdes_id);

    for (uint32_t i = 0; i < attr_count; i++) {
        // skip attribute that have been taken care by above creation process.

        switch (attr_list[i].id) {
        case SAI_PORT_SERDES_ATTR_PORT_ID:
            continue;
            break;
        default:
            sai_create_and_set_attribute(&key, key_str, port_serdes_attribs, port_serdes_vendor_attribs, &attr_list[i]);
            break;
        }
    }

    sai_log_info(SAI_API_PORT, "port_serdes id 0x%0lx created", *out_port_serdes_id);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_port_serdes(sai_object_id_t obj_port_serdes_id)
{
    sai_start_api(SAI_API_PORT, SAI_OBJECT_TYPE_PORT_SERDES, obj_port_serdes_id, &port_serdes_to_string, obj_port_serdes_id);

    port_serdes_entry ps_entry;
    la_status status = sdev->m_port_serdes.get(la_obj.index, ps_entry);
    sai_return_on_la_error(status, "Failed to find port_serdes_entry for object (0x%lx)", obj_port_serdes_id);

    status = sdev->m_port_serdes.remove(obj_port_serdes_id);

    return to_sai_status(status);
}

static sai_status_t
set_port_serdes_attribute(sai_object_id_t obj_port_serdes_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = obj_port_serdes_id;
    sai_start_api(SAI_API_PORT, SAI_OBJECT_TYPE_PORT_SERDES, obj_port_serdes_id, &port_serdes_to_string, obj_port_serdes_id, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "port_serdes 0x%0lx", obj_port_serdes_id);
    return sai_set_attribute(&key, key_str, port_serdes_attribs, port_serdes_vendor_attribs, attr);
}

static sai_status_t
get_port_serdes_attribute(sai_object_id_t obj_port_serdes_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = obj_port_serdes_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_PORT, SAI_OBJECT_TYPE_PORT_SERDES, obj_port_serdes_id, &port_serdes_to_string, obj_port_serdes_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "port_serdes 0x%0lx", obj_port_serdes_id);
    return sai_get_attributes(&key, key_str, port_serdes_attribs, port_serdes_vendor_attribs, attr_count, attr_list);
}
#endif

la_status
get_sys_from_sys_or_spa(sai_object_id_t obj_port, const la_system_port*& sys_port)
{
    la_status status;
    lsai_object la_port(obj_port);
    auto sdev = la_port.get_device();
    if (sdev == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (la_port.type == SAI_OBJECT_TYPE_PORT) {
        port_entry pentry{};
        status = sdev->m_ports.get(la_port.index, pentry);
        la_return_on_error(status);

        if (pentry.sys_port == nullptr) {
            sai_log_error(SAI_API_HOSTIF, "Incorrect dst port 0x%lx for bypass", obj_port);
            return LA_STATUS_EINVAL;
        }
        sys_port = pentry.sys_port;
        return LA_STATUS_SUCCESS;
    } else if (la_port.type == SAI_OBJECT_TYPE_LAG) {
        lag_entry lentry{};
        status = sdev->m_lags.get(la_port.index, lentry);
        auto it = lentry.members.begin();
        sys_port = (const la_system_port*)it->first;
        return LA_STATUS_SUCCESS;
    }
    return LA_STATUS_EINVAL;
}

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 7, 0)
sai_status_t
decrement_ttl_get(_In_ const sai_object_key_t* key,
                  _Inout_ sai_attribute_value_t* value,
                  _In_ uint32_t attr_index,
                  _Inout_ vendor_cache_t* cache,
                  void* arg)
{
    la_status status;
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();

    port_entry* pentry = sdev->m_ports.get_ptr(la_port.index);
    if (pentry == nullptr) {
        sai_log_error(SAI_API_PORT, "port does not exist 0x%lx", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    set_attr_value(SAI_PORT_ATTR_DISABLE_DECREMENT_TTL, (*value), pentry->service.disable_decrement_ttl);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
decrement_ttl_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    la_status status;
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();

    port_entry* pentry = sdev->m_ports.get_ptr(la_port.index);
    if (pentry == nullptr) {
        sai_log_error(SAI_API_PORT, "Port does not exist 0x%lx", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    bool disable_decrement_ttl = get_attr_value(SAI_PORT_ATTR_DISABLE_DECREMENT_TTL, (*value));

    la_ethernet_port* eth_port = nullptr;
    status = sai_port_get_ethernet_port(sdev, key->key.object_id, eth_port);
    sai_return_on_la_error(status);

    // According to customer's expectation as disable_decrement_ttl
    status = eth_port->set_decrement_ttl(!disable_decrement_ttl);
    sai_return_on_la_error(status);

    pentry->service.disable_decrement_ttl = disable_decrement_ttl;

    return SAI_STATUS_SUCCESS;
}
#endif
#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 6, 2)
sai_status_t
port_system_port_get(_In_ const sai_object_key_t* key,
                     _Inout_ sai_attribute_value_t* value,
                     _In_ uint32_t attr_index,
                     _Inout_ vendor_cache_t* cache,
                     void* arg)
{
    la_status status;
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();

    // Only allowed to get a system port OID for a VOQ switch
    if (!sdev->m_voq_cfg_manager->is_voq_switch()) {
        sai_log_error(
            SAI_API_PORT, "Failed to retrieve system port SAI ID for port ID %d, switch not in VOQ mode", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    port_entry pentry;
    status = sdev->m_ports.get(la_port.index, pentry);
    sai_return_on_la_error(status);

    if (pentry.sp_oid == 0) {
        sai_log_error(
            SAI_API_PORT, "Failed to retrieve system port SAI ID for port ID %d, no system port is present", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    set_attr_value(SAI_PORT_ATTR_SYSTEM_PORT, *value, pentry.sp_oid);
    return SAI_STATUS_SUCCESS;
}
#endif

sai_status_t
get_system_port_id(_In_ const sai_object_key_t* key,
                   _Inout_ sai_attribute_value_t* value,
                   _In_ uint32_t attr_index,
                   _Inout_ vendor_cache_t* cache,
                   void* arg)
{
    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();

    port_entry* pentry;
    la_status status = sdev->m_ports.get_ptr(la_port.index, pentry);
    sai_return_on_la_error(status);

    set_attr_value(SAI_PORT_ATTR_EXT_SYSTEM_PORT_ID, *value, pentry->sp_gid);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_adv_speed_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    return SAI_STATUS_NOT_SUPPORTED;
}

sai_status_t
port_adv_fec_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    return SAI_STATUS_NOT_SUPPORTED;
}

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 7, 0)
sai_status_t
port_if_type_get(_In_ const sai_object_key_t* key,
                 _Inout_ sai_attribute_value_t* value,
                 _In_ uint32_t attr_index,
                 _Inout_ vendor_cache_t* cache,
                 void* arg)
{
    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();

    port_entry* pentry;
    la_status status = sdev->m_ports.get_ptr(la_port.index, pentry);
    sai_return_on_la_error(status);

    set_attr_value(SAI_PORT_ATTR_INTERFACE_TYPE, (*value), pentry->if_type);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_if_type_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_port(key->key.object_id);
    auto sdev = la_port.get_device();

    port_entry* pentry;
    la_status status = sdev->m_ports.get_ptr(la_port.index, pentry);
    sai_return_on_la_error(status);

    pentry->if_type = get_attr_value(SAI_PORT_ATTR_INTERFACE_TYPE, (*value));
    return SAI_STATUS_SUCCESS;
}

constexpr uint32_t
lanes_speed_media(size_t lanes, uint32_t speed, sai_port_media_type_t media)
{
    // the combination will be unqiue for each case because speed is in Mbps and starting at 10,000
    return speed + (lanes << 4) + media;
}

sai_status_t
port_adv_if_type_get(_In_ const sai_object_key_t* key,
                     _Inout_ sai_attribute_value_t* value,
                     _In_ uint32_t attr_index,
                     _Inout_ vendor_cache_t* cache,
                     void* arg)
{
    port_entry pentry{};
    uint32_t port_idx;
    std::shared_ptr<lsai_device> sdev;
    la_mac_port* mac_port = nullptr;
    sai_status_t sai_status = get_mac_port_by_eth_obj(key->key.object_id, sdev, port_idx, pentry, mac_port);
    sai_return_on_error(sai_status);

    la_mac_port::port_speed_e la_speed;
    la_status status = mac_port->get_speed(la_speed);
    sai_return_on_la_error(status);
    uint32_t speed = sdk_to_sai_speed(la_speed); // in Mbps

    auto cur_setting = lanes_speed_media(mac_port->get_num_of_serdes(), speed, pentry.media_type);
    std::vector<sai_port_interface_type_t> if_types;

    switch (cur_setting) {
    // If SAI_PORT_MEDIA_TYPE_NOT_PRESENT, it can be PCB or Backplane
    case lanes_speed_media(1, 10000, SAI_PORT_MEDIA_TYPE_NOT_PRESENT):
    case lanes_speed_media(1, 25000, SAI_PORT_MEDIA_TYPE_NOT_PRESENT):
    case lanes_speed_media(1, 50000, SAI_PORT_MEDIA_TYPE_NOT_PRESENT):
        // KR as Cu-Backplane or PCB routing.
        if_types = {SAI_PORT_INTERFACE_TYPE_KR};
        break;
    case lanes_speed_media(2, 40000, SAI_PORT_MEDIA_TYPE_NOT_PRESENT):
    case lanes_speed_media(2, 50000, SAI_PORT_MEDIA_TYPE_NOT_PRESENT):
    case lanes_speed_media(2, 100000, SAI_PORT_MEDIA_TYPE_NOT_PRESENT):
        if_types = {SAI_PORT_INTERFACE_TYPE_KR2};
        break;
    case lanes_speed_media(4, 40000, SAI_PORT_MEDIA_TYPE_NOT_PRESENT):
    case lanes_speed_media(4, 100000, SAI_PORT_MEDIA_TYPE_NOT_PRESENT):
    case lanes_speed_media(4, 200000, SAI_PORT_MEDIA_TYPE_NOT_PRESENT):
        if_types = {SAI_PORT_INTERFACE_TYPE_KR4};
        break;
    case lanes_speed_media(1, 10000, SAI_PORT_MEDIA_TYPE_COPPER):
    case lanes_speed_media(1, 25000, SAI_PORT_MEDIA_TYPE_COPPER):
    case lanes_speed_media(1, 50000, SAI_PORT_MEDIA_TYPE_COPPER):
        // CR can be Direct Attach Copper.
        if_types = {SAI_PORT_INTERFACE_TYPE_CR};
        break;
    case lanes_speed_media(2, 40000, SAI_PORT_MEDIA_TYPE_COPPER):
    case lanes_speed_media(2, 50000, SAI_PORT_MEDIA_TYPE_COPPER):
    case lanes_speed_media(2, 100000, SAI_PORT_MEDIA_TYPE_COPPER):
        if_types = {SAI_PORT_INTERFACE_TYPE_CR2};
        break;
    case lanes_speed_media(4, 40000, SAI_PORT_MEDIA_TYPE_COPPER):
    case lanes_speed_media(4, 100000, SAI_PORT_MEDIA_TYPE_COPPER):
    case lanes_speed_media(4, 200000, SAI_PORT_MEDIA_TYPE_COPPER):
        if_types = {SAI_PORT_INTERFACE_TYPE_CR4};
        break;
    case lanes_speed_media(1, 10000, SAI_PORT_MEDIA_TYPE_FIBER):
    case lanes_speed_media(1, 25000, SAI_PORT_MEDIA_TYPE_FIBER):
    case lanes_speed_media(1, 50000, SAI_PORT_MEDIA_TYPE_FIBER):
        // Fiber Optic Short/Long Range
        if_types = {SAI_PORT_INTERFACE_TYPE_SR, SAI_PORT_INTERFACE_TYPE_LR};
        break;
    case lanes_speed_media(2, 40000, SAI_PORT_MEDIA_TYPE_FIBER):
    case lanes_speed_media(2, 50000, SAI_PORT_MEDIA_TYPE_FIBER):
    case lanes_speed_media(2, 100000, SAI_PORT_MEDIA_TYPE_FIBER):
        if_types = {SAI_PORT_INTERFACE_TYPE_SR2};
        break;
    case lanes_speed_media(4, 40000, SAI_PORT_MEDIA_TYPE_FIBER):
    case lanes_speed_media(4, 100000, SAI_PORT_MEDIA_TYPE_FIBER):
    case lanes_speed_media(4, 200000, SAI_PORT_MEDIA_TYPE_FIBER):
        if_types = {SAI_PORT_INTERFACE_TYPE_SR4, SAI_PORT_INTERFACE_TYPE_LR4};
        break;
    default:
        if_types = {SAI_PORT_INTERFACE_TYPE_NONE};
        break;
    }

    return fill_sai_list(if_types.begin(), if_types.end(), value->s32list);
}

sai_status_t
port_adv_if_type_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    return SAI_STATUS_NOT_SUPPORTED;
}
#endif

const sai_port_api_t port_api = {
    create_port,
    remove_port,
    set_port_attribute,
    get_port_attribute,
    get_port_stats,
    get_port_stats_ext,
    clear_port_stats,
    clear_port_all_stats,
    create_port_pool,
    remove_port_pool,
    set_port_pool_attribute,
    get_port_pool_attribute,
    get_port_pool_stats,
    get_port_pool_stats_ext,
    clear_port_pool_stats,
#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 6, 0)
    create_port_connector,
    remove_port_connector,
    set_port_connector_attribute,
    get_port_connector_attribute,
    create_port_serdes,
    remove_port_serdes,
    set_port_serdes_attribute,
    get_port_serdes_attribute,
#endif
};
} // namespace sai
} // namespace silicon_one
