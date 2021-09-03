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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cinttypes>

#include "api/npu/la_ac_profile.h"
#include "api/qos/la_egress_qos_profile.h"
#include "api/qos/la_ingress_qos_profile.h"
#include "api/system/la_device.h"
#include "api/system/la_l2_punt_destination.h"
#include "api/system/la_log.h"
#include "api/system/la_pci_port.h"
#include "api/system/la_recycle_port.h"
#include "api/system/la_flow_cache_handler.h"
#include "api/tm/la_ifg_scheduler.h"
#include "api/tm/la_unicast_tc_profile.h"
#include "common/math_utils.h"
#include "common/transaction.h"
#include "sai_device.h"
#include "sai_logger.h"
#include "sai_config_parser.h"
#include <stdio.h>
#include <string.h>
#include "sai_qos.h"
#include "sai_pfc.h"
#include "sai_switch.h"
#include "sai_acl.h"
#include <algorithm>
#include <fstream>
#include <iterator>
#include "sai_debug_shell.h"
extern "C" {
#include "sai_attr_ext.h"
}
#include "sai_version.h"
#include "sai_system_port.h"

using namespace std;

#define MACRO_AS_STRING(s) #s
#define STRINGIFY(s) MACRO_AS_STRING(s)

sai_version_t
get_sai_sdk_version()
{
    sai_version_t version;
    version.sai_sdk_version = la_get_version_string();
    version.ocp_sai_version = get_sai_version();
    return version;
}

const char*
get_sai_version()
{
    return STRINGIFY(SAI_VERSION);
}

#ifdef ENABLE_SERIALIZATION
namespace cereal
{
// This is automatically generated in serialization cpp file, so must forward declare
void cereal_gen_set_serialization_version_sai(unsigned int);
}
#endif

namespace silicon_one
{
namespace sai
{

#define MAX_SWITCH 10
obj_db<std::shared_ptr<lsai_device>> switches{SAI_OBJECT_TYPE_SWITCH, MAX_SWITCH};
// For testing SAI only warm boot
static la_device* s_la_device_ptr = nullptr;

la_device*
get_la_device(uint32_t sw_id)
{
    std::shared_ptr<lsai_device>* sai_dev = switches.get_ptr(sw_id);
    return (*sai_dev)->m_dev;
}

std::vector<uint32_t>
get_sai_switch_id_list()
{
    std::vector<uint32_t> object_id_list;

    std::transform(switches.map().begin(),
                   switches.map().end(),
                   std::back_inserter(object_id_list),
                   [](std::pair<const uint32_t, std::shared_ptr<lsai_device>> x) { return x.first; });

    return object_id_list;
}

void
set_one_la_logging(sai_log_level_t log_level, uint32_t sw_id)
{
    la_logger_level_e leaba_level = sai_log_level_to_leaba(log_level);
    printf("setting SDK log level to %d\n", (int)leaba_level);
    la_set_logging_level(sw_id, la_logger_component_e::API, leaba_level);
    la_set_logging_level(sw_id, la_logger_component_e::NPLAPI, leaba_level);
    la_set_logging_level(sw_id, la_logger_component_e::HLD, leaba_level);
    la_set_logging_level(sw_id, la_logger_component_e::TABLES, leaba_level);
    la_set_logging_level(sw_id, la_logger_component_e::RA, leaba_level);
    la_set_logging_level(sw_id, la_logger_component_e::LLD, leaba_level);
    la_set_logging_level(sw_id, la_logger_component_e::ACCESS, leaba_level);
}

void
set_all_la_logging(sai_log_level_t log_level)
{
    for (auto it : switches.map()) {
        auto sw = it.second;
        lsai_object la_sw(sw->m_switch_id);
        set_one_la_logging(log_level, la_sw.index);
    }
}

sai_status_t
get_device_freq(std::shared_ptr<lsai_device> sdev, _Inout_ int& device_freq)
{
    la_status status = sdev->m_dev->get_int_property(la_device_property_e::DEVICE_FREQUENCY, device_freq);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t switch_get_available_values(_In_ const sai_object_key_t* key,
                                                _Inout_ sai_attribute_value_t* value,
                                                _In_ uint32_t attr_index,
                                                _Inout_ vendor_cache_t* cache,
                                                void* arg);

static sai_status_t switch_number_of_queues_get(_In_ const sai_object_key_t* key,
                                                _Inout_ sai_attribute_value_t* value,
                                                _In_ uint32_t attr_index,
                                                _Inout_ vendor_cache_t* cache,
                                                void* arg);

static sai_status_t switch_default_1q_bridge_get(_In_ const sai_object_key_t* key,
                                                 _Inout_ sai_attribute_value_t* value,
                                                 _In_ uint32_t attr_index,
                                                 _Inout_ vendor_cache_t* cache,
                                                 void* arg);

static sai_status_t switch_port_list_get(_In_ const sai_object_key_t* key,
                                         _Inout_ sai_attribute_value_t* value,
                                         _In_ uint32_t attr_index,
                                         _Inout_ vendor_cache_t* cache,
                                         void* arg);

static sai_status_t switch_cpu_port_get(_In_ const sai_object_key_t* key,
                                        _Inout_ sai_attribute_value_t* value,
                                        _In_ uint32_t attr_index,
                                        _Inout_ vendor_cache_t* cache,
                                        void* arg);

static sai_status_t switch_default_vlan_get(_In_ const sai_object_key_t* key,
                                            _Inout_ sai_attribute_value_t* value,
                                            _In_ uint32_t attr_index,
                                            _Inout_ vendor_cache_t* cache,
                                            void* arg);

static sai_status_t switch_default_vrid_get(_In_ const sai_object_key_t* key,
                                            _Inout_ sai_attribute_value_t* value,
                                            _In_ uint32_t attr_index,
                                            _Inout_ vendor_cache_t* cache,
                                            void* arg);

static sai_status_t switch_src_mac_get(_In_ const sai_object_key_t* key,
                                       _Inout_ sai_attribute_value_t* value,
                                       _In_ uint32_t attr_index,
                                       _Inout_ vendor_cache_t* cache,
                                       void* arg);

static sai_status_t switch_vxlan_get(_In_ const sai_object_key_t* key,
                                     _Inout_ sai_attribute_value_t* value,
                                     _In_ uint32_t attr_index,
                                     _Inout_ vendor_cache_t* cache,
                                     void* arg);

static sai_status_t switch_port_number_get(_In_ const sai_object_key_t* key,
                                           _Inout_ sai_attribute_value_t* value,
                                           _In_ uint32_t attr_index,
                                           _Inout_ vendor_cache_t* cache,
                                           void* arg);

static sai_status_t switch_acl_minimum_priority_get(_In_ const sai_object_key_t* key,
                                                    _Inout_ sai_attribute_value_t* value,
                                                    _In_ uint32_t attr_index,
                                                    _Inout_ vendor_cache_t* cache,
                                                    void* arg);

static sai_status_t switch_acl_maximum_priority_get(_In_ const sai_object_key_t* key,
                                                    _Inout_ sai_attribute_value_t* value,
                                                    _In_ uint32_t attr_index,
                                                    _Inout_ vendor_cache_t* cache,
                                                    void* arg);

static sai_status_t switch_acl_stage_capability(_In_ const sai_object_key_t* key,
                                                _Inout_ sai_attribute_value_t* value,
                                                _In_ uint32_t attr_index,
                                                _Inout_ vendor_cache_t* cache,
                                                void* arg);

static sai_status_t switch_available_acl(_In_ const sai_object_key_t* key,
                                         _Inout_ sai_attribute_value_t* value,
                                         _In_ uint32_t attr_index,
                                         _Inout_ vendor_cache_t* cache,
                                         void* arg);

static sai_status_t switch_max_values_get(_In_ const sai_object_key_t* key,
                                          _Inout_ sai_attribute_value_t* value,
                                          _In_ uint32_t attr_index,
                                          _Inout_ vendor_cache_t* cache,
                                          void* arg);

static sai_status_t switch_default_trap_group_get(_In_ const sai_object_key_t* key,
                                                  _Inout_ sai_attribute_value_t* value,
                                                  _In_ uint32_t attr_index,
                                                  _Inout_ vendor_cache_t* cache,
                                                  void* arg);

static sai_status_t switch_restart_warm_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t switch_restart_warm_get(_In_ const sai_object_key_t* key,
                                            _Inout_ sai_attribute_value_t* value,
                                            _In_ uint32_t attr_index,
                                            _Inout_ vendor_cache_t* cache,
                                            void* arg);

static sai_status_t switch_acl_entry_min_prio_get(_In_ const sai_object_key_t* key,
                                                  _Inout_ sai_attribute_value_t* value,
                                                  _In_ uint32_t attr_index,
                                                  _Inout_ vendor_cache_t* cache,
                                                  void* arg);

static sai_status_t switch_acl_entry_max_prio_get(_In_ const sai_object_key_t* key,
                                                  _Inout_ sai_attribute_value_t* value,
                                                  _In_ uint32_t attr_index,
                                                  _Inout_ vendor_cache_t* cache,
                                                  void* arg);

static sai_status_t switch_ecmp_default_hash_seed_get(_In_ const sai_object_key_t* key,
                                                      _Inout_ sai_attribute_value_t* value,
                                                      _In_ uint32_t attr_index,
                                                      _Inout_ vendor_cache_t* cache,
                                                      void* arg);

static sai_status_t switch_profile_id_get(_In_ const sai_object_key_t* key,
                                          _Inout_ sai_attribute_value_t* value,
                                          _In_ uint32_t attr_index,
                                          _Inout_ vendor_cache_t* cache,
                                          void* arg);

static sai_status_t switch_lag_default_hash_seed_get(_In_ const sai_object_key_t* key,
                                                     _Inout_ sai_attribute_value_t* value,
                                                     _In_ uint32_t attr_index,
                                                     _Inout_ vendor_cache_t* cache,
                                                     void* arg);

static sai_status_t switch_init_get(_In_ const sai_object_key_t* key,
                                    _Inout_ sai_attribute_value_t* value,
                                    _In_ uint32_t attr_index,
                                    _Inout_ vendor_cache_t* cache,
                                    void* arg);

static sai_status_t switch_hardware_info_get(_In_ const sai_object_key_t* key,
                                             _Inout_ sai_attribute_value_t* value,
                                             _In_ uint32_t attr_index,
                                             _Inout_ vendor_cache_t* cache,
                                             void* arg);

static sai_status_t switch_fdb_aging_time_get(_In_ const sai_object_key_t* key,
                                              _Inout_ sai_attribute_value_t* value,
                                              _In_ uint32_t attr_index,
                                              _Inout_ vendor_cache_t* cache,
                                              void* arg);

static sai_status_t switch_default_trap_group_set(_In_ const sai_object_key_t* key,
                                                  _In_ const sai_attribute_value_t* value,
                                                  void* arg);

static sai_status_t switch_src_mac_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t switch_mirror_attr_get(_In_ const sai_object_key_t* key,
                                           _Inout_ sai_attribute_value_t* value,
                                           _In_ uint32_t attr_index,
                                           _Inout_ vendor_cache_t* cache,
                                           void* arg);

static sai_status_t switch_mirror_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t switch_vxlan_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t switch_notifications_cb_set(_In_ const sai_object_key_t* key,
                                                _In_ const sai_attribute_value_t* value,
                                                void* arg);

static sai_status_t switch_shell_enable_get(_In_ const sai_object_key_t* key,
                                            _Inout_ sai_attribute_value_t* value,
                                            _In_ uint32_t attr_index,
                                            _Inout_ vendor_cache_t* cache,
                                            void* arg);

static sai_status_t switch_notifications_cb_get(_In_ const sai_object_key_t* key,
                                                _Inout_ sai_attribute_value_t* value,
                                                _In_ uint32_t attr_index,
                                                _Inout_ vendor_cache_t* cache,
                                                void* arg);

static sai_status_t switch_shell_enable_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t switch_ecmp_default_hash_seed_set(_In_ const sai_object_key_t* key,
                                                      _In_ const sai_attribute_value_t* value,
                                                      void* arg);

static sai_status_t switch_lag_default_hash_seed_set(_In_ const sai_object_key_t* key,
                                                     _In_ const sai_attribute_value_t* value,
                                                     void* arg);
static sai_status_t switch_fdb_aging_time_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t switch_ecmp_hash_algorithm_get(_In_ const sai_object_key_t* key,
                                                   _Inout_ sai_attribute_value_t* value,
                                                   _In_ uint32_t attr_index,
                                                   _Inout_ vendor_cache_t* cache,
                                                   void* arg);

static sai_status_t switch_ecmp_hash_algorithm_set(_In_ const sai_object_key_t* key,
                                                   _In_

                                                   const sai_attribute_value_t* value,
                                                   void* arg);
static sai_status_t switch_tam_object_id_get(_In_ const sai_object_key_t* key,
                                             _Inout_ sai_attribute_value_t* value,
                                             _In_ uint32_t attr_index,
                                             _Inout_ vendor_cache_t* cache,
                                             void* arg);
static sai_status_t switch_tam_object_id_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
static sai_status_t switch_max_acl_action_count_get(_In_ const sai_object_key_t* key,
                                                    _Inout_ sai_attribute_value_t* value,
                                                    _In_ uint32_t attr_index,
                                                    _Inout_ vendor_cache_t* cache,
                                                    void* arg);
static sai_status_t switch_ecmp_hash_get(_In_ const sai_object_key_t* key,
                                         _Inout_ sai_attribute_value_t* value,
                                         _In_ uint32_t attr_index,
                                         _Inout_ vendor_cache_t* cache,
                                         void* arg);
static sai_status_t switch_lag_hash_get(_In_ const sai_object_key_t* key,
                                        _Inout_ sai_attribute_value_t* value,
                                        _In_ uint32_t attr_index,
                                        _Inout_ vendor_cache_t* cache,
                                        void* arg);
static sai_status_t switch_extended_acl_table_field_list_get(_In_ const sai_object_key_t* key,
                                                             _Inout_ sai_attribute_value_t* value,
                                                             _In_ uint32_t attr_index,
                                                             _Inout_ vendor_cache_t* cache,
                                                             void* arg);
static sai_status_t switch_ingress_acl_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
static sai_status_t switch_egress_acl_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
static sai_status_t switch_ingress_acl_get(_In_ const sai_object_key_t* key,
                                           _Inout_ sai_attribute_value_t* value,
                                           _In_ uint32_t attr_index,
                                           _Inout_ vendor_cache_t* cache,
                                           void* arg);
static sai_status_t switch_egress_acl_get(_In_ const sai_object_key_t* key,
                                          _Inout_ sai_attribute_value_t* value,
                                          _In_ uint32_t attr_index,
                                          _Inout_ vendor_cache_t* cache,
                                          void* arg);

static sai_status_t switch_route_dst_meta_data_range_get(_In_ const sai_object_key_t* key,
                                                         _Inout_ sai_attribute_value_t* value,
                                                         _In_ uint32_t attr_index,
                                                         _Inout_ vendor_cache_t* cache,
                                                         void* arg);
static sai_status_t switch_neighbor_dst_meta_data_range_get(_In_ const sai_object_key_t* key,
                                                            _Inout_ sai_attribute_value_t* value,
                                                            _In_ uint32_t attr_index,
                                                            _Inout_ vendor_cache_t* cache,
                                                            void* arg);
static sai_status_t switch_max_temp_sensors_get(_In_ const sai_object_key_t* key,
                                                _Inout_ sai_attribute_value_t* value,
                                                _In_ uint32_t attr_index,
                                                _Inout_ vendor_cache_t* cache,
                                                void* arg);

static sai_status_t switch_temp_sensors_value_get(_In_ const sai_object_key_t* key,
                                                  _Inout_ sai_attribute_value_t* value,
                                                  _In_ uint32_t attr_index,
                                                  _Inout_ vendor_cache_t* cache,
                                                  void* arg);

static sai_status_t switch_voq_attr_get(_In_ const sai_object_key_t* key,
                                        _Inout_ sai_attribute_value_t* value,
                                        _In_ uint32_t attr_index,
                                        _Inout_ vendor_cache_t* cache,
                                        void* arg);

static sai_status_t switch_system_port_list_get(_In_ const sai_object_key_t* key,
                                                _Inout_ sai_attribute_value_t* value,
                                                _In_ uint32_t attr_index,
                                                _Inout_ vendor_cache_t* cache,
                                                void* arg);

static sai_status_t switch_number_of_system_ports_get(_In_ const sai_object_key_t* key,
                                                      _Inout_ sai_attribute_value_t* value,
                                                      _In_ uint32_t attr_index,
                                                      _Inout_ vendor_cache_t* cache,
                                                      void* arg);

static sai_status_t switch_max_temp_value_get(_In_ const sai_object_key_t* key,
                                              _Inout_ sai_attribute_value_t* value,
                                              _In_ uint32_t attr_index,
                                              _Inout_ vendor_cache_t* cache,
                                              void* arg);

static sai_status_t switch_avg_temp_value_get(_In_ const sai_object_key_t* key,
                                              _Inout_ sai_attribute_value_t* value,
                                              _In_ uint32_t attr_index,
                                              _Inout_ vendor_cache_t* cache,
                                              void* arg);

static sai_status_t switch_warm_restart_pre_shutdown_set(_In_ const sai_object_key_t* key,
                                                         _In_ const sai_attribute_value_t* value,
                                                         void* arg);

static sai_status_t switch_fdb_dst_meta_data_range_get(_In_ const sai_object_key_t* key,
                                                       _Inout_ sai_attribute_value_t* value,
                                                       _In_ uint32_t attr_index,
                                                       _Inout_ vendor_cache_t* cache,
                                                       void* arg);

static sai_status_t switch_ecn_ect_enable_get(_In_ const sai_object_key_t* key,
                                              _Inout_ sai_attribute_value_t* value,
                                              _In_ uint32_t attr_index,
                                              _Inout_ vendor_cache_t* cache,
                                              void* arg);

static sai_status_t switch_ecn_ect_enable_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t switch_ecc_err_initiate_set(_In_ const sai_object_key_t* key,
                                                _In_ const sai_attribute_value_t* value,
                                                void* arg);

static sai_status_t switch_counter_refresh_interval_set(_In_ const sai_object_key_t* key,
                                                        _In_ const sai_attribute_value_t* value,
                                                        void* arg);

static sai_status_t switch_counter_refresh_interval_get(_In_ const sai_object_key_t* key,
                                                        _Inout_ sai_attribute_value_t* value,
                                                        _In_ uint32_t attr_index,
                                                        _Inout_ vendor_cache_t* cache,
                                                        void* arg);

static sai_status_t switch_miss_packet_action_set(_In_ const sai_object_key_t* key,
                                                  _In_ const sai_attribute_value_t* value,
                                                  void* arg);

static sai_status_t switch_miss_packet_action_get(_In_ const sai_object_key_t* key,
                                                  _Inout_ sai_attribute_value_t* value,
                                                  _In_ uint32_t attr_index,
                                                  _Inout_ vendor_cache_t* cache,
                                                  void* arg);

// clang-format off
extern const sai_attribute_entry_t switch_attribs[]
       // id, mandatory_on_create, valid_for_create, valid_for_set, valid_for_get, attrib_name, type
    = {{SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS, false, false, false, true, "SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS: Switch ports number", SAI_ATTR_VAL_TYPE_U32},
       {SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID, false, false, false, true, "SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID: Switch Default Virtual Router ID", SAI_ATTR_VAL_TYPE_OID},
       {SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID, false, false, false, true, "SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID: Default .1Q Bridge ID", SAI_ATTR_VAL_TYPE_OID},
       {SAI_SWITCH_ATTR_DEFAULT_VLAN_ID, false, false, false, true, "SAI_SWITCH_ATTR_DEFAULT_VLAN_ID: Default SAI VLAN ID", SAI_ATTR_VAL_TYPE_OID},
       {SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY, false, true, true, true, "SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY: Switch state change notification callback", SAI_ATTR_VAL_TYPE_PTR},
       {SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY, false, true, true, true, "SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY: Shutdown req notification callback", SAI_ATTR_VAL_TYPE_PTR},
       {SAI_SWITCH_ATTR_FDB_EVENT_NOTIFY, false, true, true, true, "SAI_SWITCH_ATTR_FDB_EVENT_NOTIFY: FDB event notification callback", SAI_ATTR_VAL_TYPE_PTR},
       {SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY, false, true, true, true, "SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY: Port state change notification callback", SAI_ATTR_VAL_TYPE_PTR},
       {SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY, false, true, true, true, "SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY: Packet event notification callback", SAI_ATTR_VAL_TYPE_PTR},
       {SAI_SWITCH_ATTR_TAM_EVENT_NOTIFY, false, true, true, true, "SAI_SWITCH_ATTR_TAM_EVENT_NOTIFY:  Telemetry event notification callback", SAI_ATTR_VAL_TYPE_PTR},
       {SAI_SWITCH_ATTR_SRC_MAC_ADDRESS, false, true, true, true, "SAI_SWITCH_ATTR_SRC_MAC_ADDRESS: Switch source MAC address", SAI_ATTR_VAL_TYPE_MAC},
       {SAI_SWITCH_ATTR_CPU_PORT, false, false, false, true, "SAI_SWITCH_ATTR_CPU_PORT: Switch CPU port", SAI_ATTR_VAL_TYPE_OID},
       {SAI_SWITCH_ATTR_PORT_LIST, false, false, false, true, "SAI_SWITCH_ATTR_PORT_LIST: Switch ports list", SAI_ATTR_VAL_TYPE_OBJLIST},
       {SAI_SWITCH_ATTR_QOS_DOT1P_TO_TC_MAP, false, true, true, true, "SAI_SWITCH_ATTR_QOS_DOT1P_TO_TC_MAP: Switch dot1p to tc QOS map", SAI_ATTR_VAL_TYPE_OID},
       {SAI_SWITCH_ATTR_QOS_DOT1P_TO_COLOR_MAP, false, true, true, true, "SAI_SWITCH_ATTR_QOS_DOT1P_TO_COLOR_MAP: Switch dot1p to color QOS map", SAI_ATTR_VAL_TYPE_OID},
       {SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP, false, true, true, true, "SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP: Switch DSCP to tc QOS map", SAI_ATTR_VAL_TYPE_OID},
       {SAI_SWITCH_ATTR_QOS_DSCP_TO_COLOR_MAP, false, true, true, true, "SAI_SWITCH_ATTR_QOS_DSCP_TO_COLOR_MAP: Switch DSCP to color QOS map", SAI_ATTR_VAL_TYPE_OID},
       {SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP, false, true, true, true, "SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP: Switch TC to queue QOS map", SAI_ATTR_VAL_TYPE_OID},
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
       {SAI_SWITCH_ATTR_QOS_MPLS_EXP_TO_TC_MAP, false, true, true, true, "SAI_SWITCH_ATTR_QOS_MPLS_EXP_TO_TC_MAP: Switch MPLS to tc QOS map", SAI_ATTR_VAL_TYPE_OID},
       {SAI_SWITCH_ATTR_QOS_MPLS_EXP_TO_COLOR_MAP, false, true, true, true, "SAI_SWITCH_ATTR_QOS_MPLS_EXP_TO_COLOR_MAP: Switch MPLS to color QOS map", SAI_ATTR_VAL_TYPE_OID},
#endif
       {SAI_SWITCH_ATTR_ACL_TABLE_MINIMUM_PRIORITY, false, false, false, true, "Minimum priority for ACL table.", SAI_ATTR_VAL_TYPE_U32},
       {SAI_SWITCH_ATTR_ACL_TABLE_MAXIMUM_PRIORITY, false, false, false, true, "Maximum priority for ACL table.", SAI_ATTR_VAL_TYPE_U32},
       {SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE, false, false, false, true, "Available ACL Tables", SAI_ATTR_VAL_TYPE_ACLRESOURCE},
       {SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE_GROUP, false, false, false, true, "Available ACL Tables", SAI_ATTR_VAL_TYPE_ACLRESOURCE},
       {SAI_SWITCH_ATTR_MIRROR_TC, false, true, true, true, "Default TC values for mirror packets", SAI_ATTR_VAL_TYPE_U8},
       {SAI_SWITCH_ATTR_ACL_STAGE_INGRESS, false, false, false, true, "Ingress ACL Stage", SAI_ATTR_VAL_TYPE_ACLCAPABILITY},
       {SAI_SWITCH_ATTR_ACL_STAGE_EGRESS, false, false, false, true, "Egress ACL Stage", SAI_ATTR_VAL_TYPE_ACLCAPABILITY},
       {SAI_SWITCH_ATTR_QUEUE_PFC_DEADLOCK_NOTIFY, false, true, true, true, "PFC deadlock notification", SAI_ATTR_VAL_TYPE_PTR },
       {SAI_SWITCH_ATTR_PFC_DLR_PACKET_ACTION, false, true, true, true, "PFC deadlock recovery action", SAI_ATTR_VAL_TYPE_S32 },
       {SAI_SWITCH_ATTR_PFC_TC_DLD_INTERVAL_RANGE, false, false, false, true, "PFC TC DLD interval range", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_PFC_TC_DLD_INTERVAL, false, true, true, true, "PFC TC DLD interval", SAI_ATTR_VAL_TYPE_MAPLIST },
       {SAI_SWITCH_ATTR_PFC_TC_DLR_INTERVAL_RANGE, false, false, false, true, "PFC TC DLR interval range", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_PFC_TC_DLR_INTERVAL, false, true, true, true, "PFC TC DLR interval", SAI_ATTR_VAL_TYPE_MAPLIST },
       {SAI_SWITCH_ATTR_NUMBER_OF_ECMP_GROUPS, false, false, false, true, "SAI_SWITCH_ATTR_NUMBER_OF_ECMP_GROUPS: ECMP number of group", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_ECMP_MEMBERS, false, false, false, true, "SAI_SWITCH_ATTR_ECMP_MEMBERS: ECMP number of members per group", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_DEFAULT_TRAP_GROUP, false, false, true, true, "SAI_SWITCH_ATTR_DEFAULT_TRAP_GROUP: Switch default trap group", SAI_ATTR_VAL_TYPE_OID },
       {SAI_SWITCH_ATTR_RESTART_WARM, false, true, true, true, "SAI_SWITCH_ATTR_RESTART_WARM: Is restart warm", SAI_ATTR_VAL_TYPE_BOOL},
       {SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY, false, false, false, true, "SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY: Switch ACL entry min prio", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_ACL_ENTRY_MAXIMUM_PRIORITY, false, false, false, true, "SAI_SWITCH_ATTR_ACL_ENTRY_MAXIMUM_PRIORITY: Switch ACL entry max prio", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_SWITCH_SHELL_ENABLE, false, false, true, true, "SAI_SWITCH_ATTR_SWITCH_SHELL_ENABLE: Enable vendor specific switch shell", SAI_ATTR_VAL_TYPE_BOOL},
       {SAI_SWITCH_ATTR_SWITCH_PROFILE_ID, false, true, false, true, "SAI_SWITCH_ATTR_SWITCH_PROFILE_ID: Handle for switch profile id", SAI_ATTR_VAL_TYPE_U32},
       {SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED, false, false, true, true, "SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED: Switch ECMP hash seed", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_SEED, false, true, true, true, "SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_SEED: Switch lag hash seed value", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_FDB_AGING_TIME, false, true, true, true, "SAI_SWITCH_ATTR_FDB_AGING_TIME: Switch fdb aging time", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_AVAILABLE_IPV4_ROUTE_ENTRY, false, false, false, true, "SAI_SWITCH_ATTR_AVAILABLE_IPV4_ROUTE_ENTRY: Get available free IPv4 Route Entries", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_AVAILABLE_IPV6_ROUTE_ENTRY, false, false, false, true, "SAI_SWITCH_ATTR_AVAILABLE_IPV4_ROUTE_ENTRY: Get available free IPv6 Route Entries", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEXTHOP_ENTRY, false, false, false, true, "SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEXTHOP_ENTRY: Get available IPv4 NextHop Entries", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEXTHOP_ENTRY, false, false, false, true, "SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEXTHOP_ENTRY: Get available IPv6 NextHop Entries", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEIGHBOR_ENTRY, false, false, false, true, "SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEIGHBOR_ENTRY: Get available IPv4 Neighbor Entries", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEIGHBOR_ENTRY, false, false, false, true, "SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEIGHBOR_ENTRY: Get available IPv6 Neighbor Entries", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_MEMBER_ENTRY, false, false, false, true, "SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_MEMBER_ENTRY: Get available NextHop Group Mbr Entries", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_ENTRY, false, false, false, true, "SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_ENTRY: Get available NextHop Group Objects", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_AVAILABLE_FDB_ENTRY, false, false, false, true, "SAI_SWITCH_ATTR_AVAILABLE_FDB_ENTRY: Get available FDB Entries", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES, false, false, false, true, "SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES: Number of Unicast Queues", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES, false, false, false, true, "SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES: Number of Multicast Queues", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_NUMBER_OF_QUEUES, false, false, false, true, "SAI_SWITCH_ATTR_NUMBER_OF_QUEUES: Total Number of Queues", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_NUMBER_OF_CPU_QUEUES, false, false, false, true, "SAI_SWITCH_ATTR_NUMBER_OF_CPU_QUEUES: The number of CPU Queues", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_ALGORITHM, false, false, true, true, "SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_ALGORITHM: Switch ECMP hash algorithm", SAI_ATTR_VAL_TYPE_S32 },
       {SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_ALGORITHM, false, false, true, true, "SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_ALGORITHM: Switch ECMP hash algorithm", SAI_ATTR_VAL_TYPE_S32 },
       {SAI_SWITCH_ATTR_TAM_OBJECT_ID, false, true, true, true, "SAI_SWITCH_ATTR_TAM_OBJECT_ID: TAM OBJECT ID", SAI_ATTR_VAL_TYPE_OBJLIST},
       {SAI_SWITCH_ATTR_MAX_ACL_ACTION_COUNT, false, false, false, true, "SAI_SWITCH_ATTR_MAX_ACL_ACTION_COUNT: ACL COUNT", SAI_ATTR_VAL_TYPE_U32},
       {SAI_SWITCH_ATTR_ECMP_HASH, false, false, true, true, "SAI_SWITCH_ATTR_ECMP_HASH: Switch ECMP hash", SAI_ATTR_VAL_TYPE_OID },
       {SAI_SWITCH_ATTR_ECMP_HASH_IPV4, false, false, true, true, "SAI_SWITCH_ATTR_ECMP_HASH: Switch ECMP hash", SAI_ATTR_VAL_TYPE_OID },
       {SAI_SWITCH_ATTR_ECMP_HASH_IPV6, false, false, true, true, "SAI_SWITCH_ATTR_ECMP_HASH: Switch ECMP hash", SAI_ATTR_VAL_TYPE_OID },
       {SAI_SWITCH_ATTR_LAG_HASH, false, false, true, true, "SAI_SWITCH_ATTR_LAG_HASH: Switch LAG hash", SAI_ATTR_VAL_TYPE_OID },
       {SAI_SWITCH_ATTR_VXLAN_DEFAULT_PORT, false, true, true, true, "SAI_SWITCH_ATTR_VXLAN_DEFAULT_PORT: Default VXLAN destination UDP port", SAI_ATTR_VAL_TYPE_U16 },
       {SAI_SWITCH_ATTR_VXLAN_DEFAULT_ROUTER_MAC, false, true, true, true, "SAI_SWITCH_ATTR_VXLAN_DEFAULT_ROUTER_MAC: Default VXLAN router MAC", SAI_ATTR_VAL_TYPE_MAC},
       {SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, false, true, false, true, "SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST: Switch ACL table match fields", SAI_ATTR_VAL_TYPE_U32LIST},
       {SAI_SWITCH_ATTR_INGRESS_ACL, false, true, true, true, "SAI_SWITCH_ATTR_INGRESS_ACL: Switch Ingress ACL", SAI_ATTR_VAL_TYPE_OID},
       {SAI_SWITCH_ATTR_EGRESS_ACL, false, true, true, true, "SAI_SWITCH_ATTR_EGRESS_ACL: Switch Egress ACL", SAI_ATTR_VAL_TYPE_OID},
       {SAI_SWITCH_ATTR_ROUTE_DST_USER_META_DATA_RANGE, false, false, false, true, "SAI_SWITCH_ATTR_ROUTE_DST_USER_META_DATA_RANGE: Switch route metadata range", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_NEIGHBOR_DST_USER_META_DATA_RANGE, false, false, false, true, "SAI_SWITCH_ATTR_NEIGHBOR_DST_USER_META_DATA_RANGE: Switch neighbor metadata range", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_FDB_DST_USER_META_DATA_RANGE, false, false, false, true, "SAI_SWITCH_ATTR_FDB_DST_USER_META_DATA_RANGE: Switch fdb metadata range", SAI_ATTR_VAL_TYPE_U32 },
       {SAI_SWITCH_ATTR_INIT_SWITCH, true, false, false, true, "SAI_SWITCH_ATTR_INIT_SWITCH: Switch init", SAI_ATTR_VAL_TYPE_BOOL },
       {SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO, true, false, false, true, "SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO: Switch hardware info", SAI_ATTR_VAL_TYPE_BOOL },
       {SAI_SWITCH_ATTR_MAX_NUMBER_OF_TEMP_SENSORS, false, false, false, true, "SAI_SWITCH_ATTR_MAX_NUMBER_OF_TEMP_SENSORS: Number of Temperature Sensors", SAI_ATTR_VAL_TYPE_U8},
       {SAI_SWITCH_ATTR_TEMP_LIST, false, false, false, true, "SAI_SWITCH_ATTR_TEMP_LIST: List of Temperature Sensors values", SAI_ATTR_VAL_TYPE_S32LIST},
       {SAI_SWITCH_ATTR_ECN_ECT_THRESHOLD_ENABLE, false, true, true, true, "SAI_SWITCH_ATTR_ECN_ECT_THRESHOLD_ENABLE: Apply ECN thresholds for ECT traffic", SAI_ATTR_VAL_TYPE_BOOL},
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
       {SAI_SWITCH_ATTR_TYPE, false, true, false, true, "SAI_SWITCH_ATTR_TYPE: Switch type", SAI_ATTR_VAL_TYPE_SWITCHTYPE},
       {SAI_SWITCH_ATTR_SWITCH_ID, false, true, false, true, "SAI_SWITCH_ATTR_SWITCH_ID: Switch ID for distributed switch systems", SAI_ATTR_VAL_TYPE_U32},
       {SAI_SWITCH_ATTR_MAX_SYSTEM_CORES, false, true, false, true, "SAI_SWITCH_ATTR_MAX_SYSTEM_CORES: Maximum number of cores in the VOQ System (chassis)", SAI_ATTR_VAL_TYPE_U32},
       {SAI_SWITCH_ATTR_SYSTEM_PORT_CONFIG_LIST, false, true, false, true, "SAI_SWITCH_ATTR_SYSTEM_PORT_CONFIG_LIST: System ports to create", SAI_ATTR_VAL_TYPE_SYSPORTCONFIGLIST},
       {SAI_SWITCH_ATTR_NUMBER_OF_SYSTEM_PORTS, false, false, false, true, "SAI_SWITCH_ATTR_NUMBER_OF_SYSTEM_PORTS: Number of SAI system ports", SAI_ATTR_VAL_TYPE_U32},
       {SAI_SWITCH_ATTR_SYSTEM_PORT_LIST, false, false, false, true, "SAI_SWITCH_ATTR_SYSTEM_PORT_LIST: System port SAI object IDs", SAI_ATTR_VAL_TYPE_OBJLIST},
#endif
       {SAI_SWITCH_ATTR_MAX_TEMP, false, false, false, true, "SAI_SWITCH_ATTR_MAX_TEMP: Highest of Temperature Sensors", SAI_ATTR_VAL_TYPE_S32},
       {SAI_SWITCH_ATTR_AVERAGE_TEMP, false, false, false, true, "SAI_SWITCH_ATTR_AVERAGE_TEMP: Average of Temperature Sensors", SAI_ATTR_VAL_TYPE_S32},
       {SAI_SWITCH_ATTR_EXT_HW_ECC_ERROR_INITIATE, false, false, true, false, "HW ECC Error Initiate Controls", SAI_ATTR_VAL_TYPE_U16},
       {SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL, false, true, true, true, "SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL: Counter refresh interval", SAI_ATTR_VAL_TYPE_U32},
       {SAI_SWITCH_ATTR_PRE_SHUTDOWN, false, false, true, false, "SAI_SWITCH_ATTR_PRE_SHUTDOWN: Execute switch warm-reboot pre-shutdown", SAI_ATTR_VAL_TYPE_BOOL},
       {SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION, false, true, true, true, "SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION: Flood control for unknown destination packets", SAI_ATTR_VAL_TYPE_S32},
       {SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION, false, true, true, true, "SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION: Broadcast miss packet action", SAI_ATTR_VAL_TYPE_S32},
       {SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION, false, true, true, true, "SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION: Multicast miss packet action", SAI_ATTR_VAL_TYPE_S32},
       {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t switch_vendor_attribs[] = {
    {SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS,
     {false, false, false, true},
     {false, false, false, true},
     switch_port_number_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID,
     {false, false, false, true},
     {false, false, false, true},
     switch_default_vrid_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID,
     {false, false, false, true},
     {false, false, false, true},
     switch_default_1q_bridge_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_DEFAULT_VLAN_ID,
     {false, false, false, true},
     {false, false, false, true},
     switch_default_vlan_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY,
     {true, false, true, false},
     {true, false, true, false},
     switch_notifications_cb_get, (void*)SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY, switch_notifications_cb_set, (void*)SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY},

    {SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY,
     {true, false, true, false},
     {true, false, true, false},
     switch_notifications_cb_get, (void*)SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY, switch_notifications_cb_set, (void*)SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY},

    {SAI_SWITCH_ATTR_FDB_EVENT_NOTIFY,
     {true, false, true, false},
     {true, false, true, false},
     switch_notifications_cb_get, (void*)SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY, switch_notifications_cb_set, (void*)SAI_SWITCH_ATTR_FDB_EVENT_NOTIFY},

    {SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY,
     {true, false, true, false},
     {true, false, true, false},
     switch_notifications_cb_get, (void*)SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY, switch_notifications_cb_set, (void*)SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY},

    {SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY,
     {true, false, true, false},
     {true, false, true, false},
     switch_notifications_cb_get, (void*)SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY, switch_notifications_cb_set, (void*)SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY},

    {SAI_SWITCH_ATTR_TAM_EVENT_NOTIFY,
     {true, false, true, false},
     {true, false, true, false},
     switch_notifications_cb_get, (void*)SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY, switch_notifications_cb_set, (void*)SAI_SWITCH_ATTR_TAM_EVENT_NOTIFY},

    {SAI_SWITCH_ATTR_SRC_MAC_ADDRESS,
     {true, false, true, true},
     {true, false, true, true},
     switch_src_mac_get, nullptr, switch_src_mac_set, nullptr},

    {SAI_SWITCH_ATTR_CPU_PORT,
     {false, false, false, true},
     {false, false, false, true},
     switch_cpu_port_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_PORT_LIST,
     {false, false, false, true},
     {false, false, false, true},
     switch_port_list_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_QOS_DOT1P_TO_TC_MAP,
     {true, false, true, true},
     {true, false, true, true},
     lasai_qos::switch_attr_qos_map_get,
     (void*)SAI_SWITCH_ATTR_QOS_DOT1P_TO_TC_MAP,
     lasai_qos::switch_attr_qos_map_set,
     (void*)SAI_QOS_MAP_TYPE_DOT1P_TO_TC},

    {SAI_SWITCH_ATTR_QOS_DOT1P_TO_COLOR_MAP,
     {true, false, true, true},
     {true, false, true, true},
     lasai_qos::switch_attr_qos_map_get,
     (void*)SAI_SWITCH_ATTR_QOS_DOT1P_TO_COLOR_MAP,
     lasai_qos::switch_attr_qos_map_set,
     (void*)SAI_QOS_MAP_TYPE_DOT1P_TO_COLOR},

    {SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP,
     {true, false, true, true},
     {true, false, true, true},
     lasai_qos::switch_attr_qos_map_get,
     (void*)SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP,
     lasai_qos::switch_attr_qos_map_set,
     (void*)SAI_QOS_MAP_TYPE_DSCP_TO_TC},

    {SAI_SWITCH_ATTR_QOS_DSCP_TO_COLOR_MAP,
     {true, false, true, true},
     {true, false, true, true},
     lasai_qos::switch_attr_qos_map_get,
     (void*)SAI_SWITCH_ATTR_QOS_DSCP_TO_COLOR_MAP,
     lasai_qos::switch_attr_qos_map_set,
     (void*)SAI_QOS_MAP_TYPE_DSCP_TO_COLOR},

    {SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP,
     {true, false, true, true},
     {true, false, true, true},
     lasai_qos::switch_attr_tc_map_get, nullptr,
     lasai_qos::switch_attr_tc_map_set, nullptr},

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    {SAI_SWITCH_ATTR_QOS_MPLS_EXP_TO_TC_MAP,
     {true, false, true, true},
     {true, false, true, true},
     lasai_qos::switch_attr_qos_map_get,
     (void*)SAI_SWITCH_ATTR_QOS_MPLS_EXP_TO_TC_MAP,
     lasai_qos::switch_attr_qos_map_set,
     (void*)SAI_QOS_MAP_TYPE_MPLS_EXP_TO_TC},

    {SAI_SWITCH_ATTR_QOS_MPLS_EXP_TO_COLOR_MAP,
     {true, false, true, true},
     {true, false, true, true},
     lasai_qos::switch_attr_qos_map_get,
     (void*)SAI_SWITCH_ATTR_QOS_MPLS_EXP_TO_COLOR_MAP,
     lasai_qos::switch_attr_qos_map_set,
     (void*)SAI_QOS_MAP_TYPE_MPLS_EXP_TO_COLOR},
#endif

    {SAI_SWITCH_ATTR_ACL_TABLE_MINIMUM_PRIORITY,
     {false, false, false, true},
     {false, false, false, true},
     switch_acl_minimum_priority_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_ACL_TABLE_MAXIMUM_PRIORITY,
     {false, false, false, true},
     {false, false, false, true},
     switch_acl_maximum_priority_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE,
     {false, false, false, true},
     {false, false, false, true},
     switch_available_acl, (void*)SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE, nullptr, nullptr},

    {SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE_GROUP,
     {false, false, false, true},
     {false, false, false, true},
     switch_available_acl, (void*)SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE_GROUP, nullptr, nullptr},

    {SAI_SWITCH_ATTR_MIRROR_TC,
     { true, false, true, true },
     { true, false, true, true },
     switch_mirror_attr_get, (void*)SAI_SWITCH_ATTR_MIRROR_TC,
     switch_mirror_attr_set, (void*)SAI_SWITCH_ATTR_MIRROR_TC},

    {SAI_SWITCH_ATTR_ACL_STAGE_INGRESS,
     {false, false, false, true},
     {false, false, false, true},
     switch_acl_stage_capability, (void*)SAI_SWITCH_ATTR_ACL_STAGE_INGRESS, nullptr, nullptr},

    {SAI_SWITCH_ATTR_ACL_STAGE_EGRESS,
     {false, false, false, true},
     {false, false, false, true},
     switch_acl_stage_capability, (void*)SAI_SWITCH_ATTR_ACL_STAGE_EGRESS, nullptr, nullptr},

    {SAI_SWITCH_ATTR_QUEUE_PFC_DEADLOCK_NOTIFY,
     {true, false, true, false},
     {true, false, true, false},
     switch_notifications_cb_get, (void*)SAI_SWITCH_ATTR_QUEUE_PFC_DEADLOCK_NOTIFY,
     switch_notifications_cb_set, (void*)SAI_SWITCH_ATTR_QUEUE_PFC_DEADLOCK_NOTIFY},

    {SAI_SWITCH_ATTR_PFC_DLR_PACKET_ACTION,
     {true, false, true, true},
     {true, false, true, true},
     lasai_pfc_base::switch_pfc_dlr_packet_action_get, nullptr,
     lasai_pfc_base::switch_pfc_dlr_packet_action_set, nullptr},

    {SAI_SWITCH_ATTR_PFC_TC_DLD_INTERVAL_RANGE,
     {false, false, false, true},
     {false, false, false, true},
     lasai_pfc_base::switch_pfc_tc_dld_interval_range_get, nullptr,
     nullptr, nullptr},

    {SAI_SWITCH_ATTR_PFC_TC_DLD_INTERVAL,
     {true, false, true, true},
     {true, false, true, true},
     lasai_pfc_base::switch_pfc_tc_dld_interval_get, nullptr,
     lasai_pfc_base::switch_pfc_tc_dld_interval_set, nullptr},

    {SAI_SWITCH_ATTR_PFC_TC_DLR_INTERVAL_RANGE,
     {false, false, false, true},
     {false, false, false, true},
     lasai_pfc_base::switch_pfc_tc_dlr_interval_range_get, nullptr,
     nullptr, nullptr},

    {SAI_SWITCH_ATTR_PFC_TC_DLR_INTERVAL,
     {true, false, true, true},
     {true, false, true, true},
     lasai_pfc_base::switch_pfc_tc_dlr_interval_get, nullptr,
     lasai_pfc_base::switch_pfc_tc_dlr_interval_set, nullptr},

    {SAI_SWITCH_ATTR_NUMBER_OF_ECMP_GROUPS,
      { false, false, false, true },
      { false, false, false, true },
      switch_max_values_get, (void*)SAI_SWITCH_ATTR_NUMBER_OF_ECMP_GROUPS, nullptr, nullptr },

    {SAI_SWITCH_ATTR_ECMP_MEMBERS,
      { false, false, false, true },
      { false, false, false, true },
      switch_max_values_get, (void*)SAI_SWITCH_ATTR_ECMP_MEMBERS, nullptr, nullptr },

    {SAI_SWITCH_ATTR_DEFAULT_TRAP_GROUP,
      { false, false, true, true },
      { false, false, true, true },
      switch_default_trap_group_get, nullptr, switch_default_trap_group_set, nullptr },

    {SAI_SWITCH_ATTR_RESTART_WARM,
     { true, false, true, true },
     { true, false, true, true },
     switch_restart_warm_get, nullptr, switch_restart_warm_set, nullptr },

    {SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY,
      { false, false, false, true },
      { false, false, false, true },
      switch_acl_entry_min_prio_get, nullptr, nullptr, nullptr },

    {SAI_SWITCH_ATTR_ACL_ENTRY_MAXIMUM_PRIORITY,
      { false, false, false, true },
      { false, false, false, true },
      switch_acl_entry_max_prio_get, nullptr, nullptr, nullptr },

    {SAI_SWITCH_ATTR_SWITCH_SHELL_ENABLE,
      { false, false, true, true },
      { false, false, true, true },
      switch_shell_enable_get, nullptr, switch_shell_enable_set, nullptr },

    {SAI_SWITCH_ATTR_SWITCH_PROFILE_ID,
      { true, false, false, true },
      { true, false, false, true },
       switch_profile_id_get, nullptr, nullptr, nullptr },

    {SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED,
      { true, false, true, true },
      { true, false, true, true },
      switch_ecmp_default_hash_seed_get, nullptr, switch_ecmp_default_hash_seed_set, nullptr},

    {SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_SEED,
      { true, false, true, true },
      { true, false, true, true },
      switch_lag_default_hash_seed_get, nullptr, switch_lag_default_hash_seed_set, nullptr},

    {SAI_SWITCH_ATTR_FDB_AGING_TIME,
      { true, false, true, true },
      { true, false, true, true },
      switch_fdb_aging_time_get, nullptr, switch_fdb_aging_time_set, nullptr},

    {SAI_SWITCH_ATTR_AVAILABLE_IPV4_ROUTE_ENTRY,
      { false, false, false, true },
      { false, false, false, true },
      switch_get_available_values, (void*)SAI_SWITCH_ATTR_AVAILABLE_IPV4_ROUTE_ENTRY,
      nullptr, nullptr },

    {SAI_SWITCH_ATTR_AVAILABLE_IPV6_ROUTE_ENTRY,
      { false, false, false, true },
      { false, false, false, true },
      switch_get_available_values, (void*)SAI_SWITCH_ATTR_AVAILABLE_IPV6_ROUTE_ENTRY,
      nullptr, nullptr },

    {SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEXTHOP_ENTRY,
      { false, false, false, true },
      { false, false, false, true },
      switch_get_available_values, (void*)SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEXTHOP_ENTRY,
      nullptr, nullptr },

    {SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEXTHOP_ENTRY,
      { false, false, false, true },
      { false, false, false, true },
      switch_get_available_values, (void*)SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEXTHOP_ENTRY,
      nullptr, nullptr },

    {SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEIGHBOR_ENTRY,
      { false, false, false, true },
      { false, false, false, true },
      switch_get_available_values, (void*)SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEIGHBOR_ENTRY,
      nullptr, nullptr },

    {SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEIGHBOR_ENTRY,
      { false, false, false, true },
      { false, false, false, true },
      switch_get_available_values, (void*)SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEIGHBOR_ENTRY,
      nullptr, nullptr },

    {SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_MEMBER_ENTRY,
      { false, false, false, true },
      { false, false, false, true },
      switch_get_available_values, (void*)SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_MEMBER_ENTRY,
      nullptr, nullptr },

    {SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_ENTRY,
      { false, false, false, true },
      { false, false, false, true },
      switch_get_available_values, (void*)SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_ENTRY,
      nullptr, nullptr },

    {SAI_SWITCH_ATTR_AVAILABLE_FDB_ENTRY,
      { false, false, false, true },
      { false, false, false, true },
      switch_get_available_values, (void*)SAI_SWITCH_ATTR_AVAILABLE_FDB_ENTRY,
      nullptr, nullptr },

    {SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES,
      { false, false, false, true },
      { false, false, false, true },
      switch_number_of_queues_get, (void*)SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES,
      nullptr, nullptr },

    {SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES,
      { false, false, false, true },
      { false, false, false, true },
      switch_number_of_queues_get, (void*)SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES,
      nullptr, nullptr },

    {SAI_SWITCH_ATTR_NUMBER_OF_QUEUES,
      { false, false, false, true },
      { false, false, false, true },
      switch_number_of_queues_get, (void*)SAI_SWITCH_ATTR_NUMBER_OF_QUEUES,
      nullptr, nullptr },

    {SAI_SWITCH_ATTR_NUMBER_OF_CPU_QUEUES,
      { false, false, false, true },
      { false, false, false, true },
      switch_number_of_queues_get, (void*)SAI_SWITCH_ATTR_NUMBER_OF_CPU_QUEUES,
      nullptr, nullptr },

    {SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_ALGORITHM,
      { false, false, true, true },
      { false, false, true, true },
      switch_ecmp_hash_algorithm_get, NULL,
      switch_ecmp_hash_algorithm_set, NULL },

    {SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_ALGORITHM,
      { false, false, true, true },
      { false, false, true, true },
      switch_ecmp_hash_algorithm_get, NULL,
      switch_ecmp_hash_algorithm_set, NULL },

    {SAI_SWITCH_ATTR_TAM_OBJECT_ID,
     {true, false, true, true},
     {true, false, true, true},
     switch_tam_object_id_get, nullptr, switch_tam_object_id_set, nullptr},

    {SAI_SWITCH_ATTR_MAX_ACL_ACTION_COUNT,
     {false, false, false, true},
     {false, false, false, true},
     switch_max_acl_action_count_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_ECMP_HASH,
     {false, false, false, true},
     {false, false, false, true},
     switch_ecmp_hash_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_ECMP_HASH_IPV4,
     {false, false, false, true},
     {false, false, false, true},
     switch_ecmp_hash_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_ECMP_HASH_IPV6,
     {false, false, false, true},
     {false, false, false, true},
     switch_ecmp_hash_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_LAG_HASH,
     {false, false, false, true},
     {false, false, false, true},
     switch_lag_hash_get, nullptr, nullptr, nullptr},

    { SAI_SWITCH_ATTR_VXLAN_DEFAULT_PORT,
      { true, false, true, true },
      { true, false, true, true },
      switch_vxlan_get, (void *)SAI_SWITCH_ATTR_VXLAN_DEFAULT_PORT,
      switch_vxlan_set, (void *)SAI_SWITCH_ATTR_VXLAN_DEFAULT_PORT},

    { SAI_SWITCH_ATTR_VXLAN_DEFAULT_ROUTER_MAC,
      { true, false, true, true },
      { true, false, true, true },
      switch_vxlan_get, (void *)SAI_SWITCH_ATTR_VXLAN_DEFAULT_ROUTER_MAC,
      switch_vxlan_set, (void *)SAI_SWITCH_ATTR_VXLAN_DEFAULT_ROUTER_MAC },

    {SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST,
     {true, false, false, true},
     {true, false, false, true},
     switch_extended_acl_table_field_list_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_INGRESS_ACL,
     {true, false, true, true},
     {true, false, true, true},
     switch_ingress_acl_get, (void*)SAI_SWITCH_ATTR_INGRESS_ACL, switch_ingress_acl_set, (void*)SAI_SWITCH_ATTR_INGRESS_ACL},

    {SAI_SWITCH_ATTR_EGRESS_ACL,
     {true, false, true, true},
     {true, false, true, true},
     switch_egress_acl_get, (void*)SAI_SWITCH_ATTR_EGRESS_ACL, switch_egress_acl_set, (void*)SAI_SWITCH_ATTR_EGRESS_ACL},

    {SAI_SWITCH_ATTR_ROUTE_DST_USER_META_DATA_RANGE,
     {false, false, false, true},
     {false, false, false, true},
     switch_route_dst_meta_data_range_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_NEIGHBOR_DST_USER_META_DATA_RANGE,
     {false, false, false, true},
     {false, false, false, true},
     switch_neighbor_dst_meta_data_range_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_FDB_DST_USER_META_DATA_RANGE,
     {false, false, false, true},
     {false, false, false, true},
     switch_fdb_dst_meta_data_range_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_INIT_SWITCH,
     {false, false, false, true},
     {false, false, false, true},
     switch_init_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO,
     {false, false, false, true},
     {false, false, false, true},
     switch_hardware_info_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_MAX_NUMBER_OF_TEMP_SENSORS,
     {false, false, false, true},
     {false, false, false, true},
     switch_max_temp_sensors_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_TEMP_LIST,
     {false, false, false, true},
     {false, false, false, true},
     switch_temp_sensors_value_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_ECN_ECT_THRESHOLD_ENABLE,
     {true, false, true, true },
     {true, false, true, true },
     switch_ecn_ect_enable_get, nullptr, switch_ecn_ect_enable_set, nullptr },

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    {SAI_SWITCH_ATTR_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     switch_voq_attr_get, (void*)SAI_SWITCH_ATTR_TYPE, nullptr, nullptr},

    {SAI_SWITCH_ATTR_SWITCH_ID,
     {true, false, false, true},
     {true, false, false, true},
     switch_voq_attr_get, (void*)SAI_SWITCH_ATTR_SWITCH_ID, nullptr, nullptr},

    {SAI_SWITCH_ATTR_MAX_SYSTEM_CORES,
     {true, false, false, true},
     {true, false, false, true},
     switch_voq_attr_get, (void*)SAI_SWITCH_ATTR_MAX_SYSTEM_CORES, nullptr, nullptr},

    {SAI_SWITCH_ATTR_SYSTEM_PORT_CONFIG_LIST,
     {true, false, false, true},
     {true, false, false, true},
     switch_voq_attr_get, (void*)SAI_SWITCH_ATTR_SYSTEM_PORT_CONFIG_LIST, nullptr, nullptr},

    {SAI_SWITCH_ATTR_NUMBER_OF_SYSTEM_PORTS,
     {false, false, false, true},
     {false, false, false, true},
     switch_number_of_system_ports_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_SYSTEM_PORT_LIST,
     {false, false, false, true},
     {false, false, false, true},
     switch_system_port_list_get, nullptr, nullptr, nullptr},
#endif

    {SAI_SWITCH_ATTR_MAX_TEMP,
     {false, false, false, true},
     {false, false, false, true},
     switch_max_temp_value_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_AVERAGE_TEMP,
     {false, false, false, true},
     {false, false, false, true},
     switch_avg_temp_value_get, nullptr, nullptr, nullptr},

    {SAI_SWITCH_ATTR_EXT_HW_ECC_ERROR_INITIATE,
      {false, false, true, false},
      {false, false, true, false},
      nullptr, nullptr, switch_ecc_err_initiate_set, nullptr},

    {SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL,
     {false, false, true, true},
     {false, false, true, true},
     switch_counter_refresh_interval_get, nullptr, switch_counter_refresh_interval_set,  (void*)SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL},

    {SAI_SWITCH_ATTR_PRE_SHUTDOWN,
     {false, false, true, false},
     {false, false, true, false},
     nullptr, nullptr, switch_warm_restart_pre_shutdown_set, nullptr},

    {SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION,
     {false, false, true, true},
     {false, false, true, true},
     switch_miss_packet_action_get, (void*)SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION, switch_miss_packet_action_set,  (void*)SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION},

    {SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION,
     {false, false, true, true},
     {false, false, true, true},
     switch_miss_packet_action_get, (void*)SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION, switch_miss_packet_action_set,  (void*)SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION},

    {SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION,
     {false, false, true, true},
     {false, false, true, true},
     switch_miss_packet_action_get, (void*)SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION, switch_miss_packet_action_set,  (void*)SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION},
};
// clang-format on

sai_status_t
laobj_db_switch::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    *count = 1;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_switch::get_object_keys(std::shared_ptr<lsai_device> sdev, uint32_t* object_count, sai_object_key_t* object_list) const
{
    lsai_object sw_obj(SAI_OBJECT_TYPE_SWITCH, sdev->m_switch_id, sdev->m_switch_id);

    uint32_t requested_object_count = *object_count;
    *object_count = 1;

    if (requested_object_count < 1) {
        return SAI_STATUS_BUFFER_OVERFLOW;
    } else {
        object_list[0].key.object_id = sw_obj.object_id();
    }

    return SAI_STATUS_SUCCESS;
}

static int
get_int_from_profile(const char* key)
{
    int ret = 0;
    const char* s;

    s = g_sai_service_method.profile_get_value(0, key);
    if (s != NULL) {
        ret = strtol(s, NULL, 10);
    } else {
        ret = 0;
    }

    return ret;
}

static sai_status_t
add_cpu_port_to_floodset(_In_ std::shared_ptr<lsai_device>& sdev, _In_ la_switch* bridge)
{
    uint16_t gid = bridge->get_gid();

    auto it = sdev->m_cpu_l2_port_map.find(gid);
    if (it == sdev->m_cpu_l2_port_map.end()) {
        sai_log_error(SAI_API_SWITCH, "No l2 cpu port created for switch index 0x%x", gid);
        return SAI_STATUS_FAILURE;
    }

    la_l2_service_port* l2_port = it->second.l2_port;
    if (l2_port == nullptr) {
        sai_log_error(SAI_API_SWITCH, "No l2 cpu port created for switch index 0x%x", gid);
        return SAI_STATUS_FAILURE;
    }

    la_l2_destination* flood_destination = nullptr;
    bridge->get_flood_destination(flood_destination);
    if (flood_destination == nullptr) {
        sai_log_error(SAI_API_SWITCH, "No flood destination created for switch index 0x%x", gid);
        return SAI_STATUS_FAILURE;
    }

    auto* multicast_group = static_cast<la_l2_multicast_group*>(flood_destination);
    la_status status = multicast_group->add(l2_port, sdev->m_pci_sys_ports[lsai_device::INJECTUP_SLICE]);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_cpu_port_from_floodset(_In_ std::shared_ptr<lsai_device>& sdev, _In_ la_switch* bridge)
{
    uint16_t gid = bridge->get_gid();

    auto it = sdev->m_cpu_l2_port_map.find(gid);
    if (it == sdev->m_cpu_l2_port_map.end() || it->second.l2_port == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    la_l2_service_port* l2_port = it->second.l2_port;
    if (l2_port == nullptr) {
        sai_log_error(SAI_API_SWITCH, "No l2 cpu port created for switch index 0x%x", gid);
        return SAI_STATUS_FAILURE;
    }

    la_l2_destination* flood_destination = nullptr;
    bridge->get_flood_destination(flood_destination);
    if (flood_destination == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    auto* multicast_group = static_cast<la_l2_multicast_group*>(flood_destination);
    la_status status = multicast_group->remove(l2_port);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
miss_packet_action_is_drop(sai_packet_action_t action, bool& is_drop)
{
    switch (action) {
    case SAI_PACKET_ACTION_DROP:
    case SAI_PACKET_ACTION_DENY: {
        is_drop = true;
        break;
    }
    case SAI_PACKET_ACTION_FORWARD:
    case SAI_PACKET_ACTION_TRANSIT: {
        is_drop = false;
        break;
    }
    case SAI_PACKET_ACTION_COPY:
    case SAI_PACKET_ACTION_LOG:
    case SAI_PACKET_ACTION_COPY_CANCEL:
    case SAI_PACKET_ACTION_TRAP:
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
process_fdb_miss_action(_In_ std::shared_ptr<lsai_device>& sdev,
                        _In_ la_switch* bridge,
                        _In_ bool bridge_is_drop,
                        _In_ sai_packet_action_t new_action,
                        _In_ void* attr_name)
{

    bool is_drop = false;
    if (bridge == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    sai_status_t status = miss_packet_action_is_drop(new_action, is_drop);
    sai_return_on_error(status);

    // when sai_switch set to drop then drop all regardless.
    // when sai_switch attribute set to forward, then depending on each vlan
    // or bridge to drop or forward
    if (!is_drop) {
        is_drop = bridge_is_drop;
    }

    la_status lstatus;
    switch ((uint64_t)attr_name) {
    case SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION:
        lstatus = bridge->set_drop_unknown_uc_enabled(is_drop);
        break;
    case SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION:
        lstatus = bridge->set_drop_unknown_bc_enabled(is_drop);
        break;
    case SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION:
        lstatus = bridge->set_drop_unknown_mc_enabled(is_drop);
        break;
    }
    sai_return_on_la_error(lstatus);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
process_vlan_fdb_miss_action(_In_ std::shared_ptr<lsai_device>& sdev,
                             _In_ lsai_vlan_t& lsaivlan,
                             _In_ sai_packet_action_t new_action,
                             _In_ void* attr_name)
{
    bool vlan_is_drop = false;
    switch ((uint64_t)attr_name) {
    case SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION:
        vlan_is_drop = (lsaivlan.m_ucast_flood_type == SAI_VLAN_FLOOD_CONTROL_TYPE_ALL) ? false : true;
        break;
    case SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION:
        vlan_is_drop = (lsaivlan.m_bcast_flood_type == SAI_VLAN_FLOOD_CONTROL_TYPE_ALL) ? false : true;
        break;
    case SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION:
        vlan_is_drop = (lsaivlan.m_mcast_flood_type == SAI_VLAN_FLOOD_CONTROL_TYPE_ALL) ? false : true;
        break;
    default:
        break;
    }
    return process_fdb_miss_action(sdev, lsaivlan.m_sdk_switch, vlan_is_drop, new_action, attr_name);
}

static sai_status_t
process_bridge_fdb_miss_action(_In_ std::shared_ptr<lsai_device>& sdev,
                               _In_ lsai_bridge_t& lsaibridge,
                               _In_ sai_packet_action_t new_action,
                               _In_ void* attr_name)
{
    bool bridge_is_drop = false;
    switch ((uint64_t)attr_name) {
    case SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION:
        bridge_is_drop = (lsaibridge.m_ucast_flood_type == SAI_BRIDGE_FLOOD_CONTROL_TYPE_SUB_PORTS) ? false : true;
        break;
    case SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION:
        bridge_is_drop = (lsaibridge.m_bcast_flood_type == SAI_BRIDGE_FLOOD_CONTROL_TYPE_SUB_PORTS) ? false : true;
        break;
    case SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION:
        bridge_is_drop = (lsaibridge.m_mcast_flood_type == SAI_BRIDGE_FLOOD_CONTROL_TYPE_SUB_PORTS) ? false : true;
        break;
    default:
        break;
    }
    return process_fdb_miss_action(sdev, lsaibridge.m_sdk_switch, bridge_is_drop, new_action, attr_name);
}

static sai_status_t
switch_miss_packet_action_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, _In_ void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();
    if (sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_packet_action_t new_action = SAI_PACKET_ACTION_FORWARD;

    switch ((int64_t)arg) {
    case SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION:
        new_action = get_attr_value(SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION, *value);
        sdev->m_fdb_ucast_miss_action = new_action;
        break;
    case SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION:
        new_action = get_attr_value(SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION, *value);
        sdev->m_fdb_bcast_miss_action = new_action;
        break;
    case SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION:
        new_action = get_attr_value(SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION, *value);
        sdev->m_fdb_mcast_miss_action = new_action;
        break;
    }

    sai_status_t status = SAI_STATUS_SUCCESS;

    auto vlans = sdev->m_vlans.map();
    for (auto it : vlans) {
        status = process_vlan_fdb_miss_action(sdev, it.second, new_action, arg);
        sai_return_on_error(status);
    }

    auto bridges = sdev->m_bridges.map();
    for (auto it : bridges) {
        status = process_bridge_fdb_miss_action(sdev, it.second, new_action, arg);
        sai_return_on_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_miss_packet_action_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();
    if (sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch ((int64_t)arg) {
    case SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION:
        set_attr_value(SAI_SWITCH_ATTR_FDB_UNICAST_MISS_PACKET_ACTION, *value, sdev->m_fdb_ucast_miss_action);
        break;
    case SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION:
        set_attr_value(SAI_SWITCH_ATTR_FDB_BROADCAST_MISS_PACKET_ACTION, *value, sdev->m_fdb_bcast_miss_action);
        break;
    case SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION:
        set_attr_value(SAI_SWITCH_ATTR_FDB_MULTICAST_MISS_PACKET_ACTION, *value, sdev->m_fdb_mcast_miss_action);
        break;
    default:
        break;
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_profile_id_get(_In_ const sai_object_key_t* key,
                      _Inout_ sai_attribute_value_t* value,
                      _In_ uint32_t attr_index,
                      _Inout_ vendor_cache_t* cache,
                      void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    set_attr_value(SAI_SWITCH_ATTR_SWITCH_PROFILE_ID, *value, sdev->m_switch_profile_id);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_ecmp_hash_algorithm_get(_In_ const sai_object_key_t* key,
                               _Inout_ sai_attribute_value_t* value,
                               _In_ uint32_t attr_index,
                               _Inout_ vendor_cache_t* cache,
                               void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    set_attr_value(SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_ALGORITHM, *value, sdev->m_ecmp_default_hash_algorithm);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_ecmp_hash_algorithm_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    auto hash_algorithm = get_attr_value(SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_ALGORITHM, *value);
    switch (hash_algorithm) {
    case SAI_HASH_ALGORITHM_CRC:
    case SAI_HASH_ALGORITHM_CRC_CCITT:
        sdev->m_ecmp_default_hash_algorithm = hash_algorithm;
        return SAI_STATUS_SUCCESS;
        break;
    case SAI_HASH_ALGORITHM_CRC_32LO:
    case SAI_HASH_ALGORITHM_CRC_32HI:
    case SAI_HASH_ALGORITHM_CRC_XOR:
    default:
        break;
    }
    return SAI_STATUS_NOT_SUPPORTED;
}

static sai_status_t
switch_hardware_info_get(_In_ const sai_object_key_t* key,
                         _Inout_ sai_attribute_value_t* value,
                         _In_ uint32_t attr_index,
                         _Inout_ vendor_cache_t* cache,
                         void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    if (sdev->m_hw_info_attr) {
        return fill_sai_list(sdev->m_hw_info.begin(), sdev->m_hw_info.end(), value->s8list);
    } else {
        value->s8list.count = 0;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_init_get(_In_ const sai_object_key_t* key,
                _Inout_ sai_attribute_value_t* value,
                _In_ uint32_t attr_index,
                _Inout_ vendor_cache_t* cache,
                void* arg)
{
    set_attr_value(SAI_SWITCH_ATTR_INIT_SWITCH, *value, true);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_default_1q_bridge_get(_In_ const sai_object_key_t* key,
                             _Inout_ sai_attribute_value_t* value,
                             _In_ uint32_t attr_index,
                             _Inout_ vendor_cache_t* cache,
                             void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    set_attr_value(SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID, *value, sdev->m_default_1q_bridge_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_port_number_get(_In_ const sai_object_key_t* key,
                       _Inout_ sai_attribute_value_t* value,
                       _In_ uint32_t attr_index,
                       _Inout_ vendor_cache_t* cache,
                       void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    auto mac_ports = sdev->get_mac_ports();
    set_attr_value(SAI_SWITCH_ATTR_NUMBER_OF_ACTIVE_PORTS, *value, mac_ports.size());
    return SAI_STATUS_SUCCESS;
}

enum class resource_usage_field { max, used };

sai_status_t
switch_get_resource_usage(_In_ const sai_object_key_t* key,
                          _In_ la_resource_descriptor::type_e type,
                          _In_ resource_usage_field field,
                          _Out_ uint64_t& usage)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();
    la_resource_usage_descriptor_vec vec;

    auto status = sdev->m_dev->get_resource_usage(type, vec);
    sai_return_on_la_error(status);

    usage = (field == resource_usage_field::used) ? vec[0].used : vec[0].total;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
switch_get_resource_used(_In_ const sai_object_key_t* key, _In_ la_resource_descriptor::type_e type, _Out_ uint64_t& usage)
{
    return switch_get_resource_usage(key, type, resource_usage_field::used, usage);
}

sai_status_t
switch_get_resource_max(_In_ const sai_object_key_t* key, _In_ la_resource_descriptor::type_e type, _Out_ uint64_t& max)
{
    return switch_get_resource_usage(key, type, resource_usage_field::max, max);
}

static sai_status_t
get_available_based_on_(_In_ const sai_object_key_t* key,
                        _In_ la_resource_descriptor::type_e type,
                        _In_ la_resource_descriptor::type_e type_max,
                        _Out_ uint64_t& available,
                        _Out_ uint64_t& max_val,
                        std::function<uint64_t(uint64_t, uint64_t)> get_available)
{
    uint64_t usage = 0;
    auto status = switch_get_resource_used(key, type, usage);
    sai_return_on_error(status);
    status = switch_get_resource_max(key, type_max, max_val);
    sai_return_on_error(status);
    available = get_available(usage, max_val);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_available_based_on_availability(_In_ const sai_object_key_t* key,
                                    _In_ la_resource_descriptor::type_e type,
                                    _In_ la_resource_descriptor::type_e type_max,
                                    _Out_ uint64_t& available)
{
    uint64_t max_val = 0;
    sai_return_on_error(get_available_based_on_(
        key, type, type_max, available, max_val, [](uint64_t usage, uint64_t max_val) { return max_val - usage; }));
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_available_based_on_ranged_index(_In_ const sai_object_key_t* key,
                                    _In_ la_resource_descriptor::type_e type,
                                    _In_ la_resource_descriptor::type_e type_max,
                                    _Out_ uint64_t& available,
                                    _Out_ uint64_t& max_val)
{
    sai_return_on_error(get_available_based_on_(
        key, type, type_max, available, max_val, [](uint64_t usage, uint64_t max_val) { return max_val - usage; }));
    return SAI_STATUS_SUCCESS;
}

uint64_t
available_entries(uint64_t max1, uint64_t value1, uint64_t max2, uint64_t value2)
{
    auto compare = [](uint64_t m1, uint64_t v1, uint64_t m2, uint64_t v2) {
        if (m1 > m2 && v1 > m2) {
            return v1;
        }
        return std::min(v1, v2);
    };

    if (max1 > max2) {
        return compare(max1, value1, max2, value2);
    }

    return compare(max2, value2, max1, value1);
}

static sai_status_t
switch_get_available_values(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    uint64_t avail = 0;

    switch ((int64_t)arg) {
    case SAI_SWITCH_ATTR_AVAILABLE_FDB_ENTRY:
        sai_return_on_error(get_available_based_on_availability(key,
                                                                la_resource_descriptor::type_e::MAC_FORWARDING_TABLE,
                                                                la_resource_descriptor::type_e::MAC_FORWARDING_TABLE,
                                                                avail));
        set_attr_value(SAI_SWITCH_ATTR_AVAILABLE_FDB_ENTRY, *value, avail);
        break;
    case SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEIGHBOR_ENTRY:
        sai_return_on_error(get_available_based_on_availability(key,
                                                                la_resource_descriptor::type_e::IPV4_VRF_DIP_EM_TABLE,
                                                                la_resource_descriptor::type_e::IPV4_VRF_DIP_EM_TABLE,
                                                                avail));
        set_attr_value(SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEIGHBOR_ENTRY, *value, avail);
        break;
    case SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEXTHOP_ENTRY: {
        sai_return_on_error(get_available_based_on_availability(
            key, la_resource_descriptor::type_e::NEXT_HOP, la_resource_descriptor::type_e::NEXT_HOP, avail));
        set_attr_value(SAI_SWITCH_ATTR_AVAILABLE_IPV4_NEXTHOP_ENTRY, *value, avail);
        break;
    }
    case SAI_SWITCH_ATTR_AVAILABLE_IPV4_ROUTE_ENTRY:
        sai_return_on_error(get_available_based_on_availability(
            key, la_resource_descriptor::type_e::LPM_IPV4_ROUTES, la_resource_descriptor::type_e::LPM_IPV4_ROUTES, avail));
        set_attr_value(SAI_SWITCH_ATTR_AVAILABLE_IPV4_ROUTE_ENTRY, *value, avail);
        break;
    case SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEIGHBOR_ENTRY:
        sai_return_on_error(get_available_based_on_availability(key,
                                                                la_resource_descriptor::type_e::IPV6_VRF_DIP_EM_TABLE,
                                                                la_resource_descriptor::type_e::IPV6_VRF_DIP_EM_TABLE,
                                                                avail));
        set_attr_value(SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEIGHBOR_ENTRY, *value, avail);
        break;
    case SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEXTHOP_ENTRY: {
        sai_return_on_error(get_available_based_on_availability(
            key, la_resource_descriptor::type_e::NEXT_HOP, la_resource_descriptor::type_e::NEXT_HOP, avail));
        set_attr_value(SAI_SWITCH_ATTR_AVAILABLE_IPV6_NEXTHOP_ENTRY, *value, avail);
        break;
    }
    case SAI_SWITCH_ATTR_AVAILABLE_IPV6_ROUTE_ENTRY:
        sai_return_on_error(get_available_based_on_availability(
            key, la_resource_descriptor::type_e::LPM_IPV6_ROUTES, la_resource_descriptor::type_e::LPM_IPV6_ROUTES, avail));
        set_attr_value(SAI_SWITCH_ATTR_AVAILABLE_IPV6_ROUTE_ENTRY, *value, avail);
        break;
    case SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_ENTRY: {
        uint64_t max_val1 = 0;
        sai_return_on_error(get_available_based_on_ranged_index(key,
                                                                la_resource_descriptor::type_e::STAGE1_LB_GROUP,
                                                                la_resource_descriptor::type_e::STAGE1_LB_GROUP,
                                                                avail,
                                                                max_val1));
        uint64_t avail2 = 0;
        uint64_t max_val2 = 0;
        sai_return_on_error(get_available_based_on_ranged_index(key,
                                                                la_resource_descriptor::type_e::STAGE2_LB_GROUP,
                                                                la_resource_descriptor::type_e::STAGE2_LB_GROUP,
                                                                avail2,
                                                                max_val2));
        set_attr_value(
            SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_ENTRY, *value, available_entries(max_val1, avail, max_val2, avail2));
        break;
    }
    case SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_MEMBER_ENTRY: {
        uint64_t max_val1 = 0;
        sai_return_on_error(get_available_based_on_ranged_index(key,
                                                                la_resource_descriptor::type_e::STAGE1_LB_MEMBER,
                                                                la_resource_descriptor::type_e::STAGE1_LB_MEMBER,
                                                                avail,
                                                                max_val1));

        uint64_t avail2 = 0;
        uint64_t max_val2 = 0;
        sai_return_on_error(get_available_based_on_ranged_index(key,
                                                                la_resource_descriptor::type_e::STAGE2_LB_MEMBER,
                                                                la_resource_descriptor::type_e::STAGE2_LB_MEMBER,
                                                                avail2,
                                                                max_val2));
        set_attr_value(
            SAI_SWITCH_ATTR_AVAILABLE_NEXT_HOP_GROUP_MEMBER_ENTRY, *value, available_entries(max_val1, avail, max_val2, avail2));
        break;
    }
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_max_values_get(_In_ const sai_object_key_t* key,
                      _Inout_ sai_attribute_value_t* value,
                      _In_ uint32_t attr_index,
                      _Inout_ vendor_cache_t* cache,
                      void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    switch ((int64_t)arg) {
    case SAI_SWITCH_ATTR_NUMBER_OF_ECMP_GROUPS:
        set_attr_value(SAI_SWITCH_ATTR_NUMBER_OF_ECMP_GROUPS, *value, LSAI_MAX_ECMP_GROUPS);
        return SAI_STATUS_SUCCESS;
    case SAI_SWITCH_ATTR_ECMP_MEMBERS:
        set_attr_value(SAI_SWITCH_ATTR_ECMP_MEMBERS, *value, LSAI_MAX_ECMP_GROUP_MEMBERS);
        return SAI_STATUS_SUCCESS;
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_port_list_get(_In_ const sai_object_key_t* key,
                     _Inout_ sai_attribute_value_t* value,
                     _In_ uint32_t attr_index,
                     _Inout_ vendor_cache_t* cache,
                     void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    auto mac_ports = sdev->get_mac_ports();

    std::vector<sai_object_id_t> output_vec;
    std::transform(mac_ports.begin(), mac_ports.end(), back_inserter(output_vec), [](port_entry* p) { return p->service.oid; });
    return fill_sai_list(output_vec.begin(), output_vec.end(), value->objlist);
}

static sai_status_t
switch_cpu_port_get(_In_ const sai_object_key_t* key,
                    _Inout_ sai_attribute_value_t* value,
                    _In_ uint32_t attr_index,
                    _Inout_ vendor_cache_t* cache,
                    void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    set_attr_value(SAI_SWITCH_ATTR_CPU_PORT, *value, sdev->m_pci_port_ids[lsai_device::PUNT_SLICE]);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_default_vlan_get(_In_ const sai_object_key_t* key,
                        _Inout_ sai_attribute_value_t* value,
                        _In_ uint32_t attr_index,
                        _Inout_ vendor_cache_t* cache,
                        void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    set_attr_value(SAI_SWITCH_ATTR_DEFAULT_VLAN_ID, *value, sdev->m_default_vlan_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_default_vrid_get(_In_ const sai_object_key_t* key,
                        _Inout_ sai_attribute_value_t* value,
                        _In_ uint32_t attr_index,
                        _Inout_ vendor_cache_t* cache,
                        void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    set_attr_value(SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID, *value, sdev->m_default_vrf_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_vxlan_get(_In_ const sai_object_key_t* key,
                 _Inout_ sai_attribute_value_t* value,
                 _In_ uint32_t attr_index,
                 _Inout_ vendor_cache_t* cache,
                 void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    switch ((int64_t)arg) {
    case SAI_SWITCH_ATTR_VXLAN_DEFAULT_ROUTER_MAC:
        set_mac_attr_value(SAI_SWITCH_ATTR_VXLAN_DEFAULT_ROUTER_MAC, *value, sdev->m_tunnel_manager->m_vxlan_default_router_mac);
        break;
    case SAI_SWITCH_ATTR_VXLAN_DEFAULT_PORT:
        set_attr_value(SAI_SWITCH_ATTR_VXLAN_DEFAULT_PORT, *value, sdev->m_tunnel_manager->m_vxlan_default_port);
        break;
    default:
        break;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_src_mac_get(_In_ const sai_object_key_t* key,
                   _Inout_ sai_attribute_value_t* value,
                   _In_ uint32_t attr_index,
                   _Inout_ vendor_cache_t* cache,
                   void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    set_mac_attr_value(SAI_SWITCH_ATTR_SRC_MAC_ADDRESS, *value, sdev->m_default_switch_mac);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_acl_minimum_priority_get(_In_ const sai_object_key_t* key,
                                _Inout_ sai_attribute_value_t* value,
                                _In_ uint32_t attr_index,
                                _Inout_ vendor_cache_t* cache,
                                void* arg)
{
    // Minimum allowed priority is 0.
    value->u32 = 0;
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_acl_entry_min_prio_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg)
{
    set_attr_value(SAI_SWITCH_ATTR_ACL_ENTRY_MINIMUM_PRIORITY, *value, lsai_device::SAI_ACL_ENTRY_MIN_PRIO);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_acl_maximum_priority_get(_In_ const sai_object_key_t* key,
                                _Inout_ sai_attribute_value_t* value,
                                _In_ uint32_t attr_index,
                                _Inout_ vendor_cache_t* cache,
                                void* arg)
{
    // Maximum allowed priority is UINT32_MAX.
    value->u32 = UINT32_MAX;
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_acl_entry_max_prio_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg)
{
    set_attr_value(SAI_SWITCH_ATTR_ACL_ENTRY_MAXIMUM_PRIORITY, *value, lsai_device::SAI_ACL_ENTRY_MAX_PRIO);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_acl_stage_capability(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg)
{
    sai_status_t status = SAI_STATUS_SUCCESS;

    switch (reinterpret_cast<uint64_t>(arg)) {
    case SAI_SWITCH_ATTR_ACL_STAGE_INGRESS:
        status = fill_sai_list(sai_acl::supported_ingress_acl_actions_list.begin(),
                               sai_acl::supported_ingress_acl_actions_list.end(),
                               value->aclcapability.action_list);
        break;
    case SAI_SWITCH_ATTR_ACL_STAGE_EGRESS:
        status = fill_sai_list(sai_acl::supported_egress_acl_actions_list.begin(),
                               sai_acl::supported_egress_acl_actions_list.end(),
                               value->aclcapability.action_list);
        break;
    default:
        return SAI_STATUS_INVALID_PARAMETER;
    }

    value->aclcapability.is_action_list_mandatory = false;

    return status;
}

static sai_status_t
fill_acl_resource(_In_ std::shared_ptr<lsai_device> sdev, _Inout_ sai_attribute_value_t* value, int64_t type)
{
    // Currently, number of available entries in SAI are lower than actual, so we can always use it.
    size_t remaining_elements;
    switch (type) {
    case SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE:
        remaining_elements = sdev->m_acl_handler->m_acl_table_db.get_free_space();
        break;
    case SAI_SWITCH_ATTR_AVAILABLE_ACL_TABLE_GROUP:
        remaining_elements = sdev->m_acl_handler->m_acl_table_group_db.get_free_space();
        break;
    default:
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_acl_bind_point_type_t bind_point_types[3]
        = {SAI_ACL_BIND_POINT_TYPE_PORT, SAI_ACL_BIND_POINT_TYPE_VLAN, SAI_ACL_BIND_POINT_TYPE_LAG};

    sai_acl_resource_t acl_resource[6];

    uint32_t index = 0;
    for (uint32_t i = 0; i < 3; i++) {
        uint32_t bind_point_type = bind_point_types[i];
        for (uint32_t stage = SAI_ACL_STAGE_INGRESS; stage <= SAI_ACL_STAGE_EGRESS; stage++) {
            acl_resource[index].bind_point = static_cast<sai_acl_bind_point_type_t>(bind_point_type);
            acl_resource[index].stage = static_cast<sai_acl_stage_t>(stage);
            acl_resource[index].avail_num = remaining_elements;
            index++;
        }
    }

    if (value->aclresource.count < 6) {
        sai_log_error(SAI_API_SWITCH, "ACL Resource List not enough space");
        value->aclresource.count = 6;
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    value->aclresource.count = 6;
    memcpy(value->aclresource.list, &acl_resource, 6 * sizeof(sai_acl_resource_t));
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_default_trap_group_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    set_attr_value(SAI_SWITCH_ATTR_DEFAULT_TRAP_GROUP, *value, sdev->m_trap_manager->m_default_trap_group_id);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_ecmp_default_hash_seed_get(_In_ const sai_object_key_t* key,
                                  _Inout_ sai_attribute_value_t* value,
                                  _In_ uint32_t attr_index,
                                  _Inout_ vendor_cache_t* cache,
                                  void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    la_uint16_t hash_seed = 0;
    la_status status = sdev->m_dev->get_ecmp_hash_seed(hash_seed);
    sai_return_on_la_error(status);

    set_attr_value(SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED, *value, hash_seed);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_lag_default_hash_seed_get(_In_ const sai_object_key_t* key,
                                 _Inout_ sai_attribute_value_t* value,
                                 _In_ uint32_t attr_index,
                                 _Inout_ vendor_cache_t* cache,
                                 void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    la_uint16_t hash_seed = 0;
    la_status status = sdev->m_dev->get_spa_hash_seed(hash_seed);
    sai_return_on_la_error(status);

    set_attr_value(SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_SEED, *value, hash_seed);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_fdb_aging_time_get(_In_ const sai_object_key_t* key,
                          _Inout_ sai_attribute_value_t* value,
                          _In_ uint32_t attr_index,
                          _Inout_ vendor_cache_t* cache,
                          void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    set_attr_value(SAI_SWITCH_ATTR_FDB_AGING_TIME, *value, sdev->aging_time);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_ecmp_hash_get(_In_ const sai_object_key_t* key,
                     _Inout_ sai_attribute_value_t* value,
                     _In_ uint32_t attr_index,
                     _Inout_ vendor_cache_t* cache,
                     void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    // Some value that lets caller proceeed without error.
    // TODO: can hash value be otained from SDK ?
    lsai_object oid(SAI_OBJECT_TYPE_HASH, sdev->m_switch_id, 1000);
    set_attr_value(SAI_SWITCH_ATTR_ECMP_HASH, *value, oid.object_id());
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_lag_hash_get(_In_ const sai_object_key_t* key,
                    _Inout_ sai_attribute_value_t* value,
                    _In_ uint32_t attr_index,
                    _Inout_ vendor_cache_t* cache,
                    void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    // Some value that lets caller proceeed without error.
    // TODO: can hash value be otained from SDK ?
    lsai_object oid(SAI_OBJECT_TYPE_HASH, sdev->m_switch_id, 2000);
    set_attr_value(SAI_SWITCH_ATTR_LAG_HASH, *value, oid.object_id());
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_tam_object_id_get(_In_ const sai_object_key_t* key,
                         _Inout_ sai_attribute_value_t* value,
                         _In_ uint32_t attr_index,
                         _Inout_ vendor_cache_t* cache,
                         void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    return fill_sai_list(
        sdev->m_tam_registry.begin(), sdev->m_tam_registry.end(), value->objlist, [](lsai_tam_entry_ptr i) { return i->m_oid; });
}

static sai_status_t
switch_tam_object_id_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    auto tam_obj_list = get_attr_value(SAI_SWITCH_ATTR_TAM_OBJECT_ID, (*value));

    std::vector<lsai_tam_entry_ptr> tam_entry_ptrs{};
    sai_status_t status = check_object_id_list(tam_entry_ptrs, SAI_OBJECT_TYPE_TAM, sdev, sdev->m_tam, tam_obj_list);
    sai_return_on_error(status);

    sdev->m_tam_registry.assign(tam_entry_ptrs.begin(), tam_entry_ptrs.end());

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_max_acl_action_count_get(_In_ const sai_object_key_t* key,
                                _Inout_ sai_attribute_value_t* value,
                                _In_ uint32_t attr_index,
                                _Inout_ vendor_cache_t* cache,
                                void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    set_attr_value(SAI_SWITCH_ATTR_MAX_ACL_ACTION_COUNT, *value, sai_acl::get_acl_actions_max_count());

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_extended_acl_table_field_list_get(_In_ const sai_object_key_t* key,
                                         _Inout_ sai_attribute_value_t* value,
                                         _In_ uint32_t attr_index,
                                         _Inout_ vendor_cache_t* cache,
                                         void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    auto udk_field_sets = sdev->m_acl_handler->m_acl_udk.get_udk_field_sets();
    // flatten all acl udk field sets and return as one single list of values.
    std::vector<uint32_t> flattened_acl_fields{};
    for (const auto& udk_field_set : udk_field_sets) {
        std::transform(udk_field_set.begin(), udk_field_set.end(), std::back_inserter(flattened_acl_fields), [](uint32_t attr) {
            return attr;
        });
    }
    return fill_sai_list(flattened_acl_fields.begin(), flattened_acl_fields.end(), value->u32list);
}

static sai_status_t
switch_ingress_acl_get(_In_ const sai_object_key_t* key,
                       _Inout_ sai_attribute_value_t* value,
                       _In_ uint32_t attr_index,
                       _Inout_ vendor_cache_t* cache,
                       void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    set_attr_value(SAI_SWITCH_ATTR_INGRESS_ACL, *value, sdev->switch_ingress_acl_oid);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_egress_acl_get(_In_ const sai_object_key_t* key,
                      _Inout_ sai_attribute_value_t* value,
                      _In_ uint32_t attr_index,
                      _Inout_ vendor_cache_t* cache,
                      void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    set_attr_value(SAI_SWITCH_ATTR_EGRESS_ACL, *value, sdev->switch_egress_acl_oid);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_route_dst_meta_data_range_get(_In_ const sai_object_key_t* key,
                                     _Inout_ sai_attribute_value_t* value,
                                     _In_ uint32_t attr_index,
                                     _Inout_ vendor_cache_t* cache,
                                     void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    sai_u32_range_t range;
    // Default + 1 is used because default meta data value has no impact on packet processing pipeline.
    range.min = LA_CLASS_ID_DEFAULT + 1;
    range.max = sdev->m_route_user_meta_max;
    set_attr_value(SAI_SWITCH_ATTR_ROUTE_DST_USER_META_DATA_RANGE, *value, range);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_neighbor_dst_meta_data_range_get(_In_ const sai_object_key_t* key,
                                        _Inout_ sai_attribute_value_t* value,
                                        _In_ uint32_t attr_index,
                                        _Inout_ vendor_cache_t* cache,
                                        void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    sai_u32_range_t range;
    // Default + 1 is used because default meta data value has no impact on packet processing pipeline.
    range.min = LA_CLASS_ID_DEFAULT + 1;
    range.max = sdev->m_neighbor_user_meta_max;
    set_attr_value(SAI_SWITCH_ATTR_NEIGHBOR_DST_USER_META_DATA_RANGE, *value, range);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_max_temp_sensors_get(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    // find number of temperature sensors based on device type.
    sai_uint8_t num_of_sensors = 0;
    switch (sdev->m_hw_device_type) {
    case sai::hw_device_type_e::PACIFIC:
        num_of_sensors = static_cast<sai_uint8_t>(la_temperature_sensor_e::PACIFIC_NUM_SENSORS);
        break;
    case sai::hw_device_type_e::GIBRALTAR:
        num_of_sensors = static_cast<sai_uint8_t>(la_temperature_sensor_e::GIBRALTAR_NUM_SENSORS);
        break;
    default:
        num_of_sensors = 0;
    }

    sai_log_debug(SAI_API_SWITCH, "num_of_sensors(%d) in %s", num_of_sensors, sdev->get_hw_device_type_str().c_str());

    set_attr_value(SAI_SWITCH_ATTR_MAX_NUMBER_OF_TEMP_SENSORS, *value, num_of_sensors);

    if (num_of_sensors == 0) {
        sai_return_on_error(SAI_STATUS_NOT_IMPLEMENTED, "Invalid hw_device_type_e seen in switch_max_temp_sensors_get.");
    }

    return SAI_STATUS_SUCCESS;
}

// get all temperataure sensors value to vector list.
static sai_status_t
get_all_temp_sensors_value(sai_object_id_t switch_obj_id, std::vector<int32_t>& sensors_values)
{
    lsai_object la_sw(switch_obj_id);
    auto sdev = la_sw.get_device();

    // find number of temperature sensors based on device type.
    sai_uint8_t num_of_sensors = 0;
    la_temperature_sensor_e sensor_begin;

    switch (sdev->m_hw_device_type) {
    case sai::hw_device_type_e::PACIFIC:
        num_of_sensors = static_cast<sai_uint8_t>(la_temperature_sensor_e::PACIFIC_NUM_SENSORS);
        sensor_begin = la_temperature_sensor_e::PACIFIC_FIRST;
        break;
    case sai::hw_device_type_e::GIBRALTAR:
        num_of_sensors = static_cast<sai_uint8_t>(la_temperature_sensor_e::GIBRALTAR_NUM_SENSORS);
        sensor_begin = la_temperature_sensor_e::GIBRALTAR_FIRST;
        break;
    default:
        sai_return_on_error(SAI_STATUS_NOT_IMPLEMENTED,
                            "Invalid hw_device_type_e(%s) seen in get_all_temp_sensors_value.",
                            sdev->get_hw_device_type_str().c_str());
    }
    sai_log_debug(SAI_API_SWITCH, "num_of_sensors(%d) in %s", num_of_sensors, sdev->get_hw_device_type_str().c_str());

    // add all temperature sensors value into vector
    uint32_t sensor_end = static_cast<uint32_t>(sensor_begin) + num_of_sensors;
    for (uint32_t sensor_id = static_cast<uint32_t>(sensor_begin); sensor_id < sensor_end; sensor_id++) {
        la_temperature_t temperature;
        la_status status = sdev->m_dev->get_temperature(static_cast<la_temperature_sensor_e>(sensor_id), temperature);
        // If not success, set temperature value to -273, (invalid value).
        if (status != LA_STATUS_SUCCESS) {
            temperature = INVALID_CACHED_TEMPERATURE;
        }

        sensors_values.push_back(static_cast<int32_t>(temperature));
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_temp_sensors_value_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg)
{
    // build temperature vector
    std::vector<int32_t> sensors_values{};
    sai_status_t sstatus = get_all_temp_sensors_value(key->key.object_id, sensors_values);
    sai_return_on_error(sstatus);

    return fill_sai_list(sensors_values.begin(), sensors_values.end(), value->s32list);
}

static sai_status_t
switch_voq_attr_get(_In_ const sai_object_key_t* key,
                    _Inout_ sai_attribute_value_t* value,
                    _In_ uint32_t attr_index,
                    _Inout_ vendor_cache_t* cache,
                    void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    switch ((int64_t)arg) {
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    case SAI_SWITCH_ATTR_TYPE:
        set_attr_value(SAI_SWITCH_ATTR_TYPE, *value, sdev->m_voq_cfg_manager->get_switch_type());
        break;
    case SAI_SWITCH_ATTR_SWITCH_ID: {
        // The SAI layer capabilities listing indicates this is
        // gettable regardless of switch type, so return 0 if not a
        // VOQ switch
        uint32_t switch_voq_id = 0;
        if (sdev->m_voq_cfg_manager->is_voq_switch()) {
            sai_status_t status = sdev->m_voq_cfg_manager->get_switch_voq_id(switch_voq_id);
            sai_return_on_error(status);
        }
        set_attr_value(SAI_SWITCH_ATTR_SWITCH_ID, *value, switch_voq_id);
    } break;
    case SAI_SWITCH_ATTR_SYSTEM_PORT_CONFIG_LIST: {
        if (sdev->m_voq_cfg_manager->is_voq_switch()) {
            sai_status_t status = sdev->m_voq_cfg_manager->get_system_port_config_list(value);
            sai_return_on_error(status);
        } else {
            value->sysportconfiglist.count = 0;
        }
        return SAI_STATUS_SUCCESS;
    } break;
    case SAI_SWITCH_ATTR_MAX_SYSTEM_CORES: {
        // As for switch ID, return 0 if not a VOQ switch
        uint32_t max_sys_cores = 0;
        if (sdev->m_voq_cfg_manager->is_voq_switch()) {
            sai_status_t status = sdev->m_voq_cfg_manager->get_max_system_cores(max_sys_cores);
            sai_return_on_error(status);
        }
        set_attr_value(SAI_SWITCH_ATTR_MAX_SYSTEM_CORES, *value, max_sys_cores);
    } break;
#endif
    default:
        break;
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_max_temp_value_get(_In_ const sai_object_key_t* key,
                          _Inout_ sai_attribute_value_t* value,
                          _In_ uint32_t attr_index,
                          _Inout_ vendor_cache_t* cache,
                          void* arg)
{
    // build temperature vector
    std::vector<int32_t> sensors_values{};
    sai_status_t sstatus = get_all_temp_sensors_value(key->key.object_id, sensors_values);
    sai_return_on_error(sstatus);

    auto max_temp = std::max_element(sensors_values.begin(), sensors_values.end());
    if (max_temp == sensors_values.end()) {
        sai_return_on_error(SAI_STATUS_FAILURE, "No temperature sensor is available.");
    }

    set_attr_value(SAI_SWITCH_ATTR_MAX_TEMP, *value, *max_temp);

    if (*max_temp == static_cast<int32_t>(INVALID_CACHED_TEMPERATURE)) {
        sai_log_error(SAI_API_SWITCH, "Sensors are not ready.");
    }

    return SAI_STATUS_SUCCESS;
}

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
static sai_status_t
switch_number_of_system_ports_get(_In_ const sai_object_key_t* key,
                                  _Inout_ sai_attribute_value_t* value,
                                  _In_ uint32_t attr_index,
                                  _Inout_ vendor_cache_t* cache,
                                  void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    uint32_t num_system_ports;
    sai_status_t sai_status = sdev->m_system_ports.get_object_count(sdev, &num_system_ports);
    sai_return_on_error(sai_status);

    set_attr_value(SAI_SWITCH_ATTR_NUMBER_OF_SYSTEM_PORTS, *value, num_system_ports);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_system_port_list_get(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    auto sys_ports = sdev->get_system_ports();

    std::vector<sai_object_id_t> output_vec;
    std::transform(sys_ports.begin(), sys_ports.end(), back_inserter(output_vec), [](system_port_entry* sp) { return sp->sp_oid; });
    return fill_sai_list(output_vec.begin(), output_vec.end(), value->objlist);
}
#endif

static sai_status_t
switch_avg_temp_value_get(_In_ const sai_object_key_t* key,
                          _Inout_ sai_attribute_value_t* value,
                          _In_ uint32_t attr_index,
                          _Inout_ vendor_cache_t* cache,
                          void* arg)
{
    // build temperature vector
    std::vector<int32_t> sensors_values{};
    sai_status_t sstatus = get_all_temp_sensors_value(key->key.object_id, sensors_values);
    sai_return_on_error(sstatus);

    int32_t avg_temp = 0;
    int32_t total_valid_sensors = 0; // number of valid temperature values.

    // check for valid temperature value and only accumulated the valid values.
    for (auto value : sensors_values) {
        // check for invalid.
        // Any value is <=(-273) will be dropped because of sensor read access error.
        if (value > static_cast<int32_t>(INVALID_CACHED_TEMPERATURE)) {
            avg_temp += value;
            total_valid_sensors++;
        }
    }

    if (total_valid_sensors == 0) {
        sai_return_on_error(SAI_STATUS_NOT_EXECUTED, "All temperature sensors returned invalid value.");
    }

    avg_temp = avg_temp / total_valid_sensors;

    set_attr_value(SAI_SWITCH_ATTR_AVERAGE_TEMP, *value, avg_temp);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_warm_restart_pre_shutdown_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    // Nothing to do for Leaba at this stage in the warm reboot processing.
    // Return SUCCESS to keep NOS happy.
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_available_acl(_In_ const sai_object_key_t* key,
                     _Inout_ sai_attribute_value_t* value,
                     _In_ uint32_t attr_index,
                     _Inout_ vendor_cache_t* cache,
                     void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    sai_return_on_error(fill_acl_resource(sdev, value, (int64_t)arg));

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_fdb_dst_meta_data_range_get(_In_ const sai_object_key_t* key,
                                   _Inout_ sai_attribute_value_t* value,
                                   _In_ uint32_t attr_index,
                                   _Inout_ vendor_cache_t* cache,
                                   void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    sai_u32_range_t range;
    // Default + 1 is used because default meta data value has no impact on packet processing pipeline.
    range.min = LA_CLASS_ID_DEFAULT + 1;
    range.max = sdev->m_fdb_user_meta_max;
    set_attr_value(SAI_SWITCH_ATTR_FDB_DST_USER_META_DATA_RANGE, *value, range);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_default_trap_group_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    // sdev->m_trap_manager->m_default_trap_group_id = get_attr_value(SAI_SWITCH_ATTR_DEFAULT_TRAP_GROUP, *value);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_restart_warm_get(_In_ const sai_object_key_t* key,
                        _Inout_ sai_attribute_value_t* value,
                        _In_ uint32_t attr_index,
                        _Inout_ vendor_cache_t* cache,
                        void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    set_attr_value(SAI_SWITCH_ATTR_RESTART_WARM, *value, sdev->m_restart_warm);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_restart_warm_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    sdev->m_restart_warm = get_attr_value(SAI_SWITCH_ATTR_RESTART_WARM, (*value));
    sdev->m_warm_boot_mode = (warm_boot_type_e)get_int_from_profile(SAI_KEY_EXT_WARM_BOOT_TYPE);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_ecn_ect_enable_get(_In_ const sai_object_key_t* key,
                          _Inout_ sai_attribute_value_t* value,
                          _In_ uint32_t attr_index,
                          _Inout_ vendor_cache_t* cache,
                          void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    set_attr_value(SAI_SWITCH_ATTR_ECN_ECT_THRESHOLD_ENABLE, *value, sdev->m_ecn_ect);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_ecn_ect_enable_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    sdev->m_ecn_ect = get_attr_value(SAI_SWITCH_ATTR_ECN_ECT_THRESHOLD_ENABLE, (*value));

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_src_mac_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    get_mac_attr_value(SAI_SWITCH_ATTR_SRC_MAC_ADDRESS, *value, sdev->m_default_switch_mac);

    la_mac_addr_t sw_mac;
    reverse_copy(std::begin(sdev->m_default_switch_mac), std::end(sdev->m_default_switch_mac), sw_mac.bytes);

    la_status status = sdev->m_l3_inject_up_port->set_mac(sw_mac);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_mirror_attr_get(_In_ const sai_object_key_t* key,
                       _Inout_ sai_attribute_value_t* value,
                       _In_ uint32_t attr_index,
                       _Inout_ vendor_cache_t* cache,
                       void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();
    sai_status_t status = SAI_STATUS_SUCCESS;

    switch ((int64_t)arg) {
    case SAI_SWITCH_ATTR_MIRROR_TC:
        set_attr_value(SAI_SWITCH_ATTR_MIRROR_TC, *value, sdev->m_mirror_handler->m_switch_attr_mirror_tc_val);
        break;
    default:
        sai_log_error(SAI_API_SWITCH, "Unknown switch mirror attr get %" PRIi64, (int64_t)arg);
        status = SAI_STATUS_NOT_IMPLEMENTED;
        break;
    }

    return status;
}

static sai_status_t
switch_mirror_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();
    sai_status_t status = SAI_STATUS_SUCCESS;

    switch ((int64_t)arg) {
    case SAI_SWITCH_ATTR_MIRROR_TC: {
        uint8_t tc = get_attr_value(SAI_SWITCH_ATTR_MIRROR_TC, *value);
        status = sdev->m_mirror_handler->switch_mirror_tc_attr_val_set(tc);
        sai_return_on_error_log(status, "failed to set MIRROR_TC attribute, tc %d, status %d", tc, status);
        sai_log_info(SAI_API_SWITCH, "Set Mirror TC value to %d", tc);
        break;
    }
    default:
        sai_log_error(SAI_API_SWITCH, "Unknown switch mirror attr set %" PRIi64, (int64_t)arg);
        status = SAI_STATUS_FAILURE;
        break;
    }

    return (status);
}

static sai_status_t
switch_vxlan_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    switch ((int64_t)arg) {
    case SAI_SWITCH_ATTR_VXLAN_DEFAULT_ROUTER_MAC:
        get_mac_attr_value(SAI_SWITCH_ATTR_VXLAN_DEFAULT_ROUTER_MAC, *value, sdev->m_tunnel_manager->m_vxlan_default_router_mac);
        break;
    case SAI_SWITCH_ATTR_VXLAN_DEFAULT_PORT: {
        uint16_t vxlan_port = get_attr_value(SAI_SWITCH_ATTR_VXLAN_DEFAULT_PORT, *value);
        sdev->m_tunnel_manager->m_vxlan_default_port = vxlan_port;
        la_status status = sdev->m_dev->set_vxlan_port_number(vxlan_port);
        sai_return_on_la_error_log(status, "Failed to set default Vxlan Port %d", vxlan_port);
        sai_log_info(SAI_API_SWITCH, "Set Vxlan udp port to %d", vxlan_port);
        break;
    }
    default:
        break;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_shell_enable_get(_In_ const sai_object_key_t* key,
                        _Inout_ sai_attribute_value_t* value,
                        _In_ uint32_t attr_index,
                        _Inout_ vendor_cache_t* cache,
                        void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    debug_shell* debug_shell = &debug_shell::get_instance();

    set_attr_value(SAI_SWITCH_ATTR_SWITCH_SHELL_ENABLE, *value, debug_shell->status_get());
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_shell_enable_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    bool shell_enable_status = get_attr_value(SAI_SWITCH_ATTR_SWITCH_SHELL_ENABLE, (*value));

    debug_shell* debug_shell = &debug_shell::get_instance();
    if (debug_shell->status_get() == shell_enable_status) {
        return SAI_STATUS_SUCCESS;
    }

    if (shell_enable_status) {
        // start debug shell and listen to interactive debug commands
        return debug_shell->start();
    } else {
        // stop debug shell if running and close debug command listening port.
        return debug_shell->stop();
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_notifications_cb_get(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    switch ((int64_t)arg) {
    case SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY:
        value->ptr = (void*)sdev->m_notification_callbacks.m_callbacks.on_switch_state_change;
        break;
    case SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY:
        value->ptr = (void*)sdev->m_notification_callbacks.m_callbacks.on_switch_shutdown_request;
        break;
    case SAI_SWITCH_ATTR_FDB_EVENT_NOTIFY:
        value->ptr = (void*)sdev->m_notification_callbacks.m_callbacks.on_fdb_event;
        break;
    case SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY:
        value->ptr = (void*)sdev->m_notification_callbacks.m_callbacks.on_port_state_change;
        break;
    case SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY:
        value->ptr = (void*)sdev->m_notification_callbacks.m_callbacks.on_packet_event;
        break;
    case SAI_SWITCH_ATTR_TAM_EVENT_NOTIFY:
        value->ptr = (void*)sdev->m_notification_callbacks.m_callbacks.on_tam_event;
        break;
    case SAI_SWITCH_ATTR_QUEUE_PFC_DEADLOCK_NOTIFY:
        value->ptr = (void*)sdev->m_notification_callbacks.m_callbacks.on_queue_pfc_deadlock;
        break;
    default:
        break;
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_notifications_cb_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    switch ((int64_t)arg) {
    case SAI_SWITCH_ATTR_SWITCH_STATE_CHANGE_NOTIFY:
        sdev->m_notification_callbacks.switch_state_change_cb_set((sai_switch_state_change_notification_fn)value->ptr);
        break;
    case SAI_SWITCH_ATTR_SHUTDOWN_REQUEST_NOTIFY:
        sdev->m_notification_callbacks.switch_shutdown_request_cb_set((sai_switch_shutdown_request_notification_fn)value->ptr);
        break;
    case SAI_SWITCH_ATTR_FDB_EVENT_NOTIFY:
        sdev->m_notification_callbacks.fdb_event_cb_set((sai_fdb_event_notification_fn)value->ptr);
        break;
    case SAI_SWITCH_ATTR_PORT_STATE_CHANGE_NOTIFY:
        sdev->m_notification_callbacks.port_state_change_cb_set((sai_port_state_change_notification_fn)value->ptr);
        break;
    case SAI_SWITCH_ATTR_PACKET_EVENT_NOTIFY:
        sdev->m_notification_callbacks.packet_event_cb_set((sai_packet_event_notification_fn)value->ptr);
        break;
    case SAI_SWITCH_ATTR_TAM_EVENT_NOTIFY:
        sdev->m_notification_callbacks.tam_event_cb_set((sai_tam_event_notification_fn)value->ptr);
        break;
    case SAI_SWITCH_ATTR_QUEUE_PFC_DEADLOCK_NOTIFY:
        sdev->m_notification_callbacks.queue_pfc_deadlock_cb_set((sai_queue_pfc_deadlock_notification_fn)value->ptr);
        break;
    default:
        break;
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_ecmp_default_hash_seed_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    auto hash_seed = get_attr_value(SAI_SWITCH_ATTR_ECMP_DEFAULT_HASH_SEED, *value);
    la_status status = sdev->m_dev->set_ecmp_hash_seed(hash_seed);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_lag_default_hash_seed_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    auto hash_seed = get_attr_value(SAI_SWITCH_ATTR_LAG_DEFAULT_HASH_SEED, *value);
    la_status status = sdev->m_dev->set_spa_hash_seed(hash_seed);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_fdb_aging_time_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();
    sdev->aging_time = get_attr_value(SAI_SWITCH_ATTR_FDB_AGING_TIME, *value);

    if (sdev->aging_time == 0) {
        sdev->m_dev->set_mac_aging_interval(LA_MAC_AGING_TIME_NEVER);
    } else {
        // Calculate age interval
        sdev->m_dev->set_mac_aging_interval((uint32_t)div_round_up(sdev->aging_time, 5));
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_acl_set(sai_acl_stage_t stage, sai_object_id_t acl_oid, const std::shared_ptr<lsai_device>& sdev)
{
    auto gress = (stage == SAI_ACL_STAGE_INGRESS) ? "Ingress" : "Egress";
    auto switch_acl_oid = (stage == SAI_ACL_STAGE_INGRESS) ? sdev->switch_ingress_acl_oid : sdev->switch_egress_acl_oid;
    if (switch_acl_oid != SAI_NULL_OBJECT_ID && acl_oid != SAI_NULL_OBJECT_ID) {
        sai_log_error(
            SAI_API_SWITCH, "%s ACL already attached switch bind point. Cannot attach ACL at switch bind point again.", gress);
        return SAI_STATUS_FAILURE;
    }

    if (acl_oid != SAI_NULL_OBJECT_ID) {
        // attach ACL at switch level
        sai_status_t status = sdev->m_acl_handler->attach_acl_on_switch(stage, acl_oid);
        sai_return_on_error(status);
        sai_log_debug(SAI_API_SWITCH, "%s ACL attached at switch bind point", gress);
    } else if (switch_acl_oid != SAI_NULL_OBJECT_ID) {
        // clear acl attachment from switch level.
        sdev->m_acl_handler->clear_acl_on_switch(stage);
        sai_log_debug(SAI_API_SWITCH, "%s ACL cleared at switch bind point", gress);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_ingress_acl_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();
    sai_object_id_t acl_oid = get_attr_value(SAI_SWITCH_ATTR_INGRESS_ACL, *value);
    sai_status_t status = switch_acl_set(SAI_ACL_STAGE_INGRESS, acl_oid, sdev);
    sai_return_on_error(status);
    sdev->switch_ingress_acl_oid = acl_oid;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_egress_acl_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();
    sai_object_id_t acl_oid = get_attr_value(SAI_SWITCH_ATTR_EGRESS_ACL, *value);
    sai_status_t status = switch_acl_set(SAI_ACL_STAGE_EGRESS, acl_oid, sdev);
    sai_return_on_error(status);
    sdev->switch_egress_acl_oid = acl_oid;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_ecc_err_initiate_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    sai_uint16_t ecc_error_type = get_attr_value(SAI_SWITCH_ATTR_EXT_HW_ECC_ERROR_INITIATE, *value);

    if (ecc_error_type == 2) {
        la_status status = sdev->m_dev->trigger_mem_protect_error(la_mem_protect_error_e::ECC_2B);
        sai_return_on_la_error(status);
    } else if (ecc_error_type == 1) {
        la_status status = sdev->m_dev->trigger_mem_protect_error(la_mem_protect_error_e::ECC_1B);
        sai_return_on_la_error(status);
    } else {
        sai_log_debug(SAI_API_SWITCH, "SAI_SWITCH_ATTR_EXT_HW_ECC_ERROR_INITIATE: supported value, 1 or 2.");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_counter_refresh_interval_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    sdev->m_counter_refresh_interval = get_attr_value(SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL, *value) * 1000;

    sdev->m_force_update = (sdev->m_counter_refresh_interval == 0);
    if (sdev->m_counter_refresh_interval != 0) {
        la_status status
            = sdev->m_dev->set_int_property(la_device_property_e::COUNTERS_SHADOW_AGE_OUT, sdev->m_counter_refresh_interval);
        sai_return_on_la_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_counter_refresh_interval_get(_In_ const sai_object_key_t* key,
                                    _Inout_ sai_attribute_value_t* value,
                                    _In_ uint32_t attr_index,
                                    _Inout_ vendor_cache_t* cache,
                                    void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    set_attr_value(SAI_SWITCH_ATTR_COUNTER_REFRESH_INTERVAL, *value, sdev->m_counter_refresh_interval / 1000);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
switch_number_of_queues_get(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg)
{
    switch ((int64_t)arg) {
    case SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES:
        set_attr_value(SAI_SWITCH_ATTR_NUMBER_OF_UNICAST_QUEUES, *value, lsai_device::SAI_NUMBER_OF_UNICAST_QUEUES);
        break;
    case SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES:
        set_attr_value(SAI_SWITCH_ATTR_NUMBER_OF_MULTICAST_QUEUES, *value, lsai_device::SAI_NUMBER_OF_MULTICAST_QUEUES);
        break;
    case SAI_SWITCH_ATTR_NUMBER_OF_QUEUES:
        set_attr_value(SAI_SWITCH_ATTR_NUMBER_OF_QUEUES, *value, lsai_device::SAI_NUMBER_OF_QUEUES);
        break;
    case SAI_SWITCH_ATTR_NUMBER_OF_CPU_QUEUES:
        set_attr_value(SAI_SWITCH_ATTR_NUMBER_OF_CPU_QUEUES, *value, lsai_device::SAI_NUMBER_OF_CPU_QUEUES);
        break;
    }
    return SAI_STATUS_SUCCESS;
}

la_status
sai_get_device(uint32_t switch_id, std::shared_ptr<lsai_device>& sdev)
{
    la_status status = switches.get(switch_id, sdev);
    return status;
}

static sai_object_id_t
get_switch_default_vlan(sai_object_id_t& default_vlan_id, sai_switch_api_t* switch_api, const sai_object_id_t& switch_id)
{
    sai_attribute_t attr{};
    attr.id = SAI_SWITCH_ATTR_DEFAULT_VLAN_ID;
    sai_status_t status = switch_api->get_switch_attribute(switch_id, 1, &attr);
    default_vlan_id = attr.value.oid;

    return status;
}

static sai_status_t
configure_bridge_port(sai_object_id_t& bridge_port_oid,
                      sai_bridge_api_t* bridge_api,
                      const sai_object_id_t& switch_id,
                      const sai_object_id_t& port_oid)
{
    std::vector<sai_attribute_t> attrs;

    sai_attribute_t attr{};

    attr.id = SAI_BRIDGE_PORT_ATTR_TYPE;
    set_attr_value(SAI_BRIDGE_PORT_ATTR_TYPE, attr.value, SAI_BRIDGE_PORT_TYPE_PORT);
    attrs.push_back(attr);

    attr.id = SAI_BRIDGE_PORT_ATTR_PORT_ID;
    set_attr_value(SAI_BRIDGE_PORT_ATTR_PORT_ID, attr.value, port_oid);
    attrs.push_back(attr);

    sai_status_t status = bridge_api->create_bridge_port(&bridge_port_oid, switch_id, attrs.size(), attrs.data());
    sai_log_debug(SAI_API_PORT, "Created bridge_port object (0x%lx)", bridge_port_oid);
    return status;
}

static sai_status_t
configure_vlan_member(sai_object_id_t& vlan_member_id,
                      sai_vlan_api_t* vlan_api,
                      const sai_object_id_t& switch_id,
                      const sai_object_id_t& vlan_id,
                      const sai_object_id_t& bridge_port_id)
{
    std::vector<sai_attribute_t> attrs;

    sai_attribute_t attr{};

    attr.id = SAI_VLAN_MEMBER_ATTR_VLAN_ID;
    set_attr_value(SAI_VLAN_MEMBER_ATTR_VLAN_ID, attr.value, vlan_id);
    attrs.push_back(attr);

    attr.id = SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID;
    set_attr_value(SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID, attr.value, bridge_port_id);
    attrs.push_back(attr);

    sai_status_t status = vlan_api->create_vlan_member(&vlan_member_id, switch_id, attrs.size(), attrs.data());
    sai_log_debug(SAI_API_PORT, "Created vlan_member object (0x%lx)", vlan_member_id);

    return status;
}

static sai_status_t
create_ports_only(sai_object_id_t switch_id, std::shared_ptr<lsai_device> sdev)
{
    // Create Ports Only
    sai_port_api_t* port_api;
    sai_status_t status = sai_api_query(SAI_API_PORT, (void**)(&port_api));
    sai_return_on_error(status, "Fail to get api, \"SAI_API_PORT\".");

    for (auto& port_grp_iter : sdev->m_port_mix_map) {
        for (auto& port_cfg : port_grp_iter.second) {
            // create attribute list
            std::vector<sai_attribute_t> attrs(port_cfg.m_attrs);

            // create SAI_PORT_ATTR_HW_LANE_LIST attribute from lsai_port_cfg_t::m_pif_lanes
            sai_attribute_t attr{};
            attr.id = SAI_PORT_ATTR_HW_LANE_LIST;
            attr.value.u32list.count = port_cfg.m_pif_lanes.size();
            attr.value.u32list.list = port_cfg.m_pif_lanes.data();
            attrs.push_back(attr);

            // create port
            status = port_api->create_port(&port_cfg.m_sai_port_id, switch_id, attrs.size(), attrs.data());
            sai_return_on_error(status, "Fail to create sai_port in create_ports_only.");
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
create_default_l2_bridge(sai_object_id_t switch_id, std::shared_ptr<lsai_device> sdev)
{
    // Create Default L2 Bridge using default VLAN
    sai_port_api_t* port_api;
    sai_status_t status = sai_api_query(SAI_API_PORT, (void**)(&port_api));
    sai_return_on_error(status, "Fail to get api, \"SAI_API_PORT\".");

    sai_bridge_api_t* bridge_api;
    status = sai_api_query(SAI_API_BRIDGE, (void**)(&bridge_api));
    sai_return_on_error(status, "Fail to get api, \"SAI_API_BRIDGE\".");

    sai_vlan_api_t* vlan_api;
    status = sai_api_query(SAI_API_VLAN, (void**)(&vlan_api));
    sai_return_on_error(status, "Fail to get api, \"SAI_API_VLAN\".");

    sai_switch_api_t* switch_api;
    status = sai_api_query(SAI_API_SWITCH, (void**)(&switch_api));
    sai_return_on_error(status, "Fail to get api, \"SAI_API_SWITCH\".");

    // Get Default VLAN
    sai_object_id_t default_vlan_id;
    status = get_switch_default_vlan(default_vlan_id, switch_api, switch_id);
    sai_return_on_error(status, "Fail to get default vlan id in create_default_l2_bridge.");

    for (auto& port_grp_iter : sdev->m_port_mix_map) {
        for (auto& port_cfg : port_grp_iter.second) {
            // create attribute list
            std::vector<sai_attribute_t> attrs(port_cfg.m_attrs);

            // create SAI_PORT_ATTR_HW_LANE_LIST attribute from lsai_port_cfg_t::m_pif_lanes
            sai_attribute_t attr{};
            attr.id = SAI_PORT_ATTR_HW_LANE_LIST;
            attr.value.u32list.count = port_cfg.m_pif_lanes.size();
            attr.value.u32list.list = port_cfg.m_pif_lanes.data();
            attrs.push_back(attr);

            // create port
            status = port_api->create_port(&port_cfg.m_sai_port_id, switch_id, attrs.size(), attrs.data());
            sai_return_on_error(status, "Fail to create sai_port in create_default_l2_bridge.");

            // create bridge port
            status = configure_bridge_port(port_cfg.m_sai_bridge_port_id, bridge_api, switch_id, port_cfg.m_sai_port_id);
            sai_return_on_error(status, "Fail to create sai_bridge_port in create_default_l2_bridge.");

            status = configure_vlan_member(
                port_cfg.m_sai_vlan_member_id, vlan_api, switch_id, default_vlan_id, port_cfg.m_sai_bridge_port_id);
            sai_return_on_error(status, "Fail to create sai_vlan_member in create_default_l2_bridge.");
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
create_port_mix(sai_object_id_t* switch_id, std::shared_ptr<lsai_device> sdev)
{
    if (sdev->m_sw_init_mode == lsai_sw_init_mode_e::NONE) {
        // no port created
        return SAI_STATUS_SUCCESS;
    }

    sai_log_info(SAI_API_SWITCH, "Init Switch Mode (%s) creating ports ... ", to_string(sdev->m_sw_init_mode).c_str());

    sai_status_t sai_status;

    switch (sdev->m_sw_init_mode) {
    case lsai_sw_init_mode_e::L2BRIDGE:
        sai_status = create_default_l2_bridge(*switch_id, sdev);
        break;
    case lsai_sw_init_mode_e::PORTONLY:
        sai_status = create_ports_only(*switch_id, sdev);
        break;
    default:
        sai_status = SAI_STATUS_NOT_IMPLEMENTED;
        break;
    }
    return sai_status;
}

static sai_status_t
apply_extended_property_bool(std::shared_ptr<lsai_device> sdev, lsai_extended_property_e ext_prop_e, const bool& value)
{
    la_status status;
    switch (ext_prop_e) {
    case lsai_extended_property_e::FLOW_CACHE_ENABLE: {
        la_flow_cache_handler* flow_cache_handler = nullptr;
        status = sdev->m_dev->get_flow_cache_handler(flow_cache_handler);
        sai_return_on_la_error(status, "Fail to get flow cache handler. Device may not support flow cache.");
        status = flow_cache_handler->set_flow_cache_enabled(value);
        sai_return_on_la_error(status);
    } break;
    case lsai_extended_property_e::ALLOW_SMAC_EQUALS_DMAC: {
        if (value) {
            status = sdev->m_dev->clear_trap_configuration(LA_EVENT_ETHERNET_SA_DA_ERROR);
            if (status != LA_STATUS_SUCCESS) {
                sai_log_warn(SAI_API_SWITCH, "Can not clear SA_DA_ERROR trap during init");
            }
        }
    } break;
    default:
        sai_log_error(
            SAI_API_SWITCH, "Invalid lsai_extended_property_e(%d) or lsai_extended_property_e is not supported.", (int)ext_prop_e);
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
apply_extended_properties(std::shared_ptr<lsai_device> sdev)
{
    sai_status_t sstatus;
    for (auto& ext_prop_itr : sdev->m_ext_properties_bool) {
        sstatus = apply_extended_property_bool(sdev, ext_prop_itr.first, ext_prop_itr.second);
        sai_return_on_error(sstatus);
        sai_log_info(SAI_API_SWITCH,
                     "Applied Extended Property(%s) to %s",
                     to_string(ext_prop_itr.first).c_str(),
                     to_string(ext_prop_itr.second).c_str());
    }
    return SAI_STATUS_SUCCESS;
}

static std::string
switch_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_switch_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << "\n";

    return log_message.str();
}

std::string
warm_boot_file_path(const char* given_path, bool is_sdk)
{
    struct stat statbuf;
    std::string ret_file(given_path);

    if ((stat(given_path, &statbuf) == 0) && (S_ISDIR(statbuf.st_mode))) {
        // given path exists and is a directory
        if (is_sdk) {
            ret_file += "/sdk_dump";
        } else {
            ret_file += "/sai_dump";
        }
    } else {
        // Given path does not exist, or it exists and is not directory. Assume it is a file name base.
        // For the SAI warm boot dump file, use the filename provided with no extension
        // in the case NOS checks for file existence.
        if (is_sdk) {
            ret_file += ".sdk";
        }
    }

    return ret_file;
}

sai_status_t
dump_switch_state(std::shared_ptr<lsai_device> sai_device, const char* archive_path)
{
    std::string sai_file = warm_boot_file_path(archive_path, false);
    std::string sdk_file = warm_boot_file_path(archive_path, true);

    if (sai_device->m_warm_boot_mode == warm_boot_type_e::FULL) {
        // stop changes in SDK and SAI
        auto la_dev = sai_device->m_dev;
        la_dev->warm_boot_disconnect();

        sai_device->close_threads();
        // dump SAI state using automatic tool
        lsai_device_serialize_save(sai_device, sai_file.c_str());

        // prevent calling any SDK functions on shutdown
        sai_device->m_dev = nullptr;

        close(sai_device->m_punt_fd);
        close(sai_device->m_inject_fd);

        // dump SDK state
        la_warm_boot_save_and_destroy(la_dev, sdk_file.c_str(), true);
    } else {
        // SAI only mode. Need to save pointer to SDK, because we need to reconnect to same la_object
        s_la_device_ptr = sai_device->m_dev;
        s_la_device_ptr->close_notification_fds();
        // dump SAI state using automatic tool
        lsai_device_serialize_save(sai_device, sai_file.c_str());
        // prevent destruction of la -objects
        sai_device->m_dev = nullptr;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
create_switch_cold_boot(transaction& txn,
                        uint32_t& sw_id,
                        std::shared_ptr<lsai_device>& sdev,
                        sai_object_id_t* switch_id,
                        uint32_t attr_count,
                        const sai_attribute_t* attr_list,
                        const std::string& hardware_name,
                        int boot_type)
{
    la_device* la_dev = nullptr;
    bool is_sim = (hardware_name.find("testdev") != std::string::npos);

    txn.status = switches.allocate_id(sw_id);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { switches.release_id(sw_id); });

    txn.status = la_create_device(hardware_name.c_str(), sw_id, la_dev);
    sai_return_on_la_error(txn.status, "Failed to create device: %s", hardware_name.c_str());
    txn.on_fail([=]() { la_destroy_device(la_dev); });

    // We use SAI_API_UNSPECIFIED for setting SDK log level. If default was changed before SDK init, need to handle here
    sai_log_level_t sai_level = SAI_LOG_LEVEL_INFO;
    lsai_logger::instance().get_logging_level(SAI_API_UNSPECIFIED, sai_level);
    set_one_la_logging(sai_level, sw_id);

    uint32_t hw_dev_id = 0;
    if (is_sim) {
        int nmatch = sscanf(hardware_name.c_str(), "/dev/testdev%d/%*s", &hw_dev_id);
        if (nmatch < 1) {
            sai_log_error(SAI_API_SWITCH, "Failed to parse hardware string: %s", hardware_name.c_str());
            txn.status = LA_STATUS_EINVAL;
            return to_sai_status(txn.status);
        }
    }

    sdev = std::make_shared<lsai_device>(sw_id, hw_dev_id, la_dev, is_sim);
    if (sdev == nullptr) {
        txn.status = LA_STATUS_ERESOURCE;
        sai_log_error(SAI_API_SWITCH, "Failed to create device: %s", hardware_name.c_str());
        return to_sai_status(txn.status);
    }

    lsai_object la_obj(SAI_OBJECT_TYPE_SWITCH, sw_id, sw_id);
    la_obj.set_device(sdev);
    switches.set(*switch_id, sdev, la_obj);

    sai_start_api_getter(sdev);

    txn.on_fail([=]() { sdev->m_dev = nullptr; });

    // First thing to do after lsai_device is created, read config files.
    const char* config_file = g_sai_service_method.profile_get_value(0, SAI_KEY_INIT_CONFIG_FILE);
    config_parser sai_config(sdev, config_file, 0);
    txn.status = sai_config.load_configuration();
    sai_return_on_la_error(txn.status, "Failed to load configuration: %s\n", config_file);
    txn.status = sai_config.load_port_mix();
    sai_return_on_la_error(txn.status, "Failed to load port_mix: %s\n", config_file);

    if (sdev && sdev->m_dev) {
        // Set boot optimization in the device properties.
        sdev->m_dev->set_bool_property(la_device_property_e::ENABLE_BOOT_OPTIMIZATION, (boot_type == BOOT_TYPE_FAST));
    }
    txn.status = sdev->initialize(txn, attr_list, attr_count);
    if (sdev && sdev->m_dev) {
        // Clear boot optimizaiton in device properties.
        sdev->m_dev->set_bool_property(la_device_property_e::ENABLE_BOOT_OPTIMIZATION, false);
    }
    sai_return_on_la_error(txn.status, "Failed to setup device: %s", hardware_name.c_str());

    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];
    key.key.object_id = *switch_id;
    snprintf(key_str, MAX_KEY_STR_LEN, "switch 0x%0lx", *switch_id);

    // loop for create_and_set attributes
    for (uint32_t i = 0; i < attr_count; i++) {
        switch (attr_list[i].id) {
        case SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO:
        case SAI_SWITCH_ATTR_FIRMWARE_PATH_NAME:
            // skip attributes we handled before

            break;
        case SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST:
            // continue. This list is processed at the time
            // of switch creation. Need to be ignored
            // after switch create.
            break;
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
        case SAI_SWITCH_ATTR_TYPE:
        case SAI_SWITCH_ATTR_SWITCH_ID:
        case SAI_SWITCH_ATTR_SYSTEM_PORT_CONFIG_LIST:
            // Create-only attribute.
            break;
#endif
        default:
            sai_create_and_set_attribute(&key, key_str, switch_attribs, switch_vendor_attribs, &attr_list[i]);
            break;
        }
    }

    // create all ports
    sai_status_t sai_status = create_port_mix(switch_id, sdev);
    sai_return_on_error(sai_status);

    // Apply extened properties configuration for HW.
    sai_status = apply_extended_properties(sdev);
    sai_return_on_error(sai_status);

    if (sdev->m_voq_cfg_manager->is_voq_switch()) {
        // create any non-internal system ports provided to create_switch
        txn.status = sdev->m_voq_cfg_manager->create_front_panel_system_ports(txn);
        sai_return_on_la_error(txn.status);
    }

    // Configure HW to learn and age automatically through learning and aging notification handler
    la_dev->set_learn_mode(la_device::learn_mode_e::SYSTEM);
    // Disable MAC aging by default, SAI_SWITCH_ATTR_FDB_AGING_TIME can change it
    la_dev->set_mac_aging_interval(LA_MAC_AGING_TIME_NEVER);

    // Process ACL key profiles if provided
    txn.status = sai_config.load_acl_key_profiles();
    sai_return_on_la_error(txn.status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
create_switch_warm_boot(transaction& txn,
                        uint32_t& sw_id,
                        std::shared_ptr<lsai_device>& sdev,
                        sai_object_id_t* switch_id,
                        uint32_t attr_count,
                        const sai_attribute_t* attr_list,
                        const std::string& hardware_name)
{
    warm_boot_type_e warm_boot_mode = (warm_boot_type_e)get_int_from_profile(SAI_KEY_EXT_WARM_BOOT_TYPE);

    if (warm_boot_mode == warm_boot_type_e::FAKE) {
        return SAI_STATUS_SUCCESS;
    }

    // This is needed to be able to recover la_object pointers in lsai_device_serialize_load
    std::shared_ptr<lsai_device> temp_sdev_ptr = std::make_shared<lsai_device>();
    const char* boot_read_file = g_sai_service_method.profile_get_value(0, SAI_KEY_WARM_BOOT_READ_FILE);

    txn.status = switches.allocate_id(sw_id);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { switches.release_id(sw_id); });

    if (warm_boot_mode == warm_boot_type_e::SAI_ONLY) {
        temp_sdev_ptr->m_dev = s_la_device_ptr;
        switches.set(sw_id, temp_sdev_ptr);

        std::string sai_dump_file = warm_boot_file_path(boot_read_file, false);
        lsai_device_serialize_load(sdev, sai_dump_file.c_str());
        sdev->m_dev = s_la_device_ptr;
        temp_sdev_ptr->m_dev = nullptr; // When destructor will run, we don't want to free the la_device pointer
        lsai_object la_obj(SAI_OBJECT_TYPE_SWITCH, sw_id, sw_id);
        la_obj.set_device(sdev);
        switches.set(*switch_id, sdev, la_obj);

        txn.status = sdev->initialize_warm_before_reconnect(txn, warm_boot_mode, 0);
        sai_return_on_la_error(txn.status, "Failed to restart after warm boot before reconnect");
        // no need for SDK reconnect in this case because we did not stop it
        txn.status = sdev->initialize_warm_after_reconnect(txn, warm_boot_mode);
        sai_return_on_la_error(txn.status, "Failed to restart after warm boot after reconnect");
    } else {
        // full warm boot restart

        la_device* la_dev = nullptr;
        std::string sdk_dump_file = warm_boot_file_path(boot_read_file, true);
        txn.status = la_warm_boot_restore(hardware_name.c_str(), sdk_dump_file.c_str(), la_dev);
        sai_return_on_la_error(txn.status, "Failed on warm boot reconnect to device: %s", hardware_name.c_str());
        txn.on_fail([=]() { la_destroy_device(la_dev); });

        // before recovering sai, state what is the revision of the dump file. We relay on SDK to recover the base revision.
        uint32_t wb_revision;
        txn.status = la_dev->warm_boot_get_base_revision(wb_revision);
        sai_return_on_la_error(txn.status, "Failed getting warm boot revision");
#ifdef ENABLE_SERIALIZATION
        ::cereal::cereal_gen_set_serialization_version_sai(wb_revision);
#endif

        sdev = std::make_shared<lsai_device>();
        if (sdev == nullptr) {
            txn.status = LA_STATUS_ERESOURCE;
            sai_log_error(SAI_API_SWITCH, "Failed to create device: %s", hardware_name.c_str());
            return to_sai_status(txn.status);
        }
        temp_sdev_ptr->m_dev = la_dev;
        switches.set(sw_id, temp_sdev_ptr);
        std::string sai_dump_file = warm_boot_file_path(boot_read_file, false);
        lsai_device_serialize_load(sdev, sai_dump_file.c_str());
        sdev->m_dev = la_dev;
        temp_sdev_ptr->m_dev = nullptr; // When destructor will run, we don't want to free the la_device pointer
        lsai_object la_obj(SAI_OBJECT_TYPE_SWITCH, sw_id, sw_id);
        la_obj.set_device(sdev);
        switches.set(*switch_id, sdev, la_obj);

        // We use SAI_API_UNSPECIFIED for setting SDK log level. If default was changed before SDK init, need to handle here
        sai_log_level_t sai_level = SAI_LOG_LEVEL_INFO;
        lsai_logger::instance().get_logging_level(SAI_API_UNSPECIFIED, sai_level);
        set_one_la_logging(sai_level, sw_id);

        txn.status = sdev->initialize_warm_before_reconnect(txn, warm_boot_mode, wb_revision);
        sai_return_on_la_error(txn.status, "Failed to restart after warm boot before reconnect");

        la_dev->warm_boot_reconnect();

        txn.status = sdev->initialize_warm_after_reconnect(txn, warm_boot_mode);
        sai_return_on_la_error(txn.status, "Failed to restart after warm boot after reconnect");
    }

    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];
    key.key.object_id = *switch_id;
    snprintf(key_str, MAX_KEY_STR_LEN, "switch 0x%0lx", *switch_id);

    // loop for create_and_set attributes
    for (uint32_t i = 0; i < attr_count; i++) {
        switch (attr_list[i].id) {
        case SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO:
        case SAI_SWITCH_ATTR_FIRMWARE_PATH_NAME:
            // skip attributes we handled before

            break;
        case SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST:
            // continue. This list is processed at the time
            // of switch creation. Need to be ignored
            // after switch create.
            break;
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
        case SAI_SWITCH_ATTR_TYPE:
        case SAI_SWITCH_ATTR_SWITCH_ID:
        case SAI_SWITCH_ATTR_SYSTEM_PORT_CONFIG_LIST:
            // Create-only attribute.
            break;
#endif
        default:
            sai_create_and_set_attribute(&key, key_str, switch_attribs, switch_vendor_attribs, &attr_list[i]);
            break;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
create_switch(sai_object_id_t* switch_id, uint32_t attr_count, const sai_attribute_t* attr_list)
{
    auto attribs = sai_parse_attributes(attr_count, attr_list);
    bool hw_info_attr = false;

    // sai_version_t version = get_sai_sdk_version();
    // sai_log_debug(SAI_API_SWITCH, "SDK version is %s and SAI version is %s", version.sai_sdk_version, version.ocp_sai_version);

    std::string hardware_name;
    {
        auto it = attribs.find(SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO);
        if (it == attribs.end()) {
            char* env_name = getenv("SDK_DEVICE_NAME");
            if (env_name == nullptr) {
                hardware_name = "/dev/uio0";
            } else {
                hardware_name = env_name;
            }
        } else {
            auto hwname = get_attr_value(SAI_SWITCH_ATTR_SWITCH_HARDWARE_INFO, it->second);
            hardware_name = (const char*)hwname.list;
            hw_info_attr = true;
        }
    }

    {
        auto it = attribs.find(SAI_SWITCH_ATTR_FIRMWARE_PATH_NAME);
        if (it != attribs.end()) {

            auto path = get_attr_value(SAI_SWITCH_ATTR_FIRMWARE_PATH_NAME, it->second);

            setenv("BASE_OUTPUT_DIR", (const char*)path.list, 1);

            sai_log_debug(SAI_API_SWITCH, "Path: BASE_OUTPUT_DIR = %s", getenv("BASE_OUTPUT_DIR"));
        }
    }

    bool init_switch_val = true;
    // This is mandatory on create, but we do not enforce that
    get_attrs_value(SAI_SWITCH_ATTR_INIT_SWITCH, attribs, init_switch_val, false);
    if (init_switch_val == false) {
        sai_return_on_error(SAI_STATUS_INVALID_PARAMETER, "Error: wrong value 'false' for SAI_SWITCH_ATTR_INIT_SWITCH");
    }

    int boot_type = get_int_from_profile(SAI_KEY_BOOT_TYPE);
    sai_log_debug(
        SAI_API_SWITCH, "Initialize switch %s %s boot", hardware_name.c_str(), (boot_type == BOOT_TYPE_WARM) ? "warm" : "cold");

    transaction txn;

    uint32_t sw_id = 0;

    std::shared_ptr<lsai_device> sdev;

    sai_status_t status;
    if (boot_type == BOOT_TYPE_WARM) {
        status = create_switch_warm_boot(txn, sw_id, sdev, switch_id, attr_count, attr_list, hardware_name);
        sai_return_on_error(status);
    } else {
        status = create_switch_cold_boot(txn, sw_id, sdev, switch_id, attr_count, attr_list, hardware_name, boot_type);
        sai_return_on_error(status);
        get_attrs_value(SAI_SWITCH_ATTR_SWITCH_PROFILE_ID, attribs, sdev->m_switch_profile_id, false);
    }

    sdev->m_hw_info = hardware_name;
    sdev->m_hw_info_attr = hw_info_attr;

    la_uint64_t user_meta;
    la_status lstatus = sdev->m_dev->get_limit(limit_type_e::ROUTE__MAX_CLASS_IDENTIFIER, user_meta);
    sai_return_on_la_error(lstatus, "Error reading route user meta max value");
    sdev->m_route_user_meta_max = user_meta;
    sdev->m_fdb_user_meta_max = user_meta;

    lstatus = sdev->m_dev->get_limit(limit_type_e::HOST__MAX_CLASS_IDENTIFIER, user_meta);
    sai_return_on_la_error(lstatus, "Error reading neighbor user meta max value");
    sdev->m_neighbor_user_meta_max = user_meta;

    sai_log_debug(SAI_API_SWITCH, "switch id 0x%lx created", *switch_id);

    // check if sai debug shell has to be created at startup time.
    char* enable_debug_shell = getenv("SAI_SHELL_ENABLE");
    if (enable_debug_shell) {
        // if not set to zero, then start debug shell listener thread.
        if (strcmp(enable_debug_shell, "0")) {
            // start debug shell and listen to interactive debug commands
            sai_log_debug(SAI_API_SWITCH, "Starting debug shell");
            debug_shell* debug_shell = &debug_shell::get_instance();
            sai_status_t status = debug_shell->start();
            if (status != SAI_STATUS_SUCCESS) {
                sai_log_debug(SAI_API_SWITCH, "Could not start debug shell");
            }
        }
    }

    return to_sai_status(txn.status);
}

static sai_status_t
remove_switch(sai_object_id_t obj_switch_id)
{
    std::shared_ptr<lsai_device> sdev;
    lsai_object la_obj;
    la_status status = switches.get(obj_switch_id, sdev, la_obj);
    sai_return_on_la_error(status, "Object is not switch id 0x%lx", obj_switch_id);

    sai_log_debug(SAI_API_SWITCH, "Remove switch id 0x%lx", obj_switch_id);

    if (sdev->m_restart_warm) {
        if (sdev->m_warm_boot_mode == warm_boot_type_e::FAKE) {
            return SAI_STATUS_SUCCESS;
        } else {
            const char* boot_write_file = g_sai_service_method.profile_get_value(0, SAI_KEY_WARM_BOOT_WRITE_FILE);
            dump_switch_state(sdev, boot_write_file);
        }
    }
    sdev->clean();
    switches.remove(obj_switch_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_switch_attribute(sai_object_id_t obj_switch_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = obj_switch_id;

    sai_start_api(SAI_API_SWITCH, SAI_OBJECT_TYPE_SWITCH, obj_switch_id, &switch_to_string, obj_switch_id, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "switch 0x%0lx", obj_switch_id);
    return sai_set_attribute(&key, key_str, switch_attribs, switch_vendor_attribs, attr);
}

static sai_status_t
get_switch_attribute(sai_object_id_t obj_switch_id, sai_uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = obj_switch_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_SWITCH, SAI_OBJECT_TYPE_SWITCH, obj_switch_id, &switch_to_string, obj_switch_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "switch 0x%0lx", obj_switch_id);
    return sai_get_attributes(&key, key_str, switch_attribs, switch_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
get_switch_stats_ext(_In_ sai_object_id_t switch_id,
                     _In_ uint32_t number_of_counters,
                     _In_ const sai_stat_id_t* counter_ids,
                     _In_ sai_stats_mode_t mode,
                     _Out_ uint64_t* counters)
{
    std::shared_ptr<lsai_device> sdev;

    lsai_object sai_obj;
    la_status status = switches.get(switch_id, sdev, sai_obj);
    sai_return_on_la_error(status, "Object is not switch id 0x%lx", switch_id);
    sai_start_api_counter(sdev);

    for (uint32_t i = 0; i < number_of_counters; i++) {
        sai_stat_id_t counter_idx = counter_ids[i];
        la_slice_ifg slice_ifg;
        sai_status_t sstatus = sdev->m_debug_counter_handler->get_counter_value(
            counter_idx, mode, counters[i], false /* is_port_count */, slice_ifg);
        sai_return_on_error(sstatus, "Failed getting value of counter %ld", counter_idx);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_switch_stats(_In_ sai_object_id_t switch_id,
                 _In_ uint32_t number_of_counters,
                 _In_ const sai_stat_id_t* counter_ids,
                 _Out_ uint64_t* counters)
{
    return get_switch_stats_ext(switch_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ, counters);
}

static sai_status_t
clear_switch_stats(_In_ sai_object_id_t switch_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t* counter_ids)
{
    uint64_t counters[number_of_counters];

    return get_switch_stats_ext(switch_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ_AND_CLEAR, counters);
}

const sai_switch_api_t switch_api = {create_switch,
                                     remove_switch,
                                     set_switch_attribute,
                                     get_switch_attribute,
                                     get_switch_stats,
                                     get_switch_stats_ext,
                                     clear_switch_stats};
}
}
