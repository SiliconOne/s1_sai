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

#ifndef __SAI_PORT_H__
#define __SAI_PORT_H__

#include "api/system/la_device.h"
#include "sai_db.h"

namespace silicon_one
{
namespace sai
{
struct port_phy_loc {
    uint32_t slice = 0;
    uint32_t ifg = 0;
    uint32_t pif = 0;
    uint32_t pif_last = 0;
    uint32_t num_of_serdes = 0;
};

// Port Counter structure
struct port_counters {
    la_uint64_t ether_stats_rx_no_errors = 0;
    la_uint64_t ether_stats_tx_no_errors = 0;
    la_uint64_t ether_in_pkts_64_octets = 0;
    la_uint64_t ether_in_pkts_65_to_127_octets = 0;
    la_uint64_t ether_in_pkts_128_to_255_octets = 0;
    la_uint64_t ether_in_pkts_256_to_511_octets = 0;
    la_uint64_t ether_in_pkts_512_to_1023_octets = 0;
    la_uint64_t ether_in_pkts_1024_to_1518_octets = 0;
    la_uint64_t ether_in_pkts_1519_to_2047_octets = 0;
    la_uint64_t ether_out_pkts_64_octets = 0;
    la_uint64_t ether_out_pkts_65_to_127_octets = 0;
    la_uint64_t ether_out_pkts_128_to_255_octets = 0;
    la_uint64_t ether_out_pkts_256_to_511_octets = 0;
    la_uint64_t ether_out_pkts_512_to_1023_octets = 0;
    la_uint64_t ether_out_pkts_1024_to_1518_octets = 0;
    la_uint64_t ether_out_pkts_1519_to_2047_octets = 0;
    la_uint64_t pause_rx_pkts = 0;
    la_uint64_t pause_tx_pkts = 0;
    // IF counters, bytes and total errors only
    la_uint64_t if_in_octets = 0;
    la_uint64_t if_in_errors = 0;
    la_uint64_t if_out_octets = 0;
    la_uint64_t if_out_errors = 0;
    // Error counters
    la_uint64_t ether_stats_undersize_pkts = 0;
    la_uint64_t ether_stats_oversize_pkts = 0;
    la_uint64_t ether_rx_oversize_pkts = 0;
    la_uint64_t ether_stats_crc_align_errors = 0;

    // Discard counters
    la_uint64_t if_in_discards = 0;
    la_uint64_t if_out_discards = 0;

    port_counters& operator=(const la_mac_port::mib_counters& mib_counters)
    {
        // Mac frames counters
        this->ether_stats_rx_no_errors = mib_counters.rx_frames_ok;
        this->ether_stats_tx_no_errors = mib_counters.tx_frames_ok;
        this->ether_in_pkts_64_octets = mib_counters.rx_64b_frames;
        this->ether_in_pkts_65_to_127_octets = mib_counters.rx_65to127b_frames;
        this->ether_in_pkts_128_to_255_octets = mib_counters.rx_128to255b_frames;
        this->ether_in_pkts_256_to_511_octets = mib_counters.rx_256to511b_frames;
        this->ether_in_pkts_512_to_1023_octets = mib_counters.rx_512to1023b_frames;
        this->ether_in_pkts_1024_to_1518_octets = mib_counters.rx_1024to1518b_frames;
        this->ether_in_pkts_1519_to_2047_octets = mib_counters.rx_1519to2500b_frames;
        this->ether_out_pkts_64_octets = mib_counters.tx_64b_frames;
        this->ether_out_pkts_65_to_127_octets = mib_counters.tx_65to127b_frames;
        this->ether_out_pkts_128_to_255_octets = mib_counters.tx_128to255b_frames;
        this->ether_out_pkts_256_to_511_octets = mib_counters.tx_256to511b_frames;
        this->ether_out_pkts_512_to_1023_octets = mib_counters.tx_512to1023b_frames;
        this->ether_out_pkts_1024_to_1518_octets = mib_counters.tx_1024to1518b_frames;
        this->ether_out_pkts_1519_to_2047_octets = mib_counters.tx_1519to2500b_frames;
        // IF counters; bytes and total errors only
        this->pause_rx_pkts = mib_counters.rx_mac_fc_frames_ok;
        this->pause_tx_pkts = mib_counters.tx_mac_fc_frames_ok;
        this->if_in_octets = mib_counters.rx_bytes_ok;
        this->if_in_errors = mib_counters.rx_crc_errors + mib_counters.rx_mac_invert + mib_counters.rx_oversize_err
                             + mib_counters.rx_undersize_err + mib_counters.rx_mac_code_err;
        this->if_out_octets = mib_counters.tx_bytes_ok;
        this->if_out_errors = mib_counters.tx_crc_errors + mib_counters.tx_mac_missing_eop_err + mib_counters.tx_mac_underrun_err;
        // Error counters
        this->ether_stats_undersize_pkts = mib_counters.rx_undersize_err;
        this->ether_stats_oversize_pkts = mib_counters.rx_oversize_err;
        this->ether_rx_oversize_pkts = mib_counters.rx_oversize_err;
        this->ether_stats_crc_align_errors = mib_counters.rx_crc_errors + mib_counters.rx_mac_invert;

        // discard counters
        this->if_in_discards = mib_counters.rx_mac_fc_frames_ok + mib_counters.rx_crc_errors + mib_counters.rx_mac_invert
                               + mib_counters.rx_oversize_err + mib_counters.rx_undersize_err + mib_counters.rx_mac_code_err;
        this->if_out_discards = mib_counters.tx_crc_errors + mib_counters.tx_mac_missing_eop_err + mib_counters.tx_mac_underrun_err;

        return *this;
    }
};

la_mac_port* get_mac_port_by_eth_obj(sai_object_id_t eth_port_obj);

uint32_t to_sai_lanes(const port_phy_loc& phy_loc);

sai_status_t get_port_phy_loc(sai_object_id_t eth_port_obj, port_phy_loc& phy_loc);

la_status port_buffer_profile_get(const lsai_object& la_port, uint32_t queue_index, sai_object_id_t& out_profile_oid);
la_status port_buffer_profile_set(const lsai_object& la_port, uint32_t queue_index, sai_object_id_t profile_id);

la_status port_scheduling_params_update(sai_object_id_t port_oid, sai_object_id_t sched_oid);
la_status port_scheduler_config_get(const lsai_object& la_port, uint32_t queue_index, sai_object_id_t& out_sched_oid);
la_status port_scheduler_config_change(const lsai_object& la_port, uint32_t queue_index, sai_object_id_t sched_oid);
sai_status_t port_scheduler_group_scheduler_config_change(std::shared_ptr<lsai_device>& out_sdev,
                                                          sai_object_id_t port_oid,
                                                          sai_object_id_t sched_oid);
sai_status_t scheduler_group_queue_scheduler_config_change(const lsai_object& la_port,
                                                           uint32_t queue_index,
                                                           sai_object_id_t sched_oid);
la_status port_wred_config_change(const lsai_object& la_port, uint32_t queue_index, sai_object_id_t wred_oid);

la_voq_gid_t get_base_voq(int port_id);
la_status get_vsc_vec(la_uint_t vsc_offset,
                      const std::shared_ptr<lsai_device> sdev,
                      la_vsc_gid_vec_t& vec,
                      la_vsc_gid_vec_t& vec_2);

sai_status_t port_qos_number_of_queues_get(_In_ const sai_object_key_t* key,
                                           _Inout_ sai_attribute_value_t* value,
                                           _In_ uint32_t attr_index,
                                           _Inout_ vendor_cache_t* cache,
                                           void* arg);

sai_status_t port_qos_queue_list_get(_In_ const sai_object_key_t* key,
                                     _Inout_ sai_attribute_value_t* value,
                                     _In_ uint32_t attr_index,
                                     _Inout_ vendor_cache_t* cache,
                                     void* arg);

sai_status_t port_ingress_number_of_priority_groups_get(_In_ const sai_object_key_t* key,
                                                        _Inout_ sai_attribute_value_t* value,
                                                        _In_ uint32_t attr_index,
                                                        _Inout_ vendor_cache_t* cache,
                                                        void* arg);

sai_status_t port_priority_group_list_get(_In_ const sai_object_key_t* key,
                                          _Inout_ sai_attribute_value_t* value,
                                          _In_ uint32_t attr_index,
                                          _Inout_ vendor_cache_t* cache,
                                          void* arg);

sai_status_t port_set_sdk_ingress_qos_profile(const std::shared_ptr<lsai_device> sdev,
                                              _In_ la_ethernet_port* eth_port,
                                              _In_ la_ingress_qos_profile* qos_profile);
sai_status_t port_set_sdk_tc_profile(const std::shared_ptr<lsai_device> sdev,
                                     _In_ port_entry* pentry,
                                     _In_ la_ethernet_port* eth_port,
                                     _In_ la_tc_profile* tc_profile);

sai_status_t read_ecn_marked_packets(std::shared_ptr<lsai_device>& sdev,
                                     la_ethernet_port* eth_port,
                                     uint32_t first_index,
                                     uint32_t last_index,
                                     sai_stats_mode_t mode,
                                     uint64_t& out_packets);

uint32_t sdk_to_sai_speed(la_mac_port::port_speed_e la_speed);
la_mac_port::port_speed_e sai_to_sdk_speed(uint32_t speed_in_mbps);
}
}
#endif
