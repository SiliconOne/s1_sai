// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco").
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

#ifndef __DEVICE_PARAMS_H__
#define __DEVICE_PARAMS_H__

#include "sai_constants.h"
#include "json_struct_writer.h"
#include "device_context/la_device_context_types.h"

namespace silicon_one
{
namespace sai
{

// PI and PD device parameter storage
struct device_params {
    la_slice_id_t slices_per_dev = 0;        // Number of Slices in Device
    la_ifg_id_t ifgs_per_slice = 0;          // Number of IFG in Slice
    std::vector<la_uint32_t> serdes_per_ifg; // Number of Serdes in IFG
    uint32_t host_serdes_id = 0;             // SerDes lane for host ports (PCI and NPUH)
    uint32_t recycle_serdes_id = 0;          // SerDes lane for recycle ports

    // PFC config thresholds
    la_uint_t pfc_head_room_max = 0;
    la_uint_t pfc_default_pause_thr = 0; // range 800-1100
    la_uint_t pfc_default_head_room = 0; // range 900-1400
    la_uint_t pfc_default_ecn_thr = 0;

    la_uint_t pfc_trap_priority = 0;

    silicon_one::la_traffic_class_t tc_lossless_profile = 0;
    silicon_one::la_traffic_class_t tc_lossy_profile = 0;

    la_uint_t pfc_voq_precharge_ncb = 0;  // VOQ pre charge credit balance
    la_uint_t pfc_scaled_thr_percent = 0; // percentage of scaled pause threshold

    // SQ group
    la_uint_t pfc_sqg_thr_max = 0;
    la_uint_t lossless_sqg_num = 0;
    la_uint_t lossy_sqg_num = 0;

    // TX output queue thresholds
    la_uint_t pfc_oq_fc_bytes_thr_max = 0;
    la_uint_t pfc_oq_fc_buffers_thr_max = 0;
    la_uint_t pfc_oq_fc_pds_thr_max = 0;
    la_uint_t pfc_oq_drop_bytes_thr_max = 0;
    la_uint_t pfc_oq_drop_buffers_thr_max = 0;
    la_uint_t pfc_oq_drop_pds_thr_max = 0;

    la_uint_t pfc_oq_fc_bytes_thr = 0;
    la_uint_t pfc_oq_fc_buffers_thr = 0;
    la_uint_t pfc_oq_drop_buffers_thr_lo = 0;
    la_uint_t pfc_oq_drop_buffers_thr_hi = 0;

    // RX CGM thresholds
    la_uint_t pfc_rx_pdr_sms_thr0 = 0; // rx pdr threshold0
    la_uint_t pfc_rx_pdr_sms_thr1 = 0; // rx pdr threshold1

    la_uint_t pfc_counter_a_thr0 = 0;
    la_uint_t pfc_counter_a_thr1 = 0;
    la_uint_t pfc_counter_a_thr2 = 0;

    // XON/XOFF timer
    la_uint_t pfc_periodic_timer = 0; // (periodic_timer * 512) / port_speed_in_gig
    la_uint_t pfc_quanta_bits = 0;
    la_uint_t pfc_quanta_max = 0;

    // PFC meter profile
    uint32_t pfc_slice_ifg_id = 0;
    uint64_t pfc_default_cir = 0;
    uint64_t pfc_default_eir = 0;
    uint64_t pfc_default_cbs = 0;
    uint64_t pfc_default_ebs = 0;

    uint64_t sms_packet_buffer_memory = 0; // sms memory reserved for packet buffers

    device_params() = default;
    la_status initialize(hw_device_type_e dev_type, matilda_model_e matilda_type);

    // Registers fields of this struct with the provided writer by
    // invoking json_struct_writer::register_loc. The
    // json_struct_writer::write method can then be invoked to write
    // any fields registered here.
    void register_fields(json_struct_writer& writer);
    void log_param_values(void);
};
}
}

#endif
