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

#include "api/system/la_device.h"
#include "device_context/la_device_context_types.h"
#include "device_params.h"

namespace silicon_one
{
namespace sai
{

la_status
device_params::initialize(hw_device_type_e dev_type, matilda_model_e matilda_type)
{
    // Common values
    slices_per_dev = 6;
    ifgs_per_slice = 2;
    la_status status = LA_STATUS_SUCCESS;

    // PFC parameters

    // common parameters
    pfc_trap_priority = 0;
    tc_lossless_profile = 0xfe;
    tc_lossy_profile = 0xff;
    lossless_sqg_num = 0;
    lossy_sqg_num = 1;
    pfc_slice_ifg_id = 1; // all injects are to ifg 1

    pfc_default_ecn_thr = 0;
    pfc_default_cir = 170000000; // from enable_pfc()
    pfc_default_eir = 170000000;
    pfc_default_cbs = 102400;
    pfc_default_ebs = 1024;

    switch (dev_type) {
    case hw_device_type_e::PACIFIC:
        serdes_per_ifg = std::vector<la_uint32_t>(6 * 2, 18);
        host_serdes_id = 18; // See: sdk/driver/pacific/src/hld/hld_types.h
        recycle_serdes_id = 19;

        pfc_default_pause_thr = 1200;
        pfc_default_head_room = 800;
        pfc_sqg_thr_max = 0x1ffff;
        pfc_rx_pdr_sms_thr0 = 58000;
        pfc_rx_pdr_sms_thr1 = 64000;
        pfc_counter_a_thr0 = 16000;
        pfc_counter_a_thr1 = 40000;
        pfc_counter_a_thr2 = 58000;

        pfc_periodic_timer = 0x3fff;
        pfc_quanta_bits = 512;
        pfc_quanta_max = 0xffff; // sdk always sets to max 0xffff
        pfc_voq_precharge_ncb = 10;
        pfc_scaled_thr_percent = 60;
        pfc_head_room_max = 0x1ffff; // 17 bits width

        pfc_oq_fc_bytes_thr_max = 0x3ffff; // 17 bits width
        pfc_oq_fc_pds_thr_max = 0x7fff;
        pfc_oq_drop_bytes_thr_max = 0x3ffff;
        pfc_oq_drop_buffers_thr_max = 0x1ffff;
        pfc_oq_fc_bytes_thr = (130 * 1024) / 256;
        pfc_oq_fc_buffers_thr = 400;
        pfc_oq_fc_buffers_thr_max = 0x1ffff; // 17 bits width
        pfc_oq_drop_pds_thr_max = 0x7fff;    // 15 bits width
        pfc_oq_drop_buffers_thr_lo = 1000;   // lossy le 100G
        pfc_oq_drop_buffers_thr_hi = 2000;   // lossy gt 100G

        sms_packet_buffer_memory = 64 * 1024 * 1024;
        break;

    case hw_device_type_e::GIBRALTAR:
        serdes_per_ifg = std::vector<la_uint32_t>{24, 24, 24, 16, 16, 24, 24, 16, 16, 24, 24, 24};
        host_serdes_id = 24; // See: sdk/driver/gibraltar/src/hld/hld_types.h
        recycle_serdes_id = 25;

        switch (matilda_type) {
        case matilda_model_e::MATILDA_32A:
        case matilda_model_e::MATILDA_32B:
        case matilda_model_e::MATILDA_64:
            sms_packet_buffer_memory = 64 * 1024 * 1024;
            break;
        case matilda_model_e::MATILDA_8T_A:
        case matilda_model_e::MATILDA_8T_B:
        case matilda_model_e::NONE:
            sms_packet_buffer_memory = 108 * 1024 * 1024;
            break;
        }

        pfc_default_pause_thr = 1200;
        pfc_default_head_room = 800;
        pfc_sqg_thr_max = 0x7ffff;
        pfc_rx_pdr_sms_thr0 = 160000;
        pfc_rx_pdr_sms_thr1 = 170000;
        pfc_counter_a_thr0 = 75000;
        pfc_counter_a_thr1 = 100000;
        pfc_counter_a_thr2 = 160000;

        if (matilda_type == matilda_model_e::MATILDA_32A || matilda_type == matilda_model_e::MATILDA_32B) {
            slices_per_dev = 3;
        } else { // matilda_model_e::MATILDA_64 and others
            slices_per_dev = 6;
        }

        if (matilda_type == matilda_model_e::MATILDA_32A || matilda_type == matilda_model_e::MATILDA_32B
            || matilda_type == matilda_model_e::MATILDA_64) {

            pfc_default_pause_thr = 1050;
            pfc_default_head_room = 1150;
            pfc_sqg_thr_max = 0x7ffff;
            pfc_rx_pdr_sms_thr0 = 155000; // pfc_counter_a_thr2
            pfc_rx_pdr_sms_thr1 = 160000; // Global Drop Thr/CounterA.Thr2

            pfc_counter_a_thr0 = 32000;
            pfc_counter_a_thr1 = 110000;
            pfc_counter_a_thr2 = 155000;

            pfc_periodic_timer = 0x3fff;
            pfc_quanta_bits = 512;
            pfc_quanta_max = 0xffff; // sdk always sets to max 0xffff
            pfc_voq_precharge_ncb = 10;
            pfc_scaled_thr_percent = 60;
            pfc_head_room_max = 0x7ffff; // 19 bits width

            pfc_oq_fc_bytes_thr_max = 0x7ffff; // 19 bits width
            pfc_oq_fc_pds_thr_max = 0xffff;
            pfc_oq_drop_bytes_thr_max = 0x7ffff;
            pfc_oq_drop_buffers_thr_max = 0x7ffff;
            pfc_oq_fc_buffers_thr_max = 0x7ffff; // 19 bits width
            pfc_oq_drop_pds_thr_max = 0xffff;    // 16 bits width
            pfc_oq_fc_bytes_thr = (130 * 1024) / 256;
            pfc_oq_fc_buffers_thr = 100; // for lossless TC

            pfc_oq_drop_buffers_thr_lo = 250;  // lossy le 100G
            pfc_oq_drop_buffers_thr_hi = 4000; // lossy gt 100G

        } else {
            pfc_default_pause_thr = 1050;
            pfc_default_head_room = 1150;
            pfc_sqg_thr_max = 0x7ffff;
            pfc_rx_pdr_sms_thr0 = 160000;
            pfc_rx_pdr_sms_thr1 = 170000;
            pfc_counter_a_thr0 = 75000;
            pfc_counter_a_thr1 = 100000;
            pfc_counter_a_thr2 = 160000;

            pfc_periodic_timer = 0x3fff;
            pfc_quanta_bits = 512;
            pfc_quanta_max = 0xffff; // sdk always sets to max 0xffff
            pfc_voq_precharge_ncb = 10;
            pfc_scaled_thr_percent = 60;
            pfc_head_room_max = 0x7ffff; // 19 bits width

            pfc_oq_fc_bytes_thr_max = 0x7ffff; // 19 bits width
            pfc_oq_fc_pds_thr_max = 0xffff;
            pfc_oq_drop_bytes_thr_max = 0x7ffff;
            pfc_oq_drop_buffers_thr_max = 0x7ffff;
            pfc_oq_fc_bytes_thr = (130 * 1024) / 256;
            pfc_oq_fc_buffers_thr = 400;
            pfc_oq_fc_buffers_thr_max = 0x7ffff; // 19 bits width
            pfc_oq_drop_pds_thr_max = 0xffff;    // 16 bits width
            pfc_oq_drop_buffers_thr_lo = 1000;   // lossy le 100G
            pfc_oq_drop_buffers_thr_hi = 4000;   // lossy gt 100G
        }

        break;

    default:
        return LA_STATUS_EINVAL;
    }
    log_param_values();
    return LA_STATUS_SUCCESS;
}

#define LOG_INT(xyz) sai_log_info(SAI_API_SWITCH, "%s = %d", #xyz, xyz)
#define LOG_LONGINT(xyz) sai_log_info(SAI_API_SWITCH, "%s = %llu", #xyz, xyz)

// log all param values
void
device_params::log_param_values()
{
    sai_log_info(SAI_API_SWITCH, "PFC related device parameters:");
    LOG_INT(pfc_head_room_max);
    LOG_INT(pfc_default_pause_thr);
    LOG_INT(pfc_default_head_room);
    LOG_INT(pfc_default_ecn_thr);
    LOG_INT(pfc_trap_priority);
    LOG_INT(tc_lossless_profile);
    LOG_INT(tc_lossy_profile);
    LOG_INT(pfc_voq_precharge_ncb);
    LOG_INT(pfc_scaled_thr_percent);
    LOG_INT(pfc_sqg_thr_max);
    LOG_INT(lossless_sqg_num);
    LOG_INT(lossy_sqg_num);
    LOG_INT(pfc_oq_fc_bytes_thr_max);
    LOG_INT(pfc_oq_fc_buffers_thr_max);
    LOG_INT(pfc_oq_fc_pds_thr_max);
    LOG_INT(pfc_oq_drop_bytes_thr_max);
    LOG_INT(pfc_oq_drop_buffers_thr_max);
    LOG_INT(pfc_oq_drop_pds_thr_max);

    LOG_INT(pfc_oq_fc_bytes_thr);
    LOG_INT(pfc_oq_fc_buffers_thr);
    LOG_INT(pfc_oq_drop_buffers_thr_lo);
    LOG_INT(pfc_oq_drop_buffers_thr_hi);
    LOG_INT(pfc_rx_pdr_sms_thr0);
    LOG_INT(pfc_rx_pdr_sms_thr1);
    LOG_INT(pfc_counter_a_thr0);
    LOG_INT(pfc_counter_a_thr1);
    LOG_INT(pfc_counter_a_thr2);
    LOG_INT(pfc_periodic_timer);
    LOG_INT(pfc_quanta_bits);
    LOG_INT(pfc_quanta_max);
    LOG_INT(pfc_slice_ifg_id);
    LOG_LONGINT(slices_per_dev);

    LOG_LONGINT(pfc_default_cir);
    LOG_LONGINT(pfc_default_eir);
    LOG_LONGINT(pfc_default_cbs);
    LOG_LONGINT(pfc_default_ebs);
    LOG_LONGINT(sms_packet_buffer_memory);
}

// Registers the given field with the j_writer keyed by the string
// version of that name
#define REGISTER_FIELD(writer, name) writer.register_loc(&name, #name)

void
device_params::register_fields(json_struct_writer& j_writer)
{
    // To enable JSON configurability of any integral field in this
    // structure, add a line here for the given field name.
    REGISTER_FIELD(j_writer, pfc_head_room_max);
    REGISTER_FIELD(j_writer, pfc_default_pause_thr);
    REGISTER_FIELD(j_writer, pfc_default_head_room);
    REGISTER_FIELD(j_writer, pfc_default_ecn_thr);
    // REGISTER_FIELD(j_writer, pfc_trap_priority);
    // REGISTER_FIELD(j_writer, tc_lossless_profile);
    // REGISTER_FIELD(j_writer, tc_lossy_profile);
    REGISTER_FIELD(j_writer, pfc_voq_precharge_ncb);
    REGISTER_FIELD(j_writer, pfc_scaled_thr_percent);
    REGISTER_FIELD(j_writer, pfc_sqg_thr_max);
    REGISTER_FIELD(j_writer, lossless_sqg_num);
    REGISTER_FIELD(j_writer, lossy_sqg_num);
    REGISTER_FIELD(j_writer, pfc_oq_fc_bytes_thr_max);
    REGISTER_FIELD(j_writer, pfc_oq_fc_buffers_thr_max);
    REGISTER_FIELD(j_writer, pfc_oq_fc_pds_thr_max);
    REGISTER_FIELD(j_writer, pfc_oq_drop_bytes_thr_max);
    REGISTER_FIELD(j_writer, pfc_oq_drop_buffers_thr_max);
    REGISTER_FIELD(j_writer, pfc_oq_drop_pds_thr_max);
    REGISTER_FIELD(j_writer, pfc_oq_fc_bytes_thr);
    REGISTER_FIELD(j_writer, pfc_oq_fc_buffers_thr);
    REGISTER_FIELD(j_writer, pfc_oq_drop_buffers_thr_lo);
    REGISTER_FIELD(j_writer, pfc_oq_drop_buffers_thr_hi);
    REGISTER_FIELD(j_writer, pfc_rx_pdr_sms_thr0);
    REGISTER_FIELD(j_writer, pfc_rx_pdr_sms_thr1);
    REGISTER_FIELD(j_writer, pfc_counter_a_thr0);
    REGISTER_FIELD(j_writer, pfc_counter_a_thr1);
    REGISTER_FIELD(j_writer, pfc_counter_a_thr2);
    REGISTER_FIELD(j_writer, pfc_periodic_timer);
    REGISTER_FIELD(j_writer, pfc_quanta_bits);
    REGISTER_FIELD(j_writer, pfc_quanta_max);
    REGISTER_FIELD(j_writer, pfc_slice_ifg_id);
    REGISTER_FIELD(j_writer, pfc_default_cir);
    REGISTER_FIELD(j_writer, pfc_default_eir);
    REGISTER_FIELD(j_writer, pfc_default_cbs);
    REGISTER_FIELD(j_writer, pfc_default_ebs);
}
}
}
