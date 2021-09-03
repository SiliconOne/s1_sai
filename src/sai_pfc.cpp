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

#include "api/tm/la_voq_set.h"
#include "sai_device.h"
#include "sai_pfc.h"
#include "sai_constants.h"

#include <algorithm>

namespace silicon_one
{
namespace sai
{

lasai_pfc_base::lasai_pfc_base(std::shared_ptr<lsai_device> sdev) : m_sdev(sdev)
{
    la_traffic_class_t tc;

    initialize_pfc_profiles();

    // initialize PFC wdog.
    for (tc = 0; tc < la_mac_port::LA_NUM_PFC_PRIORITY_CLASSES; tc++) {
        m_pfc_dld_interval[tc] = 0;
        m_pfc_dlr_interval[tc] = 0;
    }

    m_pfc_dlr_drop = true;
}

static std::string
to_string(const la_tx_cgm_oq_profile_thresholds& thr)
{
    std::stringstream stream;
    stream << "{fc_bytes_threshold=" << thr.fc_bytes_threshold << ", "
           << "fc_buffers_threshold=" << thr.fc_buffers_threshold << ", "
           << "fc_pds_threshold=" << thr.fc_pds_threshold << ", "
           << "drop_bytes_threshold=" << thr.drop_bytes_threshold << ", "
           << "drop_buffers_threshold=" << thr.drop_buffers_threshold << ", "
           << "drop_pds_threshold=" << thr.drop_pds_threshold << "}";
    return stream.str();
}

void
lasai_pfc_base::initialize_pfc_profiles()
{
    lossy_le100 = {m_sdev->m_dev_params.pfc_oq_fc_bytes_thr,
                   m_sdev->m_dev_params.pfc_oq_fc_buffers_thr,
                   m_sdev->m_dev_params.pfc_oq_fc_pds_thr_max,
                   m_sdev->m_dev_params.pfc_oq_drop_bytes_thr_max,
                   m_sdev->m_dev_params.pfc_oq_drop_buffers_thr_lo,
                   m_sdev->m_dev_params.pfc_oq_drop_pds_thr_max};

    lossy_gt100 = {m_sdev->m_dev_params.pfc_oq_fc_bytes_thr,
                   m_sdev->m_dev_params.pfc_oq_fc_buffers_thr,
                   m_sdev->m_dev_params.pfc_oq_fc_pds_thr_max,
                   m_sdev->m_dev_params.pfc_oq_drop_bytes_thr_max,
                   m_sdev->m_dev_params.pfc_oq_drop_buffers_thr_hi,
                   m_sdev->m_dev_params.pfc_oq_drop_pds_thr_max};

    lossless_le400 = {m_sdev->m_dev_params.pfc_oq_fc_bytes_thr,
                      m_sdev->m_dev_params.pfc_oq_fc_buffers_thr,
                      m_sdev->m_dev_params.pfc_oq_fc_pds_thr_max,
                      m_sdev->m_dev_params.pfc_oq_drop_bytes_thr_max,
                      m_sdev->m_dev_params.pfc_oq_drop_buffers_thr_max,
                      m_sdev->m_dev_params.pfc_oq_drop_pds_thr_max};

    lossless_gt400 = {0,
                      0,
                      0,
                      m_sdev->m_dev_params.pfc_oq_drop_bytes_thr_max,
                      m_sdev->m_dev_params.pfc_oq_drop_buffers_thr_max,
                      m_sdev->m_dev_params.pfc_oq_drop_pds_thr_max};

    uint32_t pfc_port_speed;
    for (int i = 0; i < NUM_PORT_TYPES; i++) {
        // pfc_port_speed = lasai_pfc_base::pfc_supported_speeds[i];
        pfc_port_speed = pfc_supported_speeds[i];
        m_oq_profiles[i] = {sai_to_sdk_speed(pfc_port_speed * 1000),
                            pfc_port_speed,
                            pfc_port_speed <= 100 ? lasai_pfc_base::lossy_le100 : lasai_pfc_base::lossy_gt100,
                            pfc_port_speed <= 400 ? lasai_pfc_base::lossless_le400 : lasai_pfc_base::lossless_gt400};
        sai_log_debug(SAI_API_SWITCH,
                      "Initialized pfc_port_oq_profile for speed %s to lossy=%s, lossless=%s",
                      to_string(m_oq_profiles[i].type).c_str(),
                      to_string(m_oq_profiles[i].lossy).c_str(),
                      to_string(m_oq_profiles[i].lossless).c_str());
    }
}

/* allocate leaba_port_pfc_base and initialize */
la_status
lasai_pfc_base::setup_pfc_onport(la_mac_port* mac_port, port_entry* pentry)
{
    la_status status;

    pentry->pfc = std::make_shared<lasai_port_pfc>(mac_port, m_sdev->m_pfc_handler, pentry->service.oid);
    status = pentry->pfc->initialize(pentry);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

bool
lasai_pfc_base::is_pfc_initialized() const
{
    return (m_init_pfc);
}

la_status
lasai_pfc_base::check_and_init()
{
    la_status status;

    if (!m_init_pfc) {

        status = initialize();
        la_return_on_error(status);

        status = initialize_pfc_defaults_onports();
        la_return_on_error(status);

        sai_log_info(SAI_API_SWITCH, "PFC successfully initialized on switch");

        m_init_pfc = true;
    }
    return LA_STATUS_SUCCESS;
}

/*
 * while creating ports if pfc is not initialized, nothing to do on port being created
 * else, need to allocate the pentry.pfc for lasai_port_pfc and initialize
 */
la_status
lasai_pfc_base::pfc_create_port(la_mac_port* mac_port, port_entry* pentry)
{
    la_status status;

    if (!m_init_pfc) {
        return LA_STATUS_SUCCESS;
    }

    if (pentry->pfc == nullptr) {
        status = setup_pfc_onport(mac_port, pentry);
        la_return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

/*
 * expected mode is to reset the bits then set new values - is that acceptable?
 * can do:    0x5 -> 0x0 -> 0x11 -> 0x0 -> 0x13
 * cannot do: 0x5 -> 0x11
 */
la_status
lasai_pfc_base::set_tc(la_mac_port* mac_port, sai_uint8_t enable_bits, lsai_object obj)
{
    la_status status;

    status = check_and_init();
    la_return_on_error(status);

    // need to pull pentry again and set the new bit map
    port_entry* pentry{};
    status = m_sdev->m_ports.get_ptr(obj.index, pentry);
    la_return_on_error(status);

    status = pentry->pfc->set_pfc_tc_bits(enable_bits, pentry->service.oid);
    return status;
}

// configure_default_traps already set all the trap configurations,
// including L2CPx so we just need to define PFC frame defintion for L2CP1 trap
la_status
lasai_pfc_base::initialize_pfc_trap()
{
    // define PFC packet trap matching rule
    la_control_plane_classifier::key key;
    la_control_plane_classifier::result result;
    la_control_plane_classifier::field field;

    field.type.mac = la_control_plane_classifier::mac_field_type_e::ETHERNET_PROFILE_ID;
    field.val.mac.ethernet_profile_id = LSAI_L2CP_PROFILE;
    field.mask.mac.ethernet_profile_id = LSAI_L2CP_PROFILE;
    key.push_back(field);

    field.type.mac = la_control_plane_classifier::mac_field_type_e::ETHERTYPE;
    field.val.mac.ethertype = static_cast<la_ethertype_t>(lsai_device::eth_type_e::PFC);
    field.mask.mac.ethertype = 0xffff;
    key.push_back(field);

    field.type.mac = la_control_plane_classifier::mac_field_type_e::DA;
    field.val.mac.da.flat = 0x0180c2000001;
    field.mask.mac.da.flat = 0xffffffffffff;
    key.push_back(field);

    result.event = LA_EVENT_ETHERNET_L2CP1;
    la_status status = m_sdev->m_copc_mac->append(key, result);
    la_return_on_error(status);

    status = m_sdev->m_dev->set_trap_configuration(LA_EVENT_ETHERNET_L2CP1,
                                                   m_sdev->m_dev_params.pfc_trap_priority,
                                                   nullptr,
                                                   (la_punt_destination*)(la_npu_host_destination*)m_sdev->m_npuh_dest,
                                                   false,
                                                   false,
                                                   true,
                                                   0);
    return status;
}

la_status
lasai_pfc_base::set_output_queue_profiles()
{
    la_status status;
    la_slice_id_t slice_id;

    // cycle through all slices initializing the output queue thresholds
    for (slice_id = 0; slice_id < m_sdev->m_dev_params.slices_per_dev; slice_id++) {
        la_slice_mode_e slice_mode;

        status = m_sdev->m_dev->get_slice_mode(slice_id, slice_mode);
        la_return_on_error(status);

        if (slice_mode != la_slice_mode_e::NETWORK) {
            continue;
        }

        // cycle through all OQ profiles
        for (auto& oq_prof : m_oq_profiles) {

            // program PFC threshold for different port speed
            if (oq_prof.type != la_mac_port::port_speed_e::E_800G) {
                status = m_sdev->m_dev->set_tx_cgm_pfc_port_oq_profile_thresholds(slice_id, oq_prof.type, oq_prof.lossless);
                la_return_on_error(status);
            }

            // program lossy threshold for different port speed
            status = m_sdev->m_dev->set_tx_cgm_port_oq_profile_thresholds(slice_id, oq_prof.type, oq_prof.lossy);
            la_return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

// TODO currently queue index to pfc priority is 1:1.
la_status
lasai_pfc_base::get_pfc_priority(sai_queue_index_t queue_index, la_mac_port::la_pfc_priority_t& pfc_priority)
{
    if ((queue_index >= NUM_QUEUE_PER_PORT) || (queue_index >= la_mac_port::LA_NUM_PFC_PRIORITY_CLASSES)) {
        return LA_STATUS_EINVAL;
    }

    // Currently 1:1 mapping between output queue index and pfc priority index.
    pfc_priority = queue_index;

    return LA_STATUS_SUCCESS;
}

la_status
lasai_pfc_base::is_pfc_dlr_drop(bool& drop)
{
    drop = m_pfc_dlr_drop;
    return LA_STATUS_SUCCESS;
}

la_status
lasai_pfc_base::set_pfc_dlr_drop(bool drop)
{
    m_pfc_dlr_drop = drop;
    return LA_STATUS_SUCCESS;
}

la_status
lasai_pfc_base::get_pfc_dld_interval(la_mac_port::la_pfc_priority_t tc, uint32_t& interval)
{
    interval = m_pfc_dld_interval[tc];
    return LA_STATUS_SUCCESS;
}

void
lasai_pfc_base::get_pfc_dld_interval_range(sai_u32_range_t& range)
{
    auto minmax = std::minmax_element(m_pfc_dld_interval.begin(), m_pfc_dld_interval.end());
    range = {*minmax.first, *minmax.second};
}

la_status
lasai_pfc_base::set_pfc_dld_interval(la_mac_port::la_pfc_priority_t tc, uint32_t interval)
{
    if (m_pfc_dld_interval[tc] != interval) {
        m_pfc_dld_interval[tc] = interval;

        // Need to update SDK for each port.
        la_status status;
        std::vector<port_entry*> mac_ports = m_sdev->get_mac_ports();
        for (auto& port_entry : mac_ports) {
            if (!port_entry->pfc) {
                continue;
            }
            for (la_mac_port::la_pfc_priority_t tc = 0; tc < la_mac_port::LA_NUM_PFC_PRIORITY_CLASSES; tc++) {
                bool enabled = false;
                status = port_entry->pfc->get_pfc_watchdog_enabled(tc, enabled);
                if ((status == LA_STATUS_SUCCESS) && enabled) {
                    port_entry->pfc->set_pfc_watchdog_dld_interval(tc, interval);
                }
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lasai_pfc_base::get_pfc_dlr_interval(la_mac_port::la_pfc_priority_t tc, uint32_t& interval)
{
    interval = m_pfc_dlr_interval[tc];
    return LA_STATUS_SUCCESS;
}

void
lasai_pfc_base::get_pfc_dlr_interval_range(sai_u32_range_t& range)
{
    auto minmax = std::minmax_element(m_pfc_dlr_interval.begin(), m_pfc_dlr_interval.end());
    range = {*minmax.first, *minmax.second};
}

la_status
lasai_pfc_base::set_pfc_dlr_interval(la_mac_port::la_pfc_priority_t tc, uint32_t interval)
{
    if (m_pfc_dlr_interval[tc] != interval) {
        m_pfc_dlr_interval[tc] = interval;

        // Need to update SDK for each port.
        la_status status;
        std::vector<port_entry*> mac_ports = m_sdev->get_mac_ports();
        for (auto& port_entry : mac_ports) {
            if (!port_entry->pfc) {
                continue;
            }
            for (la_mac_port::la_pfc_priority_t tc = 0; tc < la_mac_port::LA_NUM_PFC_PRIORITY_CLASSES; tc++) {
                bool enabled = false;
                status = port_entry->pfc->get_pfc_watchdog_enabled(tc, enabled);
                if ((status == LA_STATUS_SUCCESS) && enabled) {
                    port_entry->pfc->set_pfc_watchdog_dlr_interval(tc, interval);
                }
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

/*
 * For all mac_ports do default pfc initialization when pfc is globally enabled
 * when the system has been running and pfc is configured later.
 */
la_status
lasai_pfc_base::initialize_pfc_defaults_onports()
{
    la_mac_port* mac_port;
    la_status status;

    for (auto& port : m_sdev->m_ports.map()) {
        port_entry& pentry = port.second;
        if (pentry.is_mac() && (pentry.pfc == nullptr)) {
            status = m_sdev->m_dev->get_mac_port(pentry.slice_id, pentry.ifg_id, pentry.pif, mac_port);
            la_return_on_error(status);

            status = setup_pfc_onport(mac_port, &pentry);
            la_return_on_error(status);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
lasai_pfc_base::initialize()
{
    la_status status;

    if (m_lossy_source_cgm_profile == nullptr) {
        status = m_sdev->m_dev->get_default_rx_cgm_sq_profile(m_lossy_source_cgm_profile);
        la_return_on_error(status);
        sai_log_debug(SAI_API_SWITCH, "Set PFC lossy profile");
    }

    // set the maximum value that the VOQ credit balance can go negative
    status = m_sdev->m_dev->set_voq_max_negative_credit_balance(m_sdev->m_dev_params.pfc_voq_precharge_ncb);
    la_return_on_error(status);

    // setup TX congestion management output queue profile
    status = set_output_queue_profiles();
    la_return_on_error(status);

    // setup PFC trap
    status = initialize_pfc_trap();
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

sai_status_t
lasai_pfc_base::switch_pfc_dlr_packet_action_set(_In_ const sai_object_key_t* key,
                                                 _In_ const sai_attribute_value_t* value,
                                                 void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();
    if (la_sw.type != SAI_OBJECT_TYPE_SWITCH || sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (sdev->m_pfc_handler == nullptr) {
        return SAI_STATUS_UNINITIALIZED;
    }

    auto packet_action = get_attr_value(SAI_SWITCH_ATTR_PFC_DLR_PACKET_ACTION, *value);
    bool drop;
    switch (packet_action) {
    case SAI_PACKET_ACTION_DROP:
        drop = true;
        break;
    case SAI_PACKET_ACTION_FORWARD:
        drop = false;
        break;
    default:
        return SAI_STATUS_NOT_SUPPORTED;
        break;
    }

    sai_return_on_la_error(sdev->m_pfc_handler->set_pfc_dlr_drop(drop));

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lasai_pfc_base::switch_pfc_dlr_packet_action_get(_In_ const sai_object_key_t* key,
                                                 _Inout_ sai_attribute_value_t* value,
                                                 _In_ uint32_t attr_index,
                                                 _Inout_ vendor_cache_t* cache,
                                                 void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();
    if (la_sw.type != SAI_OBJECT_TYPE_SWITCH || sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (sdev->m_pfc_handler == nullptr) {
        return SAI_STATUS_UNINITIALIZED;
    }

    bool drop;
    sai_return_on_la_error(sdev->m_pfc_handler->is_pfc_dlr_drop(drop));

    set_attr_value(SAI_SWITCH_ATTR_PFC_DLR_PACKET_ACTION, *value, drop ? SAI_PACKET_ACTION_DROP : SAI_PACKET_ACTION_FORWARD);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
lasai_pfc_base::switch_pfc_tc_dld_interval_range_get(_In_ const sai_object_key_t* key,
                                                     _Inout_ sai_attribute_value_t* value,
                                                     _In_ uint32_t attr_index,
                                                     _Inout_ vendor_cache_t* cache,
                                                     void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    if (la_sw.type != SAI_OBJECT_TYPE_SWITCH || sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (sdev->m_pfc_handler == nullptr) {
        return SAI_STATUS_UNINITIALIZED;
    }

    sai_u32_range_t range;
    if (sdev->m_pfc_handler == nullptr) {
        range.min = 100;
        range.max = 100;
    } else {
        sdev->m_pfc_handler->get_pfc_dld_interval_range(range);
    }

    set_attr_value(SAI_SWITCH_ATTR_PFC_TC_DLD_INTERVAL_RANGE, *value, range);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
lasai_pfc_base::switch_pfc_tc_dld_interval_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    if (la_sw.type != SAI_OBJECT_TYPE_SWITCH || sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (sdev->m_pfc_handler == nullptr) {
        return SAI_STATUS_UNINITIALIZED;
    }

    auto maplist = get_attr_value(SAI_SWITCH_ATTR_PFC_TC_DLD_INTERVAL, *value);
    la_status status;
    for (size_t i = 0; i < value->objlist.count; i++) {
        if (maplist.list[i].key < la_mac_port::LA_NUM_PFC_PRIORITY_CLASSES) {
            status = sdev->m_pfc_handler->set_pfc_dld_interval(maplist.list[i].key, maplist.list[i].value);
            sai_return_on_la_error(status);
        } else {
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lasai_pfc_base::switch_pfc_tc_dld_interval_get(_In_ const sai_object_key_t* key,
                                               _Inout_ sai_attribute_value_t* value,
                                               _In_ uint32_t attr_index,
                                               _Inout_ vendor_cache_t* cache,
                                               void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    if (la_sw.type != SAI_OBJECT_TYPE_SWITCH || sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (sdev->m_pfc_handler == nullptr) {
        return SAI_STATUS_UNINITIALIZED;
    }

    sai_status_t sstatus = SAI_STATUS_SUCCESS;
    la_mac_port::la_pfc_priority_t tc;
    for (tc = 0; tc < la_mac_port::LA_NUM_PFC_PRIORITY_CLASSES; tc++) {
        if (tc < value->maplist.count) {
            la_status status;
            uint32_t interval;
            status = sdev->m_pfc_handler->get_pfc_dld_interval(tc, interval);
            if (status != LA_STATUS_SUCCESS) {
                sstatus = to_sai_status(status);
                break;
            }
            value->maplist.list[tc].value = interval;
            value->maplist.list[tc].key = tc;
        } else {
            sstatus = SAI_STATUS_BUFFER_OVERFLOW;
            break;
        }
    }

    value->maplist.count = tc;
    return sstatus;
}

sai_status_t
lasai_pfc_base::switch_pfc_tc_dlr_interval_range_get(_In_ const sai_object_key_t* key,
                                                     _Inout_ sai_attribute_value_t* value,
                                                     _In_ uint32_t attr_index,
                                                     _Inout_ vendor_cache_t* cache,
                                                     void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    if (la_sw.type != SAI_OBJECT_TYPE_SWITCH || sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (sdev->m_pfc_handler == nullptr) {
        return SAI_STATUS_UNINITIALIZED;
    }

    sai_u32_range_t range;
    if (sdev->m_pfc_handler == nullptr) {
        range.min = 0;
        range.max = 0;
    } else {
        sdev->m_pfc_handler->get_pfc_dlr_interval_range(range);
    }

    set_attr_value(SAI_SWITCH_ATTR_PFC_TC_DLR_INTERVAL_RANGE, *value, range);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
lasai_pfc_base::switch_pfc_tc_dlr_interval_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    if (la_sw.type != SAI_OBJECT_TYPE_SWITCH || sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (sdev->m_pfc_handler == nullptr) {
        return SAI_STATUS_UNINITIALIZED;
    }

    auto maplist = get_attr_value(SAI_SWITCH_ATTR_PFC_TC_DLR_INTERVAL, *value);
    la_status status;
    for (size_t i = 0; i < value->objlist.count; i++) {
        if (maplist.list[i].key < la_mac_port::LA_NUM_PFC_PRIORITY_CLASSES) {
            status = sdev->m_pfc_handler->set_pfc_dlr_interval(maplist.list[i].key, maplist.list[i].value);
            sai_return_on_la_error(status);
        } else {
            return SAI_STATUS_INVALID_PARAMETER;
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lasai_pfc_base::switch_pfc_tc_dlr_interval_get(_In_ const sai_object_key_t* key,
                                               _Inout_ sai_attribute_value_t* value,
                                               _In_ uint32_t attr_index,
                                               _Inout_ vendor_cache_t* cache,
                                               void* arg)
{
    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();

    if (la_sw.type != SAI_OBJECT_TYPE_SWITCH || sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (sdev->m_pfc_handler == nullptr) {
        return SAI_STATUS_UNINITIALIZED;
    }

    sai_status_t sstatus = SAI_STATUS_SUCCESS;
    la_mac_port::la_pfc_priority_t tc;
    for (tc = 0; tc < la_mac_port::LA_NUM_PFC_PRIORITY_CLASSES; tc++) {
        if (tc < value->maplist.count) {
            la_status status;
            uint32_t interval;
            status = sdev->m_pfc_handler->get_pfc_dlr_interval(tc, interval);
            if (status != LA_STATUS_SUCCESS) {
                sstatus = to_sai_status(status);
                break;
            }
            value->maplist.list[tc].value = interval;
            value->maplist.list[tc].key = tc;
        } else {
            sstatus = SAI_STATUS_BUFFER_OVERFLOW;
            break;
        }
    }

    value->maplist.count = tc;
    return sstatus;
}

lasai_hw_pfc::lasai_hw_pfc(std::shared_ptr<lsai_device> sdev) : lasai_pfc_base(sdev)
{
}

la_status
lasai_hw_pfc::initialize()
{
    la_status status;

    la_rx_pdr_sms_bytes_drop_thresholds rx_pdr_sms;
    la_rx_cgm_sms_bytes_quantization_thresholds rx_cgm_sms;
    la_rx_cgm_sqg_thresholds rx_cgm_sqg;

    // enable tuning parameters
    status = m_sdev->m_dev->set_bool_property(la_device_property_e::ENABLE_PFC_DEVICE_TUNING, true);
    la_return_on_error(status);

    // set both RX PDR thresholds set to 64K
    rx_pdr_sms.thresholds[0] = m_sdev->m_dev_params.pfc_rx_pdr_sms_thr1 * BUFFER_POOL_ENTRY_SIZE;
    rx_pdr_sms.thresholds[1] = m_sdev->m_dev_params.pfc_rx_pdr_sms_thr1 * BUFFER_POOL_ENTRY_SIZE;
    status = m_sdev->m_dev->set_rx_pdr_sms_bytes_drop_thresholds(rx_pdr_sms);
    la_return_on_error(status);

    // set RX CGM thresholds - counter-A thresholds, tuned per platform
    rx_cgm_sms.thresholds[0] = m_sdev->m_dev_params.pfc_counter_a_thr0 * BUFFER_POOL_ENTRY_SIZE;
    rx_cgm_sms.thresholds[1] = m_sdev->m_dev_params.pfc_counter_a_thr1 * BUFFER_POOL_ENTRY_SIZE;
    rx_cgm_sms.thresholds[2] = m_sdev->m_dev_params.pfc_counter_a_thr2 * BUFFER_POOL_ENTRY_SIZE;
    status = m_sdev->m_dev->set_rx_cgm_sms_bytes_quantization(rx_cgm_sms);
    la_return_on_error(status);

    // set PFC SQ group thresholds - lossless
    rx_cgm_sqg.thresholds[0] = m_sdev->m_dev_params.pfc_sqg_thr_max * BUFFER_POOL_ENTRY_SIZE;
    rx_cgm_sqg.thresholds[1] = m_sdev->m_dev_params.pfc_sqg_thr_max * BUFFER_POOL_ENTRY_SIZE;
    rx_cgm_sqg.thresholds[2] = m_sdev->m_dev_params.pfc_sqg_thr_max * BUFFER_POOL_ENTRY_SIZE;
    status = m_sdev->m_dev->set_rx_cgm_sqg_thresholds(m_sdev->m_dev_params.lossless_sqg_num, rx_cgm_sqg);
    la_return_on_error(status);

    // set PFC SQ group thresholds - lossy
    rx_cgm_sqg.thresholds[0] = m_sdev->m_dev_params.pfc_sqg_thr_max * BUFFER_POOL_ENTRY_SIZE;
    rx_cgm_sqg.thresholds[1] = m_sdev->m_dev_params.pfc_sqg_thr_max * BUFFER_POOL_ENTRY_SIZE;
    rx_cgm_sqg.thresholds[2] = m_sdev->m_dev_params.pfc_sqg_thr_max * BUFFER_POOL_ENTRY_SIZE;
    status = m_sdev->m_dev->set_rx_cgm_sqg_thresholds(m_sdev->m_dev_params.lossy_sqg_num, rx_cgm_sqg);
    la_return_on_error(status);

    // use threshold mode instead of timer
    status = m_sdev->m_dev->set_pfc_headroom_mode(la_rx_cgm_headroom_mode_e::THRESHOLD);
    la_return_on_error(status);

    return lasai_pfc_base::initialize();
}

lasai_sw_pfc::lasai_sw_pfc(std::shared_ptr<lsai_device> sdev) : lasai_pfc_base(sdev)
{
}

la_status
lasai_sw_pfc::initialize()
{
    la_status status;

    la_rx_pdr_sms_bytes_drop_thresholds rx_pdr_sms;

    initialize_default_meter();

    status = m_sdev->m_dev->set_bool_property(la_device_property_e::ENABLE_PACIFIC_SW_BASED_PFC, true);
    la_return_on_error(status);

    status = m_sdev->m_dev->set_bool_property(la_device_property_e::ENABLE_PFC_DEVICE_TUNING, true);
    la_return_on_error(status);

    status = m_sdev->m_dev->set_bool_property(la_device_property_e::PACIFIC_PFC_HBM_ENABLED, true);
    la_return_on_error(status);

    // set RX PDR thresholds
    rx_pdr_sms.thresholds[0] = m_sdev->m_dev_params.pfc_rx_pdr_sms_thr0 * BUFFER_POOL_ENTRY_SIZE;
    rx_pdr_sms.thresholds[1] = m_sdev->m_dev_params.pfc_rx_pdr_sms_thr1 * BUFFER_POOL_ENTRY_SIZE;
    status = m_sdev->m_dev->set_rx_pdr_sms_bytes_drop_thresholds(rx_pdr_sms);
    la_return_on_error(status);

    return lasai_pfc_base::initialize();
}

la_status
lasai_hw_pfc::configure_pfc_qos(la_traffic_class_t tc)
{
    return LA_STATUS_SUCCESS;
}

la_status
lasai_sw_pfc::configure_pfc_qos(la_traffic_class_t tc)
{
    la_status status;

    if (tc >= la_mac_port::LA_NUM_PFC_PRIORITY_CLASSES) {
        return LA_STATUS_EINVAL;
    }

    // make sure meter profiles were intialized
    if (m_pfc_meter == nullptr) {
        return LA_STATUS_ERESOURCE;
    }

    // set new meter values to the queue meter profile
    uint64_t cir = m_sdev->m_dev_params.pfc_default_cir;
    if (cir) {
        m_pfc_meter->set_cir(tc, cir);
    }
    uint64_t eir = m_sdev->m_dev_params.pfc_default_eir;
    if (eir) {
        m_pfc_meter->set_eir(tc, eir);
    }

    // set pause threshold
    std::chrono::microseconds latency;
    la_uint_t pause_threshold = m_sdev->m_dev_params.pfc_default_pause_thr;
    latency = std::chrono::microseconds(pause_threshold);
    status = m_sdev->m_dev->set_sw_fc_pause_threshold(tc, latency);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

// default meter action profiles (map)
std::array<pfc_meter_action_profile, NUM_METER_ACTION_PROFILES> lasai_sw_pfc::default_map{{
    {la_qos_color_e::GREEN, la_qos_color_e::GREEN, false, false, la_qos_color_e::GREEN, la_qos_color_e::GREEN},

    {la_qos_color_e::GREEN, la_qos_color_e::YELLOW, false, true, la_qos_color_e::YELLOW, la_qos_color_e::YELLOW},

    {la_qos_color_e::GREEN, la_qos_color_e::RED, true, true, la_qos_color_e::RED, la_qos_color_e::YELLOW},

    {la_qos_color_e::YELLOW, la_qos_color_e::GREEN, false, true, la_qos_color_e::YELLOW, la_qos_color_e::YELLOW},

    {la_qos_color_e::YELLOW, la_qos_color_e::YELLOW, false, true, la_qos_color_e::YELLOW, la_qos_color_e::YELLOW},

    {la_qos_color_e::YELLOW, la_qos_color_e::RED, true, true, la_qos_color_e::RED, la_qos_color_e::YELLOW},

    {la_qos_color_e::RED, la_qos_color_e::GREEN, true, true, la_qos_color_e::RED, la_qos_color_e::YELLOW},

    {la_qos_color_e::RED, la_qos_color_e::YELLOW, true, true, la_qos_color_e::RED, la_qos_color_e::YELLOW},

    {la_qos_color_e::RED, la_qos_color_e::RED, true, true, la_qos_color_e::RED, la_qos_color_e::YELLOW},
}};

la_status
lasai_sw_pfc::initialize_default_meter()
{
    la_status status;
    la_ifg_id_t ifg;
    la_slice_id_t slice;
    la_slice_ifg slice_ifg;
    la_meter_profile* meter;
    la_meter_action_profile* meter_action;

    // create PFC meter profile
    status = m_sdev->m_dev->create_meter_profile(la_meter_profile::type_e::PER_IFG,
                                                 la_meter_profile::meter_measure_mode_e::BYTES,
                                                 la_meter_profile::meter_rate_mode_e::SR_TCM,
                                                 la_meter_profile::color_awareness_mode_e::AWARE,
                                                 meter);
    la_return_on_error(status);

    // set CBS and EBS on all slice/ifg
    for (slice = 0; slice < m_sdev->m_dev_params.slices_per_dev; slice++) {
        for (ifg = 0; ifg < m_sdev->m_dev_params.ifgs_per_slice; ifg++) {
            slice_ifg.slice = slice;
            slice_ifg.ifg = ifg;

            // set default committed / excess burst size
            meter->set_cbs(slice_ifg, m_sdev->m_dev_params.pfc_default_cbs);
            meter->set_ebs_or_pbs(slice_ifg, m_sdev->m_dev_params.pfc_default_ebs);
        }
    }
    // create PFC meter action profile
    status = m_sdev->m_dev->create_meter_action_profile(meter_action);
    la_return_on_error(status);

    // set PFC meter actions
    for (auto& action : default_map) {
        status = meter_action->set_action(action.meter_color,
                                          action.rate_limiter_color,
                                          action.drop_enable,
                                          action.mark_ecn,
                                          action.packet_color,
                                          action.rx_cgm_color);
        la_return_on_error(status);
    }

    // create 8 queue meters
    status = m_sdev->m_dev->create_meter(la_meter_set::type_e::PER_IFG_EXACT, NUM_QUEUE_PER_PORT, m_pfc_meter);
    la_return_on_error(status);

    // set default meter to all 8 queue meters
    for (size_t index = 0; index < NUM_QUEUE_PER_PORT; index++) {
        m_pfc_meter->set_committed_bucket_coupling_mode(index, la_meter_set::coupling_mode_e::TO_EXCESS_BUCKET);
        m_pfc_meter->set_meter_profile(index, meter);
        m_pfc_meter->set_meter_action_profile(index, meter_action);
        for (slice = 0; slice < m_sdev->m_dev_params.slices_per_dev; slice++) {
            for (ifg = 0; ifg < m_sdev->m_dev_params.ifgs_per_slice; ifg++) {
                la_slice_ifg slice_ifg{slice, ifg};
                m_pfc_meter->set_cir(index, slice_ifg, m_sdev->m_dev_params.pfc_default_cir);
                m_pfc_meter->set_eir(index, slice_ifg, m_sdev->m_dev_params.pfc_default_eir);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

lasai_port_pfc::lasai_port_pfc(la_obj_wrap<la_mac_port> mac_port, std::shared_ptr<lasai_pfc_base> pfc_dev, sai_object_id_t port_oid)
    : m_mac_port(mac_port), m_pfc_dev(pfc_dev)
{
}

lasai_port_pfc::~lasai_port_pfc()
{
}

la_status
lasai_port_pfc::initialize(port_entry* pentry)
{
    la_status status;
    la_counter_set* pfc_counters;

    // revert to per-port (lossy) thresholds
    status = m_mac_port->set_pfc_oq_profile_tc_bitmap(0);
    la_return_on_error(status);

    // disable PFC
    status = m_mac_port->set_pfc_disable();
    la_return_on_error(status);

    // create PFC counters whether PFC enabled or not
    status = m_pfc_dev->m_sdev->m_dev->create_counter(NUM_QUEUE_PER_PORT, pfc_counters);
    la_return_on_error(status, "Failed to create pfc counters");

    // set PFC counter for this port
    status = m_mac_port->set_pfc_counter(pfc_counters);
    la_return_on_error(status, "Failed to set pfc counters for port");

    // clear QoS map
    status = clear_prio_to_queue_map();
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
lasai_port_pfc::set_prio_to_queue_map(la_uint8_t prio, la_uint8_t queue)
{
    la_status status;

    if (!m_pfc_dev->m_sdev->is_sw_pfc) {
        // TODO: When SDK supports PFC priority to queue map, add map code here
    } else {
        // validate input parameters
        if ((prio >= la_mac_port::LA_NUM_PFC_PRIORITY_CLASSES) || (queue >= NUM_QUEUE_PER_PORT)) {
            return LA_STATUS_EINVAL;
        }

        // TODO: When SDK supports PFC priority to queue map, add map code here
    }
    return LA_STATUS_SUCCESS;
}

la_status
lasai_port_pfc::clear_prio_to_queue_map()
{
    if (!m_pfc_dev->m_sdev->is_sw_pfc) {
        // TODO: When SDK supports PFC priority to queue map, add unmap code here
    } else {
        // TODO: When SDK supports PFC priority to queue map, add unmap code here
    }
    return LA_STATUS_SUCCESS;
}

/*
 * activate pfc on the port for the specific traffic classes. Does
 * - set oq profiles
 * - sets profile for tc and rx cgm sq mapping
 * - sets pfc timer and quanta on port
 * - activates pfc on the port to handle pause frames
 */
la_status
lasai_port_pfc::set_pfc_tc_bits(la_uint8_t enable_bits, sai_object_id_t oid)
{
    la_status status;
    size_t pkts_cnt, bytes_cnt;

    lsai_object port_id(oid);
    port_entry* pentry = m_pfc_dev->m_sdev->m_ports.get_ptr(port_id.index);

    uint32_t speed = 100;
    la_mac_port::port_speed_e port_type;
    status = m_mac_port->get_speed(port_type);
    la_return_on_error(status);

    // clear all PFC counters
    const la_counter_set* pfc_counters;
    status = m_mac_port->get_pfc_counter(pfc_counters);
    la_return_on_error(status);
    for (size_t queue = 0; queue < NUM_QUEUE_PER_PORT; queue++) {
        status = ((la_counter_set*)pfc_counters)->read(queue, true, true, pkts_cnt, bytes_cnt);
        la_return_on_error(status);

        // TODO: uncommented this when PFC watchdog is implemented
        // status = m_mac_port->read_pfc_queue_drain_counter(queue, true, pkts_cnt);
    }

    // set PFC timeout values
    for (int type = 0; type < NUM_PORT_TYPES; type++) {
        if (m_pfc_dev->m_oq_profiles[type].type == port_type) {
            speed = m_pfc_dev->m_oq_profiles[type].speed;
            break;
        }
    }

    bool pfc_enabled;
    la_uint8_t old_bits;
    status = m_mac_port->get_pfc_enabled(pfc_enabled, old_bits);
    la_return_on_error(status);

    sai_log_debug(SAI_API_PORT, "Port(0x%lx), PFC config old 0x%x, new 0x%x", oid, old_bits, enable_bits);

    // Ignore new bit setting if it doesn't change anything
    if (old_bits == enable_bits) {
        sai_log_info(SAI_API_PORT, "Port(0x%lx), ignoring same PFC configuration with bits 0x%x", oid, enable_bits);
        return LA_STATUS_SUCCESS;
    }

    la_mac_port::state_e mac_state;
    status = m_mac_port->get_state(mac_state);
    la_return_on_error(status);

    // The interface must be down in order to change SQ groups. If it
    // is not currently down, a flap is needed.
    bool flap_port = (mac_state != la_mac_port::state_e::INACTIVE);
    if (flap_port) {
        sai_log_info(SAI_API_PORT, "Flapping port(0x%x) during PFC TC change, old tc 0x%x new tc 0x%x", oid, old_bits, enable_bits);
        status = m_mac_port->stop();
        la_return_on_error(status);
    }

    // Cache previous FC mode if PFC hasn't already overridden it with PFC mode
    if (!m_fc_overridden) {
        status = m_mac_port->get_fc_mode(la_mac_port::fc_direction_e::BIDIR, m_cached_fc_mode);
        la_return_on_error(status);
    }

    // set PFC flow control mode
    status = m_mac_port->set_fc_mode(la_mac_port::fc_direction_e::BIDIR, la_mac_port::fc_mode_e::PFC);
    la_return_on_error(status);

    // Record that FC has now been successfully overridden by PFC
    m_fc_overridden = true;

    const device_params& dp = m_pfc_dev->m_sdev->m_dev_params;
    la_traffic_class_t tc;

    for (tc = 0; tc < la_mac_port::LA_NUM_PFC_PRIORITY_CLASSES; tc++) {
        sai_uint8_t bit = 1 << tc;
        if ((bit & enable_bits) == (bit & old_bits)) {
            continue;
        } else {
            status = ingress_priority_group_entry::set_tc_sqg(
                pentry, tc, (bit & enable_bits) ? dp.lossless_sqg_num : dp.lossy_sqg_num);
            la_return_on_error(status);
        }
    }

    // set periodic timer
    std::chrono::nanoseconds time;
    time = std::chrono::nanoseconds((dp.pfc_periodic_timer * dp.pfc_quanta_bits) / speed);
    status = m_mac_port->set_pfc_periodic_timer(time);
    la_return_on_error(status);

    // set quanta
    time = std::chrono::nanoseconds((dp.pfc_quanta_max * dp.pfc_quanta_bits) / speed);
    status = m_mac_port->set_pfc_quanta(time);
    la_return_on_error(status);

    // activate output queue thresholds
    status = m_mac_port->set_pfc_oq_profile_tc_bitmap(enable_bits);
    la_return_on_error(status);

    // SDK does not support changing currently active PFC enable bits
    // to something different without first resetting to 0, so disable
    // if not already disabled
    if (old_bits != 0) {
        sai_log_debug(
            SAI_API_PORT, "Port(0x%x), disabling PFC before changing from non-zero bits 0x%x to 0x%x", oid, old_bits, enable_bits);
        status = m_mac_port->set_pfc_disable();
        la_return_on_error(status);
    }

    // PFC is now disabled, enable if needed
    if (enable_bits != 0) {
        status = m_mac_port->set_pfc_enable(enable_bits);
        la_return_on_error(status);
    }

    // PFC should only be triggered on specific bits
    status = m_mac_port->set_pfc_tc_xoff_rx_enable(enable_bits);
    la_return_on_error(status);

    // If PFC is being disabled and FC mode has been cached, restore
    if ((enable_bits == 0) && m_fc_overridden) {
        status = m_mac_port->set_fc_mode(la_mac_port::fc_direction_e::BIDIR, m_cached_fc_mode);
        la_return_on_error(status);
        // Record that FC has been restored
        m_fc_overridden = false;
    }

    // Check if flapping port back up
    if (flap_port) {
        status = m_mac_port->activate();
        la_return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lasai_port_pfc::handle_port_speed_change(sai_object_id_t oid)
{
    la_status status;

    bool pfc_enabled;
    la_uint8_t enable_bits;

    status = m_mac_port->get_pfc_enabled(pfc_enabled, enable_bits);
    la_return_on_error(status);

    if (pfc_enabled && enable_bits) {
        status = set_pfc_tc_bits(enable_bits, oid);
        la_return_on_error(status, status.message().c_str());
    }

    return LA_STATUS_SUCCESS;
}

la_status
lasai_port_pfc::get_pfc_pause_status(sai_queue_index_t queue_index, bool& paused)
{
    la_mac_port::la_pfc_priority_t pfc_priority;
    la_return_on_error(lasai_pfc_base::get_pfc_priority(queue_index, pfc_priority));

    la_mac_port::pfc_queue_state_e state;
    la_return_on_error(m_mac_port->get_pfc_queue_state(pfc_priority, state));
    paused = (state == la_mac_port::pfc_queue_state_e::NOT_TRANSMITTING_DUE_TO_PFC);
    return LA_STATUS_SUCCESS;
}

la_status
lasai_port_pfc::get_pfc_watchdog_enabled(sai_queue_index_t queue_index, bool& enabled)
{
    la_mac_port::la_pfc_priority_t pfc_priority;
    la_return_on_error(lasai_pfc_base::get_pfc_priority(queue_index, pfc_priority));

    enabled = m_pfc_watchdog_enabled[pfc_priority];

    return LA_STATUS_SUCCESS;
}

la_status
lasai_port_pfc::set_pfc_watchdog_enabled(sai_queue_index_t queue_index, bool enabled)
{
    la_status status;
    la_mac_port::la_pfc_priority_t pfc_priority;
    la_return_on_error(lasai_pfc_base::get_pfc_priority(queue_index, pfc_priority));

    if (enabled) {
        // If DLD and/or DLR are set, then pass that to SDK for this port/tc.
        uint32_t interval;
        la_return_on_error(m_pfc_dev->get_pfc_dld_interval(pfc_priority, interval));
        if (interval) {
            la_return_on_error(
                m_mac_port->set_pfc_queue_watchdog_polling_interval(pfc_priority, std::chrono::milliseconds(interval)));
        }
        la_return_on_error(m_pfc_dev->get_pfc_dlr_interval(pfc_priority, interval));
        if (interval) {
            la_return_on_error(
                m_mac_port->set_pfc_queue_watchdog_recovery_interval(pfc_priority, std::chrono::milliseconds(interval)));
        }
    }

    la_return_on_error(m_mac_port->set_pfc_queue_watchdog_enabled(pfc_priority, enabled));
    m_pfc_watchdog_enabled[queue_index] = enabled;

    return LA_STATUS_SUCCESS;
}

la_status
lasai_port_pfc::pfc_watchdog_drop(la_mac_port::la_pfc_priority_t pfc_priority,
                                  la_voq_gid_t base_voq_id,
                                  la_system_port_gid_t sys_port_gid)
{
    la_status status;
    bool is_found = false;
    la_voq_set* voq_set;

    sai_log_debug(SAI_API_QUEUE,
                  "PFC WDOG recovery port(%d/%d/%d) tc(%d) base_voq_id=%d sys_port_gid=%d",
                  m_mac_port->get_slice(),
                  m_mac_port->get_ifg(),
                  m_mac_port->get_first_serdes_id(),
                  pfc_priority,
                  base_voq_id,
                  sys_port_gid);

    auto obj_lst = m_pfc_dev->m_sdev->m_dev->get_objects(la_object::object_type_e::VOQ_SET);
    for (auto obj : obj_lst) {
        voq_set = static_cast<la_voq_set*>(obj);
        if (voq_set->get_base_voq_id() == base_voq_id) {
            is_found = true;
            break;
        }
    }

    if (is_found) {
        // Set the cgm profile for queue to drop.
        status = voq_set->set_state(pfc_priority, la_voq_set::state_e::DROPPING);
        la_return_on_error(status,
                           "PFC WDOG recovery for port(%d/%d/%d) base_voq_id(%d) set VOQ to drop failed",
                           m_mac_port->get_slice(),
                           m_mac_port->get_ifg(),
                           m_mac_port->get_first_serdes_id(),
                           base_voq_id);

        status = voq_set->flush(pfc_priority, true);
        status = ((status == LA_STATUS_SUCCESS) || (status == LA_STATUS_EAGAIN)) ? LA_STATUS_SUCCESS : status;
        la_return_on_error(status,
                           "PFC WDOG recovery for port(%d/%d/%d) base_voq_id(%d) flush VOQ failed",
                           m_mac_port->get_slice(),
                           m_mac_port->get_ifg(),
                           m_mac_port->get_first_serdes_id(),
                           base_voq_id);

        bool is_empty = false;
        status = voq_set->is_empty(pfc_priority, is_empty);
        la_return_on_error(status,
                           "PFC WDOG recovery for port(%d/%d/%d) base_voq_id(%d) is_empty VOQ failed",
                           m_mac_port->get_slice(),
                           m_mac_port->get_ifg(),
                           m_mac_port->get_first_serdes_id(),
                           base_voq_id);

        if (!is_empty) {
            status = voq_set->restore(pfc_priority);
            la_return_on_error(status,
                               "PFC WDOG recovery for port(%d/%d/%d) base_voq_id(%d) restore VOQ failed",
                               m_mac_port->get_slice(),
                               m_mac_port->get_ifg(),
                               m_mac_port->get_first_serdes_id(),
                               base_voq_id);
        }
    } else {
        sai_log_warn(SAI_API_QUEUE,
                     "PFC WDOG recovery for port(%d/%d/%d) base_voq_id(%d) no base VOQ found",
                     m_mac_port->get_slice(),
                     m_mac_port->get_ifg(),
                     m_mac_port->get_first_serdes_id(),
                     base_voq_id);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lasai_port_pfc::pfc_watchdog_restore(la_mac_port::la_pfc_priority_t pfc_priority,
                                     la_voq_gid_t base_voq_id,
                                     la_system_port_gid_t sys_port_gid)
{
    la_status status;
    bool is_found = false;
    la_voq_set* voq_set;

    sai_log_debug(SAI_API_QUEUE,
                  "pfc_watchdog_restore port(%d/%d/%d) tc(%d) base_voq_id=%d sys_port_gid=%d",
                  m_mac_port->get_slice(),
                  m_mac_port->get_ifg(),
                  m_mac_port->get_first_serdes_id(),
                  pfc_priority,
                  base_voq_id,
                  sys_port_gid);

    auto obj_lst = m_pfc_dev->m_sdev->m_dev->get_objects(la_object::object_type_e::VOQ_SET);
    for (auto obj : obj_lst) {
        voq_set = static_cast<la_voq_set*>(obj);
        if (voq_set->get_base_voq_id() == base_voq_id) {
            is_found = true;
            break;
        }
    }

    if (is_found) {
        // Set the CGM profile for the VOQ to active.
        status = voq_set->set_state(pfc_priority, la_voq_set::state_e::ACTIVE);
        if (status != LA_STATUS_SUCCESS) {
            la_return_on_error(status,
                               "PFC WDOG restore for port(%d/%d/%d) base_voq_id(%d) set VOQ to drop failed",
                               m_mac_port->get_slice(),
                               m_mac_port->get_ifg(),
                               m_mac_port->get_first_serdes_id(),
                               base_voq_id);
        }
    } else {
        sai_log_warn(SAI_API_QUEUE,
                     "PFC WDOG restore for port(%d/%d/%d) base_voq_id(%d) no base VOQ found",
                     m_mac_port->get_slice(),
                     m_mac_port->get_ifg(),
                     m_mac_port->get_first_serdes_id(),
                     base_voq_id);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lasai_port_pfc::pfc_watchdog_drop_or_restore(la_mac_port::la_pfc_priority_t pfc_priority, bool drop)
{
    la_voq_gid_t base_voq_id;
    la_system_port_gid_t sys_port_gid;
    bool is_found = false;

    auto sys_port_obj_lst = m_pfc_dev->m_sdev->m_dev->get_objects(la_object::object_type_e::SYSTEM_PORT);

    // Fetch the system wide voq base id for this pfc_port.
    auto objs = m_pfc_dev->m_sdev->m_dev->get_dependent_objects(m_mac_port);
    for (const auto obj : objs) {
        if (obj->type() == silicon_one::la_object::object_type_e::SYSTEM_PORT) {
            const la_system_port* sys_port = static_cast<const la_system_port*>(obj);
            la_voq_set* voq_set = sys_port->get_voq_set();
            if (voq_set) {
                base_voq_id = voq_set->get_base_voq_id();
                sys_port_gid = sys_port->get_gid();
                is_found = true;
                break;
            }
        }
    }

    if (is_found) {
        // TODO: support fabric mode
        if (drop) {
            la_return_on_error(pfc_watchdog_drop(pfc_priority, base_voq_id, sys_port_gid));
        } else {
            la_return_on_error(pfc_watchdog_restore(pfc_priority, base_voq_id, sys_port_gid));
        }
    } else {
        sai_log_warn(SAI_API_QUEUE,
                     "PFC WDOG %s for port(%d/%d/%d) tc(%d) no sys_port found",
                     drop ? "recovery" : "restore",
                     m_mac_port->get_slice(),
                     m_mac_port->get_ifg(),
                     m_mac_port->get_first_serdes_id(),
                     pfc_priority);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lasai_port_pfc::init_pfc_watchdog_recovery(sai_queue_index_t queue_index, bool init)
{
    la_status status;
    la_mac_port::la_pfc_priority_t pfc_priority;
    la_return_on_error(lasai_pfc_base::get_pfc_priority(queue_index, pfc_priority));

    bool out_cntrs_alloced;
    la_mac_port::pfc_config_queue_state_e state;
    state = init ? la_mac_port::pfc_config_queue_state_e::DROPPING : la_mac_port::pfc_config_queue_state_e::ACTIVE;
    la_return_on_error(m_mac_port->set_pfc_queue_configured_state(pfc_priority, state, out_cntrs_alloced));

    la_return_on_error(pfc_watchdog_drop_or_restore(pfc_priority, init));
    return LA_STATUS_SUCCESS;
}

void
lasai_port_pfc::pfc_deadlock_recovery(sai_queue_index_t queue_index, bool detected)
{
    la_status status;
    uint32_t interval = 0;

    // Re-enable watchdog if recovery (DLR) interval configured.
    la_mac_port::la_pfc_priority_t pfc_priority;
    lasai_pfc_base::get_pfc_priority(queue_index, pfc_priority);
    m_pfc_dev->get_pfc_dlr_interval(pfc_priority, interval);
    if (detected && interval) {
        status = set_pfc_watchdog_enabled(queue_index, true);
        if (status != LA_STATUS_SUCCESS) {
            sai_log_error(SAI_API_QUEUE,
                          "Failed to enable PFC wdog for port(%d/%d/%d) queue(%d) dectected(%d).",
                          m_mac_port->get_slice(),
                          m_mac_port->get_ifg(),
                          m_mac_port->get_first_serdes_id(),
                          queue_index,
                          detected);
        }
    }

    bool drop = true;
    m_pfc_dev->is_pfc_dlr_drop(drop);
    if (drop) {
        status = init_pfc_watchdog_recovery(queue_index, detected);
    }

    if (!detected || (status != LA_STATUS_SUCCESS)) {
        // Enable PFC watchdog if queue is not stuck or recovery
        // process failed.
        status = set_pfc_watchdog_enabled(queue_index, true);
        if (status != LA_STATUS_SUCCESS) {
            sai_log_error(SAI_API_QUEUE,
                          "Failed to enable PFC wdog after recovery event for port(%d/%d/%d) queue(%d) detected(%d).",
                          m_mac_port->get_slice(),
                          m_mac_port->get_ifg(),
                          m_mac_port->get_first_serdes_id(),
                          queue_index,
                          detected);
        }
    }
}

bool
lasai_port_pfc::is_pfc_queue_stuck(sai_queue_index_t queue_index)
{
    la_status status;
    la_mac_port::pfc_queue_state_e queue_state;
    la_mac_port::la_pfc_priority_t pfc_priority;
    status = lasai_pfc_base::get_pfc_priority(queue_index, pfc_priority);
    if (status == LA_STATUS_SUCCESS) {
        status = m_mac_port->get_pfc_queue_state(pfc_priority, queue_state);
    }
    return ((status == LA_STATUS_SUCCESS) && (queue_state == la_mac_port::pfc_queue_state_e::NOT_TRANSMITTING_DUE_TO_PFC));
}

void
lasai_port_pfc::set_pfc_watchdog_dld_interval(la_mac_port::la_pfc_priority_t tc, uint32_t interval)
{
    la_status status;
    status = m_mac_port->set_pfc_queue_watchdog_polling_interval(tc, std::chrono::milliseconds(interval));
    if (status != LA_STATUS_SUCCESS) {
        sai_log_error(SAI_API_SWITCH,
                      "Failed to set PFC wdog detection interval for port(%d/%d/%d) queue(%d).",
                      m_mac_port->get_slice(),
                      m_mac_port->get_ifg(),
                      m_mac_port->get_first_serdes_id(),
                      tc);
    }
}

void
lasai_port_pfc::set_pfc_watchdog_dlr_interval(la_mac_port::la_pfc_priority_t tc, uint32_t interval)
{
    la_status status;
    status = m_mac_port->set_pfc_queue_watchdog_recovery_interval(tc, std::chrono::milliseconds(interval));
    if (status != LA_STATUS_SUCCESS) {
        sai_log_error(SAI_API_SWITCH,
                      "Failed to set PFC wdog recovery interval for port(%d/%d/%d) queue(%d).",
                      m_mac_port->get_slice(),
                      m_mac_port->get_ifg(),
                      m_mac_port->get_first_serdes_id(),
                      tc);
    }
}

la_status
configure_lossy_user_policy(la_rx_cgm_sq_profile* profile)
{
    la_status status;

    // set CGM policy (see ofa_la_tm_pfc_update_hw_source_cgm_policy)
    for (la_uint_t ctr_a_status = 0; ctr_a_status < LA_CGM_NUM_SMS_BYTES_QUANTIZATION_REGIONS; ctr_a_status++) {
        for (la_uint_t sqg_status = 0; sqg_status < LA_RX_CGM_NUM_SQG_QUANTIZATION_REGIONS; sqg_status++) {
            for (la_uint_t sq_status = 0; sq_status < LA_RX_CGM_NUM_SQ_PROFILE_QUANTIZATION_REGIONS; sq_status++) {
                bool flow_control, drop_yellow, drop_green, fc_trig;
                la_rx_cgm_policy_status rx_cgm_status = {
                    .counter_a_region = ctr_a_status, .sq_group_region = sqg_status, .sq_profile_region = sq_status,
                };
                flow_control = drop_yellow = drop_green = fc_trig = false;
                if (sq_status >= 1) {
                    drop_yellow = drop_green = true;
                }
                status = profile->set_rx_cgm_policy(rx_cgm_status, flow_control, drop_yellow, drop_green, fc_trig);
                la_return_on_error(status);
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
configure_lossy_user_profile(la_rx_cgm_sq_profile* profile, la_uint32_t threshold1)
{
    la_status status;
    la_rx_cgm_sq_profile_thresholds rx_cgm_sq;

    rx_cgm_sq.thresholds[0] = threshold1;
    rx_cgm_sq.thresholds[1] = threshold1;
    rx_cgm_sq.thresholds[2] = threshold1;
    status = profile->set_thresholds(rx_cgm_sq);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
configure_lossless_policy(la_rx_cgm_sq_profile* profile)
{
    la_status status;

    // set CGM policy (see ofa_la_tm_pfc_update_hw_source_cgm_policy)
    for (la_uint_t ctr_a_status = 0; ctr_a_status < LA_CGM_NUM_SMS_BYTES_QUANTIZATION_REGIONS; ctr_a_status++) {
        for (la_uint_t sqg_status = 0; sqg_status < LA_RX_CGM_NUM_SQG_QUANTIZATION_REGIONS; sqg_status++) {
            for (la_uint_t sq_status = 0; sq_status < LA_RX_CGM_NUM_SQ_PROFILE_QUANTIZATION_REGIONS; sq_status++) {
                bool flow_control, drop_yellow, drop_green, fc_trig;
                la_rx_cgm_policy_status rx_cgm_status = {
                    .counter_a_region = ctr_a_status, .sq_group_region = sqg_status, .sq_profile_region = sq_status,
                };
                // initialize policy values
                flow_control = drop_yellow = drop_green = false;
                fc_trig = true;

                if ((sq_status == 3) || (ctr_a_status == 3)) {
                    flow_control = drop_yellow = drop_green = true;

                } else if ((sq_status == 2) || (ctr_a_status == 2) || ((sq_status == 1) && (ctr_a_status == 1))) {
                    flow_control = true;
                }
                // initialize lossless PFC profile policy
                status = profile->set_rx_cgm_policy(rx_cgm_status, flow_control, drop_yellow, drop_green, fc_trig);
                la_return_on_error(status);
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
configure_lossless_profile(la_rx_cgm_sq_profile* profile,
                           la_uint32_t pause_threshold,
                           la_uint32_t head_room,
                           la_uint_t head_room_max,
                           uint8_t percentage)
{
    la_status status;
    la_rx_cgm_sq_profile_thresholds rx_cgm_sq;

    rx_cgm_sq.thresholds[0] = (percentage * pause_threshold) / 100;
    rx_cgm_sq.thresholds[1] = pause_threshold;
    rx_cgm_sq.thresholds[2] = pause_threshold + head_room;
    status = profile->set_thresholds(rx_cgm_sq);
    la_return_on_error(status);

    // set maximum head room threshold
    status = profile->set_pfc_headroom_threshold(head_room_max * BUFFER_POOL_ENTRY_SIZE);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

} // namespace sai
} // namespace silicon_one
