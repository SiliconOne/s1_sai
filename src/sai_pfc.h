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

#ifndef __SAI_PFC_H__
#define __SAI_PFC_H__

#include "api/system/la_device.h"
#include "api/cgm/la_rx_cgm_sq_profile.h"
#include "sai_db.h"
#include "sai_port.h"

using namespace std;

namespace silicon_one
{
namespace sai
{

//------------------------------------------------------------------------------

la_status configure_lossy_user_policy(la_rx_cgm_sq_profile* profile);
la_status configure_lossy_user_profile(la_rx_cgm_sq_profile* profile, la_uint32_t threshold1);
la_status configure_lossless_policy(la_rx_cgm_sq_profile* profile);
la_status configure_lossless_profile(la_rx_cgm_sq_profile* profile,
                                     la_uint32_t pause_threshold,
                                     la_uint32_t head_room,
                                     la_uint_t head_room_max,
                                     uint8_t percentage);

// TODO: pause_threshold and head_room needed to be configured using SAI
// buffer attributes per TC. 8 buffer profile SAI objects would be created
// with attributes, SAI_BUFFER_PROFILE_ATTR_XOFF_TH and
// SAI_BUFFER_PROFILE_ATTR_XON_TH.  These 8 buffer profile objects are then
// put into a SAI object list to be used to configure SAI port through set
// attribute  SAI_PORT_ATTR_QOS_BUFFER_PROFILE_LIST.  The port attribute
// handler will then call configure_pfc_qos().  Each profile represent
// configuration for each queue indexed by queue index value in the QoS map.
// Any profile not configure is set to SAI_NULL_OBJECT_ID.

struct pfc_config {
    sai_uint64_t pause_threshold = 0; // SAI_BUFFER_PROFILE_ATTR_XOFF_TH
    sai_uint64_t head_room = 0;       // SAI_BUFFER_POOL_ATTR_XOFF_SIZE
    sai_uint64_t ecn_threshold = 0;
    sai_uint64_t cir = 0;
    sai_uint64_t eir = 0;
};

#define NUM_PORT_TYPES 8

struct pfc_port_oq_profile {
    la_mac_port::port_speed_e type;
    la_uint_t speed;
    la_tx_cgm_oq_profile_thresholds lossy;
    la_tx_cgm_oq_profile_thresholds lossless;
};

#define NUM_METER_ACTION_PROFILES 9
struct pfc_meter_action_profile {
    la_qos_color_e meter_color;
    la_qos_color_e rate_limiter_color;
    bool drop_enable;
    bool mark_ecn;
    la_qos_color_e packet_color;
    la_qos_color_e rx_cgm_color;
};

//------------------------------------------------------------------------------

class lasai_pfc_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    friend class lsai_device;

public:
    la_tx_cgm_oq_profile_thresholds lossy_le100;
    la_tx_cgm_oq_profile_thresholds lossy_gt100;
    la_tx_cgm_oq_profile_thresholds lossless_le400;
    la_tx_cgm_oq_profile_thresholds lossless_gt400;

    // default output queue profile
    std::array<pfc_port_oq_profile, NUM_PORT_TYPES> m_oq_profiles;

    // working instances
    std::shared_ptr<lsai_device> m_sdev;

    la_obj_wrap<la_rx_cgm_sq_profile> m_lossy_source_cgm_profile = nullptr;

    lasai_pfc_base() = default; // for warm boot
    lasai_pfc_base(std::shared_ptr<lsai_device> sdev);
    virtual ~lasai_pfc_base() = default;

    virtual la_status initialize();
    la_status pfc_create_port(la_mac_port* mac_port, port_entry* pentry);
    la_status check_and_init();

    // When SAI_PORT_ATTR_QOS_BUFFER_PROFILE_LIST handler is implemented,
    // it will call this function for each item in the list.  The index
    // to the buffer profile list is TC. Use the sai_object_id_t to get
    // the threshold values and assign to pfc_config. (see addtional
    // comment above)
    virtual la_status configure_pfc_qos(la_traffic_class_t tc) = 0;

    la_status set_tc(la_mac_port* mac_port, sai_uint8_t enablebits, lsai_object obj);
    uint32_t pfc_supported_speeds[NUM_PORT_TYPES] = {10, 25, 40, 50, 100, 200, 400, 800};

    static la_status get_pfc_priority(sai_queue_index_t queue_index, la_mac_port::la_pfc_priority_t& pfc_priority);

    la_status is_pfc_dlr_drop(bool& drop);
    la_status set_pfc_dlr_drop(bool drop);
    la_status get_pfc_dld_interval(la_mac_port::la_pfc_priority_t tc, uint32_t& interval);
    void get_pfc_dld_interval_range(sai_u32_range_t& range);
    la_status set_pfc_dld_interval(la_mac_port::la_pfc_priority_t tc, uint32_t interval);
    la_status get_pfc_dlr_interval(la_mac_port::la_pfc_priority_t tc, uint32_t& interval);
    void get_pfc_dlr_interval_range(sai_u32_range_t& range);
    la_status set_pfc_dlr_interval(la_mac_port::la_pfc_priority_t tc, uint32_t interval);

    // Switch attributes handler functions
    static sai_status_t switch_pfc_dlr_packet_action_set(_In_ const sai_object_key_t* key,
                                                         _In_ const sai_attribute_value_t* value,
                                                         void* arg);
    static sai_status_t switch_pfc_dlr_packet_action_get(_In_ const sai_object_key_t* key,
                                                         _Inout_ sai_attribute_value_t* value,
                                                         _In_ uint32_t attr_index,
                                                         _Inout_ vendor_cache_t* cache,
                                                         void* arg);
    static sai_status_t switch_pfc_tc_dld_interval_range_get(_In_ const sai_object_key_t* key,
                                                             _Inout_ sai_attribute_value_t* value,
                                                             _In_ uint32_t attr_index,
                                                             _Inout_ vendor_cache_t* cache,
                                                             void* arg);
    static sai_status_t switch_pfc_tc_dld_interval_set(_In_ const sai_object_key_t* key,
                                                       _In_ const sai_attribute_value_t* value,
                                                       void* arg);
    static sai_status_t switch_pfc_tc_dld_interval_get(_In_ const sai_object_key_t* key,
                                                       _Inout_ sai_attribute_value_t* value,
                                                       _In_ uint32_t attr_index,
                                                       _Inout_ vendor_cache_t* cache,
                                                       void* arg);
    static sai_status_t switch_pfc_tc_dlr_interval_range_get(_In_ const sai_object_key_t* key,
                                                             _Inout_ sai_attribute_value_t* value,
                                                             _In_ uint32_t attr_index,
                                                             _Inout_ vendor_cache_t* cache,
                                                             void* arg);
    static sai_status_t switch_pfc_tc_dlr_interval_set(_In_ const sai_object_key_t* key,
                                                       _In_ const sai_attribute_value_t* value,
                                                       void* arg);
    static sai_status_t switch_pfc_tc_dlr_interval_get(_In_ const sai_object_key_t* key,
                                                       _Inout_ sai_attribute_value_t* value,
                                                       _In_ uint32_t attr_index,
                                                       _Inout_ vendor_cache_t* cache,
                                                       void* arg);

    bool is_pfc_initialized() const;

protected:
    bool m_init_pfc = false; // has pfc been initialized

    bool m_pfc_dlr_drop = true; // Drop packets during PFC DLR
    std::array<uint32_t, la_mac_port::LA_NUM_PFC_PRIORITY_CLASSES> m_pfc_dld_interval;
    std::array<uint32_t, la_mac_port::LA_NUM_PFC_PRIORITY_CLASSES> m_pfc_dlr_interval;

private:
    void initialize_pfc_profiles();
    la_status initialize_pfc_trap();
    la_status set_output_queue_profiles();
    la_status initialize_pfc_defaults_onports();
    la_status setup_pfc_onport(la_mac_port* port, port_entry* pentry);
};

class lasai_hw_pfc : public lasai_pfc_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    lasai_hw_pfc() = default; // for warm boot
    lasai_hw_pfc(std::shared_ptr<lsai_device> sdev);
    virtual ~lasai_hw_pfc() = default;

    la_status initialize() override;

    la_status configure_pfc_qos(la_traffic_class_t tc) override;

private:
};

class lasai_sw_pfc : public lasai_pfc_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // default meter action profiles
    static std::array<pfc_meter_action_profile, NUM_METER_ACTION_PROFILES> default_map;

    lasai_sw_pfc() = default; // for warm boot
    lasai_sw_pfc(std::shared_ptr<lsai_device> sdev);
    virtual ~lasai_sw_pfc() = default;

    la_status configure_pfc_qos(la_traffic_class_t tc) override;

    la_status initialize() override;

    // 8 PFC priority meters
    la_obj_wrap<la_meter_set> m_pfc_meter = nullptr;

private:
    la_status initialize_default_meter();
};

// class to localize per port pfc config from port_entry

class lasai_port_pfc
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    sai_object_id_t m_qos_map_oid = SAI_NULL_OBJECT_ID;

    lasai_port_pfc() = default; // for warm boot
    lasai_port_pfc(la_obj_wrap<la_mac_port> mac_port, std::shared_ptr<lasai_pfc_base> pfc_dev, sai_object_id_t port_oid);
    ~lasai_port_pfc();

    la_status initialize(port_entry* pentry);

    la_status set_prio_to_queue_map(la_uint8_t prio, la_uint8_t queue);
    la_status clear_prio_to_queue_map();
    la_status set_pfc_tc_bits(la_uint8_t enable_bits, sai_object_id_t oid);
    la_status handle_port_speed_change(sai_object_id_t oid);

    la_status get_pfc_pause_status(sai_queue_index_t queue_index, bool& paused);
    la_status get_pfc_watchdog_enabled(sai_queue_index_t queue_index, bool& enabled);
    la_status set_pfc_watchdog_enabled(sai_queue_index_t queue_index, bool enable);
    la_status init_pfc_watchdog_recovery(sai_queue_index_t queue_index, bool init);
    void pfc_deadlock_recovery(sai_queue_index_t queue_index, bool detected);
    void set_pfc_watchdog_dld_interval(la_mac_port::la_pfc_priority_t tc, uint32_t interval);
    void set_pfc_watchdog_dlr_interval(la_mac_port::la_pfc_priority_t tc, uint32_t interval);

private:
    // Whether flow control mode has been overridden by PFC. If false,
    // PFC should cache FC before changing FC to PFC mode. Otherwise,
    // old FC mode is already stored, and should be restored when PFC
    // becomes inactive
    bool m_fc_overridden = false;
    la_mac_port::fc_mode_e m_cached_fc_mode;

    bool is_pfc_queue_stuck(sai_queue_index_t pfc_priority);

    la_status pfc_watchdog_drop_or_restore(la_mac_port::la_pfc_priority_t pfc_priority, bool drop);
    la_status pfc_watchdog_drop(la_mac_port::la_pfc_priority_t pfc_priority,
                                la_voq_gid_t base_voq_id,
                                la_system_port_gid_t sys_port_gid);
    la_status pfc_watchdog_restore(la_mac_port::la_pfc_priority_t pfc_priority,
                                   la_voq_gid_t base_voq_id,
                                   la_system_port_gid_t sys_port_gid);

protected:
    la_obj_wrap<la_mac_port> m_mac_port;
    std::shared_ptr<lasai_pfc_base> m_pfc_dev;
    std::array<bool, la_mac_port::LA_NUM_PFC_PRIORITY_CLASSES> m_pfc_watchdog_enabled;
};
}
}
#endif // __SAI_PFC_H__
