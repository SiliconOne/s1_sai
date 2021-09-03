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

#include "sai_constants.h"
#include "sai_device.h"
#include "sai_port.h"
#include "sai_system_port.h"
#include "sai_utils.h"
#include "port_helper.h"

namespace silicon_one
{
namespace sai
{

sai_status_t
teardown_system_port_for_port_entry(shared_ptr<lsai_device> sdev, port_entry* pentry)
{
    la_voq_set* voq_set = nullptr;
    la_voq_set* voq_set_ecn = nullptr;
    la_status status;
    if (pentry->sys_port != nullptr) {
        la_system_port_gid_t gid = pentry->sys_port->get_gid();
        sdev->remove_la2sai_port(gid);

        voq_set = pentry->sys_port->get_voq_set();
        if (pentry->type == port_entry_type_e::MAC) {
            voq_set_ecn = pentry->sys_port->get_ect_voq_set();
        }

        status = sdev->m_dev->destroy(pentry->sys_port);
        sai_return_on_la_error(status, "Failed to remove system port for 0x%lx %s", pentry->service.oid, status.message().c_str());
        pentry->sys_port = nullptr;
    }

    if (voq_set != nullptr) {
        // stop the voq_set
        status = voq_set->set_state(silicon_one::la_voq_set::state_e::DROPPING);
        sai_return_on_la_error(
            status, "Fail to set voq set to drop state for 0x%lx %s", pentry->service.oid, status.message().c_str());

        // When destroying voq_set, voq_counter_set will be destroyed as well.
        status = sdev->m_dev->destroy(voq_set);
        sai_return_on_la_error(status, "Fail to remove voq set for 0x%lx %s", pentry->service.oid, status.message().c_str());
    }
    if (voq_set_ecn != nullptr) {
        // stop the voq_set
        status = voq_set_ecn->set_state(silicon_one::la_voq_set::state_e::DROPPING);
        sai_return_on_la_error(
            status, "Fail to set ecn voq set to drop state for 0x%lx %s", pentry->service.oid, status.message().c_str());

        // When destroying voq_set, voq_counter_set will be destroyed as well.
        status = sdev->m_dev->destroy(voq_set_ecn);
        sai_return_on_la_error(status, "Fail to remove ecn voq set for 0x%lx %s", pentry->service.oid, status.message().c_str());
    }

    // set the admin_state to false because we have destroyed the sys_port already.
    pentry->admin_state = false;

    return SAI_STATUS_SUCCESS;
}

voq_cfg_manager::voq_cfg_manager(shared_ptr<lsai_device> sdev) : m_sdev(sdev)
{
}

sai_status_t
voq_cfg_manager::validate_mandatory_voq_attr(std::unordered_map<sai_attr_id_t, sai_attribute_value_t>& attribs,
                                             sai_switch_attr_t attr,
                                             sai_attribute_value_t& attr_value,
                                             bool& has_attr)
{
    auto attr_it = attribs.find(attr);
    has_attr = (attr_it != attribs.end());
    bool is_voq = is_voq_switch();

    if (is_voq && (!has_attr)) {
        sai_log_error(SAI_API_SWITCH, "VOQ-mandatory attribute %s missing", to_string(attr).c_str());
        return SAI_STATUS_MANDATORY_ATTRIBUTE_MISSING;
    }

    if ((!is_voq) && has_attr) {
        sai_log_error(SAI_API_SWITCH,
                      "VOQ-only attr %s provided for non-voq switch (type %s)",
                      to_string(attr).c_str(),
                      to_string(m_switch_type).c_str());
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (has_attr) {
        attr_value = attr_it->second;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
voq_cfg_manager::initialize(const sai_attribute_t* attr_list, uint32_t attr_count)
{
    auto attribs = sai_parse_attributes(attr_count, attr_list);
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    get_attrs_value(SAI_SWITCH_ATTR_TYPE, attribs, m_switch_type, false);
    sai_log_debug(SAI_API_SWITCH, "Switch type %s", to_string(m_switch_type).c_str());
    if ((!is_npu_switch()) && (!is_voq_switch())) {
        // TODO: Support FABRIC mode.
        sai_log_error(SAI_API_SWITCH, "Switch type %s is not implemented", to_string(m_switch_type).c_str());
        return SAI_STATUS_NOT_IMPLEMENTED;
    }

    sai_status_t sai_status;
    bool has_attr;
    sai_attribute_value_t attr_value;

    // SAI_SWITCH_ATTR_SWITCH_ID
    sai_status = validate_mandatory_voq_attr(attribs, SAI_SWITCH_ATTR_SWITCH_ID, attr_value, has_attr);
    sai_return_on_error(sai_status);

    if (has_attr) {
        m_switch_voq_id = get_attr_value(SAI_SWITCH_ATTR_SWITCH_ID, attr_value);
    }

    // SAI_SWITCH_ATTR_MAX_SYSTEM_CORES
    sai_status = validate_mandatory_voq_attr(attribs, SAI_SWITCH_ATTR_MAX_SYSTEM_CORES, attr_value, has_attr);
    sai_return_on_error(sai_status);

    if (has_attr) {
        m_max_system_cores = get_attr_value(SAI_SWITCH_ATTR_MAX_SYSTEM_CORES, attr_value);
    }

    // SAI_SWITCH_ATTR_SYSTEM_PORT_CONFIG_LIST
    sai_status = validate_mandatory_voq_attr(attribs, SAI_SWITCH_ATTR_SYSTEM_PORT_CONFIG_LIST, attr_value, has_attr);
    sai_return_on_error(sai_status);

    if (has_attr) {
        sai_system_port_config_list_t cfg_list = get_attr_value(SAI_SWITCH_ATTR_SYSTEM_PORT_CONFIG_LIST, attr_value);

        // Verify list values
        for (uint32_t i = 0; i < cfg_list.count; ++i) {
            const sai_system_port_config_t& cfg = cfg_list.list[i];
            // NB: m_switch_voq_id and m_sdev must already be set here
            sai_status_t status = verify_system_port_config(cfg, SAI_API_SWITCH);
            sai_return_on_error(status);
        }

        // Save to internal memory
        for (uint32_t i = 0; i < cfg_list.count; ++i) {
            const sai_system_port_config_t& cfg = cfg_list.list[i];
            uint32_t starting_lane = to_sai_lane(cfg);
            m_lane_to_config[starting_lane] = cfg;
        }
    }
#endif
    return SAI_STATUS_SUCCESS;
}

sai_status_t
voq_cfg_manager::verify_system_port_config(const sai_system_port_config_t& sp_cfg, sai_api_t api_log) const
{
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    // Note:
    // attached_core_index is overall ifg index (2 * slice_id + ifg_id)
    // attached_core_port_index is starting pif lane within the given ifg

    sai_status_t bad_cfg = SAI_STATUS_INVALID_ATTR_VALUE_0 + SAI_SYSTEM_PORT_ATTR_CONFIG_INFO;

    const uint32_t num_ifgs = m_sdev->m_dev_params.slices_per_dev * m_sdev->m_dev_params.ifgs_per_slice;
    // Verify attached_core_index does not exceed number of IFGs
    if (sp_cfg.attached_core_index >= num_ifgs) {
        sai_log_error(api_log,
                      "System port with ID %u has attached_core_index %u which is an invalid IFG (num IFG = %u)",
                      sp_cfg.port_id,
                      sp_cfg.attached_core_index,
                      num_ifgs);
        return bad_cfg;
    }

    // Verify attached_core_port_index fits in 1 byte
    uint32_t acpi = sp_cfg.attached_core_port_index;
    if ((acpi >> BITS_IN_BYTE) > 0) {
        sai_log_error(
            api_log, "System port with ID %u has too large attached_core_port_index (%u exceeds 1 byte)", sp_cfg.port_id, acpi);
        return bad_cfg;
    }

    // Verify attached_core_port_index (pif lane on IFG) is a valid
    // lane for either ordinary serdes or internal ports
    la_uint32_t num_lanes = m_sdev->m_dev_params.serdes_per_ifg[sp_cfg.attached_core_index];
    if (!((acpi < num_lanes) || (acpi == m_sdev->m_dev_params.host_serdes_id)
          || (acpi == m_sdev->m_dev_params.recycle_serdes_id))) {
        sai_log_error(api_log,
                      "System port with ID %u has attached_core_port_index %u which cannot be matched to"
                      " any valid lane (<%zu) or internal port (pci,npu-host=%u; recycle=%u)",
                      sp_cfg.port_id,
                      acpi,
                      num_lanes,
                      m_sdev->m_dev_params.host_serdes_id,
                      m_sdev->m_dev_params.recycle_serdes_id);
        return bad_cfg;
    }

    // Only NUM_QUEUE_PER_PORT voqs for a system port is currently supported
    if (sp_cfg.num_voq != NUM_QUEUE_PER_PORT) {
        sai_log_error(api_log, "Num voq %d not supported", sp_cfg.num_voq);
        return bad_cfg;
    }

    // Remote ports not supported yet
    if (sp_cfg.attached_switch_id != m_switch_voq_id) {
        sai_log_error(api_log,
                      "Creating remote system port for device %u on this device %u is not supported",
                      sp_cfg.attached_switch_id,
                      m_switch_voq_id);
        return bad_cfg;
    }
#endif
    return SAI_STATUS_SUCCESS;
}

bool
voq_cfg_manager::is_npu_switch() const
{
    return (m_switch_type == SAI_SWITCH_TYPE_NPU);
}

bool
voq_cfg_manager::is_voq_switch() const
{
    return (m_switch_type == SAI_SWITCH_TYPE_VOQ);
}

la_status
voq_cfg_manager::get_sp_cfg_from_lane(uint32_t starting_lane, sai_system_port_config_t& sp_config) const
{
    auto cfg_it = m_lane_to_config.find(starting_lane);
    if (cfg_it == m_lane_to_config.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    sp_config = cfg_it->second;
    return LA_STATUS_SUCCESS;
}

sai_status_t
voq_cfg_manager::get_switch_voq_id(uint32_t& switch_voq_id) const
{
    if (!is_voq_switch()) {
        sai_log_error(SAI_API_SWITCH, "Non-VOQ switch type %s does not have a switch ID", to_string(m_switch_type).c_str());
        return SAI_STATUS_FAILURE;
    }
    switch_voq_id = m_switch_voq_id;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
voq_cfg_manager::get_max_system_cores(uint32_t& max_system_cores) const
{
    if (!is_voq_switch()) {
        sai_log_error(SAI_API_SWITCH, "Non-VOQ switch type %s does not have a max system cores", to_string(m_switch_type).c_str());
        return SAI_STATUS_FAILURE;
    }
    max_system_cores = m_max_system_cores;
    return SAI_STATUS_SUCCESS;
}

sai_switch_type_t
voq_cfg_manager::get_switch_type() const
{
    return m_switch_type;
}

la_status
voq_cfg_manager::create_front_panel_system_ports(transaction& txn)
{
    for (auto it = m_lane_to_config.begin(); it != m_lane_to_config.end(); it++) {
        uint32_t sai_lane = it->first;
        uint32_t pif = sai_lane & HW_LANE_PIF_MASK;
        if ((pif != m_sdev->m_dev_params.host_serdes_id) && (pif != m_sdev->m_dev_params.recycle_serdes_id)) {
            // Front panel port, so setup system port
            txn.status = setup_sai_system_port(sai_lane, it->second, m_sdev, txn);
            la_return_on_error(txn.status);
        }
    }
    return LA_STATUS_SUCCESS;
}
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
sai_status_t
voq_cfg_manager::get_system_port_config_list(sai_attribute_value_t* value)
{
    auto sysport_map = m_sdev->m_system_ports.map();

    return fill_sai_list(sysport_map.begin(),
                         sysport_map.end(),
                         value->sysportconfiglist,
                         [](std::pair<uint32_t, system_port_entry> x) { return x.second.config_info; });
}
#endif

// clang-format off

sai_status_t system_port_type_get(_In_ const sai_object_key_t* key,
                                  _Inout_ sai_attribute_value_t* value,
                                  _In_ uint32_t attr_index,
                                  _Inout_ vendor_cache_t* cache,
                                  void* arg);

sai_status_t port_for_system_port_get(_In_ const sai_object_key_t* key,
                                      _Inout_ sai_attribute_value_t* value,
                                      _In_ uint32_t attr_index,
                                      _Inout_ vendor_cache_t* cache,
                                      void* arg);

sai_status_t system_port_config_info_get(_In_ const sai_object_key_t* key,
                                         _Inout_ sai_attribute_value_t* value,
                                         _In_ uint32_t attr_index,
                                         _Inout_ vendor_cache_t* cache,
                                         void* arg);

extern const sai_attribute_entry_t system_port_attribs[] = {
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1,5,2)
    {SAI_SYSTEM_PORT_ATTR_TYPE, false, false, false, true, "Local or remote system port type", SAI_ATTR_VAL_TYPE_SYSPORTTYPE},
    {SAI_SYSTEM_PORT_ATTR_PORT, false, false, false, true, "Port SAI object ID this system port is attached to", SAI_ATTR_VAL_TYPE_OID},
    {SAI_SYSTEM_PORT_ATTR_CONFIG_INFO, true, true, false, true, "Config info for this system port", SAI_ATTR_VAL_TYPE_SYSPORTCONFIGINFO},
#endif
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t system_port_vendor_attribs[] = {
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1,5,2)
    {SAI_SYSTEM_PORT_ATTR_TYPE,
     {false, false, false, true},
     {false, false, false, true},
     system_port_type_get, nullptr, nullptr, nullptr},
    {SAI_SYSTEM_PORT_ATTR_PORT,
     {false, false, false, true},
     {false, false, false, true},
     port_for_system_port_get, nullptr, nullptr, nullptr},
    {SAI_SYSTEM_PORT_ATTR_CONFIG_INFO,
     {true, false, false, true},
     {true, false, false, true},
     system_port_config_info_get, nullptr, nullptr, nullptr}
#endif
};

// clang-format on

sai_status_t
verify_system_port_get(const sai_object_key_t* key, sai_attribute_value_t* value, std::shared_ptr<lsai_device> sdev)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // Only allowed to use system port API on a VOQ switch
    if (!sdev->m_voq_cfg_manager->is_voq_switch()) {
        sai_log_error(SAI_API_PORT, "System port getter failed for port ID %d, switch not in VOQ mode", key->key.object_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
system_port_type_get(_In_ const sai_object_key_t* key,
                     _Inout_ sai_attribute_value_t* value,
                     _In_ uint32_t attr_index,
                     _Inout_ vendor_cache_t* cache,
                     void* arg)
{
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    lsai_object la_sp(key->key.object_id);
    auto sdev = la_sp.get_device();

    sai_status_t sai_status;
    sai_status = verify_system_port_get(key, value, sdev);
    sai_return_on_error(sai_status);

    system_port_entry spentry{};
    la_status status = sdev->m_system_ports.get(la_sp.index, spentry);
    sai_return_on_la_error(status);

    uint32_t switch_voq_id;
    sai_status = sdev->m_voq_cfg_manager->get_switch_voq_id(switch_voq_id);
    sai_return_on_error(sai_status);

    bool is_local = (switch_voq_id == spentry.config_info.attached_switch_id);
    sai_system_port_type_t sp_type = (is_local ? SAI_SYSTEM_PORT_TYPE_LOCAL : SAI_SYSTEM_PORT_TYPE_REMOTE);
    set_attr_value(SAI_SYSTEM_PORT_ATTR_TYPE, *value, sp_type);
#endif
    return SAI_STATUS_SUCCESS;
}

sai_status_t
port_for_system_port_get(_In_ const sai_object_key_t* key,
                         _Inout_ sai_attribute_value_t* value,
                         _In_ uint32_t attr_index,
                         _Inout_ vendor_cache_t* cache,
                         void* arg)
{
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    lsai_object la_sp(key->key.object_id);
    auto sdev = la_sp.get_device();

    sai_status_t sai_status;
    sai_status = verify_system_port_get(key, value, sdev);
    sai_return_on_error(sai_status);

    system_port_entry spentry{};
    la_status status = sdev->m_system_ports.get(la_sp.index, spentry);
    sai_return_on_la_error(status);

    set_attr_value(SAI_SYSTEM_PORT_ATTR_PORT, *value, spentry.port_oid);
#endif
    return SAI_STATUS_SUCCESS;
}

sai_status_t
system_port_config_info_get(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg)
{
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    lsai_object la_sp(key->key.object_id);
    auto sdev = la_sp.get_device();

    sai_status_t sai_status;
    sai_status = verify_system_port_get(key, value, sdev);
    sai_return_on_error(sai_status);

    system_port_entry spentry{};
    la_status status = sdev->m_system_ports.get(la_sp.index, spentry);
    sai_return_on_la_error(status);

    set_attr_value(SAI_SYSTEM_PORT_ATTR_CONFIG_INFO, *value, spentry.config_info);
#endif
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
create_system_port(sai_object_id_t* system_port_id,
                   sai_object_id_t switch_id,
                   uint32_t attr_count,
                   const sai_attribute_t* attr_list)
{
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_SYSTEM_PORT, SAI_OBJECT_TYPE_SWITCH, switch_id, &attr_to_string<sai_system_port_attr_t>, switch_id, attrs);

    if (!sdev->m_voq_cfg_manager->is_voq_switch()) {
        sai_log_error(SAI_API_SYSTEM_PORT, "Cannot create system port in non-VOQ mode");
        return SAI_STATUS_FAILURE;
    }

    auto admin_state_it = attrs.find(SAI_SYSTEM_PORT_ATTR_ADMIN_STATE);
    if (admin_state_it != attrs.end()) {
        sai_log_error(SAI_API_SYSTEM_PORT, "Admin state for system port is not supported");
        return SAI_STATUS_ATTR_NOT_SUPPORTED_0 + SAI_SYSTEM_PORT_ATTR_ADMIN_STATE;
    }

    sai_system_port_config_t sp_config{};
    get_attrs_value(SAI_SYSTEM_PORT_ATTR_CONFIG_INFO, attrs, sp_config, true);

    uint32_t switch_voq_id;
    sai_status_t sai_status = sdev->m_voq_cfg_manager->get_switch_voq_id(switch_voq_id);
    sai_return_on_error(sai_status);

    sai_status = sdev->m_voq_cfg_manager->verify_system_port_config(sp_config, SAI_API_SYSTEM_PORT);
    sai_return_on_error(sai_status);

    transaction txn{};

    // Identify the port this SP belongs to
    uint32_t pif = sp_config.attached_core_port_index;
    uint32_t lane = to_sai_lane(sp_config);
    sai_object_id_t sai_port_id;
    txn.status = sdev->get_lane_to_port(lane, sai_port_id);
    sai_return_on_la_error(txn.status,
                           "Couldn't find local port OID for system port %u with starting lane %u in device IFG index %u",
                           sp_config.port_id,
                           sp_config.attached_core_port_index,
                           sp_config.attached_core_index);

    lsai_object la_port(sai_port_id);
    port_entry* pentry{nullptr};
    txn.status = sdev->m_ports.get_ptr(la_port.index, pentry);
    sai_return_on_la_error(txn.status);

    la_slice_id_t slice_id = sp_config.attached_core_index / sdev->m_dev_params.ifgs_per_slice;
    la_ifg_id_t ifg_id = sp_config.attached_core_index % sdev->m_dev_params.ifgs_per_slice;

    switch (pentry->type) {
    case port_entry_type_e::MAC: {
        la_mac_port* mac_port;
        txn.status = sdev->m_dev->get_mac_port(slice_id, ifg_id, pif, mac_port);
        sai_return_on_la_error(txn.status, "Couldn't get mac port starting on lane [%u/%u/%u]", slice_id, ifg_id, pif);

        // Verify system port speed matches port speed
        la_mac_port::port_speed_e sdk_port_speed;
        txn.status = mac_port->get_speed(sdk_port_speed);
        sai_return_on_la_error(txn.status, "Couldn't get mac port speed");

        uint32_t sai_port_speed = sdk_to_sai_speed(sdk_port_speed);

        if (sai_port_speed != sp_config.speed) {
            sai_log_error(SAI_API_SYSTEM_PORT,
                          "System port speed (%u) does not match its port speed (ID 0x%lx, speed %u)",
                          sp_config.speed,
                          pentry->service.oid,
                          sai_port_speed);
            return SAI_STATUS_INVALID_ATTR_VALUE_0 + SAI_SYSTEM_PORT_ATTR_CONFIG_INFO;
        }

        txn.status = setup_la_system_port(
            mac_port, pif + lsai_device::SAI_VSC_PORT_BASE, sp_config.speed, pentry, sdev, txn, &(sp_config.port_id));
        sai_return_on_la_error(txn.status, "Couldn't setup system port");
    } break;
    case port_entry_type_e::PCI:
    case port_entry_type_e::INTERNAL_PCI:
        // PCI port
        txn.status = setup_la_system_port(
            sdev->m_pci_ports[slice_id], lsai_device::SAI_VSC_PCI_INDEX, sp_config.speed, pentry, sdev, txn, &(sp_config.port_id));
        sai_return_on_la_error(txn.status);
        sdev->m_pci_sys_ports[slice_id] = pentry->sys_port;
        break;
    case port_entry_type_e::NPUH: {
        // NPU host port, explicitly set the SP GID since
        // normal LA system port setup is being bypassed.
        pentry->sp_gid = sp_config.port_id;
        txn.status = sdev->setup_npuh_port(sp_config.speed, pentry, txn);
        sai_return_on_la_error(txn.status);
    } break;
    case port_entry_type_e::RECYCLE: {
        // Recycle port
        txn.status = setup_la_system_port(sdev->m_recycle_ports[slice_id],
                                          lsai_device::SAI_VSC_RECYCLE_INDEX,
                                          sp_config.speed,
                                          pentry,
                                          sdev,
                                          txn,
                                          &(sp_config.port_id));
        sai_return_on_la_error(txn.status);
    } break;
    }

    // Allocate system port SAI index
    uint32_t sp_index = 0;
    txn.status = sdev->m_system_ports.allocate_id(sp_index);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_system_ports.release_id(sp_index); });

    // Create sp object
    lsai_object la_sp(SAI_OBJECT_TYPE_SYSTEM_PORT, la_obj.switch_id, sp_index);

    // Insert object into system ports db
    system_port_entry sp_entry{};
    sp_entry.sp_oid = la_sp.object_id();
    sp_entry.port_oid = sai_port_id;
    sp_entry.config_info = sp_config;
    txn.status = sdev->m_system_ports.set(*system_port_id, sp_entry, la_sp);

    pentry->sp_oid = la_sp.object_id();

    // TODO: Create and set attrs

    sai_log_debug(SAI_API_SYSTEM_PORT,
                  "sai_system_port(0x%lx) created: Starting lane [%d/%d/%d], speed %d, num VOQ %d",
                  la_sp.object_id(),
                  slice_id,
                  ifg_id,
                  pif,
                  sp_config.speed,
                  sp_config.num_voq);

    sai_log_info(SAI_API_SYSTEM_PORT, "system port id 0x%0lx created", la_sp.object_id());
#endif
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_system_port(sai_object_id_t system_port_id)
{
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    sai_start_api(
        SAI_API_SYSTEM_PORT, SAI_OBJECT_TYPE_SYSTEM_PORT, system_port_id, &attr_to_string<sai_system_port_attr_t>, system_port_id);

    lsai_object sp_obj(system_port_id);
    system_port_entry sp_entry;
    la_status status = sdev->m_system_ports.get(sp_obj.index, sp_entry);
    sai_return_on_la_error(status);

    // Get pentry
    port_entry* pentry{nullptr};
    status = sdev->m_ports.get_ptr(sp_entry.port_oid, pentry);
    sai_return_on_la_error(status);

    // Teardown for this system port
    sai_status_t sai_status = teardown_system_port_for_port_entry(sdev, pentry);
    sai_return_on_error(sai_status);

    // Reset port_entry's sp_oid (only relevant in VOQ switch mode, so
    // not performed in teardown)
    pentry->sp_oid = 0;

    // Remove SAI system port
    sdev->m_system_ports.remove(system_port_id);
#endif
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_system_port_attribute(sai_object_id_t system_port_id, const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_system_port_attribute(sai_object_id_t system_port_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = system_port_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_SYSTEM_PORT,
                  SAI_OBJECT_TYPE_SYSTEM_PORT,
                  system_port_id,
                  &attr_to_string<sai_system_port_attr_t>,
                  system_port_id,
                  attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "system port 0x%0lx", system_port_id);
    return sai_get_attributes(&key, key_str, system_port_attribs, system_port_vendor_attribs, attr_count, attr_list);
#else
    return SAI_STATUS_SUCCESS;
#endif
}

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
const sai_system_port_api_t system_port_api
    = {create_system_port, remove_system_port, set_system_port_attribute, get_system_port_attribute};
#endif

} // namespace sai
} // namespace silicon_one
