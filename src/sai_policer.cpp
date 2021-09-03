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

#include "sai_policer.h"
#include "sai_utils.h"
#include "sai_logger.h"
#include "sai_device.h"
#include "sai_leaba.h"

namespace silicon_one
{
namespace sai
{

using namespace std;

policer_manager::~policer_manager() = default;

la_meter_profile*
policer_manager::get_meter_profile(lasai_policer* policer)
{
    // change pps only the first time or when there is no attached list
    if (policer->m_attach_list.size() == 0 || policer->m_pps_profile_index == lsai_pps_profile_e::MAX) {
        if (policer->m_profile.m_type == SAI_METER_TYPE_PACKETS) {
            policer->m_pps_profile_index = policer_manager::cir_to_profile_pps(policer->m_cir);
        }
    }

    if (policer->m_pps_profile_index >= lsai_pps_profile_e::MAX) {
        return nullptr;
    }

    return m_pps_policer_profiles[(int)policer->m_pps_profile_index];
}

la_status
policer_manager::create_meter_profile_pps(int pps_index)
{
    la_meter_profile* meter_profile = nullptr;

    if (pps_index >= (int)lsai_pps_profile_e::MAX) {
        // internal error
        return LA_STATUS_EINVAL;
    }

    la_status status = m_sdev->m_dev->create_meter_profile(la_meter_profile::type_e::GLOBAL,
                                                           la_meter_profile::meter_measure_mode_e::PACKETS,
                                                           la_meter_profile::meter_rate_mode_e::SR_TCM,
                                                           la_meter_profile::color_awareness_mode_e::AWARE,
                                                           meter_profile);
    la_return_on_error(status);

    status = meter_profile->set_cbs(PUNT_BURST_SIZE_PPS[pps_index]);
    la_return_on_error(status);

    status = meter_profile->set_ebs_or_pbs(PUNT_EBS_SIZE);
    la_return_on_error(status);

    m_pps_policer_profiles[pps_index] = meter_profile;

    return LA_STATUS_SUCCESS;
}

la_status
policer_manager::create_meter_profile_bps()
{
    la_meter_profile* meter_profile = nullptr;

    la_status status = m_sdev->m_dev->create_meter_profile(la_meter_profile::type_e::PER_IFG,
                                                           la_meter_profile::meter_measure_mode_e::BYTES,
                                                           la_meter_profile::meter_rate_mode_e::SR_TCM,
                                                           la_meter_profile::color_awareness_mode_e::AWARE,
                                                           meter_profile);
    la_return_on_error(status);

    for (la_slice_id_t slice_id = 0; slice_id < m_sdev->m_dev_params.slices_per_dev; slice_id++) {
        for (la_ifg_id_t ifg = 0; ifg < m_sdev->m_dev_params.ifgs_per_slice; ifg++) {
            la_slice_ifg slice_ifg{slice_id, ifg};
            la_status status = meter_profile->set_cbs(slice_ifg, PUNT_BURST_SIZE);
            la_return_on_error(status);
            status = meter_profile->set_ebs_or_pbs(slice_ifg, PUNT_EBS_SIZE);
            la_return_on_error(status);
        }
    }
    m_bps_policer_profile = meter_profile;
    return LA_STATUS_SUCCESS;
}

la_status
policer_manager::initialize()
{
    for (int pps_index = 0; pps_index < (int)lsai_pps_profile_e::MAX; pps_index++) {
        la_status status = create_meter_profile_pps(pps_index);
        la_return_on_error(status);
    }
    la_status status = create_meter_profile_bps();
    la_return_on_error(status);

    lsai_policer_action_profile_t default_action;
    status = create_policer_action_profile(default_action, m_meter_action_profile);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
policer_manager::remove_policer_profile(lsai_policer_profile_t& profile)
{
    auto it = m_policer_profiles.find(profile);
    if (it != m_policer_profiles.end()) {
        if (it->second.ref_count == 1) {
            m_sdev->m_dev->destroy(it->second.m_profile);
            m_policer_profiles.erase(it);
        } else {
            it->second.ref_count--;
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
policer_manager::create_policer_profile(const lsai_policer_profile_t& profile, la_meter_profile*& la_profile)
{
    lsai_meter_profile_t meter_profile{};

    auto it = m_policer_profiles.find(profile);
    if (it == m_policer_profiles.end()) {
        la_status status = m_sdev->m_dev->create_meter_profile(
            profile.m_la_type,
            profile.m_type == SAI_METER_TYPE_PACKETS ? la_meter_profile::meter_measure_mode_e::PACKETS
                                                     : la_meter_profile::meter_measure_mode_e::BYTES,
            profile.m_mode == SAI_POLICER_MODE_SR_TCM ? la_meter_profile::meter_rate_mode_e::SR_TCM
                                                      : la_meter_profile::meter_rate_mode_e::TR_TCM,
            profile.m_color_src == SAI_POLICER_COLOR_SOURCE_BLIND ? la_meter_profile::color_awareness_mode_e::BLIND
                                                                  : la_meter_profile::color_awareness_mode_e::AWARE,
            meter_profile.m_profile);
        la_return_on_error(status);

        auto ebs_or_pbs = (profile.m_pbs == 0) ? profile.m_cbs : profile.m_pbs;
        if (ebs_or_pbs < 1024)
            ebs_or_pbs = 1024;

        if (profile.m_la_type == la_meter_profile::type_e::PER_IFG) {
            for (la_slice_id_t slice_id = 0; slice_id < m_sdev->m_dev_params.slices_per_dev; slice_id++) {
                for (la_ifg_id_t ifg = 0; ifg < m_sdev->m_dev_params.ifgs_per_slice; ifg++) {
                    la_slice_ifg slice_ifg{slice_id, ifg};
                    meter_profile.m_profile->set_cbs(slice_ifg, profile.m_cbs);
                    meter_profile.m_profile->set_ebs_or_pbs(slice_ifg, ebs_or_pbs);
                }
            }
        } else {
            meter_profile.m_profile->set_cbs(profile.m_cbs);
            meter_profile.m_profile->set_ebs_or_pbs(ebs_or_pbs);
        }

        meter_profile.ref_count = 1;
        m_policer_profiles[profile] = meter_profile;
        la_profile = meter_profile.m_profile;
    } else {
        it->second.ref_count++;
        la_profile = it->second.m_profile;
    }

    return LA_STATUS_SUCCESS;
}

la_status
policer_manager::set_la_meter_action_profile(la_meter_action_profile* action_profile,
                                             const lsai_policer_action_profile_t* lsai_profile)
{
    if (action_profile == nullptr || lsai_profile == nullptr) {
        return LA_STATUS_EINVAL;
    }

    /// @param[in]  meter_color         The result color of the meter.
    /// @param[in]  rate_limiter_color  The result color of the rate-limiter.
    /// @param[in]  drop_enable         Drop the packet.
    /// @param[in]  mark_ecn            Set ECN in the packet.
    /// @param[in]  packet_color        The new packet color.
    /// @param[in]  rx_cgm_color        The color to indicate to the RX-CGM. GREEN or YELLOW
    la_status status = LA_STATUS_SUCCESS;
    status = action_profile->set_action(la_qos_color_e::GREEN,                           // the result color of meter
                                        la_qos_color_e::GREEN,                           // the result color of rate-limiter
                                        lsai_profile->m_green == SAI_PACKET_ACTION_DROP, // drop the packet
                                        false,                                           // set ecn in the packet
                                        la_qos_color_e::GREEN,                           // new packet color
                                        la_qos_color_e::GREEN);                          // RX-CGM (GREEN or YELLOW)
    la_return_on_error(status);

    status = action_profile->set_action(la_qos_color_e::GREEN,
                                        la_qos_color_e::YELLOW,
                                        lsai_profile->m_green == SAI_PACKET_ACTION_DROP,
                                        false,
                                        la_qos_color_e::GREEN,
                                        la_qos_color_e::GREEN);
    la_return_on_error(status);

    status = action_profile->set_action(la_qos_color_e::YELLOW,
                                        la_qos_color_e::GREEN,
                                        lsai_profile->m_yellow == SAI_PACKET_ACTION_DROP,
                                        false,
                                        la_qos_color_e::YELLOW,
                                        la_qos_color_e::YELLOW);
    la_return_on_error(status);

    status = action_profile->set_action(la_qos_color_e::YELLOW,
                                        la_qos_color_e::YELLOW,
                                        lsai_profile->m_yellow == SAI_PACKET_ACTION_DROP,
                                        false,
                                        la_qos_color_e::YELLOW,
                                        la_qos_color_e::YELLOW);
    la_return_on_error(status);

    // Mark as red when either meter or rate-limiter are red
    status = action_profile->set_action(la_qos_color_e::GREEN,
                                        la_qos_color_e::RED,
                                        lsai_profile->m_green == SAI_PACKET_ACTION_DROP,
                                        false,
                                        la_qos_color_e::GREEN,
                                        la_qos_color_e::YELLOW);
    la_return_on_error(status);

    status = action_profile->set_action(la_qos_color_e::YELLOW,
                                        la_qos_color_e::RED,
                                        lsai_profile->m_yellow == SAI_PACKET_ACTION_DROP,
                                        false,
                                        la_qos_color_e::YELLOW,
                                        la_qos_color_e::YELLOW);
    la_return_on_error(status);

    status = action_profile->set_action(la_qos_color_e::RED,
                                        la_qos_color_e::GREEN,
                                        lsai_profile->m_red == SAI_PACKET_ACTION_DROP,
                                        false,
                                        la_qos_color_e::RED,
                                        la_qos_color_e::YELLOW);
    la_return_on_error(status);

    status = action_profile->set_action(la_qos_color_e::RED,
                                        la_qos_color_e::YELLOW,
                                        lsai_profile->m_red == SAI_PACKET_ACTION_DROP,
                                        false,
                                        la_qos_color_e::RED,
                                        la_qos_color_e::YELLOW);
    la_return_on_error(status);

    status = action_profile->set_action(la_qos_color_e::RED,
                                        la_qos_color_e::RED,
                                        lsai_profile->m_red == SAI_PACKET_ACTION_DROP,
                                        false,
                                        la_qos_color_e::RED,
                                        la_qos_color_e::YELLOW);
    la_return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
policer_manager::create_policer_action_profile(const lsai_policer_action_profile_t& profile, la_meter_action_profile*& la_profile)
{
    lsai_meter_action_profile_t meter_action_profile{};
    auto it = m_policer_action_profiles.find(profile);
    if (it == m_policer_action_profiles.end()) {

        la_status status = m_sdev->m_dev->create_meter_action_profile(meter_action_profile.m_profile);
        la_return_on_error(status);

        status = set_la_meter_action_profile(meter_action_profile.m_profile, &profile);
        la_return_on_error(status);

        meter_action_profile.ref_count = 1;

        m_policer_action_profiles[profile] = meter_action_profile;
        la_profile = meter_action_profile.m_profile;

    } else {
        it->second.ref_count++;
        la_profile = it->second.m_profile;
    }

    return LA_STATUS_SUCCESS;
}

la_status
policer_manager::remove_policer_action_profile(lsai_policer_action_profile_t& action_profile)
{
    auto it = m_policer_action_profiles.find(action_profile);
    if (it != m_policer_action_profiles.end()) {
        if (it->second.ref_count == 1) {
            m_sdev->m_dev->destroy(it->second.m_profile);
            m_policer_action_profiles.erase(it);
        } else {
            it->second.ref_count--;
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
policer_manager::create_policer(lasai_policer& policer, sai_object_id_t* policer_id)
{
    transaction txn;

    lsai_object la_pol(m_sdev->m_switch_id);
    la_pol.type = SAI_OBJECT_TYPE_POLICER;

    txn.status = m_policer_db.allocate_id(la_pol.index);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_policer_db.release_id(la_pol.index); });

    policer.oid = la_pol.object_id();
    txn.status = m_policer_db.set(la_pol.index, policer);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_policer_db.erase_id(la_pol.index); });

    *policer_id = policer.oid;

    return txn.status;
}

la_status
policer_manager::remove_policer(sai_object_id_t policer_id)
{
    lsai_object la_pol(policer_id);

    lasai_policer* policer = m_policer_db.get_ptr(la_pol.index);
    if (policer == nullptr) {
        sai_log_warn(SAI_API_POLICER, "policer does not exist, 0x%0lx", policer_id);
        return LA_STATUS_SUCCESS;
    }

    if (!policer->m_attach_list.empty()) {
        sai_log_error(SAI_API_POLICER, "policer 0x%lx still have the following attached:", policer_id);
        for (auto it : policer->m_attach_list) {
            sai_log_error(SAI_API_POLICER, "user 0x%lx ", it);
        }
        return LA_STATUS_EBUSY;
    }

    sai_log_info(SAI_API_POLICER, "policer 0x%0lx removed", policer_id);

    return m_policer_db.remove(policer_id);
}

la_status
policer_manager::bind_policer(sai_object_id_t object_id, sai_object_id_t policer_id)
{
    if (policer_id == SAI_NULL_OBJECT_ID) {
        // do nothing for null policer
        return LA_STATUS_SUCCESS;
    }

    lsai_object la_pol(policer_id);
    if (la_pol.type != SAI_OBJECT_TYPE_POLICER) {
        sai_log_error(SAI_API_POLICER, "Invalid policer id 0x%lx", policer_id);
        return LA_STATUS_EINVAL;
    }

    lasai_policer* policer = m_policer_db.get_ptr(la_pol.index);
    if (policer == nullptr) {
        return LA_STATUS_EINVAL;
    }

    policer->m_attach_list.insert(object_id);

    return LA_STATUS_SUCCESS;
}

la_status
policer_manager::unbind_policer(sai_object_id_t object_id, sai_object_id_t policer_id)
{
    if (policer_id == SAI_NULL_OBJECT_ID) {
        // do nothing for null policer
        return LA_STATUS_SUCCESS;
    }

    lsai_object la_pol(policer_id);
    if (la_pol.type != SAI_OBJECT_TYPE_POLICER) {
        sai_log_error(SAI_API_POLICER, "Invalid policer id 0x%lx", policer_id);
        return LA_STATUS_EINVAL;
    }

    lasai_policer* policer = m_policer_db.get_ptr(la_pol.index);
    if (policer == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (policer->m_attach_list.size() == 0) {
        return LA_STATUS_SUCCESS;
    }

    auto it = policer->m_attach_list.find(object_id);
    if (it != policer->m_attach_list.end()) {
        policer->m_attach_list.erase(it);
    }

    return LA_STATUS_SUCCESS;
}

sai_status_t
policer_manager::set_policer_attribute(sai_object_id_t policer_id, sai_policer_attr_t attr_id, const sai_attribute_value_t* value)
{
    lsai_object la_po(policer_id);

    lasai_policer* policer = m_policer_db.get_ptr(la_po.index);
    if (policer == nullptr) {
        sai_log_error(SAI_API_POLICER, "Can not set on invalid policer object 0x%lx", policer_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lasai_policer new_policer = *policer;

    switch (attr_id) {
    case SAI_POLICER_ATTR_METER_TYPE: {
        // MANDATORY_ON_CREATE | CREATE_ONLY
        auto type = get_attr_value(SAI_POLICER_ATTR_METER_TYPE, *value);
        if (type == policer->m_profile.m_type)
            return SAI_STATUS_SUCCESS;
        sai_log_error(SAI_API_POLICER, "Attribute SAI_POLICER_ATTR_METER_TYPE only valid on create");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    case SAI_POLICER_ATTR_MODE: {
        // MANDATORY_ON_CREATE | CREATE_ONLY
        auto mode = get_attr_value(SAI_POLICER_ATTR_MODE, *value);
        if (mode == policer->m_profile.m_mode)
            return SAI_STATUS_SUCCESS;
        sai_log_error(SAI_API_POLICER, "Attribute SAI_POLICER_ATTR_MODE only valid on create");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    case SAI_POLICER_ATTR_COLOR_SOURCE: {
        // CREATE_ONLY
        auto color_src = get_attr_value(SAI_POLICER_ATTR_COLOR_SOURCE, *value);
        if (color_src == policer->m_profile.m_color_src)
            return SAI_STATUS_SUCCESS;
        sai_log_error(SAI_API_POLICER, "Attribute SAI_POLICER_ATTR_COLOR_SOURCE only valid on create");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    case SAI_POLICER_ATTR_CBS: {
        new_policer.m_profile.m_cbs = get_attr_value(SAI_POLICER_ATTR_CBS, *value);
        break;
    }

    case SAI_POLICER_ATTR_CIR: {
        new_policer.m_cir = get_attr_value(SAI_POLICER_ATTR_CIR, *value);
        break;
    }

    case SAI_POLICER_ATTR_PBS: {
        new_policer.m_profile.m_pbs = get_attr_value(SAI_POLICER_ATTR_PBS, *value);
        break;
    }

    case SAI_POLICER_ATTR_PIR: {
        new_policer.m_pir = get_attr_value(SAI_POLICER_ATTR_PIR, *value);
        break;
    }

    case SAI_POLICER_ATTR_GREEN_PACKET_ACTION: {
        new_policer.m_action_profile.m_green = get_attr_value(SAI_POLICER_ATTR_GREEN_PACKET_ACTION, *value);
        break;
    }

    case SAI_POLICER_ATTR_YELLOW_PACKET_ACTION: {
        new_policer.m_action_profile.m_yellow = get_attr_value(SAI_POLICER_ATTR_YELLOW_PACKET_ACTION, *value);
        break;
    }

    case SAI_POLICER_ATTR_RED_PACKET_ACTION: {
        new_policer.m_action_profile.m_red = get_attr_value(SAI_POLICER_ATTR_RED_PACKET_ACTION, *value);
        break;
    }

    case SAI_POLICER_ATTR_ENABLE_COUNTER_PACKET_ACTION_LIST: {
        new_policer.m_enb_actions.clear();
        for (uint32_t i = 0; i < value->s32list.count; i++) {
            auto pkt_action = (sai_packet_action_t)value->s32list.list[i];
            new_policer.m_enb_actions.insert(pkt_action);
        }
        break;
    }

    default:
        break;
    }

    for (auto obj : policer->m_attach_list) {
        lsai_object la_obj(obj);
        if (la_obj.type == SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP) {
            m_sdev->m_trap_manager->update_trap_group_policer(la_obj.index, &new_policer);
        }
    }

    *policer = new_policer;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
policer_manager::get_policer_attribute(uint32_t index, sai_policer_attr_t attr_id, sai_attribute_value_t* value)
{
    lasai_policer policer;
    la_status status = m_policer_db.get(index, policer);
    sai_return_on_la_error(status);

    switch (attr_id) {
    case SAI_POLICER_ATTR_METER_TYPE:
        set_attr_value(SAI_POLICER_ATTR_METER_TYPE, *value, policer.m_profile.m_type);
        break;
    case SAI_POLICER_ATTR_MODE:
        set_attr_value(SAI_POLICER_ATTR_MODE, *value, policer.m_profile.m_mode);
        break;
    case SAI_POLICER_ATTR_COLOR_SOURCE:
        set_attr_value(SAI_POLICER_ATTR_COLOR_SOURCE, *value, policer.m_profile.m_color_src);
        break;
    case SAI_POLICER_ATTR_CBS:
        set_attr_value(SAI_POLICER_ATTR_CBS, *value, policer.m_profile.m_cbs);
        break;
    case SAI_POLICER_ATTR_CIR:
        set_attr_value(SAI_POLICER_ATTR_CIR, *value, policer.m_cir);
        break;
    case SAI_POLICER_ATTR_PBS:
        set_attr_value(SAI_POLICER_ATTR_PBS, *value, policer.m_profile.m_pbs);
        break;
    case SAI_POLICER_ATTR_PIR:
        set_attr_value(SAI_POLICER_ATTR_PIR, *value, policer.m_pir);
        break;
    case SAI_POLICER_ATTR_GREEN_PACKET_ACTION:
        set_attr_value(SAI_POLICER_ATTR_GREEN_PACKET_ACTION, *value, policer.m_action_profile.m_green);
        break;
    case SAI_POLICER_ATTR_YELLOW_PACKET_ACTION:
        set_attr_value(SAI_POLICER_ATTR_YELLOW_PACKET_ACTION, *value, policer.m_action_profile.m_yellow);
        break;
    case SAI_POLICER_ATTR_RED_PACKET_ACTION:
        set_attr_value(SAI_POLICER_ATTR_RED_PACKET_ACTION, *value, policer.m_action_profile.m_red);
        break;
    case SAI_POLICER_ATTR_ENABLE_COUNTER_PACKET_ACTION_LIST:
        fill_sai_list(policer.m_enb_actions.begin(), policer.m_enb_actions.end(), value->s32list);
        break;
    default:
        break;
    }
    return SAI_STATUS_SUCCESS;
}

std::vector<la_meter_set*>
policer_manager::get_meters(sai_object_id_t policer_id)
{
    lsai_object la_obj(policer_id);
    auto sdev = la_obj.get_device();

    std::vector<la_meter_set*> meters;

    lasai_policer* policer = sdev->m_policer_manager->m_policer_db.get_ptr(la_obj.index);
    if (policer == nullptr) {
        return meters;
    }

    for (auto oid : policer->m_attach_list) {
        lsai_object la_obj(oid);
        switch (la_obj.type) {
        case SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP: {
            auto tg_meter = sdev->m_trap_manager->get_trap_group_meters(oid);
            meters.insert(meters.end(), tg_meter.begin(), tg_meter.end());
            break;
        }
        default:
            break;
        }
    }

    auto acl_meter = sdev->m_acl_handler->get_acl_sdk_meter(policer_id);
    if (acl_meter != nullptr) {
        meters.push_back(acl_meter);
    }

    return meters;
}

// clang-format off
static const sai_attribute_entry_t policer_attribs[] = {
// id, mandatory_on_create, valid_for_create, valid_for_set, valid_for_get, name
    {SAI_POLICER_ATTR_METER_TYPE, true, true, true, true,
        "Policer Meter Type", SAI_ATTR_VAL_TYPE_U32},
    {SAI_POLICER_ATTR_MODE, true, true, true, true,
        "Policer Mode", SAI_ATTR_VAL_TYPE_U32},
    {SAI_POLICER_ATTR_COLOR_SOURCE, false, true, true, true,
        "Policer Color Source", SAI_ATTR_VAL_TYPE_U32},
    {SAI_POLICER_ATTR_CBS, false, true, true, true,
        "Policer Committed Burst Size in bytes/packets", SAI_ATTR_VAL_TYPE_U64 },
    {SAI_POLICER_ATTR_CIR, false, true, true, true,
        "Policer Committed Information Rate in bytes/packets", SAI_ATTR_VAL_TYPE_U64 },
    {SAI_POLICER_ATTR_PBS, false, true, true, true,
        "Policer Peak Burst Size in bytes/packets", SAI_ATTR_VAL_TYPE_U64 },
    {SAI_POLICER_ATTR_PIR, false, true, true, true,
        "Policer Peak Information Rate in bytes/packets", SAI_ATTR_VAL_TYPE_U64 },
    {SAI_POLICER_ATTR_GREEN_PACKET_ACTION, false, true, true, true,
        "Policer Action to take for Green packets", SAI_ATTR_VAL_TYPE_S32 },
    {SAI_POLICER_ATTR_YELLOW_PACKET_ACTION, false, true, true, true,
        "Policer Action to take for Yellow packets", SAI_ATTR_VAL_TYPE_S32 },
    {SAI_POLICER_ATTR_RED_PACKET_ACTION, false, true, true, true,
        "Policer Action to take for Red packets", SAI_ATTR_VAL_TYPE_S32 },
    {SAI_POLICER_ATTR_ENABLE_COUNTER_PACKET_ACTION_LIST, false, true, true, true,
        "Policer Enable/Disable counter", SAI_ATTR_VAL_TYPE_BOOL},

    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false,
        "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};

static sai_status_t policer_attr_get(_In_ const sai_object_key_t* key,
                                          _Inout_ sai_attribute_value_t* value,
                                          _In_ uint32_t attr_index,
                                          _Inout_ vendor_cache_t* cache,
                                          void* arg);

static sai_status_t policer_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static const sai_vendor_attribute_entry_t policer_vendor_attribs[] = {
    /*
       id,
       {create, remove, set, get}, // implemented
       {create, remove, set, get}, // supported
       getter, getter_arg,
       setter, setter_arg
    */
    { SAI_POLICER_ATTR_METER_TYPE, { true, false, false, true }, { true, false, false, true }, policer_attr_get, (void*)SAI_POLICER_ATTR_METER_TYPE, policer_attr_set, (void*)SAI_POLICER_ATTR_METER_TYPE},
    { SAI_POLICER_ATTR_MODE, { true, false, false, true }, { true, false, false, true }, policer_attr_get, (void*)SAI_POLICER_ATTR_MODE, policer_attr_set, (void*)SAI_POLICER_ATTR_MODE },
    { SAI_POLICER_ATTR_COLOR_SOURCE, { true, false, true, true }, { true, false, true, true }, policer_attr_get, (void*)SAI_POLICER_ATTR_COLOR_SOURCE, policer_attr_set, (void*)SAI_POLICER_ATTR_COLOR_SOURCE },
    { SAI_POLICER_ATTR_CBS, { true, false, true, true }, { true, false, true, true }, policer_attr_get, (void*)SAI_POLICER_ATTR_CBS, policer_attr_set, (void*)SAI_POLICER_ATTR_CBS },
    { SAI_POLICER_ATTR_CIR, { true, false, true, true }, { true, false, true, true }, policer_attr_get, (void*)SAI_POLICER_ATTR_CIR, policer_attr_set, (void*)SAI_POLICER_ATTR_CIR },
    { SAI_POLICER_ATTR_PBS, { true, false, true, true }, { true, false, true, true }, policer_attr_get, (void*)SAI_POLICER_ATTR_PBS, policer_attr_set, (void*)SAI_POLICER_ATTR_PBS },
    { SAI_POLICER_ATTR_PIR, { true, false, true, true }, { true, false, true, true }, policer_attr_get, (void*)SAI_POLICER_ATTR_PIR, policer_attr_set, (void*)SAI_POLICER_ATTR_PIR },
    { SAI_POLICER_ATTR_GREEN_PACKET_ACTION, { true, false, true, true }, { true, false, true, true }, policer_attr_get, (void*)SAI_POLICER_ATTR_GREEN_PACKET_ACTION, policer_attr_set, (void*)SAI_POLICER_ATTR_GREEN_PACKET_ACTION },
    { SAI_POLICER_ATTR_YELLOW_PACKET_ACTION, { true, false, true, true }, { true, false, true, true }, policer_attr_get, (void*)SAI_POLICER_ATTR_YELLOW_PACKET_ACTION, policer_attr_set, (void*)SAI_POLICER_ATTR_YELLOW_PACKET_ACTION },
    { SAI_POLICER_ATTR_RED_PACKET_ACTION, { true, false, true, true }, { true, false, true, true }, policer_attr_get, (void*)SAI_POLICER_ATTR_RED_PACKET_ACTION, policer_attr_set, (void*)SAI_POLICER_ATTR_RED_PACKET_ACTION },
    { SAI_POLICER_ATTR_ENABLE_COUNTER_PACKET_ACTION_LIST, { true, false, true, true }, { true, false, true, true }, policer_attr_get, (void*)SAI_POLICER_ATTR_ENABLE_COUNTER_PACKET_ACTION_LIST, policer_attr_set, (void*)SAI_POLICER_ATTR_ENABLE_COUNTER_PACKET_ACTION_LIST}
};
// clang-format on

static std::string
policer_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_policer_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << silicon_one::sai::to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
policer_attr_get(_In_ const sai_object_key_t* key,
                 _Inout_ sai_attribute_value_t* value,
                 _In_ uint32_t attr_index,
                 _Inout_ vendor_cache_t* cache,
                 void* arg)
{
    lsai_object la_pol(key->key.object_id);
    auto sdev = la_pol.get_device();
    sai_check_object(la_pol, SAI_OBJECT_TYPE_POLICER, sdev, "policer", key->key.object_id);

    int32_t attr_id = (uintptr_t)arg;

    return sdev->m_policer_manager->get_policer_attribute(la_pol.index, (sai_policer_attr_t)attr_id, value);
}

static sai_status_t
policer_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    lsai_object la_pol(key->key.object_id);
    auto sdev = la_pol.get_device();

    int32_t attr_id = (uintptr_t)arg;

    return sdev->m_policer_manager->set_policer_attribute(key->key.object_id, (sai_policer_attr_t)attr_id, value);
}

static void
update_policer_attributes(std::unordered_map<sai_attr_id_t, sai_attribute_value_t>& attrs, lasai_policer& policer)
{
    // loop through optional attributes
    for (auto& it : attrs) {
        switch (it.first) {
        case SAI_POLICER_ATTR_CBS:
            // default 0  create and set
            policer.m_profile.m_cbs = get_attr_value(SAI_POLICER_ATTR_CBS, it.second);
            break;
        case SAI_POLICER_ATTR_CIR:
            // default 0  create and set
            policer.m_cir = get_attr_value(SAI_POLICER_ATTR_CIR, it.second);
            break;
        case SAI_POLICER_ATTR_PBS:
            // default 0  create and set
            policer.m_profile.m_pbs = get_attr_value(SAI_POLICER_ATTR_PBS, it.second);
            break;
        case SAI_POLICER_ATTR_PIR:
            // default 0  create and set
            policer.m_pir = get_attr_value(SAI_POLICER_ATTR_PIR, it.second);
            break;
        case SAI_POLICER_ATTR_GREEN_PACKET_ACTION:
            // default FORWARD create and set
            policer.m_action_profile.m_green = get_attr_value(SAI_POLICER_ATTR_GREEN_PACKET_ACTION, it.second);
            break;
        case SAI_POLICER_ATTR_YELLOW_PACKET_ACTION:
            // default FORWARD C_S.
            policer.m_action_profile.m_yellow = get_attr_value(SAI_POLICER_ATTR_YELLOW_PACKET_ACTION, it.second);
            break;
        case SAI_POLICER_ATTR_RED_PACKET_ACTION:
            // default FORWARD C_S
            policer.m_action_profile.m_red = get_attr_value(SAI_POLICER_ATTR_RED_PACKET_ACTION, it.second);
            break;
        case SAI_POLICER_ATTR_ENABLE_COUNTER_PACKET_ACTION_LIST: {
            // default empty C_S
            for (uint32_t i = 0; i < it.second.s32list.count; i++) {
                auto pkt_action = (sai_packet_action_t)it.second.s32list.list[i];
                policer.m_enb_actions.insert(pkt_action);
            }
            break;
        }
        default:
            break;
        }
    }

    return;
}

static sai_status_t
create_policer(_Out_ sai_object_id_t* policer_id,
               _In_ sai_object_id_t switch_id,
               _In_ uint32_t attr_count,
               _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_POLICER, SAI_OBJECT_TYPE_SWITCH, switch_id, &policer_to_string, "switch", switch_id, attrs);

    lasai_policer policer{};
    get_attrs_value(SAI_POLICER_ATTR_METER_TYPE, attrs, policer.m_profile.m_type, true);
    get_attrs_value(SAI_POLICER_ATTR_MODE, attrs, policer.m_profile.m_mode, true);
    get_attrs_value(SAI_POLICER_ATTR_COLOR_SOURCE, attrs, policer.m_profile.m_color_src, false);

    update_policer_attributes(attrs, policer);

    la_status status = sdev->m_policer_manager->create_policer(policer, policer_id);
    return to_sai_status(status);
}

static sai_status_t
remove_policer(_In_ sai_object_id_t policer_id)
{
    if (policer_id == SAI_NULL_OBJECT_ID) {
        return SAI_STATUS_SUCCESS;
    }

    sai_start_api(SAI_API_POLICER, SAI_OBJECT_TYPE_POLICER, policer_id, &policer_to_string, policer_id);

    return to_sai_status(sdev->m_policer_manager->remove_policer(policer_id));
}

static sai_status_t
set_policer_attribute(_In_ sai_object_id_t policer_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = policer_id;
    sai_start_api(SAI_API_POLICER, SAI_OBJECT_TYPE_POLICER, policer_id, &policer_to_string, policer_id, "attr", *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "policer 0x%lx", policer_id);
    return sai_set_attribute(&key, key_str, policer_attribs, policer_vendor_attribs, attr);
}

static sai_status_t
get_policer_attribute(_In_ sai_object_id_t policer_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = policer_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_POLICER, SAI_OBJECT_TYPE_POLICER, policer_id, &policer_to_string, policer_id, "attrs", attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "policer 0x%lx", policer_id);
    return sai_get_attributes(&key, key_str, policer_attribs, policer_vendor_attribs, attr_count, attr_list);
}

static void
get_stats_from_meters(std::shared_ptr<lsai_device> sdev,
                      sai_stats_mode_t mode,
                      std::vector<la_meter_set*>& meter_vec,
                      la_qos_color_e color,
                      size_t& packets,
                      size_t& bytes)
{
    for (auto meter : meter_vec) {
        size_t pkts = 0, bys = 0;
        la_status status = meter->read(0, sdev->m_force_update, mode == SAI_STATS_MODE_READ_AND_CLEAR, color, pkts, bys);
        if (status == LA_STATUS_SUCCESS) {
            packets += pkts;
            bytes += bys;
        }
    }
}

static sai_status_t
get_policer_stats_ext(_In_ sai_object_id_t policer_id,
                      _In_ uint32_t number_of_counters,
                      _In_ const sai_stat_id_t* counter_ids,
                      _In_ sai_stats_mode_t mode,
                      _Out_ uint64_t* counters)
{
    lsai_object la_obj(policer_id);
    auto sdev = la_obj.get_device();
    sai_start_api_counter(sdev);

    std::vector<la_meter_set*> meter_vec = sdev->m_policer_manager->get_meters(policer_id);
    if (meter_vec.size() == 0) {
        return SAI_STATUS_SUCCESS;
    }

    size_t green_packets = 0, green_bytes = 0;
    size_t yellow_packets = 0, yellow_bytes = 0;
    size_t red_packets = 0, red_bytes = 0;

    bool read_green = false;
    bool read_yellow = false;
    bool read_red = false;
    for (uint32_t i = 0; i < number_of_counters; ++i) {
        switch (counter_ids[i]) {
        case SAI_POLICER_STAT_GREEN_BYTES: {
            if (!read_green) {
                get_stats_from_meters(sdev, mode, meter_vec, la_qos_color_e::GREEN, green_packets, green_bytes);
                read_green = true;
            }
            counters[i] = green_bytes;
            break;
        }
        case SAI_POLICER_STAT_GREEN_PACKETS: {
            if (!read_green) {
                get_stats_from_meters(sdev, mode, meter_vec, la_qos_color_e::GREEN, green_packets, green_bytes);
                read_green = true;
            }
            counters[i] = green_packets;
            break;
        }
        case SAI_POLICER_STAT_YELLOW_BYTES: {
            if (!read_yellow) {
                get_stats_from_meters(sdev, mode, meter_vec, la_qos_color_e::YELLOW, yellow_packets, yellow_bytes);
                read_yellow = true;
            }
            counters[i] = yellow_bytes;
            break;
        }
        case SAI_POLICER_STAT_YELLOW_PACKETS: {
            if (!read_yellow) {
                get_stats_from_meters(sdev, mode, meter_vec, la_qos_color_e::YELLOW, yellow_packets, yellow_bytes);
                read_yellow = true;
            }
            counters[i] = yellow_packets;

            break;
        }
        case SAI_POLICER_STAT_RED_BYTES: {
            if (!read_red) {
                get_stats_from_meters(sdev, mode, meter_vec, la_qos_color_e::RED, red_packets, red_bytes);
                read_red = true;
            }
            counters[i] = red_bytes;
            break;
        }
        case SAI_POLICER_STAT_RED_PACKETS: {
            if (!read_red) {
                get_stats_from_meters(sdev, mode, meter_vec, la_qos_color_e::RED, red_packets, red_bytes);
                read_red = true;
            }
            counters[i] = red_packets;
            break;
        }
        default:
            break;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_policer_stats(_In_ sai_object_id_t policer_id,
                  _In_ uint32_t number_of_counters,
                  _In_ const sai_stat_id_t* counter_ids,
                  _Out_ uint64_t* counters)
{
    return get_policer_stats_ext(policer_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ, counters);
}

static sai_status_t
clear_policer_stats(_In_ sai_object_id_t policer_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t* counter_ids)
{
    uint64_t counters[number_of_counters];
    return get_policer_stats_ext(policer_id, number_of_counters, counter_ids, SAI_STATS_MODE_READ_AND_CLEAR, counters);
}

const sai_policer_api_t policer_api = {create_policer,
                                       remove_policer,
                                       set_policer_attribute,
                                       get_policer_attribute,
                                       get_policer_stats,
                                       get_policer_stats_ext,
                                       clear_policer_stats};
}
}
