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

#ifndef __SAI_POLICER_H__
#define __SAI_POLICER_H__

extern "C" {
#include <sai.h>
}

#include "common/weak_ptr_unsafe.h"
#include "common/ranged_index_generator.h"
#include "api/types/la_common_types.h"
#include "api/qos/la_meter_profile.h"
#include "api/qos/la_meter_set.h"
#include "api/npu/la_rate_limiter_set.h"
#include "sai_utils.h"
#include "sai_db.h"
#include <set>
#include <map>

using namespace std;

namespace silicon_one
{
namespace sai
{

class lsai_device;
class policer_manager;

enum class lsai_pps_profile_e { SMALL = 0, MEDIUM = 1, LARGE = 2, MAX = 3 };

struct lsai_policer_profile_t {
    la_meter_profile::type_e m_la_type;
    sai_meter_type_t m_type = SAI_METER_TYPE_PACKETS;
    sai_policer_mode_t m_mode = SAI_POLICER_MODE_SR_TCM;
    sai_policer_color_source_t m_color_src = SAI_POLICER_COLOR_SOURCE_AWARE;
    sai_uint64_t m_cbs = 0;
    sai_uint64_t m_pbs = 0;
};

struct lsai_meter_profile_t {
    la_obj_wrap<la_meter_profile> m_profile = nullptr;
    uint32_t ref_count = 0;
};

struct lsai_policer_action_profile_t {
    sai_packet_action_t m_green = SAI_PACKET_ACTION_FORWARD;
    sai_packet_action_t m_yellow = SAI_PACKET_ACTION_FORWARD;
    sai_packet_action_t m_red = SAI_PACKET_ACTION_DROP;
};

struct lsai_meter_action_profile_t {
    la_obj_wrap<la_meter_action_profile> m_profile = nullptr;
    uint32_t ref_count = 0;
};

struct lsai_policer_profile_less {
    inline bool operator()(const lsai_policer_profile_t& lhs, const lsai_policer_profile_t& rhs) const
    {
        return std::tie(lhs.m_la_type, lhs.m_type, lhs.m_mode, lhs.m_color_src, lhs.m_cbs, lhs.m_pbs)
               < std::tie(rhs.m_la_type, rhs.m_type, rhs.m_mode, rhs.m_color_src, rhs.m_cbs, rhs.m_pbs);
    }
};

struct lsai_policer_action_profile_less {
    inline bool operator()(const lsai_policer_action_profile_t& lhs, const lsai_policer_action_profile_t& rhs) const
    {
        return std::tie(lhs.m_green, lhs.m_yellow, lhs.m_red) < std::tie(rhs.m_green, rhs.m_yellow, rhs.m_red);
    }
};

class lasai_policer
{
    friend class policer_manager;

public:
    lasai_policer()
    {
    }

    ~lasai_policer()
    {
        for (auto it = m_enb_actions.begin(); it != m_enb_actions.end(); it++) {
            m_enb_actions.erase(it);
        }
    }

    lsai_policer_profile_t m_profile;
    lsai_policer_action_profile_t m_action_profile;

    sai_object_id_t oid = SAI_NULL_OBJECT_ID;

    sai_uint64_t m_cir = 10000000;
    sai_uint64_t m_pir = 10000000; // only for TR_TCM

    std::set<sai_packet_action_t> m_enb_actions;

    // sai_object_id_t use thse policer_id
    std::set<sai_object_id_t> m_attach_list; // sai objects that using policer

    lsai_pps_profile_e m_pps_profile_index = lsai_pps_profile_e::MAX;
};

class policer_manager
{
public:
    policer_manager() = default;
    policer_manager(std::shared_ptr<lsai_device> sdev) : m_sdev(sdev)
    {
    }

    ~policer_manager();
    // fixed to limited types of meter profile for pps according to CSCvt01022
    static constexpr uint64_t PUNT_BURST_SIZE = 102400;
    static constexpr uint64_t PUNT_EBS_SIZE = 1024;
    static constexpr uint64_t PPS_METER_MULTIPLIER = 4; /// question if gibraltar or pacific need it?
    static constexpr uint64_t CIR_DELTA = 100;
    uint64_t CIR_PROFILE_PPS[2] = {1800, 4100};
    uint64_t PUNT_BURST_SIZE_PPS[(int)lsai_pps_profile_e::MAX] = {1024, 2048, 3072};

    lsai_pps_profile_e cir_to_profile_pps(la_rate_t cir)
    {
        if (cir <= CIR_PROFILE_PPS[(int)lsai_pps_profile_e::SMALL]) {
            return lsai_pps_profile_e::SMALL;
        } else if (cir > CIR_PROFILE_PPS[(int)lsai_pps_profile_e::SMALL]
                   && cir <= CIR_PROFILE_PPS[(int)lsai_pps_profile_e::MEDIUM]) {
            return lsai_pps_profile_e::MEDIUM;
        }
        return lsai_pps_profile_e::LARGE;
    }

    static la_status set_la_meter_action_profile(la_meter_action_profile* action_profile,
                                                 const lsai_policer_action_profile_t* lsai_profile);

    la_meter_profile* get_meter_profile(lasai_policer* policer);

    obj_db<lasai_policer> m_policer_db{SAI_OBJECT_TYPE_POLICER, MAX_POLICERS};

    static constexpr int MAX_POLICERS = 32 * 1024;
    std::shared_ptr<lsai_device> m_sdev = nullptr;

    // keep policer profile vs meter_profile in policer manager for different objects to share
    std::map<lsai_policer_profile_t, lsai_meter_profile_t, lsai_policer_profile_less> m_policer_profiles;
    // keep policer action profile vs meter action profile in policer manager for different objects to share
    std::map<lsai_policer_action_profile_t, lsai_meter_action_profile_t, lsai_policer_action_profile_less>
        m_policer_action_profiles;

    la_status initialize();
    la_status create_policer(lasai_policer& policer, sai_object_id_t* policer_id);
    la_status remove_policer(sai_object_id_t policer_id);
    sai_status_t get_policer_attribute(uint32_t index, sai_policer_attr_t attr_id, sai_attribute_value_t* value);
    sai_status_t set_policer_attribute(sai_object_id_t policer_id, sai_policer_attr_t attr_id, const sai_attribute_value_t* value);
    la_status bind_policer(sai_object_id_t object_id, sai_object_id_t policer_id);
    la_status unbind_policer(sai_object_id_t object_id, sai_object_id_t policer_id);
    la_status remove_policer_profile(lsai_policer_profile_t& profile);
    la_status remove_policer_action_profile(lsai_policer_action_profile_t& action_profile);
    la_status create_policer_profile(const lsai_policer_profile_t& profile, la_meter_profile*& la_profile);
    la_status create_policer_action_profile(const lsai_policer_action_profile_t& action_profile,
                                            la_meter_action_profile*& la_profile);
    std::vector<la_meter_set*> get_meters(sai_object_id_t policer_id);
    la_meter_profile* get_bps_policer_profile()
    {
        return m_bps_policer_profile;
    }

    la_meter_profile* get_pps_policer_profiles(lsai_pps_profile_e pps_index)
    {
        if (pps_index >= lsai_pps_profile_e::MAX) {
            return nullptr;
        }
        return m_pps_policer_profiles[(int)pps_index];
    }

    la_meter_action_profile* get_meter_action_profile()
    {
        return m_meter_action_profile;
    }

    la_status create_meter_profile_pps(int pps_index);
    la_status create_meter_profile_bps();

    // meter profile for lpts and event
    std::vector<la_obj_wrap<la_meter_profile>> m_pps_policer_profiles = {nullptr, nullptr, nullptr};
    la_obj_wrap<la_meter_profile> m_bps_policer_profile = nullptr;
    la_obj_wrap<la_meter_action_profile> m_meter_action_profile = nullptr;
};
}
}
#endif
