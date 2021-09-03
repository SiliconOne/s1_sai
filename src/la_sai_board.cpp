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

#include "la_sai_board.h"

namespace silicon_one
{
namespace sai
{

// Initialize the vectors with given number of IFGs.
// Function will clear all members, resize members with num_of_ifgs in each IFG.
// And, set empty vector to each item in IFGs.
// num_of_ifgs: Total numbers of IFG
void
lsai_lane_settings_t::initialize(la_uint32_t num_of_ifgs)
{
    ifg_swap.assign(num_of_ifgs, {});
    anlt_order.assign(num_of_ifgs, {});
    rx_inverse.assign(num_of_ifgs, {});
    tx_inverse.assign(num_of_ifgs, {});
}

// Initialize the vectors with given vector of serdes counts per ifg.
// Function will clear all members, resize members with num_of_ifgs for each IFG.
// And, set an empty vector to polarity inverse and set no-swap values on both swap and anlt_order for each IFG.
// If Json file has the specific swap and anlt_order for the IFG, values will be overwritten by config_parser::load_lane_settings()
// serdes_per_ifg: Number of Serdes Per IFG vectors
void
lsai_lane_settings_t::initialize(const std::vector<la_uint32_t>& serdes_per_ifg)
{
    auto num_of_ifgs = serdes_per_ifg.size();
    initialize(num_of_ifgs);

    // Initialize settings lane swap and invertion for based on slice/ifg/serdes
    std::vector<la_uint32_t> no_swap;
    for (la_uint32_t serdes_idx = 0; serdes_idx < 32; serdes_idx++) {
        no_swap.push_back(serdes_idx);
    }
    auto no_swap_begin = no_swap.begin();

    for (la_uint32_t ifg_idx = 0; ifg_idx < num_of_ifgs; ifg_idx++) {
        // deep copy of no_swap to ifg_swap and anlt_order
        ifg_swap[ifg_idx].assign(no_swap_begin, no_swap_begin + serdes_per_ifg[ifg_idx]);
        anlt_order[ifg_idx].assign(no_swap_begin, no_swap_begin + serdes_per_ifg[ifg_idx]);
    }
}

void
lsai_serdes_key_counters_t::inc(const lsai_serdes_media_type_e& media_type)
{
    switch (media_type) {
    case lsai_serdes_media_type_e::NOT_PRESENT:
        not_present++;
        break;
    case lsai_serdes_media_type_e::COPPER:
        copper++;
        break;
    case lsai_serdes_media_type_e::OPTIC:
        optic++;
        break;
    case lsai_serdes_media_type_e::CHIP2CHIP:
        chip2chip++;
        break;
    case lsai_serdes_media_type_e::LOOPBACK:
        loopback++;
        break;
    default:
        error_cnt++;
    }
}

la_uint32_t
lsai_serdes_key_counters_t::total()
{
    return not_present + copper + optic + chip2chip + loopback;
}

lsai_port_cfg_t::lsai_port_cfg_t(const uint32_t& pif, const uint32_t& num_of_lanes, std::vector<sai_attribute_t>& attrs)
    : m_attrs(attrs)
{
    for (uint32_t idx = 0; idx < num_of_lanes; idx++) {
        m_pif_lanes.push_back(pif + idx);
    }
}
}
}
