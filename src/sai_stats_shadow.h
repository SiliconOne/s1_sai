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

#ifndef __SAI_STATS_SHADOW_H__
#define __SAI_STATS_SHADOW_H__

#include <string>
#include <chrono>

namespace silicon_one
{
namespace sai
{

template <typename T>
class lsai_stats_shadow
{
public:
    la_status get_data(std::shared_ptr<lsai_device>& sdev, T*& data_ptr, sai_stats_mode_t mode)
    {
        if (mode != m_last_mode) {
            return LA_STATUS_EINVAL;
        }

        std::chrono::milliseconds age_out = std::chrono::milliseconds(sdev->m_counter_refresh_interval);
        auto time_since_last_update = std::chrono::steady_clock::now() - m_last_shadow_update;
        if (time_since_last_update >= age_out) {
            return LA_STATUS_EINVAL;
        }
        data_ptr = &m_data;
        return LA_STATUS_SUCCESS;
    }

    void set_data(T& data, sai_stats_mode_t mode)
    {
        m_last_shadow_update = std::chrono::steady_clock::now();
        m_data = data;
        m_last_mode = mode;
    }

private:
    sai_stats_mode_t m_last_mode;
    std::chrono::time_point<std::chrono::steady_clock> m_last_shadow_update{};
    T m_data;
};
}
}
#endif
