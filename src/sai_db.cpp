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

#include "sai_device.h"
#include "sai_db.h"

namespace silicon_one
{
namespace sai
{
uint32_t
laobj_db_base::get_switch_id(std::shared_ptr<lsai_device> sdev) const
{
    lsai_object la_sw(sdev->m_switch_id);
    return la_sw.switch_id;
}
};
}
