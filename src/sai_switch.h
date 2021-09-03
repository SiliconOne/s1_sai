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

#ifndef __SAI_SWITCH_H__
#define __SAI_SWITCH_H__

#include <stdint.h>
#include <vector>
#include "api/system/la_device.h"
#include "la_sai_object.h"

namespace silicon_one
{
namespace sai
{
la_device* get_la_device(uint32_t sw_id);
std::vector<uint32_t> get_sai_switch_id_list();
sai_status_t get_device_freq(std::shared_ptr<lsai_device> sdev, _Inout_ int& device_freq);
}
}
#endif
