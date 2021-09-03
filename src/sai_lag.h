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

#ifndef __SAI_LAG_H__
#define __SAI_LAG_H__

#include "api/types/la_common_types.h"
#include "api/types/la_system_types.h"

#include "saitypes.h"

#include "sai_device.h"

namespace silicon_one
{
namespace sai
{
/// @brief	Set MTU on the underlying mac_port
///
/// @param[in]  sys_port	Pointer of sys_port
/// @param[in]  mtu_value	MTU value
///
/// @return     sai_status_t
/// @retval		SAI_STATUS_ITEM_NOT_FOUND   Underlying port is not a mac_port, may not be an error.
/// @retval		SAI_STATUS_SUCCESS          Successfully return MTU value.
sai_status_t lsai_set_mac_port_mtu(const la_system_port* sys_port, la_uint_t mtu_value);
}
}
#endif
