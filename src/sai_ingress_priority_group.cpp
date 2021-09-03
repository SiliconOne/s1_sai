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

#include <memory>

#include "sai_device.h"

namespace silicon_one
{
namespace sai
{

using namespace std;

sai_status_t
laobj_db_ingress_priority_group::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    // TODO until ingress priority group supported is added, set object count to zero
    *count = 0;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_ingress_priority_group::get_object_keys(std::shared_ptr<lsai_device> sdev,
                                                 uint32_t* object_count,
                                                 sai_object_key_t* object_list) const
{
    // TODO
    return SAI_STATUS_SUCCESS;
}
}
}
