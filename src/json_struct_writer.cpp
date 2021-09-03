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

#include "json_struct_writer.h"

namespace silicon_one
{
namespace sai
{

json_struct_writer::json_struct_writer(const char* name) : m_name(name)
{
}

void
json_struct_writer::write(const char* key, json_t* json_value)
{
    param_map_t::const_iterator kv = m_str_to_writer_func.find(key);
    if (kv != m_str_to_writer_func.end()) {
        kv->second(json_value);
    } else {
        sai_log_error(SAI_API_SWITCH, "json_struct_writer(%s): Unknown parameter \"%s\"", m_name, key);
    }
}
}
}
