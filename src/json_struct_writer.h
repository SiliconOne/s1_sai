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

#ifndef __JSON_STRUCT_WRITER_H__
#define __JSON_STRUCT_WRITER_H__

#include <unordered_map>
#include <jansson.h>
#include "json_utils.h"
#include "sai_logger.h"

namespace silicon_one
{
namespace sai
{

// JSON utility to register memory locations to write in the event a
// specific string is observed. Deduces the templated type of the
// written memory location and saves for later. Only supports integral
// types at the moment.
class json_struct_writer
{
public:
    /// @brief json_struct_writer constructor
    ///
    /// @param[in] name Name of this writer for logging purposes.
    ///
    json_struct_writer(const char* name = "");

    /// @brief Register a location to write when a given string is encountered.
    ///
    /// @param[in] write_loc Location to set.
    /// @param[in] key Key string to associate with the location.
    ///
    template <typename T>
    void register_loc(T* write_loc, const char* key)
    {
        static_assert(std::is_integral<T>::value, "Only integral types currently supported.");
        m_str_to_writer_func[key] = [this, key, write_loc](json_t* json_val) {
            if (!json_is_hex(json_val)) {
                sai_log_error(SAI_API_SWITCH, "json_struct_writer(%s): Value for key \"%s\" must be integer or hex", key);
                return;
            }
            T new_val = static_cast<T>(json_hex_value(json_val));
            T old_val = *write_loc;
            *write_loc = new_val;
            sai_log_info(SAI_API_SWITCH,
                         "json_struct_writer(%s): Setting key \"%s\" from %s to %s",
                         m_name,
                         key,
                         std::to_string(old_val).c_str(),
                         std::to_string(new_val).c_str());
        };
    }

    /// @brief Write the given json value to its appropriate location
    /// if key was registered.
    ///
    /// @param[in] key Key that was registered (logs an error if not successful).
    /// @param[in] json_value Hex/integer value to set to the registered write location.
    void write(const char* key, json_t* json_value);

private:
    using writer_func_t = std::function<void(json_t*)>;
    using param_map_t = std::unordered_map<std::string, writer_func_t>;
    param_map_t m_str_to_writer_func;
    const char* m_name;
};
}
}

#endif
