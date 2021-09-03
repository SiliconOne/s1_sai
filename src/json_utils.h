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

#ifndef __JSON_UTILS_H__
#define __JSON_UTILS_H__

namespace silicon_one
{
namespace sai
{

///@brief declaration of json_t pointer for specific object name in json files include checking/error message of object type.
#define JSON_GET_OBJ_PTR(_json_obj_ptr, _obj_key, _obj_type, _obj_parent, _where_is_err)                                           \
    _json_obj_ptr = json_object_get(_obj_parent, _obj_key);                                                                        \
    if ((_json_obj_ptr == nullptr) || !json_is_##_obj_type(_json_obj_ptr)) {                                                       \
        sai_log_error(SAI_API_SWITCH, "JSON error on loading object \"%s\" as %s in %s", _obj_key, #_obj_type, _where_is_err);     \
        return LA_STATUS_EINVAL;                                                                                                   \
    }

#define json_is_hex(json) (json_is_integer(json) || json_is_string(json))

#define json_get_media_type_obj(j_media_type, j_parent)                                                                            \
    j_media_type = json_object_get(j_parent, "media_type");                                                                        \
    if (j_media_type == nullptr) {                                                                                                 \
        j_media_type = json_object_get(j_parent, "module_type");                                                                   \
    }

#define la_return_on_json_error(_json_status, _sai_api, format, ...)                                                               \
    do {                                                                                                                           \
        if (_json_status.error) {                                                                                                  \
            sai_log_error(_sai_api, format, ##__VA_ARGS__);                                                                        \
            return LA_STATUS_EINVAL;                                                                                               \
        }                                                                                                                          \
    } while (0);

// return integer value if it is a hex string or integer.
inline json_int_t
json_hex_value(json_t* j_obj)
{
    if (json_is_integer(j_obj)) {
        return json_integer_value(j_obj);
    }

    if (json_is_string(j_obj)) {
        return (json_int_t)std::strtoul(json_string_value(j_obj), nullptr, 16);
    }

    return 0;
}

inline const char*
json_key_name(json_t* j_obj)
{
    if (j_obj == nullptr) {
        return nullptr;
    }
    return json_object_iter_key(json_object_iter(j_obj));
}

struct json_status_t {
    bool error = false;
    std::string message = "";

    json_status_t(bool err, const std::string& msg) : error(err), message(msg){};
};

inline json_status_t
get_json_value(json_t* j_obj, bool& value)
{
    if (!json_is_boolean(j_obj)) {
        std::string msg = "JSON object('" + std::string(json_key_name(j_obj)) + "') is a json_type("
                          + std::to_string((int)json_typeof(j_obj)) + ") not bool.";
        return json_status_t(true, msg);
    }

    value = json_boolean_value(j_obj);
    return json_status_t(false, "");
}

inline json_status_t
get_json_value(json_t* j_obj, __int128& value)
{
    if (!json_is_integer(j_obj)) {
        std::string msg = "JSON object('" + std::string(json_key_name(j_obj)) + "') is a json_type("
                          + std::to_string((int)json_typeof(j_obj)) + ") not int.";
        return json_status_t(true, msg);
    }

    value = json_integer_value(j_obj);
    return json_status_t(false, "");
}

inline json_status_t
get_json_value(json_t* j_obj, int32_t& value)
{
    if (!json_is_integer(j_obj)) {
        std::string msg = "JSON object('" + std::string(json_key_name(j_obj)) + "') is a json_type("
                          + std::to_string((int)json_typeof(j_obj)) + ") not int.";
        return json_status_t(true, msg);
    }

    value = (int32_t)json_integer_value(j_obj);
    return json_status_t(false, "");
}

inline json_status_t
get_json_value(json_t* j_obj, int64_t& value)
{
    if (!json_is_integer(j_obj)) {
        std::string msg = "JSON object('" + std::string(json_key_name(j_obj)) + "') is a json_type("
                          + std::to_string((int)json_typeof(j_obj)) + ") not int.";
        return json_status_t(true, msg);
    }

    value = (int64_t)json_integer_value(j_obj);
    return json_status_t(false, "");
}

inline json_status_t
get_json_value(json_t* j_obj, std::string& value)
{
    if (!json_is_string(j_obj)) {
        std::string msg = "JSON object('" + std::string(json_key_name(j_obj)) + "') is a json_type("
                          + std::to_string((int)json_typeof(j_obj)) + ") not string.";
        return json_status_t(true, msg);
    }

    value = std::string(json_string_value(j_obj));
    return json_status_t(false, "");
}
}
}

#endif
