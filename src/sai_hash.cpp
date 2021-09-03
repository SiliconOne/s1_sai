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

#include "sai_device.h"

namespace silicon_one
{
namespace sai
{

using namespace std;

sai_status_t get_hash_native_field_list(_In_ const sai_object_key_t* key,
                                        _Inout_ sai_attribute_value_t* value,
                                        _In_ uint32_t attr_index,
                                        _Inout_ vendor_cache_t* cache,
                                        void* arg);

sai_status_t get_hash_udf_group_list(_In_ const sai_object_key_t* key,
                                     _Inout_ sai_attribute_value_t* value,
                                     _In_ uint32_t attr_index,
                                     _Inout_ vendor_cache_t* cache,
                                     void* arg);

extern const sai_attribute_entry_t hash_attribs[]
    = {{SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST, false, false, false, true, "Native hash field list", SAI_ATTR_VAL_TYPE_U32LIST},
       {SAI_HASH_ATTR_UDF_GROUP_LIST, false, true, true, true, "UDF group list", SAI_ATTR_VAL_TYPE_U32LIST},
       {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t hash_vendor_attribs[] = {{SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST,
                                                                    {false, false, false, true},
                                                                    {false, false, false, true},
                                                                    get_hash_native_field_list,
                                                                    nullptr,
                                                                    nullptr,
                                                                    nullptr},
                                                                   {SAI_HASH_ATTR_UDF_GROUP_LIST,
                                                                    {false, false, false, true},
                                                                    {false, false, false, true},
                                                                    get_hash_udf_group_list,
                                                                    nullptr,
                                                                    nullptr,
                                                                    nullptr}};
sai_status_t
laobj_db_hash::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    *count = 1;
    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_hash::get_object_keys(std::shared_ptr<lsai_device> sdev, uint32_t* object_count, sai_object_key_t* object_list) const
{
    uint32_t requested_object_count = *object_count;
    *object_count = 1;
    if (requested_object_count < 1) {
        return SAI_STATUS_BUFFER_OVERFLOW;
    } else {
        lsai_object hash_obj(SAI_OBJECT_TYPE_HASH, sdev->m_switch_id, 0);
        object_list[0].key.object_id = hash_obj.object_id();
    }
    return SAI_STATUS_SUCCESS;
}

static std::string
hash_attribute_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_hash_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

sai_status_t
get_hash_udf_group_list(_In_ const sai_object_key_t* key,
                        _Inout_ sai_attribute_value_t* value,
                        _In_ uint32_t attr_index,
                        _Inout_ vendor_cache_t* cache,
                        void* arg)
{
    value->objlist.count = 0;
    return SAI_STATUS_SUCCESS;
}

/* Get Hash native fields [sai_u32_list_t(sai_native_hash_field)] */
sai_status_t
get_hash_native_field_list(_In_ const sai_object_key_t* key,
                           _Inout_ sai_attribute_value_t* value,
                           _In_ uint32_t attr_index,
                           _Inout_ vendor_cache_t* cache,
                           void* arg)
{
    sai_object_id_t hash_id = key->key.object_id;
    lsai_object hash_obj(hash_id);
    auto sdev = hash_obj.get_device();

    sai_check_object(hash_obj, SAI_OBJECT_TYPE_HASH, sdev, "hash", hash_id);
    std::vector<uint32_t> hash_native_field_list{SAI_NATIVE_HASH_FIELD_VLAN_ID,
                                                 SAI_NATIVE_HASH_FIELD_IP_PROTOCOL,
                                                 SAI_NATIVE_HASH_FIELD_ETHERTYPE,
                                                 SAI_NATIVE_HASH_FIELD_L4_SRC_PORT,
                                                 SAI_NATIVE_HASH_FIELD_L4_DST_PORT,
                                                 SAI_NATIVE_HASH_FIELD_SRC_MAC,
                                                 SAI_NATIVE_HASH_FIELD_DST_MAC};

    return fill_sai_list(hash_native_field_list.begin(), hash_native_field_list.end(), value->u32list);
}

sai_status_t
create_hash(_Out_ sai_object_id_t* hash_id,
            _In_ sai_object_id_t switch_id,
            _In_ uint32_t attr_count,
            _In_ const sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
remove_hash(_In_ sai_object_id_t hash_id)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
set_hash_attribute(_In_ sai_object_id_t hash_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
get_hash_attribute(_In_ sai_object_id_t hash_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = hash_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_HASH, SAI_OBJECT_TYPE_HASH, hash_id, &hash_attribute_to_string, hash_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "hash 0x%0lx", hash_id);
    return sai_get_attributes(&key, key_str, hash_attribs, hash_vendor_attribs, attr_count, attr_list);
}

const sai_hash_api_t hash_api = {create_hash, remove_hash, set_hash_attribute, get_hash_attribute};
}
}
