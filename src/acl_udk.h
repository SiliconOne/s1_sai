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

#ifndef __ACL_UDK_H__
#define __ACL_UDK_H__

extern "C" {
#include <sai.h>
}

#include <unordered_map>
#include "common/ranged_index_generator.h"
#include "api/system/la_device.h"
#include "sai_utils.h"
#include "sai_constants.h"

namespace silicon_one
{
namespace sai
{

class lsai_device;

class acl_udk
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS;

public:
    acl_udk() = default;
    acl_udk(std::shared_ptr<lsai_device> sai_dev);
    ~acl_udk();
    // Process user defined acl table fields. To be used on switch attribute list
    // at the time of switch instance creation.
    sai_status_t process_user_defined_acl_table_fields(const sai_attribute_t* attr_list, uint32_t attr_count);
    // Returns true if input acl table field set matches non default acl
    // table fields.
    bool is_udk_acl_field_set(const std::set<uint32_t>& table_fields) const;
    // Returns true if input acl table field set matches or is subset of
    // default acl table fields. Also categorizes field-set as v4/v6 match profile.
    bool is_default_acl_field_set(const std::set<uint32_t>& table_fields, bool& is_v4_profile, bool& is_valid_field_set) const;
    // If an acl profile for a given set of acl table fields already exist,
    // return acl_profile
    la_acl_key_profile* get_udk_acl_profile(const std::set<uint32_t>& table_fields,
                                            uint8_t profile_type,
                                            la_acl_direction_e dir) const;
    bool is_udk_acl_profiles() const;
    const std::set<std::set<uint32_t>> get_udk_field_sets() const;
    sai_status_t create_sdk_acl_key_with_udf_fields(uint8_t profile_type,
                                                    const std::set<uint32_t>& table_fields,
                                                    la_acl_key_def_vec_t& sdk_key_vec) const;
    void destroy_acl_key_profiles();
    la_status create_sdk_acl_key_profile(uint8_t profile_type,
                                         la_acl_direction_e sdk_acl_dir,
                                         bool permanent_profile,
                                         const la_acl_key_def_vec_t& udk_fields,
                                         const std::set<uint32_t>& acl_table_fields);
    sai_status_t create_sai_acl_table_attr_field_umap(std::unordered_map<std::string, sai_acl_table_attr_t>& umap) const;
    void set_acl_key_profile_set(std::set<std::set<uint32_t>>& acl_key_profile_sets,
                                 const std::set<uint32_t> acl_key_profile_fields) const;
    sai_status_t process_acl_key_profiles(la_acl_direction_e dir, std::set<std::set<uint32_t>> acl_key_profile_sets);

private:
    void is_acl_table_attr_iphdr_distinguisher_field(uint32_t attr, bool& is_ipv4, bool& is_ipv6) const;
    bool is_default_acl_match_field(uint32_t attr_id, bool& is_v4_field, bool& is_other_field) const;
    sai_status_t create_default_acl_match_field_sets(std::set<uint32_t>& default_v4_fields, std::set<uint32_t>& default_v6_fields);
    sai_status_t get_udf_description(uint32_t attr_id, int& offset, uint8_t& width, int& pl, int& layer, la_acl_field_type_e& type)
        const;
    sai_status_t build_udf_field(la_acl_field_def& udk_acl_field, uint32_t acl_field) const;
    sai_status_t build_udf_hop_limit(la_acl_field_def& udk_acl_field) const;
    sai_status_t build_la_acl_key_vector(la_acl_direction_e sdk_acl_dir,
                                         const std::set<uint32_t>& udk_fields,
                                         la_acl_key_def_vec_t& sdk_key_vec,
                                         bool& is_v4_profile,
                                         bool& is_v6_profile,
                                         bool& add_ttl_and_hop_limit);

    sai_status_t create_user_defined_acl_sdk_profiles(la_acl_direction_e sdk_acl_dir,
                                                      const std::set<std::set<uint32_t>>& udk_field_set);
    void consolidate_set_of_udk_acl_fieldset(std::set<std::set<uint32_t>>& udk_field_sets,
                                             const std::set<uint32_t>& udk_fields) const;
    bool is_udk_field_set_v4_v6_combined(const std::set<uint32_t>& udk_field_set);
    void create_v4_v6_field_sets_from_udk(std::set<std::set<uint32_t>>& udk_field_set);
    void set_device_property_if_class_id_used(const std::set<uint32_t>& udk_fields, bool& user_meta_device_property_set) const;
    bool skip_udk_attribute(uint32_t attr_id) const;

private:
    std::shared_ptr<lsai_device> m_sdev = nullptr;
    // candidates for modification onces SDK has support for multiple acl profiles
    // per v4/v6
    static constexpr uint8_t UDK_MAX_V4_PROFILE_COUNT = 1;
    static constexpr uint8_t UDK_MAX_V6_PROFILE_COUNT = 1;
    // Contains details on UDKs used to create SDK ACL match profile.
    struct sdk_acl_profile_details {
        sdk_acl_profile_details() = default;
        sdk_acl_profile_details(const std::set<uint32_t>& udks,
                                uint8_t profile_type,
                                la_acl_direction_e dir,
                                bool permanent_profile,
                                la_acl_key_profile* profile)
            : m_udks(udks), m_profile_type(profile_type), m_dir(dir), m_permanent(permanent_profile), m_sdk_acl_profile(profile)
        {
        }
        const std::set<uint32_t> m_udks;
        uint8_t m_profile_type;
        la_acl_direction_e m_dir;
        bool m_permanent;
        la_obj_wrap<la_acl_key_profile> m_sdk_acl_profile;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(sdk_acl_profile_details);

    // a collection of sdk acl profiles created; one per each UDK field set.
    std::vector<sdk_acl_profile_details> m_sdk_acl_profiles;
};
}
}

#endif //__ACL_UDK_H__
