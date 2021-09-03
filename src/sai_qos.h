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

#ifndef __SAI_QOS_H__
#define __SAI_QOS_H__

#include <jansson.h>
#include <memory>
#include <unordered_map>

extern "C" {
#include <sai.h>
}

#include "sai_db.h"
#include "sai_utils.h"
#include "sai_warm_boot.h"

namespace silicon_one
{
namespace sai
{
struct lasai_qos_map_list_t {
    /** Number of entries in the map */
    uint32_t count;
    sai_qos_map_t* list;

    /** Map list */
    std::shared_ptr<sai_qos_map_t> shared_list;
};

class lasai_to_sdk_qos_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // need virtual destructor for serialization tool
    virtual ~lasai_to_sdk_qos_base() = default;

    void inc_ref_count()
    {
        m_reference_count++;
    }

    void dec_ref_count()
    {
        m_reference_count--;
    }

    uint32_t ref_count() const
    {
        return m_reference_count;
    }

protected:
    uint32_t m_reference_count = 0;
};

class lasai_to_sdk_qos_ingress : public lasai_to_sdk_qos_base
{
public:
    lasai_to_sdk_qos_ingress() = default;
    virtual ~lasai_to_sdk_qos_ingress() = default;
    bool operator==(const lasai_to_sdk_qos_ingress& prof_info) const
    {
        return (m_dscp_to_color == prof_info.m_dscp_to_color) && (m_dscp_to_tc == prof_info.m_dscp_to_tc)
               && (m_pcpdei_to_color == prof_info.m_pcpdei_to_color) && (m_pcpdei_to_tc == prof_info.m_pcpdei_to_tc)
               && (m_mpls_to_color == prof_info.m_mpls_to_color) && (m_mpls_to_tc == prof_info.m_mpls_to_tc);
    }

public:
    uint32_t m_dscp_to_color;
    uint32_t m_dscp_to_tc;
    uint32_t m_pcpdei_to_color;
    uint32_t m_pcpdei_to_tc;
    uint32_t m_mpls_to_tc;
    uint32_t m_mpls_to_color;
    la_obj_wrap<la_ingress_qos_profile> m_sdk_profile;
};

class lasai_to_sdk_qos_egress : public lasai_to_sdk_qos_base
{
public:
    lasai_to_sdk_qos_egress() = default;
    virtual ~lasai_to_sdk_qos_egress() = default;

public:
    la_obj_wrap<la_egress_qos_profile> m_sdk_profile;
};

class lasai_to_sdk_tc_profile : public lasai_to_sdk_qos_base
{
public:
    virtual ~lasai_to_sdk_tc_profile() = default;

public:
    uint32_t m_tc_to_queue;
    la_obj_wrap<la_tc_profile> m_sdk_profile;
};

class lasai_qos_map
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    friend class lasai_qos;

public:
    explicit lasai_qos_map(sai_qos_map_type_t type = SAI_QOS_MAP_TYPE_CUSTOM_RANGE_BASE, uint32_t element_count = 0)
        : m_map_type(type)
    {
        m_value_mapping.count = element_count;
        if (element_count != 0) {
            m_value_mapping.shared_list
                = std::shared_ptr<sai_qos_map_t>(new sai_qos_map_t[element_count], std::default_delete<sai_qos_map_t[]>());
            m_value_mapping.list = m_value_mapping.shared_list.get();
        } else {
            m_value_mapping.list = nullptr;
        }
    }

private:
    sai_qos_map_type_t m_map_type;
    lasai_qos_map_list_t m_value_mapping;
    uint32_t m_reference_count = 0;
};

class lasai_qos
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    friend class lsai_device;

    static const uint32_t MAX_QOS_MAPS = 1000;
    static const uint32_t SAI_QOS_NON_VALID_INDEX = 0xFFFF;
    static const uint32_t MAX_QOS_TC_VAL = 7;
    static const uint32_t MAX_QOS_DSCP_VAL = 63;
    static const uint32_t MAX_QOS_DOT1P_VAL = 15;
    static const uint32_t MAX_QOS_PRIO_VAL = 7;
    static const uint32_t MAX_QOS_PG_VAL = 7;
    static const uint32_t MAX_QOS_QUEUE_INDEX_VAL = 7;
    static const la_qos_color_e MAX_QOS_COLOR_VAL = la_qos_color_e::RED;

public:
    lasai_qos() = default; // for warm boot
    lasai_qos(std::shared_ptr<lsai_device> sai_dev);

    // QOS_MAP static handler functions
    static sai_status_t verify_prio_queue_one_to_one(sai_qos_map_list_t map_list);
    static sai_status_t verify_limits(sai_qos_map_t& qos_entry);
    static sai_status_t create_qos_map(_Out_ sai_object_id_t* qos_map_id,
                                       _In_ sai_object_id_t switch_id,
                                       _In_ uint32_t attr_count,
                                       _In_ const sai_attribute_t* attr_list);
    static sai_status_t remove_qos_map(_In_ sai_object_id_t qos_map_id);
    static sai_status_t set_qos_map_attribute(_In_ sai_object_id_t qos_map_id, _In_ const sai_attribute_t* attr);
    static sai_status_t get_qos_map_attribute(_In_ sai_object_id_t qos_map_id,
                                              _In_ uint32_t attr_count,
                                              _Inout_ sai_attribute_t* attr_list);
    static sai_status_t sai_qos_map_attr_type_get(_In_ const sai_object_key_t* key,
                                                  _Inout_ sai_attribute_value_t* value,
                                                  _In_ uint32_t attr_index,
                                                  _Inout_ vendor_cache_t* cache,
                                                  void* arg);
    static sai_status_t sai_qos_map_attr_list_set(_In_ const sai_object_key_t* key,
                                                  _In_ const sai_attribute_value_t* value,
                                                  void* arg);
    static sai_status_t sai_qos_map_attr_list_get(_In_ const sai_object_key_t* key,
                                                  _Inout_ sai_attribute_value_t* value,
                                                  _In_ uint32_t attr_index,
                                                  _Inout_ vendor_cache_t* cache,
                                                  void* arg);

    // Switch attributes handler functions
    static sai_status_t set_qos_map(std::shared_ptr<lsai_device> sdev,
                                    uint32_t new_map_index,
                                    std::shared_ptr<lasai_to_sdk_qos_ingress> ingress_qos_profile,
                                    sai_qos_map_type_t map_type);
    static sai_status_t set_qos_map(std::shared_ptr<lsai_device> sdev,
                                    _In_ const sai_attribute_value_t* value,
                                    std::shared_ptr<lasai_to_sdk_qos_ingress> ingress_qos_profile,
                                    sai_qos_map_type_t map_type);
    static sai_status_t switch_attr_qos_map_set(_In_ const sai_object_key_t* key,
                                                _In_ const sai_attribute_value_t* value,
                                                void* arg);
    static sai_object_id_t get_qos_map(std::shared_ptr<lsai_device> sdev,
                                       std::shared_ptr<lasai_to_sdk_qos_ingress> ingress_qos_profile,
                                       sai_qos_map_type_t map_type,
                                       uint32_t map_index);
    static sai_status_t switch_attr_qos_map_get(_In_ const sai_object_key_t* key,
                                                _Inout_ sai_attribute_value_t* value,
                                                _In_ uint32_t attr_index,
                                                _Inout_ vendor_cache_t* cache,
                                                void* arg);
    static sai_status_t set_qos_tc_map(std::shared_ptr<lsai_device> sdev,
                                       _In_ const sai_attribute_value_t* value,
                                       std::shared_ptr<lasai_to_sdk_tc_profile> tc_profile);
    static sai_status_t switch_attr_tc_map_set(_In_ const sai_object_key_t* key,
                                               _In_ const sai_attribute_value_t* value,
                                               void* arg);
    static sai_object_id_t get_qos_tc_map(std::shared_ptr<lsai_device> sdev, std::shared_ptr<lasai_to_sdk_tc_profile> tc_profile);
    static sai_status_t switch_attr_tc_map_get(_In_ const sai_object_key_t* key,
                                               _Inout_ sai_attribute_value_t* value,
                                               _In_ uint32_t attr_index,
                                               _Inout_ vendor_cache_t* cache,
                                               void* arg);
    la_status initialize_default_qos_profiles(transaction& txn, std::shared_ptr<lsai_device> sdev);
    // QOS functions for leaba
    la_status initialize_default_ingress_qos_profile(transaction& txn);
    la_status initialize_default_egress_qos_profile(transaction& txn);

    void clear_profile_qos_map(std::shared_ptr<lasai_to_sdk_qos_base> qos_profile, _In_ uint32_t index);
    sai_status_t set_ingress_profile_qos_map(std::shared_ptr<lsai_device> sdev,
                                             std::shared_ptr<lasai_to_sdk_qos_ingress> qos_profile,
                                             const lasai_to_sdk_qos_ingress& in_prof_info);

    la_status create_sdk_ingress_qos_profile(transaction& txn, std::shared_ptr<lasai_to_sdk_qos_ingress>& out_prof_info);
    void destroy_sdk_ingress_qos_profile(std::shared_ptr<lasai_to_sdk_qos_ingress> profile);
    sai_status_t setup_ingress_qos_profile(std::shared_ptr<lsai_device> sdev,
                                           _In_ const sai_attribute_value_t* map_attr,
                                           _In_ const sai_qos_map_type_t map_type,
                                           std::shared_ptr<lasai_to_sdk_qos_ingress> in_qos_profile,
                                           std::shared_ptr<lasai_to_sdk_qos_ingress>& out_qos_profile,
                                           _Out_ bool& using_default);
    static la_status configure_sdk_ingress_qos_profile(std::shared_ptr<lsai_device> sdev,
                                                       const lasai_to_sdk_qos_ingress& prof_info,
                                                       bool program_defaults);
    la_status create_sdk_egress_qos_profile(transaction& txn, std::unique_ptr<lasai_to_sdk_qos_egress>& out_prof_info);
    static la_status configure_sdk_egress_qos_profile(const lasai_to_sdk_qos_egress& prof_info);
    la_status create_sdk_tc_profile(transaction& txn, std::shared_ptr<lasai_to_sdk_tc_profile>& prof_info);
    void destroy_sdk_tc_profile(std::shared_ptr<lasai_to_sdk_tc_profile> profile);
    sai_status_t setup_tc_profile(std::shared_ptr<lsai_device> sdev,
                                  _In_ const sai_attribute_value_t* map_attr,
                                  std::shared_ptr<lasai_to_sdk_tc_profile> in_tc_profile,
                                  std::shared_ptr<lasai_to_sdk_tc_profile>& out_tc_profile,
                                  _Out_ bool& using_default);
    static la_status configure_sdk_tc_profile(std::shared_ptr<lsai_device> sdev, const lasai_to_sdk_tc_profile& prof_info);
    static sai_status_t update_qos_map_ref_count(std::shared_ptr<lsai_device> sdev,
                                                 sai_object_id_t old_map_oid,
                                                 sai_object_id_t new_map_oid);
    static std::vector<sai_uint8_t> get_pg_to_tc_list(std::shared_ptr<lsai_device> sdev,
                                                      sai_uint8_t ingress_priority_group,
                                                      sai_object_id_t qos_map_oid);
    la_ingress_qos_profile* get_default_ingress_qos_profile() const;
    la_egress_qos_profile* get_default_egress_qos_profile() const;
    la_tc_profile* get_default_tc_profile() const;
    void dump_json(json_t* parent_json) const;
    void dump();

private:
    static void qos_map_id_to_str(_In_ sai_object_id_t qos_map_id, _Out_ char* key_str);
    static sai_status_t check_and_get_device_and_map_id(const sai_object_id_t& qos_map_id,
                                                        std::shared_ptr<lsai_device>& out_sdev,
                                                        uint32_t& out_map_id,
                                                        lasai_qos_map& out_qos_map);
    static sai_status_t check_params_and_get_map_index(const sai_attribute_value_t* value,
                                                       std::shared_ptr<lsai_device> sdev,
                                                       uint32_t& out_map_id,
                                                       sai_qos_map_type_t map_type);
    static sai_status_t check_params_and_get_device(const sai_object_key_t* key, std::shared_ptr<lsai_device>& sdev);
    static la_qos_color_e sai_color_to_la_color(sai_packet_color_t sai_color);

private:
    // translate map type to the relevant default map
    std::unordered_map<uint32_t, sai_object_id_t> m_default_qos_maps;
    obj_db<lasai_qos_map> m_qos_map_db{SAI_OBJECT_TYPE_QOS_MAP, MAX_QOS_MAPS};
    std::shared_ptr<lsai_device> m_lsai_device;

    std::shared_ptr<lasai_to_sdk_qos_ingress> m_default_ingress_qos_profile = nullptr;
    std::unique_ptr<lasai_to_sdk_qos_egress> m_default_egress_qos_profile = nullptr;
    std::shared_ptr<lasai_to_sdk_tc_profile> m_default_tc_profile = nullptr;

    std::unordered_map<uint32_t, std::shared_ptr<lasai_to_sdk_tc_profile>> m_tc_profiles;
    std::vector<std::shared_ptr<lasai_to_sdk_qos_ingress>> m_ingress_qos_profiles;
};
}
}

#ifdef ENABLE_SERIALIZATION
#include "common/cereal_utils.h"

namespace cereal
{
template <class Archive>
void save(Archive&, const silicon_one::sai::lasai_qos_map_list_t&);
template <class Archive>
void load(Archive&, silicon_one::sai::lasai_qos_map_list_t&);
}
#endif
#endif //__SAI_QOS_H__
