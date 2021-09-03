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

#ifndef __SAI_WRED_H__
#define __SAI_WRED_H__

#include <unordered_map>

#include "api/cgm/la_voq_cgm_profile.h"
#include "common/math_utils.h"
#include "common/transaction.h"
#include "la_sai_object.h"

#include "saiwred.h"

#include "sai_constants.h"
#include "sai_db.h"
#include "sai_utils.h"
#include "sai_warm_boot.h"

namespace silicon_one
{
namespace sai
{

extern const la_voq_cgm_quantization_thresholds voq_sms_thresh_gb;

class lsai_wred
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    friend class lsai_wred_manager_base;
    friend class lsai_wred_manager_pacific;
    friend class lsai_wred_manager_gb;

    static constexpr uint8_t NUM_COLORS = 3;
    static constexpr uint8_t GREEN_INDEX = 0;
    static constexpr uint8_t YELLOW_INDEX = 1;
    static constexpr uint8_t RED_INDEX = 2;

public:
    void inc_ref_count()
    {
        m_ref_count++;
    }
    void dec_ref_count()
    {
        m_ref_count--;
    }

    la_obj_wrap<la_voq_cgm_profile> sdk_profile()
    {
        return m_sdk_profile;
    }
    la_obj_wrap<la_voq_cgm_profile> sdk_ecn_profile()
    {
        return m_ecn_sdk_profile;
    }

private:
    bool m_enabled[NUM_COLORS] = {false, false, false};
    uint32_t m_min_drop_threshold[NUM_COLORS] = {0, 0, 0};
    uint32_t m_max_drop_threshold[NUM_COLORS] = {0, 0, 0};
    uint32_t m_drop_probability[NUM_COLORS] = {100, 100, 100};
    uint8_t m_weight = 0;
    sai_ecn_mark_mode_t m_ecn_mode = SAI_ECN_MARK_MODE_NONE;
    la_obj_wrap<la_voq_cgm_profile> m_sdk_profile = nullptr;
    la_obj_wrap<la_voq_cgm_profile> m_ecn_sdk_profile = nullptr;
    uint32_t m_ref_count = 0;
    uint32_t m_min_ecn_threshold[NUM_COLORS] = {0, 0, 0};
    uint32_t m_max_ecn_threshold[NUM_COLORS] = {0, 0, 0};
    uint32_t m_ecn_probability[NUM_COLORS] = {0, 0, 0};
};

class lsai_wred_manager_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    friend class lsai_device;

    static constexpr uint32_t MAX_WRED_OBJECTS = 32;

public:
    // HBM block size is 8KB. Average utilization is expected to be 6KB
    static constexpr int HBM_BLOCK_SZ = (6 * 1024);

    lsai_wred_manager_base() = default; // for warm boot
    lsai_wred_manager_base(std::shared_ptr<lsai_device> sai_dev);
    virtual ~lsai_wred_manager_base();

    la_obj_wrap<la_voq_cgm_profile> default_uc_cgm_profile()
    {
        return m_default_uc_cgm_profile;
    }
    la_obj_wrap<la_voq_cgm_profile> default_uc_ecn_cgm_profile()
    {
        return m_default_uc_ecn_cgm_profile;
    }
    la_obj_wrap<la_voq_cgm_profile> cpu_uc_cgm_profile()
    {
        return m_cpu_uc_cgm_profile;
    }
    sai_object_id_t default_wred_obj_id()
    {
        return m_default_wred;
    }

    la_status initialize_default_mc_cgm_profile(transaction& txn, std::shared_ptr<lsai_device> sdev);
    la_status initialize(transaction& txn);
    la_status create_default_profiles(transaction& txn);

    la_status create_default_wred(transaction& txn, std::shared_ptr<lsai_device> sdev);

    static void wred_id_to_str(_In_ sai_object_id_t wred_id, _Out_ char* key_str);

    static sai_status_t create_wred(_Out_ sai_object_id_t* out_wred_id,
                                    _In_ sai_object_id_t switch_id,
                                    _In_ uint32_t attr_count,
                                    _In_ const sai_attribute_t* attr_list);
    static sai_status_t remove_wred(_In_ sai_object_id_t wred_id);
    static sai_status_t set_wred_attribute(_In_ sai_object_id_t wred_id, _In_ const sai_attribute_t* attr);
    static sai_status_t get_wred_attribute(_In_ sai_object_id_t wred_id,
                                           _In_ uint32_t attr_count,
                                           _Inout_ sai_attribute_t* attr_list);

    static sai_status_t sai_wred_attr_type_get(_In_ const sai_object_key_t* key,
                                               _Inout_ sai_attribute_value_t* value,
                                               _In_ uint32_t attr_index,
                                               _Inout_ vendor_cache_t* cache,
                                               void* arg);
    static sai_status_t sai_wred_attr_type_set(_In_ const sai_object_key_t* key,
                                               _In_ const sai_attribute_value_t* value,
                                               void* arg);

    la_status cgm_prof_from_oid(sai_object_id_t obj_id, la_voq_cgm_profile*& cgm_prof, la_voq_cgm_profile*& cgm_prof_ecn);
    virtual uint64_t cgm_level_to_bytes(uint8_t cgm_level)
    {
        return 0;
    }
    void inc_ref_count(sai_object_id_t wred_id);
    void dec_ref_count(sai_object_id_t wred_id);
    void dump();

protected:
    la_status device_level_config_base(std::shared_ptr<lsai_device> dev, bool init_hbm);
    la_status device_level_config_base_gb(std::shared_ptr<lsai_device> dev, bool init_hbm);

    virtual la_status device_level_config() = 0;
    virtual la_status cgm_profile_create(std::shared_ptr<lsai_device> sdev,
                                         const lsai_wred& sai_params,
                                         la_voq_cgm_profile* cgm_prof,
                                         bool is_cpu,
                                         bool mark_profile,
                                         bool is_default)
        = 0;
    la_status cgm_profile_create_default(std::shared_ptr<lsai_device> sdev,
                                         const lsai_wred& sai_params,
                                         la_voq_cgm_profile* cgm_prof,
                                         bool mark_profile);

    la_status cgm_profile_create_cpu(std::shared_ptr<lsai_device> sdev, const lsai_wred& sai_params, la_voq_cgm_profile* cgm_prof);

    virtual la_status hbm_profile_create_user(std::shared_ptr<lsai_device> sdev,
                                              const lsai_wred& sai_params,
                                              la_voq_cgm_profile* cgm_prof,
                                              bool mark_profile)
        = 0;

    virtual sai_status_t wred_profile_validate(const lsai_wred& wred) = 0;
    virtual la_status cgm_profile_create_user(std::shared_ptr<lsai_device> sdev,
                                              const lsai_wred& sai_params,
                                              la_voq_cgm_profile* cgm_prof,
                                              bool mark_profile)
        = 0;

    la_status inc_or_dec_ref_count(sai_object_id_t wred_id, bool inc);

protected:
    obj_db<lsai_wred> m_wred_db{SAI_OBJECT_TYPE_WRED, MAX_WRED_OBJECTS};
    std::shared_ptr<lsai_device> m_lsai_device;
    sai_object_id_t m_default_wred;
    la_obj_wrap<la_voq_cgm_profile> m_cpu_uc_cgm_profile;
    la_obj_wrap<la_voq_cgm_profile> m_default_uc_cgm_profile;
    la_obj_wrap<la_voq_cgm_profile> m_default_uc_ecn_cgm_profile;
    la_obj_wrap<la_voq_cgm_profile> m_default_mc_cgm_profile;

    la_status cgm_profile_set_sms_behavior(la_voq_cgm_profile* cgm_prof,
                                           uint32_t global_idx,
                                           uint32_t voq_idx_start,
                                           uint32_t age_idx_start,
                                           bool drop,
                                           bool evict,
                                           bool ecn);
    la_status cgm_profile_set_sms_behavior_gb(la_device* dev,
                                              la_voq_cgm_profile* cgm_prof,
                                              uint32_t global_idx,
                                              uint32_t voq_idx_start,
                                              uint32_t age_idx_start,
                                              bool gb_has_hbm,
                                              bool drop,
                                              bool evict,
                                              bool ecn,
                                              double drop_prob,
                                              double mark_prob);
    la_status cgm_profile_set_hbm_behavior_gb(la_device* dev,
                                              la_voq_cgm_profile* cgm_prof,
                                              uint32_t voq_start,
                                              uint32_t delay_start,
                                              uint32_t hbm_free_block_start,
                                              bool mark_profile);
    la_status cgm_profile_set_sms_behavior_user(std::shared_ptr<lsai_device> sdev,
                                                la_voq_cgm_profile* cgm_prof,
                                                const lsai_wred& sai_params,
                                                uint32_t global_start,
                                                uint32_t age_start,
                                                bool q_greater_than_max,
                                                bool evict);
    la_status cgm_profile_ecn_set_sms_behavior_user(std::shared_ptr<lsai_device> sdev,
                                                    la_voq_cgm_profile* cgm_prof,
                                                    const lsai_wred& sai_params,
                                                    uint32_t global_start,
                                                    uint32_t age_start,
                                                    bool q_greater_than_max,
                                                    bool evict);
    la_status set_sms_drop_behavior_user(std::shared_ptr<lsai_device> sdev,
                                         la_voq_cgm_profile* cgm_prof,
                                         uint32_t global_idx_start,
                                         uint32_t voq_idx_start,
                                         uint32_t voq_idx_end,
                                         uint32_t age_idx_start,
                                         bool q_greater_than_max,
                                         la_qos_color_e drop_color,
                                         double prob_drop_step,
                                         double drop_prob);

    la_status set_sms_mark_behavior_user(std::shared_ptr<lsai_device> sdev,
                                         la_voq_cgm_profile* cgm_prof,
                                         uint32_t global_idx_start,
                                         uint32_t voq_idx_start,
                                         uint32_t voq_idx_end,
                                         uint32_t age_idx_start,
                                         bool q_greater_than_max,
                                         la_qos_color_e mark_color,
                                         double ecn_mark_prob,
                                         uint32_t mid_min_max);

    la_status get_region_index_from_threshold_value(la_voq_cgm_quantization_thresholds threshold,
                                                    size_t value,
                                                    uint32_t& out_index);

    la_status check_presence_of_threshold_in_vector_and_get_index(la_voq_cgm_quantization_thresholds threshold,
                                                                  uint32_t value,
                                                                  uint32_t& out_index);

private:
    static sai_status_t check_and_get_device_and_map_id(const sai_object_id_t& wred_id,
                                                        std::shared_ptr<lsai_device>& out_sdev,
                                                        uint32_t& out_map_index,
                                                        lsai_wred& out_wred);
};

class lsai_wred_manager_gb : public lsai_wred_manager_base
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    lsai_wred_manager_gb() = default; // for warm boot
    lsai_wred_manager_gb(std::shared_ptr<lsai_device> sai_dev, bool& has_hbm) : lsai_wred_manager_base(sai_dev), gb_has_hbm(has_hbm)
    {
    }
    uint64_t cgm_level_to_bytes(uint8_t cgm_level) override;

private:
    bool gb_has_hbm;
    la_status device_level_config() override;
    la_status cgm_profile_create(std::shared_ptr<lsai_device> sdev,
                                 const lsai_wred& sai_params,
                                 la_voq_cgm_profile* cgm_prof,
                                 bool is_cpu,
                                 bool mark_profile,
                                 bool is_default) override;
    la_status hbm_profile_create_user(std::shared_ptr<lsai_device> sdev,
                                      const lsai_wred& sai_params,
                                      la_voq_cgm_profile* cgm_prof,
                                      bool mark_profile) override;
    sai_status_t wred_profile_validate(const lsai_wred& wred) override;
    la_status cgm_profile_set_sms_dequeue_cgm_level(la_device* dev, la_voq_cgm_profile* cgm_prof);
    la_status cgm_profile_set_hbm_dequeue_cgm_level(la_device* dev, la_voq_cgm_profile* cgm_prof);
    la_status cgm_profile_set_sms_packet_behavior(la_device* dev, la_voq_cgm_profile* cgm_prof);
    la_status cgm_profile_create_default_no_hbm(std::shared_ptr<lsai_device> sdev,
                                                const lsai_wred& sai_params,
                                                la_voq_cgm_profile* cgm_prof,
                                                bool is_cpu,
                                                bool mark_profile,
                                                bool is_default);
    la_status cgm_profile_create_default_hbm(std::shared_ptr<lsai_device> sdev,
                                             const lsai_wred& sai_params,
                                             la_voq_cgm_profile* cgm_prof,
                                             bool is_cpu,
                                             bool mark_profile);
    la_status hbm_profile_create_default(std::shared_ptr<lsai_device> sdev,
                                         const lsai_wred& sai_params,
                                         la_voq_cgm_profile* cgm_prof,
                                         bool mark_profile);

    la_status cgm_profile_create_user(std::shared_ptr<lsai_device> sdev,
                                      const lsai_wred& sai_params,
                                      la_voq_cgm_profile* cgm_prof,
                                      bool mark_profile) override;
    la_status cgm_profile_create_user_no_hbm(std::shared_ptr<lsai_device> sdev,
                                             const lsai_wred& sai_params,
                                             la_voq_cgm_profile* cgm_prof,
                                             bool mark_profile);
    la_status cgm_profile_create_user_with_hbm(std::shared_ptr<lsai_device> sdev,
                                               const lsai_wred& sai_params,
                                               la_voq_cgm_profile* cgm_prof,
                                               bool mark_profile);

    la_status set_hbm_behavior_user(std::shared_ptr<lsai_device> sdev,
                                    la_voq_cgm_profile* cgm_prof,
                                    uint32_t voq_idx_start,
                                    uint32_t voq_idx_end,
                                    bool drop,
                                    la_qos_color_e drop_color,
                                    double prob_drop_step);
};

class lsai_wred_manager_pacific : public lsai_wred_manager_base
{

public:
    lsai_wred_manager_pacific() = default; // for warm boot
    lsai_wred_manager_pacific(std::shared_ptr<lsai_device> sai_dev) : lsai_wred_manager_base(sai_dev)
    {
    }

private:
    la_status device_level_config() override;
    la_status cgm_profile_create(std::shared_ptr<lsai_device> sdev,
                                 const lsai_wred& sai_params,
                                 la_voq_cgm_profile* cgm_prof,
                                 bool is_cpu,
                                 bool mark_profile,
                                 bool is_default) override;
    la_status hbm_profile_create_user(std::shared_ptr<lsai_device> sdev,
                                      const lsai_wred& sai_params,
                                      la_voq_cgm_profile* cgm_prof,
                                      bool mark_profile) override;
    sai_status_t wred_profile_validate(const lsai_wred& wred) override;
    la_status cgm_profile_create_user(std::shared_ptr<lsai_device> sdev,
                                      const lsai_wred& sai_params,
                                      la_voq_cgm_profile* cgm_prof,
                                      bool mark_profile) override;
};

class lsai_wred_manager_creator
{
public:
    lsai_wred_manager_creator() = default; // for warm boot
    static std::unique_ptr<lsai_wred_manager_base> create_manager(std::shared_ptr<lsai_device> sdev,
                                                                  hw_device_type_e type,
                                                                  bool has_hbm);
};
}
}
#endif
