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

#include "sai_wred.h"

#include <math.h>
#include <memory>
#include <set>
#include "api/cgm/la_voq_cgm_profile.h"
#include "api/tm/la_voq_set.h"
#include "api/types/la_cgm_types.h"
#include "api/system/la_device.h"
#include "common/gen_utils.h"
#include "sai_device.h"
#include "sai_logger.h"

namespace silicon_one
{
namespace sai
{
using namespace std;
// Quantization thresholds for total SMS bytes used
const la_voq_cgm_quantization_thresholds global_sms_thresh_gb
    = {.thresholds = {(144 * 1024 * 384), (184 * 1024 * 384), (206 * 1024 * 384)}};

const la_voq_cgm_quantization_thresholds global_sms_thresh_gb_hbm
    = {.thresholds = {(144 * 1024 * 384), (206 * 1024 * 384), (216 * 1024 * 384)}};

const la_voq_cgm_quantization_thresholds voq_sms_thresh_gb = {.thresholds = {(50 * 384),
                                                                             (256 * 384),
                                                                             (512 * 384),
                                                                             (1024 * 384),
                                                                             (2 * 1024 * 384),
                                                                             (3 * 1024 * 384),
                                                                             (6 * 1024 * 384),
                                                                             (7 * 1024 * 384),
                                                                             (8 * 1024 * 384),
                                                                             (9 * 1024 * 384),
                                                                             (10 * 1024 * 384),
                                                                             (11 * 1024 * 384),
                                                                             (12 * 1024 * 384),
                                                                             (15 * 1024 * 384),
                                                                             (16000 * 384)}};

const la_voq_cgm_quantization_thresholds voq_age_thresh_gb
    = {.thresholds
       = {16000, 32000, 48000, 64000, 80000, 96000, 112000, 128000, 144000, 160000, 176000, 192000, 208000, 224000, 255000}};

const la_voq_cgm_quantization_thresholds voq_hbm_thresh_gb = {.thresholds = {(100),
                                                                             (1 * 1024),
                                                                             (2 * 1024),
                                                                             (4 * 1024),
                                                                             (6 * 1024),
                                                                             (8 * 1024),
                                                                             (12 * 1024),
                                                                             (16 * 1024),
                                                                             (24 * 1024),
                                                                             (32 * 1024),
                                                                             (40 * 1024),
                                                                             (48 * 1024),
                                                                             (56 * 1024),
                                                                             (62 * 1024),
                                                                             (64000)}};

// Quantization thresholds in milliseconds
const la_voq_cgm_quantization_thresholds voq_delay_quant_hbm
    = {.thresholds = {1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 24, 32, 64, 128}};

// clang-format off
//======================================================================
extern const sai_attribute_entry_t wred_attribs[] = {
    // id; mandatory_on_create; valid_for_create; valid_for_set; valid_for_get
    // *attrib_name; type;
    {SAI_WRED_ATTR_GREEN_ENABLE, false, true, true, true, "WRED green enable", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_WRED_ATTR_GREEN_MIN_THRESHOLD, false, true, true, true, "WRED green min threshold", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_GREEN_MAX_THRESHOLD, false, true, true, true, "WRED green max threshold", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_GREEN_DROP_PROBABILITY, false, true, true, true, "WRED green drop probability", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_YELLOW_ENABLE, false, true, true, true, "WRED yellow enable", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD, false, true, true, true, "WRED yellow min threshold", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD, false, true, true, true, "WRED yellow max threshold", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY, false, true, true, true, "WRED yellow drop probability", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_RED_ENABLE, false, true, true, true, "WRED red enable", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_WRED_ATTR_RED_MIN_THRESHOLD, false, true, true, true, "WRED red min threshold", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_RED_MAX_THRESHOLD, false, true, true, true, "WRED red max threshold", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_RED_DROP_PROBABILITY, false, true, true, true, "WRED red drop probability", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_WEIGHT, false, true, true, true, "WRED weight", SAI_ATTR_VAL_TYPE_U8},
    {SAI_WRED_ATTR_ECN_MARK_MODE, false, true, true, true, "WRED ECN mark mode", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_ECN_GREEN_MIN_THRESHOLD, false, true, true, true, "WRED ECN green min threshold", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_ECN_GREEN_MAX_THRESHOLD , false, true, true, true, "WRED ECN green max threshold", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_ECN_GREEN_MARK_PROBABILITY, false, true, true, true, "WRED ECN green mark probability", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_ECN_YELLOW_MIN_THRESHOLD, false, true, true, true, "WRED ECN yellow min threshold", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_ECN_YELLOW_MAX_THRESHOLD, false, true, true, true, "WRED ECN yellow max threshold", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_ECN_YELLOW_MARK_PROBABILITY, false, true, true, true, "WRED ECN yellow mark probability", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_ECN_RED_MIN_THRESHOLD, false, true, true, true, "WRED ECN red min threshold", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_ECN_RED_MAX_THRESHOLD, false, true, true, true, "WRED ECN red max threshold", SAI_ATTR_VAL_TYPE_U32},
    {SAI_WRED_ATTR_ECN_RED_MARK_PROBABILITY, false, true, true, true, "WRED ECN red mark probability", SAI_ATTR_VAL_TYPE_U32},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t wred_vendor_attribs[] = {
    /* create, remove, set, get */
    {SAI_WRED_ATTR_GREEN_ENABLE,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_GREEN_ENABLE,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_GREEN_ENABLE},
    {SAI_WRED_ATTR_GREEN_MIN_THRESHOLD,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_GREEN_MIN_THRESHOLD,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_GREEN_MIN_THRESHOLD},
    {SAI_WRED_ATTR_GREEN_MAX_THRESHOLD,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_GREEN_MAX_THRESHOLD,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_GREEN_MAX_THRESHOLD},
    {SAI_WRED_ATTR_GREEN_DROP_PROBABILITY,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_GREEN_DROP_PROBABILITY,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_GREEN_DROP_PROBABILITY},
    {SAI_WRED_ATTR_YELLOW_ENABLE,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_YELLOW_ENABLE,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_YELLOW_ENABLE},
    {SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD},
    {SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD},
    {SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY},
    {SAI_WRED_ATTR_RED_ENABLE,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_RED_ENABLE,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_RED_ENABLE},
    {SAI_WRED_ATTR_RED_MIN_THRESHOLD,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_RED_MIN_THRESHOLD,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_RED_MIN_THRESHOLD},
    {SAI_WRED_ATTR_RED_MAX_THRESHOLD,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_RED_MAX_THRESHOLD,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_RED_MAX_THRESHOLD},
    {SAI_WRED_ATTR_RED_DROP_PROBABILITY,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_RED_DROP_PROBABILITY,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_RED_DROP_PROBABILITY},
    {SAI_WRED_ATTR_WEIGHT,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_WEIGHT,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_WEIGHT},
    {SAI_WRED_ATTR_ECN_MARK_MODE,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_ECN_MARK_MODE,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_ECN_MARK_MODE},
    {SAI_WRED_ATTR_ECN_GREEN_MIN_THRESHOLD,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_ECN_GREEN_MIN_THRESHOLD,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_ECN_GREEN_MIN_THRESHOLD},
    {SAI_WRED_ATTR_ECN_GREEN_MAX_THRESHOLD,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_ECN_GREEN_MAX_THRESHOLD,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_ECN_GREEN_MAX_THRESHOLD},
    {SAI_WRED_ATTR_ECN_GREEN_MARK_PROBABILITY,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_ECN_GREEN_MARK_PROBABILITY,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_ECN_GREEN_MARK_PROBABILITY},
    {SAI_WRED_ATTR_ECN_YELLOW_MIN_THRESHOLD,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_ECN_YELLOW_MIN_THRESHOLD,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_ECN_YELLOW_MIN_THRESHOLD},
    {SAI_WRED_ATTR_ECN_YELLOW_MAX_THRESHOLD,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_ECN_YELLOW_MAX_THRESHOLD,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_ECN_YELLOW_MAX_THRESHOLD},
    {SAI_WRED_ATTR_ECN_YELLOW_MARK_PROBABILITY,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_ECN_YELLOW_MARK_PROBABILITY,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_ECN_YELLOW_MARK_PROBABILITY},
    {SAI_WRED_ATTR_ECN_RED_MIN_THRESHOLD ,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_ECN_RED_MIN_THRESHOLD ,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_ECN_RED_MIN_THRESHOLD },
    {SAI_WRED_ATTR_ECN_RED_MAX_THRESHOLD,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_ECN_RED_MAX_THRESHOLD,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_ECN_RED_MAX_THRESHOLD},
    {SAI_WRED_ATTR_ECN_RED_MARK_PROBABILITY,
     {true, true, true, true}, /* implemented */
     {true, true, true, true}, /* supported */
     lsai_wred_manager_base::sai_wred_attr_type_get,
     (void*)SAI_WRED_ATTR_ECN_RED_MARK_PROBABILITY,
     lsai_wred_manager_base::sai_wred_attr_type_set,
     (void*)SAI_WRED_ATTR_ECN_RED_MARK_PROBABILITY},
};
// clang-format on

std::unique_ptr<lsai_wred_manager_base>
lsai_wred_manager_creator::create_manager(std::shared_ptr<lsai_device> sdev, hw_device_type_e type, bool has_hbm)
{
    if (type == hw_device_type_e::GIBRALTAR) {
        return make_unique<lsai_wred_manager_gb>(sdev, has_hbm);
    }

    return make_unique<lsai_wred_manager_pacific>(sdev);
}

la_status
lsai_wred_manager_gb::device_level_config()
{
    la_status status = device_level_config_base_gb(m_lsai_device, gb_has_hbm /* do hbm init for gb with hbm */);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_gb::cgm_profile_create(std::shared_ptr<lsai_device> sdev,
                                         const lsai_wred& sai_params,
                                         la_voq_cgm_profile* cgm_prof,
                                         bool is_cpu,
                                         bool mark_profile,
                                         bool is_default)
{
    la_status la_rc;

    if (!gb_has_hbm) {
        la_rc = cgm_profile_create_default_no_hbm(sdev, sai_params, cgm_prof, is_cpu, mark_profile, is_default);
        la_return_on_error(la_rc, "failed to set SMS config for GB cgm profile");
    } else {
        la_rc = cgm_profile_create_default_hbm(sdev, sai_params, cgm_prof, is_cpu, mark_profile);
        la_return_on_error(la_rc, "failed to set HBM config for GB cgm profile");
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_gb::cgm_profile_create_default_no_hbm(std::shared_ptr<lsai_device> sdev,
                                                        const lsai_wred& sai_params,
                                                        la_voq_cgm_profile* cgm_prof,
                                                        bool is_cpu,
                                                        bool mark_profile,
                                                        bool is_default)
{
    la_status la_rc;
    la_device* dev = sdev->m_dev;

    uint32_t global_idx = 0;
    la_cgm_hbm_size_in_blocks_key hbm_key(0, 0, 0);
    uint32_t evict_buff_idx = 0, free_dram_idx = 0;
    la_voq_sms_evict_key evict_ok_key;
    la_voq_sms_evict_val evict_ok_val;

    /*
     * Per VoQ used SMS bytes thresholds
     * Per VoQ age of the oldest packet thresholds in nanoseconds
     * These thresholds are based on hardware team's recommendation
     * NOTE: SMS buffer size is 384 bytes
     */

    la_rc = cgm_prof->set_sms_bytes_quantization(voq_sms_thresh_gb);
    la_return_on_error(la_rc);
    la_rc = cgm_prof->set_sms_age_quantization(voq_age_thresh_gb);
    la_return_on_error(la_rc);

    la_uint64_t num_sms_total_bytes_regions;
    la_status lstatus = dev->get_limit(limit_type_e::DEVICE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_total_bytes_regions);
    la_return_on_error(lstatus);

    la_uint64_t max_evict_sms_used_regions;
    lstatus = dev->get_limit(limit_type_e::DEVICE__SMS_NUM_EVICTED_BUFF_QUANTIZATION_REGIONS, max_evict_sms_used_regions);
    la_return_on_error(lstatus);

    la_uint64_t max_evict_voqs_regions;
    lstatus = dev->get_limit(limit_type_e::DEVICE__HBM_NUM_OF_VOQS_QUANTIZATION_REGIONS, max_evict_voqs_regions);
    la_return_on_error(lstatus);

    // dram_wred is initialized in hw to probability 0.0 which is at index 0 of probability Lut and is not reserved by SDK.
    // set_sms_wred_drop_probability overwrites index 0 of probability Lut.
    // this is a workaround for reserving probability 0.0, once SDK starts reserving it this code should be removed.
    la_cgm_wred_key key;
    la_cgm_wred_drop_val val;
    key.hbm_blocks_by_voq_region = 0;
    key.hbm_packet_size_region = 0;
    key.color = la_qos_color_e::GREEN;
    val.drop_probability = 0.0;
    la_rc = cgm_prof->set_hbm_wred_drop_configuration(key, val);
    la_return_on_error(la_rc, "Failed to set the dram wred drops to 0");

    // Init to all pass
    for (global_idx = 0; global_idx <= global_sms_thresh_gb.thresholds.size(); global_idx++) {
        uint32_t global_thresh;
        if (global_idx == 0) {
            // threshold for global_idx = 0 is 0
            global_thresh = 0;
        } else {
            global_thresh = global_sms_thresh_gb.thresholds[global_idx - 1];
        }
        la_status la_rc
            = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, global_thresh, 0, 0, gb_has_hbm, false, false, false, 0, 0);
        la_return_on_error(la_rc, "failed to set global_idx %d to all pass", global_idx);
    }

    // set the sms dequeue congestion level
    la_rc = cgm_profile_set_sms_dequeue_cgm_level(sdev->m_dev, cgm_prof);
    la_return_on_error(la_rc, "failed to set sms congestion levels");

    // with no_hbm gb set eviction to false
    evict_ok_val.permit_eviction = gb_has_hbm;
    evict_ok_val.drop_on_eviction = false;
    for (evict_buff_idx = 0; evict_buff_idx < max_evict_sms_used_regions; evict_buff_idx++) {
        evict_ok_key.evicted_buffers_region = evict_buff_idx;
        for (free_dram_idx = 0; free_dram_idx < max_evict_voqs_regions; free_dram_idx++) {
            evict_ok_key.free_dram_cntxt_region = free_dram_idx;
            la_rc = cgm_prof->set_sms_evict_behavior(evict_ok_key, evict_ok_val);
            la_return_on_error(la_rc, "failed to set evict ok for evict buff region and free dram region");
        }
    }

    // disable the default packet drop/mark/evict profile in SDK.
    la_rc = cgm_profile_set_sms_packet_behavior(dev, cgm_prof);
    la_return_on_error(la_rc, "failed to set sms packet behavior for the cgm profile");

    // below are general recomended defaults. For SAI user created profile, we should not set them. Config should be only according
    // to SAI parameters
    if (is_default) {
        double drop_prob, mark_prob;

        // If (Qsize > 12K buffers) then:
        // Drop probability is 1:100
        // Mark probability is 1:20
        for (global_idx = 0; global_idx <= global_sms_thresh_gb.thresholds.size(); global_idx++) {
            uint32_t global_thresh;
            if (global_idx == 0) {
                // threshold for global_idx = 0 is 0
                global_thresh = 0;
            } else {
                global_thresh = global_sms_thresh_gb.thresholds[global_idx - 1];
            }
            drop_prob = double(1) / double(100);
            mark_prob = double(1) / double(20);
            la_status la_rc = cgm_profile_set_sms_behavior_gb(
                dev, cgm_prof, global_thresh, (12 * 1024), 0, gb_has_hbm, true, false, true, drop_prob, mark_prob);
            la_return_on_error(la_rc, "failed to set global_idx %d Q size > 12k", global_idx);
        }

        // If (Qsize > 15K buffers) then:
        // Drop probability is 1:10
        // Mark probability is 1:1
        for (global_idx = 0; global_idx <= global_sms_thresh_gb.thresholds.size(); global_idx++) {
            uint32_t global_thresh;
            if (global_idx == 0) {
                // threshold for global_idx = 0 is 0
                global_thresh = 0;
            } else {
                global_thresh = global_sms_thresh_gb.thresholds[global_idx - 1];
            }
            drop_prob = double(1) / double(10);
            mark_prob = double(1);
            la_status la_rc = cgm_profile_set_sms_behavior_gb(
                dev, cgm_prof, global_thresh, (15 * 1024), 0, gb_has_hbm, true, false, true, drop_prob, mark_prob);
            la_return_on_error(la_rc, "failed to set global_idx %d Q size > 15k", global_idx);
        }

        // If (Qsize > 16K buffers) then:
        // Drop probability is 1:1
        for (global_idx = 0; global_idx <= global_sms_thresh_gb.thresholds.size(); global_idx++) {
            uint32_t global_thresh;
            if (global_idx == 0) {
                // threshold for global_idx = 0 is 0
                global_thresh = 0;
            } else {
                global_thresh = global_sms_thresh_gb.thresholds[global_idx - 1];
            }
            // giving drop probability as zero and setting drop bool to true would set drop to level 7 i.e 100% drop
            la_status la_rc
                = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, global_thresh, 16000, 0, gb_has_hbm, true, false, false, 0, 0);
            la_return_on_error(la_rc, "failed to set global_idx %d Q size > 16k", global_idx);
        }

        /*****************************************************************************
        * Define behavior when  the total number of SMS buffers
        * used is below 144K buffers: (0-144K)
        *****************************************************************************/

        // No drops and mark for this region based on the set of recommendations
        // Drop probability is 0
        // Mark probability is 0

        /********************************************************************************
        * Define behavior when the total number of SMS buffers used
        * is below 206 buffers: (144K-184K)
        * global_idx = 1
        *********************************************************************************/
        /*
         * If the Queue delay is above 255us and buffer > 50
         * then packet is dropped .
         * Drop probability is 1:100 , Mark probability is 1:20
         */
        drop_prob = double(1) / double(100);
        mark_prob = double(1) / double(20);
        la_rc = cgm_profile_set_sms_behavior_gb(
            dev, cgm_prof, (144 * 1024 * 384), 50, 255, gb_has_hbm, true, false, true, drop_prob, mark_prob);
        la_return_on_error(la_rc);

        /**************************************************************************************
        * Define behavior when the total number of SMS buffers used is
        * 184K - 206K buffers
        * global_idx = 2;
        **************************************************************************************

        * If the Queue delay is above 128us and Queue size is
        * above 50 buffers, then packet is dropped
        * Drop probability is 1:20, Mark probability is 1:10
        */
        drop_prob = double(1) / double(20);
        mark_prob = double(1) / double(10);
        la_rc = cgm_profile_set_sms_behavior_gb(
            dev, cgm_prof, (184 * 1024 * 384), 50, 128, gb_has_hbm, true, false, true, drop_prob, mark_prob);
        la_return_on_error(la_rc);

        /*
         * If the Queue is above 1K buffers then packet is dropped
         */
        la_rc = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, (184 * 1024 * 384), 1024, 0, gb_has_hbm, true, false, false, 0, 0);
        la_return_on_error(la_rc);

        /**********************************************************************************
         * Define behavior when the total number of SMS buffers used is
         * above 206K buffers
         * global_idx = 3
         *********************************************************************************/

        //	If buffer size is above 50 buffers and Queue delay is above 16us  drop all (2K buffers per 400G port) and mark all
        mark_prob = double(1);
        la_rc = cgm_profile_set_sms_behavior_gb(
            dev, cgm_prof, (206 * 1024 * 384), 50, 16, gb_has_hbm, true, false, true, 0, mark_prob);
        la_return_on_error(la_rc);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_gb::cgm_profile_create_default_hbm(std::shared_ptr<lsai_device> sdev,
                                                     const lsai_wred& sai_params,
                                                     la_voq_cgm_profile* cgm_prof,
                                                     bool is_cpu,
                                                     bool mark_profile)
{
    la_status la_rc;
    la_device* dev = sdev->m_dev;

    uint32_t global_idx = 0;
    /*
     * Per VoQ used SMS bytes thresholds
     * Per VoQ age of the oldest packet thresholds in nanoseconds
     * These thresholds are based on hardware team's recommendation
     * NOTE: SMS buffer size is 384 bytes
     */

    la_rc = cgm_prof->set_sms_bytes_quantization(voq_sms_thresh_gb);
    la_return_on_error(la_rc);
    la_rc = cgm_prof->set_sms_age_quantization(voq_age_thresh_gb);
    la_return_on_error(la_rc);

    // Init to all pass
    for (global_idx = 0; global_idx <= global_sms_thresh_gb_hbm.thresholds.size(); global_idx++) {
        uint32_t global_thresh;
        if (global_idx == 0) {
            // threshold for global_idx = 0 is 0
            global_thresh = 0;
        } else {
            global_thresh = global_sms_thresh_gb_hbm.thresholds[global_idx - 1];
        }
        la_status la_rc
            = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, global_thresh, 0, 0, gb_has_hbm, false, false, false, 0, 0);
        la_return_on_error(la_rc, "create default:failed to set global_idx %d to all pass", global_idx);
    }

    // disable the default packet drop/mark/evict profile in SDK.
    la_rc = cgm_profile_set_sms_packet_behavior(dev, cgm_prof);
    la_return_on_error(la_rc, "failed to set sms packet behavior for the cgm profile");

    /*****************************************************************************
     * Define behavior when  the total number of SMS buffers
     * used is below 85K buffers: (0-144K)
     *****************************************************************************/
    // Cpu port is much slower than regular traffic port, which cause the delay based dropping always kicked in.

    if (!is_cpu) {
        //  If the Queue delay is above 128us and Queue size is above 256 buffers, then Queue is evicted
        la_rc = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, 0, 256, 128, gb_has_hbm, false, true, false, 0, 0);
        la_return_on_error(la_rc);

        // If the Queue is above 15K buffers and Queue delay is at above 64us, then Queue is evicted
        la_rc = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, 0, (15 * 1024), 64, gb_has_hbm, false, true, false, 0, 0);
        la_return_on_error(la_rc);

        // If the Queue is above 192us and 1024 buffers, then packet is dropped
        la_rc = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, 0, 1024, 192, gb_has_hbm, true, false, false, 0, 0);
        la_return_on_error(la_rc);
    }

    /*
     * If the Queue is above 16000 buffers then packet is dropped
     */
    la_rc = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, 0, 16000, 0, gb_has_hbm, true, false, false, 0, 0);
    la_return_on_error(la_rc);

    /********************************************************************************
     * Define behavior when the total number of SMS buffers used
     * is below 214 buffers: (144K-206K)
     * global_idx = 1
     *********************************************************************************/

    // If the Queue is above 15K buffers and Queue delay is at above 64us, then Queue is evicted
    la_rc
        = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, (144 * 1024 * 384), (15 * 1024), 64, gb_has_hbm, false, true, false, 0, 0);
    la_return_on_error(la_rc);

    // If the Queue delay is above 128us and Queue size is above 50 buffers, then Queue is evicted
    la_rc = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, (144 * 1024 * 384), 50, 128, gb_has_hbm, false, true, false, 0, 0);
    la_return_on_error(la_rc);

    //	If the Queue is above 192us and Queue size is above 50 buffers, then packet is dropped
    la_rc = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, (144 * 1024 * 384), 50, 192, gb_has_hbm, true, false, false, 0, 0);
    la_return_on_error(la_rc);

    /*
     * If the Queue is above 16000 buffers then packet is dropped
     */
    la_rc = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, (144 * 1024 * 384), 16000, 0, gb_has_hbm, true, false, false, 0, 0);
    la_return_on_error(la_rc);

    /**************************************************************************************
     * Define behavior when the total number of SMS buffers used is
     * 206K - 216K buffers
     * global_idx = 2;
     * drop, no eviction
     **************************************************************************************

     * If the Queue delay is above 16us and Queue size is
     * above 50 buffers, then packet is dropped
    */
    la_rc = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, (206 * 1024 * 384), 50, 16, gb_has_hbm, true, false, false, 0, 0);
    la_return_on_error(la_rc);

    /*
     * If the Queue is above 1K buffers then packet is dropped
     */
    la_rc = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, (206 * 1024 * 384), 1024, 0, gb_has_hbm, true, false, false, 0, 0);
    la_return_on_error(la_rc);

    /**********************************************************************************
     * Define behavior when the total number of SMS buffers used is
     * above 216K buffers
     * global_idx = 3
     *********************************************************************************/

    /*
     * special handling for tc7
     */
    uint32_t cos = 7;
    if (cos == 7) {
        /*
         * If the Queue is above 1K buffers then packet is dropped
         */
        la_rc = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, (216 * 1024 * 384), 1024, 0, gb_has_hbm, true, false, false, 0, 0);
        la_return_on_error(la_rc);

    } else {
        /*
         * If the non-tc7 queue, drop
         */
        la_rc = cgm_profile_set_sms_behavior_gb(dev, cgm_prof, (216 * 1024 * 384), 0, 0, gb_has_hbm, true, false, false, 0, 0);
        la_return_on_error(la_rc);
    }

    // set HBM config
    la_rc = hbm_profile_create_default(sdev, sai_params, cgm_prof, mark_profile);
    la_return_on_error(la_rc, "failed to set HBM config");

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_base::cgm_profile_create_default(std::shared_ptr<lsai_device> sdev,
                                                   const lsai_wred& sai_params,
                                                   la_voq_cgm_profile* cgm_prof,
                                                   bool mark_profile)
{
    // is_cpu false; is_default true
    return cgm_profile_create(sdev, sai_params, cgm_prof, false, mark_profile, true);
}

la_status
lsai_wred_manager_base::cgm_profile_create_cpu(std::shared_ptr<lsai_device> sdev,
                                               const lsai_wred& sai_params,
                                               la_voq_cgm_profile* cgm_prof)
{
    // is_cpu true; mark profile false; is_default true
    return cgm_profile_create(sdev, sai_params, cgm_prof, true, false, true);
}

la_status
lsai_wred_manager_gb::hbm_profile_create_default(std::shared_ptr<lsai_device> sdev,
                                                 const lsai_wred& sai_params,
                                                 la_voq_cgm_profile* cgm_prof,
                                                 bool mark_profile)
{
    la_device* dev = sdev->m_dev;

    // Q size quantization: 100, 1K, 2K, 4K, 6K, 8K, 12K, 16K, 24K, 32K, 40K, 48K, 56K, 64000
    // Shared pool quantization: 500K, 750K, 875K, 930K, 960K, 980K, 990K
    // Q delay quantization (ms): 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 24, 32, 64, 128
    // all of the above configure in the device_level_config_base_gb

    // set the hbm dequeue congestion level
    la_status la_rc = cgm_profile_set_hbm_dequeue_cgm_level(sdev->m_dev, cgm_prof);
    la_return_on_error(la_rc, "failed to set hbm congestion levels");

    /**********************************************************************************
     * Define behavior when the total number of DRAM buffers is below 500K buffers
     * hbm_free_blocks_region idx = 0
     *********************************************************************************/

    // If the Queue delay is above 32ms and size above 100 buffers, then the packet is dropped in case of dropping profile
    // marked in case of ecn profile
    la_rc = cgm_profile_set_hbm_behavior_gb(dev, cgm_prof, 100, 32, 0, mark_profile);
    la_return_on_error(la_rc);

    // If the Queue size is above 64_000 dram buffers, then the packet is dropped
    la_rc = cgm_profile_set_hbm_behavior_gb(dev, cgm_prof, 64000, 0, 0, false);
    la_return_on_error(la_rc);

    /**********************************************************************************
     * Define behavior when the total number of DRAM buffers is below 750K buffers
     * hbm_free_blocks_region idx = 1
     *********************************************************************************/

    // If the Queue delay is above 16ms and size above 100 buffers, then the packet is dropped in case of dropping profile
    // marked in case of ecn profile
    la_rc = cgm_profile_set_hbm_behavior_gb(dev, cgm_prof, 100, 16, 1, mark_profile);
    la_return_on_error(la_rc);

    // If the Queue size is above 32K dram buffers, then the packet is dropped
    la_rc = cgm_profile_set_hbm_behavior_gb(dev, cgm_prof, (32 * 1024), 0, 1, false);
    la_return_on_error(la_rc);

    /**********************************************************************************
     * Define behavior when the total number of DRAM buffers is below 875K buffers
     * hbm_free_blocks_region idx = 2
     *********************************************************************************/

    // If the Queue delay is above 12ms and size above 100 buffers, then the packet is dropped in case of dropping profile
    // marked in case of ecn profile
    la_rc = cgm_profile_set_hbm_behavior_gb(dev, cgm_prof, 100, 12, 2, mark_profile);
    la_return_on_error(la_rc);

    // If the Queue size is above 16K dram buffers, then the packet is dropped
    la_rc = cgm_profile_set_hbm_behavior_gb(dev, cgm_prof, (16 * 1024), 0, 2, false);
    la_return_on_error(la_rc);

    /**********************************************************************************
     * Define behavior when the total number of DRAM buffers is below 930K buffers
     * hbm_free_blocks_region idx = 3
     *********************************************************************************/

    // If the Queue delay is above 8ms and size above 100 buffers, then the packet is dropped in case of dropping profile
    // marked in case of ecn profile
    la_rc = cgm_profile_set_hbm_behavior_gb(dev, cgm_prof, 100, 8, 3, mark_profile);
    la_return_on_error(la_rc);

    // If the Queue size is above 8K dram buffers, then the packet is dropped
    la_rc = cgm_profile_set_hbm_behavior_gb(dev, cgm_prof, (8 * 1024), 0, 3, false);
    la_return_on_error(la_rc);
    /**********************************************************************************
     * Define behavior when the total number of DRAM buffers is below 960K buffers
     * hbm_free_blocks_region idx = 4
     *********************************************************************************/

    // If the Queue delay is above 6ms and size above 100 buffers, then the packet is dropped in case of dropping profile
    // marked in case of ecn profile
    la_rc = cgm_profile_set_hbm_behavior_gb(dev, cgm_prof, 100, 6, 4, mark_profile);
    la_return_on_error(la_rc);

    // If the Queue size is above 4K dram buffers, then the packet is dropped
    la_rc = cgm_profile_set_hbm_behavior_gb(dev, cgm_prof, (4 * 1024), 0, 4, false);
    la_return_on_error(la_rc);

    /**********************************************************************************
     * Define behavior when the total number of DRAM buffers is below 980K buffers
     * hbm_free_blocks_region idx = 5
     *********************************************************************************/

    // If the Queue delay is above 3ms and size above 100 buffers, then the packet is dropped in case of dropping profile
    // marked in case of ecn profile
    la_rc = cgm_profile_set_hbm_behavior_gb(dev, cgm_prof, 100, 3, 5, mark_profile);
    la_return_on_error(la_rc);

    // If the Queue size is above 2K dram buffers, then the packet is dropped
    la_rc = cgm_profile_set_hbm_behavior_gb(dev, cgm_prof, (2 * 1024), 0, 5, false);
    la_return_on_error(la_rc);

    /**********************************************************************************
     * Define behavior when the total number of DRAM buffers is below 990K buffers
     * hbm_free_blocks_region idx = 6
     *********************************************************************************/

    // If the Queue delay is above 1ms and size above 100 buffers, then the packet is dropped in case of dropping profile
    // marked in case of ecn profile
    la_rc = cgm_profile_set_hbm_behavior_gb(dev, cgm_prof, 100, 1, 6, mark_profile);
    la_return_on_error(la_rc);

    // If the Queue size is above 1K dram buffers, then the packet is dropped
    la_rc = cgm_profile_set_hbm_behavior_gb(dev, cgm_prof, (1 * 1024), 0, 6, false);
    la_return_on_error(la_rc);

    /**********************************************************************************
    * Define behavior when the total number of DRAM buffers is below 64000 buffers
    * hbm_free_blocks_region idx = 7
    *********************************************************************************/
    // If the Queue size is above 64_000 buffers and Queue delay above 64ms, force Q out of HBM
    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_gb::hbm_profile_create_user(std::shared_ptr<lsai_device> sdev,
                                              const lsai_wred& sai_params,
                                              la_voq_cgm_profile* cgm_prof,
                                              bool mark_profile)
{
    la_device* dev = sdev->m_dev;
    la_status la_rc;

    la_uint64_t blocks_thresh;
    la_status lstatus
        = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS, blocks_thresh);
    la_return_on_error(lstatus);

    double ema_coefficient = pow(2, -sai_params.m_weight);

    la_uint64_t block_quant_region;
    lstatus = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_REGIONS, block_quant_region);
    la_return_on_error(lstatus);

    // configure wred
    la_uint64_t num_hbm_blocks_by_voq_regions;
    lstatus = dev->get_limit(limit_type_e::DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS, num_hbm_blocks_by_voq_regions);
    la_return_on_error(lstatus);

    la_uint64_t num_packet_size_regions;
    lstatus = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__NUM_PACKET_SIZE_REGIONS, num_packet_size_regions);
    la_return_on_error(lstatus);

    if (!mark_profile) {
        // translate bytes to HBM blocks
        uint32_t min_hbm_blocks = sai_params.m_min_drop_threshold[lsai_wred::GREEN_INDEX] / HBM_BLOCK_SZ;
        uint32_t max_hbm_blocks = sai_params.m_max_drop_threshold[lsai_wred::GREEN_INDEX] / HBM_BLOCK_SZ;
        if (min_hbm_blocks == max_hbm_blocks) {
            max_hbm_blocks++;
        }

        // configure block threshold regions.
        // First regions is [0, min_hbm_blocks].
        // Last region is [max_hbm_blocks, infinity]
        // In between, linear increase between min and max_hbm_blocks

        la_voq_cgm_quantization_thresholds quant_thresh;

        quant_thresh.thresholds.resize(blocks_thresh);
        double block_step = (double)(max_hbm_blocks - min_hbm_blocks) / (double)(blocks_thresh - 1);

        quant_thresh.thresholds.push_back(min_hbm_blocks);

        for (uint32_t i = 1; i < blocks_thresh - 1; i++) {
            quant_thresh.thresholds.push_back(min_hbm_blocks + round(i * block_step));
        }
        quant_thresh.thresholds.push_back(max_hbm_blocks);
        // Set the queue-size averaging configuration.
        cgm_prof->set_averaging_configuration(ema_coefficient, quant_thresh);

        // First region - probabilty 0
        // Last region - probabilty 100
        // Inner regions - Linear probabilty, starting from 0, ending at drop probabilty user configured value

        uint32_t voq_idx_start_green = 0, voq_idx_end_green = 0, voq_idx_start_yellow = 0, voq_idx_end_yellow = 0;

        // get min and max thresholds
        uint32_t min_threshold_green = sai_params.m_min_drop_threshold[lsai_wred::GREEN_INDEX];
        uint32_t min_threshold_yellow = sai_params.m_min_drop_threshold[lsai_wred::YELLOW_INDEX];

        uint32_t max_threshold_green = sai_params.m_max_drop_threshold[lsai_wred::GREEN_INDEX];
        uint32_t max_threshold_yellow = sai_params.m_max_drop_threshold[lsai_wred::YELLOW_INDEX];

        lstatus = check_presence_of_threshold_in_vector_and_get_index(voq_hbm_thresh_gb, min_threshold_green, voq_idx_start_green);
        la_return_on_error(lstatus);

        lstatus = check_presence_of_threshold_in_vector_and_get_index(voq_hbm_thresh_gb, max_threshold_green, voq_idx_end_green);
        la_return_on_error(lstatus);

        lstatus
            = check_presence_of_threshold_in_vector_and_get_index(voq_hbm_thresh_gb, min_threshold_yellow, voq_idx_start_yellow);
        la_return_on_error(lstatus);

        lstatus = check_presence_of_threshold_in_vector_and_get_index(voq_hbm_thresh_gb, max_threshold_yellow, voq_idx_end_yellow);
        la_return_on_error(lstatus);

        double dist_min_max_green = voq_idx_end_green - voq_idx_start_green;
        double dist_min_max_yellow = voq_idx_end_yellow - voq_idx_start_yellow;

        double drop_prob_green = (double)sai_params.m_drop_probability[lsai_wred::GREEN_INDEX] / double(100);
        double drop_prob_yellow = (double)sai_params.m_drop_probability[lsai_wred::YELLOW_INDEX] / double(100);

        double prob_step_green = drop_prob_green / (double)(dist_min_max_green);
        double prob_step_yellow = drop_prob_yellow / (double)(dist_min_max_yellow);

        la_rc = set_hbm_behavior_user(
            sdev, cgm_prof, voq_idx_start_green, voq_idx_end_green, true, la_qos_color_e::GREEN, prob_step_green);
        la_return_on_error(la_rc);

        la_rc = set_hbm_behavior_user(
            sdev, cgm_prof, voq_idx_start_yellow, voq_idx_end_yellow, true, la_qos_color_e::YELLOW, prob_step_yellow);
        la_return_on_error(la_rc);
    } else {
        // configure the hbm ecn marking behavior for the cgm marking profile
        uint32_t min_hbm_blocks_ecn = 0, max_hbm_blocks_ecn = 0;
        uint32_t min_threshold_green = 0, min_threshold_yellow = 0, max_threshold_green = 0, max_threshold_yellow = 0;
        double mark_prob_green;
        double mark_prob_yellow;
        if (sdev->m_ecn_ect) {
            min_hbm_blocks_ecn = sai_params.m_min_ecn_threshold[lsai_wred::GREEN_INDEX] / HBM_BLOCK_SZ;
            max_hbm_blocks_ecn = sai_params.m_max_ecn_threshold[lsai_wred::GREEN_INDEX] / HBM_BLOCK_SZ;
            if (min_hbm_blocks_ecn == max_hbm_blocks_ecn) {
                max_hbm_blocks_ecn++;
            }

            mark_prob_green = (double)sai_params.m_ecn_probability[lsai_wred::GREEN_INDEX] / double(100);
            mark_prob_yellow = (double)sai_params.m_ecn_probability[lsai_wred::YELLOW_INDEX] / double(100);

            min_threshold_green = sai_params.m_min_ecn_threshold[lsai_wred::GREEN_INDEX];
            min_threshold_yellow = sai_params.m_min_ecn_threshold[lsai_wred::YELLOW_INDEX];
            max_threshold_green = sai_params.m_max_ecn_threshold[lsai_wred::GREEN_INDEX];
            max_threshold_yellow = sai_params.m_max_ecn_threshold[lsai_wred::YELLOW_INDEX];
        } else {
            min_hbm_blocks_ecn = sai_params.m_min_drop_threshold[lsai_wred::GREEN_INDEX] / HBM_BLOCK_SZ;
            max_hbm_blocks_ecn = sai_params.m_max_drop_threshold[lsai_wred::GREEN_INDEX] / HBM_BLOCK_SZ;
            if (min_hbm_blocks_ecn == max_hbm_blocks_ecn) {
                max_hbm_blocks_ecn++;
            }

            mark_prob_green = (double)sai_params.m_drop_probability[lsai_wred::GREEN_INDEX] / double(100);
            mark_prob_yellow = (double)sai_params.m_drop_probability[lsai_wred::YELLOW_INDEX] / double(100);

            min_threshold_green = sai_params.m_min_drop_threshold[lsai_wred::GREEN_INDEX];
            min_threshold_yellow = sai_params.m_min_drop_threshold[lsai_wred::YELLOW_INDEX];
            max_threshold_green = sai_params.m_max_drop_threshold[lsai_wred::GREEN_INDEX];
            max_threshold_yellow = sai_params.m_max_drop_threshold[lsai_wred::YELLOW_INDEX];
        }

        // ecn threshold
        la_voq_cgm_quantization_thresholds quant_thresh_ecn;
        quant_thresh_ecn.thresholds.resize(blocks_thresh);
        double block_step_ecn = (double)(max_hbm_blocks_ecn - min_hbm_blocks_ecn) / (double)(blocks_thresh - 1);
        quant_thresh_ecn.thresholds.push_back(min_hbm_blocks_ecn);

        for (uint32_t i = 1; i < blocks_thresh - 1; i++) {
            // ecn block threshold
            quant_thresh_ecn.thresholds.push_back(min_hbm_blocks_ecn + round(i * block_step_ecn));
        }

        quant_thresh_ecn.thresholds.push_back(max_hbm_blocks_ecn);
        cgm_prof->set_averaging_configuration(ema_coefficient, quant_thresh_ecn);

        uint32_t voq_idx_start_green = 0, voq_idx_end_green = 0, voq_idx_start_yellow = 0, voq_idx_end_yellow = 0;

        lstatus = check_presence_of_threshold_in_vector_and_get_index(voq_hbm_thresh_gb, min_threshold_green, voq_idx_start_green);
        la_return_on_error(lstatus);

        lstatus = check_presence_of_threshold_in_vector_and_get_index(voq_hbm_thresh_gb, max_threshold_green, voq_idx_end_green);
        la_return_on_error(lstatus);

        lstatus
            = check_presence_of_threshold_in_vector_and_get_index(voq_hbm_thresh_gb, min_threshold_yellow, voq_idx_start_yellow);
        la_return_on_error(lstatus);

        lstatus = check_presence_of_threshold_in_vector_and_get_index(voq_hbm_thresh_gb, max_threshold_yellow, voq_idx_end_yellow);
        la_return_on_error(lstatus);

        double dist_min_max_green = voq_idx_end_green - voq_idx_start_green;
        double dist_min_max_yellow = voq_idx_end_yellow - voq_idx_start_yellow;

        double prob_step_green = mark_prob_green / (double)(dist_min_max_green);
        double prob_step_yellow = mark_prob_yellow / (double)(dist_min_max_yellow);

        la_rc = set_hbm_behavior_user(
            sdev, cgm_prof, voq_idx_start_green, voq_idx_end_green, false, la_qos_color_e::GREEN, prob_step_green);
        la_return_on_error(la_rc);

        la_rc = set_hbm_behavior_user(
            sdev, cgm_prof, voq_idx_start_yellow, voq_idx_end_yellow, false, la_qos_color_e::YELLOW, prob_step_yellow);
        la_return_on_error(la_rc);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_gb::set_hbm_behavior_user(std::shared_ptr<lsai_device> sdev,
                                            la_voq_cgm_profile* cgm_prof,
                                            uint32_t voq_idx_start,
                                            uint32_t voq_idx_end,
                                            bool drop,
                                            la_qos_color_e color,
                                            double prob_step)
{
    la_device* dev = sdev->m_dev;
    la_status la_rc;

    la_uint64_t num_packet_size_regions;
    la_status lstatus = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__NUM_PACKET_SIZE_REGIONS, num_packet_size_regions);
    la_return_on_error(lstatus);

    la_uint64_t num_hbm_blocks_by_voq_regions;
    lstatus = dev->get_limit(limit_type_e::DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS, num_hbm_blocks_by_voq_regions);
    la_return_on_error(lstatus);

    double probability;

    for (uint32_t block_index = 0; block_index < num_hbm_blocks_by_voq_regions; block_index++) {
        if (block_index <= voq_idx_start) {
            probability = 0;
        } else if (block_index >= voq_idx_end) {
            probability = 1;
        } else {
            probability = (block_index - voq_idx_start) * prob_step;
        }

        // loop through the packet size region
        for (uint32_t packet_size_region = 0; packet_size_region < num_packet_size_regions - 1; packet_size_region++) {
            la_cgm_wred_key key{block_index, packet_size_region, color};
            if (drop) {
                la_cgm_wred_drop_val val{probability};
                la_rc = cgm_prof->set_hbm_wred_drop_configuration(key, val);
            } else {
                la_cgm_wred_mark_ecn_val val{probability};
                la_rc = cgm_prof->set_hbm_wred_mark_ecn_configuration(key, val);
            }
            la_return_on_error(la_rc);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_gb::cgm_profile_create_user(std::shared_ptr<lsai_device> sdev,
                                              const lsai_wred& sai_params,
                                              la_voq_cgm_profile* cgm_prof,
                                              bool mark_profile)
{
    la_status la_rc;

    if (!gb_has_hbm) {
        la_rc = cgm_profile_create_user_no_hbm(sdev, sai_params, cgm_prof, mark_profile);
        la_return_on_error(la_rc, "failed to set SMS config for GB cgm profile");
    } else {
        la_rc = cgm_profile_create_user_with_hbm(sdev, sai_params, cgm_prof, mark_profile);
        la_return_on_error(la_rc, "failed to set SMS/HBM config for GB with HBM cgm profile");
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_gb::cgm_profile_create_user_no_hbm(std::shared_ptr<lsai_device> sdev,
                                                     const lsai_wred& sai_params,
                                                     la_voq_cgm_profile* cgm_prof,
                                                     bool mark_profile)
{
    la_status la_rc;
    uint32_t global_idx = 0;

    // Initial cgm profile with the default settings (should be done for both wred and mark profiles)
    // allow the user to configure the behavior
    la_rc = cgm_profile_create_default_no_hbm(sdev, sai_params, cgm_prof, false, mark_profile, false);
    la_return_on_error(la_rc, "Failed to set the default voq cgm profile for %d", cgm_prof);

    for (global_idx = 0; global_idx <= global_sms_thresh_gb.thresholds.size(); global_idx++) {
        uint32_t global_thresh;
        if (global_idx == 0) {
            // threshold for global_idx = 0 is 0
            global_thresh = 0;
        } else {
            global_thresh = global_sms_thresh_gb.thresholds[global_idx - 1];
        }

        if (!mark_profile) {
            // program wred drop behavior between min and max threshold
            la_rc = cgm_profile_set_sms_behavior_user(sdev, cgm_prof, sai_params, global_thresh, 0, false, gb_has_hbm);
            la_return_on_error(la_rc, "failed to set drop behavior for global_idx %d", global_idx);

            // program wred drop behavior for > max threshold
            // bool if q is > max_threshold is true
            la_rc = cgm_profile_set_sms_behavior_user(sdev, cgm_prof, sai_params, global_thresh, 0, true, gb_has_hbm);
            la_return_on_error(
                la_rc, "failed to set drop behavior for region greater than max threshold for global_idx %d", global_idx);
        } else {
            // program wred mark behavior between min and max threshold
            la_rc = cgm_profile_ecn_set_sms_behavior_user(sdev, cgm_prof, sai_params, global_thresh, 0, false, gb_has_hbm);
            la_return_on_error(la_rc, "failed to set mark behavior for global_idx %d", global_idx);

            // program mark behavior for > max threshold
            // bool if q is > max_threshold is true
            la_rc = cgm_profile_ecn_set_sms_behavior_user(sdev, cgm_prof, sai_params, global_thresh, 0, true, gb_has_hbm);
            la_return_on_error(
                la_rc, "failed to set mark behavior for region greater than max threshold for global_idx %d", global_idx);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_gb::cgm_profile_create_user_with_hbm(std::shared_ptr<lsai_device> sdev,
                                                       const lsai_wred& sai_params,
                                                       la_voq_cgm_profile* cgm_prof,
                                                       bool mark_profile)
{
    la_status la_rc;

    // Initial cgm profile with the default settings (should be done for both wred and mark profiles)
    // default HBM config sets the sms and hbm behavior both
    // For now we keep the SMS config as default, the eviction would be based on the default config.
    la_rc = cgm_profile_create_default_hbm(sdev, sai_params, cgm_prof, false, mark_profile);
    la_return_on_error(la_rc, "Failed to set the default voq cgm profile for %d", cgm_prof);

    // change the HBM confid according to the SAI parameter from the user.
    la_rc = hbm_profile_create_user(sdev, sai_params, cgm_prof, mark_profile);
    la_return_on_error(la_rc, "failed to set HBM config for GB ecn profile");

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_gb::cgm_profile_set_sms_dequeue_cgm_level(la_device* dev, la_voq_cgm_profile* cgm_prof)
{
    la_status la_rc;
    la_uint64_t num_sms_voq_bytes_regions;
    la_rc = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_voq_bytes_regions);
    la_return_on_error(la_rc);

    la_uint64_t num_sms_age_regions;
    la_rc = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_age_regions);
    la_return_on_error(la_rc);

    la_voq_sms_dequeue_size_in_bytes_key key;
    la_voq_sms_dequeue_size_in_bytes_congestion_val val;
    // We only care about number of regions. Does not matter if it is HBM or non HBM device
    // In SAI congestion level measured in bytes, so we setup to ignore global occupancy and age
    for (uint32_t global_idx = 0; global_idx <= global_sms_thresh_gb.thresholds.size(); global_idx++) {
        key.sms_voqs_total_bytes_region = global_idx;
        for (uint32_t voq_bytes_region = 0; voq_bytes_region < num_sms_voq_bytes_regions; voq_bytes_region++) {
            key.sms_bytes_region = voq_bytes_region;
            val.congestion_level = voq_bytes_region;
            for (uint32_t age_idx = 0; age_idx < num_sms_age_regions; age_idx++) {
                key.sms_age_region = age_idx;
                la_rc = cgm_prof->set_sms_dequeue_size_in_bytes_congestion_level(key, val);
                la_return_on_error(la_rc);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_gb::cgm_profile_set_hbm_dequeue_cgm_level(la_device* dev, la_voq_cgm_profile* cgm_prof)
{
    la_status la_rc;

    la_uint64_t num_hbm_blocks_by_voq_quantization_regions;
    la_rc = dev->get_limit(limit_type_e::DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS,
                           num_hbm_blocks_by_voq_quantization_regions);
    la_return_on_error(la_rc);

    la_uint64_t num_hbm_pool_free_blocks_quantization_regions;
    la_rc = dev->get_limit(limit_type_e::DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS,
                           num_hbm_pool_free_blocks_quantization_regions);
    la_return_on_error(la_rc);

    la_cgm_hbm_dequeue_size_in_blocks_key key;
    la_cgm_hbm_dequeue_size_in_blocks_congestion_val val;

    // We loop through the hbm pool of free blocks and the hbm blocks of voq regions
    for (uint32_t hbm_pool_free_idx = 0; hbm_pool_free_idx < num_hbm_pool_free_blocks_quantization_regions; hbm_pool_free_idx++) {
        key.hbm_pool_free_blocks_region = hbm_pool_free_idx;
        for (uint32_t hbm_voq_region = 0; hbm_voq_region < num_hbm_blocks_by_voq_quantization_regions; hbm_voq_region++) {
            key.hbm_blocks_by_voq_region = hbm_voq_region;
            val.congestion_level = hbm_voq_region;
            la_rc = cgm_prof->set_hbm_dequeue_size_in_blocks_congestion_level(key, val);
            la_return_on_error(la_rc);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_gb::cgm_profile_set_sms_packet_behavior(la_device* dev, la_voq_cgm_profile* cgm_prof)
{
    la_status la_rc;

    la_uint64_t num_sms_packet_regions;
    la_rc = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS, num_sms_packet_regions);
    la_return_on_error(la_rc);

    la_uint64_t num_sms_age_regions;
    la_rc = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_age_regions);
    la_return_on_error(la_rc);

    la_uint64_t num_sms_voqs_total_packets_regions;
    la_rc = dev->get_limit(limit_type_e::DEVICE__SMS_NUM_PACKETS_QUANTIZATION_REGIONS, num_sms_voqs_total_packets_regions);
    la_return_on_error(la_rc);

    la_voq_sms_size_in_packets_key pkt_key;
    // Set No drop, No marking and No eviction. except for the last region
    la_voq_sms_size_in_packets_drop_val drop_val{la_qos_color_e::NONE};
    la_voq_sms_size_in_packets_mark_val mark_val{la_qos_color_e::NONE};
    la_voq_sms_size_in_packets_evict_val evict_val{false};

    for (size_t total_packets_region = 0; total_packets_region < num_sms_voqs_total_packets_regions; total_packets_region++) {
        pkt_key.sms_voqs_total_packets_region = total_packets_region;
        for (size_t voq_packets_region = 0; voq_packets_region < num_sms_packet_regions; voq_packets_region++) {
            pkt_key.sms_packets_region = voq_packets_region;
            if (voq_packets_region == num_sms_packet_regions - 1) {
                // for the final packet regions protect from changing to no-drop values
                drop_val.drop_color_level = la_qos_color_e::GREEN;
            } else {
                drop_val.drop_color_level = la_qos_color_e::NONE;
            }
            for (size_t age_region = 0; age_region < num_sms_age_regions; age_region++) {
                pkt_key.sms_age_region = age_region;
                la_rc = cgm_prof->set_sms_size_in_packets_drop_behavior(pkt_key, drop_val);
                la_return_on_error(la_rc,
                                   "Failed to set packets drop behavior for packet region %d and voq region %d",
                                   total_packets_region,
                                   voq_packets_region);
                la_rc = cgm_prof->set_sms_size_in_packets_mark_behavior(pkt_key, mark_val);
                la_return_on_error(la_rc,
                                   "Failed to set packets mark behavior for packet region %d and voq region %d",
                                   total_packets_region,
                                   voq_packets_region);
                la_rc = cgm_prof->set_sms_size_in_packets_evict_behavior(pkt_key, evict_val);
                la_return_on_error(la_rc,
                                   "Failed to set packets evict behavior for packet region %d and voq region %d",
                                   total_packets_region,
                                   voq_packets_region);
            }
        }
    }
    return LA_STATUS_SUCCESS;
}

/***********************  pacific specific functions ************************/
la_status
lsai_wred_manager_pacific::device_level_config()
{
    la_status status = device_level_config_base(m_lsai_device, true /* do hbm init */);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

// setting SMS default config - based on XR code
// HBM config according to sai_params
la_status
lsai_wred_manager_pacific::cgm_profile_create(std::shared_ptr<lsai_device> sdev,
                                              const lsai_wred& sai_params,
                                              la_voq_cgm_profile* cgm_prof,
                                              bool is_cpu,
                                              bool mark_profile,
                                              bool is_default)
{
    la_status la_rc;
    la_voq_cgm_profile::sms_bytes_quantization_thresholds voq_sms_thresh;
    la_voq_cgm_profile::sms_age_quantization_thresholds voq_age_thresh;

    voq_sms_thresh = {{(50 * 384), (250 * 384), (256 * 384), (1024 * 384), (2 * 1024 * 384), (4 * 1024 * 384), (16000 * 384)}};
    voq_age_thresh = {{2000, 4000, 8000, 16000, 32000, 34000, 36000, 38000, 42000, 44000, 46000, 48000, 64000, 128000, 255000}};

    la_rc = cgm_prof->set_sms_bytes_quantization(voq_sms_thresh);
    la_return_on_error(la_rc);

    la_rc = cgm_prof->set_sms_age_quantization(voq_age_thresh);
    la_return_on_error(la_rc);

    uint32_t global_idx;
    // Init to all pass
    for (global_idx = 0; global_idx < LA_CGM_NUM_SMS_BYTES_QUANTIZATION_REGIONS; global_idx++) {
        la_rc = cgm_profile_set_sms_behavior(cgm_prof, global_idx, 0, 0, false, false, false);
        la_return_on_error(la_rc, "failed to set global_idx %d to all pass", global_idx);
    }

    /*
     * Define behavior when  the total number of SMS buffers
     * used is below 24K buffers: (0-24K)
     */
    global_idx = 0;

    /*
     * If the Queue delay is above 64us and Queue size is above
     * 250 buffers (100KB), then Queue is evicted.
     */
    la_rc = cgm_profile_set_sms_behavior(cgm_prof, global_idx, 2, 5, false, true, false);
    la_return_on_error(la_rc, "failed to set global_idx %d to evict to hbm if above 250 and delay above 64us", global_idx);

    /*
     * If the Queue is above 16000 buffers then packet is dropped
     */
    la_rc = cgm_profile_set_sms_behavior(cgm_prof, global_idx, 7, 0, true, false, false);
    la_return_on_error(la_rc, "failed to set global_idx %d to evict to drop if above 16000", global_idx);

    /*
     * If the Queue delay is above 96 us and buffer > 1024
     * then packet is dropped
     */
    la_rc = cgm_profile_set_sms_behavior(cgm_prof, global_idx, 4, 12, true, false, false);
    la_return_on_error(la_rc, "failed to set global_idx %d to drop if above 1K and delay above 96us", global_idx);

    // Define behavior when the total number of SMS buffers used is below 32K buffers: (24k-32K)
    global_idx = 1;
    la_rc = cgm_profile_set_sms_behavior(cgm_prof, global_idx, 1, 5, false, true, false);
    la_return_on_error(la_rc, "failed to set global_idx %d to evict to hbm if delay above 64us", global_idx);

    // If the Queue is above 16000 buffers then packet is dropped
    la_rc = cgm_profile_set_sms_behavior(cgm_prof, global_idx, 7, 0, true, false, false);
    la_return_on_error(la_rc, "failed to set global_idx %d to drop if above 16000", global_idx);

    // If the Queue delay is above 96 us and buffer > 50 then packet is dropped
    la_rc = cgm_profile_set_sms_behavior(cgm_prof, global_idx, 1, 12, true, false, false);
    la_return_on_error(la_rc, "failed to set global_idx %d to drop if above 50 and delay above 96us", global_idx);

    // Define behavior when the total number of SMS buffers used is above 32K buffers (32K-35K)
    global_idx = 2;

    // If the Queue delay is above 8us and Queue size is above 256 buffers, then packet is dropped
    la_rc = cgm_profile_set_sms_behavior(cgm_prof, global_idx, 3, 2, true, false, false);
    la_return_on_error(la_rc, "failed to set global_idx %d to drop packet above 256 buffers and delay above 8us", global_idx);

    // If the Queue is above 1K buffers then packet is dropped
    la_rc = cgm_profile_set_sms_behavior(cgm_prof, global_idx, 4, 0, true, false, false);
    la_return_on_error(la_rc, "failed to set global_idx %d to drop above 1k buffers", global_idx);

    /*
     * Define behavior when the total number of SMS buffers used
     * is above 35K buffers (35K - 64K)
     */
    global_idx = 3;

    /*
     * special handling for tc7
     */
    uint32_t cos = 7; // XR function gets cos as input parameter
    if (cos == 7) {
        /*
         * If the Queue delay is above 8us and Queue size is
         * above 256 buffers, then packet is dropped
         */
        la_rc = cgm_profile_set_sms_behavior(cgm_prof, global_idx, 3, 2, true, false, false);
        la_return_on_error(la_rc, "failed to set global_idx %d to drop packet above 256 buffers and delay above 8us", global_idx);

        /*
         * If the Queue is above 1K buffers then packet is dropped
         */
        la_rc = cgm_profile_set_sms_behavior(cgm_prof, global_idx, 4, 0, true, false, false);
        la_return_on_error(la_rc, "failed to set global_idx %d to drop packet above 1K", global_idx)
    } else {
        /*
         * If the non-tc7 queue, drop
         */
        la_rc = cgm_profile_set_sms_behavior(cgm_prof, global_idx, 0, 0, true, false, false);
        la_return_on_error(la_rc, "failed to set global_idx %d to drop packet for non-tc7", global_idx)
    }

    // set HBM config
    la_rc = hbm_profile_create_user(sdev, sai_params, cgm_prof, false);
    la_return_on_error(la_rc, "failed to set HBM config");

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_pacific::hbm_profile_create_user(std::shared_ptr<lsai_device> sdev,
                                                   const lsai_wred& sai_params,
                                                   la_voq_cgm_profile* cgm_prof,
                                                   bool mark_profile)
{
    // translate bytes to HBM blocks
    uint32_t min_hbm_blocks = sai_params.m_min_drop_threshold[lsai_wred::GREEN_INDEX] / HBM_BLOCK_SZ;
    uint32_t max_hbm_blocks = sai_params.m_max_drop_threshold[lsai_wred::GREEN_INDEX] / HBM_BLOCK_SZ;
    if (min_hbm_blocks == max_hbm_blocks) {
        max_hbm_blocks++;
    }

    double ema_coefficient = pow(2, -sai_params.m_weight);

    // configure block threshold regions.
    // First regions is [0, min_hbm_blocks].
    // Last region is [max_hbm_blocks, infinity]
    // In between, linear increase between min and max_hbm_blocks
    double block_step = (double)(max_hbm_blocks - min_hbm_blocks)
                        / (double)(la_voq_cgm_profile::WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS - 1);
    la_voq_cgm_profile::wred_blocks_quantization_thresholds blocks_thresh;
    blocks_thresh.thresholds[0] = min_hbm_blocks;
    for (uint32_t i = 1; i < la_voq_cgm_profile::WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS - 1; i++) {
        blocks_thresh.thresholds[i] = min_hbm_blocks + round(i * block_step);
    }
    blocks_thresh.thresholds[la_voq_cgm_profile::WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS - 1] = max_hbm_blocks;

    cgm_prof->set_averaging_configuration(ema_coefficient, blocks_thresh);

    // configure wred
    la_voq_cgm_profile::wred_regions_probabilties probability;
    la_voq_cgm_profile::wred_action_e wred_action = sai_params.m_ecn_mode == SAI_ECN_MARK_MODE_NONE
                                                        ? la_voq_cgm_profile::wred_action_e::DROP
                                                        : la_voq_cgm_profile::wred_action_e::MARK_ECN;

    // First region - probabilty 0
    // Last region - probabilty 100
    // Inner regions - Linear probabilty, starting from 0, ending at drop probabilty user configured value
    double prob_step = (double)sai_params.m_drop_probability[lsai_wred::GREEN_INDEX]
                       / (double)(la_voq_cgm_profile::WRED_NUM_BLOCKS_QUANTIZATION_REGIONS - 2);
    for (uint32_t i = 0; i < la_voq_cgm_profile::WRED_NUM_BLOCKS_QUANTIZATION_REGIONS - 1; i++) {
        probability.probabilities[i] = round(i * prob_step);
    }
    probability.probabilities[la_voq_cgm_profile::WRED_NUM_BLOCKS_QUANTIZATION_REGIONS - 1] = 100;

    cgm_prof->set_wred_configuration(wred_action, probability);

    // setting the averaging configuration for ECN like below would override the value we set earlier for the drop.
    // HBM ECN thresholds are not accurate and determined by the drop thresholds
    /*
    // for ecn threshold configure wred and block thresholds
    if (sdev->m_ecn_ect) {
        uint32_t min_hbm_blocks_ecn = sai_params.m_min_ecn_threshold[lsai_wred::GREEN_INDEX] / HBM_BLOCK_SZ;
        uint32_t max_hbm_blocks_ecn = sai_params.m_max_ecn_threshold[lsai_wred::GREEN_INDEX] / HBM_BLOCK_SZ;
        if (min_hbm_blocks_ecn == max_hbm_blocks_ecn) {
            max_hbm_blocks_ecn++;
        }
        // ecn block threshold
        double block_step_ecn = (double)(max_hbm_blocks_ecn - min_hbm_blocks_ecn)
                                / (double)(la_voq_cgm_profile::WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS - 1);
        la_voq_cgm_profile::wred_blocks_quantization_thresholds blocks_thresh_ecn;
        blocks_thresh_ecn.thresholds[0] = min_hbm_blocks_ecn;
        for (uint32_t i = 1; i < la_voq_cgm_profile::WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS - 1; i++) {
            blocks_thresh_ecn.thresholds[i] = min_hbm_blocks_ecn + round(i * block_step_ecn);
        }

        blocks_thresh_ecn.thresholds[la_voq_cgm_profile::WRED_NUM_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS - 1]
            = max_hbm_blocks_ecn;

        cgm_prof->set_averaging_configuration(ema_coefficient, blocks_thresh_ecn);

        // configure wred
        la_voq_cgm_profile::wred_action_e wred_action_ecn = la_voq_cgm_profile::wred_action_e::MARK_ECN;
        la_voq_cgm_profile::wred_regions_probabilties ecn_probability;
        double ecn_step = (double)sai_params.m_ecn_probability[lsai_wred::GREEN_INDEX]
                          / (double)(la_voq_cgm_profile::WRED_NUM_BLOCKS_QUANTIZATION_REGIONS - 2);

        for (uint32_t i = 1; i < la_voq_cgm_profile::WRED_NUM_BLOCKS_QUANTIZATION_REGIONS - 1; i++) {
            ecn_probability.probabilities[i] = round(i * ecn_step);
        }
        ecn_probability.probabilities[la_voq_cgm_profile::WRED_NUM_BLOCKS_QUANTIZATION_REGIONS - 1] = 100;

        cgm_prof->set_wred_configuration(wred_action_ecn, ecn_probability);
    }*/

    // no need for calling set_hbm_size_in_blocks_behavior .
    // We relay on the default behavior to pass all, so wred logic will make the pass/drop/ecn decision.

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_pacific::cgm_profile_create_user(std::shared_ptr<lsai_device> sdev,
                                                   const lsai_wred& sai_params,
                                                   la_voq_cgm_profile* cgm_prof,
                                                   bool mark_profile)
{
    // wred supported only in HBM for pacific
    // keep SMS config as it as which is hardcoded for the default wred profile
    // set HBM config
    la_status la_rc = hbm_profile_create_user(sdev, sai_params, cgm_prof, false);
    la_return_on_error(la_rc, "failed to set HBM config");

    return LA_STATUS_SUCCESS;
}

sai_status_t
lsai_wred_manager_pacific::wred_profile_validate(const lsai_wred& wred)
{
    // validate enable
    if (wred.m_enabled[lsai_wred::GREEN_INDEX] != wred.m_enabled[lsai_wred::YELLOW_INDEX]) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Yellow and green must be both enabled or both disabled");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (wred.m_enabled[lsai_wred::RED_INDEX] != true) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Red must be enabled");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // validate drop probability
    if (wred.m_drop_probability[lsai_wred::GREEN_INDEX] != wred.m_drop_probability[lsai_wred::YELLOW_INDEX]) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Yellow drop probability must equal green drop probability");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (wred.m_drop_probability[lsai_wred::RED_INDEX] != 100) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Red drop probability must equal 100");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // validate min drop threshold
    if (wred.m_min_drop_threshold[lsai_wred::GREEN_INDEX] != wred.m_min_drop_threshold[lsai_wred::YELLOW_INDEX]) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Yellow min drop threshold must equal green drop threshold");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (wred.m_min_drop_threshold[lsai_wred::RED_INDEX] != 0) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Red min drop threshold must equal 0");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // validate max drop threshold
    if (wred.m_max_drop_threshold[lsai_wred::GREEN_INDEX] != wred.m_max_drop_threshold[lsai_wred::YELLOW_INDEX]) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Yellow max drop threshold must equal green drop threshold");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (wred.m_max_drop_threshold[lsai_wred::RED_INDEX] != 0) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Red max drop threshold must equal 0");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // validate weight
    if (wred.m_weight > 15) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Weight must be between 0 and 15");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (wred.m_ecn_mode != SAI_ECN_MARK_MODE_ALL && wred.m_ecn_mode != SAI_ECN_MARK_MODE_NONE) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. ECN mark mode must be MARK_MODE_ALL or MARK_MODE_NONE");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // validate ecn probability
    if (wred.m_ecn_probability[lsai_wred::GREEN_INDEX] != wred.m_ecn_probability[lsai_wred::YELLOW_INDEX]) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Yellow ecn mark probability must equal green ecn mark probability");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (wred.m_ecn_probability[lsai_wred::RED_INDEX] != 100) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Red ecn mark probability must equal 100");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // validate min ecn threshold
    if (wred.m_min_ecn_threshold[lsai_wred::GREEN_INDEX] != wred.m_min_ecn_threshold[lsai_wred::YELLOW_INDEX]) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Yellow min ecn threshold must equal green ecn threshold");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (wred.m_min_ecn_threshold[lsai_wred::RED_INDEX] != 0) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Red min ecn threshold must equal 0");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // validate max ecn threshold
    if (wred.m_max_ecn_threshold[lsai_wred::GREEN_INDEX] != wred.m_max_ecn_threshold[lsai_wred::YELLOW_INDEX]) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Yellow max ecn threshold must equal green ecn threshold");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (wred.m_max_ecn_threshold[lsai_wred::RED_INDEX] != 0) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Red max ecn threshold must equal 0");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

uint64_t
lsai_wred_manager_gb::cgm_level_to_bytes(uint8_t cgm_index)
{
    if (gb_has_hbm) {
        if (cgm_index < voq_hbm_thresh_gb.thresholds.size()) {
            return voq_hbm_thresh_gb.thresholds[cgm_index] * HBM_BLOCK_SZ;
        } else {
            // above max congestion level. We can't tell the exact number
            return voq_sms_thresh_gb.thresholds[voq_hbm_thresh_gb.thresholds.size() - 1] * HBM_BLOCK_SZ + HBM_BLOCK_SZ;
        }
    } else {
        if (cgm_index < voq_sms_thresh_gb.thresholds.size()) {
            return voq_sms_thresh_gb.thresholds[cgm_index];
        } else {
            // above max congestion level. We can't tell the exact number
            return voq_sms_thresh_gb.thresholds[voq_sms_thresh_gb.thresholds.size() - 1] + 384;
        }
    }
}

sai_status_t
lsai_wred_manager_gb::wred_profile_validate(const lsai_wred& wred)
{
    // validate drop probability
    if (wred.m_drop_probability[lsai_wred::GREEN_INDEX] > 100 || wred.m_drop_probability[lsai_wred::YELLOW_INDEX] > 100) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Green and Yellow drop probability should be in between 0 to 100");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (wred.m_drop_probability[lsai_wred::RED_INDEX] != 100) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Red drop probability must equal 100");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // validate min drop threshold for red
    if (wred.m_min_drop_threshold[lsai_wred::RED_INDEX] != 0) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Red min drop threshold must equal 0");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // validate max drop threshold for red
    if (wred.m_max_drop_threshold[lsai_wred::RED_INDEX] != 0) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Red max drop threshold must equal 0");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (wred.m_min_drop_threshold[lsai_wred::GREEN_INDEX] > (16000 * 384)
        || wred.m_min_drop_threshold[lsai_wred::YELLOW_INDEX] > (16000 * 384)) {
        sai_log_error(SAI_API_WRED,
                      "Bad WRED profile. Green and Yellow min drop threshold should not be greater than the value %d",
                      16000 * 384);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // validate weight
    if (wred.m_weight > 15) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Weight must be between 0 and 15");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // validate ecn probability
    if (wred.m_ecn_probability[lsai_wred::GREEN_INDEX] > 100 || wred.m_ecn_probability[lsai_wred::YELLOW_INDEX] > 100) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Green and Yellow ecn mark probability should be in between 0 to 100");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (wred.m_ecn_probability[lsai_wred::RED_INDEX] != 100) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Red ecn mark probability must equal 100");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // validate min ecn mark threshold for red
    if (wred.m_min_ecn_threshold[lsai_wred::RED_INDEX] != 0) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Red min ecn threshold must equal 0");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // validate max ecn threshold for red
    if (wred.m_max_ecn_threshold[lsai_wred::RED_INDEX] != 0) {
        sai_log_error(SAI_API_WRED, "Bad WRED profile. Red max ecn threshold must equal 0");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    return SAI_STATUS_SUCCESS;
}

lsai_wred_manager_base::lsai_wred_manager_base(std::shared_ptr<lsai_device> sai_dev) : m_lsai_device(sai_dev)
{
    // default wred OID should be of type SAI_OBJECT_TYPE_WRED
    lsai_object default_wred(SAI_OBJECT_TYPE_WRED, lsai_object(sai_dev->m_switch_id).switch_id, 0);
    m_default_wred = default_wred.object_id();
}

lsai_wred_manager_base::~lsai_wred_manager_base()
{
    if (m_lsai_device != nullptr) {
        if (m_default_uc_cgm_profile != nullptr) {
            m_lsai_device->destroy_la_object(m_default_uc_cgm_profile);
        }
        if (m_default_mc_cgm_profile != nullptr) {
            m_lsai_device->destroy_la_object(m_default_mc_cgm_profile);
        }
        if (m_cpu_uc_cgm_profile != nullptr) {
            m_lsai_device->destroy_la_object(m_cpu_uc_cgm_profile);
        }
    }
}

la_status
lsai_wred_manager_base::create_default_wred(transaction& txn, std::shared_ptr<lsai_device> sdev)
{
    la_device* la_dev = sdev->m_dev;
    uint32_t wred_index;

    lsai_wred sai_params;
    sai_params.m_max_drop_threshold[lsai_wred::GREEN_INDEX] = 100 * UNITS_IN_MEGA;
    sai_params.m_max_drop_threshold[lsai_wred::YELLOW_INDEX] = 100 * UNITS_IN_MEGA;

    txn.status = la_dev->create_voq_cgm_profile(m_default_uc_cgm_profile);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { la_dev->destroy(m_default_uc_cgm_profile); });
    sai_params.m_sdk_profile = m_default_uc_cgm_profile;

    txn.status = la_dev->create_voq_cgm_profile(m_default_uc_ecn_cgm_profile);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { la_dev->destroy(m_default_uc_ecn_cgm_profile); });
    sai_params.m_ecn_sdk_profile = m_default_uc_ecn_cgm_profile;

    la_status status = cgm_profile_create_default(sdev, sai_params, m_default_uc_cgm_profile, false);
    la_return_on_error(status);

    status = cgm_profile_create_default(sdev, sai_params, m_default_uc_ecn_cgm_profile, true);
    la_return_on_error(status);

    txn.status = la_dev->create_voq_cgm_profile(m_cpu_uc_cgm_profile);
    la_return_on_error(txn.status);

    status = cgm_profile_create_cpu(sdev, sai_params, m_cpu_uc_cgm_profile);
    la_return_on_error(status);

    sai_params.inc_ref_count(); // We don't want to allow deleting the default profile

    m_wred_db.insert(sai_params, wred_index);

    lsai_object wred_obj(SAI_OBJECT_TYPE_WRED, sdev->m_switch_id, wred_index);
    m_default_wred = wred_obj.object_id();

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_base::initialize_default_mc_cgm_profile(transaction& txn, std::shared_ptr<lsai_device> sdev)
{
    la_device* la_dev = sdev->m_dev;

    txn.status = la_dev->create_voq_cgm_profile(m_default_mc_cgm_profile);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { la_dev->destroy(m_default_mc_cgm_profile); });

    for (la_slice_id_t slice_id = 0; slice_id < sdev->m_dev_params.slices_per_dev; ++slice_id) {
        la_voq_set* voq_set{nullptr};
        txn.status = la_dev->get_egress_multicast_slice_replication_voq_set(slice_id, voq_set);
        la_return_on_error(txn.status);

        for (size_t voq_idx = 0, voq_max = voq_set->get_set_size(); voq_idx < voq_max; ++voq_idx) {
            txn.status = voq_set->set_cgm_profile(voq_idx, m_default_mc_cgm_profile);
            la_return_on_error(txn.status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_base::create_default_profiles(transaction& txn)
{
    txn.status = initialize_default_mc_cgm_profile(txn, m_lsai_device);
    la_return_on_error(txn.status);

    txn.status = create_default_wred(txn, m_lsai_device);
    la_return_on_error(txn.status);

    m_wred_db.set_ignore_in_get_num(1); // ignore default profile on get_count/keys
    sai_log_debug(SAI_API_WRED, "default WRED profile 0x%lx created", m_default_wred);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_base::initialize(transaction& txn)
{
    txn.status = device_level_config();
    la_return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_base::cgm_profile_set_hbm_behavior_gb(la_device* dev,
                                                        la_voq_cgm_profile* cgm_prof,
                                                        uint32_t voq_start,
                                                        uint32_t delay_start,
                                                        uint32_t hbm_free_block_start,
                                                        bool mark_profile)
{
    la_status la_rc;

    uint32_t voq_idx_start = 0, delay_idx_start = 0;
    uint32_t voq_idx = 0, delay_idx = 0;

    la_cgm_hbm_size_in_blocks_key key_green;
    la_cgm_hbm_size_in_blocks_key key_yellow;

    la_cgm_hbm_size_in_blocks_drop_val drop_val;
    la_cgm_hbm_size_in_blocks_mark_ecn_val mark_val;

    la_status lstatus = get_region_index_from_threshold_value(voq_hbm_thresh_gb, voq_start, voq_idx_start);
    la_return_on_error(lstatus);

    lstatus = get_region_index_from_threshold_value(voq_delay_quant_hbm, delay_start, delay_idx_start);
    la_return_on_error(lstatus);

    la_uint64_t num_hbm_blocks_by_voq_regions;
    lstatus = dev->get_limit(limit_type_e::DEVICE__HBM_NUM_BLOCKS_BY_VOQ_QUANTIZATION_REGIONS, num_hbm_blocks_by_voq_regions);
    la_return_on_error(lstatus);

    la_uint64_t num_hbm_queue_delay_regions;
    lstatus = dev->get_limit(limit_type_e::DEVICE__HBM_NUM_VOQ_AGE_QUANTIZATION_REGIONS, num_hbm_queue_delay_regions);
    la_return_on_error(lstatus);

    la_uint64_t num_hbm_pool_free_blocks_regions;
    lstatus = dev->get_limit(limit_type_e::DEVICE__HBM_NUM_POOL_FREE_BLOCKS_QUANTIZATION_REGIONS, num_hbm_pool_free_blocks_regions);
    la_return_on_error(lstatus);

    key_green.hbm_pool_free_blocks_region = hbm_free_block_start;
    key_yellow.hbm_pool_free_blocks_region = hbm_free_block_start;

    if (!mark_profile) {
        for (voq_idx = voq_idx_start; voq_idx < num_hbm_blocks_by_voq_regions; voq_idx++) {
            key_green.hbm_blocks_by_voq_region = voq_idx;
            key_yellow.hbm_blocks_by_voq_region = voq_idx;
            for (delay_idx = delay_idx_start; delay_idx < num_hbm_queue_delay_regions; delay_idx++) {
                key_green.hbm_queue_delay_region = delay_idx;
                key_yellow.hbm_queue_delay_region = delay_idx;

                drop_val.drop_color_level = la_qos_color_e::GREEN;
                // set drop for green packets
                la_rc = cgm_prof->set_hbm_size_in_blocks_drop_behavior(key_green, drop_val);
                la_return_on_error(la_rc);
                // set drop for yellow packets
                drop_val.drop_color_level = la_qos_color_e::YELLOW;
                la_rc = cgm_prof->set_hbm_size_in_blocks_drop_behavior(key_yellow, drop_val);
                la_return_on_error(la_rc);
            }
        }
    } else {
        for (voq_idx = voq_idx_start; voq_idx < num_hbm_blocks_by_voq_regions; voq_idx++) {
            key_green.hbm_blocks_by_voq_region = voq_idx;
            key_yellow.hbm_blocks_by_voq_region = voq_idx;
            for (delay_idx = delay_idx_start; delay_idx < num_hbm_queue_delay_regions; delay_idx++) {
                key_green.hbm_queue_delay_region = delay_idx;
                key_yellow.hbm_queue_delay_region = delay_idx;

                mark_val.mark_ecn_color_level = la_qos_color_e::GREEN;
                // set mark ecn for green packets
                la_rc = cgm_prof->set_hbm_size_in_blocks_mark_ecn_behavior(key_green, mark_val);
                la_return_on_error(la_rc);
                // set mark ecn for yellow packets
                mark_val.mark_ecn_color_level = la_qos_color_e::YELLOW;
                la_rc = cgm_prof->set_hbm_size_in_blocks_mark_ecn_behavior(key_yellow, mark_val);
                la_return_on_error(la_rc);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

/* based on XR function tmrateprofile_set_sms_behavior */
la_status
lsai_wred_manager_base::cgm_profile_set_sms_behavior(la_voq_cgm_profile* cgm_prof,
                                                     uint32_t global_idx,
                                                     uint32_t voq_idx_start,
                                                     uint32_t age_idx_start,
                                                     bool drop,
                                                     bool evict,
                                                     bool ecn)
{
    la_status la_rc;
    la_qos_color_e drop_color;
    uint32_t voq_idx = 0, age_idx = 0, hbm_idx = 0;

    if (drop) {
        /*
         * drop color = GREEN means drop ALL packets
         */
        drop_color = la_qos_color_e::GREEN;
        evict = false;
    } else {
        /*
         * drop color = RED means NO drops
         */
        drop_color = la_qos_color_e::RED;
    }
    for (voq_idx = voq_idx_start; voq_idx < (la_voq_cgm_profile::SMS_NUM_BYTES_QUANTIZATION_REGIONS - 1); voq_idx++) {
        for (hbm_idx = 0; hbm_idx < LA_CGM_NUM_HBM_NUMBER_OF_VOQS_QUANTIZATION_REGIONS; hbm_idx++) {
            for (age_idx = age_idx_start; age_idx < la_voq_cgm_profile::SMS_NUM_AGE_QUANTIZATION_REGIONS; age_idx++) {
                /*
                 * hbm_idx is the region index of the quantized value of the
                 * number of VoQs currently in HBM
                 */

                if (hbm_idx == 1) {
                    la_rc = cgm_prof->set_sms_size_in_bytes_behavior(global_idx, voq_idx, age_idx, hbm_idx, drop_color, ecn, evict);
                } else {
                    la_rc = cgm_prof->set_sms_size_in_bytes_behavior(global_idx, voq_idx, age_idx, hbm_idx, drop_color, ecn, false);
                }
                la_return_on_error(la_rc,
                                   "failed to set sms bytes behavior for global_idx = %d,"
                                   " voq_idx = %d, age_idx = %d, hbm_idx = %d, to ",
                                   global_idx,
                                   voq_idx,
                                   age_idx,
                                   hbm_idx);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_base::get_region_index_from_threshold_value(la_voq_cgm_quantization_thresholds thresholds,
                                                              size_t value,
                                                              uint32_t& out_index)
{
    out_index = 0;
    if (value) {
        auto it = find(thresholds.thresholds.begin(), thresholds.thresholds.end(), value);
        if (it == thresholds.thresholds.end()) {
            return LA_STATUS_EINVAL;
        }
        out_index = distance(thresholds.thresholds.begin(), it) + 1;
    }
    return LA_STATUS_SUCCESS;
}

// based on XR code ofa_la_tmrateprofile_gb_set_sms_behavior
la_status
lsai_wred_manager_base::cgm_profile_set_sms_behavior_gb(la_device* dev,
                                                        la_voq_cgm_profile* cgm_prof,
                                                        uint32_t global_start,
                                                        uint32_t voq_start,
                                                        uint32_t age_start,
                                                        bool gb_has_hbm,
                                                        bool drop,
                                                        bool evict,
                                                        bool mark,
                                                        double drop_prob,
                                                        double mark_prob)
{
    la_status la_rc;

    uint32_t voq_idx_start = 0, age_idx_start = 0;
    uint32_t global_idx = 0;
    uint32_t voq_idx = 0, age_idx = 0;

    la_voq_sms_size_in_bytes_evict_key evict_key;
    la_voq_sms_size_in_bytes_evict_val evict_val;

    la_voq_sms_size_in_bytes_color_key drop_key_green;
    la_voq_sms_size_in_bytes_color_key drop_key_yellow;
    la_voq_sms_size_in_bytes_drop_val drop_val;

    la_voq_sms_wred_drop_probability_selector_key wred_drop;
    la_voq_sms_wred_drop_probability_selector_drop_val wred_drop_val;

    la_voq_sms_wred_mark_probability_selector_key mark_key_green;
    la_voq_sms_wred_mark_probability_selector_key mark_key_yellow;
    la_voq_sms_wred_mark_probability_selector_mark_val mark_prob_val;

    la_status lstatus;
    if (gb_has_hbm) {
        lstatus = get_region_index_from_threshold_value(global_sms_thresh_gb_hbm, global_start, global_idx);
        la_return_on_error(lstatus);
    } else {
        lstatus = get_region_index_from_threshold_value(global_sms_thresh_gb, global_start, global_idx);
        la_return_on_error(lstatus);
    }

    lstatus = get_region_index_from_threshold_value(voq_sms_thresh_gb, voq_start * 384, voq_idx_start);
    la_return_on_error(lstatus);

    lstatus = get_region_index_from_threshold_value(voq_age_thresh_gb, age_start * 1000, age_idx_start);
    la_return_on_error(lstatus);

    drop_val.drop_probability_level
        = (drop) ? LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP : LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_ADMIT;

    evict_val.evict_to_hbm = evict;
    drop_key_green.sms_voqs_total_bytes_region = global_idx;
    drop_key_yellow.sms_voqs_total_bytes_region = global_idx;
    evict_key.sms_voqs_total_bytes_region = global_idx;

    la_uint64_t num_sms_voq_bytes_regions;
    lstatus = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_voq_bytes_regions);
    la_return_on_error(lstatus);

    la_uint64_t num_sms_age_regions;
    lstatus = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_age_regions);
    la_return_on_error(lstatus);

    la_uint64_t num_packet_size_regions;
    lstatus = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__NUM_PACKET_SIZE_REGIONS, num_packet_size_regions);
    la_return_on_error(lstatus);

    for (voq_idx = voq_idx_start; voq_idx < num_sms_voq_bytes_regions; voq_idx++) {
        drop_key_green.sms_bytes_region = voq_idx;
        drop_key_yellow.sms_bytes_region = voq_idx;
        evict_key.sms_bytes_region = voq_idx;
        if (voq_idx == num_sms_voq_bytes_regions - 1) {
            // for the final num_sms_voq_bytes_regions set the drop level to 7.
            drop_val.drop_probability_level = LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP;
        }
        for (age_idx = age_idx_start; age_idx < num_sms_age_regions; age_idx++) {

            if (drop && drop_prob != 0 && voq_idx != num_sms_voq_bytes_regions - 1) {
                // set the drop probability other than 100% or level 7
                // use drop level one to configure with the drop probability
                // the final regions (num_sms_voq_bytes_regions - 1) is set with the drop level 7 in line 2040
                la_cgm_sms_bytes_probability_level_t drop_level = 1;
                wred_drop_val.drop_probability = drop_prob;
                // loop through the packet size region to set the drop prabability and level
                for (uint32_t packet_size_region = 0; packet_size_region < num_packet_size_regions; packet_size_region++) {
                    wred_drop.packet_size_region = packet_size_region;
                    wred_drop.drop_probability_level = drop_level;
                    wred_drop.color = la_qos_color_e::GREEN;

                    la_rc = cgm_prof->set_sms_wred_drop_probability(wred_drop, wred_drop_val);
                    la_return_on_error(la_rc);

                    wred_drop.color = la_qos_color_e::YELLOW;
                    la_rc = cgm_prof->set_sms_wred_drop_probability(wred_drop, wred_drop_val);
                    la_return_on_error(la_rc);
                    // use the above set drop level to set the sms size in bytes drop behavior
                    drop_val.drop_probability_level = drop_level;
                }
            }

            drop_key_green.sms_age_region = age_idx;
            drop_key_yellow.sms_age_region = age_idx;
            drop_key_green.color = la_qos_color_e::GREEN;
            drop_key_yellow.color = la_qos_color_e::YELLOW;

            la_rc = cgm_prof->set_sms_size_in_bytes_drop_behavior(drop_key_green, drop_val);
            la_return_on_error(la_rc);
            // program drop for yellow
            la_rc = cgm_prof->set_sms_size_in_bytes_drop_behavior(drop_key_yellow, drop_val);
            la_return_on_error(la_rc);

            la_cgm_sms_bytes_probability_level_t mark_level;
            if (mark && mark_prob != 0) {
                mark_level = 1;
                // program mark_level = 1 with given probability.
                for (uint32_t packet_size_region = 0; packet_size_region < num_packet_size_regions; packet_size_region++) {
                    mark_key_green.packet_size_region = packet_size_region;
                    mark_key_green.mark_ecn_probability_level = mark_level;
                    mark_key_green.color = la_qos_color_e::GREEN;
                    mark_prob_val.mark_ecn_probability = mark_prob;

                    la_rc = cgm_prof->set_sms_wred_mark_probability(mark_key_green, mark_prob_val);
                    la_return_on_error(la_rc);
                    // program behaviour for yellow
                    mark_key_yellow.packet_size_region = packet_size_region;
                    mark_key_yellow.mark_ecn_probability_level = mark_level;
                    mark_key_yellow.color = la_qos_color_e::YELLOW;

                    la_rc = cgm_prof->set_sms_wred_mark_probability(mark_key_yellow, mark_prob_val);
                    la_return_on_error(la_rc);
                }

            } else {
                mark_level = 0;
            }
            la_voq_sms_size_in_bytes_mark_val mark_val{mark_level};
            la_rc = cgm_prof->set_sms_size_in_bytes_mark_behavior(drop_key_green, mark_val);
            la_return_on_error(la_rc);
            // set mark behavior for yellow
            la_rc = cgm_prof->set_sms_size_in_bytes_mark_behavior(drop_key_yellow, mark_val);
            la_return_on_error(la_rc);

            evict_key.sms_age_region = age_idx;
            // Program eviction behavior
            la_rc = cgm_prof->set_sms_size_in_bytes_evict_behavior(evict_key, evict_val);
            la_return_on_error(la_rc);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_base::check_presence_of_threshold_in_vector_and_get_index(la_voq_cgm_quantization_thresholds thresholds,
                                                                            uint32_t value,
                                                                            uint32_t& out_index)
{
    out_index = 0;
    // if user entered value greater than MAX 16000 * 384; change the value to MAX configurable value
    if (value > thresholds.thresholds.back()) {
        value = thresholds.thresholds.back();
    }
    if (value) {
        auto it = std::lower_bound(thresholds.thresholds.begin(), thresholds.thresholds.end(), value);
        if (it == thresholds.thresholds.end()) {
            return LA_STATUS_EINVAL;
        }
        auto it2 = find(thresholds.thresholds.begin(), thresholds.thresholds.end(), value);
        if (it2 == thresholds.thresholds.end()) {
            // lower_bound returns pointer to position of next higher number than num if num not present in vector
            // hence -1 when the threshold not present in the vector
            out_index = distance(thresholds.thresholds.begin(), it);
        } else {
            out_index = distance(thresholds.thresholds.begin(), it) + 1;
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_base::cgm_profile_set_sms_behavior_user(std::shared_ptr<lsai_device> sdev,
                                                          la_voq_cgm_profile* cgm_prof,
                                                          const lsai_wred& sai_params,
                                                          uint32_t global_start,
                                                          uint32_t age_start,
                                                          bool q_greater_than_max,
                                                          bool evict)
{
    la_status la_rc;
    la_device* dev = sdev->m_dev;

    uint32_t voq_idx_start_green = 0, voq_idx_end_green = 0, voq_idx_start_yellow = 0, voq_idx_end_yellow = 0, age_idx_start = 0;
    uint32_t global_idx = 0;

    // get min and max thresholds
    uint32_t min_threshold_green = sai_params.m_min_drop_threshold[lsai_wred::GREEN_INDEX];
    uint32_t min_threshold_yellow = sai_params.m_min_drop_threshold[lsai_wred::YELLOW_INDEX];

    uint32_t max_threshold_green = sai_params.m_max_drop_threshold[lsai_wred::GREEN_INDEX];
    uint32_t max_threshold_yellow = sai_params.m_max_drop_threshold[lsai_wred::YELLOW_INDEX];

    // get regions indexes
    la_status lstatus = get_region_index_from_threshold_value(global_sms_thresh_gb, global_start, global_idx);
    la_return_on_error(lstatus);

    lstatus = check_presence_of_threshold_in_vector_and_get_index(voq_sms_thresh_gb, min_threshold_green, voq_idx_start_green);
    la_return_on_error(lstatus);

    lstatus = check_presence_of_threshold_in_vector_and_get_index(voq_sms_thresh_gb, max_threshold_green, voq_idx_end_green);
    la_return_on_error(lstatus);

    lstatus = check_presence_of_threshold_in_vector_and_get_index(voq_sms_thresh_gb, min_threshold_yellow, voq_idx_start_yellow);
    la_return_on_error(lstatus);

    lstatus = check_presence_of_threshold_in_vector_and_get_index(voq_sms_thresh_gb, max_threshold_yellow, voq_idx_end_yellow);
    la_return_on_error(lstatus);

    lstatus = get_region_index_from_threshold_value(voq_age_thresh_gb, (age_start * 1000) / 2, age_idx_start);
    la_return_on_error(lstatus);

    la_uint64_t num_sms_voq_bytes_regions;
    lstatus = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_voq_bytes_regions);
    la_return_on_error(lstatus);

    la_uint64_t num_sms_age_regions;
    lstatus = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_age_regions);
    la_return_on_error(lstatus);

    // no need to program eviction since this is the profile for GB without HBM

    double prob_step_green;
    double prob_step_yellow;
    double drop_prob_green;
    double drop_prob_yellow;

    if (q_greater_than_max) {
        voq_idx_start_green = voq_idx_end_green;
        voq_idx_end_green = num_sms_voq_bytes_regions;
        voq_idx_start_yellow = voq_idx_end_yellow;
        voq_idx_end_yellow = num_sms_voq_bytes_regions;

        prob_step_green = 1;
        prob_step_yellow = 1;
        drop_prob_green = 1;
        drop_prob_yellow = 1;
    } else {
        // get distance between min and max threshold
        double dist_min_max_green = voq_idx_end_green - voq_idx_start_green;
        double dist_min_max_yellow = voq_idx_end_yellow - voq_idx_start_yellow;

        drop_prob_green = (double)sai_params.m_drop_probability[lsai_wred::GREEN_INDEX] / double(100);
        drop_prob_yellow = (double)sai_params.m_drop_probability[lsai_wred::YELLOW_INDEX] / double(100);

        if (dist_min_max_green > 6) {
            // probability step increases for first 6 regions which are associated with 6 drop levels.
            // drop probability above that remains constant
            prob_step_green = drop_prob_green / (double)(6);
            prob_step_yellow = drop_prob_yellow / (double)(6);
        } else {
            // probability step
            prob_step_green = drop_prob_green / (double)(dist_min_max_green);
            prob_step_yellow = drop_prob_yellow / (double)(dist_min_max_yellow);
        }
    }

    // program drop for green between min and max thresholds
    if (sai_params.m_enabled[lsai_wred::GREEN_INDEX] == true) {
        la_rc = set_sms_drop_behavior_user(sdev,
                                           cgm_prof,
                                           global_idx,
                                           voq_idx_start_green,
                                           voq_idx_end_green,
                                           age_idx_start,
                                           q_greater_than_max,
                                           la_qos_color_e::GREEN,
                                           prob_step_green,
                                           drop_prob_green);
        la_return_on_error(la_rc,
                           "Failed to program drop behavior for green color global idx %d, voq idx_start = %d, voq_idx_end= %d",
                           global_idx,
                           voq_idx_start_green,
                           voq_idx_end_green);
    }

    // program drop for yellow between min and max thresholds
    if (sai_params.m_enabled[lsai_wred::YELLOW_INDEX] == true) {
        la_rc = set_sms_drop_behavior_user(sdev,
                                           cgm_prof,
                                           global_idx,
                                           voq_idx_start_yellow,
                                           voq_idx_end_yellow,
                                           age_idx_start,
                                           q_greater_than_max,
                                           la_qos_color_e::YELLOW,
                                           prob_step_yellow,
                                           drop_prob_yellow);
        la_return_on_error(la_rc,
                           "Failed to program drop behavior for yellow color global idx %d, voq idx_start = %d, voq_idx_end= %d",
                           global_idx,
                           voq_idx_start_yellow,
                           voq_idx_end_yellow);
    }
    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_base::cgm_profile_ecn_set_sms_behavior_user(std::shared_ptr<lsai_device> sdev,
                                                              la_voq_cgm_profile* cgm_prof,
                                                              const lsai_wred& sai_params,
                                                              uint32_t global_start,
                                                              uint32_t age_start,
                                                              bool q_greater_than_max,
                                                              bool evict)
{
    la_status la_rc;
    la_device* dev = sdev->m_dev;

    uint32_t voq_idx_start_green = 0, voq_idx_end_green = 0, voq_idx_start_yellow = 0, voq_idx_end_yellow = 0, age_idx_start = 0;
    uint32_t global_idx = 0;

    uint32_t min_ecn_threshold_green = 0, min_ecn_threshold_yellow = 0, max_ecn_threshold_green = 0, max_ecn_threshold_yellow = 0;
    double ecn_probab_green;
    double ecn_probab_yellow;

    // program mark behavior between min and max threshold
    // get min and max ecn thresholds
    if (sdev->m_ecn_ect) {
        // when the SAI_SWITCH_ATTR_ECN_ECT_THRESHOLD_ENABLE is set we use the ECN thresholds for mark behavior
        min_ecn_threshold_green = sai_params.m_min_ecn_threshold[lsai_wred::GREEN_INDEX];
        min_ecn_threshold_yellow = sai_params.m_min_ecn_threshold[lsai_wred::YELLOW_INDEX];

        max_ecn_threshold_green = sai_params.m_max_ecn_threshold[lsai_wred::GREEN_INDEX];
        max_ecn_threshold_yellow = sai_params.m_max_ecn_threshold[lsai_wred::YELLOW_INDEX];

        ecn_probab_green = (double)sai_params.m_ecn_probability[lsai_wred::GREEN_INDEX] / double(100);
        ecn_probab_yellow = (double)sai_params.m_ecn_probability[lsai_wred::YELLOW_INDEX] / double(100);

    } else {
        // get min and max drop thresholds
        // use the drop thresholds to configure the marking behavior when the m_ecn_ect not set
        min_ecn_threshold_green = sai_params.m_min_drop_threshold[lsai_wred::GREEN_INDEX];
        min_ecn_threshold_yellow = sai_params.m_min_drop_threshold[lsai_wred::YELLOW_INDEX];

        max_ecn_threshold_green = sai_params.m_max_drop_threshold[lsai_wred::GREEN_INDEX];
        max_ecn_threshold_yellow = sai_params.m_max_drop_threshold[lsai_wred::YELLOW_INDEX];

        ecn_probab_green = (double)sai_params.m_drop_probability[lsai_wred::GREEN_INDEX] / double(100);
        ecn_probab_yellow = (double)sai_params.m_drop_probability[lsai_wred::YELLOW_INDEX] / double(100);
    }

    // get regions indexes
    la_status lstatus = get_region_index_from_threshold_value(global_sms_thresh_gb, global_start, global_idx);
    la_return_on_error(lstatus);

    lstatus = check_presence_of_threshold_in_vector_and_get_index(voq_sms_thresh_gb, min_ecn_threshold_green, voq_idx_start_green);
    la_return_on_error(lstatus);

    lstatus = check_presence_of_threshold_in_vector_and_get_index(voq_sms_thresh_gb, max_ecn_threshold_green, voq_idx_end_green);
    la_return_on_error(lstatus);

    lstatus
        = check_presence_of_threshold_in_vector_and_get_index(voq_sms_thresh_gb, min_ecn_threshold_yellow, voq_idx_start_yellow);
    la_return_on_error(lstatus);

    lstatus = check_presence_of_threshold_in_vector_and_get_index(voq_sms_thresh_gb, max_ecn_threshold_yellow, voq_idx_end_yellow);
    la_return_on_error(lstatus);

    lstatus = get_region_index_from_threshold_value(voq_age_thresh_gb, (age_start * 1000) / 2, age_idx_start);
    la_return_on_error(lstatus);

    la_uint64_t num_sms_voq_bytes_regions;
    lstatus = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS, num_sms_voq_bytes_regions);
    la_return_on_error(lstatus);

    la_uint64_t num_sms_age_regions;
    lstatus = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_age_regions);
    la_return_on_error(lstatus);

    // no need to program eviction since this is the profile for GB without HBM

    if (q_greater_than_max) {
        voq_idx_start_green = voq_idx_end_green;
        voq_idx_end_green = num_sms_voq_bytes_regions;
        voq_idx_start_yellow = voq_idx_end_yellow;
        voq_idx_end_yellow = num_sms_voq_bytes_regions;
    }

    // get distance between min and max threshold
    uint32_t dist_min_max_green = voq_idx_end_green - voq_idx_start_green;
    uint32_t dist_min_max_yellow = voq_idx_end_yellow - voq_idx_start_yellow;

    // divide the distance between min and max thresh into 2
    // first region with mark_level= 1 mark_probability = mark_prob /2
    // second region with mark_level = 2 mark_probability = mark_prob
    uint32_t mid_min_max_green = (dist_min_max_green % 2 == 0) ? dist_min_max_green / 2 : (dist_min_max_green + 1) / 2;
    uint32_t mid_min_max_yellow = (dist_min_max_yellow % 2 == 0) ? dist_min_max_yellow / 2 : (dist_min_max_yellow + 1) / 2;

    // program mark behavior between min and max threshold for green
    if (sai_params.m_enabled[lsai_wred::GREEN_INDEX] == true) {
        if (sai_params.m_ecn_mode == SAI_ECN_MARK_MODE_ALL || sai_params.m_ecn_mode == SAI_ECN_MARK_MODE_GREEN
            || sai_params.m_ecn_mode == SAI_ECN_MARK_MODE_GREEN_YELLOW
            || sai_params.m_ecn_mode == SAI_ECN_MARK_MODE_GREEN_RED) {
            la_rc = set_sms_mark_behavior_user(sdev,
                                               cgm_prof,
                                               global_idx,
                                               voq_idx_start_green,
                                               voq_idx_end_green,
                                               age_idx_start,
                                               q_greater_than_max,
                                               la_qos_color_e::GREEN,
                                               ecn_probab_green,
                                               mid_min_max_green);
            la_return_on_error(la_rc,
                               "Failed to program mark behavior for green color global idx %d, voq idx_start = %d, voq_idx_end= %d",
                               global_idx,
                               voq_idx_start_green,
                               voq_idx_end_green);
        }
    }

    // program mark behavior between min and max threshold for yellow
    if (sai_params.m_enabled[lsai_wred::YELLOW_INDEX] == true) {
        if (sai_params.m_ecn_mode == SAI_ECN_MARK_MODE_ALL || sai_params.m_ecn_mode == SAI_ECN_MARK_MODE_YELLOW
            || sai_params.m_ecn_mode == SAI_ECN_MARK_MODE_GREEN_YELLOW
            || sai_params.m_ecn_mode == SAI_ECN_MARK_MODE_YELLOW_RED) {
            la_rc = set_sms_mark_behavior_user(sdev,
                                               cgm_prof,
                                               global_idx,
                                               voq_idx_start_yellow,
                                               voq_idx_end_yellow,
                                               age_idx_start,
                                               q_greater_than_max,
                                               la_qos_color_e::YELLOW,
                                               ecn_probab_yellow,
                                               mid_min_max_yellow);
            la_return_on_error(
                la_rc,
                "Failed to program mark behavior for yellow color global idx %d, voq idx_start = %d, voq_idx_end= %d",
                global_idx,
                voq_idx_start_yellow,
                voq_idx_end_yellow);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_base::set_sms_drop_behavior_user(std::shared_ptr<lsai_device> sdev,
                                                   la_voq_cgm_profile* cgm_prof,
                                                   uint32_t global_idx_start,
                                                   uint32_t voq_idx_start,
                                                   uint32_t voq_idx_end,
                                                   uint32_t age_idx_start,
                                                   bool q_greater_than_max,
                                                   la_qos_color_e drop_color,
                                                   double prob_drop_step,
                                                   double drop_prob)
{
    uint32_t voq_idx = 0, age_idx = 0;
    la_device* dev = sdev->m_dev;
    la_status la_rc;

    la_voq_sms_size_in_bytes_color_key drop_key;
    la_voq_sms_size_in_bytes_drop_val drop_val;

    la_voq_sms_wred_drop_probability_selector_key wred_drop;
    la_voq_sms_wred_drop_probability_selector_drop_val wred_drop_val;

    la_uint64_t num_sms_age_regions;
    la_status lstatus = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_age_regions);
    la_return_on_error(lstatus);

    la_uint64_t num_packet_size_regions;
    lstatus = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__NUM_PACKET_SIZE_REGIONS, num_packet_size_regions);
    la_return_on_error(lstatus);

    drop_key.sms_voqs_total_bytes_region = global_idx_start;
    drop_key.sms_voqs_total_bytes_region = global_idx_start;

    la_cgm_sms_bytes_probability_level_t drop_level = 0;

    // Total 7 drop level. Drop level 0, probability 0 --> Admit . Drop level 7, probability 100 --> Total drop
    // Drop level 1-6 can be programmed with different drop probabilities
    // First region (0 - min threshold) - probabilty 0, drop level 0 programmed in first call of "cgm_profile_set_sms_behavior_gb"
    // Inner regions (min - max threshold) - Linear probability, starting from 0, ending at drop probabilty configured by user
    // Last region (> max threshold) - probabilty 100, drop level 7

    for (voq_idx = voq_idx_start; voq_idx < voq_idx_end; voq_idx++) {
        drop_key.sms_bytes_region = voq_idx;
        if (drop_level < 6 && !q_greater_than_max) {
            drop_level += 1;
            wred_drop_val.drop_probability = drop_level * prob_drop_step;
        } else if (q_greater_than_max) {
            drop_level = LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP; // level 7
            wred_drop_val.drop_probability = 1;                        // 100 % drop above max threshold
        } else {
            // dist between min max threshold can be greater than 6, we have only 6 drop level to associate with probabilities.
            // associate these regions with the user's drop probability (constant drop)
            drop_level = 6;
            wred_drop_val.drop_probability = drop_prob;
        }
        for (age_idx = age_idx_start; age_idx < num_sms_age_regions; age_idx++) {

            for (uint32_t packet_size_region = 0; packet_size_region < num_packet_size_regions; packet_size_region++) {
                wred_drop.packet_size_region = packet_size_region;
                wred_drop.drop_probability_level = drop_level;
                wred_drop.color = drop_color;

                la_rc = cgm_prof->set_sms_wred_drop_probability(wred_drop, wred_drop_val);
                la_return_on_error(la_rc);
            }
            drop_key.sms_age_region = age_idx;
            drop_key.color = drop_color;

            drop_val.drop_probability_level = drop_level;

            la_rc = cgm_prof->set_sms_size_in_bytes_drop_behavior(drop_key, drop_val);
            la_return_on_error(la_rc);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_base::set_sms_mark_behavior_user(std::shared_ptr<lsai_device> sdev,
                                                   la_voq_cgm_profile* cgm_prof,
                                                   uint32_t global_idx_start,
                                                   uint32_t voq_idx_start,
                                                   uint32_t voq_idx_end,
                                                   uint32_t age_idx_start,
                                                   bool q_greater_than_max,
                                                   la_qos_color_e mark_color,
                                                   double ecn_mark_prob,
                                                   uint32_t mid_min_max)
{
    uint32_t voq_idx = 0, age_idx = 0;
    la_device* dev = sdev->m_dev;
    la_status la_rc;

    la_voq_sms_size_in_bytes_color_key mark_key;
    la_voq_sms_wred_mark_probability_selector_key wred_mark;
    la_voq_sms_wred_mark_probability_selector_mark_val mark_prob;

    la_cgm_sms_bytes_probability_level_t mark_level;

    la_uint64_t num_sms_age_regions;
    la_status lstatus = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_AGE_QUANTIZATION_REGIONS, num_sms_age_regions);
    la_return_on_error(lstatus);

    la_uint64_t num_packet_size_regions;
    lstatus = dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__NUM_PACKET_SIZE_REGIONS, num_packet_size_regions);
    la_return_on_error(lstatus);

    uint32_t mid_idx = 1;
    mark_key.sms_voqs_total_bytes_region = global_idx_start;
    mark_key.sms_voqs_total_bytes_region = global_idx_start;

    for (voq_idx = voq_idx_start; voq_idx < voq_idx_end; voq_idx++) {
        mark_key.sms_bytes_region = voq_idx;
        if (mid_idx <= mid_min_max && !q_greater_than_max) {
            mark_level = 1;
            mark_prob.mark_ecn_probability = ecn_mark_prob / double(2); // divide by  2
            mid_idx += 1;
        } else if (q_greater_than_max) {
            mark_level = 3;
            mark_prob.mark_ecn_probability = 1;
        } else {
            mark_level = 2;
            mark_prob.mark_ecn_probability = ecn_mark_prob;
        }
        for (age_idx = age_idx_start; age_idx < num_sms_age_regions; age_idx++) {
            for (uint32_t packet_size_region = 0; packet_size_region < num_packet_size_regions; packet_size_region++) {
                wred_mark.packet_size_region = packet_size_region;
                wred_mark.mark_ecn_probability_level = mark_level;
                wred_mark.color = mark_color;

                la_rc = cgm_prof->set_sms_wred_mark_probability(wred_mark, mark_prob);
                la_return_on_error(la_rc);
            }
            mark_key.sms_age_region = age_idx;
            mark_key.color = mark_color;

            la_voq_sms_size_in_bytes_mark_val mark_val{mark_level};
            la_rc = cgm_prof->set_sms_size_in_bytes_mark_behavior(mark_key, mark_val);
            la_return_on_error(la_rc);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_base::device_level_config_base(std::shared_ptr<lsai_device> sdev, bool init_hbm)
{
    la_status la_rc;
    la_cgm_sms_bytes_quantization_thresholds sms_used_thresh;
    la_cgm_hbm_pool_free_blocks_quantization_thresholds hbm_free_thresh;
    la_cgm_hbm_blocks_by_voq_quantization_thresholds voq_hbm_used_thresh;
    la_device* dev = sdev->m_dev;

    // Quantization thresholds for total SMS bytes used
    sms_used_thresh = {{(24 * 1024 * 384), (32 * 1024 * 384), (35 * 1024 * 384)}};

    // Quantization thresholds for the number of free HBM blocks
    hbm_free_thresh = {{(58576), (68576), (98576), (118576), (174576), (298576), (548576)}};

    // Quantization thresholds for per VoQ HBM blocks used
    voq_hbm_used_thresh = {{(250),
                            (2 * 1024),
                            (4 * 1024),
                            (8 * 1024),
                            (16 * 1024),
                            (32 * 1024),
                            (62 * 1024),
                            (63 * 1024),
                            (63 * 1024),
                            (63 * 1024),
                            (63 * 1024),
                            (63 * 1024),
                            (63 * 1024),
                            (63 * 1024),
                            (63 * 1024)}};

    // allocate all blocks to pool 0. No blocks to pool 1
    if (init_hbm) {
        la_rc = dev->set_hbm_pool_max_capacity(0, 1);
        la_return_on_error(la_rc, "Failed allocating hbm pool 0 blocks");
        la_rc = dev->set_hbm_pool_max_capacity(1, 0);
        la_return_on_error(la_rc, "Failed allocating hbm pool 1 blocks");

        la_rc = dev->set_cgm_hbm_pool_free_blocks_quantization(0, hbm_free_thresh);
        la_return_on_error(la_rc, "failed to set HBM free blocks threshold");

        la_rc = dev->set_cgm_hbm_blocks_by_voq_quantization(voq_hbm_used_thresh);
        la_return_on_error(la_rc, "failed to set per voq HBM used threshold");
    }

    la_rc = dev->set_cgm_sms_voqs_age_time_granularity(1000);
    la_return_on_error(la_rc, "failed to set vog age time granulariy");

    la_rc = dev->set_cgm_sms_voqs_bytes_quantization(sms_used_thresh);
    la_return_on_error(la_rc, "failed to set total sms used threshold");

    //
    // The maximum number of VOQs is 4096 - 134(reserved) =  3962.
    // The threshold value used here will restrict number of queues to be
    // evicted to HBM at any given time. Settig to max value of 3962 can
    // cause issue with HBM eviction functionality such as queues might
    // stuck or not operable.
    //
    la_cgm_hbm_number_of_voqs_quantization_thresholds hbm_thresholds;
    for (uint32_t idx = 0; idx < LA_CGM_NUM_HBM_NUMBER_OF_VOQS_QUANTIZATION_CONFIGURABLE_THRESHOLDS; idx++) {
        hbm_thresholds.thresholds[idx] = 3500;
    }
    la_rc = dev->set_cgm_hbm_number_of_voqs_quantization(hbm_thresholds);
    la_return_on_error(la_rc, "failed to set number of voqs quantization on device")

        return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_base::device_level_config_base_gb(std::shared_ptr<lsai_device> sdev, bool init_hbm)
{
    la_status la_rc;

    la_voq_cgm_quantization_thresholds hbm_free_thresh;
    la_voq_cgm_quantization_thresholds voq_hbm_used_thresh;
    la_voq_cgm_quantization_thresholds voq_delay_quant_hbm;
    la_device* dev = sdev->m_dev;

    // Quantization thresholds for the number of free HBM blocks
    const la_uint_t max_hbm_blocks_per_pool = 1000 * 1000;

    // assert(max_hbm_blocks_per_pool >= (990 * 1000));
    hbm_free_thresh = {{(max_hbm_blocks_per_pool - (990 * 1000)),
                        (max_hbm_blocks_per_pool - (980 * 1000)),
                        (max_hbm_blocks_per_pool - (950 * 1000)),
                        (max_hbm_blocks_per_pool - (930 * 1000)),
                        (max_hbm_blocks_per_pool - (875 * 1000)),
                        (max_hbm_blocks_per_pool - (750 * 1000)),
                        (max_hbm_blocks_per_pool - (500 * 1000))}};

    // allocate all blocks to pool 0. No blocks to pool 1
    if (init_hbm) {
        la_rc = dev->set_hbm_pool_max_capacity(0, 1);
        la_return_on_error(la_rc, "Failed allocating hbm pool 0 blocks");
        la_rc = dev->set_hbm_pool_max_capacity(1, 0);
        la_return_on_error(la_rc, "Failed allocating hbm pool 1 blocks");

        la_rc = dev->set_cgm_hbm_pool_free_blocks_quantization(0, hbm_free_thresh);
        la_return_on_error(la_rc, "failed to set HBM free blocks threshold");

        la_rc = dev->set_cgm_hbm_blocks_by_voq_quantization(voq_hbm_thresh_gb);
        la_return_on_error(la_rc, "failed to set per voq HBM used threshold");

        la_rc = dev->set_cgm_hbm_voq_age_quantization(voq_age_thresh_gb);
        la_return_on_error(la_rc, "failed to set per voq HBM age quantization");
    }

    la_rc = dev->set_cgm_sms_voqs_age_time_granularity(1000);
    la_return_on_error(la_rc, "failed to set vog age time granulariy");

    if (init_hbm) {
        la_rc = dev->set_cgm_sms_voqs_bytes_quantization(global_sms_thresh_gb_hbm);
        la_return_on_error(la_rc, "failed to set total sms used threshold");
    } else {
        la_rc = dev->set_cgm_sms_voqs_bytes_quantization(global_sms_thresh_gb);
        la_return_on_error(la_rc, "failed to set total sms used threshold");
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_wred_manager_base::cgm_prof_from_oid(sai_object_id_t wred_id, la_voq_cgm_profile*& cgm_prof, la_voq_cgm_profile*& cgm_prof_ecn)
{
    if (wred_id == SAI_NULL_OBJECT_ID) {
        wred_id = m_default_wred;
    }

    lsai_object la_obj(wred_id);
    if (la_obj.type != SAI_OBJECT_TYPE_WRED || la_obj.get_device() == nullptr || la_obj.get_device()->m_dev == nullptr) {
        sai_log_error(SAI_API_WRED, "Bad WRED object id %lu", wred_id);
        return LA_STATUS_EINVAL;
    }

    lsai_wred wred;
    la_status status = m_wred_db.get(la_obj.index, wred);
    la_return_on_error(status);

    cgm_prof = wred.sdk_profile();
    cgm_prof_ecn = wred.sdk_ecn_profile();

    return LA_STATUS_SUCCESS;
}

void
lsai_wred_manager_base::inc_ref_count(sai_object_id_t wred_id)
{
    inc_or_dec_ref_count(wred_id, true);
}

void
lsai_wred_manager_base::dec_ref_count(sai_object_id_t wred_id)
{
    inc_or_dec_ref_count(wred_id, false);
}

la_status
lsai_wred_manager_base::inc_or_dec_ref_count(sai_object_id_t wred_id, bool inc)
{
    // want to keep default profile reference count unchanged.
    if (wred_id == m_default_wred || wred_id == SAI_NULL_OBJECT_ID) {
        return LA_STATUS_SUCCESS;
    }

    lsai_object la_obj(wred_id);
    if (la_obj.type != SAI_OBJECT_TYPE_WRED || la_obj.get_device() == nullptr || la_obj.get_device()->m_dev == nullptr) {
        sai_log_error(SAI_API_WRED, "Bad WRED object id %lu", wred_id);
        return LA_STATUS_EINVAL;
    }

    lsai_wred* wred = m_wred_db.get_ptr(la_obj.index);
    if (wred == nullptr) {
        return LA_STATUS_ENOTFOUND;
    }

    if (inc) {
        wred->inc_ref_count();
    } else {
        wred->dec_ref_count();
    }

    return LA_STATUS_SUCCESS;
}

static std::string
wred_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_wred_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

/**
 * @brief Create a WRED object
 *
 * @param[out] out_wred_id obj ID of allocated object
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t
lsai_wred_manager_base::create_wred(_Out_ sai_object_id_t* out_wred_id,
                                    _In_ sai_object_id_t switch_id,
                                    _In_ uint32_t attr_count,
                                    _In_ const sai_attribute_t* attr_list)
{
    transaction txn;
    txn.status = LA_STATUS_SUCCESS;

    // get relevant attributes
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_WRED, SAI_OBJECT_TYPE_SWITCH, switch_id, &wred_to_string, attrs);

    lsai_wred wred;
    bool green_enable = false;
    get_attrs_value(SAI_WRED_ATTR_GREEN_ENABLE, attrs, green_enable, false);
    wred.m_enabled[lsai_wred::GREEN_INDEX] = green_enable;

    bool yellow_enable = false;
    get_attrs_value(SAI_WRED_ATTR_YELLOW_ENABLE, attrs, yellow_enable, false);
    wred.m_enabled[lsai_wred::YELLOW_INDEX] = yellow_enable;

    bool red_enable = false;
    get_attrs_value(SAI_WRED_ATTR_RED_ENABLE, attrs, red_enable, false);
    wred.m_enabled[lsai_wred::RED_INDEX] = red_enable;

    uint8_t weight = 0;
    get_attrs_value(SAI_WRED_ATTR_WEIGHT, attrs, weight, false);
    wred.m_weight = weight;

    sai_ecn_mark_mode_t ecn_mode = SAI_ECN_MARK_MODE_NONE;
    get_attrs_value(SAI_WRED_ATTR_ECN_MARK_MODE, attrs, ecn_mode, false);
    wred.m_ecn_mode = ecn_mode;

    uint32_t green_min_threshold = 0;
    get_attrs_value(SAI_WRED_ATTR_GREEN_MIN_THRESHOLD, attrs, green_min_threshold, false);
    wred.m_min_drop_threshold[lsai_wred::GREEN_INDEX] = green_min_threshold;

    uint32_t green_max_threshold = 0;
    get_attrs_value(SAI_WRED_ATTR_GREEN_MAX_THRESHOLD, attrs, green_max_threshold, false);
    wred.m_max_drop_threshold[lsai_wred::GREEN_INDEX] = green_max_threshold;

    uint32_t green_drop_probability = 100;
    get_attrs_value(SAI_WRED_ATTR_GREEN_DROP_PROBABILITY, attrs, green_drop_probability, false);
    wred.m_drop_probability[lsai_wred::GREEN_INDEX] = green_drop_probability;

    uint32_t yellow_min_threshold = 0;
    get_attrs_value(SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD, attrs, yellow_min_threshold, false);
    wred.m_min_drop_threshold[lsai_wred::YELLOW_INDEX] = yellow_min_threshold;

    uint32_t yellow_max_threshold = 0;
    get_attrs_value(SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD, attrs, yellow_max_threshold, false);
    wred.m_max_drop_threshold[lsai_wred::YELLOW_INDEX] = yellow_max_threshold;

    uint32_t yellow_drop_probability = 100;
    get_attrs_value(SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY, attrs, yellow_drop_probability, false);
    wred.m_drop_probability[lsai_wred::YELLOW_INDEX] = yellow_drop_probability;

    uint32_t red_min_threshold = 0;
    get_attrs_value(SAI_WRED_ATTR_RED_MIN_THRESHOLD, attrs, red_min_threshold, false);
    wred.m_min_drop_threshold[lsai_wred::RED_INDEX] = red_min_threshold;

    uint32_t red_max_threshold = 0;
    get_attrs_value(SAI_WRED_ATTR_RED_MAX_THRESHOLD, attrs, red_max_threshold, false);
    wred.m_max_drop_threshold[lsai_wred::RED_INDEX] = red_max_threshold;

    uint32_t red_drop_probability = 100;
    get_attrs_value(SAI_WRED_ATTR_RED_DROP_PROBABILITY, attrs, red_drop_probability, false);
    wred.m_drop_probability[lsai_wred::RED_INDEX] = red_drop_probability;

    green_min_threshold = wred.m_min_drop_threshold[lsai_wred::GREEN_INDEX];
    get_attrs_value(SAI_WRED_ATTR_ECN_GREEN_MIN_THRESHOLD, attrs, green_min_threshold, false);
    wred.m_min_ecn_threshold[lsai_wred::GREEN_INDEX] = green_min_threshold;

    green_max_threshold = wred.m_max_drop_threshold[lsai_wred::GREEN_INDEX];
    get_attrs_value(SAI_WRED_ATTR_ECN_GREEN_MAX_THRESHOLD, attrs, green_max_threshold, false);
    wred.m_max_ecn_threshold[lsai_wred::GREEN_INDEX] = green_max_threshold;

    uint32_t green_mark_probability = wred.m_drop_probability[lsai_wred::GREEN_INDEX];
    get_attrs_value(SAI_WRED_ATTR_ECN_GREEN_MARK_PROBABILITY, attrs, green_mark_probability, false);
    wred.m_ecn_probability[lsai_wred::GREEN_INDEX] = green_mark_probability;

    yellow_min_threshold = wred.m_min_drop_threshold[lsai_wred::YELLOW_INDEX];
    get_attrs_value(SAI_WRED_ATTR_ECN_YELLOW_MIN_THRESHOLD, attrs, yellow_min_threshold, false);
    wred.m_min_ecn_threshold[lsai_wred::YELLOW_INDEX] = yellow_min_threshold;

    yellow_max_threshold = wred.m_max_drop_threshold[lsai_wred::YELLOW_INDEX];
    get_attrs_value(SAI_WRED_ATTR_ECN_YELLOW_MAX_THRESHOLD, attrs, yellow_max_threshold, false);
    wred.m_max_ecn_threshold[lsai_wred::YELLOW_INDEX] = yellow_max_threshold;

    uint32_t yellow_mark_probability = wred.m_drop_probability[lsai_wred::YELLOW_INDEX];
    get_attrs_value(SAI_WRED_ATTR_ECN_YELLOW_MARK_PROBABILITY, attrs, yellow_mark_probability, false);
    wred.m_ecn_probability[lsai_wred::YELLOW_INDEX] = yellow_mark_probability;

    red_min_threshold = wred.m_min_drop_threshold[lsai_wred::RED_INDEX];
    get_attrs_value(SAI_WRED_ATTR_ECN_RED_MIN_THRESHOLD, attrs, red_min_threshold, false);
    wred.m_min_ecn_threshold[lsai_wred::RED_INDEX] = red_min_threshold;

    red_max_threshold = wred.m_max_drop_threshold[lsai_wred::RED_INDEX];
    get_attrs_value(SAI_WRED_ATTR_ECN_RED_MAX_THRESHOLD, attrs, red_max_threshold, false);
    wred.m_max_ecn_threshold[lsai_wred::RED_INDEX] = red_max_threshold;

    uint32_t red_mark_probability = wred.m_drop_probability[lsai_wred::RED_INDEX];
    get_attrs_value(SAI_WRED_ATTR_ECN_RED_MARK_PROBABILITY, attrs, red_mark_probability, false);
    wred.m_ecn_probability[lsai_wred::RED_INDEX] = red_mark_probability;

    // validate attributes
    sai_status_t sstatus = sdev->m_wred_handler->wred_profile_validate(wred);
    sai_return_on_error(sstatus);

    // create SDK object, and insert to DB
    txn.status = sdev->m_dev->create_voq_cgm_profile(wred.m_sdk_profile);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_dev->destroy(wred.m_sdk_profile); });

    // create SDK object for ecn profile, and insert to DB
    txn.status = sdev->m_dev->create_voq_cgm_profile(wred.m_ecn_sdk_profile);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_dev->destroy(wred.m_ecn_sdk_profile); });

    txn.status = sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_sdk_profile, false);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_dev->destroy(wred.m_sdk_profile); });

    // set ecn profile
    txn.status = sdev->m_wred_handler->cgm_profile_create_user(
        sdev, wred, wred.m_ecn_sdk_profile, ecn_mode == SAI_ECN_MARK_MODE_NONE ? false : true);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_dev->destroy(wred.m_ecn_sdk_profile); });

    uint32_t wred_index = 0;
    la_status status = sdev->m_wred_handler->m_wred_db.insert(wred, wred_index);
    sai_return_on_la_error(status, "Failed inserting WRED object");
    txn.on_fail([=]() { sdev->m_wred_handler->m_wred_db.remove(wred_index); });

    lsai_object la_wred_id(SAI_OBJECT_TYPE_WRED, la_obj.switch_id, wred_index);
    *out_wred_id = la_wred_id.object_id();

    sai_log_info(SAI_API_WRED, "WRED 0x%lx created", *out_wred_id);

    lsai_logger& instance = lsai_logger::instance();
    if (instance.is_logging(SAI_API_WRED, SAI_LOG_LEVEL_DEBUG)) {
        sdev->m_wred_handler->dump();
    }

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Remove an existing WRED
 *
 * @param[in] wred_id WRED Id
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t
lsai_wred_manager_base::remove_wred(_In_ sai_object_id_t wred_id)
{
    // verify it exists
    sai_start_api(SAI_API_WRED, SAI_OBJECT_TYPE_WRED, wred_id, &wred_to_string, wred_id);

    lsai_wred wred;
    la_status status = sdev->m_wred_handler->m_wred_db.get(la_obj.index, wred);
    sai_return_on_la_error(status);

    // verify it is not in use by the device!
    if (wred.m_ref_count > 0) {
        sai_log_error(SAI_API_WRED, "Failed to erase WRED id %lx because it is in use", wred_id);
        return SAI_STATUS_OBJECT_IN_USE;
    }

    // OK to erase
    sdev->m_dev->destroy(wred.m_sdk_profile);
    if (wred.m_ecn_sdk_profile) {
        sdev->m_dev->destroy(wred.m_ecn_sdk_profile);
    }
    sdev->m_wred_handler->m_wred_db.remove(la_obj.index);

    sai_log_debug(SAI_API_WRED, "WRED 0x%lx removed", wred_id);

    return SAI_STATUS_SUCCESS;
}

/**
 * @brief Set an attribute in a WRED object
 *
 * @param[in] wred_id WRED ID
 * @param[in] attr An attribute to set
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t
lsai_wred_manager_base::set_wred_attribute(_In_ sai_object_id_t wred_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = wred_id;

    sai_start_api(SAI_API_WRED, SAI_OBJECT_TYPE_WRED, wred_id, &wred_to_string, "wred", wred_id, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "wred 0x%0lx", wred_id);
    return sai_set_attribute(&key, key_str, wred_attribs, wred_vendor_attribs, attr);
}

/**
 * @brief Get one or more attributes of a WRED object
 *
 * @param[in] wred_id WRED Id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */
sai_status_t
lsai_wred_manager_base::get_wred_attribute(_In_ sai_object_id_t wred_id,
                                           _In_ uint32_t attr_count,
                                           _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = wred_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_WRED, SAI_OBJECT_TYPE_WRED, wred_id, &wred_to_string, wred_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "bridge 0x%0lx", wred_id);
    return sai_get_attributes(&key, key_str, wred_attribs, wred_vendor_attribs, attr_count, attr_list);
}

sai_status_t
lsai_wred_manager_base::sai_wred_attr_type_get(_In_ const sai_object_key_t* key,
                                               _Inout_ sai_attribute_value_t* value,
                                               _In_ uint32_t attr_index,
                                               _Inout_ vendor_cache_t* cache,
                                               void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // verify it exists
    std::shared_ptr<lsai_device> sdev;
    uint32_t map_id;
    lsai_wred wred;
    sai_return_on_error(check_and_get_device_and_map_id(key->key.object_id, sdev, map_id, wred));

    switch ((int64_t)arg) {
    case SAI_WRED_ATTR_GREEN_ENABLE:
        set_attr_value(SAI_WRED_ATTR_GREEN_ENABLE, *value, wred.m_enabled[lsai_wred::GREEN_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_GREEN_MIN_THRESHOLD:
        set_attr_value(SAI_WRED_ATTR_GREEN_MIN_THRESHOLD, *value, wred.m_min_drop_threshold[lsai_wred::GREEN_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_GREEN_MAX_THRESHOLD:
        set_attr_value(SAI_WRED_ATTR_GREEN_MAX_THRESHOLD, *value, wred.m_max_drop_threshold[lsai_wred::GREEN_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_GREEN_DROP_PROBABILITY:
        set_attr_value(SAI_WRED_ATTR_GREEN_DROP_PROBABILITY, *value, wred.m_drop_probability[lsai_wred::GREEN_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_YELLOW_ENABLE:
        set_attr_value(SAI_WRED_ATTR_YELLOW_ENABLE, *value, wred.m_enabled[lsai_wred::YELLOW_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD:
        set_attr_value(SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD, *value, wred.m_min_drop_threshold[lsai_wred::YELLOW_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD:
        set_attr_value(SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD, *value, wred.m_max_drop_threshold[lsai_wred::YELLOW_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY:
        set_attr_value(SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY, *value, wred.m_drop_probability[lsai_wred::YELLOW_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_RED_ENABLE:
        set_attr_value(SAI_WRED_ATTR_RED_ENABLE, *value, wred.m_enabled[lsai_wred::RED_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_RED_MIN_THRESHOLD:
        set_attr_value(SAI_WRED_ATTR_RED_MIN_THRESHOLD, *value, wred.m_min_drop_threshold[lsai_wred::RED_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_RED_MAX_THRESHOLD:
        set_attr_value(SAI_WRED_ATTR_RED_MAX_THRESHOLD, *value, wred.m_max_drop_threshold[lsai_wred::RED_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_RED_DROP_PROBABILITY:
        set_attr_value(SAI_WRED_ATTR_RED_DROP_PROBABILITY, *value, wred.m_drop_probability[lsai_wred::RED_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_WEIGHT:
        set_attr_value(SAI_WRED_ATTR_WEIGHT, *value, wred.m_weight);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_ECN_MARK_MODE:
        set_attr_value(SAI_WRED_ATTR_ECN_MARK_MODE, *value, wred.m_ecn_mode);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_ECN_GREEN_MIN_THRESHOLD:
        set_attr_value(SAI_WRED_ATTR_ECN_GREEN_MIN_THRESHOLD, *value, wred.m_min_ecn_threshold[lsai_wred::GREEN_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_ECN_GREEN_MAX_THRESHOLD:
        set_attr_value(SAI_WRED_ATTR_ECN_GREEN_MAX_THRESHOLD, *value, wred.m_max_ecn_threshold[lsai_wred::GREEN_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_ECN_GREEN_MARK_PROBABILITY:
        set_attr_value(SAI_WRED_ATTR_ECN_GREEN_MARK_PROBABILITY, *value, wred.m_ecn_probability[lsai_wred::GREEN_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_ECN_YELLOW_MIN_THRESHOLD:
        set_attr_value(SAI_WRED_ATTR_ECN_YELLOW_MIN_THRESHOLD, *value, wred.m_min_ecn_threshold[lsai_wred::YELLOW_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_ECN_YELLOW_MAX_THRESHOLD:
        set_attr_value(SAI_WRED_ATTR_ECN_YELLOW_MAX_THRESHOLD, *value, wred.m_max_ecn_threshold[lsai_wred::YELLOW_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_ECN_YELLOW_MARK_PROBABILITY:
        set_attr_value(SAI_WRED_ATTR_ECN_YELLOW_MARK_PROBABILITY, *value, wred.m_ecn_probability[lsai_wred::YELLOW_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_ECN_RED_MIN_THRESHOLD:
        set_attr_value(SAI_WRED_ATTR_ECN_RED_MIN_THRESHOLD, *value, wred.m_min_ecn_threshold[lsai_wred::RED_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_ECN_RED_MAX_THRESHOLD:
        set_attr_value(SAI_WRED_ATTR_ECN_RED_MAX_THRESHOLD, *value, wred.m_max_ecn_threshold[lsai_wred::RED_INDEX]);
        return SAI_STATUS_SUCCESS;
    case SAI_WRED_ATTR_ECN_RED_MARK_PROBABILITY:
        set_attr_value(SAI_WRED_ATTR_ECN_RED_MARK_PROBABILITY, *value, wred.m_ecn_probability[lsai_wred::RED_INDEX]);
        return SAI_STATUS_SUCCESS;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_wred_manager_base::sai_wred_attr_type_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    // verify it exists
    std::shared_ptr<lsai_device> sdev;
    uint32_t map_id;
    lsai_wred wred;
    sai_return_on_error(check_and_get_device_and_map_id(key->key.object_id, sdev, map_id, wred));

    // initializing default values for attributes
    bool enabled = true;
    uint32_t min_max_threshold = 0;
    uint32_t drop_probability = 100;
    uint32_t ecn_probability = 100;
    uint8_t weight = 0;
    sai_ecn_mark_mode_t ecn_mode = SAI_ECN_MARK_MODE_NONE;

    bool is_pacific = false;

    if (sdev->m_hw_device_type == hw_device_type_e::PACIFIC) {
        is_pacific = true;
    }

    int32_t attr_id = (uintptr_t)arg;
    switch (attr_id) {
    case SAI_WRED_ATTR_GREEN_ENABLE: {
        enabled = get_attr_value(SAI_WRED_ATTR_GREEN_ENABLE, *value);
        wred.m_enabled[lsai_wred::GREEN_INDEX] = enabled;
        // copy green to yellow for pacific
        if (is_pacific) {
            wred.m_enabled[lsai_wred::YELLOW_INDEX] = wred.m_enabled[lsai_wred::GREEN_INDEX];
        }
        sdev->m_wred_handler->wred_profile_validate(wred);
        break;
    }
    case SAI_WRED_ATTR_GREEN_MIN_THRESHOLD: {
        min_max_threshold = get_attr_value(SAI_WRED_ATTR_GREEN_MIN_THRESHOLD, *value);
        wred.m_min_drop_threshold[lsai_wred::GREEN_INDEX] = min_max_threshold;
        // copy green to yellow for pacific
        if (is_pacific) {
            wred.m_min_drop_threshold[lsai_wred::YELLOW_INDEX] = wred.m_min_drop_threshold[lsai_wred::GREEN_INDEX];
        }
        sdev->m_wred_handler->wred_profile_validate(wred);
        sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_sdk_profile, false);
        // when the drop threshold changes the ecn mark threshold would change as well when the m_ecn_ect is not set
        // and when the SAI_ECN_MARK_MODE is all/green/yellow
        if (!sdev->m_ecn_ect && wred.m_ecn_mode != SAI_ECN_MARK_MODE_NONE) {
            sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_ecn_sdk_profile, true);
        }
        break;
    }
    case SAI_WRED_ATTR_GREEN_MAX_THRESHOLD: {
        min_max_threshold = get_attr_value(SAI_WRED_ATTR_GREEN_MAX_THRESHOLD, *value);
        wred.m_max_drop_threshold[lsai_wred::GREEN_INDEX] = min_max_threshold;
        // copy green to yellow for pacific
        if (is_pacific) {
            wred.m_max_drop_threshold[lsai_wred::YELLOW_INDEX] = wred.m_max_drop_threshold[lsai_wred::GREEN_INDEX];
            sdev->m_wred_handler->wred_profile_validate(wred);
        }
        sdev->m_wred_handler->wred_profile_validate(wred);
        sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_sdk_profile, false);
        if (!sdev->m_ecn_ect && wred.m_ecn_mode != SAI_ECN_MARK_MODE_NONE) {
            sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_ecn_sdk_profile, true);
        }
        break;
    }
    case SAI_WRED_ATTR_GREEN_DROP_PROBABILITY: {
        drop_probability = get_attr_value(SAI_WRED_ATTR_GREEN_DROP_PROBABILITY, *value);
        wred.m_drop_probability[lsai_wred::GREEN_INDEX] = drop_probability;
        // copy green to yellow for pacific
        if (is_pacific) {
            wred.m_drop_probability[lsai_wred::YELLOW_INDEX] = wred.m_drop_probability[lsai_wred::GREEN_INDEX];
        }
        sdev->m_wred_handler->wred_profile_validate(wred);
        sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_sdk_profile, false);
        // when the drop probability changes the ecn mark probability would change as well when the m_ecn_ect is not set
        // and when the SAI_ECN_MARK_MODE is all/green/yellow
        if (!sdev->m_ecn_ect && wred.m_ecn_mode != SAI_ECN_MARK_MODE_NONE) {
            sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_ecn_sdk_profile, true);
        }
        break;
    }
    case SAI_WRED_ATTR_YELLOW_ENABLE: {
        enabled = get_attr_value(SAI_WRED_ATTR_YELLOW_ENABLE, *value);
        wred.m_enabled[lsai_wred::YELLOW_INDEX] = enabled;
        // copy yellow to green for pacific
        if (is_pacific) {
            wred.m_enabled[lsai_wred::GREEN_INDEX] = wred.m_enabled[lsai_wred::YELLOW_INDEX];
        }
        sdev->m_wred_handler->wred_profile_validate(wred);
        break;
    }
    case SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD: {
        min_max_threshold = get_attr_value(SAI_WRED_ATTR_YELLOW_MIN_THRESHOLD, *value);
        wred.m_min_drop_threshold[lsai_wred::YELLOW_INDEX] = min_max_threshold;
        // copy yellow to green for pacific
        if (is_pacific) {
            wred.m_min_drop_threshold[lsai_wred::GREEN_INDEX] = wred.m_min_drop_threshold[lsai_wred::YELLOW_INDEX];
        }
        sdev->m_wred_handler->wred_profile_validate(wred);
        sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_sdk_profile, false);
        // when the drop threshold changes the ecn mark threshold would change as well when the m_ecn_ect is not set
        // and and when the SAI_ECN_MARK_MODE is all/green/yellow
        if (!sdev->m_ecn_ect && wred.m_ecn_mode != SAI_ECN_MARK_MODE_NONE) {
            sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_ecn_sdk_profile, true);
        }
        break;
    }
    case SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD: {
        min_max_threshold = get_attr_value(SAI_WRED_ATTR_YELLOW_MAX_THRESHOLD, *value);
        wred.m_max_drop_threshold[lsai_wred::YELLOW_INDEX] = min_max_threshold;
        // copy yellow to green for pacific
        if (is_pacific) {
            wred.m_max_drop_threshold[lsai_wred::GREEN_INDEX] = wred.m_max_drop_threshold[lsai_wred::YELLOW_INDEX];
        }
        sdev->m_wred_handler->wred_profile_validate(wred);
        sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_sdk_profile, false);
        if (!sdev->m_ecn_ect && wred.m_ecn_mode != SAI_ECN_MARK_MODE_NONE) {
            sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_ecn_sdk_profile, true);
        }
        break;
    }
    case SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY: {
        drop_probability = get_attr_value(SAI_WRED_ATTR_YELLOW_DROP_PROBABILITY, *value);
        wred.m_drop_probability[lsai_wred::YELLOW_INDEX] = drop_probability;
        // copy yellow to green for pacific
        if (is_pacific) {
            wred.m_drop_probability[lsai_wred::GREEN_INDEX] = wred.m_drop_probability[lsai_wred::YELLOW_INDEX];
        }
        sdev->m_wred_handler->wred_profile_validate(wred);
        sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_sdk_profile, false);
        // when the drop probability changes the ecn mark probability would change as well when the m_ecn_ect is not set
        // and when the SAI_ECN_MARK_MODE is all/green/yellow
        if (!sdev->m_ecn_ect && wred.m_ecn_mode != SAI_ECN_MARK_MODE_NONE) {
            sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_ecn_sdk_profile, true);
        }
        break;
    }
    case SAI_WRED_ATTR_RED_ENABLE: {
        auto red_enabled = get_attr_value(SAI_WRED_ATTR_RED_ENABLE, *value);
        if (red_enabled == false) {
            // setting to default value
            wred.m_enabled[lsai_wred::RED_INDEX] = enabled;
            sai_log_warn(SAI_API_WRED,
                         "Warning: Setting default value %s for wred %lu. Ignore user's request ",
                         enabled,
                         key->key.object_id);
        }
        break;
    }
    case SAI_WRED_ATTR_RED_MIN_THRESHOLD: {
        auto min_threshold = get_attr_value(SAI_WRED_ATTR_RED_MIN_THRESHOLD, *value);
        if (min_threshold != 0) {
            // setting to default value
            wred.m_min_drop_threshold[lsai_wred::RED_INDEX] = min_max_threshold;
            sai_log_warn(SAI_API_WRED,
                         "Warning: Setting default value %d for wred %lu. Ignore user's request ",
                         min_max_threshold,
                         key->key.object_id);
        }
        break;
    }
    case SAI_WRED_ATTR_RED_MAX_THRESHOLD: {
        auto max_threshold = get_attr_value(SAI_WRED_ATTR_RED_MAX_THRESHOLD, *value);
        if (max_threshold != 0) {
            wred.m_max_drop_threshold[lsai_wred::RED_INDEX] = min_max_threshold;
            sai_log_warn(SAI_API_WRED,
                         "Warning: Setting default value %d for wred %lu. Ignore user's request ",
                         min_max_threshold,
                         key->key.object_id);
        }
        break;
    }
    case SAI_WRED_ATTR_RED_DROP_PROBABILITY: {
        auto red_drop_prob = get_attr_value(SAI_WRED_ATTR_RED_DROP_PROBABILITY, *value);
        if (red_drop_prob != 100) {
            // setting to default value
            wred.m_drop_probability[lsai_wred::RED_INDEX] = drop_probability;
            sai_log_warn(SAI_API_WRED,
                         "Warning: Setting default value %d for wred %lu. Ignore user's request ",
                         drop_probability,
                         key->key.object_id);
        }
        break;
    }
    case SAI_WRED_ATTR_WEIGHT: {
        weight = get_attr_value(SAI_WRED_ATTR_WEIGHT, *value);
        if (weight > 15) {
            sai_log_error(SAI_API_WRED, "Bad WRED profile. Weight must be between 0 and 15");
            return SAI_STATUS_INVALID_PARAMETER;
        }
        wred.m_weight = weight;
        sdev->m_wred_handler->hbm_profile_create_user(sdev, wred, wred.m_sdk_profile, false);
        break;
    }
    case SAI_WRED_ATTR_ECN_MARK_MODE: {
        ecn_mode = get_attr_value(SAI_WRED_ATTR_ECN_MARK_MODE, *value);
        wred.m_ecn_mode = ecn_mode;
        if (is_pacific) {
            if (wred.m_ecn_mode != SAI_ECN_MARK_MODE_ALL && wred.m_ecn_mode != SAI_ECN_MARK_MODE_NONE) {
                sai_log_error(SAI_API_WRED, "Bad WRED profile. ECN mark mode must be MARK_MODE_ALL or MARK_MODE_NONE");
                return SAI_STATUS_INVALID_PARAMETER;
            }
        }
        sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_ecn_sdk_profile, true);
        break;
    }
    case SAI_WRED_ATTR_ECN_GREEN_MIN_THRESHOLD: {
        min_max_threshold = get_attr_value(SAI_WRED_ATTR_ECN_GREEN_MIN_THRESHOLD, *value);
        wred.m_min_ecn_threshold[lsai_wred::GREEN_INDEX] = min_max_threshold;
        // copy green to yellow for pacific
        if (is_pacific) {
            wred.m_min_ecn_threshold[lsai_wred::YELLOW_INDEX] = wred.m_min_ecn_threshold[lsai_wred::GREEN_INDEX];
        }
        sdev->m_wred_handler->wred_profile_validate(wred);
        // set the ECT thresholds for mark profile only when the m_ecn_ect is enabled
        if (sdev->m_ecn_ect) {
            sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_ecn_sdk_profile, true);
        }
        break;
    }
    case SAI_WRED_ATTR_ECN_GREEN_MAX_THRESHOLD: {
        min_max_threshold = get_attr_value(SAI_WRED_ATTR_ECN_GREEN_MAX_THRESHOLD, *value);
        wred.m_max_ecn_threshold[lsai_wred::GREEN_INDEX] = min_max_threshold;
        // copy green to yellow for pacific
        if (is_pacific) {
            wred.m_max_ecn_threshold[lsai_wred::YELLOW_INDEX] = wred.m_max_ecn_threshold[lsai_wred::GREEN_INDEX];
        }
        sdev->m_wred_handler->wred_profile_validate(wred);
        // set the ECT thresholds for mark profile only when the m_ecn_ect is enabled
        if (sdev->m_ecn_ect) {
            sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_ecn_sdk_profile, true);
        }
        break;
    }
    case SAI_WRED_ATTR_ECN_GREEN_MARK_PROBABILITY: {
        ecn_probability = get_attr_value(SAI_WRED_ATTR_GREEN_DROP_PROBABILITY, *value);
        wred.m_ecn_probability[lsai_wred::GREEN_INDEX] = ecn_probability;
        // copy green to yellow for pacific
        if (is_pacific) {
            wred.m_ecn_probability[lsai_wred::YELLOW_INDEX] = wred.m_ecn_probability[lsai_wred::GREEN_INDEX];
        }
        sdev->m_wred_handler->wred_profile_validate(wred);
        // set the ECN probability for mark profile only when the m_ecn_ect is enabled
        if (sdev->m_ecn_ect) {
            sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_ecn_sdk_profile, true);
        }
        break;
    }
    case SAI_WRED_ATTR_ECN_YELLOW_MIN_THRESHOLD: {
        min_max_threshold = get_attr_value(SAI_WRED_ATTR_ECN_YELLOW_MIN_THRESHOLD, *value);
        wred.m_min_ecn_threshold[lsai_wred::YELLOW_INDEX] = min_max_threshold;
        // copy yellow to green for pacific
        if (is_pacific) {
            wred.m_min_ecn_threshold[lsai_wred::GREEN_INDEX] = wred.m_min_ecn_threshold[lsai_wred::YELLOW_INDEX];
        }
        sdev->m_wred_handler->wred_profile_validate(wred);
        // set the ECT thresholds for mark profile only when the m_ecn_ect is enabled
        if (sdev->m_ecn_ect) {
            sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_ecn_sdk_profile, true);
        }
        break;
    }
    case SAI_WRED_ATTR_ECN_YELLOW_MAX_THRESHOLD: {
        min_max_threshold = get_attr_value(SAI_WRED_ATTR_ECN_YELLOW_MAX_THRESHOLD, *value);
        wred.m_max_ecn_threshold[lsai_wred::YELLOW_INDEX] = min_max_threshold;
        // copy yellow to green for pacific
        if (is_pacific) {
            wred.m_max_ecn_threshold[lsai_wred::GREEN_INDEX] = wred.m_max_ecn_threshold[lsai_wred::YELLOW_INDEX];
        }
        sdev->m_wred_handler->wred_profile_validate(wred);
        // set the ECT thresholds for mark profile only when the m_ecn_ect is enabled
        if (sdev->m_ecn_ect) {
            sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_ecn_sdk_profile, true);
        }
        break;
    }
    case SAI_WRED_ATTR_ECN_YELLOW_MARK_PROBABILITY: {
        ecn_probability = get_attr_value(SAI_WRED_ATTR_ECN_YELLOW_MARK_PROBABILITY, *value);
        wred.m_ecn_probability[lsai_wred::YELLOW_INDEX] = ecn_probability;
        // copy yellow to green for pacific
        if (is_pacific) {
            wred.m_ecn_probability[lsai_wred::GREEN_INDEX] = wred.m_ecn_probability[lsai_wred::YELLOW_INDEX];
        }
        sdev->m_wred_handler->wred_profile_validate(wred);
        // set the ECN probability for mark profile only when the m_ecn_ect is enabled
        if (sdev->m_ecn_ect) {
            sdev->m_wred_handler->cgm_profile_create_user(sdev, wred, wred.m_ecn_sdk_profile, true);
        }
        break;
    }
    case SAI_WRED_ATTR_ECN_RED_MIN_THRESHOLD: {
        auto min_threshold = get_attr_value(SAI_WRED_ATTR_ECN_RED_MIN_THRESHOLD, *value);
        if (min_threshold != 0) {
            // setting to default value
            wred.m_min_ecn_threshold[lsai_wred::RED_INDEX] = min_max_threshold;
            sai_log_warn(SAI_API_WRED,
                         "Warning: Setting default value %d for wred %lu. Ignore user's request ",
                         min_max_threshold,
                         key->key.object_id);
        }
        break;
    }
    case SAI_WRED_ATTR_ECN_RED_MAX_THRESHOLD: {
        auto max_threshold = get_attr_value(SAI_WRED_ATTR_ECN_RED_MAX_THRESHOLD, *value);
        if (max_threshold != 0) {
            wred.m_max_ecn_threshold[lsai_wred::RED_INDEX] = min_max_threshold;
            sai_log_warn(SAI_API_WRED,
                         "Warning: Setting default value %d for wred %lu. Ignore user's request ",
                         min_max_threshold,
                         key->key.object_id);
        }
        break;
    }
    case SAI_WRED_ATTR_ECN_RED_MARK_PROBABILITY: {
        auto red_drop_prob = get_attr_value(SAI_WRED_ATTR_ECN_RED_MARK_PROBABILITY, *value);
        if (red_drop_prob != 100) {
            // setting to default value
            wred.m_ecn_probability[lsai_wred::RED_INDEX] = ecn_probability;
            sai_log_warn(SAI_API_WRED,
                         "Warning: Setting default value %d for wred %lu. Ignore user's request ",
                         drop_probability,
                         key->key.object_id);
        }
        break;
    }
    }
    sdev->m_wred_handler->m_wred_db.set(map_id, wred);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_wred_manager_base::check_and_get_device_and_map_id(const sai_object_id_t& wred_id,
                                                        std::shared_ptr<lsai_device>& out_sdev,
                                                        uint32_t& out_wred_index,
                                                        lsai_wred& out_wred)
{
    lsai_object la_obj(wred_id);
    out_sdev = la_obj.get_device();
    if (la_obj.type != SAI_OBJECT_TYPE_WRED || out_sdev == nullptr || out_sdev->m_dev == nullptr) {
        sai_log_error(SAI_API_WRED, "Bad WRED object id %lu", wred_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    out_wred_index = la_obj.index;
    la_status status = out_sdev->m_wred_handler->m_wred_db.get(out_wred_index, out_wred);
    sai_return_on_la_error(status, "Failed to find WRED object id %lu", wred_id);

    return SAI_STATUS_SUCCESS;
}

void
lsai_wred_manager_base::dump()
{
    uint32_t obj_count;
    m_wred_db.get_object_count(m_lsai_device, &obj_count);
    sai_object_key_t obj_list[obj_count];

    m_wred_db.get_object_keys(m_lsai_device, &obj_count, obj_list);
    printf("WRED_map database - %d objects:\n", obj_count);
    for (uint32_t obj_num = 0; obj_num < obj_count; obj_num++) {
        printf("  object id %lx\n", obj_list[obj_num].key.object_id);
        lsai_object la_obj(obj_list[obj_num].key.object_id);
        lsai_wred wred_obj;

        m_wred_db.get(la_obj.index, wred_obj);
        printf("  SAI config:\n");
        printf("    ref count %d weight %d, ecn %s\n",
               wred_obj.m_ref_count,
               wred_obj.m_weight,
               wred_obj.m_ecn_mode == SAI_ECN_MARK_MODE_NONE ? "disabled" : "enabled");
        printf("    enable %d %d %d\n",
               wred_obj.m_enabled[lsai_wred::GREEN_INDEX],
               wred_obj.m_enabled[lsai_wred::YELLOW_INDEX],
               wred_obj.m_enabled[lsai_wred::RED_INDEX]);
        printf("    min drop %d %d %d\n",
               wred_obj.m_min_drop_threshold[lsai_wred::GREEN_INDEX],
               wred_obj.m_min_drop_threshold[lsai_wred::YELLOW_INDEX],
               wred_obj.m_min_drop_threshold[lsai_wred::RED_INDEX]);
        printf("    max drop %d %d %d\n",
               wred_obj.m_max_drop_threshold[lsai_wred::GREEN_INDEX],
               wred_obj.m_max_drop_threshold[lsai_wred::YELLOW_INDEX],
               wred_obj.m_max_drop_threshold[lsai_wred::RED_INDEX]);
        printf("    drop probability %d %d %d\n",
               wred_obj.m_drop_probability[lsai_wred::GREEN_INDEX],
               wred_obj.m_drop_probability[lsai_wred::YELLOW_INDEX],
               wred_obj.m_drop_probability[lsai_wred::RED_INDEX]);
        printf("    min ecn %d %d %d\n",
               wred_obj.m_min_ecn_threshold[lsai_wred::GREEN_INDEX],
               wred_obj.m_min_ecn_threshold[lsai_wred::YELLOW_INDEX],
               wred_obj.m_min_ecn_threshold[lsai_wred::RED_INDEX]);
        printf("    max ecn %d %d %d\n",
               wred_obj.m_max_ecn_threshold[lsai_wred::GREEN_INDEX],
               wred_obj.m_max_ecn_threshold[lsai_wred::YELLOW_INDEX],
               wred_obj.m_max_ecn_threshold[lsai_wred::RED_INDEX]);
        printf("    ecn probability %d %d %d\n",
               wred_obj.m_ecn_probability[lsai_wred::GREEN_INDEX],
               wred_obj.m_ecn_probability[lsai_wred::YELLOW_INDEX],
               wred_obj.m_ecn_probability[lsai_wred::RED_INDEX]);
        if (wred_obj.m_sdk_profile != nullptr) {
            printf("  SDK config:\n");
            la_voq_cgm_quantization_thresholds sms_bytes_qunat;
            wred_obj.m_sdk_profile->get_sms_bytes_quantization(sms_bytes_qunat);
            printf("    SMS bytes quant: ");
            for (uint32_t i = 0; i < sms_bytes_qunat.thresholds.size(); i++) {
                printf("%d ", sms_bytes_qunat.thresholds[i]);
            }
            printf("\n");

            la_uint64_t num_packet_size_regions;
            m_lsai_device->m_dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__NUM_PACKET_SIZE_REGIONS, num_packet_size_regions);
            la_voq_sms_wred_drop_probability_selector_drop_val sms_wred_drop_prob;
            la_voq_sms_wred_mark_probability_selector_mark_val sms_wred_mark_prob;
            la_voq_sms_wred_mark_probability_selector_key mark_key;
            la_voq_sms_wred_drop_probability_selector_key drop_key;
            std::vector<double> sms_wred_green_drop_prob;
            std::vector<double> sms_wred_yellow_drop_prob;
            std::vector<double> sms_wred_green_mark_prob;
            std::vector<double> sms_wred_yellow_mark_prob;
            for (uint32_t i = 0; i <= LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP; i++) {
                drop_key.drop_probability_level = i;
                drop_key.packet_size_region = 0;
                drop_key.color = la_qos_color_e::GREEN;
                wred_obj.m_sdk_profile->get_sms_wred_drop_probability(drop_key, sms_wred_drop_prob);
                sms_wred_green_drop_prob.push_back(sms_wred_drop_prob.drop_probability);
                drop_key.color = la_qos_color_e::YELLOW;
                wred_obj.m_sdk_profile->get_sms_wred_drop_probability(drop_key, sms_wred_drop_prob);
                sms_wred_yellow_drop_prob.push_back(sms_wred_drop_prob.drop_probability);

                // total 4 mark levels
                if (i < 4) {
                    mark_key.mark_ecn_probability_level = i;
                    mark_key.packet_size_region = 0;
                    mark_key.color = la_qos_color_e::GREEN;
                    wred_obj.m_sdk_profile->get_sms_wred_mark_probability(mark_key, sms_wred_mark_prob);
                    sms_wred_green_mark_prob.push_back(sms_wred_mark_prob.mark_ecn_probability);
                    mark_key.color = la_qos_color_e::YELLOW;
                    wred_obj.m_sdk_profile->get_sms_wred_mark_probability(mark_key, sms_wred_mark_prob);
                    sms_wred_yellow_mark_prob.push_back(sms_wred_mark_prob.mark_ecn_probability);
                }

                for (uint32_t j = 0; j < num_packet_size_regions; j++) {
                    drop_key.packet_size_region = j;
                    drop_key.color = la_qos_color_e::GREEN;
                    wred_obj.m_sdk_profile->get_sms_wred_drop_probability(drop_key, sms_wred_drop_prob);
                    if (sms_wred_green_drop_prob[i] != sms_wred_drop_prob.drop_probability) {
                        printf("Config error: green drop prob for prob level %d size region 0 = %lf but drop prob for size region "
                               "%d = %lf\n",
                               i,
                               sms_wred_green_drop_prob[i],
                               j,
                               sms_wred_drop_prob.drop_probability);
                    }
                    drop_key.color = la_qos_color_e::YELLOW;
                    wred_obj.m_sdk_profile->get_sms_wred_drop_probability(drop_key, sms_wred_drop_prob);
                    if (sms_wred_yellow_drop_prob[i] != sms_wred_drop_prob.drop_probability) {
                        printf("Config error: yellow drop prob for prob level %d size region 0 = %lf but drop prob for size region "
                               "%d = %lf\n",
                               i,
                               sms_wred_yellow_drop_prob[i],
                               j,
                               sms_wred_drop_prob.drop_probability);
                    }

                    if (i < 4) {
                        mark_key.packet_size_region = j;
                        mark_key.color = la_qos_color_e::GREEN;
                        wred_obj.m_sdk_profile->get_sms_wred_mark_probability(mark_key, sms_wred_mark_prob);
                        if (sms_wred_green_mark_prob[i] != sms_wred_mark_prob.mark_ecn_probability) {
                            printf(
                                "Config error: green mark prob for prob level %d size region 0 = %lf but mark prob for size region "
                                "%d = %lf\n",
                                i,
                                sms_wred_green_mark_prob[i],
                                j,
                                sms_wred_mark_prob.mark_ecn_probability);
                        }
                        mark_key.color = la_qos_color_e::YELLOW;
                        wred_obj.m_sdk_profile->get_sms_wred_mark_probability(mark_key, sms_wred_mark_prob);
                        if (sms_wred_yellow_mark_prob[i] != sms_wred_mark_prob.mark_ecn_probability) {
                            printf("Config error: yellow mark prob for prob level %d size region 0 = %lf but mark prob for size "
                                   "region "
                                   "%d = %lf\n",
                                   i,
                                   sms_wred_yellow_mark_prob[i],
                                   j,
                                   sms_wred_mark_prob.mark_ecn_probability);
                        }
                    }
                }
            }

            printf("    Drop probabilites for wred cgm profile(green, yellow):  ");
            for (uint32_t i = 0; i < sms_wred_green_drop_prob.size(); i++) {
                printf("(%.2lf, %.2lf) ", sms_wred_green_drop_prob[i], sms_wred_yellow_drop_prob[i]);
            }
            printf("\n");
            printf("    Mark probabilites for the wred cgm profile(green, yellow):  ");
            for (uint32_t i = 0; i < sms_wred_green_mark_prob.size(); i++) {
                printf("(%.2lf, %.2lf) ", sms_wred_green_mark_prob[i], sms_wred_yellow_mark_prob[i]);
            }
            printf("\n");

            std::vector<la_cgm_sms_bytes_probability_level_t> sms_size_in_bytes_drop_green;
            std::vector<la_cgm_sms_bytes_probability_level_t> sms_size_in_bytes_drop_yellow;
            std::vector<la_cgm_sms_bytes_probability_level_t> sms_size_in_bytes_mark_green;
            std::vector<la_cgm_sms_bytes_probability_level_t> sms_size_in_bytes_mark_yellow;
            std::vector<bool> sms_size_in_bytes_evict_behavior;
            la_uint64_t num_sms_voq_bytes_regions;
            m_lsai_device->m_dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS,
                                            num_sms_voq_bytes_regions);
            la_voq_sms_size_in_bytes_color_key sms_size_bytes_color_key;
            la_voq_sms_size_in_bytes_drop_val drop_color_val;
            la_voq_sms_size_in_bytes_mark_val mark_color_val;
            la_voq_sms_size_in_bytes_evict_key evict_key;
            la_voq_sms_size_in_bytes_evict_val evict_val;

            for (uint32_t i = 0; i < num_sms_voq_bytes_regions; i++) {
                sms_size_bytes_color_key.sms_voqs_total_bytes_region = 0;
                sms_size_bytes_color_key.sms_bytes_region = i;
                sms_size_bytes_color_key.sms_age_region = 0;
                sms_size_bytes_color_key.color = la_qos_color_e::GREEN;
                wred_obj.m_sdk_profile->get_sms_size_in_bytes_drop_behavior(sms_size_bytes_color_key, drop_color_val);
                sms_size_in_bytes_drop_green.push_back(drop_color_val.drop_probability_level);

                sms_size_bytes_color_key.color = la_qos_color_e::YELLOW;
                wred_obj.m_sdk_profile->get_sms_size_in_bytes_drop_behavior(sms_size_bytes_color_key, drop_color_val);
                sms_size_in_bytes_drop_yellow.push_back(drop_color_val.drop_probability_level);

                sms_size_bytes_color_key.color = la_qos_color_e::GREEN;
                wred_obj.m_sdk_profile->get_sms_size_in_bytes_mark_behavior(sms_size_bytes_color_key, mark_color_val);
                sms_size_in_bytes_mark_green.push_back(mark_color_val.mark_ecn_probability_level);

                sms_size_bytes_color_key.color = la_qos_color_e::YELLOW;
                wred_obj.m_sdk_profile->get_sms_size_in_bytes_mark_behavior(sms_size_bytes_color_key, mark_color_val);
                sms_size_in_bytes_mark_yellow.push_back(mark_color_val.mark_ecn_probability_level);

                evict_key.sms_voqs_total_bytes_region = 0;
                evict_key.sms_bytes_region = i;
                evict_key.sms_age_region = 0;
                wred_obj.m_sdk_profile->get_sms_size_in_bytes_evict_behavior(evict_key, evict_val);
                sms_size_in_bytes_evict_behavior.push_back(evict_val.evict_to_hbm);
            }
            printf("    SMS size in bytes drop behavior for the wred cgm profile(green, yellow):  ");
            // 16 sms regions
            for (uint32_t i = 0; i < num_sms_voq_bytes_regions; i++) {
                printf("(%ld, %ld) ", sms_size_in_bytes_drop_green[i], sms_size_in_bytes_drop_yellow[i]);
            }
            printf("\n");

            printf("    SMS size in bytes mark behavior for the wred cgm profile(green, yellow):  ");
            for (uint32_t i = 0; i < num_sms_voq_bytes_regions; i++) {
                printf("(%ld, %ld) ", sms_size_in_bytes_mark_green[i], sms_size_in_bytes_mark_yellow[i]);
            }
            printf("\n");

            printf("    SMS size in bytes eviction behavior:  ");
            for (uint32_t i = 0; i < num_sms_voq_bytes_regions; i++) {
                printf("%d", static_cast<int>(sms_size_in_bytes_evict_behavior[i]));
            }
            printf("\n");

            // dump hbm config
            la_voq_cgm_quantization_thresholds hbm_bytes_quant;
            double out_ema_coeff;
            wred_obj.m_sdk_profile->get_averaging_configuration(out_ema_coeff, hbm_bytes_quant);
            printf("    HBM bytes quant for the wred cgm profile: ");
            for (uint32_t i = 0; i < hbm_bytes_quant.thresholds.size(); i++) {
                printf("%d ", hbm_bytes_quant.thresholds[i]);
            }
            printf("\n");

            std::vector<double> hbm_wred_green_drop_prob;
            std::vector<double> hbm_wred_yellow_drop_prob;
            la_cgm_wred_drop_val green_val;
            la_cgm_wred_drop_val yellow_val;

            for (uint32_t packet_size_region = 0; packet_size_region < num_packet_size_regions - 1; packet_size_region++) {
                la_cgm_wred_key green_key{0, packet_size_region, la_qos_color_e::GREEN};
                wred_obj.m_sdk_profile->get_hbm_wred_drop_configuration(green_key, green_val);
                hbm_wred_green_drop_prob.push_back(green_val.drop_probability);

                la_cgm_wred_key yellow_key{0, packet_size_region, la_qos_color_e::YELLOW};
                wred_obj.m_sdk_profile->get_hbm_wred_drop_configuration(yellow_key, yellow_val);
                hbm_wred_yellow_drop_prob.push_back(yellow_val.drop_probability);
            }
            printf("    HBM packet size regions drop behavior for the wred cgm profile(green, yellow):  ");
            for (uint32_t i = 0; i < hbm_wred_green_drop_prob.size(); i++) {
                printf("(%lf, %lf) ", hbm_wred_green_drop_prob[i], hbm_wred_yellow_drop_prob[i]);
            }
            printf("\n");

            la_uint64_t block_quant_region;
            m_lsai_device->m_dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_REGIONS,
                                            block_quant_region);

            std::vector<double> hbm_wred_drop_config_green_prob;
            std::vector<double> hbm_wred_drop_config_yellow_prob;

            for (uint32_t i = 0; i < block_quant_region; i++) {
                la_cgm_wred_key green_key{i, 0, la_qos_color_e::GREEN};
                wred_obj.m_sdk_profile->get_hbm_wred_drop_configuration(green_key, green_val);
                hbm_wred_drop_config_green_prob.push_back(green_val.drop_probability);

                la_cgm_wred_key yellow_key{i, 0, la_qos_color_e::YELLOW};
                wred_obj.m_sdk_profile->get_hbm_wred_drop_configuration(yellow_key, yellow_val);
                hbm_wred_drop_config_yellow_prob.push_back(yellow_val.drop_probability);
            }
            printf("    HBM wred block quantization bytes drop behavior for the wred cgm profile(green, yellow):  ");
            for (uint32_t i = 0; i < hbm_wred_drop_config_green_prob.size(); i++) {
                printf("(%lf, %lf) ", hbm_wred_drop_config_green_prob[i], hbm_wred_drop_config_yellow_prob[i]);
            }
            printf("\n");

        } else {
            printf("  No SDK profile attached:\n");
        }

        if (wred_obj.m_ecn_sdk_profile != nullptr) {
            // ecn cgm profile config
            printf("  SDK ecn Q config:\n");
            la_voq_cgm_quantization_thresholds sms_bytes_qunat;
            wred_obj.m_ecn_sdk_profile->get_sms_bytes_quantization(sms_bytes_qunat);
            printf("    SMS bytes quant: ");
            for (uint32_t i = 0; i < sms_bytes_qunat.thresholds.size(); i++) {
                printf("%d ", sms_bytes_qunat.thresholds[i]);
            }
            printf("\n");

            la_uint64_t num_packet_size_regions;
            m_lsai_device->m_dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__NUM_PACKET_SIZE_REGIONS, num_packet_size_regions);
            la_voq_sms_wred_drop_probability_selector_drop_val sms_wred_drop_prob;
            la_voq_sms_wred_mark_probability_selector_mark_val sms_wred_mark_prob;
            la_voq_sms_wred_mark_probability_selector_key mark_key;
            la_voq_sms_wred_drop_probability_selector_key drop_key;
            std::vector<double> sms_wred_green_drop_prob;
            std::vector<double> sms_wred_yellow_drop_prob;
            std::vector<double> sms_wred_green_mark_prob;
            std::vector<double> sms_wred_yellow_mark_prob;
            for (uint32_t i = 0; i <= LA_CGM_SMS_BYTES_DROP_PROBABILITY_LEVEL_DROP; i++) {
                drop_key.drop_probability_level = i;
                drop_key.packet_size_region = 0;
                drop_key.color = la_qos_color_e::GREEN;
                wred_obj.m_ecn_sdk_profile->get_sms_wred_drop_probability(drop_key, sms_wred_drop_prob);
                sms_wred_green_drop_prob.push_back(sms_wred_drop_prob.drop_probability);
                drop_key.color = la_qos_color_e::YELLOW;
                wred_obj.m_ecn_sdk_profile->get_sms_wred_drop_probability(drop_key, sms_wred_drop_prob);
                sms_wred_yellow_drop_prob.push_back(sms_wred_drop_prob.drop_probability);

                // total 4 mark levels
                if (i < 4) {
                    mark_key.mark_ecn_probability_level = i;
                    mark_key.packet_size_region = 0;
                    mark_key.color = la_qos_color_e::GREEN;
                    wred_obj.m_ecn_sdk_profile->get_sms_wred_mark_probability(mark_key, sms_wred_mark_prob);
                    sms_wred_green_mark_prob.push_back(sms_wred_mark_prob.mark_ecn_probability);
                    mark_key.color = la_qos_color_e::YELLOW;
                    wred_obj.m_ecn_sdk_profile->get_sms_wred_mark_probability(mark_key, sms_wred_mark_prob);
                    sms_wred_yellow_mark_prob.push_back(sms_wred_mark_prob.mark_ecn_probability);
                }

                for (uint32_t j = 0; j < num_packet_size_regions; j++) {
                    drop_key.packet_size_region = j;
                    drop_key.color = la_qos_color_e::GREEN;
                    wred_obj.m_ecn_sdk_profile->get_sms_wred_drop_probability(drop_key, sms_wred_drop_prob);
                    if (sms_wred_green_drop_prob[i] != sms_wred_drop_prob.drop_probability) {
                        printf("Config error: green drop prob for prob level %d size region 0 = %lf but drop prob for size region "
                               "%d = %lf\n",
                               i,
                               sms_wred_green_drop_prob[i],
                               j,
                               sms_wred_drop_prob.drop_probability);
                    }
                    drop_key.color = la_qos_color_e::YELLOW;
                    wred_obj.m_ecn_sdk_profile->get_sms_wred_drop_probability(drop_key, sms_wred_drop_prob);
                    if (sms_wred_yellow_drop_prob[i] != sms_wred_drop_prob.drop_probability) {
                        printf("Config error: yellow drop prob for prob level %d size region 0 = %lf but drop prob for size region "
                               "%d = %lf\n",
                               i,
                               sms_wred_yellow_drop_prob[i],
                               j,
                               sms_wred_drop_prob.drop_probability);
                    }

                    if (i < 4) {
                        mark_key.packet_size_region = j;
                        mark_key.color = la_qos_color_e::GREEN;
                        wred_obj.m_ecn_sdk_profile->get_sms_wred_mark_probability(mark_key, sms_wred_mark_prob);
                        if (sms_wred_green_mark_prob[i] != sms_wred_mark_prob.mark_ecn_probability) {
                            printf(
                                "Config error: green mark prob for prob level %d size region 0 = %lf but mark prob for size region "
                                "%d = %lf\n",
                                i,
                                sms_wred_green_mark_prob[i],
                                j,
                                sms_wred_mark_prob.mark_ecn_probability);
                        }
                        mark_key.color = la_qos_color_e::YELLOW;
                        wred_obj.m_ecn_sdk_profile->get_sms_wred_mark_probability(mark_key, sms_wred_mark_prob);
                        if (sms_wred_yellow_mark_prob[i] != sms_wred_mark_prob.mark_ecn_probability) {
                            printf("Config error: yellow mark prob for prob level %d size region 0 = %lf but mark prob for size "
                                   "region "
                                   "%d = %lf\n",
                                   i,
                                   sms_wred_yellow_mark_prob[i],
                                   j,
                                   sms_wred_mark_prob.mark_ecn_probability);
                        }
                    }
                }
            }

            printf("    Drop probabilites for the ecn/mark cgm profile(green, yellow):  ");
            for (uint32_t i = 0; i < sms_wred_green_drop_prob.size(); i++) {
                printf("(%.2lf, %.2lf) ", sms_wred_green_drop_prob[i], sms_wred_yellow_drop_prob[i]);
            }
            printf("\n");
            printf("    Mark probabilites for the ecn/mark cgm profile(green, yellow):  ");
            for (uint32_t i = 0; i < sms_wred_green_mark_prob.size(); i++) {
                printf("(%.2lf, %.2lf) ", sms_wred_green_mark_prob[i], sms_wred_yellow_mark_prob[i]);
            }
            printf("\n");

            std::vector<la_cgm_sms_bytes_probability_level_t> sms_size_in_bytes_drop_green;
            std::vector<la_cgm_sms_bytes_probability_level_t> sms_size_in_bytes_drop_yellow;
            std::vector<la_cgm_sms_bytes_probability_level_t> sms_size_in_bytes_mark_green;
            std::vector<la_cgm_sms_bytes_probability_level_t> sms_size_in_bytes_mark_yellow;
            std::vector<bool> sms_size_in_bytes_evict_behavior;
            la_uint64_t num_sms_voq_bytes_regions;
            m_lsai_device->m_dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__SMS_NUM_BYTES_QUANTIZATION_REGIONS,
                                            num_sms_voq_bytes_regions);
            la_voq_sms_size_in_bytes_color_key sms_size_bytes_color_key;
            la_voq_sms_size_in_bytes_drop_val drop_color_val;
            la_voq_sms_size_in_bytes_mark_val mark_color_val;
            la_voq_sms_size_in_bytes_evict_key evict_key;
            la_voq_sms_size_in_bytes_evict_val evict_val;

            for (uint32_t i = 0; i < num_sms_voq_bytes_regions; i++) {
                sms_size_bytes_color_key.sms_voqs_total_bytes_region = 0;
                sms_size_bytes_color_key.sms_bytes_region = i;
                sms_size_bytes_color_key.sms_age_region = 0;
                sms_size_bytes_color_key.color = la_qos_color_e::GREEN;
                wred_obj.m_ecn_sdk_profile->get_sms_size_in_bytes_drop_behavior(sms_size_bytes_color_key, drop_color_val);
                sms_size_in_bytes_drop_green.push_back(drop_color_val.drop_probability_level);

                sms_size_bytes_color_key.color = la_qos_color_e::YELLOW;
                wred_obj.m_ecn_sdk_profile->get_sms_size_in_bytes_drop_behavior(sms_size_bytes_color_key, drop_color_val);
                sms_size_in_bytes_drop_yellow.push_back(drop_color_val.drop_probability_level);

                sms_size_bytes_color_key.color = la_qos_color_e::GREEN;
                wred_obj.m_ecn_sdk_profile->get_sms_size_in_bytes_mark_behavior(sms_size_bytes_color_key, mark_color_val);
                sms_size_in_bytes_mark_green.push_back(mark_color_val.mark_ecn_probability_level);

                sms_size_bytes_color_key.color = la_qos_color_e::YELLOW;
                wred_obj.m_ecn_sdk_profile->get_sms_size_in_bytes_mark_behavior(sms_size_bytes_color_key, mark_color_val);
                sms_size_in_bytes_mark_yellow.push_back(mark_color_val.mark_ecn_probability_level);

                evict_key.sms_voqs_total_bytes_region = 0;
                evict_key.sms_bytes_region = i;
                evict_key.sms_age_region = 0;
                wred_obj.m_ecn_sdk_profile->get_sms_size_in_bytes_evict_behavior(evict_key, evict_val);
                sms_size_in_bytes_evict_behavior.push_back(evict_val.evict_to_hbm);
            }
            printf("    SMS size in bytes drop behavior for the ecn/mark behavior(green, yellow):  ");
            // 16 sms regions
            for (uint32_t i = 0; i < num_sms_voq_bytes_regions; i++) {
                printf("(%ld, %ld) ", sms_size_in_bytes_drop_green[i], sms_size_in_bytes_drop_yellow[i]);
            }
            printf("\n");

            printf("    SMS size in bytes mark behavior for the ecn/mark cgm profile(green, yellow):  ");
            for (uint32_t i = 0; i < num_sms_voq_bytes_regions; i++) {
                printf("(%ld, %ld) ", sms_size_in_bytes_mark_green[i], sms_size_in_bytes_mark_yellow[i]);
            }
            printf("\n");

            printf("    SMS size in bytes eviction behavior:  ");
            for (uint32_t i = 0; i < num_sms_voq_bytes_regions; i++) {
                printf("%d", static_cast<int>(sms_size_in_bytes_evict_behavior[i]));
            }
            printf("\n");

            // dump hbm config
            la_voq_cgm_quantization_thresholds hbm_bytes_quant;
            double out_ema_coeff;
            wred_obj.m_ecn_sdk_profile->get_averaging_configuration(out_ema_coeff, hbm_bytes_quant);
            printf("    HBM bytes quant for the ecn/mark cgm profile: ");
            for (uint32_t i = 0; i < hbm_bytes_quant.thresholds.size(); i++) {
                printf("%d ", hbm_bytes_quant.thresholds[i]);
            }
            printf("\n");

            std::vector<double> hbm_wred_green_mark_prob;
            std::vector<double> hbm_wred_yellow_mark_prob;
            la_cgm_wred_mark_ecn_val green_val;
            la_cgm_wred_mark_ecn_val yellow_val;

            for (uint32_t packet_size_region = 0; packet_size_region < num_packet_size_regions - 1; packet_size_region++) {
                la_cgm_wred_key green_key{0, packet_size_region, la_qos_color_e::GREEN};
                wred_obj.m_ecn_sdk_profile->get_hbm_wred_mark_ecn_configuration(green_key, green_val);
                hbm_wred_green_mark_prob.push_back(green_val.mark_ecn_probability);

                la_cgm_wred_key yellow_key{0, packet_size_region, la_qos_color_e::YELLOW};
                wred_obj.m_ecn_sdk_profile->get_hbm_wred_mark_ecn_configuration(yellow_key, yellow_val);
                hbm_wred_yellow_mark_prob.push_back(yellow_val.mark_ecn_probability);
            }
            printf("    HBM packet size regions mark behavior the ecn/mark cgm profile(green, yellow):  ");
            for (uint32_t i = 0; i < hbm_wred_green_mark_prob.size(); i++) {
                printf("(%lf, %lf) ", hbm_wred_green_mark_prob[i], hbm_wred_yellow_mark_prob[i]);
            }
            printf("\n");

            la_uint64_t block_quant_region;
            m_lsai_device->m_dev->get_limit(limit_type_e::VOQ_CGM_PROFILE__WRED_NUM_BLOCKS_QUANTIZATION_REGIONS,
                                            block_quant_region);

            std::vector<double> hbm_wred_mark_config_green_prob;
            std::vector<double> hbm_wred_mark_config_yellow_prob;

            for (uint32_t i = 0; i < block_quant_region; i++) {
                la_cgm_wred_key green_key{i, 0, la_qos_color_e::GREEN};
                wred_obj.m_ecn_sdk_profile->get_hbm_wred_mark_ecn_configuration(green_key, green_val);
                hbm_wred_mark_config_green_prob.push_back(green_val.mark_ecn_probability);

                la_cgm_wred_key yellow_key{i, 0, la_qos_color_e::YELLOW};
                wred_obj.m_ecn_sdk_profile->get_hbm_wred_mark_ecn_configuration(yellow_key, yellow_val);
                hbm_wred_mark_config_yellow_prob.push_back(yellow_val.mark_ecn_probability);
            }
            printf("    HBM wred block quantization bytes mark behavior the ecn/mark cgm profile(green, yellow):  ");
            for (uint32_t i = 0; i < hbm_wred_mark_config_green_prob.size(); i++) {
                printf("(%lf, %lf) ", hbm_wred_mark_config_green_prob[i], hbm_wred_mark_config_yellow_prob[i]);
            }
            printf("\n");

        } else {
            printf("  No SDK profile attached:\n");
        }
    }
}

/**
 * @brief WRED methods table retrieved with sai_api_query()
 */
const sai_wred_api_t wred_api = {lsai_wred_manager_base::create_wred,
                                 lsai_wred_manager_base::remove_wred,
                                 lsai_wred_manager_base::set_wred_attribute,
                                 lsai_wred_manager_base::get_wred_attribute};
}
}
