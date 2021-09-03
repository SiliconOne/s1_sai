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

#ifdef ENABLE_SERIALIZATION
#include "common/cereal_utils.h"
#include <cereal/archives/binary.hpp>
#include <cereal/archives/json.hpp>
#include <cereal/archives/xml.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/vector.hpp>
#endif

// the following include is added for creating a in/out file stream
#include <fstream>
#include <memory>

#include "sai_device.h"
#include "sai_qos.h"

namespace silicon_one
{
namespace sai
{
bool
lsai_device_serialize_save(std::shared_ptr<silicon_one::sai::lsai_device> lsai_sptr, const char* serialization_file)
{
#ifdef ENABLE_SERIALIZATION
    std::ofstream my_file(serialization_file);
    CEREAL_UTILS_CREATE_OUTPUT_ARCHIVE(archive, my_file);
    archive(lsai_sptr);
#endif
    return true;
}

bool
lsai_device_serialize_load(std::shared_ptr<silicon_one::sai::lsai_device>& inout, const char* serialization_file)
{
#ifdef ENABLE_SERIALIZATION
    std::ifstream my_file(serialization_file);
    cereal_input_archive_class archive(my_file);
    archive(inout);
#endif
    return true;
}

la_status
warm_boot_apply_upgrade_patches(std::shared_ptr<lsai_device> sdev, uint32_t base_wb_revision)
{
    sai_log_info(SAI_API_SWITCH, "Applying warm boot patches from revision %d to current revision", base_wb_revision);

    if (base_wb_revision < 2) {
        // apply patches for fixes/features introduces in wb_revision=2
        return LA_STATUS_SUCCESS;
    }

    if (base_wb_revision < 3) {
        // apply patches for fixes/features introduces in wb_revision=3
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_SUCCESS;
}
}
}

#ifdef ENABLE_SERIALIZATION
namespace cereal
{
template <class Archive>
void save(Archive& ar, const sai_qos_map_t& m);
template <class Archive>
void load(Archive& ar, sai_qos_map_t& m);

template <class Archive>
void
save(Archive& ar, const silicon_one::sai::lasai_qos_map_list_t& m)
{
    ar(::cereal::make_nvp("count", m.count));
    for (uint i = 0; i < m.count; i++) {
        ar(m.shared_list.get()[i]);
    }
}
template void save<cereal_output_archive_class>(cereal_output_archive_class& ar, const silicon_one::sai::lasai_qos_map_list_t& m);

template <class Archive>
void
load(Archive& ar, silicon_one::sai::lasai_qos_map_list_t& m)
{
    ar(::cereal::make_nvp("count", m.count));
    if (m.count != 0) {
        m.shared_list = std::shared_ptr<sai_qos_map_t>(new sai_qos_map_t[m.count], std::default_delete<sai_qos_map_t[]>());
        for (uint i = 0; i < m.count; i++) {
            ar(m.shared_list.get()[i]);
        }
        m.list = m.shared_list.get();
    } else {
        m.list = nullptr;
    }
}
template void load<cereal_input_archive_class>(cereal_input_archive_class& ar, silicon_one::sai::lasai_qos_map_list_t& m);
}
#endif
