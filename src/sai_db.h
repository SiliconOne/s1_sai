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

#ifndef __SAI_DB_H__
#define __SAI_DB_H__

#ifdef ENABLE_SERIALIZATION
#include <cereal/types/unordered_map.hpp>
#endif
#include <unordered_map>
#include "la_sai_object.h"
#include "sai_warm_boot.h"

namespace silicon_one
{
namespace sai
{

class laobj_db_base
{
    void test();

public:
    laobj_db_base()
    {
    }
    laobj_db_base(sai_object_type_t t, size_t max) : m_max(max), m_type(t), m_ids(0, m_max)
    {
    }

    virtual ~laobj_db_base()
    {
    }

    virtual sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const = 0;
    virtual sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                         uint32_t* object_count,
                                         sai_object_key_t* object_list) const = 0;

protected:
    uint32_t get_switch_id(std::shared_ptr<lsai_device> sdev) const;

protected:
    size_t m_max;
    sai_object_type_t m_type;
    ranged_index_generator m_ids;
};

//
// obj_db template is the general data structure maps between
// sai index to la objets
//
template <typename T>
class obj_db : public laobj_db_base
{

public:
    T test();
    obj_db(sai_object_type_t t, size_t max, uint32_t shift = 0, uint32_t offset = 0)
        : laobj_db_base(t, max), m_shift(shift), m_offset(offset)
    {
    }

    ~obj_db()
    {
    }

    obj_db() = default;

#ifdef ENABLE_SERIALIZATION
    template <class Archive>
    void save(Archive& ar) const
    {
        ar(::cereal::make_nvp("max", m_max));
        ar(::cereal::make_nvp("type", m_type));
        ar(::cereal::make_nvp("ids", m_ids));
        ar(::cereal::make_nvp("shift", m_shift));
        ar(::cereal::make_nvp("offset", m_offset));
        ar(::cereal::make_nvp("ignore_in_get_all_objs", m_ignore_in_get_all_objs));
        ar(::cereal::make_nvp("map", m_map));
    }

    template <class Archive>
    void load(Archive& ar)
    {
        ar(::cereal::make_nvp("max", m_max));
        ar(::cereal::make_nvp("type", m_type));
        ar(::cereal::make_nvp("ids", m_ids));
        ar(::cereal::make_nvp("shift", m_shift));
        ar(::cereal::make_nvp("offset", m_offset));
        ar(::cereal::make_nvp("ignore_in_get_all_objs", m_ignore_in_get_all_objs));
        ar(::cereal::make_nvp("map", m_map));
    }
#endif

    la_status get(sai_object_id_t obj, T& X, lsai_object& la_obj) const
    {
        la_obj = lsai_object(obj);
        if (la_obj.type != m_type) {
            return LA_STATUS_EINVAL;
        }

        return get(la_obj.index, X);
    }

    la_status get(uint32_t index, T& X) const
    {
        if (index < m_offset) {
            return LA_STATUS_EINVAL;
        }

        auto pos = m_map.find(index);
        if (pos == m_map.end()) {
            return LA_STATUS_ENOTFOUND;
        } else {
            X = pos->second;
        }

        return LA_STATUS_SUCCESS;
    }

    la_status get_ptr(uint32_t idx, T*& X)
    {
        if (idx < m_offset) {
            return LA_STATUS_EINVAL;
        }

        auto pos = m_map.find(idx);
        if (pos == m_map.end()) {
            X = nullptr;
            return LA_STATUS_ENOTFOUND;
        }

        X = &pos->second;
        return LA_STATUS_SUCCESS;
    }

    T* get_ptr(uint32_t idx)
    {
        T* ptr = nullptr;
        get_ptr(idx, ptr);
        return ptr;
    }

    la_status get_by_id(uint32_t id, T& X) const
    {
        uint32_t index = (id << m_shift) + m_offset;
        return get(index, X);
    }

    uint32_t get_id(sai_object_id_t obj_id)
    {
        lsai_object la_obj(obj_id);
        return (la_obj.index - m_offset) >> m_shift;
    }

    // reserve in_idx is index to m_ids, out_idx is after transformation
    la_status allocate_id(uint32_t in_id, uint32_t& out_index)
    {
        out_index = UINT32_MAX;
        // INVALID_INDEX is uint64_t, so can't compare it against uint32_t
        if (!m_ids.is_available(in_id)) {
            out_index = (in_id << m_shift) + m_offset;
            return LA_STATUS_EBUSY;
        }

        uint64_t id;
        m_ids.allocate(in_id, id);
        if (id == ranged_index_generator::INVALID_INDEX) {
            return LA_STATUS_ERESOURCE;
        }
        out_index = (id << m_shift) + m_offset;
        return LA_STATUS_SUCCESS;
    }

    la_status allocate_id(uint32_t& out_index)
    {
        out_index = UINT32_MAX;
        // INVALID_INDEX is uint64_t, so can't compare it against uint32_t
        auto id = m_ids.allocate();
        if (id == ranged_index_generator::INVALID_INDEX) {
            return LA_STATUS_ERESOURCE;
        }
        out_index = (id << m_shift) + m_offset;
        return LA_STATUS_SUCCESS;
    }

    la_status set(uint32_t index, const T& X)
    {
        if (index < m_offset) {
            return LA_STATUS_EINVAL;
        }
        m_map[index] = X;
        return LA_STATUS_SUCCESS;
    }

    la_status set(sai_object_id_t& out_obj_id, const T& X, lsai_object& la_obj)
    {
        if (la_obj.index < m_offset) {
            return LA_STATUS_EINVAL;
        }
        m_map[la_obj.index] = X;
        la_obj.type = m_type;
        out_obj_id = la_obj.object_id();
        return LA_STATUS_SUCCESS;
    }

    la_status insert(const T& X, uint32_t& out_index)
    {
        la_status status = allocate_id(out_index);
        if (status != LA_STATUS_SUCCESS) {
            return status;
        }

        m_map[out_index] = X;

        return LA_STATUS_SUCCESS;
    }

    la_status remove(uint32_t index)
    {
        T X;

        la_status status = get(index, X);
        if (status != LA_STATUS_SUCCESS) {
            return status;
        }

        auto id = (index - m_offset) >> m_shift;
        m_ids.release(id);
        m_map.erase(index);
        return LA_STATUS_SUCCESS;
    }

    la_status remove(sai_object_id_t obj_id)
    {
        lsai_object la_obj(obj_id);
        return remove(la_obj.index);
    }

    void erase_id(uint32_t index)
    {
        m_map.erase(index);
    }

    void release_id(uint32_t index)
    {
        if (index < m_offset) {
            return;
        }
        auto id = (index - m_offset) >> m_shift;
        m_ids.release(id);
    }

    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override
    {
        *count = m_map.size() - m_ignore_in_get_all_objs;
        return SAI_STATUS_SUCCESS;
    }

    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override
    {
        uint32_t sw_id = get_switch_id(sdev);
        uint32_t index = 0;

        uint32_t requested_object_count = *object_count;
        *object_count = m_map.size() - m_ignore_in_get_all_objs;

        if (requested_object_count < *object_count) {
            return SAI_STATUS_BUFFER_OVERFLOW;
        }

        auto iter = m_map.begin();

        while (iter != m_map.end()) {
            lsai_object la_obj(m_type, sw_id, iter->first);
            iter++;
            if (la_obj.index < m_ignore_in_get_all_objs) {
                continue;
            }
            object_list[index].key.object_id = la_obj.object_id();
            index++;
        }

        return SAI_STATUS_SUCCESS;
    }

    std::unordered_map<uint32_t, T>& map()
    {
        return m_map;
    }

    void clear()
    {
        m_map.clear();
    }

    bool is_empty()
    {
        return m_map.size() == 0;
    }

    size_t get_free_space() const
    {
        return m_max - m_map.size();
    }

    void set_ignore_in_get_num(uint32_t num_to_ignore)
    {
        m_ignore_in_get_all_objs = num_to_ignore;
    }

private:
    uint32_t m_shift = 0;
    uint32_t m_offset = 0;
    // We can have internal objects that are hidden when doing get_object_count/keys
    // This number indicates how many objects to ignore
    uint32_t m_ignore_in_get_all_objs = 0;
    std::unordered_map<uint32_t, T> m_map;
};

class laobj_db_bridge_port : public laobj_db_base
{
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};

class laobj_db_hash : public laobj_db_base
{
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};

class laobj_db_hostif_trap : public laobj_db_base
{
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};

class laobj_db_ingress_priority_group : public laobj_db_base
{
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};

class laobj_db_lag_member : public laobj_db_base
{
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};

class laobj_db_port : public laobj_db_base
{
public:
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};

class laobj_db_queue : public laobj_db_base
{
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};

class laobj_db_scheduler_group : public laobj_db_base
{
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};

class laobj_db_switch : public laobj_db_base
{
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};

class laobj_db_vlan_member : public laobj_db_base
{
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};

class laobj_db_tunnel_map_entry : public laobj_db_base
{
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};

class laobj_db_fdb_entry : public laobj_db_base
{
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};

class laobj_db_virtual_router : public laobj_db_base
{
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};

class laobj_db_route_entry : public laobj_db_base
{
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};

class laobj_db_neighbor_entry : public laobj_db_base
{
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};

class laobj_db_mirror : public laobj_db_base
{
    sai_status_t get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const override;
    sai_status_t get_object_keys(std::shared_ptr<lsai_device> sdev,
                                 uint32_t* object_count,
                                 sai_object_key_t* object_list) const override;
};
}
}
#endif // __SAI_DB_H__
