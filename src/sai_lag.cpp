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

// -----------------------------------------
// Some portions are also:
//
// Copyright (C) 2014 Mellanox Technologies, Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License); You may
// Obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
//
// -----------------------------------------
//

#include "sai_lag.h"

#include <algorithm>
#include <vector>

#include "api/system/la_spa_port.h"
#include "api/system/la_system_port.h"
#include "common/transaction.h"
#include "sai_device.h"
#include "sai_logger.h"
#include "sai_port.h"

namespace silicon_one
{
namespace sai
{
static void la_update_lag_flood_sys(std::shared_ptr<lsai_device> sdev, lag_entry* lag_entry);

sai_status_t
lag_port_set_mtu(lag_entry* lentry_ptr, la_uint_t mtu_value)
{
    la_status status;
    sai_status_t sai_status;

    for (auto iter : lentry_ptr->members) {
        sai_status = lsai_set_mac_port_mtu(iter.first, mtu_value);
        if ((sai_status != SAI_STATUS_ITEM_NOT_FOUND) && (sai_status != SAI_STATUS_SUCCESS)) {
            // if lsai_set_mac_port_mtu returns a status other than SAI_STATUS_SUCCESS or SAI_STATUS_ITEM_NOT_FOUND
            // this is an error
            return sai_status;
        }
    }

    // update LAG ether port MTU
    if (lentry_ptr->service.eth_port != nullptr) {
        status = lentry_ptr->service.eth_port->set_mtu(mtu_value);
        sai_return_on_la_error(status, "Failed to set MTU on eth_port (%p). mtu(%d).", lentry_ptr->service.eth_port, mtu_value);
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t lag_mem_attrib_get(_In_ const sai_object_key_t* key,
                                       _Inout_ sai_attribute_value_t* value,
                                       _In_ uint32_t attr_index,
                                       _Inout_ vendor_cache_t* cache,
                                       void* arg);

static sai_status_t lag_mem_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

// clang-format off
extern const sai_attribute_entry_t lag_member_attribs[] = {
  { SAI_LAG_MEMBER_ATTR_LAG_ID, true, true, false, true, "LAG ID", SAI_ATTR_VAL_TYPE_OID},
  { SAI_LAG_MEMBER_ATTR_PORT_ID, true, true, false, true, "LAG Member Port ID", SAI_ATTR_VAL_TYPE_OID},
  { SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE, false, true, true, true, "LAG Member Egress Disable", SAI_ATTR_VAL_TYPE_BOOL},
  { SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE, false, true, true, true, "LAG Member Ingress Disable", SAI_ATTR_VAL_TYPE_BOOL},
  { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};

static const sai_vendor_attribute_entry_t lag_member_vendor_attribs[] = {
  { SAI_LAG_MEMBER_ATTR_LAG_ID,
    { true, false, false, true },  //is_implemented -
                                   // {mandatory_on_create, valid_for_create,
                                   //  valid_for_set, valid_for_get}
    { true,false, false, true },  //is_supported
    lag_mem_attrib_get, (void*)SAI_LAG_MEMBER_ATTR_LAG_ID,
    nullptr, nullptr},
  { SAI_LAG_MEMBER_ATTR_PORT_ID,
    { true, false, false, true },
    { true, false, false, true },
    lag_mem_attrib_get, (void*)SAI_LAG_MEMBER_ATTR_PORT_ID,
    nullptr, nullptr},
  { SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE,
    { true, false, true, true },
    { true, false, true, true },
    lag_mem_attrib_get, (void*)SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE,
    lag_mem_attrib_set, (void*)SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE},
  { SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE,
    { true, false, true, true },
    { true, false, true, true },
    lag_mem_attrib_get, (void*)SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE,
    lag_mem_attrib_set, (void*)SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE}
};
// clang-format on

sai_status_t
laobj_db_lag_member::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    *count = 0;

    uint32_t lags_size;
    sai_status_t status = sdev->m_lags.get_object_count(sdev, &lags_size);
    sai_return_on_error(status);

    if (lags_size == 0) {
        return SAI_STATUS_SUCCESS;
    }

    sai_object_key_t lags_obj_ids[lags_size];
    status = sdev->m_lags.get_object_keys(sdev, &lags_size, lags_obj_ids);
    sai_return_on_error(status);

    for (uint32_t lag_index = 0; lag_index < lags_size; lag_index++) {
        lag_entry* lag_entry = nullptr;
        sdev->m_lags.get_ptr(lags_obj_ids[lag_index].key.object_id, lag_entry);
        if (lag_entry == nullptr) {
            continue;
        }
        *count += lag_entry->members.size();
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_lag_member::get_object_keys(std::shared_ptr<lsai_device> sdev, uint32_t* object_count, sai_object_key_t* object_list) const
{
    uint32_t index = 0;
    uint32_t requested_object_count = *object_count;

    uint32_t lags_size;
    sai_status_t status = sdev->m_lags.get_object_count(sdev, &lags_size);
    sai_return_on_error(status);

    if (lags_size == 0) {
        return SAI_STATUS_SUCCESS;
    }

    sai_object_key_t lags_obj_ids[lags_size];
    status = sdev->m_lags.get_object_keys(sdev, &lags_size, lags_obj_ids);
    sai_return_on_error(status);

    *object_count = lags_size;

    if (requested_object_count < *object_count) {
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    for (uint32_t lag_index = 0; lag_index < lags_size; lag_index++) {
        lag_entry* lag_entry = nullptr;
        lsai_object la_lag_id_obj(lags_obj_ids[lag_index].key.object_id);
        sdev->m_lags.get_ptr(la_lag_id_obj.index, lag_entry);
        if (lag_entry == nullptr) {
            continue;
        }

        for (auto member : lag_entry->members) {
            uint32_t port_index = member.second;
            lsai_object lag_member_obj_id(SAI_OBJECT_TYPE_LAG_MEMBER, sdev->m_switch_id, port_index);
            lag_member_obj_id.detail.set(lsai_detail_type_e::LAG_MEMBER, lsai_detail_field_e::LAG, la_lag_id_obj.index);
            object_list[index].key.object_id = lag_member_obj_id.object_id();
            index++;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static std::string
lag_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_lag_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static std::string
lag_mem_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_lag_member_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
lag_acl_get(_In_ const sai_object_key_t* key,
            _Inout_ sai_attribute_value_t* value,
            _In_ uint32_t attr_index,
            _Inout_ vendor_cache_t* cache,
            void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_lag(key->key.object_id);
    auto sdev = la_lag.get_device();
    sai_check_object(la_lag, SAI_OBJECT_TYPE_LAG, sdev, "lag", key->key.object_id);

    lag_entry* entry = nullptr;
    la_status status = sdev->m_lags.get_ptr(la_lag.index, entry);
    sai_return_on_la_error(status);

    switch ((uint64_t)arg) {
    case SAI_LAG_ATTR_INGRESS_ACL:
        value->oid = entry->service.ingress_acl;
        break;
    case SAI_LAG_ATTR_EGRESS_ACL:
        value->oid = entry->service.egress_acl;
        break;
    default:
        return SAI_STATUS_NOT_SUPPORTED;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
lag_acl_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_acl_stage_t stage;
    sai_object_id_t acl_obj_id;
    switch ((int64_t)arg) {
    case SAI_LAG_ATTR_INGRESS_ACL:
        acl_obj_id = get_attr_value(SAI_LAG_ATTR_INGRESS_ACL, *value);
        stage = SAI_ACL_STAGE_INGRESS;
        break;
    case SAI_LAG_ATTR_EGRESS_ACL:
        acl_obj_id = get_attr_value(SAI_LAG_ATTR_EGRESS_ACL, *value);
        stage = SAI_ACL_STAGE_EGRESS;
        break;
    default:
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_lag(key->key.object_id);
    auto sdev = la_lag.get_device();

    if (la_lag.type != SAI_OBJECT_TYPE_LAG || sdev == nullptr || sdev->m_dev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto switch_acl = (stage == SAI_ACL_STAGE_INGRESS) ? sdev->switch_ingress_acl_oid : sdev->switch_egress_acl_oid;
    if (switch_acl != SAI_NULL_OBJECT_ID) {
        sai_log_error(SAI_API_LAG, "ACL configured at switch level. A new ACL cannot be attach to lag");
        return SAI_STATUS_FAILURE;
    }

    lsai_object sai_acl_obj(acl_obj_id);
    if (acl_obj_id != SAI_NULL_OBJECT_ID && sai_acl_obj.type != SAI_OBJECT_TYPE_ACL_TABLE
        && sai_acl_obj.type != SAI_OBJECT_TYPE_ACL_TABLE_GROUP) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lag_entry* lag_entry = sdev->m_lags.get_ptr(la_lag.index);
    if (lag_entry == nullptr) {
        sai_log_error(SAI_API_LAG, "LAG oid 0x%llx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    sai_status_t sstatus = sdev->m_acl_handler->attach_acl_on_lag(acl_obj_id, stage, lag_entry, SAI_ACL_BIND_POINT_TYPE_LAG);
    sai_return_on_error(sstatus);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
lag_vlan_get(_In_ const sai_object_key_t* key,
             _Inout_ sai_attribute_value_t* value,
             _In_ uint32_t attr_index,
             _Inout_ vendor_cache_t* cache,
             void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_lag(key->key.object_id);
    auto sdev = la_lag.get_device();
    sai_check_object(la_lag, SAI_OBJECT_TYPE_LAG, sdev, "lag", key->key.object_id);

    auto entry = sdev->m_lags.get_ptr(la_lag.index);

    if (entry != nullptr) {
        set_attr_value(SAI_LAG_ATTR_PORT_VLAN_ID, *value, entry->service.port_vlan_id);
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
set_lag_vlan(sai_object_id_t lag_oid, uint16_t port_vlan)
{
    lsai_object la_lag(lag_oid);
    auto sdev = la_lag.get_device();

    auto entry = sdev->m_lags.get_ptr(la_lag.index);
    if (entry != nullptr) {
        entry->service.port_vlan_id = port_vlan;

        la_ethernet_port* eth_port = nullptr;
        la_status status = sai_port_get_ethernet_port(sdev, lag_oid, eth_port);
        sai_return_on_la_error(status);

        status = eth_port->set_port_vid(entry->service.port_vlan_id);
        sai_return_on_la_error(status);

        auto default_vid = sdev->m_vlans.get_id(sdev->m_default_vlan_id);
        if (entry->service.port_vlan_id == default_vid) {
            // default vlan id 1
            eth_port->set_ac_profile(sdev->m_default_ac_profile);
        } else {
            // allow user defined untagged vlan id
            eth_port->set_ac_profile(sdev->m_pvlan_ac_profile);
        }
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
lag_vlan_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto port_vlan = get_attr_value(SAI_LAG_ATTR_PORT_VLAN_ID, *value);
    return set_lag_vlan(key->key.object_id, port_vlan);
}

static sai_status_t
lag_label_get(_In_ const sai_object_key_t* key,
              _Inout_ sai_attribute_value_t* value,
              _In_ uint32_t attr_index,
              _Inout_ vendor_cache_t* cache,
              void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_lag(key->key.object_id);
    auto sdev = la_lag.get_device();
    sai_check_object(la_lag, SAI_OBJECT_TYPE_LAG, sdev, "lag", key->key.object_id);

    lag_entry* lag_entry = sdev->m_lags.get_ptr(la_lag.index);
    if (lag_entry == nullptr) {
        sai_log_error(SAI_API_LAG, "LAG oid 0x%llx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    strncpy(value->chardata, lag_entry->lag_label.c_str(), sizeof(value->chardata));

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
lag_label_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_lag(key->key.object_id);
    auto sdev = la_lag.get_device();
    sai_check_object(la_lag, SAI_OBJECT_TYPE_LAG, sdev, "lag", key->key.object_id);

    lag_entry* lag_entry = sdev->m_lags.get_ptr(la_lag.index);
    if (lag_entry == nullptr) {
        sai_log_error(SAI_API_LAG, "LAG oid 0x%llx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    lag_entry->lag_label = string(value->chardata);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
lag_disable_decrement_ttl_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg)
{
    la_status status;
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_lag(key->key.object_id);
    auto sdev = la_lag.get_device();

    lag_entry* lag_entry = sdev->m_lags.get_ptr(la_lag.index);
    if (lag_entry == nullptr) {
        sai_log_error(SAI_API_LAG, "LAG oid 0x%llx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    set_attr_value(SAI_LAG_ATTR_EXT_DISABLE_DECREMENT_TTL, (*value), lag_entry->service.disable_decrement_ttl);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
lag_disable_decrement_ttl_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    la_status status;
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_lag(key->key.object_id);
    auto sdev = la_lag.get_device();

    lag_entry* lag_entry = sdev->m_lags.get_ptr(la_lag.index);
    if (lag_entry == nullptr) {
        sai_log_error(SAI_API_LAG, "LAG oid 0x%llx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    bool disable_decrement_ttl = get_attr_value(SAI_LAG_ATTR_EXT_DISABLE_DECREMENT_TTL, (*value));

    la_ethernet_port* eth_port = nullptr;
    status = sai_port_get_ethernet_port(sdev, key->key.object_id, eth_port);
    sai_return_on_la_error(status);

    // According to customer's expectation as disable_decrement_ttl
    status = eth_port->set_decrement_ttl(!disable_decrement_ttl);
    sai_return_on_la_error(status);

    lag_entry->service.disable_decrement_ttl = disable_decrement_ttl;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
do_lag_mirror_get(const sai_object_key_t* key,
                  bool is_ingress_stage,
                  sai_object_type_t sai_obj_type,
                  std::vector<sai_object_id_t>& mirror_session_oids)
{
    lsai_object lag_obj(key->key.object_id);
    auto sdev = lag_obj.get_device();
    sai_check_object(lag_obj, SAI_OBJECT_TYPE_LAG, sdev, "lag", key->key.object_id);
    lag_entry* lentry = sdev->m_lags.get_ptr(lag_obj.index);
    if (lentry == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    std::set<sai_object_id_t>* mirror_oid_set = nullptr;
    if (is_ingress_stage) {
        mirror_oid_set = &(lentry->service.ingress_mirror_oids);
    } else {
        mirror_oid_set = &(lentry->service.egress_mirror_oids);
    }

    for (auto oid : *mirror_oid_set) {
        lsai_object laobj(oid);
        if (laobj.type == sai_obj_type) {
            mirror_session_oids.push_back(oid);
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
do_lag_mirror_set(const sai_object_key_t* key, bool is_ingress_stage, std::vector<sai_object_id_t>& mirror_session_oids)
{

    lsai_object lag_obj(key->key.object_id);
    auto sdev = lag_obj.get_device();
    sai_check_object(lag_obj, SAI_OBJECT_TYPE_LAG, sdev, "lag", key->key.object_id);
    lag_entry* lentry = sdev->m_lags.get_ptr(lag_obj.index);
    if (lentry == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status_t status;
    auto gress = is_ingress_stage ? "ingress" : "egress";
    if (mirror_session_oids.empty()) {
        // Detach mirror sessions on this lag.
        status = sdev->m_mirror_handler->detach_mirror_sessions(key->key.object_id, is_ingress_stage);
        sai_return_on_error(status);
        sai_log_debug(SAI_API_LAG, "Detached all %s mirror sessions from lag 0x%lx", gress, key->key.object_id);
    } else {
        status = sdev->m_mirror_handler->attach_mirror_sessions(key->key.object_id, is_ingress_stage, mirror_session_oids);
        sai_return_on_error(status);
        sai_log_debug(SAI_API_LAG, "Attached %s mirror session/s to lag 0x%lx", gress, key->key.object_id);
    }

    // update lag entry to reflect changes related to mirroring.
    std::set<sai_object_id_t>* mirror_oid_set = nullptr;
    if (is_ingress_stage) {
        mirror_oid_set = &(lentry->service.ingress_mirror_oids);
    } else {
        mirror_oid_set = &(lentry->service.egress_mirror_oids);
    }

    if (mirror_session_oids.empty()) {
        // clear mirror-oid set since all mirrors are detached.
        mirror_oid_set->clear();
    } else {
        // add new mirror-oids to lag entry that the lag is mirroring.
        for (auto oid : mirror_session_oids) {
            mirror_oid_set->insert(oid);
        }
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
lag_mirror_session_get(_In_ const sai_object_key_t* key,
                       _Inout_ sai_attribute_value_t* value,
                       _In_ uint32_t attr_index,
                       _Inout_ vendor_cache_t* cache,
                       void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    bool is_ingress_stage = ((uintptr_t)arg == SAI_LAG_ATTR_EXT_INGRESS_MIRROR_SESSION) ? true : false;
    std::vector<sai_object_id_t> mirror_session_oids;
    sai_status_t status = do_lag_mirror_get(key, is_ingress_stage, SAI_OBJECT_TYPE_MIRROR_SESSION, mirror_session_oids);
    sai_return_on_error(status);

    if (mirror_session_oids.empty()) {
        value->objlist.count = 0;
    } else {
        return fill_sai_list(mirror_session_oids.begin(), mirror_session_oids.end(), value->objlist);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lag_mirror_session_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_status_t status;
    uint32_t attr_id = (uintptr_t)arg;
    bool is_ingress_stage = (attr_id == SAI_LAG_ATTR_EXT_INGRESS_MIRROR_SESSION) ? true : false;
    std::vector<sai_object_id_t> mirror_session_oids{};

    // Detach mirror sessions on this lag. Per SAI spec, count == 0 is used
    // to remove mirror session/s off the lag.
    if (value->objlist.count != 0) {
        // SAI specification allows to attach one or more mirror sessions on the lag.
        if (value->objlist.list == nullptr) {
            return SAI_STATUS_INVALID_PARAMETER;
        }

        for (size_t i = 0; i < value->objlist.count; ++i) {
            mirror_session_oids.push_back(value->objlist.list[i]);
        }
    }

    status = do_lag_mirror_set(key, is_ingress_stage, mirror_session_oids);
    sai_return_on_error(status);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lag_samplepacket_get(_In_ const sai_object_key_t* key,
                     _Inout_ sai_attribute_value_t* value,
                     _In_ uint32_t attr_index,
                     _Inout_ vendor_cache_t* cache,
                     void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object lag_obj(key->key.object_id);
    auto sdev = lag_obj.get_device();
    sai_check_object(lag_obj, SAI_OBJECT_TYPE_LAG, sdev, "lag", key->key.object_id);
    lag_entry* pentry = sdev->m_lags.get_ptr(lag_obj.index);
    if (pentry == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    switch ((uintptr_t)arg) {
    case SAI_LAG_ATTR_EXT_INGRESS_SAMPLEPACKET_ENABLE:
        value->oid = pentry->service.ingress_packet_sample_oid;
        break;
    case SAI_LAG_ATTR_EXT_EGRESS_SAMPLEPACKET_ENABLE:
        value->oid = pentry->service.egress_packet_sample_oid;
        break;
    default:
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lag_samplepacket_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    lsai_object lag_obj(key->key.object_id);
    auto sdev = lag_obj.get_device();
    sai_check_object(lag_obj, SAI_OBJECT_TYPE_LAG, sdev, "lag", key->key.object_id);

    sai_status_t status;
    uint32_t attr_id = (uintptr_t)arg;
    bool is_ingress_stage = (attr_id == SAI_LAG_ATTR_EXT_INGRESS_SAMPLEPACKET_ENABLE) ? true : false;
    if (value->oid != SAI_NULL_OBJECT_ID) {
        lsai_object packetsample_obj(value->oid);
        if (packetsample_obj.type != SAI_OBJECT_TYPE_SAMPLEPACKET) {
            sai_log_error(SAI_API_PORT, "Invalid sample packet object 0x%lx", value->oid);
            return SAI_STATUS_FAILURE;
        }

        lasai_samplepacket_t* packet_sample = sdev->m_samplepacket_handler->m_samplepacket_db.get_ptr(packetsample_obj.index);
        if (packet_sample == nullptr) {
            sai_log_error(
                SAI_API_PORT, "Unable to set packet sampling 0x%lx object to lag. Unknown packet sampling oid", value->oid);
            return SAI_STATUS_FAILURE;
        }
    }

    status = sdev->m_samplepacket_handler->port_packet_sampling_set(key, is_ingress_stage, value->oid);
    sai_return_on_error(status);

    return SAI_STATUS_SUCCESS;
}

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
sai_status_t
do_lag_sample_mirror_get(const sai_object_key_t* key,
                         bool is_ingress_stage,
                         sai_object_type_t sai_obj_type,
                         std::vector<sai_object_id_t>& mirror_session_oids)
{
    lsai_object port_obj(key->key.object_id);
    auto sdev = port_obj.get_device();
    sai_check_object(port_obj, SAI_OBJECT_TYPE_LAG, sdev, "lag", key->key.object_id);
    lag_entry* pentry = sdev->m_lags.get_ptr(port_obj.index);
    if (pentry == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    std::set<sai_object_id_t>* mirror_oid_set = nullptr;
    if (is_ingress_stage) {
        mirror_oid_set = &(pentry->service.ingress_sample_mirror_oids);
    } else {
        mirror_oid_set = &(pentry->service.egress_sample_mirror_oids);
    }

    for (auto oid : *mirror_oid_set) {
        lsai_object laobj(oid);
        if (laobj.type == sai_obj_type) {
            mirror_session_oids.push_back(oid);
        }
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lag_sample_mirror_session_get(_In_ const sai_object_key_t* key,
                              _Inout_ sai_attribute_value_t* value,
                              _In_ uint32_t attr_index,
                              _Inout_ vendor_cache_t* cache,
                              void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    bool is_ingress_stage = ((uintptr_t)arg == SAI_LAG_ATTR_EXT_INGRESS_SAMPLE_MIRROR_SESSION) ? true : false;
    std::vector<sai_object_id_t> sample_mirror_session_oids;
    sai_status_t status
        = do_lag_sample_mirror_get(key, is_ingress_stage, SAI_OBJECT_TYPE_MIRROR_SESSION, sample_mirror_session_oids);
    sai_return_on_error(status);

    if (sample_mirror_session_oids.empty()) {
        value->objlist.count = 0;
    } else {
        return fill_sai_list(sample_mirror_session_oids.begin(), sample_mirror_session_oids.end(), value->objlist);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lag_sample_mirror_session_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    lsai_object port_obj(key->key.object_id);
    auto sdev = port_obj.get_device();
    sai_check_object(port_obj, SAI_OBJECT_TYPE_LAG, sdev, "lag", key->key.object_id);

    sai_status_t status;
    uint32_t attr_id = (uintptr_t)arg;
    bool is_ingress_stage = (attr_id == SAI_LAG_ATTR_EXT_INGRESS_SAMPLE_MIRROR_SESSION) ? true : false;
    std::vector<sai_object_id_t> mirror_session_oids{};

    // Detach mirror sessions on this port. Per SAI spec, count == 0 is used
    // to remove mirror session/s off the port.
    if (value->objlist.count != 0) {
        // SAI specification allows to attach one or more sample mirror sessions on the port.
        if (value->objlist.list == nullptr) {
            return SAI_STATUS_INVALID_PARAMETER;
        }

        for (size_t i = 0; i < value->objlist.count; ++i) {
            lsai_object packetsample_obj(value->objlist.list[i]);
            if (packetsample_obj.type != SAI_OBJECT_TYPE_MIRROR_SESSION) {
                sai_log_error(SAI_API_PORT,
                              "Invalid mirror session packet object 0x%lx provided during sample mirror session",
                              value->objlist.list[i]);
                return SAI_STATUS_FAILURE;
            }
            mirror_session_oids.push_back(value->objlist.list[i]);
        }
    }

    status = sdev->m_samplepacket_handler->port_sample_mirror_session_set(key, is_ingress_stage, mirror_session_oids);
    sai_return_on_error(status);

    return SAI_STATUS_SUCCESS;
}
#endif

sai_status_t
lag_mtu_get(_In_ const sai_object_key_t* key,
            _Inout_ sai_attribute_value_t* value,
            _In_ uint32_t attr_index,
            _Inout_ vendor_cache_t* cache,
            void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_lag(key->key.object_id);
    auto sdev = la_lag.get_device();

    lag_entry* lag_entry = sdev->m_lags.get_ptr(la_lag.index);
    if (lag_entry == nullptr) {
        sai_log_error(SAI_API_LAG, "LAG oid 0x%llx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    set_attr_value(SAI_LAG_ATTR_EXT_MTU, (*value), lag_entry->service.mtu);
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
lag_mtu_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    sai_status_t status;
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_lag(key->key.object_id);
    auto sdev = la_lag.get_device();

    lag_entry* lentry_ptr = sdev->m_lags.get_ptr(la_lag.index);
    if (lentry_ptr == nullptr) {
        sai_log_error(SAI_API_LAG, "LAG oid 0x%llx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    uint32_t mtu = get_attr_value(SAI_LAG_ATTR_EXT_MTU, (*value));

    status = lag_port_set_mtu(lentry_ptr, mtu);
    sai_return_on_error(status);

    lentry_ptr->service.mtu = mtu;

    return SAI_STATUS_SUCCESS;
}

// clang-format off

// id; mandatory_on_create; valid_for_create; valid_for_set; valid_for_get
// *attrib_name; type;
extern const sai_attribute_entry_t lag_attribs[]
    = {{SAI_LAG_ATTR_INGRESS_ACL, false, true, true, true, "LAG bind point for Ingress ACL Object", SAI_ATTR_VAL_TYPE_OID},
       {SAI_LAG_ATTR_EGRESS_ACL, false, true, true, true, "LAG bind point for Egress ACL Object", SAI_ATTR_VAL_TYPE_OID},
       {SAI_LAG_ATTR_PORT_VLAN_ID, false, true, true, true, "LAG DEFAULT VLAN ID", SAI_ATTR_VAL_TYPE_U16},
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
       {SAI_LAG_ATTR_LABEL, true, true, true, true, "LAG LABEL", SAI_ATTR_VAL_TYPE_CHARDATA},
       {SAI_LAG_ATTR_EXT_DISABLE_DECREMENT_TTL, false, true, true, true, "DISABLE DECREMENT TTL", SAI_ATTR_VAL_TYPE_BOOL},
#endif
       {SAI_LAG_ATTR_EXT_INGRESS_MIRROR_SESSION, false, true, true, true, "LAG INGRESS MIRROR SESSION", SAI_ATTR_VAL_TYPE_OBJLIST},
       {SAI_LAG_ATTR_EXT_EGRESS_MIRROR_SESSION, false, true, true, true, "LAG EGRESS MIRROR SESSION", SAI_ATTR_VAL_TYPE_OBJLIST},
       {SAI_LAG_ATTR_EXT_INGRESS_SAMPLEPACKET_ENABLE, false, true, true, true, "INGRESS SAMPLEPACKET ENABLE", SAI_ATTR_VAL_TYPE_OID},
       {SAI_LAG_ATTR_EXT_EGRESS_SAMPLEPACKET_ENABLE, false, true, true, true, "EGRESS SAMPLEPACKET ENABLE", SAI_ATTR_VAL_TYPE_OID},
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
       {SAI_LAG_ATTR_EXT_INGRESS_SAMPLE_MIRROR_SESSION, false, true, true, true, "LAG ingress sample mirror session", SAI_ATTR_VAL_TYPE_OBJLIST},
       {SAI_LAG_ATTR_EXT_EGRESS_SAMPLE_MIRROR_SESSION, false, true, true, true, "LAG egress sample mirror session", SAI_ATTR_VAL_TYPE_OBJLIST},
#endif
       {SAI_LAG_ATTR_EXT_MTU, false, true, true, true, "LAG Port MTU Value", SAI_ATTR_VAL_TYPE_U32},
       {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t lag_vendor_attribs[] = {
    /*
    id,
    {create, remove, set, get}, // implemented
    {create, remove, set, get}, // supported
    getter, getter_arg,
    setter, setter_arg
    */
    {SAI_LAG_ATTR_INGRESS_ACL,
     {true, false, true, true},
     {true, false, true, true},
     lag_acl_get,
     (void*)SAI_LAG_ATTR_INGRESS_ACL,
     lag_acl_set,
     (void*)SAI_LAG_ATTR_INGRESS_ACL},
    {SAI_LAG_ATTR_EGRESS_ACL,
     {true, false, true, true},
     {true, false, true, true},
     lag_acl_get,
     (void*)SAI_LAG_ATTR_EGRESS_ACL,
     lag_acl_set,
     (void*)SAI_LAG_ATTR_EGRESS_ACL},
    {SAI_LAG_ATTR_PORT_VLAN_ID, {true, false, true, true}, {true, false, true, true}, lag_vlan_get, nullptr, lag_vlan_set, nullptr},
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    {SAI_LAG_ATTR_LABEL,
     {true, false, true, true},
     {true, false, true, true},
     lag_label_get,
     (void*)SAI_LAG_ATTR_LABEL,
     lag_label_set,
     (void*)SAI_LAG_ATTR_LABEL},
    {SAI_LAG_ATTR_EXT_DISABLE_DECREMENT_TTL,
     {true, false, true, true},
     {true, false, true, true},
     lag_disable_decrement_ttl_get,
     (void*)SAI_LAG_ATTR_EXT_DISABLE_DECREMENT_TTL,
     lag_disable_decrement_ttl_set,
     (void*)SAI_LAG_ATTR_EXT_DISABLE_DECREMENT_TTL},
#endif
    {SAI_LAG_ATTR_EXT_INGRESS_MIRROR_SESSION,
     {true, false, true, true},
     {true, false, true, true},
     lag_mirror_session_get,
     (void*)SAI_LAG_ATTR_EXT_INGRESS_MIRROR_SESSION,
     lag_mirror_session_set,
     (void*)SAI_LAG_ATTR_EXT_INGRESS_MIRROR_SESSION},
    {SAI_LAG_ATTR_EXT_EGRESS_MIRROR_SESSION,
     {true, false, true, true},
     {true, false, true, true},
     lag_mirror_session_get,
     (void*)SAI_LAG_ATTR_EXT_EGRESS_MIRROR_SESSION,
     lag_mirror_session_set,
     (void*)SAI_LAG_ATTR_EXT_EGRESS_MIRROR_SESSION},
    {SAI_LAG_ATTR_EXT_INGRESS_SAMPLEPACKET_ENABLE,
     {true, false, true, true},
     {true, false, true, true},
     lag_samplepacket_get,
     (void*)SAI_LAG_ATTR_EXT_INGRESS_SAMPLEPACKET_ENABLE,
     lag_samplepacket_set,
     (void*)SAI_LAG_ATTR_EXT_INGRESS_SAMPLEPACKET_ENABLE},
    {SAI_LAG_ATTR_EXT_EGRESS_SAMPLEPACKET_ENABLE,
     {true, false, true, true},
     {true, false, true, true},
     lag_samplepacket_get,
     (void*)SAI_LAG_ATTR_EXT_EGRESS_SAMPLEPACKET_ENABLE,
     lag_samplepacket_set,
     (void*)SAI_LAG_ATTR_EXT_EGRESS_SAMPLEPACKET_ENABLE},
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    {SAI_LAG_ATTR_EXT_INGRESS_SAMPLE_MIRROR_SESSION,
     {true, false, true, true},
     {true, false, true, true},
     lag_sample_mirror_session_get, (void*)SAI_LAG_ATTR_EXT_INGRESS_SAMPLE_MIRROR_SESSION, lag_sample_mirror_session_set, (void*)SAI_LAG_ATTR_EXT_INGRESS_SAMPLE_MIRROR_SESSION},

    {SAI_LAG_ATTR_EXT_EGRESS_SAMPLE_MIRROR_SESSION,
     {false, false, true, true},
     {false, false, true, true},
     lag_sample_mirror_session_get, (void*)SAI_LAG_ATTR_EXT_EGRESS_SAMPLE_MIRROR_SESSION, lag_sample_mirror_session_set, (void*)SAI_LAG_ATTR_EXT_EGRESS_SAMPLE_MIRROR_SESSION},
#endif
    {SAI_LAG_ATTR_EXT_MTU,
     {true, false, true, true},
     {true, false, true, true},
     lag_mtu_get,
     (void*)SAI_LAG_ATTR_EXT_MTU,
     lag_mtu_set,
     (void*)SAI_LAG_ATTR_EXT_MTU},
};

// clang-format on

static sai_status_t
create_lag(_Out_ sai_object_id_t* lag_id,
           _In_ sai_object_id_t switch_obj,
           _In_ uint32_t attr_count,
           _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_LAG, SAI_OBJECT_TYPE_SWITCH, switch_obj, &lag_to_string, "attrs", attrs);

    transaction txn;
    txn.status = LA_STATUS_SUCCESS;

    uint32_t index = 0;
    txn.status = sdev->m_lags.allocate_id(index);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_lags.release_id(index); });

    lag_entry entry{};
    txn.status = sdev->m_dev->create_spa_port(index, entry.spa_port);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_dev->destroy(entry.spa_port); });

    sai_status_t status = sdev->m_acl_handler->attach_acl_on_lag_create(entry);
    txn.status = to_la_status(status);
    sai_return_on_la_error(txn.status);

    lsai_object la_lag(SAI_OBJECT_TYPE_LAG, la_obj.switch_id, index);
    entry.service.oid = la_lag.object_id();
    txn.status = sdev->m_lags.set(*lag_id, entry, la_lag);
    sai_return_on_la_error(txn.status);

    sai_log_info(SAI_API_LAG, "LAG 0x%lx created", *lag_id);

    lag_entry* lag_ptr = sdev->m_lags.get_ptr(index);
    if (lag_ptr == nullptr) {
        sai_log_error(SAI_API_LAG, "Fail to get lag port vlan id 0x%lx", *lag_id);
        return SAI_STATUS_FAILURE;
    }

    uint16_t port_vlan = 1;
    get_attrs_value(SAI_LAG_ATTR_PORT_VLAN_ID, attrs, port_vlan, false);
    set_lag_vlan(*lag_id, port_vlan);
    lag_ptr->service.untagged_bridge_port = create_untagged_bridge_port(sdev, *lag_id);

    sai_uint32_t mtu = SAI_DEFAULT_LAG_MTU_SIZE;
    get_attrs_value(SAI_LAG_ATTR_EXT_MTU, attrs, mtu, false);
    lag_ptr->service.mtu = mtu;

    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];
    key.key.object_id = *lag_id;
    snprintf(key_str, MAX_KEY_STR_LEN, "lag 0x%0lx", *lag_id);

    // loop for create_and_set attributes
    for (uint32_t i = 0; i < attr_count; i++) {
        // skip attributes are  mandatory or create only
        // Also, skip attribute that have been taken care by above creation process.

        switch (attr_list[i].id) {
        case SAI_LAG_ATTR_PORT_VLAN_ID:
        case SAI_LAG_ATTR_EXT_MTU:
            continue;
        default:
            sai_create_and_set_attribute(&key, key_str, lag_attribs, lag_vendor_attribs, &attr_list[i]);
            break;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_lag(_In_ sai_object_id_t lag_id)
{
    sai_start_api(SAI_API_LAG, SAI_OBJECT_TYPE_LAG, lag_id, &lag_to_string, lag_id);

    lag_entry lag{};
    la_status status = sdev->m_lags.get(la_obj.index, lag);
    sai_return_on_la_error(status);

    if (lag.members.size() != 0) {
        sai_log_error(SAI_API_LAG, "LAG MEMBER exists %lu", lag.members.size());
        return SAI_STATUS_OBJECT_IN_USE;
    }

    if (lag.service.untagged_bridge_port != SAI_NULL_OBJECT_ID) {
        do_remove_bridge_port(lag.service.untagged_bridge_port);
        lag.service.untagged_bridge_port = SAI_NULL_OBJECT_ID;
    }

    if (lag.service.eth_port != nullptr) {
        status = sdev->m_dev->destroy(lag.service.eth_port);
        sai_return_on_la_error(status);
        lag.service.eth_port = nullptr;
    }

    status = sdev->m_dev->destroy(lag.spa_port);
    sai_return_on_la_error(status, "Fail to destroy spa_port %s", status.message().c_str());

    status = sdev->m_lags.remove(lag_id);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_lag_attribute(_In_ sai_object_id_t lag_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = lag_id;

    sai_start_api(SAI_API_LAG, SAI_OBJECT_TYPE_LAG, lag_id, &lag_to_string, "lag", lag_id, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "lag 0x%0lx", lag_id);
    return sai_set_attribute(&key, key_str, lag_attribs, lag_vendor_attribs, attr);
}

static sai_status_t
get_lag_attribute(_In_ sai_object_id_t lag_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = lag_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_LAG, SAI_OBJECT_TYPE_LAG, lag_id, &lag_to_string, "lag", lag_id, "attrs", attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "lag 0x%0lx", lag_id);
    return sai_get_attributes(&key, key_str, lag_attribs, lag_vendor_attribs, attr_count, attr_list);
}

static bool
update_lag_member_ingress_qos_profile(std::shared_ptr<lsai_device> sdev,
                                      _In_ port_entry* pentry,
                                      _In_ la_ethernet_port* eth_port,
                                      _In_ lag_entry* lag_ptr)
{
    // Update LAG with ingress QOS profiles from LAG member
    if (pentry->ingress_qos_profile) {
        sai_status_t sai_status = port_set_sdk_ingress_qos_profile(sdev, eth_port, pentry->ingress_qos_profile->m_sdk_profile);
        if (sai_status != SAI_STATUS_SUCCESS) {
            sai_log_error(SAI_API_LAG, "Failed to install ingress QOS profile to SDK");
        }
        return true;
    }
    return false;
}

static bool
update_lag_member_tc_profile(std::shared_ptr<lsai_device> sdev,
                             _In_ port_entry* pentry,
                             _In_ la_ethernet_port* eth_port,
                             _In_ lag_entry* lag_ptr)
{
    sai_status_t sai_status = SAI_STATUS_SUCCESS;

    // Update LAG with ingress QOS profiles from LAG member
    if (pentry->tc_profile) {
        sai_status = port_set_sdk_tc_profile(sdev, pentry, eth_port, pentry->tc_profile->m_sdk_profile);
        if (sai_status != SAI_STATUS_SUCCESS) {
            sai_log_error(SAI_API_LAG, "Failed to install ingress TC profile to SDK");
        }
        return true;
    }
    return false;
}

static sai_status_t
create_lag_member(_Out_ sai_object_id_t* lag_member_id,
                  _In_ sai_object_id_t switch_id,
                  _In_ uint32_t attr_count,
                  _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_LAG, SAI_OBJECT_TYPE_SWITCH, switch_id, &lag_mem_to_string, "switch", switch_id, attrs);

    sai_object_id_t lag_obj_id = 0;
    get_attrs_value(SAI_LAG_MEMBER_ATTR_LAG_ID, attrs, lag_obj_id, true);

    lsai_object la_lag(lag_obj_id);
    if (la_lag.type != SAI_OBJECT_TYPE_LAG) {
        sai_log_error(SAI_API_LAG, "Bad LAG_ID 0x%lx", lag_obj_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lag_entry* lag_ptr = sdev->m_lags.get_ptr(la_lag.index);
    if (lag_ptr == nullptr) {
        sai_log_error(SAI_API_LAG, "Bad LAG_ID 0x%lx", lag_obj_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_object_id_t port_obj_id = 0;
    get_attrs_value(SAI_LAG_MEMBER_ATTR_PORT_ID, attrs, port_obj_id, true);

    lsai_object la_port(port_obj_id);
    if (la_port.type != SAI_OBJECT_TYPE_PORT) {
        sai_log_error(SAI_API_LAG, "Bad PORT_ID 0x%lx", port_obj_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    port_entry* pentry = sdev->m_ports.get_ptr(la_port.index);
    if (pentry == nullptr) {
        sai_log_error(SAI_API_LAG, "pentry does not exist on the port index 0x%lx", la_port.index);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (pentry->service.untagged_bridge_port != SAI_NULL_OBJECT_ID) {
        do_remove_bridge_port(pentry->service.untagged_bridge_port);
        pentry->service.untagged_bridge_port = SAI_NULL_OBJECT_ID;
    }

    if (pentry->service.eth_port != nullptr) {
        la_status status = sdev->m_dev->destroy(pentry->service.eth_port);
        sai_return_on_la_error(status, "service exist on the port 0x%lx %s", port_obj_id, status.message().c_str());
        pentry->service.eth_port = nullptr;
    }

    if (pentry->sys_port == nullptr) {
        return SAI_STATUS_INVALID_PORT_MEMBER;
    }

    transaction txn;
    txn.status = lag_ptr->spa_port->add(pentry->sys_port);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { lag_ptr->spa_port->remove(pentry->sys_port); });

    lag_ptr->members.emplace(pentry->sys_port, la_port.index);
    pentry->lag_oid = lag_obj_id;

    lsai_object la_lag_member(SAI_OBJECT_TYPE_LAG_MEMBER, la_obj.switch_id, la_port.index);
    la_lag_member.detail.set(lsai_detail_type_e::LAG_MEMBER, lsai_detail_field_e::LAG, la_lag.index);

    *lag_member_id = la_lag_member.object_id();

    bool disable = false;
    get_attrs_value(SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE, attrs, disable, false);
    la_status status = lag_ptr->spa_port->set_member_transmit_enabled(pentry->sys_port, !disable);
    if (status != LA_STATUS_SUCCESS) {
        sai_log_warn(SAI_API_LAG, "Failed to set transmit enable for LAG member id 0x%0lx created", *lag_member_id);
    }
    disable = false;
    get_attrs_value(SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE, attrs, disable, false);
    lag_ptr->ingress_disable[la_lag_member.index] = disable;

    sai_log_info(SAI_API_LAG, "LAG member id 0x%0lx created", *lag_member_id);

    // Update the newly added mac_port (LAG memeber) with the LAG MTU setting.
    sai_status_t sai_status = lsai_set_mac_port_mtu(pentry->sys_port, lag_ptr->service.mtu);
    if (sai_status != SAI_STATUS_SUCCESS) {
        sai_log_warn(SAI_API_LAG, "Failed to set mtu for LAG member id 0x%0lx created", *lag_member_id);
    }
    la_update_lag_flood_sys(sdev, lag_ptr);

    update_lag_member_ingress_qos_profile(sdev, pentry, lag_ptr->service.eth_port, lag_ptr);
    update_lag_member_tc_profile(sdev, pentry, lag_ptr->service.eth_port, lag_ptr);

    return SAI_STATUS_SUCCESS;
}

//
// remove the old flood_sys port specified in lag_entry.flood_sys
// and find another system port in the members.
static void
la_update_lag_flood_sys(std::shared_ptr<lsai_device> sdev, lag_entry* lag_entry)
{
    const la_system_port* new_flood_sys = nullptr;

    if (lag_entry->flood_sys != nullptr) {
        return;
    }

    // try to find the first sys that is not the same as the current one
    auto it = lag_entry->members.begin();
    if (it != lag_entry->members.end()) {
        new_flood_sys = it->first;
    }

    la_status status = LA_STATUS_SUCCESS;
    auto deps = sdev->m_dev->get_dependent_objects(lag_entry->service.eth_port);
    for (auto objp : deps) {
        if (objp->type() == la_object::object_type_e::L2_SERVICE_PORT) {
            const la_l2_service_port* l2_ac_port = static_cast<const la_l2_service_port*>(objp);
            const la_switch* bridge = nullptr;
            status = l2_ac_port->get_attached_switch(bridge);
            if (bridge == nullptr || status != LA_STATUS_SUCCESS) {
                continue;
            }

            la_l2_destination* flood_destination = nullptr;
            status = bridge->get_flood_destination(flood_destination);
            if (status == LA_STATUS_SUCCESS && flood_destination != nullptr) {
                auto* multicast_group = static_cast<la_l2_multicast_group*>(flood_destination);
                status = multicast_group->remove(l2_ac_port);
                if (new_flood_sys != nullptr) {
                    multicast_group->add(l2_ac_port, new_flood_sys);
                }
            }
        }
    }
    lag_entry->flood_sys = new_flood_sys;
}

static sai_status_t
remove_lag_member(_In_ sai_object_id_t lag_member_id)
{
    sai_start_api(SAI_API_LAG, SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &lag_mem_to_string, "lag_mem", lag_member_id);

    port_entry* pentry = sdev->m_ports.get_ptr(la_obj.index);
    if (pentry == nullptr) {
        sai_log_error(SAI_API_LAG, "pentry does not exist on the object index 0x%lx", la_obj.index);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (pentry->sys_port == nullptr) {
        sai_log_error(SAI_API_LAG, "Invalid lag_member_id 0x%lx", lag_member_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    uint32_t lag_index = la_obj.detail.get(lsai_detail_type_e::LAG_MEMBER, lsai_detail_field_e::LAG);
    lag_entry* lag_entry = sdev->m_lags.get_ptr(lag_index);
    if (lag_entry == nullptr) {
        sai_log_warn(SAI_API_LAG, "Invalid LAG 0xd", lag_index);
        return SAI_STATUS_SUCCESS;
    }

    if (lag_entry->spa_port == nullptr) {
        sai_log_error(SAI_API_LAG, "Invalid spa entry 0x%lx", lag_member_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (lag_entry->flood_sys != nullptr && pentry->sys_port == lag_entry->flood_sys) {
        // remove old flood_sys from the members
        lag_entry->members.erase(lag_entry->flood_sys);
        lag_entry->flood_sys = nullptr;
        la_update_lag_flood_sys(sdev, lag_entry);
    } else if (pentry->sys_port != nullptr) {
        lag_entry->members.erase(pentry->sys_port);
    }

    la_status status = lag_entry->spa_port->set_member_transmit_enabled(pentry->sys_port, false);
    sai_return_on_la_error(status);
    lag_entry->ingress_disable[la_obj.index] = false;

    pentry->lag_oid = SAI_NULL_OBJECT_ID;
    status = lag_entry->spa_port->remove(pentry->sys_port);
    sai_return_on_la_error(status);

    // SAI Port is removed from LAG port. Restore the mtu value from pentry
    sai_status_t sstatus = lsai_set_mac_port_mtu(pentry->sys_port, pentry->service.mtu);
    sai_return_on_error(sstatus);

    // Re-install qos/tc profiles to the  port removed from lag
    bool ingress_qos_profile, tc_profile;
    ingress_qos_profile = update_lag_member_ingress_qos_profile(sdev, pentry, pentry->service.eth_port, lag_entry);
    tc_profile = update_lag_member_tc_profile(sdev, pentry, pentry->service.eth_port, lag_entry);

    // Update LAG using first found member with qos/tc profile configured.
    bool updated_ingress_qos_profile = false;
    bool updated_tc_profile = false;
    if (ingress_qos_profile || tc_profile) {
        for (auto it = lag_entry->members.begin(); it != lag_entry->members.end(); ++it) {
            port_entry* lag_member_pentry = sdev->m_ports.get_ptr(it->second);
            if (ingress_qos_profile && !updated_ingress_qos_profile && lag_member_pentry
                && lag_member_pentry->ingress_qos_profile) {
                update_lag_member_ingress_qos_profile(sdev, lag_member_pentry, lag_entry->service.eth_port, lag_entry);
                updated_ingress_qos_profile = true;
            }
            if (tc_profile && !updated_tc_profile && lag_member_pentry && lag_member_pentry->tc_profile) {
                update_lag_member_tc_profile(sdev, lag_member_pentry, lag_entry->service.eth_port, lag_entry);
                updated_tc_profile = true;
            }
        }
    }

    // If no qos/tc profile to apply on LAG, use defaults
    if (!updated_ingress_qos_profile) {
        sstatus = port_set_sdk_ingress_qos_profile(
            sdev, lag_entry->service.eth_port, sdev->m_qos_handler->get_default_ingress_qos_profile());
        if (sstatus != SAI_STATUS_SUCCESS) {
            sai_log_error(SAI_API_LAG, "Failed to install default ingress QOS profile for lag 0x%1x", lag_entry->service.oid);
        }
    }

    if (!updated_tc_profile) {
        sstatus
            = port_set_sdk_tc_profile(sdev, nullptr, lag_entry->service.eth_port, sdev->m_qos_handler->get_default_tc_profile());
        if (sstatus != SAI_STATUS_SUCCESS) {
            sai_log_error(SAI_API_LAG, "Failed to install default TC profile for lag 0x%1x", lag_entry->service.oid);
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_lag_member_attribute(_In_ sai_object_id_t lag_member_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = lag_member_id;

    sai_start_api(SAI_API_LAG, SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &lag_mem_to_string, "lag_mem", lag_member_id, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, " lag member id 0x%lx", lag_member_id);
    return sai_set_attribute(&key, key_str, lag_member_attribs, lag_member_vendor_attribs, attr);
}

static sai_status_t
get_lag_member_attribute(_In_ sai_object_id_t lag_member_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = lag_member_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_LAG, SAI_OBJECT_TYPE_LAG_MEMBER, lag_member_id, &lag_mem_to_string, "lag_mem", lag_member_id, "attrs", attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, " lag member id 0x%lx", lag_member_id);
    return sai_get_attributes(&key, key_str, lag_member_attribs, lag_member_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
lag_mem_attrib_get(_In_ const sai_object_key_t* key,
                   _Inout_ sai_attribute_value_t* value,
                   _In_ uint32_t attr_index,
                   _Inout_ vendor_cache_t* cache,
                   void* arg)
{
    lsai_object la_lag_member(key->key.object_id);
    auto sdev = la_lag_member.get_device();
    sai_check_object(la_lag_member, SAI_OBJECT_TYPE_LAG_MEMBER, sdev, "lag_member_id", key->key.object_id);

    int32_t attr_id = (uintptr_t)arg;
    switch (attr_id) {
    case SAI_LAG_MEMBER_ATTR_LAG_ID: {
        uint32_t lag_index = la_lag_member.detail.get(lsai_detail_type_e::LAG_MEMBER, lsai_detail_field_e::LAG);
        lsai_object la_lag(SAI_OBJECT_TYPE_LAG, la_lag_member.switch_id, lag_index);
        sai_object_id_t lag_oid = la_lag.object_id();

        set_attr_value(SAI_LAG_MEMBER_ATTR_LAG_ID, (*value), lag_oid);
        break;
    }
    case SAI_LAG_MEMBER_ATTR_PORT_ID: {
        lsai_object la_port(SAI_OBJECT_TYPE_PORT, la_lag_member.switch_id, la_lag_member.index);
        set_attr_value(SAI_LAG_MEMBER_ATTR_PORT_ID, (*value), la_port.object_id());
        break;
    }
    case SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE: {
        uint32_t lag_index = la_lag_member.detail.get(lsai_detail_type_e::LAG_MEMBER, lsai_detail_field_e::LAG);
        lag_entry lag_entry{};
        la_status status = sdev->m_lags.get(lag_index, lag_entry);
        sai_return_on_la_error(status);

        port_entry pentry{};
        status = sdev->m_ports.get(la_lag_member.index, pentry);
        sai_return_on_la_error(status);
        bool enb;
        status = lag_entry.spa_port->get_member_transmit_enabled(pentry.sys_port, enb);
        if (status == LA_STATUS_SUCCESS) {
            set_attr_value(SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE, (*value), !enb);
        }
        break;
    }
    case SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE: {
        uint32_t lag_index = la_lag_member.detail.get(lsai_detail_type_e::LAG_MEMBER, lsai_detail_field_e::LAG);
        lag_entry* lag_entry = sdev->m_lags.get_ptr(lag_index);
        if (lag_entry == nullptr) {
            return SAI_STATUS_FAILURE;
        }

        bool dis = lag_entry->ingress_disable[la_lag_member.index];
        set_attr_value(SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE, (*value), dis);
        break;
    }
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
lag_mem_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    lsai_object la_lag_member(key->key.object_id);
    auto sdev = la_lag_member.get_device();
    sai_check_object(la_lag_member, SAI_OBJECT_TYPE_LAG_MEMBER, sdev, "lag_member_id", key->key.object_id);

    switch ((int64_t)arg) {
    case SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE: {
        uint32_t lag_index = la_lag_member.detail.get(lsai_detail_type_e::LAG_MEMBER, lsai_detail_field_e::LAG);
        lag_entry lag_entry{};
        la_status status = sdev->m_lags.get(lag_index, lag_entry);
        sai_return_on_la_error(status);

        port_entry pentry{};
        status = sdev->m_ports.get(la_lag_member.index, pentry);
        sai_return_on_la_error(status);

        auto enb = get_attr_value(SAI_LAG_MEMBER_ATTR_EGRESS_DISABLE, (*value));
        transaction txn;
        txn.status = lag_entry.spa_port->set_member_transmit_enabled(pentry.sys_port, !enb);
        sai_return_on_la_error(txn.status);
        break;
    }
    case SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE: {
        uint32_t lag_index = la_lag_member.detail.get(lsai_detail_type_e::LAG_MEMBER, lsai_detail_field_e::LAG);
        lag_entry* lag_entry = sdev->m_lags.get_ptr(lag_index);
        if (lag_entry == nullptr) {
            return SAI_STATUS_FAILURE;
        }

        bool dis = get_attr_value(SAI_LAG_MEMBER_ATTR_INGRESS_DISABLE, (*value));
        lag_entry->ingress_disable[la_lag_member.index] = dis;
        break;
    }
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
create_lag_members(_In_ sai_object_id_t switch_id,
                   _In_ uint32_t object_count,
                   _In_ const uint32_t* attr_count,
                   _In_ const sai_attribute_t** attr_list,
                   _In_ sai_bulk_op_error_mode_t mode,
                   _Out_ sai_object_id_t* object_id,
                   _Out_ sai_status_t* object_statuses)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

sai_status_t
remove_lag_members(_In_ uint32_t object_count,
                   _In_ const sai_object_id_t* object_id,
                   _In_ sai_bulk_op_error_mode_t mode,
                   _Out_ sai_status_t* object_statuses)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief LAG methods table retrieved with sai_api_query()
 */
const sai_lag_api_t lag_api = {create_lag,
                               remove_lag,
                               set_lag_attribute,
                               get_lag_attribute,
                               create_lag_member,
                               remove_lag_member,
                               set_lag_member_attribute,
                               get_lag_member_attribute,
                               create_lag_members,
                               remove_lag_members};
}
}
