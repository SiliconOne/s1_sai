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

#include "api/npu/la_l2_destination.h"
#include "api/npu/la_l2_service_port.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_svi_port.h"
#include "api/npu/la_switch.h"
#include "api/system/la_device.h"
#include "api/types/la_ethernet_types.h"
#include "common/ranged_index_generator.h"
#include "sai_device.h"
#include "sai_logger.h"
#include <algorithm>
#include <string.h>
#include <string>

namespace silicon_one
{
namespace sai
{

using namespace std;

static sai_status_t fdb_attrib_get(_In_ const sai_object_key_t* key,
                                   _Inout_ sai_attribute_value_t* value,
                                   _In_ uint32_t attr_index,
                                   _Inout_ vendor_cache_t* cache,
                                   void* arg);

sai_status_t fdb_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

// clang-format off
extern const sai_attribute_entry_t fdb_attribs[] = {
    // id; mandatory_on_create; valid_for_create; valid_for_set; valid_for_get
    // *attrib_name; type;
    {SAI_FDB_ENTRY_ATTR_TYPE, true, true, true, true, "FDB entry type", SAI_ATTR_VAL_TYPE_S32},
    {SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID, false, true, true, true, "FDB entry bridge port id", SAI_ATTR_VAL_TYPE_OID},
    {SAI_FDB_ENTRY_ATTR_META_DATA, false, true, true, true, "FDB entry destination user meta", SAI_ATTR_VAL_TYPE_U32},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t fdb_vendor_attribs[] = {
    {SAI_FDB_ENTRY_ATTR_TYPE,
     /* create, remove, set, get */
     {true, false, true, true},
     {true, false, true, true},
     fdb_attrib_get, (void*)SAI_FDB_ENTRY_ATTR_TYPE, fdb_attrib_set, (void*)SAI_FDB_ENTRY_ATTR_TYPE},

    {SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID,
     {true, false, true, true},
     {true, false, true, true},
     fdb_attrib_get, (void*)SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID, fdb_attrib_set, (void*)SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID},

    {SAI_FDB_ENTRY_ATTR_META_DATA,
     {true, false, true, true},
     {true, false, true, true},
     fdb_attrib_get, (void*)SAI_FDB_ENTRY_ATTR_META_DATA, fdb_attrib_set, (void*)SAI_FDB_ENTRY_ATTR_META_DATA}
};

// clang-format on

static std::string
fdb_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_fdb_entry_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
create_fdb_entry(const sai_fdb_entry_t* fdb_entry, uint32_t attr_count, const sai_attribute_t* attr_list)
{
    if (fdb_entry == nullptr) {
        sai_log_error(SAI_API_FDB, "NULL fdb entry");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_FDB, SAI_OBJECT_TYPE_SWITCH, fdb_entry->switch_id, &fdb_to_string, fdb_entry, "attrs", attrs);

    la_switch* bridge = la_get_bridge_by_obj(fdb_entry->bv_id);
    if (bridge == nullptr) {
        sai_log_error(SAI_API_FDB, "Can not get bridge for vlan 0x%lx", fdb_entry->bv_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_mac_addr_t lmac;
    reverse_copy(std::begin(fdb_entry->mac_address), std::end(fdb_entry->mac_address), std::begin(lmac.bytes));

    sai_fdb_entry_type_t entry_type = SAI_FDB_ENTRY_TYPE_DYNAMIC;
    {
        get_attrs_value(SAI_FDB_ENTRY_ATTR_TYPE, attrs, entry_type, true);
    }

    bridge_port_entry entry{};
    sai_object_id_t bridge_port_obj = 0;
    // **** port is required:
    get_attrs_value(SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID, attrs, bridge_port_obj, true);

    auto fdb_user_meta = LA_CLASS_ID_DEFAULT;
    get_attrs_value(SAI_FDB_ENTRY_ATTR_META_DATA, attrs, fdb_user_meta, false);

    lsai_object la_bport{};
    la_status status = sdev->m_bridge_ports.get(bridge_port_obj, entry, la_bport);
    sai_return_on_la_error(status, "Incorrect BRIDGE PORT ID. 0x%lx", bridge_port_obj);

    la_ethernet_port* eth_port = nullptr;
    status = sai_port_get_ethernet_port(sdev, entry.port_obj, eth_port);
    sai_return_on_la_error(status, "no eth port ID. 0x%lx", entry.port_obj);

    std::vector<la_object*> deps = sdev->m_dev->get_dependent_objects(eth_port);
    for (auto objp : deps) {
        if (objp->type() == la_object::object_type_e::L2_SERVICE_PORT) {
            la_l2_service_port* l2_port = static_cast<la_l2_service_port*>(objp);
            const la_switch* sw = nullptr;
            status = l2_port->get_attached_switch(sw);
            if (status == LA_STATUS_SUCCESS && sw == bridge) {
                status
                    = bridge->set_mac_entry(lmac,
                                            l2_port,
                                            (entry_type == SAI_FDB_ENTRY_TYPE_DYNAMIC) ? sdev->aging_time : LA_MAC_AGING_TIME_NEVER,
                                            fdb_user_meta);
                break;
            }
        }
    }

    return to_sai_status(status);
}

static sai_status_t
remove_fdb_entry(const sai_fdb_entry_t* fdb_entry)
{
    if (fdb_entry == nullptr) {
        sai_log_error(SAI_API_FDB, "NULL fdb entry");
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_start_api(SAI_API_FDB, SAI_OBJECT_TYPE_SWITCH, fdb_entry->switch_id, &fdb_to_string, fdb_entry);

    la_switch* bridge = la_get_bridge_by_obj(fdb_entry->bv_id);
    if (bridge == nullptr) {
        sai_log_error(SAI_API_FDB, "Invalid bridge object 0x%lx", fdb_entry->bv_id);
        return SAI_STATUS_SUCCESS;
    }

    la_mac_addr_t lmac;
    reverse_copy(std::begin(fdb_entry->mac_address), std::end(fdb_entry->mac_address), std::begin(lmac.bytes));

    // check if entry exists
    la_l2_destination* l2_dest = nullptr;
    la_mac_age_info_t entry_info;
    la_status status = bridge->get_mac_entry(lmac, l2_dest, entry_info);
    sai_return_on_la_error(status);

    // remove static mac address for now
    status = bridge->remove_mac_entry(lmac);

    return to_sai_status(status);
}

static sai_status_t
set_fdb_entry_attribute(const sai_fdb_entry_t* fdb_entry, const sai_attribute_t* attr)
{
    if (fdb_entry == nullptr) {
        sai_log_error(SAI_API_FDB, "NULL fdb entry");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    memcpy(&key.key.fdb_entry, fdb_entry, sizeof(*fdb_entry));

    sai_start_api(SAI_API_FDB, SAI_OBJECT_TYPE_SWITCH, fdb_entry->switch_id, &fdb_to_string, fdb_entry, *attr);

    la_switch* bridge = la_get_bridge_by_obj(fdb_entry->bv_id);
    if (bridge == nullptr) {
        sai_log_error(SAI_API_FDB, "Invalid bridge object 0x%lx", fdb_entry->bv_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    snprintf(key_str, MAX_KEY_STR_LEN, "fdb entry %s", to_string(fdb_entry->mac_address).c_str());
    return sai_set_attribute(&key, key_str, fdb_attribs, fdb_vendor_attribs, attr);
}

static sai_status_t
get_fdb_entry_attribute(const sai_fdb_entry_t* fdb_entry, uint32_t attr_count, sai_attribute_t* attr_list)
{
    if (fdb_entry == nullptr) {
        sai_log_error(SAI_API_FDB, "NULL fdb entry");
        return SAI_STATUS_INVALID_PARAMETER;
    }
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    memcpy(&key.key.fdb_entry, fdb_entry, sizeof(*fdb_entry));

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_FDB, SAI_OBJECT_TYPE_SWITCH, fdb_entry->switch_id, &fdb_to_string, fdb_entry, "attrs", attrs);

    la_switch* bridge = la_get_bridge_by_obj(fdb_entry->bv_id);
    if (bridge == nullptr) {
        sai_log_error(SAI_API_FDB, "Invalid bridge object 0x%lx", fdb_entry->bv_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    snprintf(key_str, MAX_KEY_STR_LEN, "fdb entry %s", to_string(fdb_entry->mac_address).c_str());
    return sai_get_attributes(&key, key_str, fdb_attribs, fdb_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
fdb_attrib_get(_In_ const sai_object_key_t* key,
               _Inout_ sai_attribute_value_t* value,
               _In_ uint32_t attr_index,
               _Inout_ vendor_cache_t* cache,
               void* arg)
{
    const sai_fdb_entry_t* fdb_entry = &key->key.fdb_entry;
    if (fdb_entry == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    lsai_object la_sw(fdb_entry->switch_id);
    auto sdev = la_sw.get_device();
    if (sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_switch* bridge = la_get_bridge_by_obj(fdb_entry->bv_id);
    if (bridge == nullptr) {
        sai_log_error(SAI_API_FDB, "Invalid bridge object 0x%lx", fdb_entry->bv_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_mac_addr_t lmac;
    reverse_copy(std::begin(fdb_entry->mac_address), std::end(fdb_entry->mac_address), std::begin(lmac.bytes));

    la_l2_destination* l2_dest = nullptr;
    la_mac_age_info_t entry_info;
    la_status status = bridge->get_mac_entry(lmac, l2_dest, entry_info);
    sai_return_on_la_error(status);

    int32_t attr_id = (uintptr_t)arg;
    switch (attr_id) {
    case SAI_FDB_ENTRY_ATTR_TYPE: {
        if (entry_info.age_value == LA_MAC_AGING_TIME_NEVER) {
            set_attr_value(SAI_FDB_ENTRY_ATTR_TYPE, (*value), SAI_FDB_ENTRY_TYPE_STATIC);
        } else {
            set_attr_value(SAI_FDB_ENTRY_ATTR_TYPE, (*value), SAI_FDB_ENTRY_TYPE_DYNAMIC);
        }
        break;
    }
    case SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID: {
        if (l2_dest != nullptr) {
            const la_l2_service_port* l2_port = static_cast<const la_l2_service_port*>(l2_dest);
            uint32_t index = l2_port->get_gid();
            bridge_port_entry entry{};
            status = sdev->m_bridge_ports.get(index, entry);
            sai_return_on_la_error(status, "Incorrect bridge port 0x%lx", fdb_entry->bv_id);
            lsai_object la_bport(entry.bridge_port_oid);
            if (la_bport.type == SAI_OBJECT_TYPE_VLAN_MEMBER) {
                set_attr_value(SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID, (*value), entry.port_obj);
            } else {
                set_attr_value(SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID, (*value), entry.bridge_port_oid);
            }
        }
        break;
    }
    case SAI_FDB_ENTRY_ATTR_META_DATA: {
        la_class_id_t out_class_id = 0;
        bridge->get_mac_entry(lmac, l2_dest, entry_info, out_class_id);
        set_attr_value(SAI_FDB_ENTRY_ATTR_META_DATA, (*value), out_class_id);
        break;
    }
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
        break;
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
fdb_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    const sai_fdb_entry_t* fdb_entry = &key->key.fdb_entry;
    if (fdb_entry == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    lsai_object la_sw(fdb_entry->switch_id);
    auto sdev = la_sw.get_device();
    if (sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    la_switch* bridge = la_get_bridge_by_obj(fdb_entry->bv_id);
    if (bridge == nullptr) {
        sai_log_error(SAI_API_FDB, "Invalid bridge object 0x%lx", fdb_entry->bv_id);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    la_mac_addr_t lmac;
    reverse_copy(std::begin(fdb_entry->mac_address), std::end(fdb_entry->mac_address), std::begin(lmac.bytes));

    la_l2_destination* l2_dest = nullptr;
    la_mac_age_info_t entry_info;
    la_class_id_t class_id;
    la_status status = bridge->get_mac_entry(lmac, l2_dest, entry_info, class_id);
    if (status == LA_STATUS_ENOTFOUND) {
        sai_log_error(SAI_API_FDB, "New MAC entry, not yet installed", fdb_entry->mac_address);
        sai_return_on_la_error(status);
    }

    int32_t attr_id = (uintptr_t)arg;
    switch (attr_id) {
    case SAI_FDB_ENTRY_ATTR_TYPE: {
        const la_l2_service_port* l2_port = static_cast<const la_l2_service_port*>(l2_dest);
        uint32_t index = l2_port->get_gid();
        bridge_port_entry entry{};
        status = sdev->m_bridge_ports.get(index, entry);
        sai_return_on_la_error(status, "Incorrect bridge port 0x%lx", fdb_entry->bv_id);
        lsai_object la_bport(entry.bridge_port_oid);

        auto entry_type = get_attr_value(SAI_FDB_ENTRY_ATTR_TYPE, (*value));

        status = bridge->set_mac_entry(
            lmac, entry.l2_port, (entry_type == SAI_FDB_ENTRY_TYPE_DYNAMIC) ? sdev->aging_time : LA_MAC_AGING_TIME_NEVER, class_id);
        sai_return_on_la_error(status);

        break;
    }
    case SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID: {
        // l2_dest value from the new bridge port id
        bridge_port_entry entry{};
        sai_object_id_t bridge_port_obj = get_attr_value(SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID, (*value));

        lsai_object la_bport{};
        status = sdev->m_bridge_ports.get(bridge_port_obj, entry, la_bport);
        sai_return_on_la_error(status, "Incorrect bridge port 0x%lx", fdb_entry->bv_id);

        la_ethernet_port* eth_port = nullptr;
        status = sai_port_get_ethernet_port(sdev, entry.port_obj, eth_port);
        sai_return_on_la_error(status, "no eth port ID. 0x%lx", entry.port_obj);

        sai_fdb_entry_type_t entry_type = SAI_FDB_ENTRY_TYPE_DYNAMIC;
        if (entry_info.age_value == LA_MAC_AGING_TIME_NEVER) {
            entry_type = SAI_FDB_ENTRY_TYPE_STATIC;
        } else {
            entry_type = SAI_FDB_ENTRY_TYPE_DYNAMIC;
        }

        std::vector<la_object*> deps = sdev->m_dev->get_dependent_objects(eth_port);
        for (auto objp : deps) {
            if (objp->type() == la_object::object_type_e::L2_SERVICE_PORT) {
                la_l2_service_port* l2_port = static_cast<la_l2_service_port*>(objp);
                const la_switch* sw = nullptr;
                status = l2_port->get_attached_switch(sw);
                if (status == LA_STATUS_SUCCESS && sw == bridge) {
                    status = bridge->set_mac_entry(lmac,
                                                   l2_port,
                                                   (entry_type == SAI_FDB_ENTRY_TYPE_DYNAMIC) ? sdev->aging_time
                                                                                              : LA_MAC_AGING_TIME_NEVER,
                                                   class_id);
                    sai_return_on_la_error(status);
                    break;
                }
            }
        }
        break;
    }
    case SAI_FDB_ENTRY_ATTR_META_DATA: {
        la_class_id_t meta_data = get_attr_value(SAI_FDB_ENTRY_ATTR_META_DATA, (*value));
        if (meta_data > sdev->m_route_user_meta_max) {
            sai_log_error(SAI_API_FDB, "Out of range fdb dest user meta data 0x%lx provided", meta_data);
            return SAI_STATUS_INVALID_PARAMETER;
        }

        status = bridge->set_mac_entry(lmac, l2_dest, entry_info.age_value, meta_data);
        sai_return_on_la_error(status);
        break;
    }
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
        break;
    }
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
flush_fdb_entries(sai_object_id_t switch_id, uint32_t attr_count, const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_FDB, SAI_OBJECT_TYPE_SWITCH, switch_id, &fdb_to_string, "attrs", attrs);

    sai_fdb_flush_entry_type_t flush_type = SAI_FDB_FLUSH_ENTRY_TYPE_DYNAMIC;
    get_attrs_value(SAI_FDB_FLUSH_ATTR_ENTRY_TYPE, attrs, flush_type, false);
    bool dynamic_only = true;
    switch (flush_type) {
    case SAI_FDB_FLUSH_ENTRY_TYPE_DYNAMIC:
        dynamic_only = true;
        break;
    case SAI_FDB_FLUSH_ENTRY_TYPE_ALL:
        dynamic_only = false;
        break;
    case SAI_FDB_FLUSH_ENTRY_TYPE_STATIC:
        sai_log_error(SAI_API_FDB, "flush FDB entry type %d not supported ", flush_type);
        return SAI_STATUS_NOT_SUPPORTED;
    default:
        sai_log_error(SAI_API_FDB, "invalid flush FDB entry type %d", flush_type);
        return SAI_STATUS_INVALID_PARAMETER;
    }

    // currently no support for flushing only specific bridge port
    // sai_object_id_t flush_bridge_port_oid = SAI_NULL_OBJECT_ID;
    // get_attrs_value(SAI_FDB_FLUSH_ATTR_BRIDGE_PORT_ID, attrs, flush_bridge_port_oid, false);
    sai_object_id_t flush_bv_oid = SAI_NULL_OBJECT_ID;
    get_attrs_value(SAI_FDB_FLUSH_ATTR_BV_ID, attrs, flush_bv_oid, false);

    la_mac_entry_vec removed_macs;

    if (flush_bv_oid != SAI_NULL_OBJECT_ID) {
        // if vlan/bridge OID specified flush entries for it only
        la_switch* bridge = la_get_bridge_by_obj(flush_bv_oid);

        if (bridge == nullptr) {
            sai_log_error(SAI_API_FDB, "Invalid flush bridge/vlan object 0x%lx", flush_bv_oid);
            return SAI_STATUS_ITEM_NOT_FOUND;
        }

        la_status status = bridge->flush_mac_entries(dynamic_only, removed_macs);
        sai_return_on_la_error(status, "flush_mac_entries failed");
        return SAI_STATUS_SUCCESS;
    }

    for (auto& pair : sdev->m_vlans.map()) {
        la_status status = pair.second.m_sdk_switch->flush_mac_entries(dynamic_only, removed_macs);
        sai_return_on_la_error(status, "flush_mac_entries failed");
    }

    for (auto& pair : sdev->m_bridges.map()) {
        la_status status = pair.second.m_sdk_switch->flush_mac_entries(dynamic_only, removed_macs);
        sai_return_on_la_error(status, "flush_mac_entries failed");
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_fdb_entry::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    lsai_object sw_obj(SAI_OBJECT_TYPE_SWITCH, sdev->m_switch_id, sdev->m_switch_id);
    *count = 0;

    uint32_t vlan_count = 0;
    sai_status_t status = sai_get_object_count(sw_obj.object_id(), SAI_OBJECT_TYPE_VLAN, &vlan_count);
    sai_return_on_error(status);

    if (!vlan_count) {
        return SAI_STATUS_SUCCESS;
    }
    sai_object_key_t vlan_obj_ids[vlan_count];
    status = sai_get_object_key(sw_obj.object_id(), SAI_OBJECT_TYPE_VLAN, &vlan_count, vlan_obj_ids);
    sai_return_on_error(status);

    for (uint32_t vlan_index = 0; vlan_index < vlan_count; vlan_index++) {
        la_switch* bridge = la_get_bridge_by_obj(vlan_obj_ids[vlan_index].key.object_id);
        if (bridge == nullptr) {
            sai_log_error(SAI_API_FDB, "Invalid bridge object 0x%lx", vlan_obj_ids[vlan_index].key.object_id);
        }

        la_uint32_t entry_count;
        la_status sdk_status = bridge->get_mac_entries_count(entry_count);
        if (sdk_status != LA_STATUS_SUCCESS) {
            sai_log_error(
                SAI_API_FDB, "Failed to get MAC entries from bridge object 0x%lx", vlan_obj_ids[vlan_index].key.object_id);
        } else {
            *count += entry_count;
        }
    }
    sai_log_debug(SAI_API_SWITCH, "Total FDB entries: %d", *count);
    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_fdb_entry::get_object_keys(std::shared_ptr<lsai_device> sdev, uint32_t* object_count, sai_object_key_t* object_list) const
{
    lsai_object sw_obj(SAI_OBJECT_TYPE_SWITCH, sdev->m_switch_id, sdev->m_switch_id);

    uint32_t entry_count = 0;
    sai_status_t status = sai_get_object_count(sw_obj.object_id(), SAI_OBJECT_TYPE_FDB_ENTRY, &entry_count);
    sai_return_on_error(status);
    if (*object_count < entry_count) {
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    uint32_t vlan_count = 0;
    status = sai_get_object_count(sw_obj.object_id(), SAI_OBJECT_TYPE_VLAN, &vlan_count);
    sai_return_on_error(status);

    if (!vlan_count) {
        return SAI_STATUS_SUCCESS;
    }
    sai_object_key_t vlan_obj_ids[vlan_count];
    status = sai_get_object_key(sw_obj.object_id(), SAI_OBJECT_TYPE_VLAN, &vlan_count, vlan_obj_ids);
    sai_return_on_error(status);

    uint32_t idx = 0;
    for (uint32_t vlan_index = 0; vlan_index < vlan_count; vlan_index++) {
        la_switch* bridge = la_get_bridge_by_obj(vlan_obj_ids[vlan_index].key.object_id);
        if (bridge == nullptr) {
            sai_log_error(SAI_API_FDB, "Invalid bridge object 0x%lx", vlan_obj_ids[vlan_index].key.object_id);
        }

        la_mac_entry_vec la_mac_entries;
        la_status sdk_status = bridge->get_mac_entries(la_mac_entries);
        if (sdk_status != LA_STATUS_SUCCESS) {
            sai_log_error(
                SAI_API_FDB, "Failed to get MAC entries from bridge object 0x%lx", vlan_obj_ids[vlan_index].key.object_id);
            return SAI_STATUS_FAILURE;
        }
        for (auto sdk_entry : la_mac_entries) {
            sai_fdb_entry_t sai_entry{};
            sai_entry.switch_id = sdev->m_switch_id;
            lsai_object la_vlan(SAI_OBJECT_TYPE_VLAN, sdev->m_switch_id, sdk_entry.relay_gid);
            sai_entry.bv_id = la_vlan.object_id();
            reverse_copy(std::begin(sdk_entry.addr.bytes), std::end(sdk_entry.addr.bytes), std::begin(sai_entry.mac_address));
            object_list[idx].key.fdb_entry = sai_entry;
            idx++;
        }
    }
    sai_log_debug(SAI_API_SWITCH, "Total %d FDB entries retrieved", idx);

    return SAI_STATUS_SUCCESS;
}

const sai_fdb_api_t fdb_api
    = {create_fdb_entry, remove_fdb_entry, set_fdb_entry_attribute, get_fdb_entry_attribute, flush_fdb_entries};
}
}
