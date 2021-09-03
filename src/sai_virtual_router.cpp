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

#include "api/npu/la_l3_ac_port.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_svi_port.h"
#include "api/npu/la_vrf.h"
#include "common/ranged_index_generator.h"
#include "common/transaction.h"
#include "sai_device.h"
#include "sai_logger.h"

namespace silicon_one
{
namespace sai
{

using namespace std;

static sai_status_t vrf_attr_get(_In_ const sai_object_key_t* key,
                                 _Inout_ sai_attribute_value_t* value,
                                 _In_ uint32_t attr_index,
                                 _Inout_ vendor_cache_t* cache,
                                 void* arg);

static sai_status_t vrf_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
static sai_status_t vrf_admin_state_set(std::shared_ptr<silicon_one::sai::lsai_device> sdev,
                                        uint64_t attrib,
                                        const sai_attribute_value_t* value,
                                        vrf_entry* vrf_entry);
static sai_status_t vrf_src_mac_set(std::shared_ptr<silicon_one::sai::lsai_device> sdev,
                                    const sai_attribute_value_t* value,
                                    vrf_entry* vrf_entry);

// clang-format off
static const sai_attribute_entry_t virtual_router_attribs[] = {
    {SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE, false, true, true, true, "Admin v4 state", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE, false, true, true, true, "Admin v6 state", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS, false, true, true, true, "Source MAC address", SAI_ATTR_VAL_TYPE_MAC},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}};

static const sai_vendor_attribute_entry_t virtual_router_vendor_attribs[] = {
    SAI_ATTR_CREATE_AND_SET(SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE, vrf_attr_get, vrf_attr_set),
    SAI_ATTR_CREATE_AND_SET(SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE, vrf_attr_get, vrf_attr_set),
    SAI_ATTR_CREATE_AND_SET(SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS, vrf_attr_get, vrf_attr_set)
};
// clang-format on

static std::string
vrf_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_virtual_router_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
vrf_attr_get(_In_ const sai_object_key_t* key,
             _Inout_ sai_attribute_value_t* value,
             _In_ uint32_t attr_index,
             _Inout_ vendor_cache_t* cache,
             void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();
    if (la_sw.type != SAI_OBJECT_TYPE_VIRTUAL_ROUTER || sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    vrf_entry* vrf_entry = sdev->m_vrfs.get_ptr(la_sw.index);
    if (vrf_entry == nullptr) {
        sai_log_error(SAI_API_VIRTUAL_ROUTER, "VRF entry 0x%llx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    switch ((int64_t)arg) {
    case SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE:
        set_attr_value(SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE, *value, vrf_entry->m_admin_v4_state);
        break;

    case SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE:
        set_attr_value(SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE, *value, vrf_entry->m_admin_v6_state);
        break;

    case SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS:
        set_mac_attr_value(SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS, *value, vrf_entry->m_vrf_mac);
        break;
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
vrf_admin_state_set(std::shared_ptr<silicon_one::sai::lsai_device> sdev,
                    uint64_t attrib,
                    const sai_attribute_value_t* value,
                    vrf_entry* vrf_entry)
{
    la_status status;
    // both V4 and V6 admin state value is bool, so it does not matter we one we choose here
    bool new_vrf_admin_state = get_attr_value(SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE, *value);

    for (auto router_interface_oid : vrf_entry->m_router_interfaces) {
        lsai_object la_rif(router_interface_oid);
        rif_entry* one_rif_entry;
        status = sdev->m_l3_ports.get_ptr(la_rif.index, one_rif_entry);
        sai_return_on_la_error(status, "Internal error: failed getting router interface entry for index 0x%lx", la_rif.index);

        bool prev_enb;
        bool new_enb;
        switch (attrib) {
        case SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE:
            prev_enb = vrf_entry->m_admin_v4_state & one_rif_entry->m_admin_v4_state;
            new_enb = new_vrf_admin_state & one_rif_entry->m_admin_v4_state;
            ;
            if (prev_enb != new_enb) {
                status = one_rif_entry->l3_port->set_protocol_enabled(la_l3_protocol_e::IPV4_UC, new_enb);
                sai_return_on_la_error(status);
            }
            vrf_entry->m_admin_v4_state = new_vrf_admin_state;
            break;

        case SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE:
            prev_enb = vrf_entry->m_admin_v6_state & one_rif_entry->m_admin_v6_state;
            new_enb = new_vrf_admin_state & one_rif_entry->m_admin_v6_state;
            ;
            if (prev_enb != new_enb) {
                status = one_rif_entry->l3_port->set_protocol_enabled(la_l3_protocol_e::IPV6_UC, new_enb);
                sai_return_on_la_error(status);
            }
            vrf_entry->m_admin_v6_state = new_vrf_admin_state;
            break;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
vrf_src_mac_set(std::shared_ptr<silicon_one::sai::lsai_device> sdev, const sai_attribute_value_t* value, vrf_entry* vrf_entry)
{
    la_status status;
    la_mac_addr_t vrf_mac;
    la_mac_addr_t vrf_mac_before;
    la_mac_addr_t sw_mac;

    reverse_copy(std::begin(vrf_entry->m_vrf_mac), std::end(vrf_entry->m_vrf_mac), vrf_mac_before.bytes);
    reverse_copy(std::begin(sdev->m_default_switch_mac), std::end(sdev->m_default_switch_mac), sw_mac.bytes);
    get_mac_attr_value(SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS, *value, vrf_entry->m_vrf_mac);

    reverse_copy(std::begin(vrf_entry->m_vrf_mac), std::end(vrf_entry->m_vrf_mac), vrf_mac.bytes);
    la_mac_addr_t mac_addr;
    std::vector<la_object*> vec = sdev->m_dev->get_dependent_objects(vrf_entry->vrf);
    for (la_object* elem : vec) {
        if (elem->type() == la_object::object_type_e::L3_AC_PORT) {
            la_l3_ac_port* l3ac = static_cast<la_l3_ac_port*>((la_l3_port*)elem);
            status = l3ac->get_mac(mac_addr);
            sai_return_on_la_error(status);
            // set the mac for rif inside this vrf which uses the vrf_mac or the switch mac
            if (mac_addr.flat == vrf_mac_before.flat || mac_addr.flat == sw_mac.flat) {
                status = l3ac->set_mac(vrf_mac);
                sai_return_on_la_error(status);
            }
        } else if (elem->type() == la_object::object_type_e::SVI_PORT) {
            la_svi_port* sviport = static_cast<la_svi_port*>((la_l3_port*)elem);
            status = sviport->get_mac(mac_addr);
            sai_return_on_la_error(status);
            // set the mac for rif inside this vrf which uses the vrf_mac or the switch mac
            if (mac_addr.flat == vrf_mac_before.flat || mac_addr.flat == sw_mac.flat) {
                status = sviport->set_mac(vrf_mac);
                sai_return_on_la_error(status);
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
vrf_attr_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object la_sw(key->key.object_id);
    auto sdev = la_sw.get_device();
    if (la_sw.type != SAI_OBJECT_TYPE_VIRTUAL_ROUTER || sdev == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    vrf_entry* vrf_entry = sdev->m_vrfs.get_ptr(la_sw.index);
    if (vrf_entry == nullptr) {
        sai_log_error(SAI_API_VIRTUAL_ROUTER, "VRF entry 0x%llx is unrecognized", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    switch ((int64_t)arg) {
    case SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS:
        return vrf_src_mac_set(sdev, value, vrf_entry);
    case SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE:
    case SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE:
        return vrf_admin_state_set(sdev, (int64_t)arg, value, vrf_entry);
    }

    return SAI_STATUS_INVALID_PARAMETER;
}

static sai_status_t
create_virtual_router(sai_object_id_t* virtual_router_id,
                      sai_object_id_t obj_switch_id,
                      uint32_t attr_count,
                      const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_VIRTUAL_ROUTER, SAI_OBJECT_TYPE_SWITCH, obj_switch_id, &vrf_to_string, "switch", obj_switch_id, attrs);

    lsai_object la_vf(SAI_OBJECT_TYPE_VIRTUAL_ROUTER, la_obj.index, 0);

    transaction txn{};
    txn.status = sdev->m_vrfs.allocate_id(la_vf.index);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_vrfs.release_id(la_vf.index); });

    vrf_entry vrf_entry{};
    txn.status = sdev->m_dev->create_vrf(la_vf.index, vrf_entry.vrf);
    sai_return_on_la_error(txn.status, "Failed to create VRF with id %u", la_vf.index);

    reverse_copy(std::begin(sdev->m_default_switch_mac), std::end(sdev->m_default_switch_mac), vrf_entry.m_vrf_mac);
    get_mac_attrs_value(SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS, attrs, vrf_entry.m_vrf_mac, false);

    vrf_entry.m_admin_v4_state = true;
    vrf_entry.m_admin_v6_state = true;
    get_attrs_value(SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE, attrs, vrf_entry.m_admin_v4_state, false);
    get_attrs_value(SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE, attrs, vrf_entry.m_admin_v6_state, false);

    vrf_entry.vrf_oid = la_vf.object_id();
    sdev->m_vrfs.set(*virtual_router_id, vrf_entry, la_vf);

    sai_log_info(SAI_API_VIRTUAL_ROUTER, "Virtual Router 0x%lx created", *virtual_router_id);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_virtual_router(sai_object_id_t obj_virtual_router_id)
{
    sai_start_api(SAI_API_VIRTUAL_ROUTER,
                  SAI_OBJECT_TYPE_VIRTUAL_ROUTER,
                  obj_virtual_router_id,
                  &vrf_to_string,
                  "vrf",
                  obj_virtual_router_id);

    la_vrf* vrf = nullptr;
    la_status status = sdev->m_dev->get_vrf_by_id(la_obj.index, vrf);
    sai_return_on_la_error(status, "Failed to get vrf with id %u", la_obj.index);

    status = sdev->m_dev->destroy(vrf);
    sai_return_on_la_error(status, "Failed to destroy vrf with id %u", la_obj.index);

    status = sdev->m_vrfs.remove(obj_virtual_router_id);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_virtual_router_attribute(sai_object_id_t virtual_router_id, const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = virtual_router_id;

    snprintf(key_str, MAX_KEY_STR_LEN, "virtual router 0x%0lx", virtual_router_id);
    return sai_set_attribute(&key, key_str, virtual_router_attribs, virtual_router_vendor_attribs, attr);
}

static sai_status_t
get_virtual_router_attribute(sai_object_id_t virtual_router_id, uint32_t attr_count, sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = virtual_router_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);

    snprintf(key_str, MAX_KEY_STR_LEN, "port 0x%0lx", virtual_router_id);
    return sai_get_attributes(&key, key_str, virtual_router_attribs, virtual_router_vendor_attribs, attr_count, attr_list);
}

const sai_virtual_router_api_t router_api = {
    create_virtual_router,
    remove_virtual_router,
    set_virtual_router_attribute,
    get_virtual_router_attribute,
};
}
}
