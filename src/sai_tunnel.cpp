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

#include "api/system/la_device.h"
#include "common/gen_utils.h"
#include "common/ranged_index_generator.h"
#include "sai_device.h"
#include "sai_logger.h"

namespace silicon_one
{
namespace sai
{

// clang-format off

static sai_status_t tunnel_map_attrib_get(_In_ const sai_object_key_t* key,
                                 _Inout_ sai_attribute_value_t* value,
                                 _In_ uint32_t attr_index,
                                 _Inout_ vendor_cache_t* cache,
                                 void* arg);

static sai_status_t tunnel_map_entry_attrib_get(_In_ const sai_object_key_t* key,
                                 _Inout_ sai_attribute_value_t* value,
                                 _In_ uint32_t attr_index,
                                 _Inout_ vendor_cache_t* cache,
                                 void* arg);

static sai_status_t tunnel_attrib_get(_In_ const sai_object_key_t* key,
                                 _Inout_ sai_attribute_value_t* value,
                                 _In_ uint32_t attr_index,
                                 _Inout_ vendor_cache_t* cache,
                                 void* arg);

static sai_status_t tunnel_term_attrib_get(_In_ const sai_object_key_t* key,
                                 _Inout_ sai_attribute_value_t* value,
                                 _In_ uint32_t attr_index,
                                 _Inout_ vendor_cache_t* cache,
                                 void* arg);

//  mandatory on create, valid for create, set, get
static const sai_attribute_entry_t tunnel_map_attribs[] = {
    { SAI_TUNNEL_MAP_ATTR_TYPE, true, true, false, true,
      "Tunnel map type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_TUNNEL_MAP_ATTR_ENTRY_LIST, false, false, false, true,
      "Tunnel map to value list", SAI_ATTR_VAL_TYPE_OBJLIST },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};

static const sai_vendor_attribute_entry_t tunnel_map_vendor_attribs[] = {
    { SAI_TUNNEL_MAP_ATTR_TYPE,
      /* create, remove, set, get */
      { true, false, false, true }, /* implemented */
      { true, false, false, true }, /* supported */
      tunnel_map_attrib_get, (void*)SAI_TUNNEL_MAP_ATTR_TYPE,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ATTR_ENTRY_LIST,
      /* create, remove, set, get */
      { false, false, false, true }, /* implemented */
      { false, false, false, true }, /* supported */
      tunnel_map_attrib_get, (void*)SAI_TUNNEL_MAP_ATTR_ENTRY_LIST,
      NULL, NULL },
};

static const sai_attribute_entry_t tunnel_map_entry_attribs[] = {
    { SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE, true, true, false, true,
      "Tunnel map entry type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP, true, true, false, true,
      "Tunnel map", SAI_ATTR_VAL_TYPE_OID },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_KEY, false, true, false, true,
      "Tunnel map entry OECN key", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_VALUE, false, true, false, true,
      "Tunnel map entry OECN value", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_KEY, false, true, false, true,
      "Tunnel map entry UECN key", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_VALUE, false, true, false, true,
      "Tunnel map entry UECN value", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_KEY, false, true, false, true,
      "Tunnel map entry VLAN id key", SAI_ATTR_VAL_TYPE_U16 },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE, false, true, false, true,
      "Tunnel map entry VLAN id value", SAI_ATTR_VAL_TYPE_U16 },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY, false, true, false, true,
      "Tunnel map entry VNI id key", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE, false, true, false, true,
      "Tunnel map entry VNI id value", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_KEY, false, true, false, true,
      "Tunnel map entry Bridge id key", SAI_ATTR_VAL_TYPE_OID },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_VALUE, false, true, false, true,
      "Tunnel map entry Bridge id value", SAI_ATTR_VAL_TYPE_OID },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY, false, true, false, true,
      "Tunnel map entry Virtual Router id key", SAI_ATTR_VAL_TYPE_OID },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_VALUE, false, true, false, true,
      "Tunnel map entry Virtual Router id value", SAI_ATTR_VAL_TYPE_OID },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};

static const sai_vendor_attribute_entry_t tunnel_map_entry_vendor_attribs[] = {
    { SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE,
      /* create, remove, set, get */
      { true, false, false, true }, /* implemented */
      { true, false, false, true }, /* supported */
      tunnel_map_entry_attrib_get, (void*)SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_map_entry_attrib_get, (void*)SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_KEY,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_map_entry_attrib_get, (void*)SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_KEY,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_VALUE,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_map_entry_attrib_get, (void*)SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_VALUE,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_KEY,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_map_entry_attrib_get, (void*)SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_KEY,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_VALUE,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_map_entry_attrib_get, (void*)SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_VALUE,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_KEY,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_map_entry_attrib_get, (void*)SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_KEY,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_map_entry_attrib_get, (void*)SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_map_entry_attrib_get, (void*)SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_map_entry_attrib_get, (void*)SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_KEY,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_map_entry_attrib_get, (void*)SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_KEY,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_VALUE,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_map_entry_attrib_get, (void*)SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_VALUE,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_map_entry_attrib_get, (void*)SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY,
      NULL, NULL },
    { SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_VALUE,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_map_entry_attrib_get, (void*)SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_VALUE,
      NULL, NULL }
};

    //id; mandatory_on_create; valid_for_create; valid_for_set; valid_for_get
    // *attrib_name; type;
static const sai_attribute_entry_t tunnel_attribs[] = {
    { SAI_TUNNEL_ATTR_TYPE, true, true, false, true,
      "Tunnel type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE, true, true, false, true,
      "Tunnel underlay interface", SAI_ATTR_VAL_TYPE_OID },
    { SAI_TUNNEL_ATTR_OVERLAY_INTERFACE, false, true, false, true, // mandatory only for IPNIP/GRE
      "Tunnel overlay interface", SAI_ATTR_VAL_TYPE_OID },
    { SAI_TUNNEL_ATTR_ENCAP_SRC_IP, false, true, false, true, //TODO: Valid for set according to Mell? but header says create_only
      "Tunnel encap src IP", SAI_ATTR_VAL_TYPE_IPADDR },
    { SAI_TUNNEL_ATTR_ENCAP_TTL_MODE, false, true, false, true,
      "Tunnel encap TTL mode", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_TUNNEL_ATTR_ENCAP_TTL_VAL, false, true, false, true,  // mandatory only for TTL_MODE=PIPE
      "Tunnel encap TTL value", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_TUNNEL_ATTR_ENCAP_DSCP_MODE, false, true, false, true,
      "Tunnel encap DSCP mode", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_TUNNEL_ATTR_ENCAP_DSCP_VAL, false, true, false, true, // mandatory only for DSCP_MODE=PIPE
      "Tunnel encap DSCP value", SAI_ATTR_VAL_TYPE_U8 },
    { SAI_TUNNEL_ATTR_ENCAP_GRE_KEY_VALID, false, true, false, true,
      "Tunnel encap GRE key valid", SAI_ATTR_VAL_TYPE_BOOL },
    { SAI_TUNNEL_ATTR_ENCAP_GRE_KEY, false, true, true, true,
      "Tunnel encap GRE key", SAI_ATTR_VAL_TYPE_U32 },
    { SAI_TUNNEL_ATTR_ENCAP_ECN_MODE, false, true, false, true,
      "Tunnel encap ECN mode", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_TUNNEL_ATTR_ENCAP_MAPPERS, false, true, false, true,
      "Tunnel encap mappers", SAI_ATTR_VAL_TYPE_OBJLIST },
    { SAI_TUNNEL_ATTR_DECAP_ECN_MODE, false, true, true, true,
      "Tunnel decap ECN mode", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_TUNNEL_ATTR_DECAP_MAPPERS, false, true, false, true,
      "Tunnel decap mappers", SAI_ATTR_VAL_TYPE_OBJLIST },
    { SAI_TUNNEL_ATTR_DECAP_TTL_MODE, false, true, false, true, // mandatory only for IPnIP and GRE
      "Tunnel decap TTL mode", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_TUNNEL_ATTR_DECAP_DSCP_MODE, false, true, false, true, // mandatory only for IPnIP and GRE
      "Tunnel decap DSCP mode", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_TUNNEL_ATTR_TERM_TABLE_ENTRY_LIST, false, false, false, true,
      "Tunnel term table entries associated with this tunnel", SAI_ATTR_VAL_TYPE_OID },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};

static const sai_vendor_attribute_entry_t tunnel_vendor_attribs[] = {
    { SAI_TUNNEL_ATTR_TYPE,
      /* create, remove, set, get */
      { true, false, false, true }, /* implemented */
      { true, false, false, true }, /* supported */
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_TYPE,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_OVERLAY_INTERFACE,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_OVERLAY_INTERFACE,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_SRC_IP,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_ENCAP_SRC_IP,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_TTL_MODE,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_ENCAP_TTL_MODE,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_TTL_VAL, // TODO: All false - Mell
      { true, false, false, true },
      { true, false, false, true },
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_ENCAP_TTL_VAL,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_DSCP_MODE,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_ENCAP_DSCP_MODE,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_DSCP_VAL, // TODO: All false - Mell
      { true, false, false, true },
      { true, false, false, true },
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_ENCAP_DSCP_VAL,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_GRE_KEY_VALID,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_ENCAP_GRE_KEY_VALID,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_GRE_KEY,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_ENCAP_GRE_KEY,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_ECN_MODE,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_ENCAP_ECN_MODE,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_ENCAP_MAPPERS,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_ENCAP_MAPPERS,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_DECAP_ECN_MODE,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_DECAP_ECN_MODE,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_DECAP_MAPPERS,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_DECAP_MAPPERS,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_DECAP_TTL_MODE, /* NOTE: This one is CREATE_ONLY, yet. */
      { true, false, true, true },
      { true, false, true, true },
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_DECAP_TTL_MODE,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_DECAP_DSCP_MODE,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_DECAP_DSCP_MODE,
      NULL, NULL },
    { SAI_TUNNEL_ATTR_TERM_TABLE_ENTRY_LIST,
      /* create, remove, set, get */
      { false, false, false, true }, /* implemented */
      { false, false, false, true }, /* supported */
      tunnel_attrib_get, (void*)SAI_TUNNEL_ATTR_TERM_TABLE_ENTRY_LIST,
      NULL, NULL }
};

/* Tunnel termination attributes */
    /* mandatory on create, valid for create, set, get */
static const sai_attribute_entry_t tunnel_term_attribs[] = {
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID, true, true, false, true,
      "Tunnel termination virtual router ID", SAI_ATTR_VAL_TYPE_OID },
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE, true, true, false, true,
      "Tunnel termination type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP, true, true, false, true,
      "Tunnel termination destination IP", SAI_ATTR_VAL_TYPE_IPADDR },
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_SRC_IP, false, true, false, true,
      "Tunnel termination source IP", SAI_ATTR_VAL_TYPE_IPADDR },
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE, true, true, false, true,
      "Tunnel termination tunnel type", SAI_ATTR_VAL_TYPE_S32 },
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID, true, true, false, true,
      "Tunnel termination tunnel ID", SAI_ATTR_VAL_TYPE_OID },
    { END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, true,
      "", SAI_ATTR_VAL_TYPE_UNDETERMINED }
};


static const sai_vendor_attribute_entry_t tunnel_term_vendor_attribs[] = {
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_term_attrib_get, (void*)SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID,
      NULL, NULL },
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_term_attrib_get, (void*)SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE,
      NULL, NULL },
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_term_attrib_get, (void*)SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP,
      NULL, NULL },
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_SRC_IP,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_term_attrib_get, (void*)SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_SRC_IP,
      NULL, NULL },
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_term_attrib_get, (void*)SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE,
      NULL, NULL },
    { SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID,
      { true, false, false, true },
      { true, false, false, true },
      tunnel_term_attrib_get, (void*)SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID,
      NULL, NULL }
};

// clang-format on

static std::string
tunnel_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_tunnel_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << silicon_one::sai::to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static void
tunnel_key_to_str(_In_ sai_object_id_t tunnel_id, _Out_ char* key_str)
{
    lsai_object la_tun(tunnel_id);
    auto sdev = la_tun.get_device();
    if (sdev == nullptr || sdev->m_dev == nullptr) {
        snprintf(key_str, MAX_KEY_STR_LEN, "invalid bridge");
    }

    switch (la_tun.type) {
    case SAI_OBJECT_TYPE_TUNNEL:
        snprintf(key_str, MAX_KEY_STR_LEN, "tunnel %d", la_tun.index);
        return;
    case SAI_OBJECT_TYPE_TUNNEL_MAP:
        snprintf(key_str, MAX_KEY_STR_LEN, "tunnel map %d", la_tun.index);
        return;
    case SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY:
        snprintf(key_str, MAX_KEY_STR_LEN, "tunnel term entry %d", la_tun.index);
        return;
    case SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY:
        snprintf(key_str,
                 MAX_KEY_STR_LEN,
                 "tunnel map entry %d:%d:%d",
                 la_tun.tunnel_map_type,
                 la_tun.tunnel_map_entry_key,
                 la_tun.tunnel_map_entry_value);
        return;
    default:
        break;
    }

    snprintf(key_str, MAX_KEY_STR_LEN, "invalid bridge");
}

static std::string
tunnel_map_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_tunnel_map_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << silicon_one::sai::to_string(attrid, attr.value) << " ";

    return log_message.str();
}

sai_status_t
laobj_db_tunnel_map_entry::get_object_count(std::shared_ptr<lsai_device> sdev, uint32_t* count) const
{
    uint32_t cnt = 0;
    for (auto& tun_map : sdev->m_tunnel_manager->m_tunnel_map_db.map()) {
        cnt += tun_map.second.m_entry_list.size();
    }

    *count = cnt;

    return SAI_STATUS_SUCCESS;
}

sai_status_t
laobj_db_tunnel_map_entry::get_object_keys(std::shared_ptr<lsai_device> sdev,
                                           uint32_t* object_count,
                                           sai_object_key_t* object_list) const
{
    uint32_t entry_num = 0;

    sai_status_t status = get_object_count(sdev, &entry_num);
    sai_return_on_error(status);

    *object_count = entry_num;
    if (*object_count < entry_num) {
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    uint32_t obj_index = 0;
    for (auto& tun_map : sdev->m_tunnel_manager->m_tunnel_map_db.map()) {
        for (auto it = tun_map.second.m_entry_list.begin(); it != tun_map.second.m_entry_list.end(); ++it, obj_index++) {
            object_list[obj_index].key.object_id = *it;
        }
    }

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tunnel_map_attrib_get(_In_ const sai_object_key_t* key,
                      _Inout_ sai_attribute_value_t* value,
                      _In_ uint32_t attr_index,
                      _Inout_ vendor_cache_t* cache,
                      void* arg)
{
    lsai_object la_tun_map(key->key.object_id);
    auto sdev = la_tun_map.get_device();
    sai_check_object(la_tun_map, SAI_OBJECT_TYPE_TUNNEL_MAP, sdev, "tunnel_map", key->key.object_id);

    int32_t attr_id = (uintptr_t)arg;

    switch (attr_id) {
    case SAI_TUNNEL_MAP_ATTR_TYPE:
        return sdev->m_tunnel_manager->get_tunnel_map_type(la_tun_map.index, value);
    case SAI_TUNNEL_MAP_ATTR_ENTRY_LIST:
        return sdev->m_tunnel_manager->get_tunnel_map_entry_list(la_tun_map.index, value);
    default:
        break;
    }

    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
tunnel_map_entry_attrib_get(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg)
{
    lsai_object la_tun_map_entry(key->key.object_id);
    auto sdev = la_tun_map_entry.get_device();
    sai_check_object(la_tun_map_entry, SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY, sdev, "tunnel_map_entry", key->key.object_id);

    int32_t attr_id = (uintptr_t)arg;

    if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE) {
        set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE, *value, (sai_tunnel_map_type_t)la_tun_map_entry.tunnel_map_type);
        return SAI_STATUS_SUCCESS;
    }

    if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP) {
        lsai_object la_tun_map(SAI_OBJECT_TYPE_TUNNEL_MAP, la_tun_map_entry.switch_id, la_tun_map_entry.index);
        la_tun_map.tunnel_map_type = la_tun_map_entry.tunnel_map_type;
        sai_object_id_t obj = la_tun_map.object_id();
        set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP, *value, obj);
        return SAI_STATUS_SUCCESS;
    }

    switch (la_tun_map_entry.tunnel_map_type) {
    case SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI: {
        if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY) {
            lsai_object la_vf(SAI_OBJECT_TYPE_VIRTUAL_ROUTER, la_tun_map_entry.switch_id, la_tun_map_entry.tunnel_map_entry_key);
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY, *value, la_vf.object_id());
        } else if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE) {
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE, *value, la_tun_map_entry.tunnel_map_entry_value);
        } else {
            return SAI_STATUS_INVALID_PARAMETER;
        }
        return SAI_STATUS_SUCCESS;
    }
    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID: {
        if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY) {
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY, *value, la_tun_map_entry.tunnel_map_entry_key);
        } else if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_VALUE) {
            lsai_object la_vf(SAI_OBJECT_TYPE_VIRTUAL_ROUTER, la_tun_map_entry.switch_id, la_tun_map_entry.tunnel_map_entry_value);
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_VALUE, *value, la_vf.object_id());
        } else {
            return SAI_STATUS_INVALID_PARAMETER;
        }
        return SAI_STATUS_SUCCESS;
    }
    case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI: {
        if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_KEY) {
            lsai_object la_bdg(SAI_OBJECT_TYPE_BRIDGE, la_tun_map_entry.switch_id, la_tun_map_entry.tunnel_map_entry_key);
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_KEY, *value, la_bdg.object_id());
        } else if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE) {
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE, *value, la_tun_map_entry.tunnel_map_entry_value);
        } else {
            return SAI_STATUS_INVALID_PARAMETER;
        }
        return SAI_STATUS_SUCCESS;
    }

    case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF: {
        if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY) {
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY, *value, la_tun_map_entry.tunnel_map_entry_key);
        } else if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_VALUE) {
            lsai_object la_bdg(SAI_OBJECT_TYPE_BRIDGE, la_tun_map_entry.switch_id, la_tun_map_entry.tunnel_map_entry_value);
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_VALUE, *value, la_bdg.object_id());
        } else {
            return SAI_STATUS_INVALID_PARAMETER;
        }
        return SAI_STATUS_SUCCESS;
    }
    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID: {
        if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY) {
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY, *value, la_tun_map_entry.tunnel_map_entry_key);
        } else if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE) {
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE, *value, la_tun_map_entry.tunnel_map_entry_value);
        } else {
            return SAI_STATUS_INVALID_PARAMETER;
        }
        return SAI_STATUS_SUCCESS;
    }

    case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI: {
        if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_KEY) {
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_KEY, *value, la_tun_map_entry.tunnel_map_entry_key);
        } else if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE) {
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE, *value, la_tun_map_entry.tunnel_map_entry_value);
        } else {
            return SAI_STATUS_INVALID_PARAMETER;
        }
        return SAI_STATUS_SUCCESS;
    }

    case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
    case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN: {
        if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_KEY) {
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_KEY, *value, la_tun_map_entry.tunnel_map_entry_key);
        } else if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_KEY) {
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_KEY, *value, la_tun_map_entry.tunnel_map_entry_value);
        } else if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_VALUE) {
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_VALUE, *value, la_tun_map_entry.tunnel_map_entry_value);
        } else if (attr_id == SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_VALUE) {
            set_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_VALUE, *value, la_tun_map_entry.tunnel_map_entry_value);
        } else {
            return SAI_STATUS_INVALID_PARAMETER;
        }
        return SAI_STATUS_SUCCESS;
    }
    default:
        break;
    }

    return SAI_STATUS_INVALID_PARAMETER;
}

static sai_status_t
tunnel_attrib_get(_In_ const sai_object_key_t* key,
                  _Inout_ sai_attribute_value_t* value,
                  _In_ uint32_t attr_index,
                  _Inout_ vendor_cache_t* cache,
                  void* arg)
{
    lsai_object la_tun(key->key.object_id);
    auto sdev = la_tun.get_device();
    sai_check_object(la_tun, SAI_OBJECT_TYPE_TUNNEL, sdev, "tunnel", key->key.object_id);

    int32_t attr_id = (uintptr_t)arg;

    return sdev->m_tunnel_manager->get_tunnel_attribute(la_tun.index, (sai_tunnel_attr_t)attr_id, value);
}

static sai_status_t
tunnel_term_attrib_get(_In_ const sai_object_key_t* key,
                       _Inout_ sai_attribute_value_t* value,
                       _In_ uint32_t attr_index,
                       _Inout_ vendor_cache_t* cache,
                       void* arg)

{
    lsai_object la_tun_term(key->key.object_id);
    auto sdev = la_tun_term.get_device();
    sai_check_object(la_tun_term, SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY, sdev, "tunnel_term", key->key.object_id);

    int32_t attr_id = (uintptr_t)arg;

    auto tunnel_index = (uint32_t)la_tun_term.detail.get(lsai_detail_type_e::TUNNEL_TERM, lsai_detail_field_e::TUNNEL);

    return sdev->m_tunnel_manager->get_tunnel_term_attribute(
        la_tun_term, tunnel_index, (sai_tunnel_term_table_entry_attr_t)attr_id, value);
}

static sai_status_t
create_tunnel_map(_Out_ sai_object_id_t* tunnel_map_id,
                  _In_ sai_object_id_t switch_id,
                  _In_ uint32_t attr_count,
                  _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_TUNNEL, SAI_OBJECT_TYPE_SWITCH, switch_id, &tunnel_map_to_string, "switch", switch_id, attrs);

    tunnel_map_t tunnel_map{};
    get_attrs_value(SAI_TUNNEL_MAP_ATTR_TYPE, attrs, tunnel_map.m_type, true);

    lsai_object la_tun_map(SAI_OBJECT_TYPE_TUNNEL_MAP, la_obj.index, 0);
    la_status status = sdev->m_tunnel_manager->create_tunnel_map(tunnel_map, la_tun_map);
    sai_return_on_la_error(status);

    *tunnel_map_id = la_tun_map.object_id();

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_tunnel_map(_In_ sai_object_id_t tunnel_map_id)
{
    sai_start_api(SAI_API_TUNNEL, SAI_OBJECT_TYPE_TUNNEL_MAP, tunnel_map_id, &tunnel_map_to_string, "tunnel map", tunnel_map_id);

    la_status status = sdev->m_tunnel_manager->remove_tunnel_map(tunnel_map_id);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_tunnel_map_attribute(_In_ sai_object_id_t tunnel_map_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_tunnel_map_attribute(_In_ sai_object_id_t tunnel_map_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tunnel_map_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_TUNNEL, SAI_OBJECT_TYPE_TUNNEL_MAP, tunnel_map_id, &tunnel_map_to_string, "tunnel map", tunnel_map_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "tunnel map 0x%0lx", tunnel_map_id);
    return sai_get_attributes(&key, key_str, tunnel_map_attribs, tunnel_map_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
create_tunnel(_Out_ sai_object_id_t* tunnel_id,
              _In_ sai_object_id_t switch_id,
              _In_ uint32_t attr_count,
              _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_TUNNEL, SAI_OBJECT_TYPE_SWITCH, switch_id, &tunnel_to_string, "switch", switch_id, attrs);

    tunnel_t tunnel{};
    get_attrs_value(SAI_TUNNEL_ATTR_TYPE, attrs, tunnel.m_type, true);

    if (tunnel.m_type == SAI_TUNNEL_TYPE_IPINIP || tunnel.m_type == SAI_TUNNEL_TYPE_IPINIP_GRE
        || tunnel.m_type == SAI_TUNNEL_TYPE_VXLAN) {
        get_attrs_value(SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE, attrs, tunnel.m_underlay_oid, true);
    }

    if (tunnel.m_type == SAI_TUNNEL_TYPE_IPINIP || tunnel.m_type == SAI_TUNNEL_TYPE_IPINIP_GRE) {
        get_attrs_value(SAI_TUNNEL_ATTR_OVERLAY_INTERFACE, attrs, tunnel.m_overlay_oid, true);
    }

    get_attrs_value(SAI_TUNNEL_ATTR_ENCAP_SRC_IP, attrs, tunnel.m_src_ip, false);
    get_attrs_value(SAI_TUNNEL_ATTR_ENCAP_TTL_MODE, attrs, tunnel.m_encap_ttl_mode, false);

    if (tunnel.m_encap_ttl_mode == SAI_TUNNEL_TTL_MODE_PIPE_MODEL) {
        get_attrs_value(SAI_TUNNEL_ATTR_ENCAP_TTL_VAL, attrs, tunnel.m_ttl, true);
    }

    get_attrs_value(SAI_TUNNEL_ATTR_ENCAP_DSCP_MODE, attrs, tunnel.m_encap_dscp_mode, false);

    if (tunnel.m_encap_dscp_mode == SAI_TUNNEL_DSCP_MODE_PIPE_MODEL) {
        get_attrs_value(SAI_TUNNEL_ATTR_ENCAP_DSCP_VAL, attrs, tunnel.m_dscp_val, true);
    }

    get_attrs_value(SAI_TUNNEL_ATTR_ENCAP_GRE_KEY_VALID, attrs, tunnel.m_gre_key_valid, false);

    if (tunnel.m_gre_key_valid) {
        get_attrs_value(SAI_TUNNEL_ATTR_ENCAP_GRE_KEY, attrs, tunnel.m_gre_key, false);
    }

    get_attrs_value(SAI_TUNNEL_ATTR_ENCAP_ECN_MODE, attrs, tunnel.m_encap_ecn_mode, false);

    sai_object_list_t encap_mappers{};
    get_attrs_value(SAI_TUNNEL_ATTR_ENCAP_MAPPERS, attrs, encap_mappers, false);
    tunnel.m_encap_mappers.assign(encap_mappers.list, encap_mappers.list + encap_mappers.count);

    get_attrs_value(SAI_TUNNEL_ATTR_DECAP_ECN_MODE, attrs, tunnel.m_decap_ecn_mode, false);

    sai_object_list_t decap_mappers{};
    get_attrs_value(SAI_TUNNEL_ATTR_DECAP_MAPPERS, attrs, decap_mappers, false);
    tunnel.m_decap_mappers.assign(decap_mappers.list, decap_mappers.list + decap_mappers.count);

    if (tunnel.m_type == SAI_TUNNEL_TYPE_IPINIP || tunnel.m_type == SAI_TUNNEL_TYPE_IPINIP_GRE) {
        get_attrs_value(SAI_TUNNEL_ATTR_DECAP_TTL_MODE, attrs, tunnel.m_decap_ttl_mode, true);
        get_attrs_value(SAI_TUNNEL_ATTR_DECAP_DSCP_MODE, attrs, tunnel.m_decap_dscp_mode, true);
    }

    la_status status = sdev->m_tunnel_manager->create_tunnel(tunnel, tunnel_id);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_tunnel(_In_ sai_object_id_t tunnel_id)
{
    sai_start_api(SAI_API_TUNNEL, SAI_OBJECT_TYPE_TUNNEL, tunnel_id, &tunnel_to_string, "tunnel", tunnel_id);

    la_status status = sdev->m_tunnel_manager->remove_tunnel(tunnel_id);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_tunnel_attribute(_In_ sai_object_id_t tunnel_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_SUCCESS;
}

static sai_status_t
get_tunnel_attribute(_In_ sai_object_id_t tunnel_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tunnel_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_TUNNEL, SAI_OBJECT_TYPE_TUNNEL, tunnel_id, &tunnel_to_string, "tunnel", tunnel_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "tunnel 0x%0lx", tunnel_id);
    return sai_get_attributes(&key, key_str, tunnel_attribs, tunnel_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
get_tunnel_stats(_In_ sai_object_id_t tunnel_id,
                 _In_ uint32_t number_of_counters,
                 _In_ const sai_stat_id_t* counter_ids,
                 _Out_ uint64_t* counters)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_tunnel_stats_ext(_In_ sai_object_id_t tunnel_id,
                     _In_ uint32_t number_of_counters,
                     _In_ const sai_stat_id_t* counter_ids,
                     _In_ sai_stats_mode_t mode,
                     _Out_ uint64_t* counters)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
clear_tunnel_stats(_In_ sai_object_id_t tunnel_id, _In_ uint32_t number_of_counters, _In_ const sai_stat_id_t* counter_ids)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static std::string
tunnel_term_table_entry_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_tunnel_term_table_entry_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << silicon_one::sai::to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
create_tunnel_term_table_entry(_Out_ sai_object_id_t* tunnel_term_table_entry_id,
                               _In_ sai_object_id_t switch_id,
                               _In_ uint32_t attr_count,
                               _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_TUNNEL, SAI_OBJECT_TYPE_SWITCH, switch_id, &tunnel_term_table_entry_to_string, "switch", switch_id, attrs);

    lsai_object la_tun_term(SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY, la_obj.index, 0);
    tunnel_term_t tunnel_term{};
    get_attrs_value(SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID, attrs, tunnel_term.m_vrf_oid, true);

    sai_tunnel_term_table_entry_type_t tun_term_type;
    get_attrs_value(SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE, attrs, tun_term_type, true);
    la_tun_term.detail.set(lsai_detail_type_e::TUNNEL_TERM, lsai_detail_field_e::TYPE, tun_term_type);

    get_attrs_value(SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP, attrs, tunnel_term.m_dst_ip, true);
    if (tun_term_type == SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P) {
        get_attrs_value(SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_SRC_IP, attrs, tunnel_term.m_src_ip, true);
    }

    sai_object_id_t tunnel_id;
    get_attrs_value(SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID, attrs, tunnel_id, true);
    lsai_object la_tun(tunnel_id);
    la_tun_term.detail.set(lsai_detail_type_e::TUNNEL_TERM, lsai_detail_field_e::TUNNEL, la_tun.index);

    la_status status = sdev->m_tunnel_manager->create_tunnel_term(tunnel_term, la_tun_term);
    sai_return_on_la_error(status);

    *tunnel_term_table_entry_id = la_tun_term.object_id();

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_tunnel_term_table_entry(_In_ sai_object_id_t tunnel_term_table_entry_id)
{
    sai_start_api(SAI_API_TUNNEL,
                  SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY,
                  tunnel_term_table_entry_id,
                  &tunnel_term_table_entry_to_string,
                  "tunnel_term",
                  tunnel_term_table_entry_id);

    la_status status = sdev->m_tunnel_manager->remove_tunnel_term(tunnel_term_table_entry_id);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_tunnel_term_table_entry_attribute(_In_ sai_object_id_t tunnel_term_table_entry_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_tunnel_term_table_entry_attribute(_In_ sai_object_id_t tunnel_term_table_entry_id,
                                      _In_ uint32_t attr_count,
                                      _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tunnel_term_table_entry_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_TUNNEL,
                  SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY,
                  tunnel_term_table_entry_id,
                  &tunnel_term_table_entry_to_string,
                  "tunnel_term",
                  tunnel_term_table_entry_id,
                  attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "tunnel 0x%0lx", tunnel_term_table_entry_id);
    return sai_get_attributes(&key, key_str, tunnel_term_attribs, tunnel_term_vendor_attribs, attr_count, attr_list);
}

static std::string
tunnel_map_entry_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_tunnel_map_entry_attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << silicon_one::sai::to_string(attrid, attr.value) << " ";

    return log_message.str();
}

//
// create_tunnel_map_entry
// the returned object id contains all the mandatory information on it.
// Since all the tunnel entry information are mandatory, and the inforamtion can be
// packed into the object id, so we store the entry obj in the map list and make sure
// there is no duplication.
//
static sai_status_t
create_tunnel_map_entry(_Out_ sai_object_id_t* tunnel_map_entry_id,
                        _In_ sai_object_id_t switch_id,
                        _In_ uint32_t attr_count,
                        _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_TUNNEL, SAI_OBJECT_TYPE_SWITCH, switch_id, &tunnel_map_entry_to_string, "tunnel_map_entry", switch_id, attrs);

    lsai_object la_tun_map_entry(SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY, la_obj.index, 0);
    sai_tunnel_map_type_t type = SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID;
    get_attrs_value(SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE, attrs, type, true);
    la_tun_map_entry.tunnel_map_type = type;

    sai_object_id_t obj_tun = SAI_NULL_OBJECT_ID;
    get_attrs_value(SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP, attrs, obj_tun, true);
    lsai_object la_tun(obj_tun);
    la_tun_map_entry.index = la_tun.index;

    switch (type) {
    case SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI: {
        sai_object_id_t obj_vrf;
        get_attrs_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY, attrs, obj_vrf, true);
        lsai_object la_vrf(obj_vrf);
        la_tun_map_entry.tunnel_map_entry_key = la_vrf.index;
        get_attrs_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE, attrs, la_tun_map_entry.tunnel_map_entry_value, true);
        *tunnel_map_entry_id = la_tun_map_entry.object_id();
        sdev->m_tunnel_manager->add_tunnel_map_entry(la_tun_map_entry.index, *tunnel_map_entry_id);
        return SAI_STATUS_SUCCESS;
    }
    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID: {
        get_attrs_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY, attrs, la_tun_map_entry.tunnel_map_entry_key, true);
        sai_object_id_t obj_vrf;
        get_attrs_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_VALUE, attrs, obj_vrf, true);
        lsai_object la_vrf(obj_vrf);
        la_tun_map_entry.tunnel_map_entry_value = la_vrf.index;
        *tunnel_map_entry_id = la_tun_map_entry.object_id();
        sdev->m_tunnel_manager->add_tunnel_map_entry(la_tun_map_entry.index, *tunnel_map_entry_id);
        return SAI_STATUS_SUCCESS;
    }
    case SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI: {
        sai_object_id_t obj_bdg;
        get_attrs_value(SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_KEY, attrs, obj_bdg, true);
        lsai_object la_bdg(obj_bdg);
        la_tun_map_entry.tunnel_map_entry_key = la_bdg.index;
        get_attrs_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE, attrs, la_tun_map_entry.tunnel_map_entry_value, true);
        *tunnel_map_entry_id = la_tun_map_entry.object_id();
        sdev->m_tunnel_manager->add_tunnel_map_entry(la_tun_map_entry.index, *tunnel_map_entry_id);
        return SAI_STATUS_SUCCESS;
    }

    case SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF: {
        get_attrs_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY, attrs, la_tun_map_entry.tunnel_map_entry_key, true);
        sai_object_id_t obj_bdg;
        get_attrs_value(SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_VALUE, attrs, obj_bdg, true);
        lsai_object la_bdg(obj_bdg);
        la_tun_map_entry.tunnel_map_entry_value = la_bdg.index;
        *tunnel_map_entry_id = la_tun_map_entry.object_id();
        sdev->m_tunnel_manager->add_tunnel_map_entry(la_tun_map_entry.index, *tunnel_map_entry_id);
        return SAI_STATUS_SUCCESS;
    }
    case SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID: {
        get_attrs_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY, attrs, la_tun_map_entry.tunnel_map_entry_key, true);
        get_attrs_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE, attrs, la_tun_map_entry.tunnel_map_entry_value, true);
        *tunnel_map_entry_id = la_tun_map_entry.object_id();
        sdev->m_tunnel_manager->add_tunnel_map_entry(la_tun_map_entry.index, *tunnel_map_entry_id);
        return SAI_STATUS_SUCCESS;
    }

    case SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI: {
        get_attrs_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_KEY, attrs, la_tun_map_entry.tunnel_map_entry_key, true);
        get_attrs_value(SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE, attrs, la_tun_map_entry.tunnel_map_entry_value, true);
        *tunnel_map_entry_id = la_tun_map_entry.object_id();
        sdev->m_tunnel_manager->add_tunnel_map_entry(la_tun_map_entry.index, *tunnel_map_entry_id);
        return SAI_STATUS_SUCCESS;
    }

    case SAI_TUNNEL_MAP_TYPE_OECN_TO_UECN:
    case SAI_TUNNEL_MAP_TYPE_UECN_OECN_TO_OECN: {
        for (auto a : attrs) {
            switch (a.first) {
            case SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_KEY: {
                la_tun_map_entry.tunnel_map_entry_key = get_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_KEY, a.second);
                break;
            }
            case SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_KEY: {
                la_tun_map_entry.tunnel_map_entry_key = get_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_KEY, a.second);
                break;
            }
            case SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_VALUE: {
                la_tun_map_entry.tunnel_map_entry_value = get_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_UECN_VALUE, a.second);
                break;
            }
            case SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_VALUE: {
                la_tun_map_entry.tunnel_map_entry_value = get_attr_value(SAI_TUNNEL_MAP_ENTRY_ATTR_OECN_VALUE, a.second);
                break;
            }
            }
        }
        *tunnel_map_entry_id = la_tun_map_entry.object_id();
        sdev->m_tunnel_manager->add_tunnel_map_entry(la_tun_map_entry.index, *tunnel_map_entry_id);
        return SAI_STATUS_SUCCESS;
    }
    default:
        break;
    }

    return SAI_STATUS_INVALID_PARAMETER;
}

static sai_status_t
remove_tunnel_map_entry(_In_ sai_object_id_t tunnel_map_entry_id)
{
    sai_start_api(SAI_API_TUNNEL,
                  SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY,
                  tunnel_map_entry_id,
                  &tunnel_map_entry_to_string,
                  "tunnel_map_entry",
                  tunnel_map_entry_id);

    la_status status = sdev->m_tunnel_manager->remove_tunnel_map_entry(la_obj.index, tunnel_map_entry_id);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
set_tunnel_map_entry_attribute(_In_ sai_object_id_t tunnel_map_entry_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_tunnel_map_entry_attribute(_In_ sai_object_id_t tunnel_map_entry_id,
                               _In_ uint32_t attr_count,
                               _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tunnel_map_entry_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_TUNNEL,
                  SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY,
                  tunnel_map_entry_id,
                  &tunnel_map_entry_to_string,
                  "tunnel_map_entry",
                  tunnel_map_entry_id,
                  attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "tunnel map entry 0x%0lx", tunnel_map_entry_id);
    return sai_get_attributes(&key, key_str, tunnel_map_entry_attribs, tunnel_map_entry_vendor_attribs, attr_count, attr_list);
}

const sai_tunnel_api_t tunnel_api = {create_tunnel_map,
                                     remove_tunnel_map,
                                     set_tunnel_map_attribute,
                                     get_tunnel_map_attribute,
                                     create_tunnel,
                                     remove_tunnel,
                                     set_tunnel_attribute,
                                     get_tunnel_attribute,
                                     get_tunnel_stats,
                                     get_tunnel_stats_ext,
                                     clear_tunnel_stats,
                                     create_tunnel_term_table_entry,
                                     remove_tunnel_term_table_entry,
                                     set_tunnel_term_table_entry_attribute,
                                     get_tunnel_term_table_entry_attribute,
                                     create_tunnel_map_entry,
                                     remove_tunnel_map_entry,
                                     set_tunnel_map_entry_attribute,
                                     get_tunnel_map_entry_attribute};
}
}
