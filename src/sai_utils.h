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

#ifndef __SAI_UTILS_H__
#define __SAI_UTILS_H__

#include <algorithm>
#include <arpa/inet.h>
#include <iterator>
#include <memory>

#include "saihostif.h"
#include "saifdb.h"
#include "sainexthop.h"
#include "saiobject.h"
#include "saiport.h"
#include "saistatus.h"
#include "saiswitch.h"

#include "sai_leaba.h"
#include "sai_logger.h"

///@brief check status. Return immediately on failure.
#define sai_return_on_la_error_no_log(X)                                                                                           \
    do {                                                                                                                           \
        if (X != LA_STATUS_SUCCESS) {                                                                                              \
            return to_sai_status(X);                                                                                               \
        }                                                                                                                          \
    } while (0)

///@brief Check status. Generate a log message, then return.
#define sai_return_on_la_error_log(X, format, ...)                                                                                 \
    do {                                                                                                                           \
        if (X != LA_STATUS_SUCCESS) {                                                                                              \
            sai_log_error(SAI_API_UNSPECIFIED, format, ##__VA_ARGS__);                                                             \
            return to_sai_status(X);                                                                                               \
        }                                                                                                                          \
    } while (0);

#define SGET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, NAME, ...) NAME
#define sai_return_on_la_error(...)                                                                                                \
    SGET_MACRO(__VA_ARGS__,                                                                                                        \
               sai_return_on_la_error_log,                                                                                         \
               sai_return_on_la_error_log,                                                                                         \
               sai_return_on_la_error_log,                                                                                         \
               sai_return_on_la_error_log,                                                                                         \
               sai_return_on_la_error_log,                                                                                         \
               sai_return_on_la_error_log,                                                                                         \
               sai_return_on_la_error_log,                                                                                         \
               sai_return_on_la_error_no_log)                                                                                      \
    (__VA_ARGS__)

///@brief check status. Return immediately on failure.
#define sai_return_on_error_no_log(X)                                                                                              \
    do {                                                                                                                           \
        if (X != SAI_STATUS_SUCCESS) {                                                                                             \
            return X;                                                                                                              \
        }                                                                                                                          \
    } while (0)

///@brief Check status. Generate a log message, then return.
#define sai_return_on_error_log(X, format, ...)                                                                                    \
    do {                                                                                                                           \
        if (X != SAI_STATUS_SUCCESS) {                                                                                             \
            sai_log_error(SAI_API_UNSPECIFIED, format, ##__VA_ARGS__);                                                             \
            return X;                                                                                                              \
        }                                                                                                                          \
    } while (0);

#define SGET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, NAME, ...) NAME
#define sai_return_on_error(...)                                                                                                   \
    SGET_MACRO(__VA_ARGS__,                                                                                                        \
               sai_return_on_error_log,                                                                                            \
               sai_return_on_error_log,                                                                                            \
               sai_return_on_error_log,                                                                                            \
               sai_return_on_error_log,                                                                                            \
               sai_return_on_error_log,                                                                                            \
               sai_return_on_error_log,                                                                                            \
               sai_return_on_error_log,                                                                                            \
               sai_return_on_error_no_log)                                                                                         \
    (__VA_ARGS__)

///@brief check status, and break immediately if not success.
#define sai_break_on_error(X)                                                                                                      \
    {                                                                                                                              \
        if (X != SAI_STATUS_SUCCESS) {                                                                                             \
            break;                                                                                                                 \
        }                                                                                                                          \
    }

///@brief check status. Return immediately on failure.
#define la_return_on_error_no_log(X)                                                                                               \
    do {                                                                                                                           \
        if (X != LA_STATUS_SUCCESS) {                                                                                              \
            return X;                                                                                                              \
        }                                                                                                                          \
    } while (0)

///@brief Check status. Generate a log message, then return.
#define la_return_on_error_log(X, format, ...)                                                                                     \
    do {                                                                                                                           \
        if (X != LA_STATUS_SUCCESS) {                                                                                              \
            sai_log_error(SAI_API_UNSPECIFIED, format, ##__VA_ARGS__);                                                             \
            return X;                                                                                                              \
        }                                                                                                                          \
    } while (0);

#define SGET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, NAME, ...) NAME
#define la_return_on_error(...)                                                                                                    \
    SGET_MACRO(__VA_ARGS__,                                                                                                        \
               la_return_on_error_log,                                                                                             \
               la_return_on_error_log,                                                                                             \
               la_return_on_error_log,                                                                                             \
               la_return_on_error_log,                                                                                             \
               la_return_on_error_log,                                                                                             \
               la_return_on_error_log,                                                                                             \
               la_return_on_error_log,                                                                                             \
               la_return_on_error_no_log)                                                                                          \
    (__VA_ARGS__)

///@brief check status, and break immediately if not success.
#define la_break_on_error(X)                                                                                                       \
    {                                                                                                                              \
        la_status X = X;                                                                                                           \
        if (X != LA_STATUS_SUCCESS) {                                                                                              \
            break;                                                                                                                 \
        }                                                                                                                          \
    }

#define sai_check_object(laobj, objtype, sdev, msg, id)                                                                            \
    {                                                                                                                              \
        if (laobj.type != objtype || sdev == nullptr || sdev->m_dev == nullptr) {                                                  \
            sai_log_error(SAI_API_UNSPECIFIED, "Bad %s id 0x%lx", msg, id);                                                        \
            return SAI_STATUS_INVALID_PARAMETER;                                                                                   \
        }                                                                                                                          \
    }

#define la_check_object(laobj, objtype, sdev, msg, id)                                                                             \
    {                                                                                                                              \
        if (laobj.type != objtype || sdev == nullptr || sdev->m_dev == nullptr) {                                                  \
            sai_log_error(SAI_API_UNSPECIFIED, "Bad %s id 0x%lx", msg, id);                                                        \
            return LA_STATUS_EINVAL;                                                                                               \
        }                                                                                                                          \
    }

#define IS_SAI_SERVICE_PORT(laobj) (laobj.type == SAI_OBJECT_TYPE_PORT || laobj.type == SAI_OBJECT_TYPE_LAG)

namespace silicon_one
{
namespace sai
{

/*
 *  SAI operation type
 *  Values must start with 0 base and be without gaps
 */
typedef enum _sai_operation_t {
    SAI_OPERATION_CREATE,
    SAI_OPERATION_REMOVE,
    SAI_OPERATION_SET,
    SAI_OPERATION_GET,
    SAI_OPERATION_MAX
} sai_operation_t;

/*
 *  Attribute value types
 */
typedef enum _sai_attribute_value_type_t {
    SAI_ATTR_VAL_TYPE_UNDETERMINED,
    SAI_ATTR_VAL_TYPE_BOOL,
    SAI_ATTR_VAL_TYPE_CHARDATA,
    SAI_ATTR_VAL_TYPE_U8,
    SAI_ATTR_VAL_TYPE_S8,
    SAI_ATTR_VAL_TYPE_U16,
    SAI_ATTR_VAL_TYPE_S16,
    SAI_ATTR_VAL_TYPE_U32,
    SAI_ATTR_VAL_TYPE_S32,
    SAI_ATTR_VAL_TYPE_U64,
    SAI_ATTR_VAL_TYPE_S64,
    SAI_ATTR_VAL_TYPE_MAC,
    SAI_ATTR_VAL_TYPE_IPV4,
    SAI_ATTR_VAL_TYPE_IPV6,
    SAI_ATTR_VAL_TYPE_IPADDR,
    SAI_ATTR_VAL_TYPE_OID,
    SAI_ATTR_VAL_TYPE_OBJLIST,
    SAI_ATTR_VAL_TYPE_U32LIST,
    SAI_ATTR_VAL_TYPE_S32LIST,
    SAI_ATTR_VAL_TYPE_VLANLIST,
    SAI_ATTR_VAL_TYPE_ACLFIELD,
    SAI_ATTR_VAL_TYPE_ACLACTION,
    SAI_ATTR_VAL_TYPE_ACLCAPABILITY,
    SAI_ATTR_VAL_TYPE_ACLRESOURCE,
    SAI_ATTR_VAL_TYPE_PORTBREAKOUT,
    SAI_ATTR_VAL_TYPE_PTR,
    SAI_ATTR_VAL_TYPE_SWITCHTYPE,
    SAI_ATTR_VAL_TYPE_SYSPORTCONFIGINFO,
    SAI_ATTR_VAL_TYPE_SYSPORTCONFIGLIST,
    SAI_ATTR_VAL_TYPE_SYSPORTTYPE,
    SAI_ATTR_VAL_TYPE_MAPLIST,
    SAI_ATTR_VAL_TYPE_S32RANGE,
    SAI_ATTR_VAL_TYPE_U32RANGE
} sai_attribute_value_type_t;

typedef struct _sai_attribute_entry_t {
    sai_attr_id_t id;
    bool mandatory_on_create;
    bool valid_for_create;
    bool valid_for_set;
    bool valid_for_get;
    const char* attrib_name;
    sai_attribute_value_type_t type;
} sai_attribute_entry_t;

/**
 * @brief Switch notification table passed to the adapter via sai_initialize_switch()
 */
typedef struct _sai_switch_notification_t {
    sai_switch_state_change_notification_fn on_switch_state_change;
    sai_fdb_event_notification_fn on_fdb_event;
    sai_port_state_change_notification_fn on_port_state_change;
    sai_switch_shutdown_request_notification_fn on_switch_shutdown_request;
    sai_packet_event_notification_fn on_packet_event;
    sai_tam_event_notification_fn on_tam_event;
    sai_queue_pfc_deadlock_notification_fn on_queue_pfc_deadlock;
} sai_switch_notification_t;

#define SAI_TYPE_CHECK_RANGE(type) (type < SAI_OBJECT_TYPE_MAX)

#define SAI_TYPE_STR(type) SAI_TYPE_CHECK_RANGE(type) ? sai_type2str_arr[type] : "Unknown object type"

static __attribute__((__used__)) const char* sai_type2str_arr[] = {
    /* SAI_OBJECT_TYPE_NULL = 0 */
    "NULL type",

    /*SAI_OBJECT_TYPE_PORT = 1 */
    "Port type",

    /*SAI_OBJECT_TYPE_LAG = 2 */
    "LAG type",

    /*SAI_OBJECT_TYPE_VIRTUAL_ROUTER = 3 */
    "Virtual router type",

    /* SAI_OBJECT_TYPE_NEXT_HOP = 4 */
    "Next hop type",

    /* SAI_OBJECT_TYPE_NEXT_HOP_GROUP = 5 */
    "Next hop group type",

    /* SAI_OBJECT_TYPE_ROUTER_INTERFACE = 6 */
    "Router interface type",

    /* SAI_OBJECT_TYPE_ACL_TABLE = 7 */
    "ACL table type",

    /* SAI_OBJECT_TYPE_ACL_ENTRY = 8 */
    "ACL entry type",

    /* SAI_OBJECT_TYPE_ACL_COUNTER = 9 */
    "ACL counter type",

    /* SAI_OBJECT_TYPE_HOST_INTERFACE = 10 */
    "Host interface type",

    /* SAI_OBJECT_TYPE_MIRROR = 11 */
    "Mirror type",

    /* SAI_OBJECT_TYPE_SAMPLEPACKET = 12 */
    "Sample packet type",

    /* SAI_OBJECT_TYPE_STP_INSTANCE = 13 */
    "Stp instance type"

    /* SAI_OBJECT_TYPE_MAX = 14 */
};

typedef sai_status_t (*sai_attribute_set_fn)(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);
typedef union {
    int dummy;
} vendor_cache_t;
typedef sai_status_t (*sai_attribute_get_fn)(_In_ const sai_object_key_t* key,
                                             _Inout_ sai_attribute_value_t* value,
                                             _In_ uint32_t attr_index,
                                             _Inout_ vendor_cache_t* cache,
                                             void* arg);
typedef struct _sai_vendor_attribute_entry_t {
    sai_attr_id_t id;
    bool is_implemented[SAI_OPERATION_MAX];
    bool is_supported[SAI_OPERATION_MAX];
    sai_attribute_get_fn getter;
    void* getter_arg;
    sai_attribute_set_fn setter;
    void* setter_arg;
} sai_vendor_attribute_entry_t;

typedef sai_status_t (*attr_enum_info_fn)(int32_t* attrs, uint32_t* count);
typedef struct _attr_enum_info_t {
    int32_t* attrs;
    uint32_t count;
    bool all;
    attr_enum_info_fn fn;
} attr_enum_info_t;
typedef struct _obj_type_attrs_enum_infos_t {
    const attr_enum_info_t* info;
    uint32_t count;
} obj_type_attrs_enums_info_t;
typedef struct _obj_type_attrs_info_t {
    const sai_vendor_attribute_entry_t* vendor_data;
    const obj_type_attrs_enums_info_t enums_info;
} obj_type_attrs_info_t;

#define END_FUNCTIONALITY_ATTRIBS_ID 0xFFFFFFFF

sai_status_t check_attribs_metadata(_In_ uint32_t attr_count,
                                    _In_ const sai_attribute_t* attr_list,
                                    _In_ const sai_attribute_entry_t* functionality_attr,
                                    _In_ const sai_vendor_attribute_entry_t* functionality_vendor_attr,
                                    _In_ sai_operation_t oper);

sai_status_t find_attrib_in_list(_In_ uint32_t attr_count,
                                 _In_ const sai_attribute_t* attr_list,
                                 _In_ sai_attr_id_t attrib_id,
                                 _Out_ const sai_attribute_value_t** attr_value,
                                 _Out_ uint32_t* index);

sai_status_t sai_create_and_set_attribute(_In_ const sai_object_key_t* key,
                                          _In_ const char* key_str,
                                          _In_ const sai_attribute_entry_t* functionality_attr,
                                          _In_ const sai_vendor_attribute_entry_t* functionality_vendor_attr,
                                          _In_ const sai_attribute_t* attr);

sai_status_t sai_set_attribute(_In_ const sai_object_key_t* key,
                               _In_ const char* key_str,
                               _In_ const sai_attribute_entry_t* functionality_attr,
                               _In_ const sai_vendor_attribute_entry_t* functionality_vendor_attr,
                               _In_ const sai_attribute_t* attr);

sai_status_t sai_get_attributes(_In_ const sai_object_key_t* key,
                                _In_ const char* key_str,
                                _In_ const sai_attribute_entry_t* functionality_attr,
                                _In_ const sai_vendor_attribute_entry_t* functionality_vendor_attr,
                                _In_ uint32_t attr_count,
                                _Inout_ sai_attribute_t* attr_list);

#define MAX_KEY_STR_LEN 100
#define MAX_VALUE_STR_LEN 100
#define MAX_LIST_VALUE_STR_LEN 1000

#define PORT_NUMBER 32

sai_status_t sai_value_to_str(_In_ sai_attribute_value_t value,
                              _In_ sai_attribute_value_type_t type,
                              _In_ uint32_t max_length,
                              _Out_ char* value_str);
sai_status_t sai_attr_list_to_str(_In_ uint32_t attr_count,
                                  _In_ const sai_attribute_t* attr_list,
                                  _In_ const sai_attribute_entry_t* functionality_attr,
                                  _In_ uint32_t max_length,
                                  _Out_ char* list_str);
sai_status_t sai_ipprefix_to_str(_In_ sai_ip_prefix_t value, _In_ uint32_t max_length, _Out_ char* value_str);
sai_status_t sai_ipaddr_to_str(_In_ sai_ip_address_t value,
                               _In_ uint32_t max_length,
                               _Out_ char* value_str,
                               _Out_ int* chars_written);
sai_status_t sai_nexthops_to_str(_In_ uint32_t next_hop_count,
                                 _In_ const sai_object_id_t* nexthops,
                                 _In_ uint32_t max_length,
                                 _Out_ char* str);

template <class BidirIt, class OutputIt>
OutputIt
reverse_copy(BidirIt first, BidirIt last, OutputIt d_first)
{
    while (first != last) {
        *(d_first++) = *(--last);
    }
    return d_first;
}

template <class BidirIt>
void
reverse(BidirIt first, BidirIt last)
{
    while ((first != last) && (first != --last)) {
        std::iter_swap(first++, last);
    }
}

template <class T>
static void
cartesion_product_append(std::vector<std::vector<T>>& result, const std::vector<T>& expansion)
{
    size_t width = expansion.size();

    // Make a copy of each elem in result for each elem in expansion
    for (auto r_it = result.begin(); r_it != result.end(); r_it += width) {
        r_it = result.insert(r_it, width - 1, *r_it);
    }

    // Append each elem in expansion onto each set of expanded results
    for (auto r_it = result.begin(); r_it != result.end();) {
        for (auto e_it = expansion.begin(); e_it != expansion.end(); e_it++, r_it++) {
            (*r_it).push_back(*e_it);
        }
    }
}

template <class ForwardIt, typename OutputList>
sai_status_t
fill_sai_list(ForwardIt first, ForwardIt last, OutputList& output)
{
    size_t count = std::distance(first, last);
    if (count > output.count) {
        output.count = count;
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    std::copy(first, last, output.list);
    output.count = count;

    return SAI_STATUS_SUCCESS;
}

template <typename ForwardIt, typename OutputList, typename Func>
sai_status_t
fill_sai_list(ForwardIt first, ForwardIt last, OutputList& output, Func transform)
{
    size_t count = std::distance(first, last);
    if (count > output.count) {
        output.count = count;
        return SAI_STATUS_BUFFER_OVERFLOW;
    }

    std::transform(first, last, output.list, transform);
    output.count = count;

    return SAI_STATUS_SUCCESS;
}

extern uint32_t ip_mask_to_length(uint32_t mask);
extern uint32_t ipv6_mask_to_length(const sai_ip6_t& mask);
extern void ipv4_prefix_length_to_mask(uint8_t prefix_length, sai_ip4_t& mask);
extern void ipv6_prefix_length_to_mask(uint8_t prefix_length, sai_ip6_t& mask);

const sai_attribute_entry_t* obj_type_attr_info_get(_In_ sai_object_type_t object_type);

template <typename T>
std::string
attr_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = static_cast<T>(attr.id);

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

uint32_t to_sai_lane(const sai_system_port_config_t& sp_config);
uint32_t to_sai_lane(uint32_t slice_id, uint32_t ifg_id, uint32_t pif);

inline la_ip_addr
to_sdk(const sai_ip_address_t& in_addr)
{
    using namespace std;

    if (in_addr.addr_family == SAI_IP_ADDR_FAMILY_IPV6) {
        la_ipv6_addr_t out_addr;
        reverse_copy(begin(in_addr.addr.ip6), end(in_addr.addr.ip6), begin(out_addr.b_addr));
        return {out_addr};
    } else {
        la_ipv4_addr_t out_addr{.s_addr = ntohl(in_addr.addr.ip4)};
        return {out_addr};
    }
}

bool continue_on_failure(uint32_t from, uint32_t object_count, sai_bulk_op_error_mode_t mode, sai_status_t* object_statuses);
}
}
#endif
