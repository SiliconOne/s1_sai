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

%module saicli
%include "sai_constants.h"
%include "sai_extra_apis.h"
%include "sai_constants.h"
%include <sai_attr_ext.h>

%{
extern "C" {
#include <sai.h>
#include <sai_attr_ext.h>
}
#include "sai_extra_apis.h"
#include "sai_test_utils.h"
#include "sai_device.h"

#include <sstream>
#include <unordered_map>
#include <vector>
#include <arpa/inet.h>

#define CONFIG_FILE_PATH_LEN 200
#define ACL_KEY_PROFILE_FILE_PATH_LEN 200
#define SAI_MAX_PUNT_PKT_LEN 8192 * 2
// Below global variables are used to communicate packet attributes to Python
int sai_num_punt_pkts = 0;
char sai_last_punt_pkt[SAI_MAX_PUNT_PKT_LEN];
uint64_t sai_last_punt_pkt_sip = 0;
uint64_t sai_last_punt_pkt_inglag = 0;
uint64_t sai_last_punt_pkt_trap_id = 0;
uint64_t sai_last_punt_pkt_dst_port = 0;
int g_sai_boot_type = 0; // communicate boot type from Python to SAI
int g_sai_warm_boot_type = 0; // communicate warm boot type from Python to SAI

using namespace silicon_one::sai;

void dump_event_counters(sai_object_id_t switch_id)
{
    lsai_object la_sw(switch_id);
    auto sdev = la_sw.get_device();

    return sdev->dump_event_counters();
}

uint32_t get_sai_version_number()
{
#ifdef SAI_VERSION_152
    return 0x01050200;
#else
#ifdef SAI_VERSION_181
    return 0x01080100;
#else
#ifdef SAI_VERSION_1811
    return 0x01080101;
#else
    return 0x01070100;
#endif
#endif
#endif
}

std::string get_hw_device_type(sai_object_id_t switch_id) {
    lsai_object la_sw(switch_id);
    auto sdev = la_sw.get_device();

    return sdev->get_hw_device_type_str();
}

template <class T>
static void dict_set(PyObject* dict, const char* string, T val) {
    PyDict_SetItem(dict, PyString_FromString(string), PyInt_FromLong(val));
}

PyObject* get_dev_params(sai_object_id_t switch_id) {
    lsai_object la_sw(switch_id);
    auto sdev = la_sw.get_device();

    device_params dp = sdev->m_dev_params;
    PyObject *ret_dict = PyDict_New();
    dict_set(ret_dict, "slices_per_dev", dp.slices_per_dev);
    dict_set(ret_dict, "sms_packet_buffer_memory", dp.sms_packet_buffer_memory);

    return ret_dict;
}

void
sai_packet_event_callback(sai_object_id_t switchid,
                          sai_size_t buffer_size,
                          const void* buffer,
                          uint32_t attr_count,
                          const sai_attribute_t* attr_list)
{
    char bin_to_hex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    sai_num_punt_pkts += 1;

    sai_last_punt_pkt_sip = 0;
    sai_last_punt_pkt_inglag = 0;
    sai_last_punt_pkt_trap_id = 0;
    sai_last_punt_pkt_dst_port = 0;

    for (uint32_t i = 0; i < attr_count; i++) {
        switch(attr_list[i].id) {
        case SAI_HOSTIF_PACKET_ATTR_INGRESS_PORT:
            sai_last_punt_pkt_sip = attr_list[i].value.oid;
            break;
        case SAI_HOSTIF_PACKET_ATTR_INGRESS_LAG:
            sai_last_punt_pkt_inglag = attr_list[i].value.oid;
            break;
        case SAI_HOSTIF_PACKET_ATTR_HOSTIF_TRAP_ID:
            sai_last_punt_pkt_trap_id = attr_list[i].value.oid;
            break;
        case SAI_HOSTIF_PACKET_ATTR_EGRESS_PORT_OR_LAG:
            sai_last_punt_pkt_dst_port = attr_list[i].value.oid;
            break;
        default:
            // unsupported attribute?
            break;
        }
    }

    // Transform binary packet to hex string to be handled by Python
    for (sai_size_t i = 0; i < buffer_size; i++) {
        sai_last_punt_pkt[i * 2] = bin_to_hex[((unsigned char *)buffer)[i] >> 4];
        sai_last_punt_pkt[i * 2 + 1] = bin_to_hex[((unsigned char *)buffer)[i] & 0xf];
    }
    for (sai_size_t i = 2 * buffer_size; i < sizeof(sai_last_punt_pkt); i++) {
        sai_last_punt_pkt[i] = 0;
    }
}

void mac_parse(const std::string& input, uint8_t *mac) {
     if (input.length() < 4 + 6 * 2) {
         PyErr_SetString(PyExc_RuntimeError, "mac address too short");
     }

    uint8_t hex_num;
    for (int i = 4, j = 0; j < 6; i += 2, j++) {
        if (input[i] >= 'a' && input[i] <= 'f') {
            hex_num = ((input[i] - 'a' + 10) << 4);
        } else if (input[i] >= 'A' && input[i] <= 'F') {
            hex_num = ((input[i] - 'A' + 10) << 4);
        } else {
            hex_num = ((input[i] - '0') << 4);
        }
        if (input[i + 1] >= 'a' && input[i + 1] <= 'f') {
            hex_num += input[i+1] - 'a' + 10;
        } else if (input[i + 1] >= 'a' && input[i + 1] <= 'f') {
            hex_num += input[i+1] - 'A' + 10;
        } else {
            hex_num += input[i+1] - '0';
        }
        mac[j] = hex_num;
    }
}

sai_status_t
    sai_get_object_key(sai_object_id_t switch_id, sai_object_type_t object_type, uint32_t *object_count, unsigned long int* uint64_list) {
    sai_object_key_t object_list[*object_count];
    uint32_t list_count = *object_count;
    sai_status_t status = sai_get_object_key(switch_id, object_type, &list_count, object_list);
    if (status == SAI_STATUS_SUCCESS) {
        for (uint32_t i = 0; i < *object_count; i++) {
            uint64_list[i] = object_list[i].key.object_id;
        }
    }
    return status;
}

sai_status_t
    sai_get_object_key(sai_object_id_t switch_id, sai_object_type_t object_type, uint32_t *object_count, _sai_fdb_entry_t* fdb_entry_list) {
    sai_object_key_t object_list[*object_count];
    uint32_t list_count = *object_count;
    if (object_type != SAI_OBJECT_TYPE_FDB_ENTRY) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (sai_get_object_key(switch_id, object_type, &list_count, object_list) == SAI_STATUS_SUCCESS) {
        for (uint32_t i = 0; i < *object_count; i++) {
            fdb_entry_list[i].switch_id = object_list[i].key.fdb_entry.switch_id;
            fdb_entry_list[i].bv_id = object_list[i].key.fdb_entry.bv_id;
            memcpy(&fdb_entry_list[i].mac_address, object_list[i].key.fdb_entry.mac_address, sizeof(sai_mac_t));
        }
        return SAI_STATUS_SUCCESS;
    }

    return SAI_STATUS_FAILURE;
}

sai_status_t
    sai_get_object_key(sai_object_id_t switch_id, sai_object_type_t object_type, uint32_t *object_count, _sai_route_entry_t* route_entry_list) {
    sai_object_key_t object_list[*object_count];
    uint32_t list_count = *object_count;
    if (object_type != SAI_OBJECT_TYPE_ROUTE_ENTRY) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (sai_get_object_key(switch_id, object_type, &list_count, object_list) == SAI_STATUS_SUCCESS) {
        for (uint32_t i = 0; i < *object_count; i++) {
            route_entry_list[i].switch_id = object_list[i].key.route_entry.switch_id;
            route_entry_list[i].vr_id = object_list[i].key.route_entry.vr_id;
            route_entry_list[i].destination.addr_family = object_list[i].key.route_entry.destination.addr_family;
            if (object_list[i].key.route_entry.destination.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
                route_entry_list[i].destination.addr.ip4 = object_list[i].key.route_entry.destination.addr.ip4;
                route_entry_list[i].destination.mask.ip4 = object_list[i].key.route_entry.destination.mask.ip4;
            } else {
                memcpy(route_entry_list[i].destination.addr.ip6, object_list[i].key.route_entry.destination.addr.ip6, 16);
                memcpy(route_entry_list[i].destination.mask.ip6, object_list[i].key.route_entry.destination.mask.ip6, 16);
            }
        }
        return SAI_STATUS_SUCCESS;
    }

    return SAI_STATUS_FAILURE;
}

sai_status_t
    sai_get_object_key(sai_object_id_t switch_id, sai_object_type_t object_type, uint32_t *object_count, _sai_neighbor_entry_t* neighbor_entry_list) {
    sai_object_key_t object_list[*object_count];
    uint32_t list_count = *object_count;
    if (object_type != SAI_OBJECT_TYPE_NEIGHBOR_ENTRY) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    if (sai_get_object_key(switch_id, object_type, &list_count, object_list) == SAI_STATUS_SUCCESS) {
        for (uint32_t i = 0; i < *object_count; i++) {
            neighbor_entry_list[i].switch_id = object_list[i].key.neighbor_entry.switch_id;
            neighbor_entry_list[i].rif_id = object_list[i].key.neighbor_entry.rif_id;
            neighbor_entry_list[i].ip_address.addr_family = object_list[i].key.neighbor_entry.ip_address.addr_family;
            if (object_list[i].key.neighbor_entry.ip_address.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
                neighbor_entry_list[i].ip_address.addr.ip4 = object_list[i].key.neighbor_entry.ip_address.addr.ip4;
            } else {
                memcpy(neighbor_entry_list[i].ip_address.addr.ip6, object_list[i].key.neighbor_entry.ip_address.addr.ip6, 16);
            }
        }
        return SAI_STATUS_SUCCESS;
    }

    return SAI_STATUS_FAILURE;
}

std::unordered_map<sai_object_id_t, uint32_t> sai_tam_event_msg_counters;
uint32_t sai_tam_event_ecc_cor_counter = 0;
uint32_t sai_tam_event_ecc_uncor_counter = 0;
uint32_t sai_tam_event_parity_counter = 0;
uint32_t sai_tam_event_decode_error = 0;

void
sai_tam_event_callback(sai_object_id_t tam_oid,
                       sai_size_t buffer_size,
                       const void *buffer,
                       uint32_t attr_count,
                       const sai_attribute_t *attr_list)
{
    auto found = sai_tam_event_msg_counters.find(tam_oid);
    if (found == sai_tam_event_msg_counters.end()) {
        sai_tam_event_msg_counters[tam_oid] = 0;
    }
    sai_tam_event_msg_counters[tam_oid] += buffer_size;

    for(sai_size_t i=0; i<buffer_size; i++) {
        sai_tam_event_desc_t desc = ((sai_tam_event_desc_t *)buffer)[i];
        if (desc.type == SAI_TAM_EVENT_TYPE_SWITCH && desc.event.switch_event.type == SAI_SWITCH_EVENT_TYPE_PARITY_ERROR) {
            if (desc.event.switch_event.data.parity_error.err_type == ECC_COR) {
                sai_tam_event_ecc_cor_counter++;
            }
            else if (desc.event.switch_event.data.parity_error.err_type == ECC_UNCOR) {
                sai_tam_event_ecc_uncor_counter++;
            }
            else if (desc.event.switch_event.data.parity_error.err_type == PARITY) {
                sai_tam_event_parity_counter++;
            } else {
                sai_tam_event_decode_error++;
            }
        } else {
            sai_tam_event_decode_error++;
        }
    }
}

uint32_t get_sai_tam_event_msg_counts (sai_object_id_t tam_oid)
{
    auto found = sai_tam_event_msg_counters.find(tam_oid);
    if (found == sai_tam_event_msg_counters.end()) {
        return 0;
    }

    return sai_tam_event_msg_counters[tam_oid];
}

void set_sai_tam_event_msg_counts (sai_object_id_t tam_oid, uint32_t counts)
{
    sai_tam_event_msg_counters[tam_oid] = counts;
}

uint32_t get_sai_tam_event_msg_total_counts ()
{
    uint32_t total_counts = 0;
    for(auto tam_counter : sai_tam_event_msg_counters) {
        total_counts += tam_counter.second;
    }

    return total_counts;
}

void clear_sai_tam_event_msg_counts ()
{
    sai_tam_event_msg_counters.clear();
}

std::unordered_map<sai_object_id_t, uint32_t> sai_port_state_up_msg_counters;
std::unordered_map<sai_object_id_t, uint32_t> sai_port_state_down_msg_counters;
std::unordered_map<sai_object_id_t, bool> sai_port_state_up;

uint32_t sai_port_state_change_error_msg = 0;

void
sai_port_state_change_callback(uint32_t count, const sai_port_oper_status_notification_t* data)
{
    for (uint32_t idx = 0; idx < count; idx++) {
        switch(data[idx].port_state) {
            case sai_port_oper_status_t::SAI_PORT_OPER_STATUS_UP: {
                auto found = sai_port_state_up_msg_counters.find(data[idx].port_id);
                if (found == sai_port_state_up_msg_counters.end()) {
                    sai_port_state_up_msg_counters[data[idx].port_id] = 0;
                }
                sai_port_state_up_msg_counters[data[idx].port_id]++;
                sai_port_state_up[data[idx].port_id] = true;
                break;
            }
            case sai_port_oper_status_t::SAI_PORT_OPER_STATUS_DOWN: {
                auto found = sai_port_state_down_msg_counters.find(data[idx].port_id);
                if (found == sai_port_state_down_msg_counters.end()) {
                    sai_port_state_down_msg_counters[data[idx].port_id] = 0;
                }
                sai_port_state_down_msg_counters[data[idx].port_id]++;
                sai_port_state_up[data[idx].port_id] = false;
                break;
            }
            default:
                sai_port_state_change_error_msg++; break;
        }
    }
}

bool is_sai_port_state_up (sai_object_id_t sai_port_id)
{
    auto found = sai_port_state_up.find(sai_port_id);
    if (found == sai_port_state_up.end()) {
        return false;
    }

    return sai_port_state_up[sai_port_id];
}

// we need this function to override the sai_port_state_up stage, beucase SDK does not send message when la_mac_port::stop() is called.
bool set_sai_port_state_up (sai_object_id_t sai_port_id, bool state_up)
{
    auto found = sai_port_state_up.find(sai_port_id);
    if (found == sai_port_state_up.end()) {
        return false;
    }

    sai_port_state_up[sai_port_id] = state_up;

    return true;
}


uint32_t get_sai_port_state_up_msg_counts (sai_object_id_t sai_port_id)
{
    // Not tested yet
    auto found = sai_port_state_up_msg_counters.find(sai_port_id);
    if (found == sai_port_state_up_msg_counters.end()) {
        return 0;
    }

    return sai_port_state_up_msg_counters[sai_port_id];
}

uint32_t get_sai_port_state_down_msg_counts (sai_object_id_t sai_port_id)
{
    // Not tested yet
    auto found = sai_port_state_down_msg_counters.find(sai_port_id);
    if (found == sai_port_state_down_msg_counters.end()) {
        return 0;
    }

    return sai_port_state_down_msg_counters[sai_port_id];
}

void clear_all_sai_port_state_msg_counts ()
{
    sai_port_state_up_msg_counters.clear();
    sai_port_state_down_msg_counters.clear();
}

static const char DEFAULT_RES_DIR[] = "res/";
static const char RES_OUTPUT_DIR_ENVVAR[] = "RES_OUTPUT_DIR";
char config_file_name[CONFIG_FILE_PATH_LEN] = "config/sherman_p5.json";
char acl_key_profile_file_name[ACL_KEY_PROFILE_FILE_PATH_LEN] = "config/acl_key_profile.json";
char g_warm_boot_base_file_name[CONFIG_FILE_PATH_LEN] = "warmboot_dump";

const char*
profile_get_value(sai_switch_profile_id_t profile_id, const char* variable)
{
    const char* res_outdir_env = getenv(RES_OUTPUT_DIR_ENVVAR);
    std::stringstream config_file_full_path;
    std::stringstream acl_key_profile_file_full_path;
    std::stringstream str_boot_type;
    std::stringstream str_warm_boot_type;
    std::stringstream str_warm_boot_file_name;

    str_warm_boot_file_name << g_warm_boot_base_file_name;

    str_boot_type << g_sai_boot_type;
    str_warm_boot_type << g_sai_warm_boot_type;

    if (config_file_name[0] == '/') {
        // this is absolute path
        config_file_full_path << config_file_name;
    }
    else if (res_outdir_env) {
        config_file_full_path << res_outdir_env << "/" << config_file_name;
    } else {
        config_file_full_path << DEFAULT_RES_DIR << config_file_name;
    }

    if (res_outdir_env) {
        acl_key_profile_file_full_path << res_outdir_env << "/" << acl_key_profile_file_name;
    } else {
        acl_key_profile_file_full_path << DEFAULT_RES_DIR << acl_key_profile_file_name;
    }

    static std::unordered_map<std::string, std::string> sai_key_map = {
        {SAI_KEY_NUM_QUEUES, "256"}
    };

    // This is not static info. Can by changed by Python code
    sai_key_map[SAI_KEY_BOOT_TYPE] = str_boot_type.str();
    sai_key_map[SAI_KEY_EXT_WARM_BOOT_TYPE] = str_warm_boot_type.str();
    sai_key_map[SAI_KEY_INIT_CONFIG_FILE] = config_file_full_path.str();
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    sai_key_map[SAI_ACL_KEY_PROFILE_FILE] = acl_key_profile_file_full_path.str();
#endif
    sai_key_map[SAI_KEY_WARM_BOOT_READ_FILE] = str_warm_boot_file_name.str();
    sai_key_map[SAI_KEY_WARM_BOOT_WRITE_FILE] = str_warm_boot_file_name.str();
    // Callback to the test code for non-existent value should be fatal
    if (sai_key_map.find(variable) == sai_key_map.end()) {
        return nullptr;
    } else {
    return sai_key_map.at(variable).c_str();
  }
}

void
sai_fdb_evt_callback(uint32_t count, const sai_fdb_event_notification_data_t* data)
{
    sai_fdb_evt(count, data);
}

void
sai_queue_pfc_deadlock_event_callback(uint32_t count,
                                      const sai_queue_deadlock_notification_data_t* data)
{
    sai_queue_pfc_deadlock_evt(count, data);
}
%}

#define SWIGWORDSIZE64 1
%include exception.i
%include stdint.i
%include std_string.i
%include typemaps.i
%include "carrays.i"
%include std_vector.i

%inline %{
    extern int sai_num_punt_pkts;
    extern char sai_last_punt_pkt[SAI_MAX_PUNT_PKT_LEN];
    extern uint64_t sai_last_punt_pkt_sip;
    extern uint64_t sai_last_punt_pkt_inglag;
    extern uint64_t sai_last_punt_pkt_dst_port;
    extern char config_file_name[CONFIG_FILE_PATH_LEN];
    extern uint32_t sai_port_state_change_error_msg;
    extern uint64_t sai_last_punt_pkt_trap_id;
    extern int g_sai_boot_type;
    extern int g_sai_warm_boot_type;
    extern uint32_t sai_tam_event_ecc_cor_counter;
    extern uint32_t sai_tam_event_ecc_uncor_counter;
    extern uint32_t sai_tam_event_parity_counter;
    extern uint32_t sai_tam_event_decode_error;

    extern PyObject* get_dev_params(sai_object_id_t switch_id);
    extern std::string get_hw_device_type (sai_object_id_t switch_id);
    extern bool is_sai_port_state_up (sai_object_id_t sai_port_id);
    extern bool set_sai_port_state_up (sai_object_id_t sai_port_id, bool state_up);
    extern uint32_t get_sai_port_state_up_msg_counts (sai_object_id_t sai_port_id);
    extern uint32_t get_sai_port_state_down_msg_counts (sai_object_id_t sai_port_id);
    extern void clear_all_sai_port_state_msg_counts ();
    extern void dump_event_counters(sai_object_id_t switch_id);
    extern uint32_t get_sai_version_number ();
    extern uint32_t get_sai_tam_event_msg_counts (sai_object_id_t tam_oid);
    extern void set_sai_tam_event_msg_counts (sai_object_id_t tam_oid, uint32_t counts);
    extern uint32_t get_sai_tam_event_msg_total_counts ();
    extern void clear_sai_tam_event_msg_counts ();
%}

// sai_py_... structs are for translating sai types to Python recognizable types
%inline %{
    template<typename list_type>
        PyObject *sai_py_int_list(list_type int_list) {
        PyObject *ret_list = PyList_New(0);
        for (uint32_t i = 0; i < int_list.count; i++) {
            PyList_Append(ret_list, PyInt_FromLong(int_list.list[i]));
        }

        return ret_list;

    }

    PyObject *sai_py_bytes_list(sai_s8_list_t int_list) {
        return PyBytes_FromStringAndSize((char *)int_list.list, int_list.count);
    }

    // for getting back mac address from attribute as "xx:xx:xx:xx:xx:xx" Python string
    typedef struct _sai_py_mac_t {
        char addr[18];
    } sai_py_mac_t;

    // for getting back IP address in attribute as IPv4/6 formatted Python string
    typedef struct _sai_py_ip_t {
        char addr[100];
    } sai_py_ip_t;

    typedef struct _sai_py_qos_map_list_t {
        PyObject *list;
    } sai_py_qos_map_list_t;

    typedef struct _sai_py_map_list_t {
        PyObject *list;
    } sai_py_map_list_t;

    extern int sai_num_punt_pkts;
    extern char sai_last_punt_pkt[SAI_MAX_PUNT_PKT_LEN];
    extern uint64_t sai_last_punt_pkt_sip;
    extern uint64_t sai_last_punt_pkt_inglag;
    extern uint64_t sai_last_punt_pkt_dst_port;
    extern char config_file_name[CONFIG_FILE_PATH_LEN];
    extern char g_warm_boot_base_file_name[CONFIG_FILE_PATH_LEN];
    extern uint64_t sai_last_punt_pkt_trap_id;
%}

%template(sai_py_object_list) sai_py_int_list<sai_object_list_t>;
%template(sai_py_s32_list) sai_py_int_list<sai_s32_list_t>;
%template(sai_py_u32_list) sai_py_int_list<sai_u32_list_t>;
%template(sai_py_s16_list) sai_py_int_list<sai_s16_list_t>;
%template(sai_py_u16_list) sai_py_int_list<sai_u16_list_t>;
%template(sai_py_u8_list) sai_py_int_list<sai_u8_list_t>;

%extend _sai_py_qos_map_list_t {
    _sai_py_qos_map_list_t(sai_qos_map_list_t qos_map_list) {
        sai_py_qos_map_list_t *sl =
            (sai_py_qos_map_list_t *) malloc(sizeof(sai_py_qos_map_list_t));

        PyObject *outer_list = PyList_New(0);
        sl->list = outer_list;

        for (uint32_t i = 0; i < qos_map_list.count; i++) {
            PyObject *key_val_list = PyList_New(0);
            PyObject *key_list = PyList_New(0);
            PyObject *val_list = PyList_New(0);

            PyList_Append(val_list, PyInt_FromLong(qos_map_list.list[i].value.tc));
            PyList_Append(val_list, PyInt_FromLong(qos_map_list.list[i].value.dscp));
            PyList_Append(val_list, PyInt_FromLong(qos_map_list.list[i].value.dot1p));
            PyList_Append(val_list, PyInt_FromLong(qos_map_list.list[i].value.prio));
            PyList_Append(val_list, PyInt_FromLong(qos_map_list.list[i].value.pg));
            PyList_Append(val_list, PyInt_FromLong(qos_map_list.list[i].value.queue_index));
            PyList_Append(val_list, PyInt_FromLong(int(qos_map_list.list[i].value.color)));
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
            PyList_Append(val_list, PyInt_FromLong(qos_map_list.list[i].value.mpls_exp));
#endif

            PyList_Append(key_list, PyInt_FromLong(qos_map_list.list[i].key.tc));
            PyList_Append(key_list, PyInt_FromLong(qos_map_list.list[i].key.dscp));
            PyList_Append(key_list, PyInt_FromLong(qos_map_list.list[i].key.dot1p));
            PyList_Append(key_list, PyInt_FromLong(qos_map_list.list[i].key.prio));
            PyList_Append(key_list, PyInt_FromLong(qos_map_list.list[i].key.pg));
            PyList_Append(key_list, PyInt_FromLong(qos_map_list.list[i].key.queue_index));
            PyList_Append(key_list, PyInt_FromLong(int(qos_map_list.list[i].key.color)));
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
            PyList_Append(key_list, PyInt_FromLong(qos_map_list.list[i].key.mpls_exp));
#endif

            PyList_Append(key_val_list, key_list);
            PyList_Append(key_val_list, val_list);
            PyList_Append(outer_list, key_val_list);
        }

        return sl;
    }
 }

%extend _sai_py_map_list_t {
    _sai_py_map_list_t(sai_map_list_t map_list) {
        sai_py_map_list_t *sl =
            (sai_py_map_list_t *)malloc(sizeof(sai_py_map_list_t));

        PyObject *outer_list = PyList_New(0);
        PyObject *key_list = PyList_New(0);
        PyObject *val_list = PyList_New(0);
        PyList_Append(outer_list, key_list);
        PyList_Append(outer_list, val_list);

        sl->list = outer_list;

        for (uint32_t i = 0; i < map_list.count; i++) {
            PyList_Append(key_list, PyInt_FromLong(map_list.list[i].key));
            PyList_Append(val_list, PyInt_FromLong(map_list.list[i].value));
        }

        return sl;
    }
 }

%extend _sai_py_mac_t {
    _sai_py_mac_t(sai_attribute_t *attr) {
        uint8_t *mac = attr->value.mac;

        auto sl = new sai_py_mac_t();
        sprintf(sl->addr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return sl;
    }

    _sai_py_mac_t(sai_mac_t mac) {
        auto sl = new sai_py_mac_t();
        sprintf(sl->addr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return sl;
    }

    _sai_py_mac_t(sai_mac_t *mac_t) {
        uint8_t *mac = mac_t[0];
        auto sl = new sai_py_mac_t();
        sprintf(sl->addr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return sl;
    }

    _sai_py_mac_t(sai_uint8_t *mac_t) {
        uint8_t *mac = mac_t;
        auto sl = new sai_py_mac_t();
        sprintf(sl->addr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return sl;
    }
}

%extend _sai_py_ip_t {
    _sai_py_ip_t(sai_ip_address_t *ipaddr) {
        auto sl = new sai_py_ip_t();

        if (ipaddr->addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
            inet_ntop(AF_INET, &ipaddr->addr.ip4, sl->addr, sizeof(sl->addr));
        } else {
            inet_ntop(AF_INET6, &ipaddr->addr.ip6, sl->addr, sizeof(sl->addr));
        }
        return sl;
    }
 }

%callback("%s");
void
sai_packet_event_callback(sai_object_id_t switchid,
                          sai_size_t buffer_size,
                          const void* buffer,
                          uint32_t attr_count,
                          const sai_attribute_t* attr_list);

void
sai_tam_event_callback(sai_object_id_t tam_oid,
                       sai_size_t buffer_size,
                       const void *buffer,
                       uint32_t attr_count,
                       const sai_attribute_t *attr_list);


void sai_port_state_change_callback(uint32_t count, const sai_port_oper_status_notification_t* data);

void sai_queue_pfc_deadlock_event_callback(uint32_t count, const sai_queue_deadlock_notification_data_t* data);

const char* profile_get_value(sai_switch_profile_id_t profile_id, const char* variable);

void sai_fdb_evt_callback(uint32_t count, const sai_fdb_event_notification_data_t* data);

%nocallback;

%template(vectoru64) std::vector<uint64_t>;
%template(vectoru32) std::vector<uint32_t>;
%template(vectoru8) std::vector<uint8_t>;
%template(vectori32) std::vector<int32_t>;

// Conversion of sai_status_t to python exception
%typemap(out) sai_status_t {
    if (result != SAI_STATUS_SUCCESS) {
        std::ostringstream output;
        output << "SAI error: " << result;
        SWIG_exception(SWIG_RuntimeError, output.str().c_str());
        SWIG_fail;
    }

    $result = VOID_Object;
}

// for create_next_hop_group_members
%typemap(out) std::vector<std::pair<sai_object_id_t, sai_status_t>> {
    PyObject *ret_list = PyList_New(0);
    PyObject *obj_id_list = PyList_New(0);
    PyObject *status_list = PyList_New(0);

    for (uint32_t i = 0; i < $1.size(); i++) {
        PyList_Append(obj_id_list, PyInt_FromLong($1.at(i).first));
        PyList_Append(status_list, PyInt_FromLong($1.at(i).second));
    }

    PyList_Append(ret_list, status_list);
    PyList_Append(ret_list, obj_id_list);

    $result = ret_list;
}

// for remove_next_hop_group_members, create/remove/set_inseg_entries
%typemap(out) std::vector<sai_status_t> {
    PyObject *ret_list = PyList_New(0);

    for (uint32_t i = 0; i < $1.size(); i++) {
        PyList_Append(ret_list, PyInt_FromLong($1.at(i)));
    }

    $result = ret_list;
 }

// Conversion from python sai_object_id_t list to len, sai_object_id_t *
%typemap(in, numinputs=1) (uint32_t object_count, sai_object_id_t *object_ids) {
    if (!PySequence_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a list");
        SWIG_fail;
    }

    auto len = PySequence_Length($input);
    auto vec = new sai_object_id_t[len];

    for (int i = 0; i < len; i++) {
        PyObject *o = PySequence_GetItem($input,i);
        if (PyNumber_Check(o)) {
           vec[i] = (sai_object_id_t) PyInt_AsLong(o);
        } else {
            PyErr_SetString(PyExc_ValueError,"Sequence elements must be numbers");
           return nullptr;
        }
    }

    $1 = len;
    $2 = vec;
}

// Conversion from python sai_object_id_t list to object_count, const sai_object_id_t *
// Used in remove_next_hop_group_members
%typemap(in, numinputs=1) (uint32_t object_count, const sai_object_id_t *object_ids) {
    if (!PySequence_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a list");
        SWIG_fail;
    }

    auto len = PySequence_Length($input);
    auto vec = new sai_object_id_t[len];

    for (int i = 0; i < len; i++) {
        PyObject *o = PySequence_GetItem($input,i);
        if (PyNumber_Check(o)) {
            vec[i] = (sai_object_id_t) PyInt_AsLong(o);
        } else {
            PyErr_SetString(PyExc_ValueError,"Sequence elements must be numbers");
            return nullptr;
        }
    }

    $1 = len;
    $2 = vec;
 }

// Conversion from python int list to len, int32 *
%typemap(in, numinputs=1) (const uint32_t int_count, int32_t *int_list) {
    if (!PySequence_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a list");
        SWIG_fail;
    }

    auto len = PySequence_Length($input);
    auto vec = new int32_t[len];

    for (int i = 0; i < len; i++) {
        PyObject *o = PySequence_GetItem($input,i);
        if (PyNumber_Check(o)) {
           vec[i] = (int32_t) PyInt_AsLong(o);
        } else {
            PyErr_SetString(PyExc_ValueError,"Sequence elements must be numbers");
           return nullptr;
        }
    }

    $1 = len;
    $2 = vec;
}


// Conversion from python int list to len, uint32 *
%typemap(in, numinputs=1) (const uint32_t int_count, uint32_t *int_list) {
    if (!PySequence_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a list");
        SWIG_fail;
    }

    auto len = PySequence_Length($input);
    auto vec = new uint32_t[len];

    for (int i = 0; i < len; i++) {
        PyObject *o = PySequence_GetItem($input,i);
        if (PyNumber_Check(o)) {
           vec[i] = (uint32_t) PyInt_AsLong(o);
        } else {
            PyErr_SetString(PyExc_ValueError,"Sequence elements must be numbers");
           return nullptr;
        }
    }

    $1 = len;
    $2 = vec;
}

// Conversion from python int list to len, uint8_t *
%typemap(in, numinputs=1) (const uint32_t int_count, uint8_t *int_list) {
    if (!PySequence_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a list");
        SWIG_fail;
    }

    auto len = PySequence_Length($input);
    auto vec = new uint8_t[len];

    for (int i = 0; i < len; i++) {
        PyObject *o = PySequence_GetItem($input,i);
        if (PyNumber_Check(o)) {
            vec[i] = (uint8_t) PyInt_AsLong(o);
        } else {
            PyErr_SetString(PyExc_ValueError,"Sequence elements must be numbers");
            return nullptr;
        }
    }

    $1 = len;
    $2 = vec;
}

// Conversion from python int list to len, int8_t *
%typemap(in, numinputs=1) (const uint32_t int_count, int8_t *int_list) {
    if (!PySequence_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a list");
        SWIG_fail;
    }

    auto len = PySequence_Length($input);
    auto vec = new int8_t[len];

    for (int i = 0; i < len; i++) {
        PyObject *o = PySequence_GetItem($input,i);
        if (PyNumber_Check(o)) {
            vec[i] = (int8_t) PyInt_AsLong(o);
        } else {
            PyErr_SetString(PyExc_ValueError,"Sequence elements must be numbers");
            return nullptr;
        }
    }

    $1 = len;
    $2 = vec;
 }

%extend _sai_object_list_t {
    _sai_object_list_t(uint32_t object_count, sai_object_id_t *object_ids) {
        auto sl = new _sai_object_list_t();
        sl->count = object_count;
        sl->list = object_ids;
        return sl;
    }

    std::vector<sai_object_id_t> to_pylist() {
        std::vector<sai_object_id_t> return_vec;
        for (uint32_t i=0; i<$self->count; i++) {
            return_vec.push_back($self->list[i]);
        }
        return return_vec;
    }
}

%extend _sai_s32_list_t {
    _sai_s32_list_t(const uint32_t int_count, int32_t *int_list) {
        auto sl = new _sai_s32_list_t();
        sl->count = int_count;
        sl->list = int_list;
        return sl;
    }

    std::vector<int32_t> to_pylist() {
        std::vector<int32_t> return_vec;
        for (uint32_t i=0; i<$self->count; i++) {
            return_vec.push_back($self->list[i]);
        }
        return return_vec;
    }
}

%extend _sai_u32_list_t {
    _sai_u32_list_t(const uint32_t int_count, uint32_t *int_list) {
        auto sl = new _sai_u32_list_t();
        sl->count = int_count;
        sl->list = int_list;
        return sl;
    }

    std::vector<uint32_t> to_pylist() {
        std::vector<uint32_t> return_vec;
        for (uint32_t i=0; i<$self->count; i++) {
            return_vec.push_back($self->list[i]);
        }
        return return_vec;
    }
}

%extend _sai_u8_list_t {
    _sai_u8_list_t(const uint32_t int_count, uint8_t *int_list) {
        auto sl = new _sai_u8_list_t();
        sl->count = int_count;
        sl->list = int_list;
        return sl;
    }

    std::vector<uint8_t> to_pylist() {
        std::vector<uint8_t> return_vec;
        for (uint32_t i=0; i<$self->count; i++) {
            return_vec.push_back($self->list[i]);
        }
        return return_vec;
    }
}

%extend _sai_s8_list_t {
    _sai_s8_list_t(const uint32_t int_count, int8_t *int_list) {
        auto sl = new _sai_s8_list_t();
        sl->count = int_count;
        sl->list = int_list;
        return sl;
    }

    std::vector<int8_t> to_pylist() {
        std::vector<int8_t> return_vec;
        for (uint32_t i=0; i<$self->count; i++) {
            return_vec.push_back($self->list[i]);
        }
        return return_vec;
    }
}

%extend _sai_ip_address_t {
    _sai_ip_address_t(sai_ip4_t ip4) {
        auto ipaddr = new _sai_ip_address_t();
        ipaddr->addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        ipaddr->addr.ip4 = ip4;
        return ipaddr;
    }

    _sai_ip_address_t(sai_uint8_t* ipv6_addr) {
        auto ipaddr = new _sai_ip_address_t();
        ipaddr->addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(ipaddr->addr.ip6, ipv6_addr, 16);
        return ipaddr;
    }

    _sai_ip_address_t(sai_u8_list_t& ipv6_addr) {
        auto ipaddr = new _sai_ip_address_t();
        ipaddr->addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(ipaddr->addr.ip6, ipv6_addr.list, ipv6_addr.count);
        return ipaddr;
    }
}

 // Conversion from Python list of sai_stat_id_t to count, sai_stat_id_t *
// used by clear_*_stats functions
 %typemap(in, numinputs=1) (uint32_t number_of_counters, const sai_stat_id_t* counter_ids) {
    if (!PySequence_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a list");
        SWIG_fail;
    }

    auto len = PySequence_Length($input);
    auto vec = new sai_stat_id_t[len];

    for (uint32_t i = 0; i < len; ++i) {
        auto obj = PySequence_GetItem($input, i);
        if (PyNumber_Check(obj)) {
            vec[i] = (sai_stat_id_t) PyInt_AsLong(obj);
        } else {
            PyErr_SetString(PyExc_ValueError,"Sequence elements must be numbers");
            return NULL;
        }
    }

    $1 = len;
    $2 = vec;
}

// Conversion from python list to count, attr_list pair for sai setter attribute functions
%typemap(in, numinputs=1) (uint32_t attr_count, const sai_attribute_t *attr_list) {
    if (!PySequence_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a list");
        SWIG_fail;
    }

    auto len = PySequence_Length($input);
    auto vec = new sai_attribute_t[len];

    for (uint32_t i = 0; i < len; ++i) {
        sai_attribute_t* ptr;

        auto obj = PySequence_GetItem($input, i);
        auto res = SWIG_ConvertPtr(obj, (void**)&ptr, $descriptor(sai_attribute_t*), 0);
        if (!SWIG_IsOK(res)) {
            PyErr_SetString(PyExc_RuntimeError, "Failed to get attribute from sai attribute list");
            SWIG_fail;
        }

        if (ptr == 0) {
            break;
        }
        vec[i] = *ptr;
    }

    $1 = len;
    $2 = vec;
}

// Conversion from python list to count, attr_list pair for sai getter attribute functions
%typemap(in, numinputs=1) (uint32_t attr_count, sai_attribute_t *attr_list) {
    if (!PySequence_Check($input)) {
        $1 = 1;

        if ((SWIG_ConvertPtr($input,(void **) &$2, $2_descriptor,SWIG_POINTER_EXCEPTION)) == -1)
            return nullptr;
    }
    else {
        auto len = PySequence_Length($input);
        $2 = new sai_attribute_t[len];

        for (uint32_t i = 0; i < len; ++i) {
            sai_attribute_t* ptr;

            auto obj = PySequence_GetItem($input, i);
            auto res = SWIG_ConvertPtr(obj, (void**)&ptr, $descriptor(sai_attribute_t*), 0);
            if (!SWIG_IsOK(res)) {
                PyErr_SetString(PyExc_RuntimeError, "Failed to get attribute from sai attribute list");
                SWIG_fail;
            }

            if (ptr == 0) {
                break;
            }
            $2[i] = *ptr;
        }

        $1 = len;
    }
}

%typemap(freearg) (uint32_t attr_count, sai_attribute_t *attr_list) {
    for (uint32_t i = 0; i < $1; ++i) {
        PyObject *item;
        item = SWIG_NewPointerObj(&$2[i], $2_descriptor, 0);
        PyList_SetItem($input, i, item);
    }
}

%clear (uint32_t attr_count, sai_attribute_t *attr_list);

// Handling for sai api query
%typemap(in, numinputs=1) (sai_api_t api, void** api_method_table) (void* temp) {
    $1 = static_cast<sai_api_t>(PyInt_AsLong($input));
    $2 = &temp;
}

%typemap(argout) (sai_api_t api, void** api_method_table) {
    const std::unordered_map<sai_api_t, swig_type_info*, std::hash<std::underlying_type<sai_api_t>::type>> api_map
        = { {SAI_API_ACL, $descriptor(sai_acl_api_t*)},
            {SAI_API_BRIDGE, $descriptor(sai_bridge_api_t*)},
            {SAI_API_BUFFER, $descriptor(sai_buffer_api_t*)},
            {SAI_API_DEBUG_COUNTER, $descriptor(sai_debug_counter_api_t*)},
            {SAI_API_FDB, $descriptor(sai_fdb_api_t*)},
            {SAI_API_HASH, $descriptor(sai_hash_api_t*)},
            {SAI_API_HOSTIF, $descriptor(sai_hostif_api_t*)},
            {SAI_API_LAG, $descriptor(sai_lag_api_t*)},
            {SAI_API_MPLS, $descriptor(sai_mpls_api_t*)},
            {SAI_API_NEIGHBOR, $descriptor(sai_neighbor_api_t*)},
            {SAI_API_NEXT_HOP, $descriptor(sai_next_hop_api_t*)},
            {SAI_API_NEXT_HOP_GROUP, $descriptor(sai_next_hop_group_api_t*)},
            {SAI_API_PORT, $descriptor(sai_port_api_t*)},
            {SAI_API_QOS_MAP, $descriptor(sai_qos_map_api_t*)},
            {SAI_API_QUEUE, $descriptor(sai_queue_api_t*)},
            {SAI_API_ROUTER_INTERFACE, $descriptor(sai_router_interface_api_t*)},
            {SAI_API_ROUTE, $descriptor(sai_route_api_t*)},
            {SAI_API_SCHEDULER, $descriptor(sai_scheduler_api_t*)},
            {SAI_API_SCHEDULER_GROUP, $descriptor(sai_scheduler_group_api_t*)},
            {SAI_API_SWITCH, $descriptor(sai_switch_api_t*)},
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
            {SAI_API_SYSTEM_PORT, $descriptor(sai_system_port_api_t*)},
#endif
            {SAI_API_TUNNEL, $descriptor(sai_tunnel_api_t*)},
            {SAI_API_VIRTUAL_ROUTER, $descriptor(sai_virtual_router_api_t*)},
            {SAI_API_VLAN, $descriptor(sai_vlan_api_t*)},
            {SAI_API_WRED, $descriptor(sai_wred_api_t*)},
            {SAI_API_POLICER, $descriptor(sai_policer_api_t*)},
            {SAI_API_MIRROR, $descriptor(sai_mirror_api_t*)},
            {SAI_API_SAMPLEPACKET, $descriptor(sai_samplepacket_api_t*)},
            {SAI_API_TAM, $descriptor(sai_tam_api_t*)},
          };

    auto it = api_map.find($1);
    if (it == api_map.end()) {
        PyErr_SetString(PyExc_RuntimeError, "Unknown sai api id");
        SWIG_fail;
    }

    $result = SWIG_NewPointerObj(*$2, it->second, 0);
}

// Handing for sai object id returns
%typemap(in, numinputs=0) sai_object_id_t* SAI_OBJECT_ID_OUT (sai_object_id_t temp) {
    $1 = &temp;
}

%typemap(argout) sai_object_id_t* SAI_OBJECT_ID_OUT {
    $result = PyInt_FromLong(*$1);
}

// needs to be after the attr_list, attr_count typemap
%inline %{
    extern sai_status_t swig_test_create_or_remove_route_entries(
        sai_route_entry_t *route_entry,
        uint32_t attr_count,
        const sai_attribute_t *attr_list,
        const uint32_t num_routes,
        const uint32_t inc_start_bit,
        const bool bulk_operation,
        const bool to_create
        );
%}

%{
sai_status_t
swig_test_create_or_remove_route_entries(
    sai_route_entry_t *route_entry,
    uint32_t attr_count,
    const sai_attribute_t *attr_list,
    const uint32_t num_routes,
    const uint32_t inc_start_bit,
    const bool bulk_operation,
    const bool to_create
    )
{
    return sai_test_create_or_remove_route_entries(route_entry, attr_count, attr_list, num_routes, inc_start_bit,
            bulk_operation, to_create);
}
%}

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 8, 0)
// bulk inseg remove
%typemap(in, numinputs=1) (uint32_t object_count, const sai_inseg_entry_t *inseg_entry) {
    if (!PySequence_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a list");
        SWIG_fail;
    }

    auto len = PySequence_Length($input);
    auto vec = new sai_inseg_entry_t[len];

    for (uint32_t i = 0; i < len; ++i) {
        sai_inseg_entry_t* ptr;

        auto obj = PySequence_GetItem($input, i);
        auto res = SWIG_ConvertPtr(obj, (void**)&ptr, $descriptor(sai_inseg_entry_t*), 0);
        if (!SWIG_IsOK(res)) {
            PyErr_SetString(PyExc_RuntimeError, "Failed to get entry from inseg list");
            SWIG_fail;
        }

        if (ptr == 0) {
            break;
        }
        vec[i] = *ptr;
    }

    $1 = len;
    $2 = vec;
}

%typemap(freearg) (uint32_t object_count, const sai_inseg_entry_t *inseg_entry) {
    delete[] $2;
}

// bulk set
%typemap(in) (uint32_t object_count, const sai_inseg_entry_t *inseg_entry,
              const sai_attribute_t *attr_list) {

    if (!PySequence_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a list");
        SWIG_fail;
    }

    auto len = PySequence_Length($input);
    $1 = len;
    $2 = new sai_inseg_entry_t[$1];
    $3 = new sai_attribute_t[$1];

    for (uint32_t i = 0; i < $1; ++i) {
        sai_inseg_entry_t* inseg_entry;
        auto inseg_attr_pair = PySequence_GetItem($input, i);

        if (!PySequence_Check(inseg_attr_pair)) {
            PyErr_SetString(PyExc_ValueError, "Expecting a list");
            SWIG_fail;
        }

        auto py_inseg_entry = PySequence_GetItem(inseg_attr_pair, 0);
        if (!SWIG_IsOK(SWIG_ConvertPtr(py_inseg_entry, (void **) &inseg_entry,
              $descriptor(sai_inseg_entry_t *), 0))) {
            SWIG_exception_fail(SWIG_TypeError, "in method '$symname', "
                                "expecting type sai_inseg_entry_t");
        }
        $2[i] = *inseg_entry;

        auto py_attr_list = PySequence_GetItem(inseg_attr_pair, 1);
        if (!PySequence_Check(py_attr_list)) {
            PyErr_SetString(PyExc_ValueError, "Expecting a list");
            SWIG_fail;
        }

        auto len = PySequence_Length(py_attr_list);

        for (uint32_t attr_idx = 0; attr_idx < len; ++attr_idx) {
            sai_attribute_t* attr_ptr;

            auto obj = PySequence_GetItem(py_attr_list, attr_idx);
            auto res = SWIG_ConvertPtr(obj, (void**)&attr_ptr, $descriptor(sai_attribute_t*), 0);
            if (!SWIG_IsOK(res)) {
                PyErr_SetString(PyExc_RuntimeError,
                          "Failed to get attribute from inseg sai attribute list");
                SWIG_fail;
            }

            if (attr_ptr == 0) {
                break;
            }
            $3[i] = *attr_ptr;
        }
    }
}

%typemap(freearg) (uint32_t object_count, const sai_inseg_entry_t *inseg_entry,
                   const sai_attribute_t *attr_list) {
    delete[] $2;
    delete[] $3;
}

// bulk create
%typemap(in) (uint32_t object_count, const sai_inseg_entry_t *inseg_entry,
              const uint32_t *attr_count, const sai_attribute_t **attr_list) {

    if (!PySequence_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a list");
        SWIG_fail;
    }

    auto len = PySequence_Length($input);
    $1 = len;
    $2 = new sai_inseg_entry_t[len];
    $3 = new uint32_t[len];
    $4 = new sai_attribute_t*[len];

    for (uint32_t i = 0; i < $1; ++i) {
        sai_inseg_entry_t* inseg_entry;
        auto inseg_attr_pair = PySequence_GetItem($input, i);

        if (!PySequence_Check(inseg_attr_pair)) {
            PyErr_SetString(PyExc_ValueError, "Expecting a list");
            SWIG_fail;
        }

        auto py_inseg_entry = PySequence_GetItem(inseg_attr_pair, 0);
        if (!SWIG_IsOK(SWIG_ConvertPtr(py_inseg_entry, (void **) &inseg_entry,
              $descriptor(sai_inseg_entry_t *), 0))) {
            SWIG_exception_fail(SWIG_TypeError, "in method '$symname', "
                                "expecting type sai_inseg_entry_t");
        }
        $2[i] = *inseg_entry;

        auto py_attr_list = PySequence_GetItem(inseg_attr_pair, 1);
        if (!PySequence_Check(py_attr_list)) {
            PyErr_SetString(PyExc_ValueError, "Expecting a list");
            SWIG_fail;
        }

        auto attr_len = PySequence_Length(py_attr_list);
        $3[i] = attr_len;
        $4[i] = new sai_attribute_t[attr_len];

        for (uint32_t attr_idx = 0; attr_idx < attr_len; ++attr_idx) {
            sai_attribute_t* attr_ptr;

            auto obj = PySequence_GetItem(py_attr_list, attr_idx);
            auto res = SWIG_ConvertPtr(obj, (void**)&attr_ptr, $descriptor(sai_attribute_t*), 0);
            if (!SWIG_IsOK(res)) {
                PyErr_SetString(PyExc_RuntimeError,
                          "Failed to get attribute from inseg sai attribute list");
                SWIG_fail;
            }

            if (attr_ptr == 0) {
                break;
            }
            $4[i][attr_idx] = *attr_ptr;
        }
    }
}

// bulk create free
%typemap(freearg) (uint32_t object_count, const sai_inseg_entry_t *inseg_entry,
                   const uint32_t *attr_count, const sai_attribute_t **attr_list) {
    if (arg4) {
        for (uint32_t i = 0; i < $1; ++i) {
            delete[] $4[i];
        }
    }
    delete[] $2;
    delete[] $3;
    delete[] $4;
}


// bulk get
%typemap(in) (uint32_t object_count, const sai_inseg_entry_t *inseg_entry,
              const uint32_t *attr_count, sai_attribute_t **attr_list) {

    if (!PySequence_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a list");
        SWIG_fail;
    }

    auto len = PySequence_Length($input);
    $1 = len;
    $2 = new sai_inseg_entry_t[len];
    $3 = new uint32_t[len];
    $4 = new sai_attribute_t*[len];

    for (uint32_t i = 0; i < $1; ++i) {
        sai_inseg_entry_t* inseg_entry;
        auto inseg_attr_pair = PySequence_GetItem($input, i);

        if (!PySequence_Check(inseg_attr_pair)) {
            PyErr_SetString(PyExc_ValueError, "Expecting a list");
            SWIG_fail;
        }

        auto py_inseg_entry = PySequence_GetItem(inseg_attr_pair, 0);
        if (!SWIG_IsOK(SWIG_ConvertPtr(py_inseg_entry, (void **) &inseg_entry,
              $descriptor(sai_inseg_entry_t *), 0))) {
            SWIG_exception_fail(SWIG_TypeError, "in method '$symname', "
                                "expecting type sai_inseg_entry_t");
        }
        $2[i] = *inseg_entry;

        auto py_attr_list = PySequence_GetItem(inseg_attr_pair, 1);
        if (!PySequence_Check(py_attr_list)) {
            PyErr_SetString(PyExc_ValueError, "Expecting a list");
            SWIG_fail;
        }

        auto attr_len = PySequence_Length(py_attr_list);
        $3[i] = attr_len;
        $4[i] = new sai_attribute_t[attr_len];

        for (uint32_t attr_idx = 0; attr_idx < attr_len; ++attr_idx) {
            sai_attribute_t* attr_ptr;

            auto obj = PySequence_GetItem(py_attr_list, attr_idx);
            auto res = SWIG_ConvertPtr(obj, (void**)&attr_ptr, $descriptor(sai_attribute_t*), 0);
            if (!SWIG_IsOK(res)) {
                PyErr_SetString(PyExc_RuntimeError,
                          "Failed to get attribute from inseg sai attribute list");
                SWIG_fail;
            }

            if (attr_ptr == 0) {
                break;
            }
            $4[i][attr_idx] = *attr_ptr;
        }
    }
}

%typemap(freearg) (uint32_t object_count, const sai_inseg_entry_t *inseg_entry,
                   const uint32_t *attr_count, sai_attribute_t **attr_list) {
    if (arg4) {
        for (uint32_t i = 0; i < $1; ++i) {
            delete[] $4[i];
        }
    }
    delete[] $2;
    delete[] $3;
    delete[] $4;
}
#endif

%apply sai_object_id_t* SAI_OBJECT_ID_OUT { sai_object_id_t *acl_table_id,
                sai_object_id_t *acl_entry_id,
                sai_object_id_t *acl_counter_id,
                sai_object_id_t *acl_range_id,
                sai_object_id_t *acl_table_group_id,
                sai_object_id_t *acl_table_group_member_id,
                sai_object_id_t *bfd_session_id,
                sai_object_id_t *bridge_port_id,
                sai_object_id_t *bridge_id,
                uint64_t *count, // for sai_object_type_get_availability
                sai_object_id_t *ingress_priority_group_id,
                sai_object_id_t *buffer_pool_id,
                sai_object_id_t *buffer_profile_id,
                sai_object_id_t *debug_counter_id,
                sai_object_id_t *dtel_id,
                sai_object_id_t *dtel_queue_report_id,
                sai_object_id_t *dtel_int_session_id,
                sai_object_id_t *dtel_report_session_id,
                sai_object_id_t *dtel_event_id,
                sai_object_id_t *hash_id,
                sai_object_id_t *hostif_trap_group_id,
                sai_object_id_t *hostif_trap_id,
                sai_object_id_t *hostif_user_defined_trap_id,
                sai_object_id_t *hostif_id,
                sai_object_id_t *hostif_table_entry_id,
                sai_object_id_t *ipmc_group_id,
                sai_object_id_t *ipmc_group_member_id,
                sai_object_id_t *l2mc_group_id,
                sai_object_id_t *l2mc_group_member_id,
                sai_object_id_t *lag_id,
                sai_object_id_t *lag_member_id,
                sai_object_id_t *mirror_session_id,
                sai_object_id_t *next_hop_group_id,
                sai_object_id_t *next_hop_group_member_id,
                sai_object_id_t *next_hop_id,
                sai_object_id_t *policer_id,
                sai_object_id_t *port_id,
                sai_object_id_t *port_pool_id,
                sai_object_id_t *qos_map_id,
                sai_object_id_t *queue_id,
                sai_object_id_t *router_interface_id,
                sai_object_id_t *rpf_group_id,
                sai_object_id_t *rpf_group_member_id,
                sai_object_id_t *samplepacket_id,
                sai_object_id_t *scheduler_group_id,
                sai_object_id_t *scheduler_id,
                sai_object_id_t *segmentroute_sidlist_id,
                sai_object_id_t *stp_id,
                sai_object_id_t *stp_port_id,
                sai_object_id_t *switch_id,
                sai_object_id_t *system_port_id,
                sai_object_id_t *tam_stat_id,
                sai_object_id_t *tam_id,
                sai_object_id_t *tam_threshold_id,
                sai_object_id_t *tam_snapshot_id,
                sai_object_id_t *tam_transport_id,
                sai_object_id_t *tam_collector_id,
                sai_object_id_t *tam_report_id,
                sai_object_id_t *tam_event_id,
                sai_object_id_t *tam_event_action_id,
                sai_object_id_t *tunnel_map_id,
                sai_object_id_t *tunnel_id,
                sai_object_id_t *tunnel_term_table_entry_id,
                sai_object_id_t *tunnel_map_entry_id,
                sai_object_id_t *object_id,
                sai_object_id_t *tam_microburst_id,
                sai_object_id_t *tam_histogram_id,
                sai_object_id_t *udf_id,
                sai_object_id_t *udf_match_id,
                sai_object_id_t *udf_group_id,
                sai_object_id_t *virtual_router_id,
                sai_object_id_t *vlan_id,
                sai_object_id_t *vlan_member_id,
                sai_object_id_t *wred_id };

// Workaround for nested union
%extend _sai_acl_field_data_t {
    bool get_data_booldata() {
        return $self->data.booldata;
    }

    sai_uint8_t get_data_u8() {
        return $self->data.u8;
    }

    sai_int8_t get_data_s8() {
        return $self->data.s8;
    }

    sai_uint16_t get_data_u16() {
        return $self->data.u16;
    }

    sai_int16_t get_data_s16() {
        return $self->data.s16;
    }

    sai_uint32_t get_data_u32() {
        return $self->data.u32;
    }

    sai_int32_t get_data_s32() {
        return $self->data.s32;
    }

    sai_mac_t* get_data_mac() {
        sai_mac_t *mac;
        mac = (sai_mac_t *) malloc(sizeof(sai_mac_t));
        memcpy(mac, $self->data.mac, sizeof(sai_mac_t));
        return mac;
    }

    sai_ip_address_t* get_data_ip4() {
        sai_ip_address_t *ipaddr;
        ipaddr = (sai_ip_address_t *) malloc(sizeof(sai_ip_address_t));

        ipaddr->addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        ipaddr->addr.ip4 = $self->data.ip4;
        return ipaddr;
    }

    sai_ip_address_t* get_data_ip6() {
        sai_ip_address_t *ipaddr;
        ipaddr = (sai_ip_address_t *) malloc(sizeof(sai_ip_address_t));

        ipaddr->addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(ipaddr->addr.ip6, $self->data.ip6, sizeof(sai_ip6_t));
        return ipaddr;
    }

    sai_object_id_t get_data_oid() {
        return $self->data.oid;
    }

    sai_object_list_t get_data_objlist() {
        return $self->data.objlist;
    }

    sai_u8_list_t get_data_u8list() {
        return $self->data.u8list;
    }

    sai_uint8_t get_mask_u8() {
        return $self->mask.u8;
    }

    sai_int8_t get_mask_s8() {
        return $self->mask.s8;
    }

    sai_uint16_t get_mask_u16() {
        return $self->mask.u16;
    }

    sai_int16_t get_mask_s16() {
        return $self->mask.s16;
    }

    sai_uint32_t get_mask_u32() {
        return $self->mask.u32;
    }

    sai_int32_t get_mask_s32() {
        return $self->mask.s32;
    }

    sai_mac_t* get_mask_mac() {
        sai_mac_t *mac;
        mac = (sai_mac_t *) malloc(sizeof(sai_mac_t));
        memcpy(mac, $self->mask.mac, sizeof(sai_mac_t));
        return mac;
    }

    sai_ip_address_t* get_mask_ip4() {
        sai_ip_address_t *ipaddr;
        ipaddr = (sai_ip_address_t *) malloc(sizeof(sai_ip_address_t));

        ipaddr->addr_family = SAI_IP_ADDR_FAMILY_IPV4;
        ipaddr->addr.ip4 = $self->mask.ip4;
        return ipaddr;
    }

    sai_ip_address_t* get_mask_ip6() {
        sai_ip_address_t *ipaddr;
        ipaddr = (sai_ip_address_t *) malloc(sizeof(sai_ip_address_t));

        ipaddr->addr_family = SAI_IP_ADDR_FAMILY_IPV6;
        memcpy(ipaddr->addr.ip6, $self->mask.ip6, sizeof(sai_ip6_t));
        return ipaddr;
    }

    sai_u8_list_t get_mask_u8list() {
        return $self->mask.u8list;
    }
}

// SAI attribute handling
%extend _sai_attribute_t {
    _sai_attribute_t(sai_attr_id_t attr, const std::string& input) {
        auto sa = new _sai_attribute_t();
        sa->id = attr;

        // string starting with "mac:" means python sent us mac address
        if (input.compare(0, 4, "mac:") == 0) {
            mac_parse(input, sa->value.mac);
        } else if (attr == SAI_HOSTIF_ATTR_NAME) {
            strncpy((char*)&(sa->value.chardata), input.c_str(), SAI_HOSTIF_NAME_SIZE);
        } else if (attr == SAI_HOSTIF_ATTR_GENETLINK_MCGRP_NAME) {
            strncpy((char*)&(sa->value.chardata), input.c_str(), SAI_HOSTIF_GENETLINK_MCGRP_NAME_SIZE);
        }
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
        else if (attr == SAI_LAG_ATTR_LABEL) {
            strncpy((char*)&(sa->value.chardata), input.c_str(), sizeof(sa->value.chardata));
        }
#endif
        else {
            sa->value.s8list.list = reinterpret_cast<int8_t*>(strdup(input.c_str()));
            sa->value.s8list.count = input.length();
        }
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, const int8_t input) {
        auto sa =  new _sai_attribute_t();
        sa->id = attr;
        sa->value.s8 = input;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, const uint64_t input) {
        auto sa =  new _sai_attribute_t();
        sa->id = attr;
        sa->value.u64 = input;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, const sai_s8_list_t& input) {
        auto sa = new _sai_attribute_t();
        sa->id = attr;
        sa->value.s8list.count = input.count;
        sa->value.s8list.list = input.list;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, const sai_s32_list_t& input) {
        auto sa = new _sai_attribute_t();
        sa->id = attr;
        sa->value.s32list.count = input.count;
        sa->value.s32list.list = input.list;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, const sai_u32_list_t& input) {
        auto sa = new _sai_attribute_t();
        sa->id = attr;
        sa->value.u32list.count = input.count;
        sa->value.u32list.list = input.list;
        return sa;
    }


    _sai_attribute_t(sai_attr_id_t attr, const sai_object_list_t& input) {
        auto sa = new _sai_attribute_t();
        sa->id = attr;
        sa->value.objlist.count = input.count;
        sa->value.objlist.list = input.list;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, const bool input) {
        auto sa = new _sai_attribute_t();
        sa->id = attr;
        sa->value.booldata = input;
        return sa;
    }

    // IPv6 case. If we want to use sai_u8_list for other purpose, will need to change this
    _sai_attribute_t(sai_attr_id_t attr, const sai_u8_list_t& ipv6_addr) {
        auto sa = new _sai_attribute_t();
        sa->id = attr;
        if (ipv6_addr.count != 16) {
            PyErr_SetString(PyExc_RuntimeError, "IPv6 address with len != 16B");
        }
        memcpy(sa->value.ip6, ipv6_addr.list, ipv6_addr.count);
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, sai_packet_event_notification_fn callback) {
        auto sa = new _sai_attribute_t();
        sa->id = attr;
        sa->value.ptr = (void *)callback;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, sai_port_state_change_notification_fn callback) {
        auto sa = new _sai_attribute_t();
        sa->id = attr;
        sa->value.ptr = (void *)callback;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, sai_queue_pfc_deadlock_notification_fn callback) {
        auto sa = new _sai_attribute_t();
        sa->id = attr;
        sa->value.ptr = (void *)callback;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, sai_fdb_event_notification_fn callback) {
        auto sa = new _sai_attribute_t();
        sa->id = attr;
        sa->value.ptr = (void *)callback;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, sai_ip_address_t ip_addr) {
        auto sa = new _sai_attribute_t();
        sa->id = attr;
        sa->value.ipaddr = ip_addr;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, const sai_qos_map_list_t& input) {
        _sai_attribute_t *sa;
        sa = (_sai_attribute_t *) malloc(sizeof(_sai_attribute_t));
        sa->id = attr;
        sa->value.qosmap.count = input.count;
        sa->value.qosmap.list = input.list;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, const sai_map_list_t& input) {
        _sai_attribute_t *sa;
        sa = (_sai_attribute_t *) malloc(sizeof(_sai_attribute_t));
        sa->id = attr;
        sa->value.maplist.count = input.count;
        sa->value.maplist.list = input.list;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, const _sai_acl_action_data_t& ad) {
        _sai_attribute_t *sa;
        sa = (_sai_attribute_t *) malloc(sizeof(_sai_attribute_t));
        sa->id = attr;
        sa->value.aclaction = ad;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, const _sai_acl_field_data_t& fd) {
        _sai_attribute_t *sa;
        sa = (_sai_attribute_t *) malloc(sizeof(_sai_attribute_t));
        sa->id = attr;
        sa->value.aclfield = fd;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, const _sai_acl_resource_list_t& rl) {
        _sai_attribute_t *sa;
        sa = (_sai_attribute_t *) malloc(sizeof(_sai_attribute_t));
        sa->id = attr;
        sa->value.aclresource = rl;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, const _sai_acl_capability_t& ca) {
        _sai_attribute_t *sa;
        sa = (_sai_attribute_t *) malloc(sizeof(_sai_attribute_t));
        sa->id = attr;
        sa->value.aclcapability = ca;
        return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, const sai_u32_range_t& input) {
        auto sa = new _sai_attribute_t();
        sa->id = attr;
        sa->value.u32range.min = input.min;
        sa->value.u32range.max = input.max;
        return sa;
    }

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    _sai_attribute_t(sai_attr_id_t attr, const sai_system_port_config_t& config) {
      auto sa = new _sai_attribute_t();
      sa->id = attr;
      sa->value.sysportconfig = config;
      return sa;
    }

    _sai_attribute_t(sai_attr_id_t attr, const sai_system_port_config_list_t& config_list) {
        auto sa = new _sai_attribute_t();
        sa->id = attr;
        sa->value.sysportconfiglist.count = config_list.count;
        sa->value.sysportconfiglist.list = config_list.list;
        return sa;
    }
#endif

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 8, 0)
    _sai_attribute_t(sai_attr_id_t attr, const sai_prbs_rx_state_t& rx_state) {
      auto sa = new _sai_attribute_t();
      sa->id = attr;
      sa->value.rx_state = rx_state;
      return sa;
    }

#endif
}

%extend _sai_u32_range_t {
    _sai_u32_range_t(uint32_t min, uint32_t max) {
        _sai_u32_range_t *r;
        r = (_sai_u32_range_t *) malloc(sizeof(_sai_u32_range_t));
        r->min = min;
        r->max = max;
        return r;
    }
}

%extend _sai_acl_action_data_t {
    _sai_acl_action_data_t(bool enable, const bool parameter) {
        _sai_acl_action_data_t *ad;
        ad = (_sai_acl_action_data_t *) malloc(sizeof(_sai_acl_action_data_t));
        ad->enable = enable;
        ad->parameter.booldata = parameter;
        return ad;
    }

    _sai_acl_action_data_t(bool enable, const uint64_t parameter) {
        _sai_acl_action_data_t *ad;
        ad = (_sai_acl_action_data_t *) malloc(sizeof(_sai_acl_action_data_t));
        ad->enable = enable;
        ad->parameter.oid = parameter;
        return ad;
    }

    _sai_acl_action_data_t(bool enable, sai_object_list_t parameter) {
        _sai_acl_action_data_t *ad;
        ad = (_sai_acl_action_data_t *) malloc(sizeof(_sai_acl_action_data_t));
        ad->enable = enable;
        ad->parameter.objlist.list  = (sai_object_id_t *)calloc(parameter.count, sizeof(sai_object_id_t));
        for (uint32_t i = 0; i < parameter.count; ++i) {
            ad->parameter.objlist.list[i] = parameter.list[i];
        }
        ad->parameter.objlist.count  = parameter.count;
        return ad;
    }
}


%extend _sai_acl_field_data_t {
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    _sai_acl_field_data_t(bool enable, sai_object_id_t data, uint64_t mask) {
        _sai_acl_field_data_t *fd;
        fd = (_sai_acl_field_data_t *) malloc(sizeof(_sai_acl_field_data_t));
        fd->enable = enable;
        fd->data.oid = data;
        fd->mask.u64 = mask;
        return fd;
    }
#endif
    _sai_acl_field_data_t(bool enable, uint32_t data, uint32_t mask) {
        _sai_acl_field_data_t *fd;
        fd = (_sai_acl_field_data_t *) malloc(sizeof(_sai_acl_field_data_t));
        fd->enable = enable;
        fd->data.u32 = data;
        fd->mask.u32 = mask;
        return fd;
    }

    _sai_acl_field_data_t(bool enable, sai_ip_address_t data, sai_ip_address_t mask) {
        _sai_acl_field_data_t *fd;
        fd = (_sai_acl_field_data_t *) malloc(sizeof(_sai_acl_field_data_t));
        fd->enable = enable;
        if (data.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
            memcpy(&fd->data.ip4, &data.addr.ip4, sizeof(sai_ip4_t));
            memcpy(&fd->mask.ip4, &mask.addr.ip4, sizeof(sai_ip4_t));
        } else {
            memcpy(&fd->data.ip6, &data.addr.ip6, sizeof(sai_ip6_t));
            memcpy(&fd->mask.ip6, &mask.addr.ip6, sizeof(sai_ip6_t));
        }

        return fd;
    }

    _sai_acl_field_data_t(bool enable, const std::string& data, const std::string& mask) {
        _sai_acl_field_data_t *fd;
        fd = (_sai_acl_field_data_t *) malloc(sizeof(_sai_acl_field_data_t));
        fd->enable = enable;
        mac_parse(data, fd->data.mac);
        mac_parse(mask, fd->mask.mac);
        return fd;
    }

    _sai_acl_field_data_t(bool enable, const sai_object_list_t& data) {
        _sai_acl_field_data_t *fd;
        fd = (_sai_acl_field_data_t *) malloc(sizeof(_sai_acl_field_data_t));
        fd->enable = enable;
        fd->data.objlist.count = data.count;
        if (data.count == 0) {
            fd->data.objlist.list = nullptr;
        } else {
            size_t list_size = data.count * sizeof(sai_object_id_t);
            fd->data.objlist.list = (sai_object_id_t *) malloc(list_size);
            memcpy(fd->data.objlist.list, data.list, list_size);
        }
        return fd;
    }
}

%extend _sai_acl_resource_list_t {
    _sai_acl_resource_list_t(uint32_t count) {
        _sai_acl_resource_list_t *rl;
        rl = (_sai_acl_resource_list_t *) malloc(sizeof(_sai_acl_resource_list_t));
        rl->count = count;
        rl->list = (_sai_acl_resource_t *) malloc(count * sizeof(_sai_acl_resource_t));

        return rl;
    }

     _sai_acl_resource_t* get_index(int index)
    {
        return &($self->list[index]);
    }
}

%extend _sai_acl_capability_t {
    _sai_acl_capability_t(bool is_mandatory, uint32_t count) {
        _sai_acl_capability_t *ca ;
        ca = (_sai_acl_capability_t *) malloc(sizeof(_sai_acl_capability_t));
        ca->is_action_list_mandatory = is_mandatory;
        ca->action_list.count = count;
        ca->action_list.list = (sai_int32_t *) malloc(count*sizeof(sai_int32_t));
        return ca;
    }
}

%extend _sai_fdb_entry_t {
    _sai_fdb_entry_t(sai_object_id_t switch_id, const std::string& mac, sai_object_id_t bv_id) {
        auto sf = new _sai_fdb_entry_t();
        sf->switch_id = switch_id;
        mac_parse(mac, sf->mac_address);
        sf->bv_id = bv_id;
        return sf;
    }
}

%extend _sai_inseg_entry_t {
    _sai_inseg_entry_t(sai_object_id_t switch_id, sai_label_id_t label) {
        auto new_ent = new _sai_inseg_entry_t();
        new_ent->switch_id = switch_id;
        new_ent->label = label;
        return new_ent;
    }
}

%extend _sai_neighbor_entry_t {
    _sai_neighbor_entry_t(sai_object_id_t switch_id, sai_object_id_t rif_id, sai_ip_address_t ip_addr) {
        auto sn = new _sai_neighbor_entry_t();
        sn->switch_id = switch_id;
        sn->rif_id = rif_id;
        sn->ip_address = ip_addr;
        return sn;
    }
}

%extend _sai_route_entry_t {
    _sai_route_entry_t(sai_object_id_t switch_id, sai_object_id_t vr_id, sai_ip_address_t ip_addr, sai_ip_address_t ip_mask)  {
        auto sr = new _sai_route_entry_t();
        sr->switch_id = switch_id;
        sr->vr_id = vr_id;

        if (ip_addr.addr_family == SAI_IP_ADDR_FAMILY_IPV4) {
            if (ip_mask.addr_family != SAI_IP_ADDR_FAMILY_IPV4) {
                PyErr_SetString(PyExc_RuntimeError, "Got IPv4 address with IPv6 mask");
            }
            sr->destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
            sr->destination.addr.ip4 = ip_addr.addr.ip4;
            sr->destination.mask.ip4 = ip_mask.addr.ip4;
        } else {
            if (ip_mask.addr_family != SAI_IP_ADDR_FAMILY_IPV6) {
                PyErr_SetString(PyExc_RuntimeError, "Got IPv6 address with IPv4 mask");
            }
            sr->destination.addr_family = SAI_IP_ADDR_FAMILY_IPV6;
            memcpy(sr->destination.addr.ip6, ip_addr.addr.ip6, 16);
            memcpy(sr->destination.mask.ip6, ip_mask.addr.ip6, 16);
        }
        return sr;
    }
}

// for sai_get_object_count
%apply uint32_t *OUTPUT { uint32_t *count };
%apply uint32_t *INOUT { uint32_t *object_count };
// This does not work with uint64_t, only with native types
%array_class(unsigned long int, int_array)
sai_status_t sai_get_object_key(sai_object_id_t switch_id, sai_object_type_t object_type, uint32_t *object_count, unsigned long int* object_list);
%array_class(_sai_fdb_entry_t, fdb_entry_array)
sai_status_t sai_get_object_key(sai_object_id_t switch_id, sai_object_type_t object_type, uint32_t *object_count, _sai_fdb_entry_t* object_list);
%array_class(_sai_route_entry_t, route_entry_array)
sai_status_t sai_get_object_key(sai_object_id_t switch_id, sai_object_type_t object_type, uint32_t *object_count, _sai_route_entry_t* object_list);
%array_class(_sai_neighbor_entry_t, neighbor_entry_array)
sai_status_t sai_get_object_key(sai_object_id_t switch_id, sai_object_type_t object_type, uint32_t *object_count, _sai_neighbor_entry_t* object_list);

sai_status_t swig_query_attribute_enum_values_capability(sai_object_id_t switch_id,
                                                         sai_object_type_t object_type,
                                                         sai_attr_id_t attr_id,
                                                         unsigned long int* out_list_size,
                                                         unsigned long int* out_list);

sai_status_t swig_sai_query_attribute_capability(sai_object_id_t switch_id,
                                                 sai_object_type_t object_type,
                                                 sai_attr_id_t attr_id,
                                                 PyObject *val_list);

%{
sai_status_t swig_query_attribute_enum_values_capability(sai_object_id_t switch_id,
                                                        sai_object_type_t object_type,
                                                        sai_attr_id_t attr_id,
                                                        unsigned long int *out_list_size,
                                                        unsigned long int* out_list) {

    if (out_list_size == nullptr || out_list == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    sai_s32_list_t cap_list;
    cap_list.count = *out_list_size;
    cap_list.list = new int32_t[*out_list_size];
    sai_status_t ret_val;

    sai_query_attribute_enum_values_capability(switch_id, object_type, attr_id, &cap_list);

    if (cap_list.count > *out_list_size) {
        ret_val = SAI_STATUS_BUFFER_OVERFLOW;
    } else {
        ret_val = SAI_STATUS_SUCCESS;

        for (unsigned int i = 0; i < cap_list.count; i++) {
            out_list[i] = cap_list.list[i];
        }
    }

    *out_list_size = cap_list.count;
    delete cap_list.list;
    return ret_val;
}

sai_status_t swig_sai_query_attribute_capability(sai_object_id_t switch_id,
                                                 sai_object_type_t object_type,
                                                 sai_attr_id_t attr_id,
                                                 PyObject *val_list)
{
    sai_attr_capability_t attr_capability;
    sai_status_t result;

    if (val_list == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    result = sai_query_attribute_capability(switch_id, object_type, attr_id, &attr_capability);

    if (result == SAI_STATUS_SUCCESS) {
        if (attr_capability.create_implemented) {
            PyList_Append(val_list, PyString_FromString("true"));
        } else {
            PyList_Append(val_list, PyString_FromString("false"));
        }
        if (attr_capability.set_implemented) {
            PyList_Append(val_list, PyString_FromString("true"));
        } else {
            PyList_Append(val_list, PyString_FromString("false"));
        }
        if (attr_capability.get_implemented) {
            PyList_Append(val_list, PyString_FromString("true"));
        } else {
            PyList_Append(val_list, PyString_FromString("false"));
        }
    }
    return result;
}
%}


// Generic SAI files
%include "sai/saitypes.h"
%include "sai/saiobject.h"
%include "sai/saistatus.h"
%include "sai/sai.h"

%extend _sai_service_method_table_t {
    _sai_service_method_table_t(sai_profile_get_value_fn cb_profile_get_value, sai_profile_get_next_value_fn cb_profile_get_next_value)  {
        auto ssmt = new _sai_service_method_table_t();
        ssmt->profile_get_value = cb_profile_get_value;
        ssmt->profile_get_next_value = cb_profile_get_next_value;
        return ssmt;
    }
}

//
// Per-API handling -- declaring function pointers as member functions
//
struct sai_hostif_api_t {
    sai_status_t create_hostif(
        _Out_ sai_object_id_t *hostif_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_hostif(
        _In_ sai_object_id_t hostif_id);

    sai_status_t set_hostif_attribute(
        _In_ sai_object_id_t hostif_id, _In_ const sai_attribute_t* attr);

    sai_status_t get_hostif_attribute(
        _In_ sai_object_id_t hostif_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t* attr_list);

    sai_status_t create_hostif_table_entry(
        _Out_ sai_object_id_t *hostif_table_entry_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_hostif_table_entry(
        _In_ sai_object_id_t hostif_table_entry_id);

    sai_status_t set_hostif_table_entry_attribute(
        _In_ sai_object_id_t hostif_table_entry_id, _In_ const sai_attribute_t* attr);

    sai_status_t get_hostif_table_entry_attribute(
        _In_ sai_object_id_t hostif_table_entry_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t* attr_list);

    sai_status_t send_hostif_packet(
        _In_ sai_object_id_t hostif_id,
        _In_ sai_size_t buffer_size,
        _In_ const char *buffer,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t create_hostif_trap(
        _Out_ sai_object_id_t *hostif_trap_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_hostif_trap(
        _In_ sai_object_id_t hostif_trap_id);

    sai_status_t set_hostif_trap_attribute(
        _In_ sai_object_id_t hostif_trap_id,
        _In_ sai_attribute_t* attr_list);

    sai_status_t get_hostif_trap_attribute(
        _In_ sai_object_id_t hostif_trap_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t* attr_list);

    sai_status_t create_hostif_trap_group(
        _Out_ sai_object_id_t *hostif_trap_group_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_hostif_trap_group(
        _In_ sai_object_id_t hostif_trap_group_id);

    sai_status_t set_hostif_trap_group_attribute(
        _In_ sai_object_id_t hostif_trap_group_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_hostif_trap_group_attribute(
        _In_ sai_object_id_t hostif_trap_group_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
};
%ignore _sai_hostif_api_t;
%include "sai/saihostif.h"

%extend sai_hostif_api_t {
    sai_status_t send_hostif_packet_wrapper(
        _In_ sai_object_id_t hostif_id,
        _In_ sai_size_t buffer_size,
        _In_ const char *buffer,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list) {
            uint8_t new_buffer[buffer_size];
            uint8_t hex_num;
            for (uint32_t i = 0; i < buffer_size; i+=2) {
               if (buffer[i] >= 'a' && buffer[i] <= 'f') {
                   hex_num = ((buffer[i] - 'a' + 10) << 4);
               } else {
                   hex_num = ((buffer[i] - '0') << 4);
               }
               if (buffer[i + 1] >= 'a' && buffer[i + 1] <= 'f') {
                   hex_num += buffer[i+1] - 'a' + 10;
               } else {
                   hex_num += buffer[i+1] - '0';
               }
               new_buffer[i/2] = hex_num;
           }
           return $self->send_hostif_packet(hostif_id, buffer_size / 2, new_buffer, attr_count, attr_list);
       }
}

struct sai_mpls_api_t {
    sai_status_t create_inseg_entry(
        _In_ const sai_inseg_entry_t *inseg_entry_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_inseg_entry(
        _In_ const sai_inseg_entry_t *inseg_entry);

    sai_status_t set_inseg_entry_attribute(
        _In_ const sai_inseg_entry_t *inseg_entry,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_inseg_entry_attribute(
        _In_ const sai_inseg_entry_t *inseg_entry,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 8, 0)
    sai_status_t create_inseg_entries(
        _In_ uint32_t object_count,
        _In_ const sai_inseg_entry_t *inseg_entry,
        _In_ const uint32_t *attr_count,
        _In_ const sai_attribute_t **attr_list,
        _In_ sai_bulk_op_error_mode_t mode,
        _Out_ sai_status_t *object_statuses);

    sai_status_t remove_inseg_entries(
        _In_ uint32_t object_count,
        _In_ const sai_inseg_entry_t *inseg_entry,
        _In_ sai_bulk_op_error_mode_t mode,
        _Out_ sai_status_t *object_statuses);

    sai_status_t set_inseg_entries_attribute(
        _In_ uint32_t object_count,
        _In_ const sai_inseg_entry_t *inseg_entry,
        _In_ const sai_attribute_t *attr_list,
        _In_ sai_bulk_op_error_mode_t mode,
        _Out_ sai_status_t *object_statuses);

    sai_status_t get_inseg_entries_attribute(
        _In_ uint32_t object_count,
        _In_ const sai_inseg_entry_t *inseg_entry,
        _In_ const uint32_t *attr_count,
        _Inout_ sai_attribute_t **attr_list,
        _In_ sai_bulk_op_error_mode_t mode,
        _Out_ sai_status_t *object_statuses);
#endif
};
%ignore _sai_mpls_api_t;
%include "sai/saimpls.h"

struct sai_bridge_api_t {
    sai_status_t create_bridge(
        _Out_ sai_object_id_t *bridge_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_bridge(
        _In_ sai_object_id_t bridge_id);

    sai_status_t create_bridge_port(
        _Out_ sai_object_id_t *bridge_port_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_bridge_port(
        _In_ sai_object_id_t bridge_port_id);

    sai_status_t set_bridge_attribute(
        _In_ sai_object_id_t bridge_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_bridge_attribute(
        _In_ sai_object_id_t bridge_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

    sai_status_t set_bridge_port_attribute(
        _In_ sai_object_id_t bridge_port_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_bridge_port_attribute(
        _In_ sai_object_id_t bridge_port_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);


};
%ignore _sai_bridge_api_t;
%include "sai/saibridge.h"

struct sai_debug_counter_api_t {
    sai_status_t create_debug_counter(_Out_ sai_object_id_t *debug_counter_id,
                                      _In_ sai_object_id_t switch_id,
                                      _In_ uint32_t attr_count,
                                      _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_debug_counter(_In_ sai_object_id_t debug_counter_id);

    sai_status_t set_debug_counter_attribute(_In_ sai_object_id_t debug_counter_id,
                                             _In_ const sai_attribute_t *attr);

    sai_status_t get_debug_counter_attribute(_In_ sai_object_id_t debug_counter_id,
                                             _In_ uint32_t attr_count,
                                             _Inout_ sai_attribute_t *attr_list);
};
%ignore _sai_debug_counter_api_t;
%include "sai/saidebugcounter.h"

struct sai_buffer_api_t {
    sai_status_t create_buffer_pool(_Out_ sai_object_id_t* buffer_pool_id,
                                    _In_ sai_object_id_t switch_id,
                                    _In_ uint32_t attr_count,
                                    _In_ const sai_attribute_t* attr_list);

    sai_status_t remove_buffer_pool(_In_ sai_object_id_t buffer_pool_id);

    sai_status_t set_buffer_pool_attribute(_In_ sai_object_id_t buffer_pool_id,
                                        _In_ const sai_attribute_t* attr);

    sai_status_t get_buffer_pool_attribute(_In_ sai_object_id_t buffer_pool_id,
                                            _In_ uint32_t attr_count,
                                            _Out_ sai_attribute_t* attr_list);
    sai_status_t get_buffer_pool_stats(_In_ sai_object_id_t buffer_pool_id,
                                        _In_ uint32_t number_of_counters,
                                        _In_ const sai_stat_id_t* counter_ids,
                                        _Out_ uint64_t* counters);
    sai_status_t get_buffer_pool_stats_ext(_In_ sai_object_id_t buffer_pool_id,
                                            _In_ uint32_t number_of_counters,
                                            _In_ const sai_stat_id_t* counter_ids,
                                            _In_ sai_stats_mode_t mode,
                                            _Out_ uint64_t* counters);

    sai_status_t clear_buffer_pool_stats(_In_ sai_object_id_t pool_id,
                                        _In_ uint32_t number_of_counters,
                                        _In_ const sai_stat_id_t* counter_ids);

    sai_status_t create_ingress_priority_group(_Out_ sai_object_id_t* ingress_priority_group_id,
                                _In_ sai_object_id_t switch_id,
                                _In_ uint32_t attr_count,
                                _In_ const sai_attribute_t* attr_list);
    sai_status_t remove_ingress_priority_group(_In_ sai_object_id_t ingress_priority_group_id);

    sai_status_t set_ingress_priority_group_attribute(_In_ sai_object_id_t ingress_priority_group_id,
                                                        _In_ const sai_attribute_t* attr);

    sai_status_t get_ingress_priority_group_attribute(_In_ sai_object_id_t ingress_priority_group_id,
                                                    _In_ uint32_t attr_count,
                                                    _Inout_ sai_attribute_t* attr_list);

    sai_status_t get_ingress_priority_group_stats(_In_ sai_object_id_t ingress_priority_group_id,
                                            _In_ uint32_t number_of_counters,
                                            _In_ const sai_stat_id_t* counter_ids,
                                            _Out_ uint64_t* counters);

    sai_status_t get_ingress_priority_group_stats_ext(_In_ sai_object_id_t ingress_priority_group_id,
                                        _In_ uint32_t number_of_counters,
                                        _In_ const sai_stat_id_t* counter_ids,
                                        _In_ sai_stats_mode_t mode,
                                        _Out_ uint64_t* counters);

    sai_status_t clear_ingress_priority_group_stats(_In_ sai_object_id_t ingress_priority_group_id,
                                   _In_ uint32_t number_of_counters,
                                   _In_ const sai_stat_id_t* counter_ids);

    sai_status_t create_buffer_profile(_Out_ sai_object_id_t* buffer_profile_id,
                      _In_ sai_object_id_t switch_id,
                      _In_ uint32_t attr_count,
                      _In_ const sai_attribute_t* attr_list);

    sai_status_t remove_buffer_profile(_In_ sai_object_id_t buffer_profile_id);

    sai_status_t set_buffer_profile_attribute(_In_ sai_object_id_t buffer_profile_id,
                                            _In_ const sai_attribute_t* attr);

    sai_status_t get_buffer_profile_attribute(_In_ sai_object_id_t buffer_profile_id,
                                                _In_ uint32_t attr_count,
                                                _Inout_ sai_attribute_t* attr_list);
};
%ignore _sai_buffer_api_t;
%include "sai/saibuffer.h"

struct sai_lag_api_t
{
    sai_status_t create_lag(
        _Out_ sai_object_id_t *lag_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_lag(_In_ sai_object_id_t lag_id);

    sai_status_t set_lag_attribute(
        _In_ sai_object_id_t lag_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_lag_attribute(
        _In_ sai_object_id_t lag_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

    sai_status_t create_lag_member(
        _Out_ sai_object_id_t *lag_member_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_lag_member(
        _In_ sai_object_id_t lag_member_id);

    sai_status_t set_lag_member_attribute(
        _In_ sai_object_id_t lag_member_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_lag_member_attribute(
        _In_ sai_object_id_t lag_member_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
};
%ignore _sai_lag_api_t;
%include "sai/sailag.h"

struct sai_fdb_api_t {
    sai_status_t create_fdb_entry(
        _In_ const sai_fdb_entry_t *fdb_entry,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_fdb_entry(
        _In_ const sai_fdb_entry_t *fdb_entry);

    sai_status_t set_fdb_entry_attribute(
        _In_ const sai_fdb_entry_t *fdb_entry,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_fdb_entry_attribute(
        _In_ const sai_fdb_entry_t *fdb_entry,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

    sai_status_t flush_fdb_entries(
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);
};
%ignore _sai_fdb_api_t;
%include "sai/saifdb.h"

struct sai_neighbor_api_t {
    sai_status_t create_neighbor_entry(
        _In_ const sai_neighbor_entry_t *neighbor_entry,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_neighbor_entry(
        _In_ const sai_neighbor_entry_t *neighbor_entry);

    sai_status_t set_neighbor_entry_attribute(
        _In_ const sai_neighbor_entry_t *neighbor_entry,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_neighbor_entry_attribute(
        _In_ const sai_neighbor_entry_t *neighbor_entry,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

    sai_status_t remove_all_neighbor_entries(
        _In_ sai_object_id_t switch_id);
};
%ignore _sai_neighbor_api_t;
%include "sai/saineighbor.h"

struct sai_next_hop_api_t {
    sai_status_t create_next_hop(
        _Out_ sai_object_id_t *next_hop_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_next_hop(
        _In_ sai_object_id_t next_hop_id);

    sai_status_t set_next_hop_attribute(
        _In_ sai_object_id_t next_hop_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_next_hop_attribute(
        _In_ sai_object_id_t next_hop_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
};
%ignore _sai_next_hop_api_t;
%include "sai/sainexthop.h"

struct sai_next_hop_group_api_t {

    sai_status_t create_next_hop_group(
        _Out_ sai_object_id_t *next_hop_group_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_next_hop_group(
        _In_ sai_object_id_t next_hop_group_id);

    sai_status_t set_next_hop_group_attribute(
        _In_ sai_object_id_t next_hop_group_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_next_hop_group_attribute(
        _In_ sai_object_id_t next_hop_group_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

    sai_status_t create_next_hop_group_member(
        _Out_ sai_object_id_t *next_hop_group_member_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_next_hop_group_member(
        _In_ sai_object_id_t next_hop_group_member_id);

    sai_status_t set_next_hop_group_member_attribute(
        _In_ sai_object_id_t next_hop_group_member_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_next_hop_group_member_attribute(
        _In_ sai_object_id_t next_hop_group_member_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
    sai_status_t remove_next_hop_group_members(
       _In_ uint32_t object_count,
       _In_ const sai_object_id_t* object_ids,
       _In_ sai_bulk_op_error_mode_t mode,
       _Out_ sai_status_t* object_statuses);
};
%ignore _sai_next_hop_group_api_t;
%include "sai/sainexthopgroup.h"

struct sai_port_api_t {
    sai_status_t create_port(
        _Out_ sai_object_id_t *port_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_port(
        _In_ sai_object_id_t port_id);

    sai_status_t set_port_attribute(
        _In_ sai_object_id_t port_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_port_attribute(
        _In_ sai_object_id_t port_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

    sai_status_t get_port_stats(
        _In_ sai_object_id_t port_id,
        _In_ uint32_t number_of_counters,
        _In_ const sai_stat_id_t *counter_ids,
        _Out_ uint64_t *counters);

    sai_status_t get_port_stats_ext(
        _In_ sai_object_id_t port_id,
        _In_ uint32_t number_of_counters,
        _In_ const sai_stat_id_t *counter_ids,
        _In_ sai_stats_mode_t mode,
        _Out_ uint64_t *counters);

    sai_status_t clear_port_stats(
        _In_ sai_object_id_t port_id,
        _In_ uint32_t number_of_counters,
        _In_ const sai_stat_id_t *counter_ids);

    sai_status_t clear_port_all_stats(
        _In_ sai_object_id_t port_id);

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    sai_status_t create_port_connector(
        _Out_ sai_object_id_t *port_connector_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_port_connector(
        _In_ sai_object_id_t port_connector_id);

    sai_status_t set_port_connector_attribute(
        _In_ sai_object_id_t port_connector_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_port_connector_attribute(
        _In_ sai_object_id_t port_connector_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
#endif

    sai_status_t create_port_serdes(
        _Out_ sai_object_id_t *port_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_port_serdes(
        _In_ sai_object_id_t port_id);

    sai_status_t set_port_serdes_attribute(
        _In_ sai_object_id_t port_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_port_serdes_attribute(
        _In_ sai_object_id_t port_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
};
%ignore _sai_port_api_t;
%include "sai/saiport.h"

%extend _sai_qos_map_list_t {
    _sai_qos_map_list_t(PyObject *input) {
        if (!PySequence_Check(input)) {
            PyErr_SetString(PyExc_TypeError, "Expecting list of key/value lists");
            return nullptr;
        }

        uint32_t list_len = PyObject_Length(input);
        _sai_qos_map_list_t *s = new _sai_qos_map_list_t();
        sai_qos_map_t *list = new sai_qos_map_t[list_len];
        s->list = list;

        s->count = list_len;
        for (uint32_t i = 0; i < s->count; i++) {
            PyObject *key_val = PyList_GetItem(input, i);
            if (!PyList_Check(key_val)) {
                PyErr_SetString(PyExc_TypeError, "One of the values in the outer list is not a list");
                return nullptr;
            }

            if (PyObject_Length(key_val) != 2) {
                PyErr_SetString(PyExc_TypeError, "One of the key/value pairs has wrong length");
                return nullptr;
            }
            PyObject *key = PyList_GetItem(key_val, 0);
            PyObject *val = PyList_GetItem(key_val, 1);

            uint32_t key_list_len = PyObject_Length(key);
            uint32_t val_list_len = PyObject_Length(val);
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
            if (key_list_len != 8 || val_list_len != 8) {
                PyErr_SetString(PyExc_TypeError, "key and val lists must have 8 elements each");
                return nullptr;
            }
#else
            if (key_list_len != 7 || val_list_len != 7) {
                PyErr_SetString(PyExc_TypeError, "key and val lists must have 7 elements each");
                return nullptr;
            }
#endif

            s->list[i].key.tc = PyInt_AsLong(PyList_GetItem(key, 0));
            s->list[i].value.tc = PyInt_AsLong(PyList_GetItem(val, 0));
            s->list[i].key.dscp = PyInt_AsLong(PyList_GetItem(key, 1));
            s->list[i].value.dscp = PyInt_AsLong(PyList_GetItem(val, 1));
            s->list[i].key.dot1p = PyInt_AsLong(PyList_GetItem(key, 2));
            s->list[i].value.dot1p = PyInt_AsLong(PyList_GetItem(val, 2));
            s->list[i].key.prio = PyInt_AsLong(PyList_GetItem(key, 3));
            s->list[i].value.prio = PyInt_AsLong(PyList_GetItem(val, 3));
            s->list[i].key.pg = PyInt_AsLong(PyList_GetItem(key, 4));
            s->list[i].value.pg = PyInt_AsLong(PyList_GetItem(val, 4));
            s->list[i].key.queue_index = PyInt_AsLong(PyList_GetItem(key, 5));
            s->list[i].value.queue_index = PyInt_AsLong(PyList_GetItem(val, 5));
            s->list[i].key.color = (sai_packet_color_t) PyInt_AsLong(PyList_GetItem(key, 6));
            s->list[i].value.color = (sai_packet_color_t) PyInt_AsLong(PyList_GetItem(val, 6));
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
            s->list[i].key.mpls_exp = PyInt_AsLong(PyList_GetItem(key, 7));
            s->list[i].value.mpls_exp = PyInt_AsLong(PyList_GetItem(val, 7));
#endif
        }

        return s;
    }
}

struct sai_qos_map_api_t {
    sai_status_t create_qos_map(
        _Out_ sai_object_id_t *qos_map_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_qos_map(
        _In_ sai_object_id_t qos_map_id);

    sai_status_t set_qos_map_attribute(
        _In_ sai_object_id_t qos_map_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_qos_map_attribute(
        _In_ sai_object_id_t qos_map_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
};
%ignore _sai_qos_map_api_t;
%include "sai/saiqosmap.h"

%extend _sai_map_list_t {
    _sai_map_list_t(PyObject *input) {

        uint32_t list_len = PyObject_Length(input);
        if (list_len != 2) {
            PyErr_SetString(PyExc_TypeError, "map_list has the wrong length");
            return nullptr;
        }

        PyObject *key_list = PyList_GetItem(input, 0);
        PyObject *val_list = PyList_GetItem(input, 1);
        uint32_t key_list_len = PyObject_Length(key_list);
        uint32_t val_list_len = PyObject_Length(val_list);
        if (val_list_len != key_list_len) {
            PyErr_SetString(PyExc_TypeError,
                            "map_list key list and value list do not have matching lengths");
            return nullptr;
        }

        _sai_map_list_t *s = new _sai_map_list_t();
        sai_map_t *list = new sai_map_t[key_list_len];
        s->list = list;

        s->count = key_list_len;
        for (uint32_t i = 0; i < s->count; i++) {
            s->list[i].key = PyInt_AsLong(PyList_GetItem(key_list, i));
            s->list[i].value = PyInt_AsLong(PyList_GetItem(val_list, i));
        }

        return s;
    }
}

struct sai_queue_api_t {
    sai_status_t create_queue(
                              _Out_ sai_object_id_t *queue_id,
                              _In_ sai_object_id_t switch_id,
                              _In_ uint32_t attr_count,
                              _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_queue(
                              _In_ sai_object_id_t queue_id);

    sai_status_t set_queue_attribute(
                                     _In_ sai_object_id_t queue_id,
                                     _In_ const sai_attribute_t *attr);

    sai_status_t get_queue_attribute(
                                     _In_ sai_object_id_t queue_id,
                                     _In_ uint32_t attr_count,
                                     _Inout_ sai_attribute_t *attr_list);

    sai_status_t get_queue_stats(
                                     _In_ sai_object_id_t queue_id,
                                     _In_ uint32_t number_of_counters,
                                     _In_ const sai_stat_id_t *counter_ids,
                                     _Out_ uint64_t *counters);

    sai_status_t get_queue_stats_ext(
                                         _In_ sai_object_id_t queue_id,
                                         _In_ uint32_t number_of_counters,
                                         _In_ const sai_stat_id_t *counter_ids,
                                         _In_ sai_stats_mode_t mode,
                                         _Out_ uint64_t *counters);

    sai_status_t clear_queue_stats(
                                       _In_ sai_object_id_t queue_id,
                                       _In_ uint32_t number_of_counters,
                                       _In_ const sai_stat_id_t *counter_ids);
};
%ignore _sai_queue_api_t;
%include "sai/saiqueue.h"

%typemap(in) (uint32_t object_count, const sai_route_entry_t *route_entry, const uint32_t *attr_count, const sai_attribute_t **attr_list) {
    if (!PySequence_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a list");
        SWIG_fail;
    }

    $1 = PySequence_Length($input);
    $2 = new sai_route_entry_t[$1];
    $3 = new uint32_t[$1];
    $4 = new sai_attribute_t*[$1];

    for (uint32_t i = 0; i < $1; ++i) {
        sai_route_entry_t* route_entry = nullptr;
        auto route_attr_pair = PySequence_GetItem($input, i);

        if (!PySequence_Check(route_attr_pair)) {
            PyErr_SetString(PyExc_ValueError, "Expecting a list");
            SWIG_fail;
        }

        auto py_route_entry = PySequence_GetItem(route_attr_pair, 0);
        if (!SWIG_IsOK(SWIG_ConvertPtr(py_route_entry, (void **) &route_entry, $descriptor(sai_route_entry_t *), 0))) {
            SWIG_exception_fail(SWIG_TypeError, "in method '$symname', expecting type sai_route_entry_t");
        }
        $2[i] = *route_entry;

        auto py_attr_list = PySequence_GetItem(route_attr_pair, 1);
        if (!PySequence_Check(py_attr_list)) {
            PyErr_SetString(PyExc_ValueError, "Expecting a list");
            SWIG_fail;
        }

        $3[i] = PySequence_Length(py_attr_list);
        $4[i] = new sai_attribute_t[$3[i]];

        for (uint32_t attr_idx = 0; attr_idx < $3[i]; ++attr_idx) {
            sai_attribute_t* attr_ptr;

            auto obj = PySequence_GetItem(py_attr_list, attr_idx);
            auto res = SWIG_ConvertPtr(obj, (void**)&attr_ptr, $descriptor(sai_attribute_t*), 0);
            if (!SWIG_IsOK(res)) {
                PyErr_SetString(PyExc_RuntimeError, "Failed to get attribute from sai attribute list");
                SWIG_fail;
            }

            if (attr_ptr == 0) {
                break;
            }
            $4[i][attr_idx] = *attr_ptr;
        }
    }
}

%typemap(freearg) (uint32_t object_count, const sai_route_entry_t *route_entry, const uint32_t *attr_count, const sai_attribute_t **attr_list) {
    if ($4) {
        for (uint32_t i = 0; i < $1; ++i) {
            delete[] $4[i];
        }
    }
    delete[] $2;
    delete[] $3;
    delete[] $4;
}

%typemap(in) (uint32_t object_count, const sai_route_entry_t *route_entry) {
    if (!PySequence_Check($input)) {
        PyErr_SetString(PyExc_ValueError, "Expecting a list");
        SWIG_fail;
    }

    $1 = PySequence_Length($input);
    $2 = new sai_route_entry_t[$1];

    for (uint32_t i = 0; i < $1; ++i) {
        sai_route_entry_t* route_entry = nullptr;
        auto py_route_entry = PySequence_GetItem($input, i);
        if (!SWIG_IsOK(SWIG_ConvertPtr(py_route_entry, (void **) &route_entry, $descriptor(sai_route_entry_t *), 0))) {
            SWIG_exception_fail(SWIG_TypeError, "in method '$symname', expecting type sai_route_entry_t");
        }
        $2[i] = *route_entry;
    }
}

%typemap(freearg) (uint32_t object_count, const sai_route_entry_t *route_entry) {
    delete[] $2;
}

// need to be after the typemaps
%include "sai_test_utils.h"

%inline {
sai_status_t
swig_create_route_entries(
    _In_ uint32_t object_count,
    _In_ const sai_route_entry_t *route_entry,
    _In_ const uint32_t *attr_count,
    _In_ const sai_attribute_t **attr_list)
{
    std::vector<sai_status_t> object_statuses(object_count, SAI_STATUS_SUCCESS);
    return route_api.create_route_entries(object_count, route_entry, attr_count, attr_list,
            SAI_BULK_OP_ERROR_MODE_IGNORE_ERROR, object_statuses.data());
}

sai_status_t
swig_remove_route_entries(
    _In_ uint32_t object_count,
    _In_ const sai_route_entry_t *route_entry)
{
    std::vector<sai_status_t> object_statuses(object_count, SAI_STATUS_SUCCESS);
    return route_api.remove_route_entries(object_count, route_entry,
            SAI_BULK_OP_ERROR_MODE_IGNORE_ERROR, object_statuses.data());
}

}

struct sai_route_api_t {
    sai_status_t create_route_entry(
        _In_ const sai_route_entry_t *route_entry,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_route_entry(
        _In_ const sai_route_entry_t *route_entry);

    sai_status_t set_route_entry_attribute(
        _In_ const sai_route_entry_t *route_entry,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_route_entry_attribute(
        _In_ const sai_route_entry_t *route_entry,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

    sai_status_t create_route_entries(
        _In_ uint32_t object_count,
        _In_ const sai_route_entry_t *route_entry,
        _In_ const uint32_t *attr_count,
        _In_ const sai_attribute_t **attr_list,
        _In_ sai_bulk_op_error_mode_t mode,
        _Out_ sai_status_t *object_statuses);

    sai_status_t remove_route_entries(
        _In_ uint32_t object_count,
        _In_ const sai_route_entry_t *route_entry,
        _In_ sai_bulk_op_error_mode_t mode,
        _Out_ sai_status_t *object_statuses);

    sai_status_t set_route_entries_attribute(
        _In_ uint32_t object_count,
        _In_ const sai_route_entry_t *route_entry,
        _In_ const sai_attribute_t *attr_list,
        _In_ sai_bulk_op_error_mode_t mode,
        _Out_ sai_status_t *object_statuses);

    sai_status_t get_route_entries_attribute(
        _In_ uint32_t object_count,
        _In_ const sai_route_entry_t *route_entry,
        _In_ const uint32_t *attr_count,
        _Inout_ sai_attribute_t **attr_list,
        _In_ sai_bulk_op_error_mode_t mode,
        _Out_ sai_status_t *object_statuses);
};
%ignore _sai_route_api_t;
%include "sai/sairoute.h"

struct sai_router_interface_api_t {
    sai_status_t create_router_interface(
        _Out_ sai_object_id_t *router_interface_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_router_interface(
        _In_ sai_object_id_t router_interface_id);

    sai_status_t get_router_interface_attribute(
        _In_ sai_object_id_t router_interface_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

    sai_status_t get_router_interface_stats(
        _In_ sai_object_id_t router_interface_id,
        _In_ uint32_t number_of_counters,
        _In_ const sai_stat_id_t *counter_ids,
        _Out_ uint64_t *counters);

    sai_status_t get_router_interface_stats_ext(
        _In_ sai_object_id_t router_interface_id,
        _In_ uint32_t number_of_counters,
        _In_ const sai_stat_id_t *counter_ids,
        _In_ sai_stats_mode_t mode,
        _Out_ uint64_t *counters);

    sai_status_t clear_router_interface_stats(
        _In_ sai_object_id_t router_interface_id,
        _In_ uint32_t number_of_counters,
        _In_ const sai_stat_id_t *counter_ids);

    sai_status_t set_router_interface_attribute(
        _In_ sai_object_id_t router_interface_id,
        _In_ const sai_attribute_t *attr);
};
%ignore _sai_router_interface_api_t;
%include "sai/sairouterinterface.h"

struct sai_scheduler_api_t {
    sai_status_t create_scheduler(_Out_ sai_object_id_t *scheduler_id,
                                  _In_ sai_object_id_t switch_id,
                                  _In_ uint32_t attr_count,
                                  _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_scheduler(_In_ sai_object_id_t scheduler_id);

    sai_status_t set_scheduler_attribute(_In_ sai_object_id_t scheduler_id,
                                         _In_ const sai_attribute_t *attr);

    sai_status_t get_scheduler_attribute(_In_ sai_object_id_t scheduler_id,
                                         _In_ uint32_t attr_count,
                                         _Inout_ sai_attribute_t *attr_list);
};
%ignore _sai_scheduler_api_t;
%include "sai/saischeduler.h"

struct sai_scheduler_group_api_t {
    sai_status_t create_scheduler_group(_Out_ sai_object_id_t *scheduler_id,
                                  _In_ sai_object_id_t switch_id,
                                  _In_ uint32_t attr_count,
                                  _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_scheduler_group(_In_ sai_object_id_t scheduler_id);

    sai_status_t set_scheduler_group_attribute(_In_ sai_object_id_t scheduler_id,
                                         _In_ const sai_attribute_t *attr);

    sai_status_t get_scheduler_group_attribute(_In_ sai_object_id_t scheduler_id,
                                         _In_ uint32_t attr_count,
                                         _Inout_ sai_attribute_t *attr_list);
};
%ignore _sai_scheduler_group_api_t;
%include "sai/saischedulergroup.h"

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
%extend _sai_system_port_config_t {
    _sai_system_port_config_t(PyObject *input) {
        sai_system_port_config_t *cfg = new sai_system_port_config_t();

        if (!PySequence_Check(input)) {
            PyErr_SetString(PyExc_TypeError, "Non-sequence value");
            return nullptr;
        }

        if (PyObject_Length(input) != 6) {
            PyErr_SetString(PyExc_TypeError, "Sequence should have length 6");
            return nullptr;
        }

        PyObject *port_id = PyList_GetItem(input, 0);
        PyObject *attached_switch_id = PyList_GetItem(input, 1);
        PyObject *attached_core_index = PyList_GetItem(input, 2);
        PyObject *attached_core_port_index = PyList_GetItem(input, 3);
        PyObject *speed = PyList_GetItem(input, 4);
        PyObject *num_voq = PyList_GetItem(input, 5);

        cfg->port_id = PyInt_AsLong(port_id);
        cfg->attached_switch_id = PyInt_AsLong(attached_switch_id);
        cfg->attached_core_index = PyInt_AsLong(attached_core_index);
        cfg->attached_core_port_index = PyInt_AsLong(attached_core_port_index);
        cfg->speed = PyInt_AsLong(speed);
        cfg->num_voq = PyInt_AsLong(num_voq);

        return cfg;
    }
}

%extend _sai_system_port_config_list_t {
    _sai_system_port_config_list_t(PyObject *input) {
        if (!PySequence_Check(input)) {
            PyErr_SetString(PyExc_TypeError, "Expecting sequence");
            return nullptr;
        }

        uint32_t list_len = PyObject_Length(input);
        sai_system_port_config_list_t *s = new sai_system_port_config_list_t();
        sai_system_port_config_t *list = new sai_system_port_config_t[list_len];
        s->count = list_len;
        s->list = list;
        for (uint32_t i = 0; i < s->count; i++) {
            PyObject *config = PyList_GetItem(input, i);
            if (!PySequence_Check(config)) {
                PyErr_SetString(PyExc_TypeError, "Non-sequence value found within sequence");
                return nullptr;
            }

            if (PyObject_Length(config) != 6) {
                PyErr_SetString(PyExc_TypeError, "Each element should have length 6");
                return nullptr;
            }
            PyObject *port_id = PyList_GetItem(config, 0);
            PyObject *attached_switch_id = PyList_GetItem(config, 1);
            PyObject *attached_core_index = PyList_GetItem(config, 2);
            PyObject *attached_core_port_index = PyList_GetItem(config, 3);
            PyObject *speed = PyList_GetItem(config, 4);
            PyObject *num_voq = PyList_GetItem(config, 5);

            s->list[i].port_id = PyInt_AsLong(port_id);
            s->list[i].attached_switch_id = PyInt_AsLong(attached_switch_id);
            s->list[i].attached_core_index = PyInt_AsLong(attached_core_index);
            s->list[i].attached_core_port_index = PyInt_AsLong(attached_core_port_index);
            s->list[i].speed = PyInt_AsLong(speed);
            s->list[i].num_voq = PyInt_AsLong(num_voq);
        }

        return s;
    }
}
#endif

struct sai_switch_api_t {
    sai_status_t create_switch(
        _Out_ sai_object_id_t *switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_switch(
        _In_ sai_object_id_t switch_id);

    sai_status_t set_switch_attribute(
        _In_ sai_object_id_t switch_id,
        _In_ const sai_attribute_t *attr);

   sai_status_t get_switch_attribute(
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

    sai_status_t get_switch_stats(_In_ sai_object_id_t switch_id,
                                  _In_ uint32_t number_of_counters,
                                  _In_ const sai_stat_id_t *counter_ids,
                                  _Out_ uint64_t *counters);

    sai_status_t get_switch_stats_ext(_In_ sai_object_id_t switch_id,
                                      _In_ uint32_t number_of_counters,
                                      _In_ const sai_stat_id_t *counter_ids,
                                      _In_ sai_stats_mode_t mode,
                                      _Out_ uint64_t *counters);

    sai_status_t clear_switch_stats(_In_ sai_object_id_t switch_id,
                                    _In_ uint32_t number_of_counters,
                                    _In_ const sai_stat_id_t *counter_ids);

};
%ignore _sai_switch_api_t;
%include "sai/saiswitch.h"

#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
struct sai_system_port_api_t {
    sai_status_t create_system_port(_Out_ sai_object_id_t* system_port_id,
                                    _In_ sai_object_id_t switch_id,
                                    _In_ uint32_t attr_count,
                                    _In_ const sai_attribute_t* attr_list);

    sai_status_t remove_system_port(
        _In_ sai_object_id_t system_port_id);

    sai_status_t set_system_port_attribute(
        _In_ sai_object_id_t system_port_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_system_port_attribute(
        _In_ sai_object_id_t system_port_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
};
%ignore _sai_system_port_api_t;
%include "sai/saisystemport.h"
#endif

struct sai_virtual_router_api_t {
    sai_status_t create_virtual_router(
        _Out_ sai_object_id_t *virtual_router_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_virtual_router(
        _In_ sai_object_id_t virtual_router_id);

    sai_status_t set_virtual_router_attribute(
        _In_ sai_object_id_t virtual_router_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_virtual_router_attribute(
        _In_ sai_object_id_t virtual_router_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
};
%ignore _sai_virtual_router_api_t;
%include "sai/saivirtualrouter.h"

struct sai_vlan_api_t {
    sai_status_t create_vlan(
        _Out_ sai_object_id_t *vlan_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_vlan(
        _In_ sai_object_id_t vlan_id);

    sai_status_t set_vlan_attribute(
        _In_ sai_object_id_t vlan_id, _In_ const sai_attribute_t* attr);

    sai_status_t get_vlan_attribute(
        _In_ sai_object_id_t vlan_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

    sai_status_t create_vlan_member(
        _Out_ sai_object_id_t *vlan_member_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_vlan_member(
        _In_ sai_object_id_t vlan_member_id);

    sai_status_t set_vlan_member_attribute(
        _In_ sai_object_id_t vlan_member_id, _In_ const sai_attribute_t* attr);

    sai_status_t get_vlan_member_attribute(
        _In_ sai_object_id_t vlan_member_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
};
%ignore _sai_vlan_api_t;
%include "sai/saivlan.h"

struct sai_wred_api_t {
    sai_status_t create_wred(_Out_ sai_object_id_t *wred_id,
                             _In_ sai_object_id_t switch_id,
                             _In_ uint32_t attr_count,
                             _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_wred(_In_ sai_object_id_t wred_id);

    sai_status_t set_wred_attribute(_In_ sai_object_id_t wred_id,
                                    _In_ const sai_attribute_t *attr);

    sai_status_t get_wred_attribute(_In_ sai_object_id_t wred_id,
                                    _In_ uint32_t attr_count,
                                    _Inout_ sai_attribute_t *attr_list);
};
%ignore _sai_wred_api_t;
%include "sai/saiwred.h"

struct sai_hash_api_t {
    sai_status_t create_hash(_Out_ sai_object_id_t* hash_id,
                             _In_ sai_object_id_t switch_id,
                             _In_ uint32_t attr_count,
                             _In_ const sai_attribute_t* attr_list);

    sai_status_t remove_hash(_In_ sai_object_id_t hash_id);

    sai_status_t set_hash_attribute(_In_ sai_object_id_t hash_id,
                                    _In_ const sai_attribute_t *attr);

    sai_status_t get_hash_attribute(_In_ sai_object_id_t hash_id,
                                    _In_ uint32_t attr_count,
                                    _Inout_ sai_attribute_t *attr_list);
};
%ignore _sai_hash_api_t;
%include "sai/saihash.h"

struct sai_acl_api_t {
    sai_status_t create_acl_table(
        _Out_ sai_object_id_t* acl_table_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t* attr_list);

    sai_status_t remove_acl_table(
        _In_ sai_object_id_t acl_table_id);

    sai_status_t set_acl_table_attribute(
        _In_ sai_object_id_t acl_table_id,
        _In_ const sai_attribute_t* attr);

    sai_status_t get_acl_table_attribute(
        _In_ sai_object_id_t acl_table_id,
        _In_ uint32_t attr_count,
        _Out_ sai_attribute_t* attr_list);

    sai_status_t create_acl_entry(
        _Out_ sai_object_id_t* acl_entry_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t* attr_list);

    sai_status_t remove_acl_entry(
        _In_ sai_object_id_t acl_entry_id);

    sai_status_t set_acl_entry_attribute(
        _In_ sai_object_id_t acl_entry_id,
        _In_ const sai_attribute_t* attr);

    sai_status_t get_acl_entry_attribute(
        _In_ sai_object_id_t acl_entry_id,
        _In_ uint32_t attr_count,
        _Out_ sai_attribute_t* attr_list);

    sai_status_t create_acl_counter(
        _Out_ sai_object_id_t* acl_counter_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t* attr_list);

    sai_status_t remove_acl_counter(
        _In_ sai_object_id_t acl_counter_id);

    sai_status_t set_acl_counter_attribute(
        _In_ sai_object_id_t acl_counter_id,
        _In_ const sai_attribute_t* attr);

    sai_status_t get_acl_counter_attribute(
        _In_ sai_object_id_t acl_counter_id,
        _In_ uint32_t attr_count,
        _Out_ sai_attribute_t* attr_list);

    sai_status_t create_acl_range(
        _Out_ sai_object_id_t* acl_range_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t* attr_list);

    sai_status_t remove_acl_range(
        _In_ sai_object_id_t acl_range_id);

    sai_status_t set_acl_range_attribute(
        _In_ sai_object_id_t acl_range_id,
        _In_ const sai_attribute_t* attr);

    sai_status_t get_acl_range_attribute(
        _In_ sai_object_id_t acl_range_id,
        _In_ uint32_t attr_count,
        _Out_ sai_attribute_t* attr_list);

    sai_status_t create_acl_table_group(
        _Out_ sai_object_id_t* acl_table_group_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t* attr_list);

    sai_status_t remove_acl_table_group(
        _In_ sai_object_id_t acl_table_group_id);

    sai_status_t set_acl_table_group_attribute(
        _In_ sai_object_id_t acl_table_group_id,
        _In_ const sai_attribute_t* attr);

    sai_status_t get_acl_table_group_attribute(
        _In_ sai_object_id_t acl_table_group_id,
        _In_ uint32_t attr_count,
        _Out_ sai_attribute_t* attr_list);

    sai_status_t create_acl_table_group_member(
        _Out_ sai_object_id_t* acl_table_group_member_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t* attr_list);

    sai_status_t remove_acl_table_group_member(
        _In_ sai_object_id_t acl_table_group_member_id);

    sai_status_t set_acl_table_group_member_attribute(
        _In_ sai_object_id_t acl_table_group_member_id,
        _In_ const sai_attribute_t* attr);

    sai_status_t get_acl_table_group_member_attribute(
        _In_ sai_object_id_t acl_table_group_member_id,
        _In_ uint32_t attr_count,
        _Out_ sai_attribute_t* attr_list);
};
%ignore _sai_acl_api_t;
%include "sai/saiacl.h"
%include "sai/saiqueue.h"

struct sai_policer_api_t {
    sai_status_t create_policer(_Out_ sai_object_id_t *policer_id,
                             _In_ sai_object_id_t switch_id,
                             _In_ uint32_t attr_count,
                             _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_policer(_In_ sai_object_id_t policer_id);

    sai_status_t set_policer_attribute(_In_ sai_object_id_t policer_id,
                                    _In_ const sai_attribute_t *attr);

    sai_status_t get_policer_attribute(_In_ sai_object_id_t policer_id,
                                    _In_ uint32_t attr_count,
                                    _Inout_ sai_attribute_t *attr_list);
    sai_status_t get_policer_stats(_In_ sai_object_id_t policer_id,
                                   _In_ uint32_t number_of_counters,
                                   _In_ const sai_stat_id_t *counter_ids,
                                   _Out_ uint64_t *counters);

    sai_status_t get_policer_stats_ext(_In_ sai_object_id_t policer_id,
                                       _In_ uint32_t number_of_counters,
                                       _In_ const sai_stat_id_t *counter_ids,
                                       _In_ sai_stats_mode_t mode,
                                       _Out_ uint64_t *counters);

    sai_status_t clear_policer_stats(_In_ sai_object_id_t policer_id,
                                     _In_ uint32_t number_of_counters,
                                     _In_ const sai_stat_id_t *counter_ids);
};
%ignore _sai_policer_api_t;
%include "sai/saipolicer.h"

struct sai_tunnel_api_t {
    sai_status_t create_tunnel_map(
        _Out_ sai_object_id_t *tunnel_map_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_tunnel_map(
        _In_ sai_object_id_t tunnel_map_id);

    sai_status_t set_tunnel_map_attribute(
        _In_ sai_object_id_t tunnel_map_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_tunnel_map_attribute(
        _In_ sai_object_id_t tunnel_map_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

    sai_status_t create_tunnel(
        _Out_ sai_object_id_t *tunnel_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_tunnel(
        _In_ sai_object_id_t tunnel_id);

    sai_status_t set_tunnel_attribute(
        _In_ sai_object_id_t tunnel_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_tunnel_attribute(
        _In_ sai_object_id_t tunnel_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

    sai_status_t get_tunnel_stats(
        _In_ sai_object_id_t tunnel_id,
        _In_ uint32_t number_of_counters,
        _In_ const sai_stat_id_t *counter_ids,
        _Out_ uint64_t *counters);

    sai_status_t get_tunnel_stats_ext(
        _In_ sai_object_id_t tunnel_id,
        _In_ uint32_t number_of_counters,
        _In_ const sai_stat_id_t *counter_ids,
        _In_ sai_stats_mode_t mode,
        _Out_ uint64_t *counters);

    sai_status_t clear_tunnel_stats(
        _In_ sai_object_id_t tunnel_id,
        _In_ uint32_t number_of_counters,
        _In_ const sai_stat_id_t *counter_ids);

    sai_status_t create_tunnel_term_table_entry(
        _Out_ sai_object_id_t *tunnel_term_table_entry_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_tunnel_term_table_entry(
        _In_ sai_object_id_t tunnel_term_table_entry_id);

    sai_status_t set_tunnel_term_table_entry_attribute(
        _In_ sai_object_id_t tunnel_term_table_entry_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_tunnel_term_table_entry_attribute(
        _In_ sai_object_id_t tunnel_term_table_entry_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

    sai_status_t create_tunnel_map_entry(
        _Out_ sai_object_id_t *tunnel_map_entry_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

    sai_status_t remove_tunnel_map_entry(
        _In_ sai_object_id_t tunnel_map_entry_id);

    sai_status_t set_tunnel_map_entry_attribute(
        _In_ sai_object_id_t tunnel_map_entry_id,
        _In_ const sai_attribute_t *attr);

    sai_status_t get_tunnel_map_entry_attribute(
        _In_ sai_object_id_t tunnel_map_entry_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);

};
%ignore _sai_tunnel_api_t;
%include "sai/saitunnel.h"
struct sai_mirror_api_t {
    sai_status_t create_mirror_session(
        _Out_ sai_object_id_t* mirror_session_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t* attr_list);
    sai_status_t remove_mirror_session(_In_ sai_object_id_t mirror_session_id);
    sai_status_t set_mirror_session_attribute(
        _In_ sai_object_id_t mirror_session_id,
        _In_ const sai_attribute_t* attr);
    sai_status_t get_mirror_session_attribute(
        _In_ sai_object_id_t mirror_session_id,
       _In_ uint32_t attr_count,
       _Inout_ sai_attribute_t* attr_list);
};
%ignore _sai_mirror_api_t;
%include "sai/saimirror.h"

struct sai_samplepacket_api_t {
    sai_status_t create_samplepacket(
        _Out_ sai_object_id_t* samplepacket_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t* attr_list);
    sai_status_t remove_samplepacket(_In_ sai_object_id_t samplepacket_id);
    sai_status_t set_samplepacket_attribute(
        _In_ sai_object_id_t samplepacket_id,
        _In_ const sai_attribute_t* attr);
    sai_status_t get_samplepacket_attribute(
        _In_ sai_object_id_t samplepacket_id,
       _In_ uint32_t attr_count,
       _Inout_ sai_attribute_t* attr_list);
};
%ignore _sai_samplepacket_api_t;
%include "saisamplepacket.h"

struct sai_tam_api_t {
    sai_status_t create_tam(
        _Out_ sai_object_id_t *tam_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam(
        _In_ sai_object_id_t tam_id);
    sai_status_t set_tam_attribute(
        _In_ sai_object_id_t tam_id,
        _In_ const sai_attribute_t *attr);
    sai_status_t get_tam_attribute(
        _In_ sai_object_id_t tam_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
    sai_status_t create_tam_report(
        _Out_ sai_object_id_t *tam_report_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam_report(
        _In_ sai_object_id_t tam_report_id);
    sai_status_t get_tam_report_attribute(
        _In_ sai_object_id_t tam_report_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
    sai_status_t set_tam_report_attribute(
        _In_ sai_object_id_t tam_report_id,
        _In_ const sai_attribute_t *attr);
    sai_status_t create_tam_transport(
        _Out_ sai_object_id_t *tam_transport_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam_transport(
        _In_ sai_object_id_t tam_transport_id);
    sai_status_t get_tam_transport_attribute(
        _In_ sai_object_id_t tam_transport_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
    sai_status_t set_tam_transport_attribute(
        _In_ sai_object_id_t tam_transport_id,
        _In_ const sai_attribute_t *attr);
    sai_status_t create_tam_collector(
        _Out_ sai_object_id_t *tam_collector_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam_collector(
        _In_ sai_object_id_t tam_collector_id);
    sai_status_t get_tam_collector_attribute(
        _In_ sai_object_id_t tam_collector_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
    sai_status_t set_tam_collector_attribute(
        _In_ sai_object_id_t tam_collector_id,
        _In_ const sai_attribute_t *attr);
    sai_status_t create_tam_event_action(
        _Out_ sai_object_id_t *tam_event_action_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam_event_action(
        _In_ sai_object_id_t tam_event_action_id);
    sai_status_t get_tam_event_action_attribute(
        _In_ sai_object_id_t tam_event_action_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
    sai_status_t set_tam_event_action_attribute(
        _In_ sai_object_id_t tam_event_action_id,
        _In_ const sai_attribute_t *attr);
    sai_status_t create_tam_event(
        _Out_ sai_object_id_t *tam_event_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);
    sai_status_t remove_tam_event(
        _In_ sai_object_id_t tam_event_id);
    sai_status_t get_tam_event_attribute(
        _In_ sai_object_id_t tam_event_id,
        _In_ uint32_t attr_count,
        _Inout_ sai_attribute_t *attr_list);
    sai_status_t set_tam_event_attribute(
        _In_ sai_object_id_t tam_event_id,
        _In_ const sai_attribute_t *attr);
};
%ignore _sai_tam_api_t;
%include "sai/saitam.h"

%{
    #include "sai_netlink_socket.h"
    #include "sai_netlink_test.h"
%}

%template(NlPsampleVec) std::vector<silicon_one::sai::NlPsample>;

%inline %{

    std::vector<silicon_one::sai::NlPsample> swig_wrap_recieve(const std::string& family, const std::string& group,uint32_t num_samples,int timeout_sec){
    std::vector<NlPsample> vec;
    Py_BEGIN_ALLOW_THREADS;
    vec = receive_psample_test(family, group, num_samples, timeout_sec);
    Py_END_ALLOW_THREADS;
    return vec;
}
%}


%include "sai_netlink_socket.h"
%include "sai_netlink_test.h"


%template(bufferPoolStatVec) std::vector<sai_buffer_pool_stat_t>;
%template(getBufferPoolCounters) get_counters<sai_buffer_pool_stat_t>;

%template(queueStatVec) std::vector<sai_queue_stat_t>;
%template(getQueueCounters) get_counters<sai_queue_stat_t>;

%template(bridgePortStatVec) std::vector<sai_bridge_port_stat_t>;
%template(getBridgePortCounters) get_counters<sai_bridge_port_stat_t>;

%template(portStatVec) std::vector<sai_port_stat_t>;
%template(getPortCounters) get_counters<sai_port_stat_t>;

%template(rifStatVec) std::vector<sai_router_interface_stat_t>;
%template(getRifCounters) get_counters<sai_router_interface_stat_t>;

%template(getQueueCountersExt) get_counters_ext<sai_queue_stat_t>;
%template(getBridgePortCountersExt) get_counters_ext<sai_bridge_port_stat_t>;
%template(getPortCountersExt) get_counters_ext<sai_port_stat_t>;
%template(getRifCountersExt) get_counters_ext<sai_router_interface_stat_t>;
%template(switchStatVec) std::vector<sai_switch_stat_t>;
%template(getSwitchCountersExt) get_counters_ext<sai_switch_stat_t>;

%template(policerStatVec) std::vector<sai_policer_stat_t>;
%template(getPolicerCounters) get_counters<sai_policer_stat_t>;
