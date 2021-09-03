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

#ifndef __SAI_CONSTANTS_H__
#define __SAI_CONSTANTS_H__

#include <stdint.h>

#define SAI_VERSION_CODE(a, b, c) (((a) << 24) + ((b) << 16) + ((c) << 8))
#define SAI_VERSION_CODE_PRE_RELEASE(a, b, c, d) (SAI_VERSION_CODE(a, b, c) + d)

namespace silicon_one
{
namespace sai
{
enum class hw_device_type_e { NONE, PACIFIC, GIBRALTAR, INVALID };
enum class port_entry_type_e { MAC = 0, PCI = 1, INTERNAL_PCI = 2, NPUH = 3, RECYCLE = 4 };

// Supported switch init mode
enum class lsai_sw_init_mode_e {
    NONE = 0, // Do not init.
    L2BRIDGE, // Default l2 bridge setup
    PORTONLY  // Create port only; this is useful for user to define bridge ports.
};

// Serdes Media Type in SI parameters files
enum class lsai_serdes_media_type_e {
    NOT_PRESENT = 0, // SDK default
    COPPER,          // cable wire or front panel port
    OPTIC,           // optic/fiber module connection
    CHIP2CHIP,       // chip-to-chip connection include fabric, ASIC, or PCB loopback.
    LOOPBACK         // Electrical loopback
};

// lsai_device class resource controls
static constexpr int NUM_QUEUE_PER_PORT = 8;

static constexpr uint32_t MAX_SAI_EGRESS_BUFFER_POOL_SIZE_PA = 64 * 1024 * 1024;
static constexpr uint32_t MAX_SAI_EGRESS_BUFFER_POOL_SIZE_GB = 108 * 1024 * 1024;
static constexpr uint16_t BUFFER_POOL_ENTRY_SIZE = 384;
static constexpr uint32_t BUFFER_POOL_SIZE_IN_BYTES = BUFFER_POOL_ENTRY_SIZE * 1024 * 1024;
static constexpr uint32_t MAX_BUFFER_POOL_COUNT = 4;

static constexpr int SAI_MAX_TAM_REPORT = 8;
static constexpr int SAI_MAX_TAM_EVENT_ACTION = 32;
static constexpr int SAI_MAX_TAM_TRANSPORT = 8;
static constexpr int SAI_MAX_TAM_COLLECTOR = 8;
static constexpr int SAI_MAX_TAM_EVENT = 256;
static constexpr int SAI_MAX_TAM = 1;
// hardcoded values for now, until we support setting them using SAI_TAM_INT_ properties
static constexpr uint64_t LSAI_INT_PROBE_MARKER = 0xaaaabbbbccccdddd;
static constexpr uint64_t LSAI_INT_DEVICE_ID = 1;

static constexpr int LSAI_MAX_ECMP_GROUPS = 8192;
static constexpr int LSAI_MAX_ECMP_GROUP_MEMBERS = 512;

// Port Speed controls
static constexpr int INJECT_PORT_SPEED = 1000;        // mbps
static constexpr int PUNT_PORT_SPEED = 1000;          // mbps
static constexpr int RECYCLE_PORT_SPEED = 1000 * 100; // mbps

// Hardware/SerDes Defines
static constexpr uint32_t IFGS_PER_SLICE = 2;      // Number of IFGs in Slice
static constexpr uint32_t HW_LANE_PIF_MASK = 0xFF; // Mask of PIF in SAI HW lane number.
static constexpr uint32_t SERDES_PREEMPHASIS_DEFAULT_VALUE = 50;
static constexpr uint32_t PORT_SERDES_ENABLE_SQUELCH_PREEM_VAL = 0; // 0 pre-emphasis value as serdes squelch is enabled.

// Packet buffers controls
static constexpr uint32_t SAI_DEFAULT_MTU_SIZE = 1514;     // SAI default MTU size for PORT (defined by SAI)
static constexpr uint32_t SAI_DEFAULT_LAG_MTU_SIZE = 9100; // SAI default MTU size for LAG (defined by SAI)
static constexpr uint32_t SAI_MAC_MAX_MTU_SIZE = 10012;    // Max MTU size for SAI Port Objects, from
                                                           // pacific/src/hld/system/mac_pool_port.cpp:MAX_NETWORK_PORT_PACKET_SIZE.
                                                           // Symbolic linked by gibraltar (Same value for gibraltar).
static constexpr uint32_t SOCKET_IF_DEFAULT_MTU_SIZE = 10240; // Max MTU size of interface for socket packet
static constexpr int INJECT_BUFFER_SIZE = SOCKET_IF_DEFAULT_MTU_SIZE;

// Others Defines
static constexpr float INVALID_CACHED_TEMPERATURE = -273.0;

static constexpr int BOOT_TYPE_COLD = 0;
static constexpr int BOOT_TYPE_WARM = 1;
static constexpr int BOOT_TYPE_FAST = 2;

// CRM Max Values
static constexpr uint32_t LSAI_MAX_DEBUG_COUNTERS = 5000; // arbitrary number. We can increase it. There is no real limitation.
static constexpr uint64_t SAI_MAX_ROUTES = 450000;

static constexpr uint32_t BITS_IN_BYTE = 8;

static constexpr uint32_t LSAI_L2CP_PROFILE = 0x1;

#define SAI_ACL_KEY_PROFILE_FILE "ACL_KEY_PROFILE_FILE"

// clang-format off

/*
 *  id,
 *  {create, remove, set, get}, // implemented
 *  {create, remove, set, get}, // supported
 *  getter, getter_arg,
 *  setter, setter_arg
 */
#define SAI_ATTR_CREATE_ONLY(attr, getfunc)  \
    {attr,                                   \
     { true, false, false, true },           \
     { true, false, false, true },           \
     getfunc, (void*)attr,                   \
     nullptr, nullptr}

#define SAI_ATTR_CREATE_AND_SET(attr, getfunc, setfunc)  \
    {attr,                                               \
     { true, false, true, true },                        \
     { true, false, true, true },                        \
     getfunc, (void*)attr,                               \
     setfunc, (void*)attr}

#define SAI_ATTR_READ_ONLY(attr, getfunc)                \
    {attr,                                               \
     {false, false, false, true},                        \
     {false, false, false, true},                        \
     getfunc, (void*)attr, nullptr, nullptr}
}
}
#endif
