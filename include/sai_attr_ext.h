// BEGIN_LEGAL
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

#ifndef __SAI_ATTR_EXT_H__
#define __SAI_ATTR_EXT_H__

/**
 * @def SAI_KEY_EXT_WARM_BOOT_TYPE
 *
 * 0: Default warm boot sequence. Save and restore everything
 * 1: Test mode warm boot. On shutdown, save to file, and release SAI data structs. Do not touch internal SDK structs
 *                         On restart, recover SAI state from file. Recreate pointers to internal SDK data where needed.
 * 2: Fake warm boot. On shutdown, do not close anything.
 *                    On restart, only recover threads, and external socket connections if needed
 * In modes 1 and 2, the assumption is that the upper layer do remove/create_switch sequence without exiting
 * the process. So, internal data structs are not freed, and remain in memory.
 *
 */
#define SAI_KEY_EXT_WARM_BOOT_TYPE                         "SAI_EXT_WARM_BOOT_TYPE"

// Extension of sai_vlan_member_attr_t; SAI VLAN custom attributes
typedef enum _sai_vlan_member_attr_ext_t
{
    SAI_VLAN_MEMBER_ATTR_EXT_START = SAI_VLAN_MEMBER_ATTR_CUSTOM_RANGE_START,

    /**
     * @brief Egress DOT1Q Tag VLAN
     *
     * Valid only for .1Q bridge ports.
     * When SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE is set to SAI_VLAN_TAGGING_MODE_TAGGED:
     *  1) If this attribute is created, rewrite the out tag VLAN ID with this value.
     *  2) If this attribute is not created, out tag VLAN ID will be equal to SAI_VLAN_MEMBER_ATTR_VLAN_ID.
     * When SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE is set to SAI_VLAN_TAGGING_MODE_UNTAGGED, this attribute is
     * ineffective. 
     *
     * @type sai_uint16_t
     * @flags CREATE_ONLY
     * @default "out tag VLAN will be equal to SAI_VLAN_MEMBER_ATTR_VLAN_ID"
     */
    SAI_VLAN_MEMBER_ATTR_EXT_EGR_DOT1Q_TAG_VLAN = SAI_VLAN_MEMBER_ATTR_EXT_START,

    SAI_VLAN_MEMBER_ATTR_EXT_END

} sai_vlan_member_attr_ext_t;

typedef enum _sai_router_interface_attr_ext_t
{
    SAI_ROUTER_INTERFACE_ATTR_EXT_START = SAI_ROUTER_INTERFACE_ATTR_CUSTOM_RANGE_START,

    /**
     * @brief Default Router Interface Egress DOT1Q Tag VLAN
     *
     * @type sai_uint16_t
     * @flags CREATE_ONLY
     * @default false
     */
    SAI_ROUTER_INTERFACE_ATTR_EXT_EGR_DOT1Q_TAG_VLAN = SAI_ROUTER_INTERFACE_ATTR_EXT_START,

    SAI_ROUTER_INTERFACE_ATTR_EXT_END

} sai_router_interface_attr_ext_t;

typedef enum _sai_router_interface_stat_ext_t
{
    SAI_ROUTER_INTERFACE_STAT_CUSTOM_RANGE_START = 0x10000000,

    /** Ingress IPv4 byte stat count */
    SAI_ROUTER_INTERFACE_STAT_IPV4_IN_OCTETS = SAI_ROUTER_INTERFACE_STAT_CUSTOM_RANGE_START,

    /** Ingress IPv4 packet stat count */
    SAI_ROUTER_INTERFACE_STAT_IPV4_IN_PACKETS,

    /** Ingress IPv6 byte stat count */
    SAI_ROUTER_INTERFACE_STAT_IPV6_IN_OCTETS,

    /** Ingress IPV6 packet stat count */
    SAI_ROUTER_INTERFACE_STAT_IPV6_IN_PACKETS,

    /** Ingress MPLS byte stat count */
    SAI_ROUTER_INTERFACE_STAT_MPLS_IN_OCTETS,

    /** Ingress MPLS packet stat count */
    SAI_ROUTER_INTERFACE_STAT_MPLS_IN_PACKETS,

    /** Egress IPv4 byte stat count */
    SAI_ROUTER_INTERFACE_STAT_IPV4_OUT_OCTETS,

    /** Egress IPv4 packet stat count */
    SAI_ROUTER_INTERFACE_STAT_IPV4_OUT_PACKETS,

    /** Egress IPv6 byte stat count */
    SAI_ROUTER_INTERFACE_STAT_IPV6_OUT_OCTETS,

    /** Egress IPV6 packet stat count */
    SAI_ROUTER_INTERFACE_STAT_IPV6_OUT_PACKETS,

    /** Egress MPLS byte stat count */
    SAI_ROUTER_INTERFACE_STAT_MPLS_OUT_OCTETS,

    /** Egress MPLS packet stat count */
    SAI_ROUTER_INTERFACE_STAT_MPLS_OUT_PACKETS,

} sai_router_interface_stat_ext_t;

typedef enum _sai_port_attr_ext_t
{
    SAI_PORT_ATTR_EXT_START = SAI_PORT_ATTR_CUSTOM_RANGE_START,

    /**
     * @brief System Port Global ID
     * Used as metadata in the sflow tunnel headers
     * Must be unique across all ports
     *
     * @type sai_uint16_t
     * @flags CREATE_ONLY
     * @default internal
     */
    SAI_PORT_ATTR_EXT_SYSTEM_PORT_ID = SAI_PORT_ATTR_EXT_START,

    SAI_PORT_ATTR_EXT_END

} sai_port_attr_ext_t;

/**
 * @brief List of Port Serdes attributes Extension
 */
typedef enum _sai_port_serdes_attr_ext_t
{
    SAI_PORT_SERDES_ATTR_EXT_START = SAI_PORT_SERDES_ATTR_CUSTOM_RANGE_START,

    /**
     * @brief Port serdes CTLE Tune
     *
     * List of port serdes CTLE Tune values. The values are of type sai_s32_list_t
     * where the count is number lanes in a port and the list specifies list of values
     * to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_CTLE_TUNE = SAI_PORT_SERDES_ATTR_EXT_START,

    /**
     * @brief Port serdes TX LUT Mode
     *
     * List of port serdes TX LUT mode. The values are of type sai_s32_list_t
     * where the count is number lanes in a port and the list specifies list of values
     * to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_TX_LUT_MODE,

    /**
     * @brief Port serdes control TX PRE1 filter
     *
     * List of port serdes TX fir precursor1 tap-filter values.
     * The values are of type sai_s32_list_t where the count is number lanes in
     * a port and the list specifies list of values to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_TX_PRE1,

    /**
     * @brief Port serdes control TX PRE2 filter
     *
     * List of port serdes TX fir precursor2 tap-filter values.
     * The values are of type sai_s32_list_t where the count is number lanes in
     * a port and the list specifies list of values to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_TX_PRE2,

    /**
     * @brief Port serdes control TX PRE3 filter
     *
     * List of port serdes TX fir precursor3 tap-filter values.
     * The values are of type sai_s32_list_t where the count is number lanes in
     * a port and the list specifies list of values to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_TX_PRE3,

    /**
     * @brief Port serdes control TX MAIN filter
     *
     * List of port serdes TX fir maincursor tap-filter values.
     * The values are of type sai_s32_list_t where the count is number lanes in
     * a port and the list specifies list of values to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_TX_MAIN,

    /**
     * @brief Port serdes control TX POST filter
     *
     * List of port serdes TX fir postcursor1 tap-filter values.
     * The values are of type sai_s32_list_t where the count is number lanes in
     * a port and the list specifies list of values to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_TX_POST,

    /**
     * @brief Port serdes control TX POST2 filter
     *
     * List of port serdes TX fir postcursor2 tap-filter values.
     * The values are of type sai_s32_list_t where the count is number lanes in
     * a port and the list specifies list of values to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_TX_POST2,

    /**
     * @brief Port serdes control TX POST3 filter
     *
     * List of port serdes TX fir postcursor3 tap-filter values.
     * The values are of type sai_s32_list_t where the count is number lanes in
     * a port and the list specifies list of values to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_TX_POST3,

    /**
     * @brief Port serdes control TX Inner EYE1
     *
     * List of port serdes TX Inner EYE1 values.
     * The values are of type sai_s32_list_t where the count is number lanes in
     * a port and the list specifies list of values to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE1,

    /**
     * @brief Port serdes control TX Inner EYE2
     *
     * List of port serdes TX Inner EYE2 values.
     * The values are of type sai_s32_list_t where the count is number lanes in
     * a port and the list specifies list of values to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_TX_INNER_EYE2,

    /**
     * @brief Port serdes control RX CTLE Code
     *
     * List of port serdes RX CTLE Code values.
     * The values are of type sai_s32_list_t where the count is number lanes in
     * a port and the list specifies list of values to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_RX_CTLE_CODE,

    /**
     * @brief Port serdes control RX DSP Mode
     *
     * List of port serdes RX DSP Mode values.
     * The values are of type sai_s32_list_t where the count is number lanes in
     * a port and the list specifies list of values to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_RX_DSP_MODE,

    /**
     * @brief Port serdes control RX AFE Trim
     *
     * List of port serdes RX AFE Trim values.
     * The values are of type sai_s32_list_t where the count is number lanes in
     * a port and the list specifies list of values to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_RX_AFE_TRIM,

    /**
     * @brief Port serdes control RX VGA Tracking
     *
     * List of port serdes RX VGA Tracking values.
     * The values are of type sai_s32_list_t where the count is number lanes in
     * a port and the list specifies list of values to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_RX_VGA_TRACKING,

    /**
     * @brief Port serdes control RX AC Coupling Bypass
     *
     * List of port serdes RX AC Coupling Bypass values.
     * The values are of type sai_s32_list_t where the count is number lanes in
     * a port and the list specifies list of values to be applied to each lane.
     *
     * @type sai_s32_list_t
     * @flags CREATE_AND_SET
     * @default internal
     */
    SAI_PORT_SERDES_ATTR_EXT_RX_AC_COUPLING_BYPASS,

    /**
     * @brief End of attributes
     */
    SAI_PORT_SERDES_ATTR_EXT_END

} sai_port_serdes_attr_ext_t;

// Switch attribute extension
typedef enum _sai_switch_attr_ext_t
{
    SAI_SWITCH_ATTR_EXT_START = SAI_SWITCH_ATTR_CUSTOM_RANGE_START,

    /**
     * @brief List of ACL Field list
     *
     * The value is of type sai_s32_list_t where each list member is of type 
     * sai_acl_table_attr_t. Only fields in the range SAI_ACL_TABLE_ATTR_FIELD_START
     * and SAI_ACL_TABLE_ATTR_FIELD_END as well any custom SAI_ACL_TABLE_ATTR_FIELD
     * are allowed. All other field types in sai_acl_table_attr_t are ignored.
     *
     * @type sai_s32_list_t sai_acl_table_attr_t
     * @flags CREATE_ONLY
     * @default disabled 
     */
    SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST = SAI_SWITCH_ATTR_EXT_START,

    /**
     * @brief Inject ECC error. 
     * 
     * When this value is set, ECC error initiate register will be set in HW. 
     * As a result, ECC error will be generated. This feature is for testing and debug purpose.
     * If value is 1, 1 bit ecc error is generated and 2 for 2 bits error.
     * 
     * @type sai_uint16_t
     * @flags SET_ONLY
     */
    SAI_SWITCH_ATTR_EXT_HW_ECC_ERROR_INITIATE,
 
    /**
     * @brief End of attributes
     */
    SAI_SWITCH_ATTR_EXT_END

} sai_switch_attr_ext_t;

//////////////////////////////////////////////////
// TODO: This is the sai_switch_event_type_t and SAI_TAM_EVENT_ATTR_TYPE defination copied from PR1119.
//       We need to remove this once the pull requet is merged to SAI.
//       https://github.com/opencomputeproject/SAI/pull/1119
// 
/**
 * @brief TAM Switch Event Types
 */
typedef enum _sai_switch_event_type_t
{
    /** None */
    SAI_SWITCH_EVENT_TYPE_NONE,

    /** ALL */
    SAI_SWITCH_EVENT_TYPE_ALL,

    /** Stable Full */
    SAI_SWITCH_EVENT_TYPE_STABLE_FULL,

    /** Stable Error */
    SAI_SWITCH_EVENT_TYPE_STABLE_ERROR,

    /** Uncontrolled Shutdown */
    SAI_SWITCH_EVENT_TYPE_UNCONTROLLED_SHUTDOWN,

    /** Downgrade during Warm Boot */
    SAI_SWITCH_EVENT_TYPE_WARM_BOOT_DOWNGRADE,

    /** Parity Error */
    SAI_SWITCH_EVENT_TYPE_PARITY_ERROR,
} sai_switch_event_type_t;

typedef enum _sai_tam_event_attr_ext_t
{
    SAI_TAM_EVENT_ATTR_EXT_START = SAI_TAM_EVENT_ATTR_CUSTOM_RANGE_START,

    /**
     * @brief Type of ingress packet drops
     *
     * @type sai_packet_drop_type_ingress_t
     * @flags CREATE_AND_SET
     * @default SAI_PACKET_DROP_TYPE_INGRESS_NONE
     * @validonly SAI_TAM_EVENT_ATTR_TYPE == SAI_TAM_EVENT_TYPE_PACKET_DROP or SAI_TAM_EVENT_ATTR_TYPE == SAI_TAM_EVENT_TYPE_PACKET_DROP_STATEFUL
     */
    SAI_TAM_EVENT_ATTR_PACKET_DROP_TYPE_INGRESS = SAI_TAM_EVENT_ATTR_EXT_START,

    /**
     * @brief Type of MMU packet drops
     *
     * @type sai_packet_drop_type_mmu_t
     * @flags CREATE_AND_SET
     * @default SAI_PACKET_DROP_TYPE_MMU_NONE
     * @validonly SAI_TAM_EVENT_ATTR_TYPE == SAI_TAM_EVENT_TYPE_PACKET_DROP or SAI_TAM_EVENT_ATTR_TYPE == SAI_TAM_EVENT_TYPE_PACKET_DROP_STATEFUL
     */
    SAI_TAM_EVENT_ATTR_PACKET_DROP_TYPE_MMU,

    /**
     * @brief Type of egress packet drops
     *
     * @type sai_packet_drop_type_egress_t
     * @flags CREATE_AND_SET
     * @default SAI_PACKET_DROP_TYPE_EGRESS_NONE
     * @validonly SAI_TAM_EVENT_ATTR_TYPE == SAI_TAM_EVENT_TYPE_PACKET_DROP or SAI_TAM_EVENT_ATTR_TYPE == SAI_TAM_EVENT_TYPE_PACKET_DROP_STATEFUL
     */
    SAI_TAM_EVENT_ATTR_PACKET_DROP_TYPE_EGRESS,

    /**
     * @brief Type of switch event
     *
     * @type sai_s32_list_t sai_switch_event_type_t
     * @flags CREATE_AND_SET
     * @default empty
     * @validonly SAI_TAM_EVENT_ATTR_TYPE == SAI_TAM_EVENT_TYPE_SWITCH
     */
    SAI_TAM_EVENT_ATTR_SWITCH_EVENT_TYPE,

    SAI_TAM_EVENT_ATTR_EXT_END

} sai_tam_event_attr_ext_t;

// ENUM ID for Switch Type Event.
#define SAI_TAM_EVENT_TYPE_SWITCH   100

// TAM Vender Buffer Data structure - sai_tam_event_desc_t

typedef enum _sai_tam_switch_event_ecc_err_type_e {
    ECC_COR = 0,
    ECC_UNCOR = 1,
    PARITY = 2
} sai_tam_switch_event_ecc_err_type_e;

typedef struct _sai_tam_switch_ecc_error_t {
    sai_tam_switch_event_ecc_err_type_e err_type;
    sai_uint32_t instance_addr;
    sai_uint64_t data;
} sai_tam_switch_ecc_error_t;

typedef sai_switch_event_type_t sai_tam_switch_event_type_t;

typedef union _sai_tam_switch_event_data_t {
    sai_tam_switch_ecc_error_t parity_error;
    // struct stable_full_s {
    // ...
    // }
    // struct stable_error_s {
    // ...
    // }
    // struct warmboot_downgrade_s {
    // ...
    // }
} sai_tam_switch_event_data_t;

typedef struct _sai_tam_switch_event_t {
    sai_tam_switch_event_type_t type;
    sai_tam_switch_event_data_t data;
} sai_tam_switch_event_t;

/* TBA:
typedef struct _sai_tam_ingress_pkt_drop_event_t {
    sai_packet_drop_type_ingress_t type;
    // ... other members
} sai_tam_ingress_pkt_drop_event_t;

typedef struct _sai_tam_egress_pkt_drop_event_t {
    sai_packet_drop_type_egress_t type;
    // ... other members
} sai_tam_egress_pkt_drop_event_t;

typedef struct _sai_tam_mmu_pkt_drop_event_t {
    sai_packet_drop_type_mmu_t type;
    // ... other members
} sai_tam_mmu_pkt_drop_event_t;

typedef struct _sai_tam_resource_util_t {
    size_t state;                ///< Resource state.
    size_t used;                 ///< Resource's usage.
    size_t total;                ///< Total physical Resources.
} sai_tam_resource_util_t;
*/

typedef union _sai_tam_event_data_t {
    // when event_type == SAI_TAM_EVENT_TYPE_SWITCH
    sai_tam_switch_event_t switch_event;
    
    // when event_type == SAI_TAM_EVENT_ATTR_PACKET_DROP_TYPE_INGRESS
    // sai_tam_ingress_pkt_drop_event_t ingress_pkt_drop_event;
    
    // when event_type == SAI_TAM_EVENT_ATTR_PACKET_DROP_TYPE_EGRESS
    // sai_tam_egress_pkt_drop_event_t egress_pkt_drop_event;
    
    // when event_type == SAI_TAM_EVENT_ATTR_PACKET_DROP_TYPE_MMU
    // sai_tam_mmu_pkt_drop_event_t mmu_pkt_drop_event;
    
    // when event_type == SAI_TAM_EVENT_TYPE_RESOURCE_UTILIZATION
    // sai_tam_resource_util_t resource_util;
} sai_tam_event_data_t;

typedef struct _sai_tam_event_desc_t {
    /// Block ID of interrupt source register
    sai_uint32_t block_id;
    
    /// Time stamp of the notification in nano-seconds based on CLOCK_MONOTONIC.
    sai_uint64_t timestamp_ns;
    
    /// SAI TAM event type
    sai_tam_event_type_t type;
    
    /// SAI TAM Event Info
    sai_tam_event_data_t event;
} sai_tam_event_desc_t;

typedef enum _sai_lag_attr_ext_t {
    SAI_LAG_ATTR_EXT_START = SAI_LAG_ATTR_CUSTOM_RANGE_START,

    /**
     * @brief To enable/disable Decrement TTL
     *
     * @type bool
     * @flags CREATE_AND_SET
     * @default false
     */
    SAI_LAG_ATTR_EXT_DISABLE_DECREMENT_TTL,

    /**
     * @brief Enable/Disable Mirror session
     *
     * Enable ingress mirroring by assigning list of mirror session object id
     * as attribute value, disable ingress mirroring by assigning object_count
     * as 0 in objlist.
     *
     * @type sai_object_list_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_MIRROR_SESSION
     * @default empty
     */
    SAI_LAG_ATTR_EXT_INGRESS_MIRROR_SESSION,
    
    
    /**
     * @brief Enable/Disable Mirror session
     *
     * Enable egress mirroring by assigning list of mirror session object id
     * as attribute value, disable egress mirroring by assigning object_count
     * as 0 in objlist.
     *
     * @type sai_object_list_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_MIRROR_SESSION
     * @default empty
     */
    SAI_LAG_ATTR_EXT_EGRESS_MIRROR_SESSION,

    /**
     * @brief Enable/Disable Samplepacket session
     *
     * Enable ingress sampling by assigning samplepacket object id.Disable
     * ingress sampling by assigning #SAI_NULL_OBJECT_ID as attribute value.
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_SAMPLEPACKET
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_LAG_ATTR_EXT_INGRESS_SAMPLEPACKET_ENABLE,
    
    /**
     * @brief Enable/Disable Samplepacket session
     *
     * Enable egress sampling by assigning samplepacket object id Disable
     * egress sampling by assigning #SAI_NULL_OBJECT_ID as attribute value.
     *
     * @type sai_object_id_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_SAMPLEPACKET
     * @allownull true
     * @default SAI_NULL_OBJECT_ID
     */
    SAI_LAG_ATTR_EXT_EGRESS_SAMPLEPACKET_ENABLE,
    
    
    /**
     * @brief Enable/Disable Samplepacket session
     *
     * Enable sample ingress mirroring by assigning list of mirror object ids Disable
     * sample ingress mirroring by assigning object_count as 0 in objlist
     *
     * @type sai_object_list_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_MIRROR_SESSION
     * @default empty
     */
    SAI_LAG_ATTR_EXT_INGRESS_SAMPLE_MIRROR_SESSION,
    
    /**
     * @brief Enable/Disable Samplepacket session
     *
     * Enable sample egress mirroring by assigning list of mirror object ids Disable
     * sample egress mirroring by assigning object_count as 0 in objlist
     *
     * @type sai_object_list_t
     * @flags CREATE_AND_SET
     * @objects SAI_OBJECT_TYPE_MIRROR_SESSION
     * @default empty
     */
    SAI_LAG_ATTR_EXT_EGRESS_SAMPLE_MIRROR_SESSION,

    /**
     * @brief MTU of LAG Port
     *
     * @type sai_uint32_t
     * @flags CREATE_AND_SET
     * @default 9100
     */
    SAI_LAG_ATTR_EXT_MTU

} sai_lag_attr_ext_t;

typedef enum _sai_in_drop_reason_ext_t {
    SAI_IN_DROP_REASON_EXT_START = SAI_IN_DROP_REASON_CUSTOM_RANGE_BASE,

    /** MPLS Routing table lookup miss */
    SAI_IN_DROP_REASON_MPLS_MISS

} sai_in_drop_reason_ext_t;

typedef enum _sai_hostif_trap_type_ext_t {
    /** Default packet action is drop */
    SAI_HOSTIF_TRAP_TYPE_EXT_SMAC_EQUALS_DMAC = SAI_HOSTIF_TRAP_TYPE_SWITCH_CUSTOM_RANGE_BASE,
    SAI_HOSTIF_TRAP_TYPE_BGP_KEEPALIVE,
    SAI_HOSTIF_TRAP_TYPE_BGPV6_KEEPALIVE,
    SAI_HOSTIF_TRAP_TYPE_NEIGHBOR_MISS
} sai_hostif_trap_type_ext_t;

// end TODO
//////////////////////////////////////////////////

#endif
