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

#include "sai_device.h"
#include "api/cgm/la_voq_cgm_profile.h"
#include "api/tm/la_interface_scheduler.h"
#include "api/npu/la_filter_group.h"
#include "api/npu/la_copc.h"
#include "api/packetapi/la_packet_headers.h"
#include "api/packetapi/la_packet_types.h"
#include "api/system/la_l2_punt_destination.h"
#include "api/system/la_log.h"
#include "api/system/la_punt_destination.h"
#include "api/system/la_l2_mirror_command.h"
#include "api/system/la_punt_inject_port.h"
#include "api/system/la_npu_host_port.h"
#include "api/system/la_device.h"
#include "api/types/la_limit_types.h"
#include "common/gen_utils.h"
#include "common/la_status.h"
#include "lld/ll_device.h"
#include "port_helper.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_vlan.h>
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <thread>
#include <linux/ip.h>
#include <bitset>
#include "sai_bridge.h"
#include "sai_lag.h"
#include "sai_mpls.h"
#include "sai_queue.h"
#include "sai_switch.h"
#include "sai_strings.h"
#include "sai_trap.h"
#include "sai_scheduler_group.h"
#include "sai_utils.h"

namespace silicon_one
{
namespace sai
{
#define MACRO_AS_STRING(s) #s
#define STRINGIFY(s) MACRO_AS_STRING(s)

struct sai_event_priority_t {
    la_event_e event;
    uint32_t priority;
    bool skip_inject_up;
    bool skip_p2p;
    bool overwrite_phb;
};

// list of events/traps default to forward
const static std::vector<la_event_e> sai_clear_trap_vec = {
    LA_EVENT_ETHERNET_BCAST_PKT,
    LA_EVENT_L3_ICMP_REDIRECT,
    LA_EVENT_ETHERNET_ARP,
    LA_EVENT_ETHERNET_DHCPV4_SERVER,
    LA_EVENT_ETHERNET_DHCPV4_CLIENT,
    LA_EVENT_ETHERNET_DHCPV6_SERVER,
    LA_EVENT_ETHERNET_DHCPV6_CLIENT,
};

// list of events/traps default to punt
const static std::vector<sai_event_priority_t> sai_punt_trap_vec = {
    {LA_EVENT_L3_LOCAL_SUBNET, (uint32_t)LA_EVENT_L3_LOCAL_SUBNET, false, false, true},
    {LA_EVENT_ETHERNET_LEARN_PUNT, (uint32_t)LA_EVENT_ETHERNET_LEARN_PUNT, false, false, true},
    {LA_EVENT_ETHERNET_HOP_BY_HOP, (uint32_t)LA_EVENT_ETHERNET_HOP_BY_HOP, false, false, true},
    {LA_EVENT_L3_ACL_FORCE_PUNT, (uint32_t)LA_EVENT_L3_ACL_FORCE_PUNT, false, false, false},
    {LA_EVENT_ETHERNET_ACL_FORCE_PUNT, (uint32_t)LA_EVENT_ETHERNET_ACL_FORCE_PUNT, false, false},
};

// list of events/traps default to drop
const static std::vector<sai_event_priority_t> sai_drop_trap_vec = {
    {LA_EVENT_IPV6_MC_FORWARDING_DISABLED, 1, true, false, true},
};

// list of events/traps with max size counters
const static std::vector<la_event_e> sai_max_counter_trap_vec = {
    LA_EVENT_L3_DROP_ADJ,
    LA_EVENT_ETHERNET_NO_SERVICE_MAPPING,
    LA_EVENT_ETHERNET_NO_TERMINATION_ON_L3_PORT,
    LA_EVENT_ETHERNET_SA_DA_ERROR,
    LA_EVENT_ETHERNET_VLAN_MEMBERSHIP,
    LA_EVENT_ETHERNET_SA_MULTICAST,
    LA_EVENT_ETHERNET_SA_ERROR,
    LA_EVENT_ETHERNET_DA_ERROR,
    LA_EVENT_ETHERNET_SAME_INTERFACE,
    LA_EVENT_L3_LOCAL_SUBNET,
    LA_EVENT_L3_TX_MTU_FAILURE,
    LA_EVENT_L3_ACL_DROP,
    LA_EVENT_IPV4_CHECKSUM,
    LA_EVENT_IPV4_HEADER_ERROR,
    LA_EVENT_IPV4_NON_COMP_MC,
    LA_EVENT_IPV4_MC_FORWARDING_DISABLED,
    LA_EVENT_IPV6_ILLEGAL_DIP,
    LA_EVENT_IPV6_HEADER_ERROR,
    LA_EVENT_MPLS_ILM_MISS,
};

sai_status_t
lsai_device::tam_notification_handler(const la_notification_desc& desc, const std::string& notification_str)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    if (m_dev == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    lsai_tam_event_desc sai_desc{};
    sai_desc = desc;

    sai_log_message(SAI_API_SWITCH,
                    sai_desc.event_level(),
                    "tam_notification_handler: %s message - %s, block_id(%d), addr(%d), event: %s.",
                    notification_str.c_str(),
                    sai_desc.types_in_str().c_str(),
                    desc.block_id,
                    desc.addr,
                    sai_desc.event_in_str().c_str());

    if (m_tam_registry.size() == 0) {
        sai_log_warn(SAI_API_SWITCH, "tam_notification_handler: received notification but no registered tam object.");
        return SAI_STATUS_SUCCESS;
    }

    la_status status{LA_STATUS_SUCCESS};
    bool handled_by_at_least_once = false;
    for (auto tam_ptr : m_tam_registry) {
        status = tam_ptr->event_handler(desc);
        if (status == LA_STATUS_SUCCESS) {
            handled_by_at_least_once = true;
        }
    }

    if (!handled_by_at_least_once) {
        sai_log_warn(SAI_API_SWITCH,
                     "tam_notification_handler: No tam event is created to report this event type(%s).",
                     sai_desc.types_in_str().c_str());
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_device::link_notification_handler(const la_notification_desc& link_desc, const std::string& notification_str)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    // la object pointers
    la_mac_port* mac_port;

    if (m_dev == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    sai_log_debug(SAI_API_SWITCH,
                  "link_notification_handler: %s message - %d, %d, mac_port[%d/%d/%d].",
                  notification_str.c_str(),
                  (int)link_desc.type,
                  (int)link_desc.u.link.type,
                  link_desc.u.link.slice_id,
                  link_desc.u.link.ifg_id,
                  link_desc.u.link.first_serdes_id);

    la_status status
        = m_dev->get_mac_port(link_desc.u.link.slice_id, link_desc.u.link.ifg_id, link_desc.u.link.first_serdes_id, mac_port);
    sai_return_on_la_error(status,
                           "link_notification_handler: Fail to find la_mac_port pointer by [%d/%d/%d].",
                           link_desc.u.link.slice_id,
                           link_desc.u.link.ifg_id,
                           link_desc.u.link.first_serdes_id);

    // from mac_port, find sai_object_id
    sai_object_id_t sai_port_id = SAI_NULL_OBJECT_ID;
    auto objs = m_dev->get_dependent_objects(mac_port);
    for (const auto obj : objs) {
        if (obj->type() == silicon_one::la_object::object_type_e::SYSTEM_PORT) {
            const la_system_port* sys_port = static_cast<const la_system_port*>(obj);
            la_system_port_gid_t gid = sys_port->get_gid();
            status = get_la2sai_port(gid, sai_port_id);
            sai_return_on_la_error(
                status, "link_notification_handler: Fail to find sai_port_id by sys_port(%p), gid(%d).", sys_port, gid);

            sai_log_debug(SAI_API_SWITCH,
                          "link_notification_handler: find system port(%p), sai_port_id(0x%lx), gid(%d)",
                          sys_port,
                          sai_port_id,
                          gid);
            break;
        }
    }
    if (sai_port_id == SAI_NULL_OBJECT_ID) {
        sai_log_error(SAI_API_SWITCH,
                      "link_notification_handler: Fail to find sai_port_id by la_mac_port(%p)(%d/%d/%d).",
                      mac_port,
                      link_desc.u.link.slice_id,
                      link_desc.u.link.ifg_id,
                      link_desc.u.link.first_serdes_id);
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    sai_port_oper_status_notification_t port_status = {sai_port_id, sai_port_oper_status_t::SAI_PORT_OPER_STATUS_NOT_PRESENT};
    switch (link_desc.u.link.type) {
    case la_link_notification_type_e::UP:
        port_status.port_state = sai_port_oper_status_t::SAI_PORT_OPER_STATUS_UP;
        break;
    case la_link_notification_type_e::DOWN:
        port_status.port_state = sai_port_oper_status_t::SAI_PORT_OPER_STATUS_DOWN;
        break;
    case la_link_notification_type_e::ERROR:
        // SAI doesn't support link error message from SDK. Therefore, send out warning messaage and return without invoke
        // notification_callbacks. Link Error message may not be fatal error for mac_port.
        sai_log_warn(SAI_API_PORT,
                     "Port-id(0x%llx), mac_port[%d/%d/%d], error received. check SDK log for detail.",
                     sai_port_id,
                     link_desc.u.link.slice_id,
                     link_desc.u.link.ifg_id,
                     link_desc.u.link.first_serdes_id);
        return SAI_STATUS_SUCCESS;
    default:
        sai_log_error(SAI_API_SWITCH, "link_notification_handler: Error link_desc.u.link.type(%d).", (int)link_desc.u.link.type);
        return SAI_STATUS_SUCCESS;
    }
    std::lock_guard<std::mutex> cb_lock(m_notification_callbacks.m_port_state_change_cb_lock);
    if (m_notification_callbacks.m_callbacks.on_port_state_change != nullptr) {
        m_notification_callbacks.m_callbacks.on_port_state_change(1, &port_status);
    } else {
        sai_log_debug(SAI_API_SWITCH, "link_notification_handler: No callback installed for port state change.");
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_device::pfc_watchdog_notification_handler(const la_notification_desc& notification_desc, const std::string& notification_str)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    // la object pointers
    la_mac_port* mac_port;

    if (m_dev == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    sai_log_debug(SAI_API_SWITCH,
                  "linkpfc_watchdog_notification_handler: %s message - %d,"
                  " mac_port[%d/%d/%d] pfc_priority - %d detected - %d.",
                  notification_str.c_str(),
                  (int)notification_desc.type,
                  notification_desc.u.pfc_watchdog.slice_id,
                  notification_desc.u.pfc_watchdog.ifg_id,
                  notification_desc.u.pfc_watchdog.first_serdes_id,
                  notification_desc.u.pfc_watchdog.pfc_priority,
                  notification_desc.u.pfc_watchdog.detected);

    la_status status;
    status = m_dev->get_mac_port(notification_desc.u.pfc_watchdog.slice_id,
                                 notification_desc.u.pfc_watchdog.ifg_id,
                                 notification_desc.u.pfc_watchdog.first_serdes_id,
                                 mac_port);
    sai_return_on_la_error(status,
                           "pfc_watchdog_notification_handler: Fail to find "
                           "la_mac_port pointer by [%d/%d/%d] pfc_priority - %d detected - %d.",
                           notification_desc.u.pfc_watchdog.slice_id,
                           notification_desc.u.pfc_watchdog.ifg_id,
                           notification_desc.u.pfc_watchdog.first_serdes_id,
                           notification_desc.u.pfc_watchdog.pfc_priority,
                           notification_desc.u.pfc_watchdog.detected);

    // from mac_port, find sai_object_id
    sai_object_id_t sai_port_id = SAI_NULL_OBJECT_ID;
    auto objs = m_dev->get_dependent_objects(mac_port);
    for (const auto obj : objs) {
        if (obj->type() == silicon_one::la_object::object_type_e::SYSTEM_PORT) {
            const la_system_port* sys_port = static_cast<const la_system_port*>(obj);
            la_system_port_gid_t gid = sys_port->get_gid();
            status = get_la2sai_port(gid, sai_port_id);
            sai_return_on_la_error(
                status, "pfc_watchdog_notification_handler: Fail to find sai_port_id by sys_port(%p), gid(%d).", sys_port, gid);

            sai_log_debug(SAI_API_SWITCH,
                          "pfc_watchdog_notification_handler: find system port(%p), sai_port_id(0x%lx), gid(%d)",
                          sys_port,
                          sai_port_id,
                          gid);
            break;
        }
    }
    if (sai_port_id == SAI_NULL_OBJECT_ID) {
        sai_log_error(SAI_API_SWITCH,
                      "pfc_watchdog_notification_handler: Fail to find sai_port_id "
                      "by la_mac_port(%p)(%d/%d/%d) pfc_priority - %d detected - %d.",
                      mac_port,
                      notification_desc.u.pfc_watchdog.slice_id,
                      notification_desc.u.pfc_watchdog.ifg_id,
                      notification_desc.u.pfc_watchdog.first_serdes_id,
                      notification_desc.u.pfc_watchdog.pfc_priority,
                      notification_desc.u.pfc_watchdog.detected);
        return SAI_STATUS_INVALID_OBJECT_ID;
    }

    lsai_object la_port(sai_port_id);
    auto sdev = la_port.get_device();
    port_entry pentry{};
    status = sdev->m_ports.get(la_port.index, pentry);
    sai_return_on_la_error(status,
                           "pfc_watchdog_notification_handler: Fail to get pentry "
                           "port_index(%d).",
                           la_port.index);
    lsai_object la_queue(SAI_OBJECT_TYPE_QUEUE, la_port.switch_id, 0);
    la_queue.detail.set(lsai_detail_type_e::QUEUE, lsai_detail_field_e::PORT, la_port.index);
    // TODO - currently pfc_priority/queue index is 1:1.
    la_queue.index = notification_desc.u.pfc_watchdog.pfc_priority;

    std::lock_guard<std::mutex> cb_lock(m_notification_callbacks.m_port_state_change_cb_lock);

    sai_queue_deadlock_notification_data_t pfc_deadlock;
    pfc_deadlock.app_managed_recovery = false;
    if (m_notification_callbacks.m_callbacks.on_queue_pfc_deadlock) {
        pfc_deadlock.queue_id = la_queue.object_id();
        pfc_deadlock.event = notification_desc.u.pfc_watchdog.detected ? SAI_QUEUE_PFC_DEADLOCK_EVENT_TYPE_DETECTED
                                                                       : SAI_QUEUE_PFC_DEADLOCK_EVENT_TYPE_RECOVERED;
        m_notification_callbacks.m_callbacks.on_queue_pfc_deadlock(1, &pfc_deadlock);
    }

    if (!pfc_deadlock.app_managed_recovery) {
        // Application is not managing PFC deadlock recovery so
        // SAI/SDK will manage it.
        sai_log_debug(SAI_API_SWITCH,
                      "pfc_watchdog_notification_handler: SAI handling "
                      "PFC DEADLOCK recovery for port(%d) pfc_priority(%d) detected(%d).",
                      la_port.index,
                      notification_desc.u.pfc_watchdog.pfc_priority,
                      notification_desc.u.pfc_watchdog.detected);
        pentry.pfc->pfc_deadlock_recovery(la_queue.index, notification_desc.u.pfc_watchdog.detected);
    }

    return SAI_STATUS_SUCCESS;
}

void
lsai_device::notification_listen()
{
    fd_set notify_fd_set;
    int retval;
    int max_fd; // maximum value of descriptor id
    la_status status;

    max_fd = std::max(m_crit_fd, m_normal_fd) + 1;
    sai_log_debug(
        SAI_API_SWITCH, "notification_listen: Started! crit_fd(%d), normal_fd(%d), max_fd(%d).", m_crit_fd, m_normal_fd, max_fd);

    FD_ZERO(&notify_fd_set);
    while (1) {
        FD_SET(m_crit_fd, &notify_fd_set);
        FD_SET(m_normal_fd, &notify_fd_set);
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000; // 10 milliseconds

        // block and listen to notify_fd_set
        retval = select(max_fd, &notify_fd_set, nullptr, nullptr, &timeout);

        if (m_threads_should_exit) {
            break;
        }

        if (retval <= 0) {
            continue;
        }

        int len;
        la_notification_desc desc{};
        std::string notification_str;

        // when select successfully return ...
        desc = {};

        // read the descriptor and clear the flag
        if (FD_ISSET(m_crit_fd, &notify_fd_set)) {
            len = read(m_crit_fd, &desc, sizeof(desc));
            notification_str = "critical";
            FD_CLR(m_crit_fd, &notify_fd_set);
        } else if (FD_ISSET(m_normal_fd, &notify_fd_set)) {
            len = read(m_normal_fd, &desc, sizeof(desc));
            notification_str = "normal";
            FD_CLR(m_normal_fd, &notify_fd_set);
        } else {
            // notification_str = "normal";
            sai_log_error(SAI_API_SWITCH, "notification_listen: Received notify_fd_set but not crit_fd or normal_fd.");
            continue;
        }

        if (len != sizeof(desc)) {
            // other side closed the socket
            if (len <= 0) {
                break;
            }
            sai_log_error(
                SAI_API_SWITCH, "notification_listen: %s pipe descriptor size error, len(%d).", notification_str.c_str(), len);
            continue;
        }

        // decode the descriptor type and handle the message.
        switch (desc.type) {
        case la_notification_type_e::NONE: ///< Reserved
            sai_log_warn(SAI_API_SWITCH, "notification_listen: la_notification_type_e::NONE is not supported.");
            break;
        case la_notification_type_e::BFD:
            sai_log_warn(SAI_API_SWITCH, "notification_listen: la_notification_type_e::BFD is not supported.");
            break;
        case la_notification_type_e::ECC: ///< ECC error reported by anything other than CIF block protected memory.
            tam_notification_handler(desc, notification_str);
            break;
        case la_notification_type_e::ECC_REMOTE:
            sai_log_warn(SAI_API_SWITCH, "notification_listen: la_notification_type_e::ECC_REMOTE is not supported.");
            break;
        case la_notification_type_e::INFORMATIVE: ///< Informative
            sai_log_warn(SAI_API_SWITCH, "notification_listen: la_notification_type_e::INFORMATIVE is not supported.");
            break;
        case la_notification_type_e::LACK_OF_RESOURCES: ///< Lack of resources.
            sai_log_warn(SAI_API_SWITCH, "notification_listen: la_notification_type_e::LACK_OF_RESOURCES is not supported.");
            break;
        case la_notification_type_e::LINK: ///< MAC link notification.
            link_notification_handler(desc, notification_str);
            break;
        case la_notification_type_e::MEM_PROTECT: ///< CIF block memory protection - ECC 1b: ECC 2b: Parity.
            tam_notification_handler(desc, notification_str);
            break;
        case la_notification_type_e::MISCONFIGURATION: ///< Misconfiguration
            sai_log_warn(SAI_API_SWITCH, "notification_listen: la_notification_type_e::MISCONFIGURATION is not supported.");
            break;
        case la_notification_type_e::OTHER:
            sai_log_warn(SAI_API_SWITCH, "notification_listen: la_notification_type_e::OTHER is not supported.");
            break;
        case la_notification_type_e::PCI: ///< PCI interface hotplug and AER.
            sai_log_warn(SAI_API_SWITCH, "notification_listen: la_notification_type_e::PCI is not supported.");
            break;
        case la_notification_type_e::RESOURCE_MONITOR: ///< Resources notifications.
            sai_log_warn(SAI_API_SWITCH, "notification_listen: la_notification_type_e::RESOURCE_MONITOR is not supported.");
            break;
        case la_notification_type_e::THRESHOLD_CROSSED: ///< Threshold crossed.
            sai_log_warn(SAI_API_SWITCH, "notification_listen: la_notification_type_e::THRESHOLD_CROSSED is not supported.");
            break;
        case la_notification_type_e::PFC_WATCHDOG: ///< PFC Watchdog detected.
            pfc_watchdog_notification_handler(desc, notification_str);
            break;
        default:
            sai_log_error(SAI_API_SWITCH,
                          "notification_listen: Received unsupported notification type (%d), size_of(%d) from %s pipe.",
                          (int)desc.type,
                          len,
                          notification_str.c_str());
        }
    }
    sai_log_error(SAI_API_SWITCH, "Exiting notification listen thread");
}

uint32_t
lsai_device::receive_pkt_from_simulator(int socket_fd, uint8_t* packet_buffer, size_t packet_buffer_size)
{
    // If sender sent partial packet, build complete packet upto packet_buffer_size  with repeated recv().
    // The byte stream received will start with 4 bytes of packet len. This len shim header
    // is handshake/format between NSIM sender/USK and application. Using that length
    //  value, receive all 'len' bytes before parsing packet.
    uint32_t buf_len = 0;
    uint8_t* recv_ptr = (uint8_t*)&buf_len;
    uint32_t off = 0;
    int curr_recv = 0;
    while (off != sizeof(buf_len)) {
        curr_recv = recv(socket_fd, recv_ptr + off, sizeof(buf_len) - off, 0);
        if (curr_recv <= 0) {
            if ((EAGAIN == errno) || (EINTR == errno)) {
                sai_log_debug(SAI_API_SWITCH, "punt_listen: EAGAIN / EINTR recevied during receive");
                continue;
            }
            sai_log_debug(SAI_API_SWITCH, "punt_listen: connection closed while reading length");
            break;
        } else {
            off += curr_recv;
        }
    }

    if (buf_len > packet_buffer_size) {
        sai_log_debug(SAI_API_SWITCH, "punt_listen: buf_len (%lx) > max packet size (%lx)", buf_len, packet_buffer_size);
        buf_len = 0;
        return buf_len;
    }

    off = 0;
    recv_ptr = (uint8_t*)packet_buffer;
    while (off != buf_len) {
        curr_recv = recv(socket_fd, recv_ptr + off, buf_len - off, 0);
        if (curr_recv <= 0) {
            if ((EAGAIN == errno) || (EINTR == errno)) {
                sai_log_debug(SAI_API_SWITCH, "punt_listen: EAGAIN / EINTR recevied during receive");
                continue;
            }

            sai_log_debug(SAI_API_SWITCH, "punt_listen: connection closed while reading packet");
            break;
        } else {
            off += curr_recv;
        }
    }

    if (off != buf_len) {
        sai_log_debug(SAI_API_SWITCH, "Could not receive packet of size (%lx). Possibly other end closed", buf_len);
        buf_len = 0;
        return buf_len;
    }

    return buf_len;
}

void
lsai_device::learn_yield()
{
    // start processing only when schedule queue is empty
    std::this_thread::yield();
}

void
lsai_device::learn_listen()
{
    static uint8_t packet_buffer[INJECT_BUFFER_SIZE]; // Assuming the consumer copies the packet data before we get new packet
    fd_set rfds;
    int retval;
    int len;
    int max_fd = m_learn_fd;

    sai_log_debug(SAI_API_FDB, "started learn listen thread\n");
    while (true) {
        FD_ZERO(&rfds);
        FD_SET(m_learn_fd, &rfds);

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000; // 10 milliseconds
        retval = select(max_fd + 1, &rfds, nullptr, nullptr, &timeout);

        if (m_threads_should_exit) {
            break;
        }

        if (retval <= 0) {
            learn_yield();
            continue;
        }

        if (!FD_ISSET(m_learn_fd, &rfds)) {
            learn_yield();
            continue;
        }

        if (m_is_sim) {
            len = receive_pkt_from_simulator(m_learn_fd, packet_buffer, sizeof(packet_buffer));
            sai_log_debug(SAI_API_FDB, "learn_listen: received notification %d bytes from kernel", len);
        } else {
            len = recv(m_learn_fd, packet_buffer, sizeof(packet_buffer), MSG_DONTWAIT);
        }

        if (len > 0) {
            size_t pkt_offset = 0;
            punt_process_status_e ret = sai_process_learn_header(packet_buffer, len, &pkt_offset);
            if (ret == punt_process_status_e::INVALID) {
                m_total_punt_process_failed++;
                m_punt_debugs->log("Error processing packet received from asic, total: %lu", m_total_punt_process_failed);
                learn_yield();
                continue;
            } else if (ret == punt_process_status_e::TERMINATED) {
                // Locally consumed packet processed
                learn_yield();
                continue;
            }
        } else {
            // No bytes to read means other side closed the connection
            break;
        }
    }

    sai_log_debug(SAI_API_FDB, "Terminating learn_listen thread");
    return;
}

la_status
lsai_device::send_samplepacket(const sai_object_id_t& hostif_oid,
                               sai_object_id_t& src_port_oid,
                               sai_object_id_t& dst_port_oid,
                               uint32_t mirror_id,
                               uint8_t* packet_buffer,
                               size_t& pkt_offset,
                               int len)
{
    constexpr uint32_t sample_max_size = 128;
    lsai_object la_nl_hostif_obj(hostif_oid);
    lsai_hostif nl_hostif;
    auto status = m_hostifs.get(la_nl_hostif_obj.index, nl_hostif);
    if (status != LA_STATUS_SUCCESS) {
        sai_log_error(SAI_API_SWITCH, "hostif 0x%lx does not exist", la_nl_hostif_obj.index);
        la_return_on_error(status);
    }

    // get ifindex from src_port hostif. If src_port is not known, use 0 for unknown
    uint16_t iifindex = 0;
    auto it = m_port_hostif_index_map.find(src_port_oid);
    if (it != m_port_hostif_index_map.end()) {
        iifindex = it->second;
    }

    uint16_t oifindex = 0;
    it = m_port_hostif_index_map.find(dst_port_oid);
    if (it != m_port_hostif_index_map.end()) {
        iifindex = it->second;
    }

    // get samplepacket rate
    auto sdev = la_nl_hostif_obj.get_device();

    // Currently only ingress sampling is supported so it is safe to assume we need to subtract the ingress_offset from the
    // mirror_id in the punt header
    // This logic makes some assumption and takes the mirror gid and maps back to session instance.
    la_uint64_t ingress_offset;
    status = sdev->m_dev->get_limit(limit_type_e::DEVICE__MIN_INGRESS_MIRROR_GID, ingress_offset);
    if (status != LA_STATUS_SUCCESS) {
        sai_log_error(SAI_API_SWITCH, "error getting ingress offset");
        la_return_on_error(status);
    }

    if (mirror_id >= ingress_offset) {
        mirror_id -= ingress_offset;
    }

    lasai_mirror_session_t* session = nullptr;
    status = sdev->m_mirror_handler->m_mirror_db.get_ptr(mirror_id, session);
    if (status != LA_STATUS_SUCCESS) {
        sai_log_error(SAI_API_SWITCH, "mirror_id 0x%lx does not exist", mirror_id);
        la_return_on_error(status);
    }

    uint32_t samplepacket_rate = session->sample_rate;

    // packet size before truncation
    uint32_t orig_size = len - pkt_offset;
    auto data = packet_buffer + pkt_offset;

    auto truncate_size = std::min(orig_size, sample_max_size);

    auto sstatus = nl_hostif.nl_sock->send_sample(iifindex, oifindex, samplepacket_rate, orig_size, data, truncate_size);
    if (sstatus != SAI_STATUS_SUCCESS) {
        sai_log_error(SAI_API_SWITCH, "error sending sflow sample %d", sstatus);
        return to_la_status(sstatus);
    }
    return LA_STATUS_SUCCESS;
}

void
lsai_device::punt_listen()
{
    static uint8_t packet_buffer[INJECT_BUFFER_SIZE]; // Assuming the consumer copies the packet data before we get new packet
    fd_set rfds;
    int retval;
    int len;
    int max_fd = m_punt_fd;

    sai_log_debug(SAI_API_SWITCH, "started punt listen thread\n");
    while (true) {
        FD_ZERO(&rfds);
        FD_SET(m_punt_fd, &rfds);

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000; // 10 milliseconds
        retval = select(max_fd + 1, &rfds, nullptr, nullptr, &timeout);

        if (m_threads_should_exit) {
            break;
        }

        if (retval <= 0) {
            continue;
        }

        if (!FD_ISSET(m_punt_fd, &rfds)) {
            continue;
        }

        if (m_is_sim) {
            len = receive_pkt_from_simulator(m_punt_fd, packet_buffer, sizeof(packet_buffer));
            sai_log_debug(SAI_API_SWITCH, "punt_listen: received %d bytes from kernel", len);
        } else {
            len = recv(m_punt_fd, packet_buffer, sizeof(packet_buffer), MSG_DONTWAIT);
        }

        if (len > 0) {
            uint32_t attr_count = 4;
            size_t pkt_offset = 0;
            size_t extra_offset = 0;
            sai_attribute_t attr_list[4];

            sai_object_id_t src_port_oid;
            sai_object_id_t dst_port_oid;
            sai_object_id_t trap_oid;
            uint32_t mirror_id;

            punt_process_status_e ret = sai_process_punt_header(
                packet_buffer, (uint32_t)len, &attr_count, attr_list, &pkt_offset, src_port_oid, dst_port_oid, trap_oid, mirror_id);
            if (ret == punt_process_status_e::INVALID) {
                m_total_punt_process_failed++;
                m_punt_debugs->log("Error processing packet received from asic, total: %lu", m_total_punt_process_failed);
                continue;
            } else if (ret == punt_process_status_e::TERMINATED) {
                // Locally consumed packet processed
                continue;
            }

            sai_trim_internal_header(packet_buffer + pkt_offset, &extra_offset);
            pkt_offset += extra_offset;
            if (pkt_offset >= (uint32_t)len) {
                m_total_punt_process_failed++;
                m_punt_debugs->log("Error processing packet received from asic, total: %lu", m_total_punt_process_failed);
                continue;
            }
            std::lock_guard<std::mutex> lock(m_notification_callbacks.m_packet_event_cb_lock);
            // callback mode
            if (m_notification_callbacks.m_callbacks.on_packet_event != nullptr) {
                m_notification_callbacks.m_callbacks.on_packet_event(
                    m_switch_id, len - pkt_offset, packet_buffer + pkt_offset, attr_count, attr_list);
            }

            {
                // find entry in hostif table
                lsai_hostif_table_entry_key_t entry_key = lsai_hostif_table_entry_key_t(src_port_oid, trap_oid);
                std::unique_lock<std::mutex> lock(m_hostif_lock);
                auto it = m_hostif_table_entry_map.find(entry_key);
                if (it == m_hostif_table_entry_map.end()) {
                    entry_key = lsai_hostif_table_entry_key_t(0, trap_oid);
                    it = m_hostif_table_entry_map.find(entry_key);
                    if (it == m_hostif_table_entry_map.end()) {
                        entry_key = lsai_hostif_table_entry_key_t(0, 0);
                        it = m_hostif_table_entry_map.find(entry_key);
                    }
                }

                if (it != m_hostif_table_entry_map.end()) {
                    auto hostif_table_entry = it->second;
                    if (hostif_table_entry.channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_GENETLINK) {
                        lsai_object trap_obj(trap_oid);
                        if (trap_obj.index == SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET) {
                            auto status = send_samplepacket(
                                hostif_table_entry.host_if, src_port_oid, dst_port_oid, mirror_id, packet_buffer, pkt_offset, len);
                            if (status != LA_STATUS_SUCCESS) {
                                return;
                            }
                        }
                    } else if (hostif_table_entry.channel_type == SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_NETDEV_PHYSICAL_PORT) {
                        const sai_object_id_t* hostif_oid = nullptr;
                        auto it = m_port_hostif_map.find(src_port_oid);
                        if (it != m_port_hostif_map.end()) {
                            hostif_oid = &(it->second);
                        }
                        lock.unlock();
                        if (hostif_oid != nullptr) {
                            lsai_object la_obj(*hostif_oid);
                            auto sdev = la_obj.get_device();
                            if (la_obj.type != SAI_OBJECT_TYPE_HOSTIF) {
                                return;
                            }
                            lsai_hostif hostif;
                            auto status = m_hostifs.get(la_obj.index, hostif);
                            if (status != LA_STATUS_SUCCESS) {
                                return;
                            }
                            bool wrote_all_bytes = false;
                            int bytes_to_send = len - pkt_offset;
                            while (!wrote_all_bytes && bytes_to_send > 0) {
                                int num_sent = write(hostif.netdev_fd, packet_buffer + pkt_offset, bytes_to_send);
                                if (num_sent > 0 && num_sent != bytes_to_send) {
                                    sai_log_debug(SAI_API_SWITCH,
                                                  "punt_listen: Injected partial packet of bytes %d into netdev interface. Sending "
                                                  "remaining %d bytes",
                                                  num_sent,
                                                  bytes_to_send);
                                    bytes_to_send -= num_sent;
                                    pkt_offset += num_sent;
                                } else {
                                    wrote_all_bytes = true;
                                }
                            }
                        }
                    }
                }
            }
        } else {
            if (m_is_sim && len == 0) {
                // in case of sim env and sock_stream type socket, keep listen thread alive.
                sai_log_debug(SAI_API_SWITCH, "punt_listen: received zero bytes from kernel. Should not have happened");
                continue;
            }
            sai_log_debug(SAI_API_SWITCH, "punt_listen: received %d bytes from kernel. Listen thread exited", len);
            // No bytes to read means other side closed the connection
            break;
        }
    }

    sai_log_debug(SAI_API_SWITCH, "Terminating punt_listen thread");
    return;
}

static la_status
sai_la_punject_if_create_raw_socket(const char* if_name, int* socket_out)
{
    sai_log_debug(SAI_API_SWITCH, "Create packet socket on %s", if_name);

    std::string cmd = "echo 0 > /proc/sys/net/ipv6/conf/";
    cmd = cmd + if_name + "/router_solicitations";
    std::system(cmd.c_str());

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        sai_log_error(SAI_API_SWITCH, "Couldn't create packet socket. error=%s", strerror(errno));
        return LA_STATUS_EINVAL;
    }

    struct ifreq req;
    memset(&req, 0, sizeof(req));
    snprintf(req.ifr_name, sizeof(req.ifr_name), "%s", if_name);

    req.ifr_mtu = SOCKET_IF_DEFAULT_MTU_SIZE;
    if (ioctl(sock, SIOCSIFMTU, &req)) {
        // MTU changed Fail
        sai_log_error(SAI_API_SWITCH, "Fail to set interface %s with MTU(%d).", if_name, req.ifr_mtu);
        return LA_STATUS_EINVAL;
    }

    int rv = ioctl(sock, SIOCGIFINDEX, &req);
    if (rv < 0) {
        sai_log_error(SAI_API_SWITCH,
                      "Couldn't get IFINDEX for punject interface %s. "
                      "error=%s",
                      if_name,
                      strerror(errno));
        close(sock);
        return LA_STATUS_EINVAL;
    }

    /* Make socket as non blocking*/
    (void)fcntl(sock, F_SETFL, O_NONBLOCK);

    struct sockaddr_ll addr;
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = req.ifr_ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);

    /* bind operation for socket*/
    rv = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (rv < 0) {
        sai_log_error(SAI_API_SWITCH, "Couldn't bind to interface %s. error=%s", if_name, strerror(errno));
        close(sock);
        return LA_STATUS_EINVAL;
    }
    *socket_out = sock;

    sai_log_notice(SAI_API_SWITCH, "Socket=%d created and bound to Device=%s", *socket_out, if_name);

    return LA_STATUS_SUCCESS;
}

static la_status
sai_la_puntject_up(const char* if_name)
{
    struct ifreq base_ifreq;
    memset(&base_ifreq, 0, sizeof(struct ifreq));
    snprintf(base_ifreq.ifr_name, sizeof(base_ifreq.ifr_name), "%s", if_name);

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        sai_log_error(SAI_API_SWITCH, "couldn't create packet socket. error=%s", strerror(errno));
        return LA_STATUS_EINVAL;
    }

    int rv = ioctl(sock, SIOCGIFFLAGS, &base_ifreq);
    if (rv < 0) {
        sai_log_error(SAI_API_SWITCH, "couldn't get netdevice=%s flags. error=%s", base_ifreq.ifr_name, strerror(errno));
        close(sock);
        return LA_STATUS_EINVAL;
    }

    if (!(base_ifreq.ifr_flags & IFF_UP)) {
        base_ifreq.ifr_flags |= (IFF_UP | IFF_RUNNING);
        rv = ioctl(sock, SIOCSIFFLAGS, &base_ifreq);
        if (rv < 0) {
            sai_log_error(SAI_API_SWITCH, "couldn't set netdevice=%s flags. error=%s", base_ifreq.ifr_name, strerror(errno));
            close(sock);
            return LA_STATUS_EINVAL;
        }
    } else {
        sai_log_info(SAI_API_SWITCH, "netdevice=%s is already UP", base_ifreq.ifr_name);
    }

    close(sock);
    return LA_STATUS_SUCCESS;
}

void
lsai_device::close_threads()
{
    if (m_threads_should_exit == false) {
        m_threads_should_exit = true;
        m_notification_thread.join();
        m_punt_thread.join();
        m_learn_thread.join();
        if (m_netdev_thread.joinable()) {
            m_netdev_thread.join();
        }
    }
}

la_status
lsai_device::initialize_kernel_conn_fd(transaction& txn)
{
    sai_log_debug(SAI_API_SWITCH, "initialize_kernel_conn_fd");

    if (m_is_sim) {
        // simulator
        std::stringstream base_ss;
        base_ss << "/tmp/leaba" << m_hw_dev_id << "_";
        std::stringstream punt_ss;
        punt_ss << PUNT_SLICE;
        std::string punt_socket_path = base_ss.str() + punt_ss.str();
        std::stringstream inject_ss;
        inject_ss << INJECTUP_SLICE;
        std::string inject_socket_path = base_ss.str() + inject_ss.str();
        std::stringstream learn_ss;
        learn_ss << LEARN_PUNT_SLICE;
        std::string learn_socket_path = base_ss.str() + learn_ss.str();
        struct sockaddr_un addr;

        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, punt_socket_path.c_str(), sizeof(addr.sun_path));
        m_punt_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (connect(m_punt_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            sai_log_error(SAI_API_SWITCH, "connect punt fd to %s failed", punt_socket_path.c_str());
            m_punt_fd = -1;
            return LA_STATUS_EINVAL;
        }

        strncpy(addr.sun_path, inject_socket_path.c_str(), sizeof(addr.sun_path));
        m_inject_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (connect(m_inject_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            sai_log_error(SAI_API_SWITCH, "connect inject fd to %s failed", inject_socket_path.c_str());
            m_inject_fd = -1;
            return LA_STATUS_EINVAL;
        }

        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, learn_socket_path.c_str(), sizeof(addr.sun_path));
        m_learn_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (connect(m_learn_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            sai_log_error(SAI_API_SWITCH, "connect learn fd to %s failed", learn_socket_path.c_str());
            m_learn_fd = -1;
            return LA_STATUS_EINVAL;
        }
    } else {
        la_status status;

        auto ldev = m_dev->get_ll_device();

        auto if_name = ldev->get_network_interface_name(PUNT_SLICE);
        status = sai_la_puntject_up(if_name.c_str());
        la_return_on_error(status);
        status = sai_la_punject_if_create_raw_socket(if_name.c_str(), &m_punt_fd);
        la_return_on_error(status);

        if_name = ldev->get_network_interface_name(INJECTUP_SLICE);
        status = sai_la_puntject_up(if_name.c_str());
        la_return_on_error(status);
        status = sai_la_punject_if_create_raw_socket(if_name.c_str(), &m_inject_fd);
        la_return_on_error(status);

        if_name = ldev->get_network_interface_name(LEARN_PUNT_SLICE);
        status = sai_la_puntject_up(if_name.c_str());
        la_return_on_error(status);
        status = sai_la_punject_if_create_raw_socket(if_name.c_str(), &m_learn_fd);
        la_return_on_error(status);

        status = to_la_status(m_knet_sock.open(m_hw_dev_id));
        if (status != LA_STATUS_SUCCESS) {
            m_use_knet = false;
            sai_log_info(SAI_API_SWITCH, "Could not open knet socket. Falling back to user space hostif implementation.");
        } else {
            m_use_knet = true;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::initialize_knet(transaction& txn)
{
    auto status = m_knet_sock.send_clear_kernel();
    la_return_on_error(to_la_status(status), "Failed to reset knet state");

    status = m_hostif_handler->initialize_knet_genetlinks();
    la_return_on_error(to_la_status(status));

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::initialize_kernel_start_threads(transaction& txn)
{
    // Create thread listening on m_punt_fd
    m_threads_should_exit = false;
    m_punt_thread = std::thread(&lsai_device::punt_listen, this);
    m_learn_thread = std::thread(&lsai_device::learn_listen, this);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::pre_initialize_notification_thread(transaction& txn)
{
    int notification_mask = (1 << (int)la_notification_type_e::LINK) | (1 << (int)la_notification_type_e::PFC_WATCHDOG)
                            | (1 << (int)la_notification_type_e::ECC) | (1 << (int)la_notification_type_e::MEM_PROTECT);

    // get/check notification IDs
    if (m_dev == nullptr) {
        sai_log_error(SAI_API_SWITCH, "pre_initialize_notification_thread: Error m_dev not ready");
        return LA_STATUS_EINVAL;
    }

    // opening notification sockets. Events will wait on the sockets until we start processing them
    txn.status = m_dev->open_notification_fds(notification_mask, m_crit_fd, m_normal_fd);
    la_return_on_error(txn.status, "Failed on open_notification_fds");

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::initialize_notification_thread(transaction& txn)
{
    // notification thread which handles all types of notifications from SDK.
    m_threads_should_exit = false;
    m_notification_thread = std::thread(&lsai_device::notification_listen, this);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::initialize_misc_defaults(transaction& txn)
{
    uint32_t nh_id;
    la_mac_addr_t mac_addr = {.flat = 0};

    // next_hop_drop_id is used for common drop next hop action
    txn.status = m_next_hops.allocate_id(nh_id);
    la_return_on_error(txn.status, "Out of nexthop IDs");
    txn.on_fail([=]() { m_next_hops.release_id(nh_id); });

    txn.status = m_dev->create_next_hop(nh_id, mac_addr, nullptr, la_next_hop::nh_type_e::DROP, m_next_hop_drop);
    la_return_on_error(txn.status, "Failed to create default next hop drop: %s\n", txn.status.message().c_str());
    txn.on_fail([=]() { m_dev->destroy(m_next_hop_drop); });

    lsai_object la_nh(m_switch_id);
    la_nh.index = nh_id;
    next_hop_entry entry{};
    entry.next_hop = m_next_hop_drop;
    m_next_hops.set(m_next_hop_drop_id, entry, la_nh);
    txn.on_fail([=]() { m_next_hops.erase_id(nh_id); });
    // Ignore the object we created in get_object_count/keys
    m_next_hops.set_ignore_in_get_num(1);

    // always create default vlan at initialization
    uint32_t df_index = 0;
    txn.status = m_vlans.allocate_id(DEFAULT_VLAN_ID, df_index);
    la_return_on_error(txn.status, "Failed to allocate default id");

    txn.status = create_la_bridge(m_default_bridge, shared_from_this(), df_index, txn);
    la_return_on_error(txn.status, "fail to create default bridge");

    m_l2_inject_up_port = m_cpu_l2_port_map[df_index].l2_port;

    lsai_object la_vlan(SAI_OBJECT_TYPE_VLAN, la_nh.switch_id, df_index);
    m_default_vlan_id = la_vlan.object_id();

    lsai_vlan_t lsaivlan;
    lsaivlan.m_oid = m_default_vlan_id;
    lsaivlan.m_sdk_switch = m_default_bridge;
    txn.status = m_vlans.set(la_vlan.index, lsaivlan);

    // always create dot1q bridge at initialization and it the same bridge as default vlan
    lsai_object la_bridge(SAI_OBJECT_TYPE_BRIDGE, la_nh.switch_id, df_index);
    m_default_1q_bridge_id = la_bridge.object_id();
    lsai_bridge_t lsaibridge;
    lsaibridge.m_oid = m_default_1q_bridge_id;
    lsaibridge.m_sdk_switch = m_default_bridge;
    txn.status = m_bridges.set(df_index, lsaibridge);

    // hardcoded value for first phase. Will be changed later
    m_dev->set_inband_network_telemetry_data(1, LSAI_INT_PROBE_MARKER);

    return create_acl_mirror_command();
}

la_status
lsai_device::create_acl_mirror_command()
{
    transaction txn;
    txn.status = LA_STATUS_SUCCESS;

    if (m_acl_mirror_cmds.size() != 0) {
        return LA_STATUS_SUCCESS;
    }

    // create 8 mirrors to cpu and each for one tc for acl copy
    for (int i = 0; i < SAI_NUMBER_OF_CPU_QUEUES; i++) {
        uint32_t session_instance = 0;
        txn.status = m_mirror_handler->allocate_mirror_session_instance(session_instance);
        la_return_on_error(txn.status);
        txn.on_fail([=]() { m_mirror_handler->free_mirror_session_instance(session_instance); });

        // create mirror cmd
        la_mac_addr_t mac_addr{.flat = 0x0a0b0c0d0e0fULL};
        float probability = 1;
        la_vlan_tag_tci_t vlan_tag{};
        la_uint_t voq_offset = i;

        la_obj_wrap<la_l2_mirror_command> l2_mirror_cmd;
        bool is_ingress_stage = true;
        la_mirror_gid_t ingress_mirror_gid;
        ingress_mirror_gid = m_mirror_handler->mirror_session_instance_to_gid(session_instance, is_ingress_stage);
        la_return_on_error(txn.status);

        txn.status = m_dev->create_l2_mirror_command(
            ingress_mirror_gid, m_punt_inject_port, mac_addr, vlan_tag, voq_offset, nullptr, probability, l2_mirror_cmd);
        la_return_on_error(txn.status);
        txn.on_fail([=]() { m_dev->destroy(l2_mirror_cmd); });

        m_acl_mirror_cmds.push_back(l2_mirror_cmd);
    }

    return txn.status;
}

la_status
lsai_device::initialize_logger_throttled(transaction& txn)
{
    m_punt_debugs = make_unique<lsai_logger_throttled>();
    m_mac_learn_debugs = make_unique<lsai_logger_throttled>();
    m_fdb_notification_debugs = make_unique<lsai_logger_throttled>();

    m_bulk_fdb_notification_count = 0;
    m_bulk_fdb_notification_last_sent = std::chrono::steady_clock::now();
    for (uint32_t i = 0; i < lsai_device::MAX_FDB_ENTRY_PROCESSING_ENTRIES; i++) {
        m_bulk_fdb_notifications[i].attr = &m_bulk_fdb_notification_attrs[i];
        m_bulk_fdb_notifications[i].attr_count = 1;
    }

    m_punt_debugs->initialize(
        SAI_API_SWITCH, lsai_logger_throttled::DEFAULT_DEBUG_SUPRESSED, lsai_logger_throttled::DEFAULT_DEBUG_WAIT_TIME);
    m_mac_learn_debugs->initialize(
        SAI_API_SWITCH, lsai_logger_throttled::DEFAULT_DEBUG_SUPRESSED, lsai_logger_throttled::DEFAULT_DEBUG_WAIT_TIME);
    m_fdb_notification_debugs->initialize(
        SAI_API_SWITCH, lsai_logger_throttled::DEFAULT_DEBUG_SUPRESSED, lsai_logger_throttled::DEFAULT_DEBUG_WAIT_TIME);
    m_total_punt_processed = m_total_punt_process_failed = m_total_learn_processed = m_total_learn_process_failed
        = m_total_fdb_notifications_sent = 0;

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::configure_default_traps(transaction& txn)
{
    txn.status = m_dev->create_copc(la_control_plane_classifier::type_e::MAC, m_copc_mac);
    la_return_on_error(txn.status, "Failed creating mac l2 lpts. rc %s", txn.status.message().c_str());
    txn.status = m_dev->create_copc(la_control_plane_classifier::type_e::IPV4, m_copc_ipv4);
    la_return_on_error(txn.status, "Failed creating IPv4 l2 lpts. rc %s", txn.status.message().c_str());
    txn.status = m_dev->create_copc(la_control_plane_classifier::type_e::IPV6, m_copc_ipv6);
    la_return_on_error(txn.status, "Failed creating IPv6 l2 lpts. rc %s", txn.status.message().c_str());

    // Enable ARP traps
    la_control_plane_classifier::key key;
    la_control_plane_classifier::result result;
    la_control_plane_classifier::field field;

    field.type.mac = la_control_plane_classifier::mac_field_type_e::ETHERNET_PROFILE_ID;
    field.val.mac.ethernet_profile_id = LSAI_L2CP_PROFILE;
    field.mask.mac.ethernet_profile_id = LSAI_L2CP_PROFILE;
    key.push_back(field);

    field.type.mac = la_control_plane_classifier::mac_field_type_e::ETHERTYPE;
    field.val.mac.ethertype = 0x0806;
    field.mask.mac.ethertype = 0xffff;
    key.push_back(field);

    result.event = LA_EVENT_ETHERNET_ARP;
    txn.status = m_copc_mac->append(key, result);
    la_return_on_error(txn.status);

    la_counter_set* counter_set = nullptr;
    m_dev->get_limit(limit_type_e::COUNTER_SET__MAX_PIF_COUNTER_OFFSET, counter_set_max_size);
    counter_set_default_size = 1;
    for (int event = 0; event < LA_EVENT_APP_LAST; event++) {
        counter_set = nullptr;
        if (std::any_of(sai_max_counter_trap_vec.begin(),
                        sai_max_counter_trap_vec.end(),
                        [event](const la_event_e& per_port_event) { return per_port_event == event; })) {
            // Create a large counter to allow a counter per port
            txn.status = m_dev->create_counter(counter_set_max_size, counter_set);
        } else {
            // Create a default counter to aggregate counts across all ports for this trap
            txn.status = m_dev->create_counter(counter_set_default_size, counter_set);
        }
        la_return_on_error(txn.status, "Fail to create trap counter. rc %s", txn.status.message().c_str());
        m_event_counters[(la_event_e)event] = counter_set;
        txn.on_fail([=]() { m_dev->destroy(counter_set); });

        la_trap_priority_t priority = 0;
        la_counter_or_meter_set* tmp_cnt = nullptr;
        const la_punt_destination* punt_dest;
        bool skip = false;
        bool skip_p2p = false;
        bool overwrite_phb = false;
        la_traffic_class_t tc = 0;
        la_status status = LA_STATUS_SUCCESS;

        status = m_dev->get_trap_configuration((la_event_e)event, priority, tmp_cnt, punt_dest, skip, skip_p2p, overwrite_phb, tc);
        if (status == LA_STATUS_SUCCESS) {
            m_dev->set_trap_configuration((la_event_e)event, priority, counter_set, punt_dest, skip, skip_p2p, overwrite_phb, tc);
        }
    }

    for (auto t : sai_clear_trap_vec) {
        txn.status = m_dev->clear_trap_configuration(t);
        // allow entry not found
        if (txn.status == LA_STATUS_EINVAL) {
            la_return_on_error(txn.status);
        }
    }

    // extra traps configured for drop
    for (auto t : sai_drop_trap_vec) {
        txn.status = m_dev->set_trap_configuration(
            t.event, t.priority, m_event_counters[t.event], nullptr, t.skip_inject_up, t.skip_p2p, t.overwrite_phb, 0);
        la_return_on_error(txn.status);
    }

    // extra traps configured for punt to cpu
    for (auto t : sai_punt_trap_vec) {
        txn.status = m_dev->set_trap_configuration(t.event,
                                                   t.priority,
                                                   m_event_counters[t.event],
                                                   (t.event == LA_EVENT_ETHERNET_LEARN_PUNT) ? m_learn_punt_dest : m_punt_dest,
                                                   t.skip_inject_up,
                                                   t.skip_p2p,
                                                   t.overwrite_phb,
                                                   0);
        la_return_on_error(txn.status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::create_default_vrf(transaction& txn)
{
    lsai_object la_vf(m_switch_id);
    txn.status = m_vrfs.allocate_id(la_vf.index);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_vrfs.release_id(la_vf.index); });

    vrf_entry vrf_entry{};
    txn.status = m_dev->create_vrf(la_vf.index, vrf_entry.vrf);
    la_return_on_error(txn.status, "Failed to create VRF with id %u", la_vf.index);
    txn.on_fail([=]() { m_dev->destroy(vrf_entry.vrf); });

    la_vf.type = SAI_OBJECT_TYPE_VIRTUAL_ROUTER;
    vrf_entry.vrf_oid = la_vf.object_id();
    m_vrfs.set(la_vf.index, vrf_entry);
    m_default_vrf_id = la_vf.object_id();

    txn.on_fail([=]() { m_vrfs.erase_id(la_vf.index); });

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::create_mc_lpts_mirror_cmd()
{
    la_uint64_t max_mirror_gid{};

    la_status status = m_dev->get_limit(limit_type_e::DEVICE__MAX_INGRESS_MIRROR_GID, max_mirror_gid);
    la_return_on_error(status);

    la_l2_mirror_command* mirror_command{};
    status = m_dev->create_mc_lpts_mirror_command(max_mirror_gid - 1, m_pci_sys_ports[INJECTUP_SLICE], mirror_command);
    la_return_on_error(status);

    status = m_dev->set_mc_lpts_snoop_configuration(
        0, false /* skip_inject_up_packets */, false /* skip_p2p_packets */, mirror_command);
    la_return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::create_injectup_port(transaction& txn)
{
    txn.status
        = m_dev->create_ethernet_port(m_pci_sys_ports[INJECTUP_SLICE], la_ethernet_port::port_type_e::AC, m_injectup_eth_port);
    la_return_on_error(txn.status);
    txn.on_fail([=]() {
        m_dev->destroy(m_injectup_eth_port);
        m_injectup_eth_port = nullptr;
    });

    txn.status = m_injectup_eth_port->set_ac_profile(m_default_ac_profile);
    la_return_on_error(txn.status, "Failed assigning default ac profile, %s", txn.status.message().c_str());

    txn.status = create_cpu_l3_port(m_default_vrf_id, m_l3_inject_up_port, txn);
    la_return_on_error(txn.status);

    txn.status = create_mc_lpts_mirror_cmd();
    la_return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::create_cpu_l3_port(sai_object_id_t obj_vrf_id, la_l3_ac_port*& l3_port, transaction& txn)
{
    uint32_t router_port_id = 0;
    txn.status = m_l3_ports.allocate_id(router_port_id);
    la_return_on_error(
        txn.status, "Can not allocate router port id ether port 0x%lx", m_pci_sys_ports[lsai_device::INJECTUP_SLICE]);
    txn.on_fail([=]() { m_l3_ports.release_id(router_port_id); });

    lsai_object la_obj(obj_vrf_id);
    vrf_entry vrf_entry{};
    txn.status = m_vrfs.get(la_obj.index, vrf_entry);
    la_return_on_error(txn.status, "fail to get vrf");

    /// use the vrf mac if present
    la_mac_addr_t cpu_l3_mac;
    reverse_copy(std::begin(vrf_entry.m_vrf_mac), std::end(vrf_entry.m_vrf_mac), cpu_l3_mac.bytes);
    if (cpu_l3_mac.flat == 0) {
        // use the switch default mac
        reverse_copy(std::begin(m_default_switch_mac), std::end(m_default_switch_mac), cpu_l3_mac.bytes);
    }

    la_l3_ac_port* new_l3_port = nullptr;
    txn.status = m_dev->create_l3_ac_port(router_port_id,
                                          m_injectup_eth_port,
                                          0,
                                          0,
                                          cpu_l3_mac,
                                          vrf_entry.vrf,
                                          m_qos_handler->get_default_ingress_qos_profile(),
                                          m_qos_handler->get_default_egress_qos_profile(),
                                          new_l3_port);
    la_return_on_error(txn.status, "fail to create inject up l3 port, %s", txn.status.message().c_str());
    txn.on_fail([=]() { m_dev->destroy(new_l3_port); });
    l3_port = new_l3_port;

    txn.status = l3_port->set_protocol_enabled(la_l3_protocol_e::IPV4_UC, true);
    la_return_on_error(txn.status);

    txn.status = l3_port->set_protocol_enabled(la_l3_protocol_e::IPV6_UC, true);
    la_return_on_error(txn.status);

    txn.status = l3_port->set_ecn_remark_enabled(true);
    la_return_on_error(txn.status);

    txn.status = l3_port->set_ecn_counting_enabled(true);
    la_return_on_error(txn.status);

    la_counter_set* ingress_counter_set = nullptr;
    txn.status = m_dev->create_counter(1, ingress_counter_set);
    la_return_on_error(txn.status, "Failed to create ingress counter set for router port, rc %s", txn.status.message().c_str());
    txn.on_fail([=]() { m_dev->destroy(ingress_counter_set); });

    txn.status = l3_port->set_ingress_counter(la_counter_set::type_e::PORT, ingress_counter_set);
    la_return_on_error(txn.status, "Failed to set ingress counter set for router port, rc %s", txn.status.message().c_str());

    la_counter_set* egress_counter_set = nullptr;
    txn.status = m_dev->create_counter(1, egress_counter_set);
    la_return_on_error(txn.status, "Failed to create egress counter set for router port, %s", txn.status.message().c_str());
    txn.on_fail([=]() { m_dev->destroy(egress_counter_set); });

    txn.status = l3_port->set_egress_counter(la_counter_set::type_e::PORT, egress_counter_set);
    la_return_on_error(txn.status, "Failed to set egress counter set for router port, %s", txn.status.message().c_str());

    la_counter_set* egress_qos_counter_set = nullptr;
    txn.status = m_dev->create_counter(NUM_QUEUE_PER_PORT, egress_qos_counter_set);
    la_return_on_error(txn.status, "Failed to create egress qos counter set for router port, %s", txn.status.message().c_str());
    txn.on_fail([=]() { m_dev->destroy(egress_qos_counter_set); });

    txn.status = l3_port->set_egress_counter(la_counter_set::type_e::QOS, egress_qos_counter_set);
    la_return_on_error(txn.status, "Failed to set egress qos counter set for router port, %s", txn.status.message().c_str());

    sai_log_debug(SAI_API_ROUTER_INTERFACE, "cpu router interface id %d created", router_port_id);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::create_cpu_l2_port(uint16_t bridge_gid, la_switch* bridge, la_l2_service_port*& l2_port, transaction& txn)
{
    uint32_t index = 0;

    txn.status = m_bridge_ports.allocate_id(index);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_bridge_ports.release_id(index); });

    // NOTE assume first m_vlans is start from 4k and carry 1 tag to/from cpu
    // m_bridges carry two tags
    uint16_t vid1 = 0, vid2 = 0;
    if (bridge_gid < (tunnel_manager::MAX_INTERNAL_BRIDGES + lsai_device::MAX_BRIDGES)) {
        vid1 = 1;
        vid2 = 0xfff & bridge_gid;
    } else {
        vid1 = 0xfff & bridge_gid;
    }

    txn.status = m_dev->create_ac_l2_service_port(index,
                                                  m_injectup_eth_port,
                                                  vid1,
                                                  vid2,
                                                  m_default_filter_group,
                                                  m_qos_handler->get_default_ingress_qos_profile(),
                                                  m_qos_handler->get_default_egress_qos_profile(),
                                                  l2_port);
    la_return_on_error(txn.status, "Failed to create L2 ac port, %s", txn.status.message().c_str());
    txn.on_fail([=]() { m_dev->destroy(l2_port); });

    // cpu port is always trunk with ingress strip and egress insert
    la_vlan_tag_t out_tag = {.tpid = 0x8100, .tci = {.fields = {.pcp = 0, .dei = 0, .vid = vid1}}};
    la_vlan_edit_command egress_edit_cmd(0 /* num tags to pop */, out_tag);
    txn.status = l2_port->set_egress_vlan_edit_command(egress_edit_cmd);
    la_return_on_error(txn.status, "Failed to set l2 ac port egress tagging mode, %s", txn.status.message().c_str());
    la_vlan_edit_command ingress_edit_cmd(1);
    txn.status = l2_port->set_ingress_vlan_edit_command(ingress_edit_cmd);
    la_return_on_error(txn.status, "Failed to set l2 ac port egress tagging mode, %s", txn.status.message().c_str());

    txn.status = l2_port->attach_to_switch(bridge);
    la_return_on_error(txn.status, "Failed to attach bridge port to bridge, %s", txn.status.message().c_str());
    txn.on_fail([=]() { l2_port->detach(); });

    txn.status = l2_port->set_stp_state(la_port_stp_state_e::FORWARDING);
    la_return_on_error(txn.status, "Failed to set stp state on bridge port, %s", txn.status.message().c_str());

    la_counter_set* egress_counter_set = nullptr;
    txn.status = m_dev->create_counter(1, egress_counter_set);
    la_return_on_error(txn.status, "Failed to create egress counter set for bridge port, %s", txn.status.message().c_str());
    txn.on_fail([=]() { m_dev->destroy(egress_counter_set); });

    txn.status = l2_port->set_egress_counter(la_counter_set::type_e::PORT, egress_counter_set);
    la_return_on_error(txn.status, "Failed to set egress counter set for bridge port, %s", txn.status.message().c_str());

    txn.status = l2_port->set_egress_feature_mode(la_l2_service_port::egress_feature_mode_e::L2);
    la_return_on_error(txn.status, "Failed to set egress feature mode for bridge port, %s", txn.status.message().c_str());

    la_counter_set* egress_qos_counter_set = nullptr;
    txn.status = m_dev->create_counter(NUM_QUEUE_PER_PORT, egress_qos_counter_set);
    la_return_on_error(txn.status, "Failed to create egress qos counter set for bridge port, %s", txn.status.message().c_str());
    txn.on_fail([=]() { m_dev->destroy(egress_qos_counter_set); });

    txn.status = l2_port->set_egress_counter(la_counter_set::type_e::QOS, egress_qos_counter_set);
    la_return_on_error(txn.status, "Failed to set egress qos counter set for bridge port, %s", txn.status.message().c_str());

    cpu_l2_port_entry cpu_l2_port{};
    cpu_l2_port.l2_port = l2_port;
    // Attach switch ACL on cpu l2 port.
    sai_status_t status = m_acl_handler->attach_acl_on_cpu_l2_port_create(cpu_l2_port);
    txn.status = to_la_status(status);
    la_return_on_error(txn.status);

    m_cpu_l2_port_map[bridge_gid] = cpu_l2_port;

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::destroy_cpu_l2_port(uint16_t bridge_gid)
{
    auto it = m_cpu_l2_port_map.find(bridge_gid);
    if (it != m_cpu_l2_port_map.end()) {
        if (it->second.l2_port != nullptr) {
            // detach any attached ACLs
            sai_status_t status = m_acl_handler->clear_acl_on_cpu_l2_port_removal(it->second);
            la_return_on_error(to_la_status(status), "Failed to clear ACL on cpu l2 port");

            m_dev->destroy(it->second.l2_port);
        }
        m_cpu_l2_port_map.erase(it);
    } else {
        return LA_STATUS_ENOTFOUND;
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::create_punt_port(transaction& txn)
{
    txn.status = m_dev->create_punt_inject_port(m_pci_sys_ports[PUNT_SLICE], la_mac_addr_t{}, m_punt_inject_port);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_dev->destroy(m_punt_inject_port); });

    la_vlan_tag_tci_t vlan_tag{};
    vlan_tag.fields.vid = 100;
    la_mac_addr_t mac_addr{.flat = 0x0a0b0c0d0e0fULL};
    txn.status = m_dev->create_l2_punt_destination(0, m_punt_inject_port, mac_addr, vlan_tag, m_punt_dest);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_dev->destroy(m_punt_dest); });

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::create_learn_punt_port(transaction& txn)
{
    txn.status = m_dev->create_punt_inject_port(m_pci_sys_ports[LEARN_PUNT_SLICE], la_mac_addr_t{}, m_learn_punt_port);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_dev->destroy(m_learn_punt_port); });

    la_vlan_tag_tci_t vlan_tag{};
    vlan_tag.fields.vid = 200;
    la_mac_addr_t mac_addr{.flat = 0x0f0e0d0c0b0aULL};
    txn.status = m_dev->create_l2_punt_destination(1, m_learn_punt_port, mac_addr, vlan_tag, m_learn_punt_dest);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_dev->destroy(m_learn_punt_dest); });

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::create_pci_ports(transaction& txn)
{
    la_pci_port* pci_port;

    m_pci_port_ids.resize(m_dev_params.slices_per_dev);
    m_pci_ports.resize(m_dev_params.slices_per_dev);
    m_pci_sys_ports.resize(m_dev_params.slices_per_dev);
    for (la_slice_id_t slice_id = 0; slice_id < m_dev_params.slices_per_dev; slice_id += 2) {
        pci_port = nullptr;
        txn.status = m_dev->create_pci_port(slice_id, 0, false, pci_port);
        la_return_on_error(txn.status);
        txn.on_fail([=]() { m_dev->destroy(pci_port); });

        m_pci_ports[slice_id] = pci_port;

        uint32_t port_index;
        port_entry* pentry{nullptr};
        uint32_t lane = to_sai_lane(slice_id, 0, m_dev_params.host_serdes_id);
        txn.status = allocate_port(lane,
                                   (slice_id == PUNT_SLICE || slice_id == LEARN_PUNT_SLICE) ? port_entry_type_e::PCI
                                                                                            : port_entry_type_e::INTERNAL_PCI,
                                   port_index,
                                   pentry,
                                   txn);
        la_return_on_error(txn.status);
        m_pci_port_ids[slice_id] = pentry->service.oid;
        txn.status = setup_internal_system_port(
            pci_port, m_dev_params.host_serdes_id, SAI_VSC_PCI_INDEX, PUNT_PORT_SPEED, pentry, shared_from_this(), txn);
        la_return_on_error(txn.status);
        m_pci_sys_ports[slice_id] = pentry->sys_port;

        switch (slice_id) {
        case PUNT_SLICE:
            txn.status = create_punt_port(txn);
            la_return_on_error(txn.status);
            break;
        case INJECTUP_SLICE:
            txn.status = create_injectup_port(txn);
            la_return_on_error(txn.status);
            break;
        case LEARN_PUNT_SLICE:
            txn.status = create_learn_punt_port(txn);
            la_return_on_error(txn.status);
            break;
        default:
            break;
        }

        pci_port->activate();
    }

    return txn.status;
}

la_status
lsai_device::create_recycle_ports(transaction& txn)
{
    la_recycle_port* recycle_port;
    la_interface_scheduler* sch;
    m_recycle_ports.resize(m_dev_params.slices_per_dev);
    for (la_slice_id_t slice_id = 1; slice_id < m_dev_params.slices_per_dev; slice_id += 2) {
        recycle_port = nullptr;

        txn.status = m_dev->create_recycle_port(slice_id, 0, recycle_port);
        la_return_on_error(txn.status);
        txn.on_fail([=]() { m_dev->destroy(recycle_port); });

        m_recycle_ports[slice_id] = recycle_port;

        uint32_t port_index;
        port_entry* pentry{nullptr};
        uint32_t lane = to_sai_lane(slice_id, 0, m_dev_params.recycle_serdes_id);
        la_status status = allocate_port(lane, port_entry_type_e::RECYCLE, port_index, pentry, txn);
        la_return_on_error(status);
        txn.status = setup_internal_system_port(recycle_port,
                                                m_dev_params.recycle_serdes_id,
                                                SAI_VSC_RECYCLE_INDEX,
                                                RECYCLE_PORT_SPEED,
                                                pentry,
                                                shared_from_this(),
                                                txn);
        la_return_on_error(txn.status);

        sch = recycle_port->get_scheduler();
        sch->set_credit_cir(100000000000);
        sch->set_transmit_cir(100000000000);
        sch->set_credit_eir_or_pir(100000000000, false);
        sch->set_transmit_eir_or_pir(100000000000, false);
        sch->set_cir_weight(1);
        sch->set_eir_weight(1);

        if (slice_id == lsai_device::INJECT_UP_RECYCLE_SLICE) {
            txn.status
                = m_dev->create_ethernet_port(pentry->sys_port, la_ethernet_port::port_type_e::AC, m_recycle_injectup_eth_port);
            la_return_on_error(txn.status, "Failed to create recycle injectup port");
            txn.on_fail([=]() {
                m_dev->destroy(m_recycle_injectup_eth_port);
                m_recycle_injectup_eth_port = nullptr;
            });
            txn.status = m_recycle_injectup_eth_port->set_ac_profile(m_default_ac_profile);
            la_return_on_error(txn.status, "Failed assign default ac profile to recycle injectup port");
        }
    }
    return txn.status;
}

la_status
lsai_device::setup_npuh_port(uint32_t speed, port_entry* pentry, transaction& txn)
{
    la_uint_t vsc_offset = SAI_VSC_NPUH_INDEX;
    la_voq_set* voq_set = nullptr;
    la_vsc_gid_vec_t vsc_vec(m_dev_params.slices_per_dev);
    // create another set of voqs
    la_voq_set* voq_set_ecn = nullptr;
    la_vsc_gid_vec_t vsc_vec_ecn(m_dev_params.slices_per_dev);
    txn.status = setup_sp_voq_and_cgm(vsc_offset, pentry, vsc_vec, vsc_vec_ecn, voq_set, voq_set_ecn, txn);
    la_return_on_error(txn.status);

    lsai_object sw_id(m_switch_id);
    txn.status
        = m_dev->create_npu_host_port(nullptr /* remote_device */, pentry->sp_gid, voq_set, get_tc_profile(pentry), m_npuh_port);
    la_return_on_error(txn.status);

    // Since setup_system_port wasn't called (SDK created system port
    // automatically), explicitly set the SP in the port_entry here.
    silicon_one::la_system_port* la_sp = (silicon_one::la_system_port*)m_npuh_port->get_system_port();
    pentry->sys_port = la_sp;

    txn.status = setup_sp_tm_defaults(voq_set, voq_set_ecn, vsc_vec, vsc_vec_ecn, speed, pentry, m_npuh_port->get_scheduler(), txn);
    la_return_on_error(txn.status);

    return txn.status;
}

la_status
lsai_device::create_npuh_port(transaction& txn)
{
    la_slice_id_t slice_id = 0;
    la_ifg_id_t ifg_id = 1;
    uint32_t port_index;
    port_entry* pentry{nullptr};
    uint32_t lane = to_sai_lane(slice_id, ifg_id, m_dev_params.host_serdes_id);
    txn.status = allocate_port(lane, port_entry_type_e::NPUH, port_index, pentry, txn);
    la_return_on_error(txn.status);
    m_npuh_port_id = pentry->service.oid;

    if (m_voq_cfg_manager->is_voq_switch()) {
        // In VOQ mode, the npu host port is created through
        // setup_sai_system_port to register the SAI system port
        // object at the same time. This is handled differently than
        // other internal ports since the create_npu_host_port SDK
        // call performs the la_system_port creation
        txn.status = setup_sai_system_port(slice_id, ifg_id, m_dev_params.host_serdes_id, shared_from_this(), txn);
    } else {
        txn.status = setup_npuh_port(PUNT_PORT_SPEED, pentry, txn);
    }
    la_return_on_error(txn.status);

    txn.status = m_dev->create_npu_host_destination(m_npuh_port, m_npuh_dest);
    return txn.status;
}

la_tc_profile*
lsai_device::get_tc_profile(const port_entry* pentry)
{
    if (pentry && pentry->tc_profile) {
        return pentry->tc_profile->m_sdk_profile;
    }

    return m_qos_handler->get_default_tc_profile();
}

la_ingress_qos_profile*
lsai_device::get_ingress_qos_profile(const port_entry* pentry)
{
    if (pentry && pentry->ingress_qos_profile) {
        return pentry->ingress_qos_profile->m_sdk_profile;
    }

    return m_qos_handler->get_default_ingress_qos_profile();
}

la_status
lsai_device::initialize_tm_schedulers(transaction& txn)
{
    constexpr uint64_t txpdr_port_speed = 100ULL * UNITS_IN_MEGA;

    for (la_slice_id_t slice_id = 0; slice_id < m_dev_params.slices_per_dev; ++slice_id) {
        for (la_ifg_id_t ifg_id = 0; ifg_id < m_dev_params.ifgs_per_slice; ++ifg_id) {
            la_ifg_scheduler* ifg_sch;
            txn.status = m_dev->get_ifg_scheduler(slice_id, ifg_id, ifg_sch);
            la_return_on_error(txn.status);

            ifg_sch->set_credit_burst_size(16);
            ifg_sch->set_transmit_burst_size(16);

            ifg_sch->set_txpdr_cir(txpdr_port_speed);
            ifg_sch->set_txpdr_eir_or_pir(txpdr_port_speed, false);
            ifg_sch->set_txpdr_cir_weight(1);
            ifg_sch->set_txpdr_eir_weight(1);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::initialize_default_filter_group(transaction& txn)
{
    txn.status = m_dev->create_filter_group(m_default_filter_group);
    la_return_on_error(txn.status, "Failed creating default filter group");
    txn.on_fail([=]() { m_dev->destroy(m_default_filter_group); });

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::initialize_default_ac_profile(transaction& txn)
{
    txn.status = m_dev->create_ac_profile(m_default_ac_profile);
    la_return_on_error(txn.status, "Failed to create default ac profile");
    txn.on_fail([=]() { m_dev->destroy(m_default_ac_profile); });

    txn.status
        = m_default_ac_profile->set_key_selector_per_format(LA_PACKET_VLAN_FORMAT_UNTAGGED, la_ac_profile::key_selector_e::PORT);
    la_return_on_error(txn.status, "Failed setting AC profile untagged packets mapping.");

    txn.status
        = m_default_ac_profile->set_key_selector_per_format(LA_PACKET_VLAN_FORMAT_802Q, la_ac_profile::key_selector_e::PORT_VLAN);
    la_return_on_error(txn.status, "Failed setting AC profile 802.q packets mapping.");

    txn.status = m_default_ac_profile->set_key_selector_per_format(LA_PACKET_VLAN_FORMAT_802QinQ,
                                                                   la_ac_profile::key_selector_e::PORT_VLAN_VLAN);
    la_return_on_error(txn.status, "Failed setting AC profile 802.QinQ packets mapping.");

    txn.status = m_dev->create_ac_profile(m_pvlan_ac_profile);
    la_return_on_error(txn.status, "Failed to create default ac profile");
    txn.on_fail([=]() { m_dev->destroy(m_pvlan_ac_profile); });

    txn.status = m_pvlan_ac_profile->set_key_selector_per_format(LA_PACKET_VLAN_FORMAT_UNTAGGED,
                                                                 la_ac_profile::key_selector_e::PORT_PVLAN);
    la_return_on_error(txn.status, "Failed setting AC profile untagged packets mapping.");

    txn.status
        = m_pvlan_ac_profile->set_key_selector_per_format(LA_PACKET_VLAN_FORMAT_802Q, la_ac_profile::key_selector_e::PORT_VLAN);
    la_return_on_error(txn.status, "Failed setting AC profile 802.q packets mapping.");

    txn.status = m_pvlan_ac_profile->set_key_selector_per_format(LA_PACKET_VLAN_FORMAT_802QinQ,
                                                                 la_ac_profile::key_selector_e::PORT_VLAN_VLAN);
    la_return_on_error(txn.status, "Failed setting AC profile 802.QinQ packets mapping.");
    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::initialize_serdes_parameters()
{
    for (la_slice_id_t slice = 0; slice < m_dev_params.slices_per_dev; ++slice) {
        for (la_ifg_id_t ifg = 0; ifg < m_dev_params.ifgs_per_slice; ++ifg) {
            la_uint32_t index = slice * m_dev_params.ifgs_per_slice + ifg;

            la_status status = m_dev->set_serdes_source(slice, ifg, m_board_cfg.lanes.ifg_swap[index]);
            return_on_error(status);

            status = m_dev->set_serdes_anlt_order(slice, ifg, m_board_cfg.lanes.anlt_order[index]);
            return_on_error(status);

            for (la_uint32_t serdes : m_board_cfg.lanes.rx_inverse[index]) {
                status = m_dev->set_serdes_polarity_inversion(slice, ifg, serdes, la_serdes_direction_e::RX, true);
                return_on_error(status);
            }

            for (la_uint32_t serdes : m_board_cfg.lanes.tx_inverse[index]) {
                status = m_dev->set_serdes_polarity_inversion(slice, ifg, serdes, la_serdes_direction_e::TX, true);
                return_on_error(status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::gibraltar_mbist_repair()
{
    // External commands for adjusting the voltage.
    const char* pre_fixup_command = getenv("GB_INIT_FIXUP_PRE");
    const char* post_fixup_command = getenv("GB_INIT_FIXUP_POST");

    if (pre_fixup_command) {
        int rc = system(pre_fixup_command);
        if (rc != 0) {
            sai_log_error(SAI_API_SWITCH, "gb pre fixup command rc: %d, cmd: %s", rc, pre_fixup_command);
        }
    }

    m_dev->set_bool_property(la_device_property_e::ENABLE_MBIST_REPAIR, true);

    la_status status = m_dev->diagnostics_test(la_device::test_feature_e::MEM_BIST);
    if (status != LA_STATUS_SUCCESS) {
        sai_log_error(SAI_API_SWITCH, "MEM_BIST test failed, %s", status.message().c_str());
    }

    if (post_fixup_command) {
        int rc = system(post_fixup_command);
        if (rc != 0) {
            sai_log_error(SAI_API_SWITCH, "gb post fixup command rc: %d, cmd: %s", rc, post_fixup_command);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::setup_defaults(transaction& txn)
{
    txn.status = initialize_default_ac_profile(txn);
    la_return_on_error(txn.status);

    txn.status = m_wred_handler->create_default_profiles(txn); // must be done after initialize(TOPOLOGY)
    la_return_on_error(txn.status);

    txn.status = initialize_default_filter_group(txn);
    la_return_on_error(txn.status);

    txn.status = m_qos_handler->initialize_default_qos_profiles(txn, shared_from_this());
    la_return_on_error(txn.status);

    txn.status = initialize_tm_schedulers(txn);
    la_return_on_error(txn.status);

    txn.status = create_recycle_ports(txn);
    la_return_on_error(txn.status);

    txn.status = create_default_vrf(txn);
    la_return_on_error(txn.status);

    txn.status = create_pci_ports(txn);
    la_return_on_error(txn.status);

    txn.status = create_npuh_port(txn);
    la_return_on_error(txn.status);

    txn.status = m_policer_manager->initialize();
    la_return_on_error(txn.status);

    txn.status = create_trap_manager(txn);
    la_return_on_error(txn.status);

    txn.status = configure_default_traps(txn);
    la_return_on_error(txn.status);

    txn.status = initialize_logger_throttled(txn);
    la_return_on_error(txn.status);

    txn.status = initialize_misc_defaults(txn);
    la_return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::reinitialize_hostif_genetlinks(transaction& txn)
{
    // Genetlinks are currently not opened in SIM
    if (m_is_sim) {
        return LA_STATUS_SUCCESS;
    }
    for (auto& item : m_hostifs.map()) {
        auto& hostif = item.second;
        if (hostif.hostif_attr_type == SAI_HOSTIF_TYPE_GENETLINK) {
            auto sstatus = hostif.nl_sock->open(hostif.ifname, hostif.multicast_group);
            txn.status = to_la_status(sstatus);
            la_return_on_error(txn.status);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::reinitialize_hostif_tap_devices(transaction& txn)
{
    for (auto& item : m_hostifs.map()) {
        auto& hostif = item.second;
        if (hostif.hostif_attr_type == SAI_HOSTIF_TYPE_NETDEV) {
            auto sstatus = m_hostif_handler->create_netdev(hostif);
            txn.status = to_la_status(sstatus);
            la_return_on_error(txn.status);

            // Set oper status to what was serialized
            sstatus = m_hostif_handler->set_netdev_oper_status(hostif, hostif.oper_status);
            txn.status = to_la_status(sstatus);
            la_return_on_error(txn.status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::reinitialize_knet_samplepackets(transaction& txn)
{
    trap_id_t knet_trap_id = m_trap_manager->trap_knet_index_from_trap(SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET);
    for (auto& item : m_samplepacket_handler->m_samplepacket_db.map()) {
        auto& samplepacket = item.second;
        if (samplepacket.type == SAI_SAMPLEPACKET_TYPE_SLOW_PATH) {
            lsai_object mirror_obj(samplepacket.slow_path_mirror_session_oid);
            auto session = m_mirror_handler->m_mirror_db.get_ptr(mirror_obj.index);
            if (session == nullptr) {
                sai_log_error(SAI_API_SWITCH, "Failed find mirror object_id=0x%lx", samplepacket.slow_path_mirror_session_oid);
                return LA_STATUS_ENOTFOUND;
            }

            if (!session->mirror_cmd_ingress || !session->mirror_cmd_egress) {
                sai_log_error(SAI_API_SWITCH,
                              "Mirror doesn't have mirror command defined object_id=0x%lx",
                              samplepacket.slow_path_mirror_session_oid);
                return LA_STATUS_ENOTFOUND;
            }

            auto status
                = m_knet_sock.send_set_sample_parameters(session->mirror_cmd_ingress->oid(), knet_trap_id, session->sample_rate);
            la_return_on_error(to_la_status(status));

            status = m_knet_sock.send_set_sample_parameters(session->mirror_cmd_egress->oid(), knet_trap_id, session->sample_rate);
            la_return_on_error(to_la_status(status));
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::reinitialize_knet(transaction& txn)
{
    bool dirty = false;
    auto sstatus = m_knet_sock.send_get_module_satus(dirty);
    la_return_on_error(to_la_status(sstatus), "Failed to get knet dirty status");
    if (dirty) {
        // dirty means already initialized - kernel module wasn't reloaded
        return LA_STATUS_SUCCESS;
    }

    txn.status = to_la_status(m_trap_manager->initialize_kernel_trap_tables());
    la_return_on_error(txn.status);

    txn.status = reinitialize_knet_samplepackets(txn);
    la_return_on_error(txn.status);

    for (auto& item : m_hostifs.map()) {
        auto& hostif = item.second;
        if (hostif.hostif_attr_type == SAI_HOSTIF_TYPE_NETDEV) {
            auto sstatus = m_hostif_handler->create_netdev(hostif);
            txn.status = to_la_status(sstatus);
            la_return_on_error(txn.status);

            // Set oper status to what was serialized
            sstatus = m_hostif_handler->set_netdev_oper_status(hostif, hostif.oper_status);
            txn.status = to_la_status(sstatus);
            la_return_on_error(txn.status);
        }
    }

    for (auto& item : m_hostif_table.map()) {
        auto sstatus = m_hostif_handler->add_knet_action(item.second);
        txn.status = to_la_status(sstatus);
        la_return_on_error(txn.status);
    }

    m_hostif_handler->update_knet_genetlinks();

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::initialize_warm_before_reconnect(transaction& txn, warm_boot_type_e warm_boot_mode, uint32_t base_wb_revision)
{
    if (warm_boot_mode == warm_boot_type_e::FAKE) {

        return LA_STATUS_SUCCESS;
    }

    txn.status = warm_boot_apply_upgrade_patches(shared_from_this(), base_wb_revision);
    la_return_on_error(txn.status);
    initialize_obj_ext_info();
    initialize_logger_throttled(txn);
    m_trap_manager->initialize_warm();
    txn.status = pre_initialize_notification_thread(txn);
    la_return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::initialize_warm_after_reconnect(transaction& txn, warm_boot_type_e warm_boot_mode)
{
    if (warm_boot_mode == warm_boot_type_e::FAKE) {
        return LA_STATUS_SUCCESS;
    }

    // start processing SDK notifications
    txn.status = initialize_notification_thread(txn);
    la_return_on_error(txn.status, "Failed initializing notifcation thread");

    // We might get punt packets from kernel socket regardless of SDK state, so must handle them only after SDK is reconnected
    txn.status = initialize_kernel_conn_fd(txn);
    la_return_on_error(txn.status, "Failed initializing punt connection fd");

    if (m_use_knet) {
        txn.status = reinitialize_knet(txn);
        la_return_on_error(txn.status, "Failed reinitializing knet");
    } else {
        txn.status = reinitialize_hostif_tap_devices(txn);
        la_return_on_error(txn.status, "Failed reinitializing hostif TAP devices");

        txn.status = reinitialize_hostif_genetlinks(txn);
        la_return_on_error(txn.status, "Failed reinitializing hostif genetlinks");
    }

    txn.status = initialize_kernel_start_threads(txn);
    la_return_on_error(txn.status, "Failed starting punt thread");

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::initialize(transaction& txn, const sai_attribute_t* attr_list, uint32_t attr_count)
{
    m_qos_handler = make_unique<lasai_qos>(shared_from_this());
    m_acl_handler = make_unique<sai_acl>(shared_from_this());
    m_debug_counter_handler = make_unique<debug_counter_manager>(shared_from_this());
    m_sched_handler = make_unique<lsai_sched>(shared_from_this());
    m_sched_group_handler = make_unique<lsai_sched_group>(shared_from_this());
    m_mpls_handler = make_unique<mpls_handler>(shared_from_this());
    m_punt_debugs = make_unique<lsai_logger_throttled>();
    m_mac_learn_debugs = make_unique<lsai_logger_throttled>();
    m_fdb_notification_debugs = make_unique<lsai_logger_throttled>();
    m_tunnel_manager = make_unique<tunnel_manager>(shared_from_this());
    m_mirror_handler = make_unique<sai_mirror>(shared_from_this());
    m_samplepacket_handler = make_unique<sai_samplepacket>(shared_from_this());
    m_hostif_handler = make_unique<sai_hostif>(shared_from_this());
    m_policer_manager = make_unique<policer_manager>(shared_from_this());
    m_voq_cfg_manager = make_unique<voq_cfg_manager>(shared_from_this());

    if (m_dev->get_ll_device()->get_device_revision() == la_device_revision_e::GIBRALTAR_A0) {
        txn.status = gibraltar_mbist_repair();
        la_return_on_error(txn.status);
    }

    m_dev->set_int_property(la_device_property_e::COUNTERS_SHADOW_AGE_OUT, m_counter_refresh_interval);

    m_dev->set_bool_property(la_device_property_e::STATISTICAL_METER_COUNTING, true);

    // enable Explicit Congestion Notification (ECN) capable transport in the data plane.
    m_dev->set_bool_property(la_device_property_e::ENABLE_ECN_QUEUING, true);

    // Needed to create 2 ACL tables with counters
    m_dev->set_bool_property(la_device_property_e::ENABLE_INGRESS_L2_AC_PORT_COUNTERS, false);

    // Set DSP rather than DLP in mirror metadata
    m_dev->set_bool_property(la_device_property_e::DESTINATION_SYSTEM_PORT_IN_IBM_METADATA, true);

    // Improve LPM insertion rate for large amounts
    m_dev->set_int_property(la_device_property_e::LPM_REBALANCE_INTERVAL, 3000);

    txn.status = m_dev->initialize(la_device::init_phase_e::DEVICE);
    la_return_on_error(txn.status, "Device-phase initialization failed, %s", txn.status.message().c_str());

    for (la_slice_id_t slice = 0; slice < m_dev_params.slices_per_dev; ++slice) {
        txn.status = m_dev->set_slice_mode(slice, la_slice_mode_e::NETWORK);
        la_return_on_error(txn.status);
    }

    txn.status = initialize_serdes_parameters();

    // discover whether device has hbm.
    bool has_hbm = false;
    if (m_hw_device_type == hw_device_type_e::GIBRALTAR) {
        std::vector<bool> device_caps;
        txn.status = m_dev->get_device_bool_capabilities(device_caps);
        la_return_on_error(txn.status);

        has_hbm = device_caps[(int)la_device::device_bool_capability_e::HAS_HBM];
    }
    m_wred_handler = lsai_wred_manager_creator::create_manager(shared_from_this(), m_hw_device_type, has_hbm);

    txn.status = m_wred_handler->initialize(txn); // must be done before initialize(TOPOLOGY)
    la_return_on_error(txn.status);

    // must be done before init phase moves into TOPOLOGY state.
    txn.status = to_la_status(m_acl_handler->m_acl_udk.process_user_defined_acl_table_fields(attr_list, attr_count));
    la_return_on_error(txn.status);

    txn.status = m_dev->initialize(la_device::init_phase_e::TOPOLOGY);
    la_return_on_error(txn.status, "Topology-phase initialization failed, %s", txn.status.message().c_str());

    txn.status = to_la_status(m_voq_cfg_manager->initialize(attr_list, attr_count));
    la_return_on_error(txn.status);

    setup_defaults(txn);
    la_return_on_error(txn.status);

    txn.status = create_pfc_handler(false);
    la_return_on_error(txn.status);

    txn.status = initialize_kernel_conn_fd(txn);
    la_return_on_error(txn.status);

    if (m_use_knet) {
        txn.status = initialize_knet(txn);
        la_return_on_error(txn.status);

        txn.status = to_la_status(m_trap_manager->initialize_kernel_trap_tables());
        la_return_on_error(txn.status);
    }

    txn.status = initialize_kernel_start_threads(txn);
    la_return_on_error(txn.status);

    txn.status = pre_initialize_notification_thread(txn);
    la_return_on_error(txn.status);

    txn.status = initialize_notification_thread(txn);
    la_return_on_error(txn.status);

    txn.status = m_mpls_handler->initialize(txn, shared_from_this());
    la_return_on_error(txn.status);

    initialize_obj_ext_info();

    return LA_STATUS_SUCCESS;
}

void
lsai_device::initialize_obj_ext_info()
{
    m_per_obj_info[SAI_OBJECT_TYPE_ACL_COUNTER] = &m_acl_handler->m_acl_counter_db;
    m_per_obj_info[SAI_OBJECT_TYPE_ACL_ENTRY] = &m_acl_handler->m_acl_entry_db;
    m_per_obj_info[SAI_OBJECT_TYPE_ACL_TABLE] = &m_acl_handler->m_acl_table_db;
    m_per_obj_info[SAI_OBJECT_TYPE_ACL_TABLE_GROUP] = &m_acl_handler->m_acl_table_group_db;
    m_per_obj_info[SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER] = &m_acl_handler->m_acl_table_group_member_db;
    m_per_obj_info[SAI_OBJECT_TYPE_BRIDGE] = &m_bridges;
    m_per_obj_info[SAI_OBJECT_TYPE_BRIDGE_PORT] = &m_laobj_db_bridge_port;
    m_per_obj_info[SAI_OBJECT_TYPE_BUFFER_POOL] = &m_buffer_pools;
    m_per_obj_info[SAI_OBJECT_TYPE_BUFFER_PROFILE] = &m_buffer_profiles;
    m_per_obj_info[SAI_OBJECT_TYPE_DEBUG_COUNTER] = &m_debug_counter_handler->m_debug_counter_db;
    m_per_obj_info[SAI_OBJECT_TYPE_FDB_ENTRY] = &m_laobj_db_fdb_entries;
    m_per_obj_info[SAI_OBJECT_TYPE_HASH] = &m_laobj_db_hash;
    m_per_obj_info[SAI_OBJECT_TYPE_HOSTIF_TRAP] = &m_laobj_db_hostif_trap;
    m_per_obj_info[SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP] = &m_trap_manager->m_groups;
    m_per_obj_info[SAI_OBJECT_TYPE_INGRESS_PRIORITY_GROUP] = &m_laobj_db_ingress_priority_group;
    m_per_obj_info[SAI_OBJECT_TYPE_LAG] = &m_lags;
    m_per_obj_info[SAI_OBJECT_TYPE_LAG_MEMBER] = &m_laobj_db_lag_member;
    m_per_obj_info[SAI_OBJECT_TYPE_MIRROR_SESSION] = &m_laobj_db_mirror_entries;
    m_per_obj_info[SAI_OBJECT_TYPE_NEIGHBOR_ENTRY] = &m_laobj_db_neighbor_entries;
    m_per_obj_info[SAI_OBJECT_TYPE_NEXT_HOP] = &m_next_hops;
    m_per_obj_info[SAI_OBJECT_TYPE_NEXT_HOP_GROUP] = &m_next_hop_groups;
    m_per_obj_info[SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER] = &m_next_hop_group_members;
    m_per_obj_info[SAI_OBJECT_TYPE_POLICER] = &m_policer_manager->m_policer_db;
    m_per_obj_info[SAI_OBJECT_TYPE_PORT] = &m_laobj_db_port;
    m_per_obj_info[SAI_OBJECT_TYPE_PORT_SERDES] = &m_port_serdes;
    m_per_obj_info[SAI_OBJECT_TYPE_QOS_MAP] = &m_qos_handler->m_qos_map_db;
    m_per_obj_info[SAI_OBJECT_TYPE_QUEUE] = &m_laobj_db_queue;
    m_per_obj_info[SAI_OBJECT_TYPE_ROUTE_ENTRY] = &m_laobj_db_route_entries;
    m_per_obj_info[SAI_OBJECT_TYPE_ROUTER_INTERFACE] = &m_l3_ports;
    m_per_obj_info[SAI_OBJECT_TYPE_SAMPLEPACKET] = &m_samplepacket_handler->m_samplepacket_db;
    m_per_obj_info[SAI_OBJECT_TYPE_SCHEDULER] = &m_sched_handler->m_scheduler_db;
    m_per_obj_info[SAI_OBJECT_TYPE_SWITCH] = &m_laobj_db_switch;
    m_per_obj_info[SAI_OBJECT_TYPE_SYSTEM_PORT] = &m_system_ports;
    m_per_obj_info[SAI_OBJECT_TYPE_TAM] = &m_tam;
    m_per_obj_info[SAI_OBJECT_TYPE_TAM_COLLECTOR] = &m_tam_collector;
    m_per_obj_info[SAI_OBJECT_TYPE_TAM_EVENT] = &m_tam_event;
    m_per_obj_info[SAI_OBJECT_TYPE_TAM_EVENT_ACTION] = &m_tam_event_action;
    m_per_obj_info[SAI_OBJECT_TYPE_TAM_REPORT] = &m_tam_report;
    m_per_obj_info[SAI_OBJECT_TYPE_TAM_TRANSPORT] = &m_tam_transport;
    m_per_obj_info[SAI_OBJECT_TYPE_TUNNEL] = &m_tunnel_manager->m_tunnel_db;
    m_per_obj_info[SAI_OBJECT_TYPE_TUNNEL_MAP] = &m_tunnel_manager->m_tunnel_map_db;
    m_per_obj_info[SAI_OBJECT_TYPE_TUNNEL_MAP_ENTRY] = &m_laobj_db_tunnel_map_entry;
    m_per_obj_info[SAI_OBJECT_TYPE_TUNNEL_TERM_TABLE_ENTRY] = &m_tunnel_manager->m_tunnel_term_db;
    m_per_obj_info[SAI_OBJECT_TYPE_VIRTUAL_ROUTER] = &m_vrfs;
    m_per_obj_info[SAI_OBJECT_TYPE_VLAN] = &m_vlans;
    m_per_obj_info[SAI_OBJECT_TYPE_VLAN_MEMBER] = &m_laobj_db_vlan_member;
    m_per_obj_info[SAI_OBJECT_TYPE_WRED] = &m_wred_handler->m_wred_db;
}

lsai_device::lsai_device(uint32_t sw_id, uint32_t hw_dev_id, la_device* la_dev, bool sim)
{
    uint32_t idx;
    lsai_object la_sw(SAI_OBJECT_TYPE_SWITCH, sw_id, sw_id);

    m_ports.allocate_id(idx); // remove first port index 0
    m_hw_dev_id = hw_dev_id;
    m_switch_id = la_sw.object_id();
    m_dev = la_dev;
    m_is_sim = sim;
    m_hw_info_attr = false;
    // la_set_logging_level(la_dev->get_id(), la_logger_level_e::DEBUG);
}

lsai_device::~lsai_device()
{
    if (sdk_operations_allowed()) {
        m_dev->close_notification_fds();
        la_destroy_device(m_dev);
        m_dev = nullptr;
        if (m_punt_fd != -1) {
            close(m_punt_fd);
            m_punt_fd = -1;
        }
        if (m_inject_fd != -1) {
            close(m_inject_fd);
            m_inject_fd = -1;
        }
        for (auto fd : m_frontport_netdev_sock_fds) {
            close(fd);
        }
    }
}

bool
lsai_device::sdk_operations_allowed()
{
    return m_dev != nullptr;
}

void
lsai_device::clean()
{
    close_threads();
    // All these poses shared pointers to lsai_device, so they must be reset outside of the destructor
    m_acl_handler.reset();
    m_debug_counter_handler.reset();
    m_qos_handler.reset();
    m_trap_manager.reset();
    m_sched_handler.reset();
    m_sched_group_handler.reset();
    m_wred_handler.reset();
    m_mpls_handler.reset();
    m_tunnel_manager.reset();
    m_mirror_handler.reset();
    m_samplepacket_handler.reset();
    m_policer_manager.reset();
    m_pfc_handler.reset();
    m_voq_cfg_manager.reset();
    m_hostif_handler.reset();

    // clean up tam objects pointers.
    m_tam_registry.clear();
    m_tam.clear();
    m_tam_event.clear();
    m_tam_event_action.clear();
    m_tam_report.clear();
    m_tam_transport.clear();
    m_tam_collector.clear();
}

la_status
lsai_device::alloc_prefix_object(uint32_t nh_index, next_hop_entry& nh_entry)
{
    la_status status = LA_STATUS_SUCCESS;
    uint32_t gid;

    status = m_mpls_handler->allocate_gid(gid);
    la_return_on_error(status, "Failed allocating gid for prefix object");

    status = m_dev->create_prefix_object(gid, nh_entry.next_hop, la_prefix_object::prefix_type_e::NORMAL, nh_entry.m_prefix_object);
    la_return_on_error(status, "Failed creating prefix object");

    status = m_next_hops.set(nh_index, nh_entry);
    la_return_on_error(status, "Failed updating next hop with new prefix object");

    return LA_STATUS_SUCCESS;
}

void
lsai_device::release_prefix_object(uint32_t nh_index, const next_hop_entry& nh_entry)
{
    next_hop_entry tmp_nh_entry = nh_entry;
    la_prefix_object* pref_obj = tmp_nh_entry.m_prefix_object;

    if (pref_obj != nullptr) {
        m_mpls_handler->release_gid(pref_obj->get_gid());
        m_dev->destroy(pref_obj);
        tmp_nh_entry.m_prefix_object = nullptr;
        m_next_hops.set(nh_index, tmp_nh_entry);
    }
}

void
lsai_device::destroy_la_object(la_object* obj)
{
    if (m_dev) {
        m_dev->destroy(obj);
    }
}

la_status
lsai_device::create_trap_manager(transaction& txn)
{
    m_trap_manager = std::make_shared<trap_manager>(shared_from_this());

    txn.status = m_trap_manager->initialize();

    return txn.status;
}

la_status
lsai_device::set_la2sai_port(la_system_port_gid_t sp_gid, sai_object_id_t obj_id)
{
    if (m_la2sai_port_map.find(sp_gid) != m_la2sai_port_map.end() && m_la2sai_port_map[sp_gid] != obj_id) {
        sai_log_info(
            SAI_API_SWITCH, "sai port 0x%lx is replaced by 0x%lx for sys port %d", m_la2sai_port_map[sp_gid], obj_id, sp_gid);
    }
    m_la2sai_port_map[sp_gid] = obj_id;

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::get_la2sai_port(la_system_port_gid_t sp_gid, sai_object_id_t& obj)
{
    if (m_la2sai_port_map.find(sp_gid) != m_la2sai_port_map.end()) {
        obj = m_la2sai_port_map[sp_gid];
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_ENOTFOUND;
}

la_status
lsai_device::remove_la2sai_port(la_system_port_gid_t sp_gid)
{
    auto it = m_la2sai_port_map.find(sp_gid);
    if (it != m_la2sai_port_map.end()) {
        m_la2sai_port_map.erase(it);
    }
    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::get_lane_to_port(uint32_t lane, sai_object_id_t& port_oid) const
{
    auto it = m_lane_to_port_map.find(lane);
    if (it != m_lane_to_port_map.end()) {
        port_oid = it->second;
        return LA_STATUS_SUCCESS;
    }
    return LA_STATUS_ENOTFOUND;
}

la_status
lsai_device::set_lane_to_port(uint32_t lane, sai_object_id_t port_oid)
{
    if ((m_lane_to_port_map.find(lane) != m_lane_to_port_map.end()) && (m_lane_to_port_map[lane] != port_oid)) {
        sai_log_info(SAI_API_SWITCH, "replacing lane %u with lane %u for port OID 0x%lx", m_lane_to_port_map[lane], lane, port_oid);
    }
    m_lane_to_port_map[lane] = port_oid;
    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::remove_lane_to_port(uint32_t lane)
{
    auto it = m_lane_to_port_map.find(lane);
    if (it != m_lane_to_port_map.end()) {
        m_lane_to_port_map.erase(it);
    }
    return LA_STATUS_SUCCESS;
}

std::vector<port_entry*>
lsai_device::get_mac_ports()
{
    std::vector<port_entry*> mac_ports;

    for (auto& port : m_ports.map()) {
        if (port.second.is_mac()) {
            mac_ports.push_back(&(port.second));
        }
    }

    return mac_ports;
}

std::vector<system_port_entry*>
lsai_device::get_system_ports()
{
    std::vector<system_port_entry*> sys_ports;

    for (auto& sys_port : m_system_ports.map()) {
        sys_ports.push_back(&(sys_port.second));
    }

    return sys_ports;
}

la_status
lsai_device::create_pfc_handler(bool is_sw_pfc)
{
    if (is_sw_pfc)
        m_pfc_handler = std::make_shared<lasai_sw_pfc>(shared_from_this());
    else
        m_pfc_handler = std::make_shared<lasai_hw_pfc>(shared_from_this());

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::mac_entry_conversion(sai_object_type_t obj_type,
                                  sai_object_key_t* obj_ids,
                                  uint32_t count,
                                  std::vector<mac_and_src_port_entry>& out_mac_entries)
{
    for (uint32_t bridge_index = 0; bridge_index < count; bridge_index++) {
        la_switch* bridge = la_get_bridge_by_obj(obj_ids[bridge_index].key.object_id);
        if (bridge == nullptr) {
            sai_log_error(SAI_API_FDB, "Invalid bridge object 0x%lx", obj_ids[bridge_index].key.object_id);
            return LA_STATUS_EINVAL;
        }

        la_mac_entry_vec la_mac_entries;
        la_status sdk_status = bridge->get_mac_entries(la_mac_entries);
        if (sdk_status != LA_STATUS_SUCCESS) {
            sai_log_error(SAI_API_FDB, "Failed to get MAC entries from bridge object 0x%lx", obj_ids[bridge_index].key.object_id);
            return LA_STATUS_EUNKNOWN;
        }
        sai_log_debug(SAI_API_SWITCH, "Total entries from SDK: 0x%d", la_mac_entries.size());
        for (auto& sdk_entry : la_mac_entries) {
            sai_log_debug(SAI_API_SWITCH,
                          "MAC entry: slp 0x%05x, relay id 0x%04x, mac addr %012lx",
                          sdk_entry.slp_gid,
                          sdk_entry.relay_gid,
                          sdk_entry.addr);

            mac_and_src_port_entry sai_entry{};
            sai_entry.switch_id = m_switch_id;
            lsai_object la_vlan(obj_type, m_switch_id, sdk_entry.relay_gid);
            sai_entry.bv_id = la_vlan.object_id();

            sai_object_id_t sai_port_id = SAI_NULL_OBJECT_ID;
            bridge_port_entry bp_entry{};
            auto status = m_bridge_ports.get(sdk_entry.slp_gid & MAX_BRIDGE_PORTS_MASK, bp_entry);
            if (status == LA_STATUS_SUCCESS) {
                sai_port_id = bp_entry.bridge_port_oid;
            }
            lsai_object la_port{};
            status = m_bridge_ports.get(sai_port_id, bp_entry, la_port);
            if (status != LA_STATUS_SUCCESS) {
                sai_log_debug(SAI_API_SWITCH, "Incorrect BRIDGE PORT ID");
                // Continue processing without returning error
                continue;
            }
            sai_entry.port_id = sai_port_id;

            memcpy(&sai_entry.mac_address, sdk_entry.addr.bytes, sizeof(sai_mac_t));

            out_mac_entries.push_back(sai_entry);
        }
    }
    return LA_STATUS_SUCCESS;
}

// Endian-neutral data structure contruction from a learn notification packet
la_status
lsai_device::learn_record_conversion(uint8_t* lr_ptr, sai_fdb_event_notification_data_t* fdb_entry_ptr)
{
    if (lr_ptr == nullptr || fdb_entry_ptr == nullptr) {
        return LA_STATUS_EINVAL;
    }

    la_status status = LA_STATUS_SUCCESS;
    uint8_t* learn_record_ptr = lr_ptr;
    uint8_t command = (*learn_record_ptr & 0xc0) >> 6;

    switch (command) {
    case silicon_one::la_packet_types::la_learn_notification_type_e::LA_LEARN_NOTIFICATION_TYPE_NEW:
        fdb_entry_ptr->event_type = SAI_FDB_EVENT_LEARNED;
        break;
    case silicon_one::la_packet_types::la_learn_notification_type_e::LA_LEARN_NOTIFICATION_TYPE_UPDATE:
        fdb_entry_ptr->event_type = SAI_FDB_EVENT_MOVE;
        break;
    case silicon_one::la_packet_types::la_learn_notification_type_e::LA_LEARN_NOTIFICATION_TYPE_REFRESH:
        fdb_entry_ptr->event_type = SAI_FDB_EVENT_AGED;
        break;
    default:
        return LA_STATUS_EUNKNOWN;
    }

    // Refer to la_packet_headers.h, la_learn_record has the field definitions
    uint32_t slp = (*learn_record_ptr & 0x3f) << 14 | *(learn_record_ptr + 1) << 6 | (*(learn_record_ptr + 2) & 0xfc) >> 2;
    learn_record_ptr += 2;
    uint16_t relay_id = (*learn_record_ptr & 0x03) << 12 | *(learn_record_ptr + 1) << 4 | (*(learn_record_ptr + 2) & 0xF0) >> 4;
    learn_record_ptr += 2;

    sai_fdb_entry_t sai_learn_record;

    sai_learn_record.switch_id = m_switch_id;
    auto vlan_ptr = m_vlans.get_ptr(relay_id);
    if (vlan_ptr == nullptr) {
        lsai_object la_bridge(SAI_OBJECT_TYPE_BRIDGE, m_switch_id, relay_id);
        sai_learn_record.bv_id = la_bridge.object_id();
    } else {
        lsai_object la_bridge(SAI_OBJECT_TYPE_VLAN, m_switch_id, relay_id);
        sai_learn_record.bv_id = la_bridge.object_id();
    }

    sai_object_id_t sai_port_id = SAI_NULL_OBJECT_ID;

    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    // slp field contains Source LP
    // SLP is NPL destination mask encoded
    bridge_port_entry bp_entry{};
    status = m_bridge_ports.get(slp & MAX_BRIDGE_PORTS_MASK, bp_entry);
    if (status == LA_STATUS_SUCCESS) {
        if (bp_entry.vlan_member_oid == SAI_NULL_OBJECT_ID) {
            sai_port_id = bp_entry.bridge_port_oid;
        } else {
            sai_port_id = bp_entry.vlan_member_oid;
        }
    }
    fdb_entry_ptr->attr[0].id = SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID;
    set_attr_value(SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID, fdb_entry_ptr->attr[0].value, sai_port_id);

    uint8_t mac_addr[6];
    mac_addr[5] = (*(learn_record_ptr)&0xF) << 4 | (*(learn_record_ptr + 1) & 0xF0) >> 4;
    mac_addr[4] = (*(learn_record_ptr + 1) & 0x0F) << 4 | (*(learn_record_ptr + 2) & 0xF0) >> 4;
    mac_addr[3] = (*(learn_record_ptr + 2) & 0x0F) << 4 | (*(learn_record_ptr + 3) & 0xF0) >> 4;
    mac_addr[2] = (*(learn_record_ptr + 3) & 0x0F) << 4 | (*(learn_record_ptr + 4) & 0xF0) >> 4;
    mac_addr[1] = (*(learn_record_ptr + 4) & 0x0F) << 4 | (*(learn_record_ptr + 5) & 0xF0) >> 4;
    mac_addr[0] = (*(learn_record_ptr + 5) & 0x0F) << 4 | (*(learn_record_ptr + 6) & 0xF0) >> 4;
    learn_record_ptr += 6;
    sai_mac_t sai_mac;
    packet_header_bswap(mac_addr, sizeof(sai_mac_t), (uint8_t*)&sai_mac);
    memcpy(&sai_learn_record.mac_address, &sai_mac, sizeof(sai_mac_t));

    // Only used by the debug below
    // uint8_t mact_ldb = *learn_record_ptr & 0xF;

    // Disable debug and make the logs less crowded
    // sai_log_debug(SAI_API_SWITCH,
    //               "learn record: cmd %d, slp 0x%05x, relay id 0x%04x, mac addr %016lx mact_ldb %d",
    //               command,
    //               slp,
    //               relay_id,
    //               *(uint64_t*)mac_addr,
    //               mact_ldb);
    memcpy(&fdb_entry_ptr->fdb_entry, &sai_learn_record, sizeof(sai_fdb_entry_t));
    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::sai_process_learn_notification(uint8_t* pkt_ptr, size_t* pkt_offset)
{
    // Process InjectUp after Punt header
    struct ethhdr* eth_hdr = (struct ethhdr*)pkt_ptr;
    uint16_t eth_type = ntohs(eth_hdr->h_proto);
    uint8_t* hdr_ptr = pkt_ptr;

    if (eth_type == (uint16_t)eth_type_e::DOT1Q) {
        ether_hdr_1q_t* oneqhdr = (ether_hdr_1q_t*)pkt_ptr;
        eth_type = ntohs(oneqhdr->type_or_len);
        if (eth_type != (uint16_t)eth_type_e::INJECTUP) {
            return LA_STATUS_EINVAL;
        }
        hdr_ptr = pkt_ptr + sizeof(ether_hdr_1q_t);
        *pkt_offset += sizeof(ether_hdr_1q_t);
    } else if (eth_type == (uint16_t)eth_type_e::INJECTUP) {
        hdr_ptr = pkt_ptr + sizeof(struct ethhdr);
        *pkt_offset += sizeof(ethhdr);
    } else {
        return LA_STATUS_EINVAL;
    }

    union la_packet_inject_header_up injectup_hdr, *injectup_hdr_ptr = &injectup_hdr;
    packet_header_bswap(hdr_ptr, SIZEOF_LA_PACKET_INJECT_HEADER_UP, (uint8_t*)&injectup_hdr);
    if (injectup_hdr_ptr->type != silicon_one::la_packet_types::la_packet_inject_type_e::LA_PACKET_INJECT_TYPE_UP_LEARN_RECORD) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }
    *pkt_offset += SIZEOF_LA_PACKET_INJECT_HEADER_UP;
    hdr_ptr += SIZEOF_LA_PACKET_INJECT_HEADER_UP;

    union la_learn_record_header lr_notification_hdr, *lr_notification_hdr_ptr = &lr_notification_hdr;
    packet_header_bswap(hdr_ptr, SIZEOF_LA_LEARN_RECORD_HEADER, (uint8_t*)&lr_notification_hdr);
    (*pkt_offset) += SIZEOF_LA_LEARN_RECORD_HEADER;
    hdr_ptr += SIZEOF_LA_LEARN_RECORD_HEADER;

    uint8_t num_of_lrs = lr_notification_hdr_ptr->num_lr_records;
    // LRI header is currently configured as 0
    // Could be used to carry various metadata in the future
    // uint32_t learn_notify_header = lr_notification_hdr_ptr->lri_header;

    // From ASIC, learn notification packet contains up to 10 packets
    sai_fdb_event_notification_data_t sai_fdb_notifications[NUM_LEARN_RECORDS_PER_NOTIFICATION];
    sai_attribute_t sai_fdb_notification_attrs[NUM_LEARN_RECORDS_PER_NOTIFICATION];
    for (uint8_t i = 0; i < num_of_lrs; i++) {
        sai_fdb_notifications[i].attr = &sai_fdb_notification_attrs[i];
        sai_fdb_notifications[i].attr_count = 1;

        auto status = learn_record_conversion(hdr_ptr, &sai_fdb_notifications[i]);
        la_return_on_error(status);

        (*pkt_offset) += SIZEOF_LA_LEARN_RECORD;
        hdr_ptr += SIZEOF_LA_LEARN_RECORD;
    }

    // Process each one of the FDB entries and based on learn mode of each bridge port,
    // complete MAC event processing procedures.
    learn_notification_handler(num_of_lrs, sai_fdb_notifications);
    return LA_STATUS_SUCCESS;
}

void
lsai_device::sai_trim_internal_header(uint8_t* pkt_ptr, size_t* pkt_offset)
{
    size_t temp_offset = 0;
    bool trim_done = false;

    while (!trim_done) {
        struct ethhdr* eth_hdr = (struct ethhdr*)(pkt_ptr + temp_offset);
        uint16_t eth_type = ntohs(eth_hdr->h_proto);
        if (eth_type == (uint16_t)eth_type_e::DOT1Q) {
            ether_hdr_1q_t* oneqhdr = (ether_hdr_1q_t*)(pkt_ptr + temp_offset);
            eth_type = ntohs(oneqhdr->type_or_len);
            if (eth_type == (uint16_t)eth_type_e::PUNT) {
                temp_offset += (sizeof(ether_hdr_1q_t) + SIZEOF_LA_PACKET_PUNT_HEADER);
            } else if (eth_type == (uint16_t)eth_type_e::INJECTUP) {
                temp_offset += (sizeof(ether_hdr_1q_t) + SIZEOF_LA_PACKET_INJECT_HEADER_UP);
            } else {
                trim_done = true;
            }
        } else if (eth_type == (uint16_t)eth_type_e::PUNT) {
            temp_offset += (sizeof(ethhdr) + SIZEOF_LA_PACKET_PUNT_HEADER);
        } else if (eth_type == (uint16_t)eth_type_e::INJECTUP) {
            temp_offset += (sizeof(ethhdr) + SIZEOF_LA_PACKET_INJECT_HEADER_UP);
        } else {
            trim_done = true;
        }
    }
    if (pkt_offset != nullptr) {
        *pkt_offset = temp_offset;
    }
}

punt_process_status_e
lsai_device::sai_process_initial_eth_headers(uint8_t* pkt_ptr, uint32_t len, size_t* pkt_offset, uint16_t* eth_type)
{
    if (pkt_ptr == nullptr || pkt_offset == nullptr) {
        return punt_process_status_e::INVALID;
    }

    struct ethhdr* eth_hdr = (struct ethhdr*)pkt_ptr;
    *eth_type = ntohs(eth_hdr->h_proto);

    *pkt_offset = 0;

    if (*eth_type == (uint16_t)eth_type_e::DOT1Q) {
        ether_hdr_1q_t* oneqhdr = (ether_hdr_1q_t*)pkt_ptr;
        uint16_t vlan = (0xFFF * ntohs(oneqhdr->q_hdr.vid));
        sai_log_debug(SAI_API_SWITCH, "punt packet vlan %d", vlan);
        *eth_type = ntohs(oneqhdr->type_or_len);
        if (*eth_type != (uint16_t)eth_type_e::PUNT) {
            return punt_process_status_e::INVALID;
        }

        if (len < sizeof(ether_hdr_1q_t)) {
            sai_log_error(SAI_API_SWITCH, "punt packet or learn record received is partial");
            return punt_process_status_e::INVALID;
        }

        *pkt_offset = sizeof(ether_hdr_1q_t);
    } else if (*eth_type == (uint16_t)eth_type_e::PUNT) {
        if (len < sizeof(struct ethhdr)) {
            sai_log_error(SAI_API_SWITCH, "punt packet or learn record received is partial");
            return punt_process_status_e::INVALID;
        }

        *pkt_offset = sizeof(ethhdr);
    } else {
        if (*eth_type == (uint16_t)eth_type_e::INJECTUP) {
            // extra header added by the python test for cpu proxy the output port
            if (len < SIZEOF_LA_PACKET_PUNT_HEADER) {
                sai_log_error(SAI_API_SWITCH, "punt packet or learn record received is partial");
                return punt_process_status_e::INVALID;
            }

            *pkt_offset += SIZEOF_LA_PACKET_PUNT_HEADER;

            *eth_type = ntohs(*((uint16_t*)pkt_ptr + 14));
            if (*eth_type == (uint16_t)eth_type_e::DOT1Q) {
                if (len < SIZEOF_LA_PACKET_PUNT_HEADER + 6) {
                    sai_log_error(SAI_API_SWITCH, "punt packet or learn record received is partial");
                    return punt_process_status_e::INVALID;
                }

                *pkt_offset += 6;
            } else if (*eth_type == (uint16_t)eth_type_e::PUNT) {
                if (len < SIZEOF_LA_PACKET_PUNT_HEADER + 2) {
                    sai_log_error(SAI_API_SWITCH, "punt packet or learn record received is partial");
                    return punt_process_status_e::INVALID;
                }

                *pkt_offset += 2;
            } else {
                return punt_process_status_e::INVALID;
            }
        } else {
            return punt_process_status_e::INVALID;
        }
    }
    return punt_process_status_e::DONE;
}

punt_process_status_e
lsai_device::sai_process_learn_header(uint8_t* pkt_ptr, uint32_t len, size_t* pkt_offset)
{
    if (pkt_ptr == nullptr || pkt_offset == nullptr) {
        return punt_process_status_e::INVALID;
    }

    punt_process_status_e parse_result;
    uint16_t eth_type{};
    parse_result = sai_process_initial_eth_headers(pkt_ptr, len, pkt_offset, &eth_type);
    if (parse_result != punt_process_status_e::DONE) {
        sai_log_debug(SAI_API_SWITCH, "learn punt packet parsing failed");
        return parse_result;
    }

    uint8_t* hdr_ptr = pkt_ptr + *pkt_offset;
    union la_packet_punt_header loc_punt_hdr, *punt_hdr = &loc_punt_hdr;

    packet_header_bswap(hdr_ptr, SIZEOF_LA_PACKET_PUNT_HEADER, (uint8_t*)&loc_punt_hdr);
    (*pkt_offset) += SIZEOF_LA_PACKET_PUNT_HEADER;
    hdr_ptr += SIZEOF_LA_PACKET_PUNT_HEADER;

    // We are not supposed to see non-learn notification packets in learn thread
    if (punt_hdr->next_header != silicon_one::la_packet_types::la_protocol_type_e::LA_PROTOCOL_TYPE_ETHERNET
        || punt_hdr->code != LA_EVENT_ETHERNET_LEARN_PUNT) {
        m_mac_learn_debugs->log("Error processing non-learn notificaiton packets received from asic");
        return punt_process_status_e::INVALID;
    }

    la_status status = sai_process_learn_notification(hdr_ptr, pkt_offset);
    if (status == LA_STATUS_SUCCESS) {
        m_total_learn_processed++;
        m_mac_learn_debugs->log("Learn notificaiton packets processed: %lu", m_total_learn_processed);
        return punt_process_status_e::TERMINATED;
    } else {
        m_total_learn_process_failed++;
        m_mac_learn_debugs->log("Error processing learn notificaiton packets received from asic: %lu",
                                m_total_learn_process_failed);
        return punt_process_status_e::INVALID;
    }

    return punt_process_status_e::DONE;
}

punt_process_status_e
lsai_device::sai_process_punt_header(uint8_t* pkt_ptr,
                                     uint32_t len,
                                     uint32_t* attr_count,
                                     sai_attribute_t* attr_list,
                                     size_t* pkt_offset,
                                     sai_object_id_t& src_port_oid,
                                     sai_object_id_t& dst_port_oid,
                                     sai_object_id_t& trap_oid,
                                     uint32_t& mirror_id)
{
    if (pkt_ptr == nullptr || attr_count == nullptr || attr_list == nullptr || pkt_offset == nullptr) {
        return punt_process_status_e::INVALID;
    }

    punt_process_status_e parse_result;
    uint16_t eth_type{};

    *pkt_offset = 0;

    parse_result = sai_process_initial_eth_headers(pkt_ptr, len, pkt_offset, &eth_type);
    if (parse_result != punt_process_status_e::DONE) {
        sai_log_debug(SAI_API_SWITCH, "punt packet parsing failed");
        return parse_result;
    }

    uint8_t* hdr_ptr = pkt_ptr + *pkt_offset;
    int a_index = 0;
    union la_packet_punt_header loc_punt_hdr, *punt_hdr = &loc_punt_hdr;

    packet_header_bswap(hdr_ptr, SIZEOF_LA_PACKET_PUNT_HEADER, (uint8_t*)&loc_punt_hdr);
    (*pkt_offset) += SIZEOF_LA_PACKET_PUNT_HEADER;
    hdr_ptr += SIZEOF_LA_PACKET_PUNT_HEADER;

    // We are not supposed to see learn notification packets in punt thread
    if (punt_hdr->next_header == silicon_one::la_packet_types::la_protocol_type_e::LA_PROTOCOL_TYPE_ETHERNET
        && punt_hdr->code == LA_EVENT_ETHERNET_LEARN_PUNT) {
        return punt_process_status_e::INVALID;
    }

    // call thread safe function  sai_start_api for header translation
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    // attribute
    sai_object_id_t src_port = SAI_NULL_OBJECT_ID;
    sai_object_id_t dst_port = SAI_NULL_OBJECT_ID;

    la_status status = LA_STATUS_EINVAL;
    src_port_oid = SAI_NULL_OBJECT_ID;
    if (punt_hdr->source_sp != INVALID_PUNT_SYS) {
        status = get_la2sai_port(punt_hdr->source_sp, src_port);
        if (status == LA_STATUS_SUCCESS) {
            src_port_oid = src_port;
        }
    }

    uint16_t vlan_id = 0;
    if ((punt_hdr->source_lp & 0x80000) == 0) {
        rif_entry* rif_entry = m_l3_ports.get_ptr(punt_hdr->source_lp);
        if (rif_entry != nullptr) {
            if (rif_entry->outer_vlan_id != 0) {
                vlan_id = rif_entry->outer_vlan_id;
            } else if (rif_entry->bridge_obj != SAI_NULL_OBJECT_ID) {
                lsai_object la_vlan(rif_entry->bridge_obj);
                if (la_vlan.type == SAI_OBJECT_TYPE_VLAN) {
                    vlan_id = m_vlans.get_id(rif_entry->bridge_obj);
                }
            }
            if (src_port_oid == SAI_NULL_OBJECT_ID) {
                src_port_oid = rif_entry->port_obj;
            }
        }
    } else {
        bridge_port_entry* pentry = nullptr;
        pentry = m_bridge_ports.get_ptr(punt_hdr->source_lp & 0xffff);
        if (status == LA_STATUS_SUCCESS && pentry != nullptr) {
            src_port = pentry->port_obj;
            vlan_id = pentry->vlan_id;

            if (src_port_oid == SAI_NULL_OBJECT_ID) {
                src_port_oid = pentry->port_obj;
            }
        }
    }

    if (src_port_oid == m_pci_port_ids[INJECTUP_SLICE]) {
        src_port_oid = m_pci_port_ids[PUNT_SLICE];
    }

    attr_list[a_index].id = SAI_HOSTIF_PACKET_ATTR_INGRESS_PORT;
    set_attr_value(SAI_HOSTIF_PACKET_ATTR_INGRESS_PORT, attr_list[a_index].value, src_port_oid);

    *attr_count = ++a_index;

    sai_object_id_t src_lag_oid = SAI_NULL_OBJECT_ID;
    {
        // Find Source LAG ID
        lsai_object la_port(src_port_oid);
        port_entry* pentry = nullptr;
        pentry = m_ports.get_ptr(la_port.index);
        if (pentry != nullptr) {
            src_lag_oid = pentry->lag_oid;
        }
    }
    if (src_lag_oid != SAI_NULL_OBJECT_ID) {
        attr_list[a_index].id = SAI_HOSTIF_PACKET_ATTR_INGRESS_LAG;
        set_attr_value(SAI_HOSTIF_PACKET_ATTR_INGRESS_LAG, attr_list[a_index].value, src_lag_oid);
        *attr_count = ++a_index;
    }

    dst_port_oid = SAI_NULL_OBJECT_ID;
    if (punt_hdr->destination_sp != INVALID_PUNT_SYS) {
        status = get_la2sai_port(punt_hdr->destination_sp, dst_port);
        attr_list[a_index].id = SAI_HOSTIF_PACKET_ATTR_EGRESS_PORT_OR_LAG;
        set_attr_value(SAI_HOSTIF_PACKET_ATTR_EGRESS_PORT_OR_LAG, attr_list[a_index].value, dst_port);
        *attr_count = ++a_index;
        if (status == LA_STATUS_SUCCESS) {
            dst_port_oid = dst_port;
        }
    }

    // optional attribute
    sai_object_id_t trap_obj = SAI_NULL_OBJECT_ID;
    lsai_object la_port(src_port);
    auto sdev = la_port.get_device();

    // only valid if mirrored packet
    mirror_id = punt_hdr->code;

    bool action_cont = true;
    status = sdev->m_trap_manager->get_trap_base_id(la_port.switch_id, punt_hdr->code, punt_hdr->source, trap_obj, action_cont);
    if (status == LA_STATUS_SUCCESS) {
        attr_list[a_index].id = SAI_HOSTIF_PACKET_ATTR_HOSTIF_TRAP_ID;
        set_attr_value(SAI_HOSTIF_PACKET_ATTR_HOSTIF_TRAP_ID, attr_list[a_index].value, trap_obj);
        *attr_count = ++a_index;
    }
    trap_oid = trap_obj;

    if (vlan_id == 0 || !action_cont) {
        return punt_process_status_e::DONE;
    }

    auto pkt_eth_1q = (struct ether_hdr_1q_t*)(pkt_ptr + *pkt_offset);
    eth_type = ntohs(pkt_eth_1q->q_hdr.tpid);
    if (eth_type == (uint16_t)eth_type_e::DOT1Q) {
        return punt_process_status_e::DONE;
    }

    struct dot1q_hdr dot1q {
    };
    dot1q.tpid = htons((uint16_t)eth_type_e::DOT1Q);

    if (vlan_id > lsai_device::MAX_VLANS) {
        // SKIP for 1D case
        return punt_process_status_e::DONE;
    } else {
        dot1q.vid = htons(vlan_id);
    }

    memmove(pkt_ptr + *pkt_offset - 4, pkt_ptr + *pkt_offset, sizeof(ethhdr));
    memcpy(pkt_ptr + *pkt_offset + 8, &dot1q, 4);
    *pkt_offset -= 4;

    return punt_process_status_e::DONE;
}

sai_status_t
lsai_device::sai2la_inject_header(uint8_t* pkt_hdr,
                                  uint64_t dscp,
                                  la_traffic_class_t out_tc,
                                  la_qos_color_e out_color,
                                  int* p_size,
                                  int* sock_ptr,
                                  uint32_t attr_count,
                                  const sai_attribute_t* attr_list)
{
    if (pkt_hdr == nullptr || !p_size) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    auto attrs = sai_parse_attributes(attr_count, attr_list);

    // call thread safe function sai_start_api for header translation
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    sai_hostif_tx_type_t tx_type = SAI_HOSTIF_TX_TYPE_PIPELINE_LOOKUP;
    get_attrs_value(SAI_HOSTIF_PACKET_ATTR_HOSTIF_TX_TYPE, attrs, tx_type, true);

    if (tx_type == SAI_HOSTIF_TX_TYPE_PIPELINE_LOOKUP) {
        union la_packet_inject_header_up loc_inj_up_hdr, *inj_up_hdr = &loc_inj_up_hdr;

        bzero(inj_up_hdr, SIZEOF_LA_PACKET_INJECT_HEADER_UP);

        inj_up_hdr->type = la_packet_types::LA_PACKET_INJECT_TYPE_UP_ETH;
        // slice2 pci port has been used as a trunk(untag for L3) to send inject up
        inj_up_hdr->ssp_gid = m_pci_sys_ports[INJECTUP_SLICE]->get_gid();

        inj_up_hdr->fwd_qos_tag = dscp;

        // putting values in phb_dp and phb_tc
        inj_up_hdr->phb_tc = out_tc;

#if CURRENT_SAI_VERSION_CODE == SAI_VERSION_CODE(1, 5, 2)
        // use phb/TC always from packet processing..for now.
        inj_up_hdr->phb_src = la_inject_up_hdr_phb_src_e::PHB_FROM_PACKET_PROCESSING;
#endif

        inj_up_hdr->phb_dp = (uint64_t)out_color;

        packet_header_bswap((uint8_t*)inj_up_hdr, SIZEOF_LA_PACKET_INJECT_HEADER_UP, pkt_hdr);
        *p_size = SIZEOF_LA_PACKET_INJECT_HEADER_UP;
        *sock_ptr = m_inject_fd;
    } else if (tx_type == SAI_HOSTIF_TX_TYPE_PIPELINE_BYPASS) {
        union la_packet_inject_header_down loc_inj_down_hdr, *inj_down_hdr = &loc_inj_down_hdr;
        bzero(inj_down_hdr, SIZEOF_LA_PACKET_INJECT_HEADER_DOWN);

        sai_object_id_t obj_dst_port = SAI_NULL_OBJECT_ID;
        get_attrs_value(SAI_HOSTIF_PACKET_ATTR_EGRESS_PORT_OR_LAG, attrs, obj_dst_port, true);

        uint8_t traffic_class = 0;
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
        get_attrs_value(SAI_HOSTIF_PACKET_ATTR_EGRESS_QUEUE_INDEX, attrs, traffic_class, false);
#endif

        const la_system_port* sys_port = nullptr;
        la_status status = get_sys_from_sys_or_spa(obj_dst_port, sys_port);
        sai_return_on_la_error(status);

        inj_down_hdr->type = la_packet_types::LA_PACKET_INJECT_TYPE_DOWN;
        inj_down_hdr->dest = sys_port->get_gid();
        inj_down_hdr->phb_tc = traffic_class;

        packet_header_bswap((uint8_t*)inj_down_hdr, SIZEOF_LA_PACKET_INJECT_HEADER_DOWN, pkt_hdr);
        *p_size = SIZEOF_LA_PACKET_INJECT_HEADER_DOWN;
        *sock_ptr = m_inject_fd;
    } else {
        return SAI_STATUS_INVALID_PARAMETER;
    }
    return SAI_STATUS_SUCCESS;
}

void
lsai_device::dump_cpu_port_stats() const
{
    la_counter_set* ingress_counter = nullptr;
    la_counter_set* egress_counter = nullptr;
    size_t in_packets = -1, in_bytes = -1, out_packets = -1, out_bytes = -1;

    la_status status;

    status = m_l3_inject_up_port->get_ingress_counter(la_counter_set::type_e::PORT, ingress_counter);
    status = ingress_counter->read(0, m_force_update, 0, in_packets, in_bytes);
    status = m_l3_inject_up_port->get_egress_counter(la_counter_set::type_e::PORT, egress_counter);
    status = egress_counter->read(0, m_force_update, 0, out_packets, out_bytes);
    if (in_packets || in_bytes || out_packets || out_bytes) {
        sai_log_debug(SAI_API_UNSPECIFIED,
                      "l3_inject_up_port ingress (%ld %ld) egress (%ld %ld)\n",
                      in_packets,
                      in_bytes,
                      out_packets,
                      out_bytes);
    }

    status = m_l2_inject_up_port->get_ingress_counter(la_counter_set::type_e::PORT, ingress_counter);
    status = ingress_counter->read(0, m_force_update, 0, in_packets, in_bytes);
    status = m_l2_inject_up_port->get_egress_counter(la_counter_set::type_e::PORT, egress_counter);
    status = egress_counter->read(0, m_force_update, 0, out_packets, out_bytes);
    if (in_packets || in_bytes || out_packets || out_bytes) {
        sai_log_debug(SAI_API_UNSPECIFIED,
                      "l2_inject_up_port ingress (%ld %ld) egress (%ld %ld)\n",
                      in_packets,
                      in_bytes,
                      out_packets,
                      out_bytes);
    }

    for (auto it = m_cpu_l2_port_map.begin(); it != m_cpu_l2_port_map.end(); it++) {
        la_l2_service_port* l2_port = it->second.l2_port;
        status = l2_port->get_ingress_counter(la_counter_set::type_e::PORT, ingress_counter);
        status = ingress_counter->read(0, m_force_update, 0, in_packets, in_bytes);
        status = l2_port->get_egress_counter(la_counter_set::type_e::PORT, egress_counter);
        status = egress_counter->read(0, m_force_update, 0, out_packets, out_bytes);
        if (in_packets || in_bytes || out_packets || out_bytes) {
            sai_log_debug(SAI_API_UNSPECIFIED,
                          "cpu_l2_port %d ingress (%ld %ld) egress (%ld %ld)\n",
                          it->first,
                          in_packets,
                          in_bytes,
                          out_packets,
                          out_bytes);
        }
    }
}

void
lsai_device::sai_prepend_inject_header(uint8_t* packet_buffer, uint8_t* packet_ptr, size_t inject_header_size, int packet_size)
{
    // It is only important to have the correct ethernet protocol in the vlan header
    // first 14 bytes are not important
    ether_hdr_1q_t eth1q;
    eth1q.q_hdr.tpid = 0x0081;
    eth1q.q_hdr.vid = 0x6400;
    eth1q.type_or_len = 0x0371;

    uint32_t temp[6];
    sscanf("12:34:56:78:9a:bc", "%02x:%02x:%02x:%02x:%02x:%02x", &temp[0], &temp[1], &temp[2], &temp[3], &temp[4], &temp[5]);
    std::copy(std::begin(temp), std::end(temp), std::begin(eth1q.daddr));
    sscanf("de:ad:de:ad:de:ad", "%02x:%02x:%02x:%02x:%02x:%02x", &temp[0], &temp[1], &temp[2], &temp[3], &temp[4], &temp[5]);
    std::copy(std::begin(temp), std::end(temp), std::begin(eth1q.saddr));

    // memcpy(packet_buffer, outer_eth_hdr, sizeof(struct ethhdr));
    memcpy(packet_buffer, &eth1q, sizeof(eth1q));
    memcpy(packet_buffer + sizeof(struct ethhdr) + sizeof(struct dot1q_hdr) + inject_header_size, packet_ptr, packet_size);
}

sai_status_t
lsai_device::sai2la_inject_packet(uint8_t* pkt_ptr, int* p_size, uint32_t attr_count, const sai_attribute_t* attr_list)
{
    static uint8_t packet_buffer[INJECT_BUFFER_SIZE + 4]; // this function is sync

    if (pkt_ptr == nullptr || !p_size) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    struct ethhdr* eth_hdr = (struct ethhdr*)pkt_ptr;
    uint16_t eth_type = ntohs(eth_hdr->h_proto);

    uint64_t dscp = 0;
    la_traffic_class_t out_tc;
    la_qos_color_e out_color;
    uint8_t* hdr_ptr = pkt_ptr;

    if (eth_type == (uint16_t)eth_type_e::DOT1Q) {
        // could use the pcp/dei field of vlan header to support dot1q tag mapping in future
        out_tc = 0;
        out_color = la_qos_color_e::GREEN;
        ether_hdr_1q_t* oneqhdr = (ether_hdr_1q_t*)pkt_ptr;
        eth_type = ntohs(oneqhdr->type_or_len);

        hdr_ptr = pkt_ptr + sizeof(ether_hdr_1q_t);
    } else {
        hdr_ptr = pkt_ptr + sizeof(struct ethhdr);
    }

    if (eth_type == (uint16_t)eth_type_e::IPV4) {
        struct iphdr* ip = (struct iphdr*)hdr_ptr;
        dscp = ip->tos;
        // extract only the dscp bits from the tos/traffic class
        dscp = dscp >> 2;

        la_ingress_qos_profile* profile = m_qos_handler->get_default_ingress_qos_profile();
        la_ip_dscp dscp_val = {.value = (la_uint8_t)dscp};
        profile->get_traffic_class_mapping(la_ip_version_e::IPV4, dscp_val, out_tc);
        profile->get_color_mapping(la_ip_version_e::IPV4, dscp_val, out_color);
    } else if (eth_type == (uint16_t)eth_type_e::IPV6) {
        struct ipv6* ipv6 = (struct ipv6*)hdr_ptr;
        dscp = (ipv6->traffic_class_hi << 4) | ipv6->traffic_class_lo;
        // extract only the dscp bits from the tos/traffic class
        dscp = dscp >> 2;

        la_ingress_qos_profile* profile = m_qos_handler->get_default_ingress_qos_profile();
        la_ip_dscp dscp_val = {.value = (la_uint8_t)dscp};
        profile->get_traffic_class_mapping(la_ip_version_e::IPV6, dscp_val, out_tc);
        profile->get_color_mapping(la_ip_version_e::IPV6, dscp_val, out_color);
    } else {
        // MPLS
        struct mpls* mpls = (struct mpls*)hdr_ptr;
        dscp = (ntohl(mpls->entry) & mpls_header_e::MPLS_TC_MASK) >> mpls_header_e::MPLS_TC_SHIFT;
        la_ingress_qos_profile* profile = m_qos_handler->get_default_ingress_qos_profile();
        la_mpls_tc mpls_tc = {.value = la_uint8_t(dscp)};
        profile->get_traffic_class_mapping(mpls_tc, out_tc);
        profile->get_color_mapping(mpls_tc, out_color);
    }

    int new_buffer_size = *p_size + SIZEOF_LA_PACKET_INJECT_HEADER_UP + sizeof(struct ethhdr) + sizeof(struct dot1q_hdr);

    if (new_buffer_size >= INJECT_BUFFER_SIZE) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    int hdr_size = new_buffer_size - sizeof(struct ethhdr) - sizeof(struct dot1q_hdr);
    int sock = m_inject_fd;
    size_t length_header_end_offset = 0;
    if (m_is_sim) {
        // Transmitted packet unit starts with a 4B header that contains # of bytes in packet
        length_header_end_offset = 4;
        // Store length
        *(uint32_t*)packet_buffer = new_buffer_size;
        new_buffer_size += 4;
    }

    // Prepare inject header and copy inject header into packet buffer at offset inject header offset
    auto inject_hdr_offset = sizeof(struct ethhdr) + sizeof(struct dot1q_hdr) + length_header_end_offset;
    sai_status_t sstatus
        = sai2la_inject_header(packet_buffer + inject_hdr_offset, dscp, out_tc, out_color, &hdr_size, &sock, attr_count, attr_list);
    sai_return_on_error(sstatus);

    // Aftern length header offset (on SIM env its at 4B offset ; on HW offset is zero), write ethernet jacket header values.
    sai_prepend_inject_header(packet_buffer + length_header_end_offset, pkt_ptr, SIZEOF_LA_PACKET_INJECT_HEADER_UP, *p_size);

    int num_sent = send(sock, packet_buffer, new_buffer_size, 0);
    if (num_sent != new_buffer_size) {
        sai_return_on_error(SAI_STATUS_FAILURE, "num_sent(%d) != new_buffer_size(%d)", num_sent, new_buffer_size);
    }

    *p_size = num_sent;

    lsai_logger& instance = lsai_logger::instance();
    if (instance.is_logging(SAI_API_SWITCH, SAI_LOG_LEVEL_DEBUG)) {
        dump_cpu_port_stats();
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_device::prepare_netdev_inject_packet_down(const lsai_hostif& hostif,
                                               uint8_t* packet_buffer,
                                               int pkt_size,
                                               uint8_t* pkt_with_punt_header,
                                               size_t* new_buffer_size)
{
    // If pkt is less than minpkt size, add pad bytes
    size_t pad_size = (pkt_size < 64) ? 64 - pkt_size : 0;
    *new_buffer_size = pkt_size + SIZEOF_LA_PACKET_INJECT_HEADER_DOWN + sizeof(struct ethhdr) + sizeof(struct dot1q_hdr) + pad_size;

    if (*new_buffer_size >= INJECT_BUFFER_SIZE) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    union la_packet_inject_header_down loc_inj_down_hdr, *inj_down_hdr = &loc_inj_down_hdr;
    bzero(inj_down_hdr, SIZEOF_LA_PACKET_INJECT_HEADER_DOWN);
    inj_down_hdr->type = la_packet_types::LA_PACKET_INJECT_TYPE_DOWN;

    const la_system_port* sys_port = nullptr;
    la_status status = get_sys_from_sys_or_spa(hostif.port_lag_id, sys_port);
    sai_return_on_la_error(status);
    inj_down_hdr->dest = sys_port->get_gid();

    size_t length_header_end_offset = 0;
    if (m_is_sim) {
        // Transmitted packet unit starts with a 4B header that contains # of bytes in packet
        length_header_end_offset = 4;
        // Store length
        *(uint32_t*)pkt_with_punt_header = *new_buffer_size;
        *new_buffer_size += 4;
    }

    // Copy inject header and copy inject header into packet buffer at offset inject header offset
    auto inject_hdr_offset = sizeof(struct ethhdr) + sizeof(struct dot1q_hdr) + length_header_end_offset;
    packet_header_bswap((uint8_t*)inj_down_hdr, SIZEOF_LA_PACKET_INJECT_HEADER_DOWN, pkt_with_punt_header + inject_hdr_offset);

    // Aftern length header offset (on SIM env its at 4B offset ; on HW offset is zero), write ethernet jacket header values.
    sai_prepend_inject_header(
        pkt_with_punt_header + length_header_end_offset, packet_buffer, SIZEOF_LA_PACKET_INJECT_HEADER_DOWN, pkt_size);

    return SAI_STATUS_SUCCESS;
}

void
lsai_device::netdev_listen()
{
    uint8_t packet_buffer[INJECT_BUFFER_SIZE + 4];
    fd_set working_fds;
    int max_fd;

    while (true) {
        FD_ZERO(&working_fds);
        // After every timeout period, an attempt is made to include any new netdev
        // interfaces created since last select was done.
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000; // 10 milliseconds

        if (m_threads_should_exit) {
            break;
        }

        std::vector<int> netdev_fds{};
        {
            std::lock_guard<std::mutex> lock(m_hostif_lock);
            std::for_each(
                m_frontport_netdev_sock_fds.begin(), m_frontport_netdev_sock_fds.end(), [&working_fds, &netdev_fds](int fd) {
                    FD_SET(fd, &working_fds);
                    // make a copy of netdev fds that are already opened for iteration over fds to work
                    // error free if netdev tearsdown during iteration.
                    netdev_fds.push_back(fd);
                });
            auto max_fd_it = std::max_element(m_frontport_netdev_sock_fds.begin(), m_frontport_netdev_sock_fds.end());
            max_fd = *max_fd_it;
        }
        auto rv = select(max_fd + 1, &working_fds, nullptr, nullptr, &timeout);
        // In case of error select always returns -1 and sets errno.
        if (rv <= 0) {
            continue;
        }

        for (auto fd : netdev_fds) {
            if (FD_ISSET(fd, &working_fds)) {
                int len = read(fd, packet_buffer, sizeof(packet_buffer));
                const lsai_hostif* hostif = nullptr;
                if (len > 0) {
                    std::lock_guard<std::mutex> lock(m_hostif_lock);
                    auto it = m_netdev_sock_fd_to_hostif.find(fd);
                    if (it == m_netdev_sock_fd_to_hostif.end()) {
                        sai_log_error(SAI_API_SWITCH,
                                      "netdev_listen: packet inject into asic failed because netdev interface"
                                      " does not exist anymore.");
                        continue;
                    }
                    hostif = &(it->second);
                }
                // fetch packet from netdev intf and send it to cpu intf
                if (len > 0 && hostif != nullptr) {
                    sai_log_debug(
                        SAI_API_SWITCH, "netdev_listen: received %d bytes from hostif interface %s", len, hostif->ifname.c_str());
                    size_t new_pkt_size = 0;
                    uint8_t pkt_with_punt_header[INJECT_BUFFER_SIZE + 4];
                    if (prepare_netdev_inject_packet_down(*hostif, packet_buffer, len, pkt_with_punt_header, &new_pkt_size)
                        != SAI_STATUS_SUCCESS) {
                        sai_log_debug(SAI_API_SWITCH, "netdev_listen: could not prepare packet to inject into asic.");
                        continue;
                    }

                    sai_log_debug(SAI_API_SWITCH,
                                  "netdev_listen: inject packet of length %d into asic. Buffer length = %d",
                                  *(uint32_t*)pkt_with_punt_header,
                                  new_pkt_size);
                    size_t offset = 0;
                    while (new_pkt_size != offset) {
                        auto sent_bytes = send(m_punt_fd, pkt_with_punt_header + offset, new_pkt_size - offset, 0);
                        if (sent_bytes < 0) {
                            if ((EAGAIN == errno) || (EINTR == errno)) {
                                sai_log_debug(SAI_API_SWITCH, "netdev_listen: EAGAIN / EINTR recevied during send");
                                continue;
                            }

                            sai_log_error(SAI_API_SWITCH,
                                          "netdev_listen: could not inject packet received from hostif %s into asic. Send error."
                                          " Sent size %d did not match packet size %d",
                                          hostif->ifname.c_str(),
                                          offset,
                                          new_pkt_size);
                            break;
                        }

                        offset += sent_bytes;
                    }
                } else if (len < 0 && hostif) {
                    sai_log_error(SAI_API_SWITCH,
                                  "netdev_listen: packet inject into asic failed because hostif interface"
                                  " %s received packet of negative length %d.",
                                  hostif->ifname.c_str(),
                                  len);
                } else if (hostif) {
                    sai_log_debug(
                        SAI_API_SWITCH, "netdev_listen: Recevied EOF on hostif interface %s", hostif->ifname.c_str(), len);
                }
            }
        }
    }
    sai_log_debug(SAI_API_SWITCH, "Terminating netdev_listen thread");
    return;
}

sai_status_t
lsai_device::switchport_hostif_tx_listener_start()
{
    // Start listening thread on all sock FDs of netdev_peer (This thread will
    // also listen for packets on future created netdev intf corresponding to frontport)
    // Single thread to process Rx packets from netdev intf and inject into
    // CPU-port or ASIC pipeline.

    if (!m_netdev_listen_thread_started) {
        m_netdev_listen_thread_started = true;
        m_netdev_thread = std::thread(&lsai_device::netdev_listen, this);
    }
    return SAI_STATUS_SUCCESS;
}

sai_status_t
lsai_device::switchport_hostif_socket_fd_set(const lsai_hostif& hostif, int fd)
{
    std::lock_guard<std::mutex> lock(m_hostif_lock);
    m_frontport_netdev_sock_fds.push_back(fd);
    m_netdev_sock_fd_to_hostif.emplace(fd, hostif);
    return SAI_STATUS_SUCCESS;
}

std::string
lsai_device::get_hw_device_type_str()
{
    const static std::vector<std::string> hw_device_type_str = {"none", "pacific", "gibraltar", "invalid"};
    return hw_device_type_str[(int)m_hw_device_type];
}

void
lsai_device::dump_event_counters()
{
    size_t event_packets, event_bytes;
    size_t port_packets, port_bytes;
    la_status status;
    sai_log_info(SAI_API_SWITCH, "dump trap counters");
    for (auto ec : m_event_counters) {
        la_counter_set* counter_set = ec.second;
        event_packets = 0;
        event_bytes = 0;
        if (counter_set != nullptr) {
            for (la_uint_t i = 0; i < counter_set->get_set_size(); i++) {
                port_packets = 0;
                port_bytes = 0;
                status
                    = counter_set->read(i, m_force_update /* force_update */, false /* clear_on_read */, port_packets, port_bytes);
                if (LA_STATUS_SUCCESS == status) {
                    event_packets += port_packets;
                    event_bytes += port_bytes;
                } else {
                    sai_log_error(SAI_API_SWITCH,
                                  "error %s reading counter for trap %s packet %d bytes %d",
                                  status.message().c_str(),
                                  la_event_names[ec.first]);
                }
            }
            if (event_packets != 0) {
                sai_log_info(SAI_API_SWITCH, "trap %s packet %d bytes %d", la_event_names[ec.first], event_packets, event_bytes);
            }
        }
    }

    for (auto ec : m_event_counters) {
        la_trap_priority_t priority = 0;
        la_counter_or_meter_set* tmp_cnt = nullptr;
        const la_punt_destination* punt_dest;
        bool skip = false;
        bool skip_p2p = false;
        bool overwrite_phb = false;
        la_traffic_class_t tc = 0;

        status = m_dev->get_trap_configuration(ec.first, priority, tmp_cnt, punt_dest, skip, skip_p2p, overwrite_phb, tc);
        if (status == LA_STATUS_SUCCESS) {
            sai_log_debug(
                SAI_API_SWITCH, "trap %s punt_dest 0x%lx priority %d tc %d", la_event_names[ec.first], punt_dest, priority, tc);
        }
    }

    m_trap_manager->dump_default_trap_meter_stats();
}

la_status
lsai_device::learn_notification_process_entry(const sai_fdb_event_notification_data_t* data,
                                              sai_bridge_port_fdb_learning_mode_t& learn_mode)
{
    std::lock_guard<std::recursive_mutex> lock(m_mutex);

    const sai_fdb_entry_t* fdb_entry = &data->fdb_entry;
    sai_fdb_event_t fdb_event = data->event_type;
    lsai_object la_sw(fdb_entry->switch_id);
    auto sdev = la_sw.get_device();

    // Today only SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID is defined
    if (data->attr[0].id != SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID) {
        sai_log_debug(SAI_API_FDB,
                      "Bridge port ID attribute missing, %s, BRIDGE_PORT_ID: UNKNOWN, SWITCH_ID: 0x%lx, "
                      "BV_ID: 0x%lx, MAC: %s, attri count: %d",
                      to_string(fdb_event).c_str(),
                      fdb_entry->switch_id,
                      fdb_entry->bv_id,
                      to_string(fdb_entry->mac_address).c_str(),
                      data->attr_count);
        return LA_STATUS_EINVAL;
    }

    auto pv_id = get_attr_value(SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID, data->attr[0].value);
    sai_log_debug(SAI_API_FDB,
                  "%s, BRIDGE_PORT_ID: 0x%lx, SWITCH_ID: 0x%lx, BV_ID: 0x%lx, MAC: %s, attri count: %d",
                  to_string(fdb_event).c_str(),
                  pv_id,
                  fdb_entry->switch_id,
                  fdb_entry->bv_id,
                  to_string(fdb_entry->mac_address).c_str(),
                  data->attr_count);

    la_switch* bridge = la_get_bridge_by_obj(fdb_entry->bv_id);
    if (bridge == nullptr) {
        sai_log_debug(SAI_API_FDB,
                      "Can not get bridge or vlan, event: %s, BRIDGE_PORT_ID: 0x%lx, SWITCH_ID: 0x%lx, "
                      "BV_ID: 0x%lx, MAC: %s, attri count: %d",
                      to_string(fdb_event).c_str(),
                      pv_id,
                      fdb_entry->switch_id,
                      fdb_entry->bv_id,
                      to_string(fdb_entry->mac_address).c_str(),
                      data->attr_count);
        return LA_STATUS_EINVAL;
    }

    lsai_object la_bport(pv_id);
    bridge_port_entry entry{};
    lsai_object la_port{};
    la_status status = LA_STATUS_SUCCESS;
    status = sdev->m_bridge_ports.get(la_bport.index, entry);
    if (status != LA_STATUS_SUCCESS) {
        sai_log_debug(SAI_API_FDB,
                      "Incorrect BRIDGE PORT ID, event: %s, BRIDGE_PORT_ID: 0x%lx, SWITCH_ID: 0x%lx, "
                      "BV_ID: 0x%lx, MAC: %s, attri count: %d",
                      to_string(fdb_event).c_str(),
                      pv_id,
                      fdb_entry->switch_id,
                      fdb_entry->bv_id,
                      to_string(fdb_entry->mac_address).c_str(),
                      data->attr_count);
        return LA_STATUS_EINVAL;
    }

    la_mac_addr_t lmac;
    reverse_copy(std::begin(fdb_entry->mac_address), std::end(fdb_entry->mac_address), std::begin(lmac.bytes));

    auto t2 = std::chrono::steady_clock::now();
    auto duration = t2 - m_bulk_fdb_notification_last_sent;

    learn_mode = entry.learn_mode;

    set_attr_value(SAI_FDB_ENTRY_ATTR_BRIDGE_PORT_ID, data->attr[0].value, entry.bridge_port_oid);

    switch (learn_mode) {
    case SAI_BRIDGE_PORT_FDB_LEARNING_MODE_HW:
        // Use SYSTEM learning mode to process learn and age notifications
        // install/modify/delete MAC entries through SDK APIs
        switch (fdb_event) {
        case SAI_FDB_EVENT_LEARNED:
        case SAI_FDB_EVENT_MOVE:
            // if MAC aging is disable, we need to give non-zero age time to install a dynamic entry
            status = bridge->set_mac_entry(lmac, entry.l2_port, (sdev->aging_time == 0) ? 60 : sdev->aging_time);
            if (status != LA_STATUS_SUCCESS) {
                sai_log_error(SAI_API_FDB,
                              "Can not install a MAC entry, event: %s, BRIDGE_PORT_ID: 0x%lx, SWITCH_ID: 0x%lx, "
                              "BV_ID: 0x%lx, MAC: %s, attri count: %d",
                              to_string(fdb_event).c_str(),
                              pv_id,
                              fdb_entry->switch_id,
                              fdb_entry->bv_id,
                              to_string(fdb_entry->mac_address).c_str(),
                              data->attr_count);
                return status;
            }
            break;
        case SAI_FDB_EVENT_AGED:
            status = bridge->remove_mac_entry(lmac);
            if (status != LA_STATUS_SUCCESS) {
                sai_log_error(SAI_API_FDB,
                              "Can not remove a MAC entry, event: %s, BRIDGE_PORT_ID: 0x%lx, SWITCH_ID: 0x%lx, "
                              "BV_ID: 0x%lx, MAC: %s, attri count: %d",
                              to_string(fdb_event).c_str(),
                              pv_id,
                              fdb_entry->switch_id,
                              fdb_entry->bv_id,
                              to_string(fdb_entry->mac_address).c_str(),
                              data->attr_count);
                return status;
            }
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }

    // Use SYSTEM learning mode to process learn and age notifications
    // install/modify/delete MAC entries through SAI FDB notification callback

    if (m_notification_callbacks.m_callbacks.on_fdb_event == nullptr) {
        // Do not generate log entries if no callback is registered
        return LA_STATUS_ENOTFOUND;
    }

    // do deep copy the data to the global fdb notification structure
    m_bulk_fdb_notifications[m_bulk_fdb_notification_count] = *data;
    m_bulk_fdb_notifications[m_bulk_fdb_notification_count].attr = &m_bulk_fdb_notification_attrs[m_bulk_fdb_notification_count];
    *(m_bulk_fdb_notifications[m_bulk_fdb_notification_count].attr) = *(data->attr);
    m_bulk_fdb_notification_count++;

    if ((m_bulk_fdb_notification_count == lsai_device::MAX_FDB_ENTRY_PROCESSING_ENTRIES)
        || ((m_bulk_fdb_notification_prev_bridge_port_id != entry.bridge_port_oid)
            && (m_bulk_fdb_notification_prev_bridge_port_id != SAI_NULL_OBJECT_ID))
        || duration > MAX_FDB_NOTIFICAITON_WAIT_TIME) {
        m_bulk_fdb_notification_last_sent = t2;
        return LA_STATUS_SUCCESS;
    } else {
        m_bulk_fdb_notification_prev_bridge_port_id = entry.bridge_port_oid;
        return LA_STATUS_EAGAIN;
    }
    return LA_STATUS_SUCCESS;
}
void
lsai_device::learn_notification_handler(uint32_t count, const sai_fdb_event_notification_data_t* data)
{
    // Process each one of the FDB entries based on each bridge port's learn mode
    sai_log_debug(SAI_API_SWITCH, "Processing %d MAC event(s)", count);
    m_bulk_fdb_notification_count = 0;
    for (uint32_t i = 0; i < count; i++) {
        sai_bridge_port_fdb_learning_mode_t learn_mode{};
        la_status status = learn_notification_process_entry(&data[i], learn_mode);

        if ((status == LA_STATUS_SUCCESS && m_bulk_fdb_notification_count != 0) || (i == count - 1)) {
            // Invoke FDB notification callback function out side of m_mutex lock
            if (m_notification_callbacks.m_callbacks.on_fdb_event != nullptr) {
                m_notification_callbacks.m_callbacks.on_fdb_event(m_bulk_fdb_notification_count, m_bulk_fdb_notifications);
            }
            m_bulk_fdb_notification_count = 0;
        }
        // Ignore other errors and continue process entries
    }
}

la_status
lsai_device::allocate_port(uint32_t lane,
                           port_entry_type_e type,
                           uint32_t& port_index,
                           port_entry*& out_pentry_ptr,
                           transaction& txn)
{
    txn.status = m_ports.allocate_id(port_index);
    la_return_on_error(txn.status);
    txn.on_fail([=]() { m_ports.release_id(port_index); });

    lsai_object la_port(SAI_OBJECT_TYPE_PORT, m_switch_id, port_index);

    port_entry pentry{};
    pentry.service.oid = la_port.object_id();
    pentry.type = type;
    pentry.base_voq = get_base_voq(port_index);

    // Store location for use when system port is not necessarily
    // available
    uint32_t ifg_idx = lane >> 8;
    pentry.slice_id = ifg_idx / m_dev_params.ifgs_per_slice;
    pentry.ifg_id = ifg_idx % m_dev_params.ifgs_per_slice;
    pentry.pif = lane & HW_LANE_PIF_MASK;

    if (m_voq_cfg_manager->is_voq_switch()) {
        // If VOQ switch, create map entry to translate sai_lane to
        // the port's OID
        txn.status = set_lane_to_port(lane, pentry.service.oid);
        la_return_on_error(txn.status, "Failed to create lane %u map to port OID 0x%0lx", lane, pentry.service.oid);
        sai_log_debug(SAI_API_PORT, "Mapping lane 0x%lx to port ID 0x%0lx", lane, pentry.service.oid);
    }

    // Calculate port's default system port GID, note that in VOQ mode
    // this is overridden with the SAI-provided SP GID
    la_uint64_t min_sp_gid;
    txn.status = m_dev->get_limit(limit_type_e::DEVICE__MIN_SYSTEM_PORT_GID, min_sp_gid);
    la_return_on_error(txn.status);
    pentry.sp_gid = min_sp_gid + port_index;

    // for mac_port, create an ingress_priority_group_entry for each tc
    if (pentry.is_mac()) {
        for (uint8_t ipg = 0; ipg < NUM_QUEUE_PER_PORT; ipg++) {
            pentry.ingress_priority_group_entries.emplace_back(ipg);
        }
    }

    txn.status = m_ports.set(port_index, pentry);
    la_return_on_error(txn.status);

    txn.status = m_ports.get_ptr(port_index, out_pentry_ptr);
    la_return_on_error(txn.status);

    return txn.status;
}

la_status
lsai_device::setup_sp_voq_and_cgm(la_uint_t vsc_offset,
                                  const port_entry* pentry,
                                  la_vsc_gid_vec_t& vsc_vec,
                                  la_vsc_gid_vec_t& vsc_vec_ecn,
                                  la_voq_set*& voq_set,
                                  la_voq_set*& voq_set_ecn,
                                  transaction& txn)
{
    txn.status = get_vsc_vec(vsc_offset, shared_from_this(), vsc_vec, vsc_vec_ecn);
    sai_log_debug(SAI_API_PORT,
                  "slice %d ifg %d vsc %d %d %d %d %d %d",
                  pentry->slice_id,
                  pentry->ifg_id,
                  vsc_vec[0],
                  vsc_vec[1],
                  vsc_vec[2],
                  vsc_vec[3],
                  vsc_vec[4],
                  vsc_vec[5]);

    txn.status = m_dev->create_voq_set(
        pentry->base_voq, NUM_QUEUE_PER_PORT, vsc_vec, m_switch_id, pentry->slice_id, pentry->ifg_id, voq_set);
    la_return_on_error(txn.status, "Failed creating voq set, %s", txn.status.message().c_str());
    txn.on_fail([=]() { m_dev->destroy(voq_set); });

    la_voq_cgm_profile* cgm_profile = m_wred_handler->default_uc_cgm_profile();
    if (pentry->type == port_entry_type_e::PCI || pentry->type == port_entry_type_e::INTERNAL_PCI) {
        cgm_profile = m_wred_handler->cpu_uc_cgm_profile();
    }

    for (int i = 0; i < NUM_QUEUE_PER_PORT; ++i) {
        txn.status = voq_set->set_cgm_profile(i, cgm_profile);
        la_return_on_error(txn.status, "Failed to set voq congestion profile, %s", txn.status.message().c_str());
    }

    // create second set of voq only for gb since set_ect_voq_set currently implemented only for gb
    if (pentry->type == port_entry_type_e::MAC && m_hw_device_type == hw_device_type_e::GIBRALTAR) {
        txn.status = m_dev->create_voq_set((pentry->base_voq) + NUM_QUEUE_PER_PORT,
                                           NUM_QUEUE_PER_PORT,
                                           vsc_vec_ecn,
                                           m_switch_id,
                                           pentry->slice_id,
                                           pentry->ifg_id,
                                           voq_set_ecn);
        la_return_on_error(txn.status, "Failed creating ecn voq set, %s", txn.status.message().c_str());
        txn.on_fail([=]() { m_dev->destroy(voq_set_ecn); });

        for (int i = 0; i < NUM_QUEUE_PER_PORT; ++i) {
            txn.status = voq_set_ecn->set_cgm_profile(i, m_wred_handler->default_uc_ecn_cgm_profile());
            la_return_on_error(txn.status, "Failed to set ecn voq congestion profile, %s", txn.status.message().c_str());
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_device::setup_sp_tm_defaults(la_voq_set* voq_set,
                                  la_voq_set* voq_set_ecn,
                                  la_vsc_gid_vec_t& vsc_vec,
                                  la_vsc_gid_vec_t& vsc_vec_ecn,
                                  uint64_t port_mbps,
                                  port_entry* pentry,
                                  la_interface_scheduler* scheduler,
                                  transaction& txn)
{
    txn.status = port_scheduler_default_config(shared_from_this(), *pentry, scheduler, port_mbps, vsc_vec, vsc_vec_ecn);
    la_return_on_error(txn.status, "Failed to configure port scheduler, %s", txn.status.message().c_str());

    la_counter_set* voq_counter_set = nullptr;
    // create stats for 8 queues, each queue has 2 stats, one enqueued, the other dropped
    txn.status = m_dev->create_counter(2 * NUM_QUEUE_PER_PORT, voq_counter_set);
    la_return_on_error(txn.status, "Failed to create counter, %s", txn.status.message().c_str());
    txn.on_fail([=]() { m_dev->destroy(voq_counter_set); });

    // group_size is always 1 here, since each counter has its own stats (no sharing)
    txn.status = voq_set->set_counter(la_voq_set::voq_counter_type_e::BOTH, 1, voq_counter_set);
    la_return_on_error(txn.status, "Failed to set counter to the voq, %s", txn.status.message().c_str());

    // voq_set_ecn is created only for GB hw
    if (pentry->type == port_entry_type_e::MAC && m_hw_device_type == hw_device_type_e::GIBRALTAR) {
        la_counter_set* voq_counter_set_ecn = nullptr;
        // create stats for 8 queues, each queue has 2 stats, one enqueued, the other dropped
        txn.status = m_dev->create_counter(2 * NUM_QUEUE_PER_PORT, voq_counter_set_ecn);
        la_return_on_error(txn.status, "Failed to create counter for ecn voq set, %s", txn.status.message().c_str());
        txn.on_fail([=]() { m_dev->destroy(voq_counter_set_ecn); });

        // group_size is always 1 here, since each counter has its own stats (no sharing)
        txn.status = voq_set_ecn->set_counter(la_voq_set::voq_counter_type_e::BOTH, 1, voq_counter_set_ecn);
        la_return_on_error(txn.status, "Failed to set counter to the ecn voq set, %s", txn.status.message().c_str());
    }

    // set default wred object to all queues
    for (uint32_t i = 0; i < NUM_QUEUE_PER_PORT; i++) {
        pentry->wred_oids[i] = m_wred_handler->default_wred_obj_id();
    }

    return LA_STATUS_SUCCESS;
}

std::vector<la_counter_set*>
port_entry::get_voq_counter_sets()
{
    std::vector<la_counter_set*> ret_counter_set;
    la_status status;
    size_t size = 2 * NUM_QUEUE_PER_PORT;
    la_voq_set::voq_counter_type_e type = la_voq_set::voq_counter_type_e::BOTH;

    la_counter_set* voq_counter_set = nullptr;
    auto voq_set = sys_port->get_voq_set();
    if (voq_set != nullptr) {
        status = voq_set->get_counter(type, size, voq_counter_set);
        if (status == LA_STATUS_SUCCESS) {
            ret_counter_set.push_back(voq_counter_set);
        }
    }

    la_counter_set* voq_counter_set_ecn = nullptr;
    auto voq_set_ecn = sys_port->get_ect_voq_set();
    if (voq_set_ecn != nullptr) {
        status = voq_set_ecn->get_counter(type, size, voq_counter_set_ecn);
        if (status == LA_STATUS_SUCCESS) {
            ret_counter_set.push_back(voq_counter_set_ecn);
        }
    }

    return ret_counter_set;
}

std::vector<la_voq_set*>
port_entry::get_voq_sets()
{
    la_status status;
    std::vector<la_voq_set*> ret_set;

    auto voq_set = sys_port->get_voq_set();
    if (voq_set != nullptr) {
        ret_set.push_back(voq_set);
    }

    auto voq_set_ecn = sys_port->get_ect_voq_set();
    if (voq_set_ecn != nullptr) {
        ret_set.push_back(voq_set_ecn);
    }

    return ret_set;
}
}
}
