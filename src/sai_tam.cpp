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
#include "sai_tam.h"
#include "sai_logger.h"
#include "sai_constants.h"
#include <map>
#include <mutex>
#include <algorithm>

namespace silicon_one
{
namespace sai
{

using namespace std;

static constexpr uint32_t TAM_MAX_DESCRIPTOR_IN_REPORT = 128;
static sai_object_id_t search_oid = 0;

#define SAI_TAM_EVENT_MUTEX_LOCK(sdev, oid)                                                                                        \
    if (sdev == nullptr) {                                                                                                         \
        la_return_on_error(LA_STATUS_ENOTINITIALIZED,                                                                              \
                           "Missing lsai_device pointer in tam_event,  tam_event_action or tam_report (OID:0x%lx)",                \
                           oid);                                                                                                   \
    }                                                                                                                              \
    std::lock_guard<std::recursive_mutex> lock(sdev->m_mutex);

/// Return enum ID of a supported type.
lsai_tam_event_desc::supported_event_type_e
lsai_tam_event_desc::supported_event_type() const
{
    switch (static_cast<uint32_t>(type)) {
    case SAI_TAM_EVENT_TYPE_SWITCH:
        switch (event.switch_event.type) {
        case SAI_SWITCH_EVENT_TYPE_PARITY_ERROR:
            return lsai_tam_event_desc::supported_event_type_e::SWITCH_EVENT_PARITY_ERROR;
        default:
            return lsai_tam_event_desc::supported_event_type_e::NOT_SUPPORTED;
        }
        break;
    default:
        return lsai_tam_event_desc::supported_event_type_e::NOT_SUPPORTED;
    }
}

lsai_tam_event_desc&
lsai_tam_event_desc::operator=(const la_notification_desc& desc)
{
    this->timestamp_ns = desc.timestamp_ns;
    this->block_id = desc.block_id;
    this->addr = desc.addr;

    switch (desc.type) {
    case la_notification_type_e::ECC:
        this->type = (sai_tam_event_type_t)SAI_TAM_EVENT_TYPE_SWITCH;
        this->event.switch_event.type = sai_switch_event_type_t::SAI_SWITCH_EVENT_TYPE_PARITY_ERROR;
        this->event.switch_event.data.parity_error.instance_addr = -1;
        this->event.switch_event.data.parity_error.data = desc.u.ecc.data;
        this->event.switch_event.data.parity_error.err_type = sai_tam_switch_event_ecc_err_type_e::PARITY;
        break;
    case la_notification_type_e::MEM_PROTECT:
        this->type = (sai_tam_event_type_t)SAI_TAM_EVENT_TYPE_SWITCH;
        this->event.switch_event.type = sai_switch_event_type_t::SAI_SWITCH_EVENT_TYPE_PARITY_ERROR;
        this->event.switch_event.data.parity_error.instance_addr = desc.u.mem_protect.instance_addr;
        this->event.switch_event.data.parity_error.data = desc.u.mem_protect.entry;
        switch (desc.u.mem_protect.error) {
        case la_mem_protect_error_e::ECC_1B:
            this->event.switch_event.data.parity_error.err_type = sai_tam_switch_event_ecc_err_type_e::ECC_COR;
            break;
        case la_mem_protect_error_e::ECC_2B:
            this->event.switch_event.data.parity_error.err_type = sai_tam_switch_event_ecc_err_type_e::ECC_UNCOR;
            break;
        case la_mem_protect_error_e::PARITY:
            this->event.switch_event.data.parity_error.err_type = sai_tam_switch_event_ecc_err_type_e::PARITY;
            break;
        default:
            sai_log_error(SAI_API_SWITCH,
                          "lsai_tam_event_desc: la_mem_protect_error_e.type(%s) is not supported.",
                          to_string(desc.u.mem_protect.error).c_str());
        }
        break;
    default:
        sai_log_debug(
            SAI_API_SWITCH, "lsai_tam_event_desc: la_notification_desc.type(%s) is not supported.", to_string(desc.type).c_str());
        break;
    }

    return *this;
}

static sai_tam_event_desc_t
to_sai_tam_event_desc(const lsai_tam_event_desc& in)
{
    sai_tam_event_data_t event{};
    switch (static_cast<uint32_t>(in.type)) {
    case SAI_TAM_EVENT_TYPE_SWITCH:
        switch (in.event.switch_event.type) {
        case SAI_SWITCH_EVENT_TYPE_PARITY_ERROR:
            event.switch_event.type = in.event.switch_event.type;
            event.switch_event.data.parity_error.data = in.event.switch_event.data.parity_error.data;
            event.switch_event.data.parity_error.err_type = in.event.switch_event.data.parity_error.err_type;
            event.switch_event.data.parity_error.instance_addr = in.event.switch_event.data.parity_error.instance_addr;
            break;
        default:
            sai_log_debug(
                SAI_API_SWITCH, "to_sai_tam_event_desc: lsai_tam_event_desc(%s) is not supported.", in.types_in_str().c_str());
            break;
        }
        break;
    default:
        sai_log_debug(
            SAI_API_SWITCH, "to_sai_tam_event_desc: lsai_tam_event_desc(%s) is not supported.", in.types_in_str().c_str());
        break;
    }

    return sai_tam_event_desc_t{in.block_id, in.timestamp_ns, in.type, event};
}

string
lsai_tam_event_desc::types_in_str() const
{
    std::stringstream ss;

    switch (static_cast<uint32_t>(type)) {
    case SAI_TAM_EVENT_TYPE_SWITCH:
        ss << "Type(SAI_TAM_EVENT_TYPE_SWITCH)";
        ss << ", Switch Event Type(" << to_string(event.switch_event.type) << ")";
        break;
    default:
        ss << "Type(" << to_string(type) << ")";
        break;
    }

    return ss.str();
}

string
lsai_tam_event_desc::event_in_str() const
{
    std::stringstream ss;

    switch (supported_event_type()) {
    case supported_event_type_e::SWITCH_EVENT_PARITY_ERROR:
        ss << std::showbase << std::hex << std::uppercase;
        ss << "err_type(" << to_string(event.switch_event.data.parity_error.err_type) << ")";
        ss << ", mem_addr(" << event.switch_event.data.parity_error.instance_addr << ")";
        ss << ", mem_data(" << event.switch_event.data.parity_error.data << ")";
        break;
    default:
        ss << "event(Unknown)";
        break;
    }

    return ss.str();
}

sai_log_level_t
lsai_tam_event_desc::event_level() const
{
    switch (supported_event_type()) {
    case supported_event_type_e::SWITCH_EVENT_PARITY_ERROR:
        if (event.switch_event.data.parity_error.err_type == sai_tam_switch_event_ecc_err_type_e::ECC_UNCOR) {
            return SAI_LOG_LEVEL_ERROR;
        }
        return SAI_LOG_LEVEL_WARN;
    default:
        return SAI_LOG_LEVEL_WARN;
    }
}

// lsai_tam_transport_entry methods definition

la_status
lsai_tam_transport_entry::set_type(sai_tam_transport_type_t transport_type)
{
    m_type = transport_type;

    return LA_STATUS_SUCCESS;
}

// lsai_tam_collector_entry methods definition

la_status
lsai_tam_collector_entry::bind_transport(lsai_tam_transport_entry_ptr transport_ptr)
{
    // check transport is valid
    if (transport_ptr == nullptr) {
        la_return_on_error(LA_STATUS_EINVAL, "bind_transport: Invalid tam_transport pointer.");
    }

    // check if bound already...
    if (transport_ptr == m_transport) {
        la_return_on_error(
            LA_STATUS_EEXIST, "tam_collector(0x%lx) is bound to tam_transport(0x%lx) already.", m_oid, transport_ptr->m_oid);
    }

    if (m_transport != nullptr) {
        // collector entry is bound to another transport, unbind that transport first
        la_status status = unbind_transport();
        la_return_on_error(status);
    }

    // bind transport with this transport
    m_transport = transport_ptr;

    sai_log_debug(SAI_API_TAM, "tam_collector(0x%lx) is bound with tam_transport(0x%lx).", m_oid, transport_ptr->m_oid);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_collector_entry::unbind_transport()
{
    // check if the collector is bound to a transport
    if (m_transport == nullptr) {
        sai_log_debug(SAI_API_TAM, "No bound transport, tam_collection_object(0x%lx).", m_oid);
        return LA_STATUS_SUCCESS;
    }

    sai_log_debug(SAI_API_TAM, "tam_collection_object(0x%lx) unbound with tam_transport(0x%lx).", m_oid, m_transport->m_oid);

    // unbind the transport
    m_transport = nullptr;

    return LA_STATUS_SUCCESS;
}

// lsai_tam_report_entry methods definition

la_status
lsai_tam_report_entry::set_type(sai_tam_report_type_t report_type)
{
    m_type = report_type;

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_report_entry::set_interval(sai_uint32_t time_interval)
{
    m_interval = time_interval;

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_report_entry::enqueue(lsai_tam_event_desc desc, const sai_object_id_t& tam_oid)
{
    SAI_TAM_EVENT_MUTEX_LOCK(m_sdev, m_oid);

    if (m_mode == SAI_TAM_REPORT_MODE_ALL) {
        auto tam_event_desc = to_sai_tam_event_desc(desc);
        return report(tam_oid, 1, &tam_event_desc);
    }

    // if m_mode == SAI_TAM_REPORT_MODE_BULK, just enqueue to m_buffer
    m_buffer.push_back(desc);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_report_entry::enqueue(std::vector<lsai_tam_event_desc> desc_list, const sai_object_id_t& tam_oid)
{
    SAI_TAM_EVENT_MUTEX_LOCK(m_sdev, m_oid);

    if (m_mode == SAI_TAM_REPORT_MODE_ALL) {
        std::vector<sai_tam_event_desc_t> tam_event_desc_list;
        std::transform(desc_list.begin(), desc_list.end(), std::back_inserter(tam_event_desc_list), [](lsai_tam_event_desc i) {
            return to_sai_tam_event_desc(i);
        });
        return report(tam_oid, tam_event_desc_list.size(), tam_event_desc_list.data());
    }

    // if m_mode == SAI_TAM_REPORT_MODE_BULK, just enqueue to m_buffer
    m_buffer.insert(m_buffer.end(), desc_list.begin(), desc_list.end());

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_report_entry::report(const sai_object_id_t& tam_oid, const uint32_t& desc_counts, sai_tam_event_desc_t* desc_array)
{
    std::lock_guard<std::mutex> cb_lock(m_sdev->m_notification_callbacks.m_tam_event_cb_lock);

    if (m_sdev->m_notification_callbacks.m_callbacks.on_tam_event != nullptr) {
        m_sdev->m_notification_callbacks.m_callbacks.on_tam_event(tam_oid, desc_counts, desc_array, 0, nullptr);
    } else {
        sai_log_debug(SAI_API_SWITCH, "mem_ecc_notification_handler: No callback installed for TAM event.");
    }

    sai_log_debug(SAI_API_TAM, "tam_report (0x%lx) sent report for tam event (0x%lx).", m_oid, tam_oid);

    // TODO: We will handle other report types here.

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_report_entry::report_and_erase()
{
    SAI_TAM_EVENT_MUTEX_LOCK(m_sdev, m_oid);

    uint32_t desc_counts = m_buffer.size();

    if (desc_counts == 0) {
        return LA_STATUS_SUCCESS;
    }

    if (desc_counts > TAM_MAX_DESCRIPTOR_IN_REPORT) {
        desc_counts = TAM_MAX_DESCRIPTOR_IN_REPORT;
    }

    // TODO: need to fix the tam_object_ID
    // TODO: this copy action is a work-around to avoid using struct in sai_attr_ext which gives cereal autogen issue.
    //       cereal autogen doesn't read/geneerate struct in sai_attr_ext. If fixed, we should change m_buffer to
    //       sai_tam_event_desc_t type.
    std::vector<sai_tam_event_desc_t> tam_event_desc_list;
    std::transform(m_buffer.begin(), m_buffer.end(), std::back_inserter(tam_event_desc_list), [](lsai_tam_event_desc i) {
        return to_sai_tam_event_desc(i);
    });
    report(0, desc_counts, tam_event_desc_list.data());

    auto it = m_buffer.begin();
    m_buffer.erase(it, it + desc_counts);

    sai_log_debug(SAI_API_TAM, "tam_report(0x%lx) reported (%d) of descriptors.", m_oid, desc_counts);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_report_entry::flush()
{
    la_status status{LA_STATUS_SUCCESS};
    while (m_buffer.size() != 0) {
        status = report_and_erase();
        la_return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

// lsai_tam_event_action_entry methods definition

la_status
lsai_tam_event_action_entry::bind_reporter(lsai_tam_report_entry_ptr report_ptr)
{
    // check report is valid
    if (report_ptr == nullptr) {
        la_return_on_error(LA_STATUS_EINVAL, "bind_reporter: Invalid tam_report pointer.");
    }

    // check if bound already...
    if (report_ptr == m_reporter) {
        la_return_on_error(
            LA_STATUS_EEXIST, "tam_event_action(0x%lx) is bound to tam_report(0x%lx) already.", m_oid, report_ptr->m_oid);
    }

    if (m_reporter != nullptr) {
        // event_action entry is bound to another reporter, unbind that reporter first
        la_status status = unbind_reporter();
        la_return_on_error(status);
    }

    // bind event_action with this reporter
    m_reporter = report_ptr;

    sai_log_debug(SAI_API_TAM, "tam_event_action_object(0x%lx) is bound with tam_report_object(0x%lx).", m_oid, report_ptr->m_oid);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_event_action_entry::unbind_reporter()
{
    // find the event_action_oid in this reporter
    if (m_reporter == nullptr) {
        sai_log_debug(SAI_API_TAM, "No bound reporter, tam_event_action_object(0x%lx).", m_oid);
        return LA_STATUS_SUCCESS;
    }

    // Flush the reporter then unbind it
    m_reporter->flush();
    auto reporter_oid = m_reporter->m_oid;
    m_reporter.reset();
    m_reporter = nullptr;

    sai_log_debug(SAI_API_TAM, "tam_event_action_object(0x%lx) unbound with tam_report_object(0x%lx).", m_oid, reporter_oid);

    return LA_STATUS_SUCCESS;
}

// lsai_tam_event_entry methods definition

std::vector<lsai_tam_event_action_entry_ptr>::iterator
lsai_tam_event_entry::find_event_action(const sai_object_id_t& event_action_oid)
{
    silicon_one::sai::search_oid = event_action_oid;

    return std::find_if(m_event_action_list.begin(), m_event_action_list.end(), [](lsai_tam_event_action_entry_ptr i) {
        return i->m_oid == silicon_one::sai::search_oid;
    });
}

std::vector<lsai_tam_collector_entry_ptr>::iterator
lsai_tam_event_entry::find_collector(const sai_object_id_t& collector_oid)
{
    silicon_one::sai::search_oid = collector_oid;

    return std::find_if(m_collector_list.begin(), m_collector_list.end(), [](lsai_tam_collector_entry_ptr i) {
        return i->m_oid == silicon_one::sai::search_oid;
    });
}

bool
lsai_tam_event_entry::match_event_types(lsai_tam_event_desc desc)
{
    // sai_tam_event_type_t must match with tam_event_entry::m_type
    if (desc.type != m_type) {
        return false;
    }

    switch (static_cast<uint32_t>(desc.type)) {
    case SAI_TAM_EVENT_TYPE_SWITCH: {
        // If event descriptor type is switch event type, check if switch event matches tam_event_entry::m_switch_event_types
        // First, check if switch_event is set to ALL.
        auto all_it = std::find(
            m_switch_event_types.begin(), m_switch_event_types.end(), sai_switch_event_type_t::SAI_SWITCH_EVENT_TYPE_ALL);
        if (all_it != m_switch_event_types.end()) {
            return true;
        }
        // Second, check if individual switch_event is matched.
        auto it = std::find(m_switch_event_types.begin(), m_switch_event_types.end(), desc.event.switch_event.type);
        if (it != m_switch_event_types.end()) {
            return true;
        }
    } break;
    default:
        // Others are not supported yet.
        sai_log_debug(SAI_API_TAM, "Not Implemented. type(%d)", desc.type);
        break;
    }

    return false;
}

la_status
lsai_tam_event_entry::bind_event_action(lsai_tam_event_action_entry_ptr event_action_ptr)
{
    // check event_action is valid
    if (event_action_ptr == nullptr) {
        la_return_on_error(LA_STATUS_EINVAL, "bind_event_action: Invalid tam_event_action pointer.");
    }

    // check if bound already...
    auto event_action_it = find_event_action(event_action_ptr->m_oid);
    if (event_action_it != m_event_action_list.end()) {
        la_return_on_error(
            LA_STATUS_EEXIST, "tam_event_action(0x%lx) is bound to tam_event(0x%lx) already.", event_action_ptr->m_oid, m_oid);
    }

    // bind the tam_event_action
    m_event_action_list.push_back(event_action_ptr);

    sai_log_debug(
        SAI_API_TAM, "tam_event_action_object(0x%lx) is bound with tam_event_object(0x%lx).", event_action_ptr->m_oid, m_oid);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_event_entry::unbind_event_action(const sai_object_id_t& event_action_oid)
{
    // find the event_action_oid in this tam_event
    auto event_action_it = find_event_action(event_action_oid);

    // return not found if event_action_oid is not in m_event_action_list
    if (event_action_it == m_event_action_list.end()) {
        sai_log_debug(
            SAI_API_TAM,
            "event_action list: %s",
            to_string(m_event_action_list.begin(),
                      m_event_action_list.end(),
                      [](std::vector<silicon_one::sai::lsai_tam_event_action_entry_ptr>::iterator i) { return (*i)->m_oid; })
                .c_str());

        la_return_on_error(
            LA_STATUS_ENOTFOUND, "tam_event_action(0x%lx) is not found in tam_event(0x%lx).", event_action_oid, m_oid);
    }

    // flush the event_action->reporter before unbind.
    if (((*event_action_it) != nullptr) && ((*event_action_it)->m_reporter != nullptr)) {
        (*event_action_it)->m_reporter->flush();
    }

    // unbind tam_event_action
    m_event_action_list.erase(event_action_it);

    sai_log_debug(SAI_API_TAM, "tam_event_action_object(0x%lx) unbound with tam_event(0x%lx).", event_action_oid, m_oid);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_event_entry::unbind_all_event_actions()
{
    la_status status{LA_STATUS_SUCCESS};

    std::map<sai_object_id_t, lsai_tam_report_entry_ptr> temp_reporter_map;

    // check if all event_action's reporters are valid.
    for (auto event_action_ptr : m_event_action_list) {
        if ((event_action_ptr != nullptr) && (event_action_ptr->m_reporter != nullptr)) {
            temp_reporter_map[event_action_ptr->m_reporter->m_oid] = event_action_ptr->m_reporter;
        }
    }

    // flush all reporters.
    for (auto item : temp_reporter_map) {
        status = item.second->flush();
        if (status) {
            sai_log_warn(SAI_API_TAM,
                         "Flush fail for tam_report(0x%lx), called by tam_event(0x%lx). %s",
                         item.second->m_oid,
                         m_oid,
                         status.message().c_str());
        }
    }

    // clear the event_action list
    sai_log_debug(SAI_API_TAM, "tam_event(0x%lx) unbind all tam_event_action (count:%d).", m_oid, m_event_action_list.size());
    m_event_action_list.clear();

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_event_entry::bind_collector(lsai_tam_collector_entry_ptr collector_ptr)
{
    // check collector is valid
    if (collector_ptr == nullptr) {
        la_return_on_error(LA_STATUS_EINVAL, "bind_collector: Invalid tam_collector pointer.");
    }

    // check if bound already...
    auto collector_it = find_collector(collector_ptr->m_oid);
    if (collector_it != m_collector_list.end()) {
        la_return_on_error(
            LA_STATUS_EEXIST, "tam_collector(0x%lx) is bound to tam_event(0x%lx) already.", collector_ptr->m_oid, m_oid);
    }

    // bind the tam_collector
    m_collector_list.push_back(collector_ptr);

    sai_log_debug(SAI_API_TAM, "tam_collector_object(0x%lx) is bound with tam_event_object(0x%lx).", collector_ptr->m_oid, m_oid);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_event_entry::unbind_collector(const sai_object_id_t& collector_oid)
{
    // find the collector_oid in this tam_event
    auto collector_it = find_collector(collector_oid);

    // return not found if collector_oid is not in m_collector_list
    if (collector_it == m_collector_list.end()) {
        sai_log_debug(SAI_API_TAM,
                      "collector list: %s",
                      to_string(m_collector_list.begin(),
                                m_collector_list.end(),
                                [](std::vector<silicon_one::sai::lsai_tam_collector_entry_ptr>::iterator i) { return (*i)->m_oid; })
                          .c_str());

        la_return_on_error(LA_STATUS_ENOTFOUND, "tam_collector(0x%lx) is not found in tam_event(0x%lx).", collector_oid, m_oid);
    }

    // unbind tam_collector
    m_collector_list.erase(collector_it);

    sai_log_debug(SAI_API_TAM, "tam_collector_object(0x%lx) unbound with tam_event(0x%lx).", collector_oid, m_oid);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_event_entry::unbind_all_collectors()
{
    la_status status{LA_STATUS_SUCCESS};

    // clear the collector list
    sai_log_debug(SAI_API_TAM, "tam_event(0x%lx) unbind all tam_collector (count:%d).", m_oid, m_collector_list.size());
    m_collector_list.clear();

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_event_entry::send_to_reporters(lsai_tam_event_desc desc, const sai_object_id_t& tam_oid)
{
    SAI_TAM_EVENT_MUTEX_LOCK(m_sdev, m_oid);

    la_status status{LA_STATUS_SUCCESS};

    if (!match_event_types(desc)) {
        sai_log_debug(
            SAI_API_TAM, "tam_event (0x%lx), not matched with event descriptor type(%s)", m_oid, desc.types_in_str().c_str());
        return status;
    }

    // send the descriptor to each event_action's reporter
    for (auto event_action_ptr : m_event_action_list) {
        if ((event_action_ptr != nullptr) && (event_action_ptr->m_reporter != nullptr)) {
            status = event_action_ptr->m_reporter->enqueue(desc, tam_oid);
            if (status) {
                sai_log_warn(SAI_API_TAM, "%s", status.message().c_str());
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_event_entry::send_to_reporters(std::vector<lsai_tam_event_desc> desc_list, const sai_object_id_t& tam_oid)
{
    SAI_TAM_EVENT_MUTEX_LOCK(m_sdev, m_oid);

    la_status status{LA_STATUS_SUCCESS};

    std::vector<lsai_tam_event_desc> matched_list;
    for (auto desc : desc_list) {
        if (match_event_types(desc)) {
            matched_list.push_back(desc);
        } else {
            sai_log_debug(
                SAI_API_TAM, "tam_event (0x%lx), not matched with event descriptor type(%s)", m_oid, desc.types_in_str().c_str());
        }
    }

    // send the descriptor to each event_action's reporter
    for (auto event_action_ptr : m_event_action_list) {
        if ((event_action_ptr != nullptr) && (event_action_ptr->m_reporter != nullptr)) {
            status = event_action_ptr->m_reporter->enqueue(matched_list, tam_oid);
            if (status) {
                sai_log_warn(SAI_API_TAM, "%s", status.message().c_str());
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

// lsai_tam_entry methods definition

la_status
lsai_tam_entry::event_handler(const la_notification_desc& desc)
{
    SAI_TAM_EVENT_MUTEX_LOCK(m_sdev, m_oid);

    lsai_tam_event_desc event_desc{};
    event_desc = desc;

    switch (static_cast<uint32_t>(event_desc.type)) {
    case SAI_TAM_EVENT_TYPE_SWITCH: {
        sai_log_debug(SAI_API_SWITCH, "tam (0x%lx) event_handler: Received SWITCH_EVENT.", m_oid);

        bool reported = false;
        for (auto tam_event_ptr : m_tam_events) {
            if (tam_event_ptr->m_type == SAI_TAM_EVENT_TYPE_SWITCH) {
                tam_event_ptr->send_to_reporters(event_desc, m_oid);
                reported = true;
            }
        }
        // Check if there are any registered tam events for ecc
        if (!reported) {
            sai_log_debug(SAI_API_SWITCH, "tam (0x%lx) event_handler: No tam_event object for reporting SWITCH_EVENT.", m_oid);
            return LA_STATUS_EEXIST;
        }
    } break;
    default:
        la_return_on_error(
            LA_STATUS_ENOTIMPLEMENTED, "event type(%d) is not supported in tam_object(0x%lx).", event_desc.type, m_oid);
        break;
    }

    return LA_STATUS_SUCCESS;
}

std::vector<lsai_tam_event_entry_ptr>::iterator
lsai_tam_entry::find_event(const sai_object_id_t& event_oid)
{
    silicon_one::sai::search_oid = event_oid;

    return std::find_if(m_tam_events.begin(), m_tam_events.end(), [](lsai_tam_event_entry_ptr i) {
        return i->m_oid == silicon_one::sai::search_oid;
    });
}

la_status
lsai_tam_entry::register_tam_event(lsai_tam_event_entry_ptr tam_event_ptr)
{
    auto it = find_event(tam_event_ptr->m_oid);
    if (it != m_tam_events.end()) {
        la_return_on_error(
            LA_STATUS_EEXIST, "tam_event(0x%lx) is registered with tam_entry(0x%lx) already.", tam_event_ptr->m_oid, m_oid);
    }
    m_tam_events.push_back(tam_event_ptr);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_entry::unregister_tam_event(const sai_object_id_t& event_oid)
{
    auto it = find_event(event_oid);
    if (it == m_tam_events.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    m_tam_events.erase(it);

    return LA_STATUS_SUCCESS;
}

la_status
lsai_tam_entry::remove_all_registries()
{
    m_tam_events.clear();

    return LA_STATUS_SUCCESS;
}

static sai_status_t tam_transport_type_get(_In_ const sai_object_key_t* key,
                                           _Inout_ sai_attribute_value_t* value,
                                           _In_ uint32_t attr_index,
                                           _Inout_ vendor_cache_t* cache,
                                           void* arg);

static sai_status_t tam_transport_src_port_get(_In_ const sai_object_key_t* key,
                                               _Inout_ sai_attribute_value_t* value,
                                               _In_ uint32_t attr_index,
                                               _Inout_ vendor_cache_t* cache,
                                               void* arg);

static sai_status_t tam_transport_src_port_set(_In_ const sai_object_key_t* key,
                                               _In_ const sai_attribute_value_t* value,
                                               void* arg);

static sai_status_t tam_transport_dst_port_get(_In_ const sai_object_key_t* key,
                                               _Inout_ sai_attribute_value_t* value,
                                               _In_ uint32_t attr_index,
                                               _Inout_ vendor_cache_t* cache,
                                               void* arg);

static sai_status_t tam_transport_dst_port_set(_In_ const sai_object_key_t* key,
                                               _In_ const sai_attribute_value_t* value,
                                               void* arg);

static sai_status_t tam_transport_mtu_get(_In_ const sai_object_key_t* key,
                                          _Inout_ sai_attribute_value_t* value,
                                          _In_ uint32_t attr_index,
                                          _Inout_ vendor_cache_t* cache,
                                          void* arg);

static sai_status_t tam_transport_mtu_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t tam_transport_auth_get(_In_ const sai_object_key_t* key,
                                           _Inout_ sai_attribute_value_t* value,
                                           _In_ uint32_t attr_index,
                                           _Inout_ vendor_cache_t* cache,
                                           void* arg);

static sai_status_t tam_transport_auth_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t tam_collector_src_ip_get(_In_ const sai_object_key_t* key,
                                             _Inout_ sai_attribute_value_t* value,
                                             _In_ uint32_t attr_index,
                                             _Inout_ vendor_cache_t* cache,
                                             void* arg);

static sai_status_t tam_collector_src_ip_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t tam_collector_dst_ip_get(_In_ const sai_object_key_t* key,
                                             _Inout_ sai_attribute_value_t* value,
                                             _In_ uint32_t attr_index,
                                             _Inout_ vendor_cache_t* cache,
                                             void* arg);

static sai_status_t tam_collector_dst_ip_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t tam_collector_localhost_get(_In_ const sai_object_key_t* key,
                                                _Inout_ sai_attribute_value_t* value,
                                                _In_ uint32_t attr_index,
                                                _Inout_ vendor_cache_t* cache,
                                                void* arg);

static sai_status_t tam_collector_localhost_set(_In_ const sai_object_key_t* key,
                                                _In_ const sai_attribute_value_t* value,
                                                void* arg);

static sai_status_t tam_collector_transport_get(_In_ const sai_object_key_t* key,
                                                _Inout_ sai_attribute_value_t* value,
                                                _In_ uint32_t attr_index,
                                                _Inout_ vendor_cache_t* cache,
                                                void* arg);

static sai_status_t tam_collector_transport_set(_In_ const sai_object_key_t* key,
                                                _In_ const sai_attribute_value_t* value,
                                                void* arg);

static sai_status_t tam_collector_dscp_get(_In_ const sai_object_key_t* key,
                                           _Inout_ sai_attribute_value_t* value,
                                           _In_ uint32_t attr_index,
                                           _Inout_ vendor_cache_t* cache,
                                           void* arg);

static sai_status_t tam_collector_dscp_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t tam_report_type_get(_In_ const sai_object_key_t* key,
                                        _Inout_ sai_attribute_value_t* value,
                                        _In_ uint32_t attr_index,
                                        _Inout_ vendor_cache_t* cache,
                                        void* arg);

static sai_status_t tam_report_type_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t tam_report_mode_get(_In_ const sai_object_key_t* key,
                                        _Inout_ sai_attribute_value_t* value,
                                        _In_ uint32_t attr_index,
                                        _Inout_ vendor_cache_t* cache,
                                        void* arg);

static sai_status_t tam_report_interval_get(_In_ const sai_object_key_t* key,
                                            _Inout_ sai_attribute_value_t* value,
                                            _In_ uint32_t attr_index,
                                            _Inout_ vendor_cache_t* cache,
                                            void* arg);

static sai_status_t tam_report_interval_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t tam_event_action_report_id_get(_In_ const sai_object_key_t* key,
                                                   _Inout_ sai_attribute_value_t* value,
                                                   _In_ uint32_t attr_index,
                                                   _Inout_ vendor_cache_t* cache,
                                                   void* arg);

static sai_status_t tam_event_action_report_id_set(_In_ const sai_object_key_t* key,
                                                   _In_ const sai_attribute_value_t* value,
                                                   void* arg);

static sai_status_t tam_event_type_get(_In_ const sai_object_key_t* key,
                                       _Inout_ sai_attribute_value_t* value,
                                       _In_ uint32_t attr_index,
                                       _Inout_ vendor_cache_t* cache,
                                       void* arg);

static sai_status_t tam_event_action_list_get(_In_ const sai_object_key_t* key,
                                              _Inout_ sai_attribute_value_t* value,
                                              _In_ uint32_t attr_index,
                                              _Inout_ vendor_cache_t* cache,
                                              void* arg);

static sai_status_t tam_event_collect_list_get(_In_ const sai_object_key_t* key,
                                               _Inout_ sai_attribute_value_t* value,
                                               _In_ uint32_t attr_index,
                                               _Inout_ vendor_cache_t* cache,
                                               void* arg);

static sai_status_t tam_switch_event_type_get(_In_ const sai_object_key_t* key,
                                              _Inout_ sai_attribute_value_t* value,
                                              _In_ uint32_t attr_index,
                                              _Inout_ vendor_cache_t* cache,
                                              void* arg);

static sai_status_t tam_switch_event_type_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg);

static sai_status_t tam_event_objects_list_get(_In_ const sai_object_key_t* key,
                                               _Inout_ sai_attribute_value_t* value,
                                               _In_ uint32_t attr_index,
                                               _Inout_ vendor_cache_t* cache,
                                               void* arg);

static sai_status_t tam_bind_point_list_get(_In_ const sai_object_key_t* key,
                                            _Inout_ sai_attribute_value_t* value,
                                            _In_ uint32_t attr_index,
                                            _Inout_ vendor_cache_t* cache,
                                            void* arg);

static sai_status_t tam_event_objects_list_set(_In_ const sai_object_key_t* key,
                                               _In_ const sai_attribute_value_t* value,
                                               void* arg);

// clang-format off
extern const sai_attribute_entry_t tam_transport_attribs[] = {
    {SAI_TAM_TRANSPORT_ATTR_TRANSPORT_TYPE, true, true, false, true, "TAM transport type", SAI_ATTR_VAL_TYPE_U32},
    {SAI_TAM_TRANSPORT_ATTR_SRC_PORT, false, true, true, true, "TAM transport source port", SAI_ATTR_VAL_TYPE_U32},
    {SAI_TAM_TRANSPORT_ATTR_DST_PORT, false, true, true, true, "TAM transport destination port", SAI_ATTR_VAL_TYPE_U32},
    {SAI_TAM_TRANSPORT_ATTR_TRANSPORT_AUTH_TYPE, false, true, true, true, "TAM transport authentication type", SAI_ATTR_VAL_TYPE_U32},
    {SAI_TAM_TRANSPORT_ATTR_MTU, false, true, true, true, "TAM transport MTU", SAI_ATTR_VAL_TYPE_U32},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t tam_transport_vendor_attribs[] = {
    {SAI_TAM_TRANSPORT_ATTR_TRANSPORT_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     tam_transport_type_get, nullptr, nullptr, nullptr},

    {SAI_TAM_TRANSPORT_ATTR_SRC_PORT,
     {true, false, true, true},
     {true, false, true, true},
     tam_transport_src_port_get, nullptr, tam_transport_src_port_set, nullptr},

    {SAI_TAM_TRANSPORT_ATTR_DST_PORT,
     {true, false, true, true},
     {true, false, true, true},
     tam_transport_dst_port_get, nullptr, tam_transport_dst_port_set, nullptr},

    {SAI_TAM_TRANSPORT_ATTR_TRANSPORT_AUTH_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     tam_transport_auth_get, nullptr, tam_transport_dst_port_set, nullptr},

    {SAI_TAM_TRANSPORT_ATTR_MTU,
     {true, false, true, true},
     {true, false, true, true},
     tam_transport_mtu_get, nullptr, tam_transport_dst_port_set, nullptr},
};

extern const sai_attribute_entry_t tam_collector_attribs[] = {
    {SAI_TAM_COLLECTOR_ATTR_SRC_IP, false, true, true, true, "TAM collector source IP address", SAI_ATTR_VAL_TYPE_IPADDR},
    {SAI_TAM_COLLECTOR_ATTR_DST_IP, false, true, true, true, "TAM collector destination IP address", SAI_ATTR_VAL_TYPE_IPADDR},
    {SAI_TAM_COLLECTOR_ATTR_LOCALHOST, false, true, true, true, "TAM collector destination local CPU", SAI_ATTR_VAL_TYPE_BOOL},
    {SAI_TAM_COLLECTOR_ATTR_VIRTUAL_ROUTER_ID, false, true, true, true, "TAM collector virtual Router ID", SAI_ATTR_VAL_TYPE_OID},
    {SAI_TAM_COLLECTOR_ATTR_TRUNCATE_SIZE, false, true, true, true, "TAM collector report truncate size", SAI_ATTR_VAL_TYPE_U16},
    {SAI_TAM_COLLECTOR_ATTR_TRANSPORT, true, true, true, true, "TAM collector transport object", SAI_ATTR_VAL_TYPE_OID},
    {SAI_TAM_COLLECTOR_ATTR_DSCP_VALUE, false, true, true, true, "TAM collector DSCP", SAI_ATTR_VAL_TYPE_U8},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t tam_collector_vendor_attribs[] = {
    {SAI_TAM_COLLECTOR_ATTR_SRC_IP,
     {true, false, true, true},
     {true, false, true, true},
     tam_collector_src_ip_get, nullptr, tam_collector_src_ip_set, nullptr},

    {SAI_TAM_COLLECTOR_ATTR_DST_IP,
     {true, false, true, true},
     {true, false, true, true},
     tam_collector_dst_ip_get, nullptr, tam_collector_dst_ip_set, nullptr},

    {SAI_TAM_COLLECTOR_ATTR_LOCALHOST,
     {true, false, false, true},
     {true, false, false, true},
     tam_collector_localhost_get, nullptr, tam_collector_localhost_set, nullptr},

    {SAI_TAM_COLLECTOR_ATTR_VIRTUAL_ROUTER_ID,
     {false, false, false, false},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    {SAI_TAM_COLLECTOR_ATTR_TRUNCATE_SIZE,
     {false, false, false, false},
     {false, false, false, false},
     nullptr, nullptr, nullptr, nullptr},

    {SAI_TAM_COLLECTOR_ATTR_TRANSPORT,
     {true, false, true, true},
     {true, false, true, true},
     tam_collector_transport_get, nullptr, tam_collector_transport_set, nullptr},

    {SAI_TAM_COLLECTOR_ATTR_DSCP_VALUE,
     {true, false, false, true},
     {true, false, true, true},
     tam_collector_dscp_get, nullptr, tam_collector_dscp_set, nullptr},
};

extern const sai_attribute_entry_t tam_report_attribs[] = {
    {SAI_TAM_REPORT_ATTR_TYPE, true, true, true, true, "TAM report type", SAI_ATTR_VAL_TYPE_U32},
    {SAI_TAM_REPORT_ATTR_REPORT_MODE, false, true, false, true, "TAM report mode", SAI_ATTR_VAL_TYPE_U32},
    {SAI_TAM_REPORT_ATTR_REPORT_INTERVAL, false, true, true, true, "TAM report interval in micro second", SAI_ATTR_VAL_TYPE_U32},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t tam_report_vendor_attribs[] = {
    {SAI_TAM_REPORT_ATTR_TYPE,
     {true, false, true, true},
     {true, false, true, true},
     tam_report_type_get, nullptr, tam_report_type_set, nullptr},

    {SAI_TAM_REPORT_ATTR_REPORT_MODE,
     {true, false, false, true},
     {true, false, false, true},
     tam_report_mode_get, nullptr, nullptr, nullptr},

    {SAI_TAM_REPORT_ATTR_REPORT_INTERVAL,
     {true, false, true, true},
     {true, false, true, true},
     tam_report_interval_get, nullptr, tam_report_interval_set, nullptr},
};

extern const sai_attribute_entry_t tam_event_action_attribs[] = {
    {SAI_TAM_EVENT_ACTION_ATTR_REPORT_TYPE, true, true, true, true, "TAM Event Action Report Object ID", SAI_ATTR_VAL_TYPE_OID},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t tam_event_action_vendor_attribs[] = {
    {SAI_TAM_EVENT_ACTION_ATTR_REPORT_TYPE,
     {true, false, true, true},
     {true, false, true, true},
     tam_event_action_report_id_get, nullptr, tam_event_action_report_id_set, nullptr},
};

extern const sai_attribute_entry_t tam_event_attribs[] = {
    {SAI_TAM_EVENT_ATTR_TYPE, true, true, false, true, "TAM Event Type", SAI_ATTR_VAL_TYPE_U32},
    {SAI_TAM_EVENT_ATTR_ACTION_LIST, true, true, false, true, "TAM Event Action object list ", SAI_ATTR_VAL_TYPE_OBJLIST},
    {SAI_TAM_EVENT_ATTR_COLLECTOR_LIST, true, true, false, true, "TAM Event Collector object list ", SAI_ATTR_VAL_TYPE_OBJLIST},
    {SAI_TAM_EVENT_ATTR_SWITCH_EVENT_TYPE, false, true, true, true, "TAM Event's Swtich Event Type", SAI_ATTR_VAL_TYPE_S32LIST},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t tam_event_vendor_attribs[] = {
    {SAI_TAM_EVENT_ATTR_TYPE,
     {true, false, false, true},
     {true, false, false, true},
     tam_event_type_get, nullptr, nullptr, nullptr},

    {SAI_TAM_EVENT_ATTR_ACTION_LIST,
     {true, false, false, true},
     {true, false, false, true},
     tam_event_action_list_get, nullptr, nullptr, nullptr},

    {SAI_TAM_EVENT_ATTR_COLLECTOR_LIST,
     {true, false, false, true},
     {true, false, false, true},
     tam_event_collect_list_get, nullptr, nullptr, nullptr},

    {SAI_TAM_EVENT_ATTR_SWITCH_EVENT_TYPE,
     {true, false, true, true},
     {true, false, true, true},
     tam_switch_event_type_get, nullptr, tam_switch_event_type_set, nullptr},
};

extern const sai_attribute_entry_t tam_attribs[] = {
    {SAI_TAM_ATTR_EVENT_OBJECTS_LIST, false, true, true, true, "TAM Event Object List", SAI_ATTR_VAL_TYPE_OBJLIST},
    {SAI_TAM_ATTR_TAM_BIND_POINT_TYPE_LIST, false, true, false, true, "TAM Bind Point Type List", SAI_ATTR_VAL_TYPE_S32LIST},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t tam_vendor_attribs[] = {
    {SAI_TAM_ATTR_EVENT_OBJECTS_LIST,
     {true, false, true, true},
     {true, false, true, true},
     tam_event_objects_list_get, nullptr, tam_event_objects_list_set, nullptr},

    {SAI_TAM_ATTR_TAM_BIND_POINT_TYPE_LIST,
     {true, false, false, true},
     {true, false, false, true},
     tam_bind_point_list_get, nullptr, nullptr, nullptr},
};

// clang-format on

static sai_status_t
tam_transport_type_get(_In_ const sai_object_key_t* key,
                       _Inout_ sai_attribute_value_t* value,
                       _In_ uint32_t attr_index,
                       _Inout_ vendor_cache_t* cache,
                       void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_transport_obj(key->key.object_id);
    auto sdev = tam_transport_obj.get_device();

    lsai_tam_transport_entry_ptr transport_ptr;
    la_status status = sdev->m_tam_transport.get(tam_transport_obj.index, transport_ptr);
    sai_return_on_la_error(status, "Failed to find tam_transport_entry for object (0x%lx)", key->key.object_id);

    set_attr_value(SAI_TAM_TRANSPORT_ATTR_TRANSPORT_TYPE, *value, transport_ptr->m_type);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_transport_src_port_get(_In_ const sai_object_key_t* key,
                           _Inout_ sai_attribute_value_t* value,
                           _In_ uint32_t attr_index,
                           _Inout_ vendor_cache_t* cache,
                           void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_transport_obj(key->key.object_id);
    auto sdev = tam_transport_obj.get_device();

    lsai_tam_transport_entry_ptr transport_ptr;
    la_status status = sdev->m_tam_transport.get(tam_transport_obj.index, transport_ptr);
    sai_return_on_la_error(status, "Failed to find tam_transport_entry for object (0x%lx)", key->key.object_id);

    set_attr_value(SAI_TAM_TRANSPORT_ATTR_SRC_PORT, *value, transport_ptr->m_src_port);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_transport_src_port_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_transport_obj(key->key.object_id);
    auto sdev = tam_transport_obj.get_device();

    lsai_tam_transport_entry_ptr transport_ptr;
    la_status status = sdev->m_tam_transport.get(tam_transport_obj.index, transport_ptr);
    sai_return_on_la_error(status, "Failed to find tam_transport_entry for object (0x%lx)", key->key.object_id);

    transport_ptr->m_src_port = get_attr_value(SAI_TAM_TRANSPORT_ATTR_SRC_PORT, (*value));

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_transport_dst_port_get(_In_ const sai_object_key_t* key,
                           _Inout_ sai_attribute_value_t* value,
                           _In_ uint32_t attr_index,
                           _Inout_ vendor_cache_t* cache,
                           void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_transport_obj(key->key.object_id);
    auto sdev = tam_transport_obj.get_device();

    lsai_tam_transport_entry_ptr transport_ptr;
    la_status status = sdev->m_tam_transport.get(tam_transport_obj.index, transport_ptr);
    sai_return_on_la_error(status, "Failed to find tam_transport_entry for object (0x%lx)", key->key.object_id);

    set_attr_value(SAI_TAM_TRANSPORT_ATTR_DST_PORT, *value, transport_ptr->m_dst_port);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_transport_dst_port_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_transport_obj(key->key.object_id);
    auto sdev = tam_transport_obj.get_device();

    lsai_tam_transport_entry_ptr transport_ptr;
    la_status status = sdev->m_tam_transport.get(tam_transport_obj.index, transport_ptr);
    sai_return_on_la_error(status, "Failed to find tam_transport_entry for object (0x%lx)", key->key.object_id);

    transport_ptr->m_dst_port = get_attr_value(SAI_TAM_TRANSPORT_ATTR_DST_PORT, (*value));

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_transport_mtu_get(_In_ const sai_object_key_t* key,
                      _Inout_ sai_attribute_value_t* value,
                      _In_ uint32_t attr_index,
                      _Inout_ vendor_cache_t* cache,
                      void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_transport_obj(key->key.object_id);
    auto sdev = tam_transport_obj.get_device();

    lsai_tam_transport_entry_ptr transport_ptr;
    la_status status = sdev->m_tam_transport.get(tam_transport_obj.index, transport_ptr);
    sai_return_on_la_error(status, "Failed to find tam_transport_entry for object (0x%lx)", key->key.object_id);

    set_attr_value(SAI_TAM_TRANSPORT_ATTR_MTU, *value, transport_ptr->m_mtu);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_transport_mtu_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_transport_obj(key->key.object_id);
    auto sdev = tam_transport_obj.get_device();

    lsai_tam_transport_entry_ptr transport_ptr;
    la_status status = sdev->m_tam_transport.get(tam_transport_obj.index, transport_ptr);
    sai_return_on_la_error(status, "Failed to find tam_transport_entry for object (0x%lx)", key->key.object_id);

    transport_ptr->m_mtu = get_attr_value(SAI_TAM_TRANSPORT_ATTR_MTU, (*value));

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_transport_auth_get(_In_ const sai_object_key_t* key,
                       _Inout_ sai_attribute_value_t* value,
                       _In_ uint32_t attr_index,
                       _Inout_ vendor_cache_t* cache,
                       void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_transport_obj(key->key.object_id);
    auto sdev = tam_transport_obj.get_device();

    lsai_tam_transport_entry_ptr transport_ptr;
    la_status status = sdev->m_tam_transport.get(tam_transport_obj.index, transport_ptr);
    sai_return_on_la_error(status, "Failed to find tam_transport_entry for object (0x%lx)", key->key.object_id);

    set_attr_value(SAI_TAM_TRANSPORT_ATTR_TRANSPORT_AUTH_TYPE, *value, transport_ptr->m_auth);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_transport_auth_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_transport_obj(key->key.object_id);
    auto sdev = tam_transport_obj.get_device();

    lsai_tam_transport_entry_ptr transport_ptr;
    la_status status = sdev->m_tam_transport.get(tam_transport_obj.index, transport_ptr);
    sai_return_on_la_error(status, "Failed to find tam_transport_entry for object (0x%lx)", key->key.object_id);

    sai_tam_transport_auth_type_t auth = get_attr_value(SAI_TAM_TRANSPORT_ATTR_TRANSPORT_AUTH_TYPE, (*value));
    if (auth != SAI_TAM_TRANSPORT_AUTH_TYPE_NONE) {
        sai_return_on_error(SAI_STATUS_NOT_IMPLEMENTED,
                            "Only support SAI_TAM_TRANSPORT_AUTH_TYPE_NONE at this moment. Invalid transport auth type %u.",
                            auth);
    }
    transport_ptr->m_auth = auth;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_collector_src_ip_get(_In_ const sai_object_key_t* key,
                         _Inout_ sai_attribute_value_t* value,
                         _In_ uint32_t attr_index,
                         _Inout_ vendor_cache_t* cache,
                         void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_collector_obj(key->key.object_id);
    auto sdev = tam_collector_obj.get_device();

    lsai_tam_collector_entry_ptr collector_ptr;
    la_status status = sdev->m_tam_collector.get(tam_collector_obj.index, collector_ptr);
    sai_return_on_la_error(status, "Failed to find tam_collector_entry for object (0x%lx)", key->key.object_id);

    set_attr_value(SAI_TAM_COLLECTOR_ATTR_SRC_IP, *value, collector_ptr->m_src_ip);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_collector_src_ip_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_collector_obj(key->key.object_id);
    auto sdev = tam_collector_obj.get_device();

    lsai_tam_collector_entry_ptr collector_ptr;
    la_status status = sdev->m_tam_collector.get(tam_collector_obj.index, collector_ptr);
    sai_return_on_la_error(status, "Failed to find tam_collector_entry for object (0x%lx)", key->key.object_id);

    collector_ptr->m_src_ip = get_attr_value(SAI_TAM_COLLECTOR_ATTR_SRC_IP, (*value));

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_collector_dst_ip_get(_In_ const sai_object_key_t* key,
                         _Inout_ sai_attribute_value_t* value,
                         _In_ uint32_t attr_index,
                         _Inout_ vendor_cache_t* cache,
                         void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_collector_obj(key->key.object_id);
    auto sdev = tam_collector_obj.get_device();

    lsai_tam_collector_entry_ptr collector_ptr;
    la_status status = sdev->m_tam_collector.get(tam_collector_obj.index, collector_ptr);
    sai_return_on_la_error(status, "Failed to find tam_collector_entry for object (0x%lx)", key->key.object_id);

    set_attr_value(SAI_TAM_COLLECTOR_ATTR_DST_IP, *value, collector_ptr->m_dst_ip);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_collector_dst_ip_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_collector_obj(key->key.object_id);
    auto sdev = tam_collector_obj.get_device();

    lsai_tam_collector_entry_ptr collector_ptr;
    la_status status = sdev->m_tam_collector.get(tam_collector_obj.index, collector_ptr);
    sai_return_on_la_error(status, "Failed to find tam_collector_entry for object (0x%lx)", key->key.object_id);

    collector_ptr->m_dst_ip = get_attr_value(SAI_TAM_COLLECTOR_ATTR_DST_IP, (*value));

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_collector_localhost_get(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_collector_obj(key->key.object_id);
    auto sdev = tam_collector_obj.get_device();

    lsai_tam_collector_entry_ptr collector_ptr;
    la_status status = sdev->m_tam_collector.get(tam_collector_obj.index, collector_ptr);
    sai_return_on_la_error(status, "Failed to find tam_collector_entry for object (0x%lx)", key->key.object_id);

    set_attr_value(SAI_TAM_COLLECTOR_ATTR_LOCALHOST, *value, collector_ptr->m_localhost);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_collector_localhost_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_collector_obj(key->key.object_id);
    auto sdev = tam_collector_obj.get_device();

    lsai_tam_collector_entry_ptr collector_ptr;
    la_status status = sdev->m_tam_collector.get(tam_collector_obj.index, collector_ptr);
    sai_return_on_la_error(status, "Failed to find tam_collector_entry for object (0x%lx)", key->key.object_id);

    collector_ptr->m_localhost = get_attr_value(SAI_TAM_COLLECTOR_ATTR_LOCALHOST, (*value));

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_collector_transport_get(_In_ const sai_object_key_t* key,
                            _Inout_ sai_attribute_value_t* value,
                            _In_ uint32_t attr_index,
                            _Inout_ vendor_cache_t* cache,
                            void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_collector_obj(key->key.object_id);
    auto sdev = tam_collector_obj.get_device();

    lsai_tam_collector_entry_ptr collector_ptr;
    la_status status = sdev->m_tam_collector.get(tam_collector_obj.index, collector_ptr);
    sai_return_on_la_error(status, "Failed to find tam_collector_entry for object (0x%lx)", key->key.object_id);

    // check if bound to a transport
    if (collector_ptr->m_transport == nullptr) {
        set_attr_value(SAI_TAM_EVENT_ACTION_ATTR_REPORT_TYPE, *value, SAI_NULL_OBJECT_ID);
        sai_log_debug(SAI_API_TAM, "tam_collector object (0x%lx) is not bound to a tam_transport object.", key->key.object_id);
        return SAI_STATUS_SUCCESS;
    }

    set_attr_value(SAI_TAM_COLLECTOR_ATTR_TRANSPORT, *value, collector_ptr->m_transport->m_oid);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_collector_transport_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_collector_obj(key->key.object_id);
    auto sdev = tam_collector_obj.get_device();

    lsai_tam_collector_entry_ptr collector_ptr;
    la_status status = sdev->m_tam_collector.get(tam_collector_obj.index, collector_ptr);
    sai_return_on_la_error(status, "Failed to find tam_collector_entry for object (0x%lx)", key->key.object_id);

    // check transport object ID and entry
    auto transport_id = get_attr_value(SAI_TAM_COLLECTOR_ATTR_TRANSPORT, (*value));

    lsai_object transport_obj(transport_id);
    lsai_tam_transport_entry_ptr transport_ptr;
    status = sdev->m_tam_transport.get(transport_obj.index, transport_ptr);
    sai_return_on_la_error(status, "Failed to find tam transport object, 0x%lx in database.", transport_id);

    // bind the tam transport object
    status = collector_ptr->bind_transport(transport_ptr);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_collector_dscp_get(_In_ const sai_object_key_t* key,
                       _Inout_ sai_attribute_value_t* value,
                       _In_ uint32_t attr_index,
                       _Inout_ vendor_cache_t* cache,
                       void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_collector_obj(key->key.object_id);
    auto sdev = tam_collector_obj.get_device();

    lsai_tam_collector_entry_ptr collector_ptr;
    la_status status = sdev->m_tam_collector.get(tam_collector_obj.index, collector_ptr);
    sai_return_on_la_error(status, "Failed to find tam_collector_entry for object (0x%lx)", key->key.object_id);

    set_attr_value(SAI_TAM_COLLECTOR_ATTR_DSCP_VALUE, *value, collector_ptr->m_dscp);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_collector_dscp_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_collector_obj(key->key.object_id);
    auto sdev = tam_collector_obj.get_device();

    lsai_tam_collector_entry_ptr collector_ptr;
    la_status status = sdev->m_tam_collector.get(tam_collector_obj.index, collector_ptr);
    sai_return_on_la_error(status, "Failed to find tam_collector_entry for object (0x%lx)", key->key.object_id);

    collector_ptr->m_dscp = get_attr_value(SAI_TAM_COLLECTOR_ATTR_DSCP_VALUE, (*value));

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_report_type_get(_In_ const sai_object_key_t* key,
                    _Inout_ sai_attribute_value_t* value,
                    _In_ uint32_t attr_index,
                    _Inout_ vendor_cache_t* cache,
                    void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_report_obj(key->key.object_id);
    auto sdev = tam_report_obj.get_device();

    lsai_tam_report_entry_ptr report_ptr;
    la_status status = sdev->m_tam_report.get(tam_report_obj.index, report_ptr);
    sai_return_on_la_error(status, "Failed to find tam_report_entry for object (0x%lx)", key->key.object_id);

    set_attr_value(SAI_TAM_REPORT_ATTR_TYPE, *value, report_ptr->m_type);

    return SAI_STATUS_SUCCESS;
}

static bool
tam_report_type_supported(_In_ sai_tam_report_type_t report_type)
{
    switch (report_type) {
    case SAI_TAM_REPORT_TYPE_JSON:
    case SAI_TAM_REPORT_TYPE_VENDOR_EXTN:
        return true;
    default:
        return false;
    }
}

static sai_status_t
tam_report_type_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_report_obj(key->key.object_id);
    auto sdev = tam_report_obj.get_device();

    lsai_tam_report_entry_ptr report_ptr;
    la_status status = sdev->m_tam_report.get(tam_report_obj.index, report_ptr);
    sai_return_on_la_error(status, "Failed to find tam_report_entry for object (0x%lx)", key->key.object_id);

    sai_tam_report_type_t report_type = get_attr_value(SAI_TAM_REPORT_ATTR_TYPE, (*value));
    if (!tam_report_type_supported(report_type)) {
        sai_return_on_error(SAI_STATUS_NOT_IMPLEMENTED, "SAI_TAM_REPORT_TYPE_(%d) is not supported.", report_type);
    }

    status = report_ptr->set_type(report_type);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_report_mode_get(_In_ const sai_object_key_t* key,
                    _Inout_ sai_attribute_value_t* value,
                    _In_ uint32_t attr_index,
                    _Inout_ vendor_cache_t* cache,
                    void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_report_obj(key->key.object_id);
    auto sdev = tam_report_obj.get_device();

    lsai_tam_report_entry_ptr report_ptr;
    la_status status = sdev->m_tam_report.get(tam_report_obj.index, report_ptr);
    sai_return_on_la_error(status, "Failed to find tam_report_entry for object (0x%lx)", key->key.object_id);

    set_attr_value(SAI_TAM_REPORT_ATTR_REPORT_MODE, *value, report_ptr->m_mode);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_report_interval_get(_In_ const sai_object_key_t* key,
                        _Inout_ sai_attribute_value_t* value,
                        _In_ uint32_t attr_index,
                        _Inout_ vendor_cache_t* cache,
                        void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_report_obj(key->key.object_id);
    auto sdev = tam_report_obj.get_device();

    lsai_tam_report_entry_ptr report_ptr;
    la_status status = sdev->m_tam_report.get(tam_report_obj.index, report_ptr);
    sai_return_on_la_error(status, "Failed to find tam_report_entry for object (0x%lx)", key->key.object_id);

    set_attr_value(SAI_TAM_REPORT_ATTR_REPORT_INTERVAL, *value, report_ptr->m_interval);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_report_interval_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_report_obj(key->key.object_id);
    auto sdev = tam_report_obj.get_device();

    lsai_tam_report_entry_ptr report_ptr;
    la_status status = sdev->m_tam_report.get(tam_report_obj.index, report_ptr);
    sai_return_on_la_error(status, "Failed to find tam_report_entry for object (0x%lx)", key->key.object_id);

    sai_uint32_t interval = get_attr_value(SAI_TAM_REPORT_ATTR_REPORT_INTERVAL, (*value));
    status = report_ptr->set_interval(interval);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_event_action_report_id_get(_In_ const sai_object_key_t* key,
                               _Inout_ sai_attribute_value_t* value,
                               _In_ uint32_t attr_index,
                               _Inout_ vendor_cache_t* cache,
                               void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object event_action_obj(key->key.object_id);
    auto sdev = event_action_obj.get_device();

    lsai_tam_event_action_entry_ptr event_action_ptr;
    la_status status = sdev->m_tam_event_action.get(event_action_obj.index, event_action_ptr);
    sai_return_on_la_error(status, "Failed to find tam_event_action_entry for object (0x%lx)", key->key.object_id);

    // check if bound to a reporter
    if (event_action_ptr->m_reporter == nullptr) {
        set_attr_value(SAI_TAM_EVENT_ACTION_ATTR_REPORT_TYPE, *value, SAI_NULL_OBJECT_ID);
        sai_log_debug(SAI_API_TAM, "tam_event_action object (0x%lx) is not bound to a tam_report object.", key->key.object_id);
        return SAI_STATUS_SUCCESS;
    }

    set_attr_value(SAI_TAM_EVENT_ACTION_ATTR_REPORT_TYPE, *value, event_action_ptr->m_reporter->m_oid);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_event_action_report_id_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object event_action_obj(key->key.object_id);
    auto sdev = event_action_obj.get_device();

    // check event_action object ID and entry
    lsai_tam_event_action_entry_ptr event_action_ptr;
    la_status status = sdev->m_tam_event_action.get(event_action_obj.index, event_action_ptr);
    sai_return_on_la_error(status, "Failed to find tam_event_action_entry for object (0x%lx)", key->key.object_id);

    // check reporter object ID and entry
    auto reporter_id = get_attr_value(SAI_TAM_EVENT_ACTION_ATTR_REPORT_TYPE, (*value));

    lsai_object reporter_obj(reporter_id);
    lsai_tam_report_entry_ptr reporter_ptr;
    status = sdev->m_tam_report.get(reporter_obj.index, reporter_ptr);
    sai_return_on_la_error(status, "Failed to find tam report object, 0x%lx in database.", reporter_id);

    // bind the tam report object
    status = event_action_ptr->bind_reporter(reporter_ptr);
    sai_return_on_la_error(status);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_event_type_get(_In_ const sai_object_key_t* key,
                   _Inout_ sai_attribute_value_t* value,
                   _In_ uint32_t attr_index,
                   _Inout_ vendor_cache_t* cache,
                   void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object event_obj(key->key.object_id);
    auto sdev = event_obj.get_device();

    lsai_tam_event_entry_ptr event_ptr;
    la_status status = sdev->m_tam_event.get(event_obj.index, event_ptr);
    sai_return_on_la_error(status, "Failed to find tam_event_entry for object (0x%lx)", key->key.object_id);

    set_attr_value(SAI_TAM_EVENT_ATTR_TYPE, *value, event_ptr->m_type);

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_event_action_list_get(_In_ const sai_object_key_t* key,
                          _Inout_ sai_attribute_value_t* value,
                          _In_ uint32_t attr_index,
                          _Inout_ vendor_cache_t* cache,
                          void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object event_obj(key->key.object_id);
    auto sdev = event_obj.get_device();

    lsai_tam_event_entry_ptr event_ptr;
    la_status status = sdev->m_tam_event.get(event_obj.index, event_ptr);
    sai_return_on_la_error(status, "Failed to find tam_event_entry for object (0x%lx)", key->key.object_id);

    return fill_sai_list(event_ptr->m_event_action_list.begin(),
                         event_ptr->m_event_action_list.end(),
                         value->objlist,
                         [](lsai_tam_event_action_entry_ptr i) { return i->m_oid; });
}

static sai_status_t
tam_event_collect_list_get(_In_ const sai_object_key_t* key,
                           _Inout_ sai_attribute_value_t* value,
                           _In_ uint32_t attr_index,
                           _Inout_ vendor_cache_t* cache,
                           void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object event_obj(key->key.object_id);
    auto sdev = event_obj.get_device();

    lsai_tam_event_entry_ptr event_ptr;
    la_status status = sdev->m_tam_event.get(event_obj.index, event_ptr);
    sai_return_on_la_error(status, "Failed to find tam_event_entry for object (0x%lx)", key->key.object_id);

    return fill_sai_list(event_ptr->m_collector_list.begin(),
                         event_ptr->m_collector_list.end(),
                         value->objlist,
                         [](lsai_tam_collector_entry_ptr i) { return i->m_oid; });
}

static sai_status_t
tam_switch_event_type_get(_In_ const sai_object_key_t* key,
                          _Inout_ sai_attribute_value_t* value,
                          _In_ uint32_t attr_index,
                          _Inout_ vendor_cache_t* cache,
                          void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object event_obj(key->key.object_id);
    auto sdev = event_obj.get_device();

    lsai_tam_event_entry_ptr event_ptr;
    la_status status = sdev->m_tam_event.get(event_obj.index, event_ptr);
    sai_return_on_la_error(status, "Failed to find tam_event_entry for object (0x%lx)", key->key.object_id);

    if (event_ptr->m_type != SAI_TAM_EVENT_TYPE_SWITCH) {
        sai_return_on_error(SAI_STATUS_INVALID_PARAMETER,
                            "tam_event type (%d) is not SAI_TAM_EVENT_TYPE_SWITCH, and SAI_TAM_EVENT_ATTR_SWITCH_EVENT_TYPE "
                            "attribute becomes invalid.",
                            (int)(event_ptr->m_type));
    }

    sai_log_debug(SAI_API_TAM,
                  "tam_switch_event_type_get:tam_event (0x%lx) switch_event_type: %s",
                  event_ptr->m_oid,
                  to_string(event_ptr->m_switch_event_types.begin(),
                            event_ptr->m_switch_event_types.end(),
                            [](std::vector<sai_switch_event_type_t>::iterator i) { return *i; })
                      .c_str());

    return fill_sai_list(event_ptr->m_switch_event_types.begin(), event_ptr->m_switch_event_types.end(), value->s32list);
}

static sai_status_t
tam_switch_event_type_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    // only for SAI_TAM_EVENT_ATTR_TYPE == SAI_TAM_EVENT_TYPE_SWITCH
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object event_obj(key->key.object_id);
    auto sdev = event_obj.get_device();

    lsai_tam_event_entry_ptr event_ptr;
    la_status status = sdev->m_tam_event.get(event_obj.index, event_ptr);
    sai_return_on_la_error(status, "Failed to find tam_event_entry for object (0x%lx)", key->key.object_id);

    if (event_ptr->m_type != SAI_TAM_EVENT_TYPE_SWITCH) {
        sai_return_on_error(SAI_STATUS_INVALID_PARAMETER,
                            "tam_event type (%d) is not SAI_TAM_EVENT_TYPE_SWITCH, and SAI_TAM_EVENT_ATTR_SWITCH_EVENT_TYPE "
                            "attribute becomes invalid.",
                            (int)(event_ptr->m_type));
    }

    auto switch_event_type_list = get_attr_value(SAI_TAM_EVENT_ATTR_SWITCH_EVENT_TYPE, (*value));

    if (switch_event_type_list.count == 0) {
        sai_log_debug(SAI_API_TAM, "Clearing switch event type list.");
        event_ptr->m_switch_event_types.clear();
        return SAI_STATUS_SUCCESS;
    }

    event_ptr->m_switch_event_types.assign((sai_switch_event_type_t*)(switch_event_type_list.list),
                                           (sai_switch_event_type_t*)(switch_event_type_list.list + switch_event_type_list.count));

    sai_log_debug(SAI_API_TAM,
                  "tam_switch_event_type_set:tam_event (0x%lx) switch_event_type: %s",
                  event_ptr->m_oid,
                  to_string(event_ptr->m_switch_event_types.begin(),
                            event_ptr->m_switch_event_types.end(),
                            [](std::vector<sai_switch_event_type_t>::iterator i) { return *i; })
                      .c_str());

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
tam_event_objects_list_get(_In_ const sai_object_key_t* key,
                           _Inout_ sai_attribute_value_t* value,
                           _In_ uint32_t attr_index,
                           _Inout_ vendor_cache_t* cache,
                           void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_obj(key->key.object_id);
    auto sdev = tam_obj.get_device();

    lsai_tam_entry_ptr tam_ptr;
    la_status status = sdev->m_tam.get(tam_obj.index, tam_ptr);
    sai_return_on_la_error(status, "Failed to find tam_entry for object (0x%lx)", key->key.object_id);

    sai_log_debug(SAI_API_TAM,
                  "m_tam_events: %s",
                  to_string(tam_ptr->m_tam_events.begin(),
                            tam_ptr->m_tam_events.end(),
                            [](std::vector<silicon_one::sai::lsai_tam_event_entry_ptr>::iterator i) { return (*i)->m_oid; })
                      .c_str());

    return fill_sai_list(tam_ptr->m_tam_events.begin(),
                         tam_ptr->m_tam_events.end(),
                         value->objlist,
                         [](lsai_tam_event_entry_ptr i) { return i->m_oid; });
}

static sai_status_t
tam_bind_point_list_get(_In_ const sai_object_key_t* key,
                        _Inout_ sai_attribute_value_t* value,
                        _In_ uint32_t attr_index,
                        _Inout_ vendor_cache_t* cache,
                        void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_obj(key->key.object_id);
    auto sdev = tam_obj.get_device();

    lsai_tam_entry_ptr tam_ptr;
    la_status status = sdev->m_tam.get(tam_obj.index, tam_ptr);
    sai_return_on_la_error(status, "Failed to find tam_entry for object (0x%lx)", key->key.object_id);

    return fill_sai_list(tam_ptr->m_bind_point_types.begin(), tam_ptr->m_bind_point_types.end(), value->s32list);
}

static sai_status_t
tam_event_objects_list_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{
    if (key == nullptr || value == nullptr) {
        return SAI_STATUS_INVALID_PARAMETER;
    }

    lsai_object tam_obj(key->key.object_id);
    auto sdev = tam_obj.get_device();

    lsai_tam_entry_ptr tam_ptr;
    la_status status = sdev->m_tam.get(tam_obj.index, tam_ptr);
    sai_return_on_la_error(status, "Failed to find tam_entry for object (0x%lx)", key->key.object_id);

    auto event_list = get_attr_value(SAI_TAM_ATTR_EVENT_OBJECTS_LIST, (*value));

    // check event_action object
    std::vector<lsai_tam_event_entry_ptr> tam_event_vec;
    auto sai_status = check_object_id_list(tam_event_vec, SAI_OBJECT_TYPE_TAM_EVENT, sdev, sdev->m_tam_event, event_list);
    sai_return_on_error(sai_status);

    sai_log_debug(SAI_API_TAM, "tam_event_objects_list_set unregister all tam_events.");

    status = tam_ptr->remove_all_registries();
    sai_return_on_la_error(status, "Fail to remove registries, tam_object(0x%lx).", tam_ptr->m_oid);

    for (auto event_ptr : tam_event_vec) {
        status = tam_ptr->register_tam_event(event_ptr);
        sai_return_on_la_error(status, "Fail to register tam_event(0x%lx) to tam object(0x%lx).", event_ptr->m_oid, tam_ptr->m_oid);
    }

    return SAI_STATUS_SUCCESS;
}

///
/// Create, remove and get/set attribute functions for TAM objects
///

template <typename attr_t>
static std::string
tam_attr_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (attr_t)attr.id;

    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value) << " ";

    return log_message.str();
}

static sai_status_t
create_tam(_Out_ sai_object_id_t* tam_id,
           _In_ sai_object_id_t switch_id,
           _In_ uint32_t attr_count,
           _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_TAM, SAI_OBJECT_TYPE_SWITCH, switch_id, &tam_attr_to_string<sai_tam_attr_t>, switch_id, attrs);

    // mandatory event object list for tam creation because we only support TAM event as this moment.
    sai_object_list_t event_list{};
    get_attrs_value(SAI_TAM_ATTR_EVENT_OBJECTS_LIST, attrs, event_list, true);

    sai_s32_list_t bind_point_list{};
    get_attrs_value(SAI_TAM_ATTR_TAM_BIND_POINT_TYPE_LIST, attrs, bind_point_list, false);

    // check event_action object
    std::vector<lsai_tam_event_entry_ptr> tam_event_vec;
    auto sai_status = check_object_id_list(tam_event_vec, SAI_OBJECT_TYPE_TAM_EVENT, sdev, sdev->m_tam_event, event_list);
    sai_return_on_error(sai_status);

    sai_log_debug(SAI_API_TAM, "create_tam finished checking all attributes.");

    transaction txn;
    txn.status = LA_STATUS_SUCCESS;

    uint32_t tam_index = 0;
    txn.status = sdev->m_tam.allocate_id(tam_index);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_tam.release_id(tam_index); });

    // All attributes are correct, and we can create the object now.
    // create a lsai_tam_entry for this tam_event
    lsai_tam_entry_ptr tam_ptr = std::make_shared<lsai_tam_entry>();

    // initialize lsai_object to collect information, la_obj is the switch obj from sai_start_api()
    lsai_object tam_obj(SAI_OBJECT_TYPE_TAM, la_obj.index, tam_index);
    tam_ptr->m_oid = tam_obj.object_id();
    tam_ptr->m_sdev = sdev;
    tam_ptr->m_bind_point_types.assign((sai_tam_bind_point_type_t*)(bind_point_list.list),
                                       (sai_tam_bind_point_type_t*)(bind_point_list.list + bind_point_list.count));

    // save event entry into obj_db
    txn.status = sdev->m_tam.set(tam_index, tam_ptr);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_tam.remove(tam_index); });

    // register tam_event
    for (auto event_ptr : tam_event_vec) {
        txn.status = tam_ptr->register_tam_event(event_ptr);
        sai_return_on_la_error(txn.status);
    }

    *tam_id = tam_ptr->m_oid;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_tam(_In_ sai_object_id_t tam_id)
{
    sai_start_api(SAI_API_TAM, SAI_OBJECT_TYPE_TAM, tam_id, &tam_attr_to_string<sai_tam_attr_t>, tam_id);

    lsai_tam_entry_ptr tam_ptr;
    la_status status = sdev->m_tam.get(la_obj.index, tam_ptr);
    sai_return_on_la_error(status, "Failed to find tam_entry for object (0x%lx)", tam_id);

    status = tam_ptr->remove_all_registries();
    sai_return_on_la_error(status, "Fail to remove registries. tam object(0x%lx).", tam_id);

    status = sdev->m_tam.remove(tam_id);
    return to_sai_status(status);
}

static sai_status_t
set_tam_attribute(_In_ sai_object_id_t tam_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tam_id;

    sai_start_api(SAI_API_TAM, SAI_OBJECT_TYPE_TAM, tam_id, &tam_attr_to_string<sai_tam_attr_t>, tam_id, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "tam 0x%0lx", tam_id);
    return sai_set_attribute(&key, key_str, tam_attribs, tam_vendor_attribs, attr);
}

static sai_status_t
get_tam_attribute(_In_ sai_object_id_t tam_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tam_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_TAM, SAI_OBJECT_TYPE_TAM, tam_id, &tam_attr_to_string<sai_tam_attr_t>, tam_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "tam 0x%0lx", tam_id);
    return sai_get_attributes(&key, key_str, tam_attribs, tam_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
create_tam_math_func(_Out_ sai_object_id_t* tam_math_func_id,
                     _In_ sai_object_id_t switch_id,
                     _In_ uint32_t attr_count,
                     _In_ const sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
remove_tam_math_func(_In_ sai_object_id_t tam_math_func_id)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_tam_math_func_attribute(_In_ sai_object_id_t tam_math_func_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
set_tam_math_func_attribute(_In_ sai_object_id_t tam_math_func_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
create_tam_report(_Out_ sai_object_id_t* tam_report_id,
                  _In_ sai_object_id_t switch_id,
                  _In_ uint32_t attr_count,
                  _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_TAM, SAI_OBJECT_TYPE_SWITCH, switch_id, &tam_attr_to_string<sai_tam_report_attr_t>, switch_id, attrs);

    // mandatory attribute for tam_report creation
    sai_tam_report_type_t report_type;
    get_attrs_value(SAI_TAM_REPORT_ATTR_TYPE, attrs, report_type, true);
    if (!tam_report_type_supported(report_type)) {
        sai_return_on_error(SAI_STATUS_NOT_IMPLEMENTED, "SAI_TAM_REPORT_TYPE_(%d) is not supported.", report_type);
    }

    transaction txn;
    txn.status = LA_STATUS_SUCCESS;

    uint32_t report_idx = 0;
    txn.status = sdev->m_tam_report.allocate_id(report_idx);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_tam_report.release_id(report_idx); });

    // initialize lsai_object to collect information
    lsai_object report_obj(SAI_OBJECT_TYPE_TAM_REPORT, la_obj.index, report_idx);

    // setup the tam_report_entry
    lsai_tam_report_entry_ptr report_entry_ptr = std::make_shared<lsai_tam_report_entry>(sdev, report_obj.object_id(), report_type);
    get_attrs_value(SAI_TAM_REPORT_ATTR_REPORT_MODE, attrs, report_entry_ptr->m_mode, false);
    get_attrs_value(SAI_TAM_REPORT_ATTR_REPORT_INTERVAL, attrs, report_entry_ptr->m_interval, false);

    txn.status = sdev->m_tam_report.set(report_idx, report_entry_ptr);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_tam_report.remove(report_idx); });

    *tam_report_id = report_entry_ptr->m_oid;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_tam_report(_In_ sai_object_id_t tam_report_id)
{
    sai_start_api(
        SAI_API_TAM, SAI_OBJECT_TYPE_TAM_REPORT, tam_report_id, &tam_attr_to_string<sai_tam_report_attr_t>, tam_report_id);

    lsai_tam_report_entry_ptr report_entry_ptr;
    la_status status = sdev->m_tam_report.get(la_obj.index, report_entry_ptr);
    sai_return_on_la_error(status, "Failed to find tam_report_entry for object (0x%lx)", tam_report_id);

    // Make sure reporter buffer is empty before remove.
    status = report_entry_ptr->flush();
    sai_return_on_la_error(status, "Fail to flush tam_report_entry buffer. (0x%lx)", tam_report_id);

    status = sdev->m_tam_report.remove(tam_report_id);
    return to_sai_status(status);
}

static sai_status_t
get_tam_report_attribute(_In_ sai_object_id_t tam_report_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tam_report_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_TAM, SAI_OBJECT_TYPE_TAM_REPORT, tam_report_id, &tam_attr_to_string<sai_tam_report_attr_t>, tam_report_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "tam_report 0x%0lx", tam_report_id);
    return sai_get_attributes(&key, key_str, tam_report_attribs, tam_report_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
set_tam_report_attribute(_In_ sai_object_id_t tam_report_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tam_report_id;

    sai_start_api(
        SAI_API_TAM, SAI_OBJECT_TYPE_TAM_REPORT, tam_report_id, &tam_attr_to_string<sai_tam_report_attr_t>, tam_report_id, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "tam_report 0x%0lx", tam_report_id);
    return sai_set_attribute(&key, key_str, tam_report_attribs, tam_report_vendor_attribs, attr);
}

static sai_status_t
create_tam_event_threshold(_Out_ sai_object_id_t* tam_event_threshold_id,
                           _In_ sai_object_id_t switch_id,
                           _In_ uint32_t attr_count,
                           _In_ const sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
remove_tam_event_threshold(_In_ sai_object_id_t tam_event_threshold_id)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_tam_event_threshold_attribute(_In_ sai_object_id_t tam_event_threshold_id,
                                  _In_ uint32_t attr_count,
                                  _Inout_ sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
set_tam_event_threshold_attribute(_In_ sai_object_id_t tam_event_threshold_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
create_tam_int(_Out_ sai_object_id_t* tam_int_id,
               _In_ sai_object_id_t switch_id,
               _In_ uint32_t attr_count,
               _In_ const sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
remove_tam_int(_In_ sai_object_id_t tam_int_id)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_tam_int_attribute(_In_ sai_object_id_t tam_int_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
set_tam_int_attribute(_In_ sai_object_id_t tam_int_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
create_tam_tel_type(_Out_ sai_object_id_t* tam_tel_type_id,
                    _In_ sai_object_id_t switch_id,
                    _In_ uint32_t attr_count,
                    _In_ const sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
remove_tam_tel_type(_In_ sai_object_id_t tam_tel_type_id)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_tam_tel_type_attribute(_In_ sai_object_id_t tam_tel_type_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
set_tam_tel_type_attribute(_In_ sai_object_id_t tam_tel_type_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
create_tam_transport(_Out_ sai_object_id_t* tam_transport_id,
                     _In_ sai_object_id_t switch_id,
                     _In_ uint32_t attr_count,
                     _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_TAM, SAI_OBJECT_TYPE_SWITCH, switch_id, &tam_attr_to_string<sai_tam_transport_attr_t>, switch_id, attrs);

    // mandatory attribute for tam_transport creation
    sai_tam_transport_type_t transport_type;
    get_attrs_value(SAI_TAM_TRANSPORT_ATTR_TRANSPORT_TYPE, attrs, transport_type, true);

    // Validate that transport type is a valid supported type.
    switch (transport_type) {
    case SAI_TAM_TRANSPORT_TYPE_NONE:
    case SAI_TAM_TRANSPORT_TYPE_UDP:
        break;
    case SAI_TAM_TRANSPORT_TYPE_TCP:
    case SAI_TAM_TRANSPORT_TYPE_GRPC:
#if CURRENT_SAI_VERSION_CODE >= SAI_VERSION_CODE(1, 6, 0)
    case SAI_TAM_TRANSPORT_TYPE_MIRROR:
#endif
    default:
        sai_return_on_error(SAI_STATUS_NOT_IMPLEMENTED,
                            "Only support SAI_TAM_TRANSPORT_TYPE_NONE|UDP at this moment. Invalid transport type %u.",
                            transport_type);
    }

    transaction txn;
    txn.status = LA_STATUS_SUCCESS;

    uint32_t transport_idx = 0;
    txn.status = sdev->m_tam_transport.allocate_id(transport_idx);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_tam_transport.release_id(transport_idx); });

    // initialize lsai_object to collect information
    lsai_object transport_obj(SAI_OBJECT_TYPE_TAM_TRANSPORT, la_obj.index, transport_idx);

    // setup the tam_transport_entry
    lsai_tam_transport_entry_ptr transport_entry_ptr
        = std::make_shared<lsai_tam_transport_entry>(sdev, transport_obj.object_id(), transport_type);
    get_attrs_value(SAI_TAM_TRANSPORT_ATTR_SRC_PORT, attrs, transport_entry_ptr->m_src_port, false);
    get_attrs_value(SAI_TAM_TRANSPORT_ATTR_DST_PORT, attrs, transport_entry_ptr->m_dst_port, false);
    get_attrs_value(SAI_TAM_TRANSPORT_ATTR_TRANSPORT_AUTH_TYPE, attrs, transport_entry_ptr->m_auth, false);
    get_attrs_value(SAI_TAM_TRANSPORT_ATTR_MTU, attrs, transport_entry_ptr->m_mtu, false);

    txn.status = sdev->m_tam_transport.set(transport_idx, transport_entry_ptr);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_tam_transport.remove(transport_idx); });

    *tam_transport_id = transport_entry_ptr->m_oid;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_tam_transport(_In_ sai_object_id_t tam_transport_id)
{
    sai_start_api(SAI_API_TAM,
                  SAI_OBJECT_TYPE_TAM_TRANSPORT,
                  tam_transport_id,
                  &tam_attr_to_string<sai_tam_transport_attr_t>,
                  tam_transport_id);

    lsai_tam_transport_entry_ptr transport_entry_ptr;
    la_status status = sdev->m_tam_transport.get(la_obj.index, transport_entry_ptr);
    sai_return_on_la_error(status, "Failed to find tam_transport_entry for object (0x%lx)", tam_transport_id);

    status = sdev->m_tam_transport.remove(tam_transport_id);
    return to_sai_status(status);
}

static sai_status_t
get_tam_transport_attribute(_In_ sai_object_id_t tam_transport_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tam_transport_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_TAM,
                  SAI_OBJECT_TYPE_TAM_TRANSPORT,
                  tam_transport_id,
                  &tam_attr_to_string<sai_tam_transport_attr_t>,
                  tam_transport_id,
                  attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "tam_transport 0x%0lx", tam_transport_id);
    return sai_get_attributes(&key, key_str, tam_transport_attribs, tam_transport_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
set_tam_transport_attribute(_In_ sai_object_id_t tam_transport_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tam_transport_id;

    sai_start_api(SAI_API_TAM,
                  SAI_OBJECT_TYPE_TAM_TRANSPORT,
                  tam_transport_id,
                  &tam_attr_to_string<sai_tam_transport_attr_t>,
                  tam_transport_id,
                  *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "tam_transport 0x%0lx", tam_transport_id);
    return sai_set_attribute(&key, key_str, tam_transport_attribs, tam_transport_vendor_attribs, attr);
}

static sai_status_t
create_tam_telemetry(_Out_ sai_object_id_t* tam_telemetry_id,
                     _In_ sai_object_id_t switch_id,
                     _In_ uint32_t attr_count,
                     _In_ const sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
remove_tam_telemetry(_In_ sai_object_id_t tam_telemetry_id)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
get_tam_telemetry_attribute(_In_ sai_object_id_t tam_telemetry_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
set_tam_telemetry_attribute(_In_ sai_object_id_t tam_telemetry_id, _In_ const sai_attribute_t* attr)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}

static sai_status_t
create_tam_collector(_Out_ sai_object_id_t* tam_collector_id,
                     _In_ sai_object_id_t switch_id,
                     _In_ uint32_t attr_count,
                     _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_TAM, SAI_OBJECT_TYPE_SWITCH, switch_id, &tam_attr_to_string<sai_tam_collector_attr_t>, switch_id, attrs);

    // mandatory attribute for tam_collector creation
    sai_object_id_t transport_id;
    get_attrs_value(SAI_TAM_COLLECTOR_ATTR_TRANSPORT, attrs, transport_id, true);
    sai_uint8_t dscp;
    get_attrs_value(SAI_TAM_COLLECTOR_ATTR_DSCP_VALUE, attrs, dscp, true);

    transaction txn;
    txn.status = LA_STATUS_SUCCESS;

    // check if transport exists
    lsai_object transport_obj(transport_id);
    lsai_tam_transport_entry_ptr transport_ptr;
    txn.status = sdev->m_tam_transport.get(transport_obj.index, transport_ptr);
    sai_return_on_la_error(txn.status, "Failed to find tam transport object, 0x%lx in database.", transport_id);

    // We have different mandatory attributes for tam_collector creation based on transport type.
    sai_ip_address_t src_ip;
    sai_ip_address_t dst_ip;
    if (transport_ptr->m_type == SAI_TAM_TRANSPORT_TYPE_UDP) {
        get_attrs_value(SAI_TAM_COLLECTOR_ATTR_SRC_IP, attrs, src_ip, true);
        get_attrs_value(SAI_TAM_COLLECTOR_ATTR_DST_IP, attrs, dst_ip, true);
    }

    uint32_t collector_idx = 0;
    txn.status = sdev->m_tam_collector.allocate_id(collector_idx);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_tam_collector.release_id(collector_idx); });

    // initialize lsai_object to collect information
    lsai_object collector_obj(SAI_OBJECT_TYPE_TAM_COLLECTOR, la_obj.index, collector_idx);

    // setup the tam_collector_entry
    lsai_tam_collector_entry_ptr collector_entry_ptr = std::make_shared<lsai_tam_collector_entry>(sdev, collector_obj.object_id());
    collector_entry_ptr->m_transport = transport_ptr;
    collector_entry_ptr->m_dscp = dscp;
    if (transport_ptr->m_type == SAI_TAM_TRANSPORT_TYPE_UDP) {
        collector_entry_ptr->m_src_ip = src_ip;
        collector_entry_ptr->m_dst_ip = dst_ip;
    }
    get_attrs_value(SAI_TAM_COLLECTOR_ATTR_LOCALHOST, attrs, collector_entry_ptr->m_localhost, false);

    txn.status = sdev->m_tam_collector.set(collector_idx, collector_entry_ptr);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_tam_collector.remove(collector_idx); });

    *tam_collector_id = collector_entry_ptr->m_oid;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_tam_collector(_In_ sai_object_id_t tam_collector_id)
{
    sai_start_api(SAI_API_TAM,
                  SAI_OBJECT_TYPE_TAM_COLLECTOR,
                  tam_collector_id,
                  &tam_attr_to_string<sai_tam_collector_attr_t>,
                  tam_collector_id);

    lsai_tam_collector_entry_ptr collector_entry_ptr;
    la_status status = sdev->m_tam_collector.get(la_obj.index, collector_entry_ptr);
    sai_return_on_la_error(status, "Failed to find tam_collector_entry for object (0x%lx)", tam_collector_id);

    status = sdev->m_tam_collector.remove(tam_collector_id);
    return to_sai_status(status);
}

static sai_status_t
get_tam_collector_attribute(_In_ sai_object_id_t tam_collector_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tam_collector_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_TAM,
                  SAI_OBJECT_TYPE_TAM_COLLECTOR,
                  tam_collector_id,
                  &tam_attr_to_string<sai_tam_collector_attr_t>,
                  tam_collector_id,
                  attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "tam_collector 0x%0lx", tam_collector_id);
    return sai_get_attributes(&key, key_str, tam_collector_attribs, tam_collector_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
set_tam_collector_attribute(_In_ sai_object_id_t tam_collector_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tam_collector_id;

    sai_start_api(SAI_API_TAM,
                  SAI_OBJECT_TYPE_TAM_COLLECTOR,
                  tam_collector_id,
                  &tam_attr_to_string<sai_tam_collector_attr_t>,
                  tam_collector_id,
                  *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "tam_collector 0x%0lx", tam_collector_id);
    return sai_set_attribute(&key, key_str, tam_collector_attribs, tam_collector_vendor_attribs, attr);
}

static sai_status_t
create_tam_event_action(_Out_ sai_object_id_t* tam_event_action_id,
                        _In_ sai_object_id_t switch_id,
                        _In_ uint32_t attr_count,
                        _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_TAM, SAI_OBJECT_TYPE_SWITCH, switch_id, &tam_attr_to_string<sai_tam_event_action_attr_t>, switch_id, attrs);

    // mandatory attribute for tam_event_action creation
    sai_object_id_t reporter_id;
    get_attrs_value(SAI_TAM_EVENT_ACTION_ATTR_REPORT_TYPE, attrs, reporter_id, true);

    transaction txn;
    txn.status = LA_STATUS_SUCCESS;

    // check if reporter exist
    lsai_object reporter_obj(reporter_id);
    lsai_tam_report_entry_ptr reporter_ptr;
    txn.status = sdev->m_tam_report.get(reporter_obj.index, reporter_ptr);
    sai_return_on_la_error(txn.status, "Failed to find tam report object, 0x%lx in database.", reporter_id);

    uint32_t ea_index = 0;
    txn.status = sdev->m_tam_event_action.allocate_id(ea_index);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_tam_event_action.release_id(ea_index); });

    // initialize lsai_object to collect information
    lsai_object event_action_obj(SAI_OBJECT_TYPE_TAM_EVENT_ACTION, la_obj.index, ea_index);

    lsai_tam_event_action_entry_ptr event_action_ptr = std::make_shared<lsai_tam_event_action_entry>();
    event_action_ptr->m_oid = event_action_obj.object_id();
    event_action_ptr->m_sdev = sdev;

    // save event_action entry into obj_db
    txn.status = sdev->m_tam_event_action.set(ea_index, event_action_ptr);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_tam_event_action.remove(ea_index); });

    // bind event_action to reporter
    txn.status = event_action_ptr->bind_reporter(reporter_ptr);
    sai_return_on_la_error(txn.status);

    *tam_event_action_id = event_action_ptr->m_oid;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_tam_event_action(_In_ sai_object_id_t tam_event_action_id)
{
    sai_start_api(SAI_API_TAM,
                  SAI_OBJECT_TYPE_TAM_EVENT_ACTION,
                  tam_event_action_id,
                  &tam_attr_to_string<sai_tam_event_action_attr_t>,
                  tam_event_action_id);

    lsai_tam_event_action_entry_ptr event_action_entry_ptr;
    la_status status = sdev->m_tam_event_action.get(la_obj.index, event_action_entry_ptr);
    sai_return_on_la_error(status, "Failed to find tam_event_action_entry for object (0x%lx)", tam_event_action_id);

    // unbind reporter before removing event_action object
    status = event_action_entry_ptr->unbind_reporter();
    sai_return_on_la_error(status, "Fail to unbind reporter, tam_event_action_entry(0x%lx)", tam_event_action_id);

    status = sdev->m_tam_event_action.remove(tam_event_action_id);
    return to_sai_status(status);
}

static sai_status_t
get_tam_event_action_attribute(_In_ sai_object_id_t tam_event_action_id,
                               _In_ uint32_t attr_count,
                               _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tam_event_action_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_TAM,
                  SAI_OBJECT_TYPE_TAM_EVENT_ACTION,
                  tam_event_action_id,
                  &tam_attr_to_string<sai_tam_event_action_attr_t>,
                  tam_event_action_id,
                  attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "tam_event_action 0x%0lx", tam_event_action_id);
    return sai_get_attributes(&key, key_str, tam_event_action_attribs, tam_event_action_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
set_tam_event_action_attribute(_In_ sai_object_id_t tam_event_action_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tam_event_action_id;

    sai_start_api(SAI_API_TAM,
                  SAI_OBJECT_TYPE_TAM_EVENT_ACTION,
                  tam_event_action_id,
                  &tam_attr_to_string<sai_tam_event_action_attr_t>,
                  tam_event_action_id,
                  *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "tam_event_action 0x%0lx", tam_event_action_id);
    return sai_set_attribute(&key, key_str, tam_event_action_attribs, tam_event_action_vendor_attribs, attr);
}

static sai_status_t
create_tam_event(_Out_ sai_object_id_t* tam_event_id,
                 _In_ sai_object_id_t switch_id,
                 _In_ uint32_t attr_count,
                 _In_ const sai_attribute_t* attr_list)
{
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_TAM, SAI_OBJECT_TYPE_SWITCH, switch_id, &tam_attr_to_string<sai_tam_event_attr_t>, switch_id, attrs);

    // mandatory attribute for tam_event creation
    sai_tam_event_type_t event_type;
    get_attrs_value(SAI_TAM_EVENT_ATTR_TYPE, attrs, event_type, true);

    sai_object_list_t event_action_list{};
    get_attrs_value(SAI_TAM_EVENT_ATTR_ACTION_LIST, attrs, event_action_list, true);

    sai_object_list_t event_collector_list{};
    get_attrs_value(SAI_TAM_EVENT_ATTR_COLLECTOR_LIST, attrs, event_collector_list, true);

    // The switch event type is an extention valid for event type of SAI_TAM_EVENT_TYPE_SWITCH
    sai_s32_list_t switch_event_type_list{};
    get_attrs_value(SAI_TAM_EVENT_ATTR_SWITCH_EVENT_TYPE, attrs, switch_event_type_list, false);

    // only support following settings at this moment,
    // SAI_TAM_EVENT_ATTR_TYPE == SAI_TAM_EVENT_TYPE_FLOW_WATCHLIST
    // SAI_TAM_EVENT_ATTR_TYPE == SAI_TAM_EVENT_TYPE_SWITCH with SAI_TAM_EVENT_ATTR_SWITCH_EVENT_TYPE with count >= 1.
    switch (static_cast<uint32_t>(event_type)) {
    case SAI_TAM_EVENT_TYPE_FLOW_WATCHLIST:
        break;
    case SAI_TAM_EVENT_TYPE_SWITCH:
        if (switch_event_type_list.count == 0) {
            sai_return_on_error(SAI_STATUS_INVALID_PARAMETER, "SAI_TAM_EVENT_ATTR_SWITCH_EVENT_TYPE must be valid.");
        }
        break;
    default:
        sai_return_on_error(SAI_STATUS_NOT_IMPLEMENTED, "Only support SAI_TAM_EVENT_TYPE_FLOW_WATCHLIST/SWITCH at this moment.");
    }

    // check event_action objects
    std::vector<lsai_tam_event_action_entry_ptr> tam_event_action_vec;
    auto sai_status = check_object_id_list(
        tam_event_action_vec, SAI_OBJECT_TYPE_TAM_EVENT_ACTION, sdev, sdev->m_tam_event_action, event_action_list);
    sai_return_on_error(sai_status);

    // check collector objects
    std::vector<lsai_tam_collector_entry_ptr> tam_collector_vec;
    sai_status
        = check_object_id_list(tam_collector_vec, SAI_OBJECT_TYPE_TAM_COLLECTOR, sdev, sdev->m_tam_collector, event_collector_list);
    sai_return_on_error(sai_status);

    // All attributes are correct, and we can create the object now.
    transaction txn;
    txn.status = LA_STATUS_SUCCESS;

    uint32_t event_idx = 0;
    txn.status = sdev->m_tam_event.allocate_id(event_idx);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_tam_event.release_id(event_idx); });

    // create a lsai_tam_event_entry for this tam_event
    lsai_tam_event_entry_ptr tam_event_entry_ptr = std::make_shared<lsai_tam_event_entry>();

    // initialize lsai_object to collect information, la_obj is the switch obj from sai_start_api()
    lsai_object event_obj(SAI_OBJECT_TYPE_TAM_EVENT, la_obj.index, event_idx);
    tam_event_entry_ptr->m_oid = event_obj.object_id();
    tam_event_entry_ptr->m_type = event_type;
    tam_event_entry_ptr->m_switch_event_types.assign(
        (sai_switch_event_type_t*)(switch_event_type_list.list),
        (sai_switch_event_type_t*)(switch_event_type_list.list + switch_event_type_list.count));
    tam_event_entry_ptr->m_sdev = sdev;

    // save event entry into obj_db
    txn.status = sdev->m_tam_event.set(event_idx, tam_event_entry_ptr);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_tam_event.remove(event_idx); });

    sai_log_debug(SAI_API_TAM, "create_tam_event created tam_event_entry_ptr(0x%lx).", tam_event_entry_ptr->m_oid);

    // bind all event_action object in list
    for (auto ea_ptr : tam_event_action_vec) {
        txn.status = tam_event_entry_ptr->bind_event_action(ea_ptr);
        sai_return_on_la_error(txn.status);
        txn.on_fail([=]() { tam_event_entry_ptr->unbind_event_action(ea_ptr->m_oid); });
    }

    // bind all collector object in list
    for (auto ea_ptr : tam_collector_vec) {
        txn.status = tam_event_entry_ptr->bind_collector(ea_ptr);
        sai_return_on_la_error(txn.status);
        txn.on_fail([=]() { tam_event_entry_ptr->unbind_collector(ea_ptr->m_oid); });
    }

    *tam_event_id = tam_event_entry_ptr->m_oid;

    return SAI_STATUS_SUCCESS;
}

static sai_status_t
remove_tam_event(_In_ sai_object_id_t tam_event_id)
{
    sai_start_api(SAI_API_TAM, SAI_OBJECT_TYPE_TAM_EVENT, tam_event_id, &tam_attr_to_string<sai_tam_event_attr_t>, tam_event_id);

    lsai_tam_event_entry_ptr event_entry_ptr;
    la_status status = sdev->m_tam_event.get(la_obj.index, event_entry_ptr);
    sai_return_on_la_error(status, "Failed to find tam_event_entry for object (0x%lx)", tam_event_id);

    // unbind all event_action objects
    status = event_entry_ptr->unbind_all_event_actions();
    sai_return_on_la_error(status);

    // unbind all collector objects
    status = event_entry_ptr->unbind_all_collectors();
    sai_return_on_la_error(status);

    // erase this tam_event object from event vector in tam_entry
    if (sdev->m_tam.map().size() != 0) {
        static_assert(SAI_MAX_TAM == 1, "SAI_MAX_TAM is not 1. Need to update lsai_tam_event_entry.");
        // The following hardcoded tam index need to update if SAI_MAX_TAM is not 1.
        lsai_tam_entry_ptr tam_ptr;
        status = sdev->m_tam.get(0, tam_ptr);
        sai_return_on_la_error(status, "Fatal Error in tam map when removing tam_event object (0x%lx).", tam_event_id);
        tam_ptr->unregister_tam_event(tam_event_id);
    }

    status = sdev->m_tam_event.remove(tam_event_id);

    return to_sai_status(status);
}

static sai_status_t
get_tam_event_attribute(_In_ sai_object_id_t tam_event_id, _In_ uint32_t attr_count, _Inout_ sai_attribute_t* attr_list)
{
    sai_object_key_t key;
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tam_event_id;

    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_TAM, SAI_OBJECT_TYPE_TAM_EVENT, tam_event_id, &tam_attr_to_string<sai_tam_event_attr_t>, tam_event_id, attrs);

    snprintf(key_str, MAX_KEY_STR_LEN, "tam_event 0x%0lx", tam_event_id);
    return sai_get_attributes(&key, key_str, tam_event_attribs, tam_event_vendor_attribs, attr_count, attr_list);
}

static sai_status_t
set_tam_event_attribute(_In_ sai_object_id_t tam_event_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    char key_str[MAX_KEY_STR_LEN];

    key.key.object_id = tam_event_id;

    sai_start_api(
        SAI_API_TAM, SAI_OBJECT_TYPE_TAM_EVENT, tam_event_id, &tam_attr_to_string<sai_tam_event_attr_t>, tam_event_id, *attr);

    snprintf(key_str, MAX_KEY_STR_LEN, "tam_event 0x%0lx", tam_event_id);
    return sai_set_attribute(&key, key_str, tam_event_attribs, tam_event_vendor_attribs, attr);
}

const sai_tam_api_t tam_api = {create_tam,
                               remove_tam,
                               set_tam_attribute,
                               get_tam_attribute,
                               create_tam_math_func,
                               remove_tam_math_func,
                               set_tam_math_func_attribute,
                               get_tam_math_func_attribute,
                               create_tam_report,
                               remove_tam_report,
                               set_tam_report_attribute,
                               get_tam_report_attribute,
                               create_tam_event_threshold,
                               remove_tam_event_threshold,
                               set_tam_event_threshold_attribute,
                               get_tam_event_threshold_attribute,
                               create_tam_int,
                               remove_tam_int,
                               set_tam_int_attribute,
                               get_tam_int_attribute,
                               create_tam_tel_type,
                               remove_tam_tel_type,
                               set_tam_tel_type_attribute,
                               get_tam_tel_type_attribute,
                               create_tam_transport,
                               remove_tam_transport,
                               set_tam_transport_attribute,
                               get_tam_transport_attribute,
                               create_tam_telemetry,
                               remove_tam_telemetry,
                               set_tam_telemetry_attribute,
                               get_tam_telemetry_attribute,
                               create_tam_collector,
                               remove_tam_collector,
                               set_tam_collector_attribute,
                               get_tam_collector_attribute,
                               create_tam_event_action,
                               remove_tam_event_action,
                               set_tam_event_action_attribute,
                               get_tam_event_action_attribute,
                               create_tam_event,
                               remove_tam_event,
                               set_tam_event_attribute,
                               get_tam_event_attribute};
}
}

using namespace silicon_one::sai;

sai_status_t
sai_tam_telemetry_get_data(_In_ sai_object_id_t switch_id,
                           _In_ sai_object_list_t obj_list,
                           _In_ bool clear_on_read,
                           _Inout_ sai_size_t* buffer_size,
                           _Out_ void* buffer)
{
    return SAI_STATUS_NOT_IMPLEMENTED;
}
