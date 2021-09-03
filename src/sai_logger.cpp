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

#include <syslog.h>
#include "sai_logger.h"
#include "api/system/la_log.h"
#include "common/gen_utils.h"
#include "common/logger.h"

using namespace std;
using namespace silicon_one::sai;

void
sai_logging_param_set(int enable_syslog, int enable_stdout_msg)
{
    lsai_logger::instance().enable_syslog(enable_syslog != 0);
    lsai_logger::instance().enable_stdout_msg(enable_stdout_msg != 0);
}

namespace silicon_one
{
namespace sai
{

static constexpr uint32_t TIMESTAMP_BUFFER_SIZE = 30;

void
lsai_logger::log_function(sai_log_level_t severity, const char* msg)
{
    int level;
    string level_str;

    /* translate sai log level to syslog level */
    switch (severity) {
    case SAI_LOG_LEVEL_DEBUG:
        level = LOG_DEBUG;
        level_str = "DEBUG";
        break;

    case SAI_LOG_LEVEL_INFO:
        level = LOG_INFO;
        level_str = "INFO";
        break;

    case SAI_LOG_LEVEL_NOTICE:
        level = LOG_NOTICE;
        level_str = "NOTICE";
        break;

    case SAI_LOG_LEVEL_WARN:
        level = LOG_WARNING;
        level_str = "WARNING";
        break;

    case SAI_LOG_LEVEL_ERROR:
        level = LOG_ERR;
        level_str = "ERR";
        break;

    case SAI_LOG_LEVEL_CRITICAL:
        level = LOG_CRIT;
        level_str = "CRITICAL";
        break;

    default:
        level = LOG_DEBUG;
        level_str = "DEBUG";
        break;
    }

    if (m_syslog_msg) {
        syslog(level, "%s", msg);
    }
    if (m_stdout_msg) {
        char timestamp[TIMESTAMP_BUFFER_SIZE]{"\0"};
        silicon_one::add_timestamp(timestamp, sizeof(timestamp));
        printf("%s[%s] %s\n", timestamp, level_str.c_str(), msg);
    }
}

static void
la_logger_function(la_device_id_t device_id,
                   la_logger_component_e log_component,
                   la_logger_level_e logging_level,
                   const char* message)
{
    sai_log_level_t severity = SAI_LOG_LEVEL_DEBUG;

    switch (logging_level) {
    case la_logger_level_e::EMERG:
    case la_logger_level_e::ALERT:
    case la_logger_level_e::CRIT:
        severity = SAI_LOG_LEVEL_CRITICAL;
        break;
    case la_logger_level_e::ERROR:
        severity = SAI_LOG_LEVEL_ERROR;
        break;
    case la_logger_level_e::WARNING:
        severity = SAI_LOG_LEVEL_WARN;
        break;
    case la_logger_level_e::NOTICE:
        severity = SAI_LOG_LEVEL_NOTICE;
        break;
    case la_logger_level_e::INFO:
        severity = SAI_LOG_LEVEL_INFO;
        break;
    case la_logger_level_e::DEBUG:
    case la_logger_level_e::XDEBUG:
    case la_logger_level_e::SPAM:
    default:
        severity = SAI_LOG_LEVEL_DEBUG;
        break;
    }

    lsai_logger::instance().log(SAI_API_UNSPECIFIED, severity, "%s", message);
}

lsai_logger::lsai_logger()
{
    for (int apid = 0; apid <= (int)SAI_API_MAX; apid++) {
        set_logging_level((sai_api_t)apid, SAI_LOG_LEVEL_WARN);
    }

    la_set_logger_function(la_logger_function);
}

void
lsai_logger::set_logging_level(sai_api_t apid, sai_log_level_t log_level)
{
    extern void set_all_la_logging(sai_log_level_t log_level);

    if (apid < SAI_API_MAX) {
        m_log_level[apid] = log_level;

        if (apid == SAI_API_UNSPECIFIED) {
            set_all_la_logging(log_level); // configure SDK log level
        }
    } else {
        for (int i = 0; i <= (int)SAI_API_MAX; i++) {
            m_log_level[i] = log_level;
        }
        set_all_la_logging(log_level);
    }
}

void
lsai_logger::get_logging_level(sai_api_t apid, sai_log_level_t& log_level)
{
    log_level = m_log_level[apid];
}

void
lsai_logger::log(sai_api_t apid, sai_log_level_t log_level, const char* format, ...)
{
    enum { LOG_BUFFER = 4096 };
    char message[LOG_BUFFER];

    std::string api_str = to_string(apid);
    int off = 0;
    if (apid != SAI_API_UNSPECIFIED) {
        off = snprintf(message, LOG_BUFFER, "%s: ", api_str.c_str());
    }

    va_list ap;
    va_start(ap, format);
    vsnprintf(message + off, LOG_BUFFER - off, format, ap);
    va_end(ap);

    log_function(log_level, message);

    if (off >= LOG_BUFFER) {
        printf("sai log message length was truncated due to over sized length\n");
    }
}

lsai_logger_throttled::lsai_logger_throttled()
{
    m_apid = SAI_API_UNSPECIFIED;
    m_message_count_interval = DEFAULT_DEBUG_SUPRESSED;
    m_cur_message_count = 0;
}

void
lsai_logger_throttled::initialize(sai_api_t apid, uint16_t interval, uint16_t messages)
{
    m_apid = apid;
    m_message_time_interval = std::chrono::seconds(interval);
    m_last_sent = std::chrono::steady_clock::now();
    m_message_count_interval = messages;
    m_cur_message_count = 0;
}

void
lsai_logger_throttled::log(const char* format, ...)
{
    auto t2 = std::chrono::steady_clock::now();
    auto duration = t2 - m_last_sent;

    if (duration > m_message_time_interval || (m_cur_message_count % m_message_count_interval == 0)) {
        enum { LOG_BUFFER = 4096 };
        char message[LOG_BUFFER];

        va_list ap;
        va_start(ap, format);
        vsnprintf(message, LOG_BUFFER, format, ap);
        va_end(ap);

        sai_log_debug(m_apid, message);

        m_last_sent = t2;
        if (m_cur_message_count != 0) {
            m_cur_message_count = 0;
        }
    }
    m_cur_message_count++;
}
}
}
