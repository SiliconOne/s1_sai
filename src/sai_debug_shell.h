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

#ifndef __SAI_DEBUG_SHELL_H__
#define __SAI_DEBUG_SHELL_H__

extern "C" {
#include <sai.h>
}
#include <memory>
#include <vector>

namespace silicon_one
{
namespace sai
{

class lsai_device;
// -------- Sai Debug Shell implementation in brief. -----------
// At runtime, a single instance of python interpreter that can execute sai/sdk
// python APIs can br started. In order to start interpreter, driver process has
// to either set sai attribute SAI_SWITCH_ATTR_SWITCH_SHELL_ENABLE to true or the
// driver process has to be started after setting environment variable
// SAI_SHELL_ENABLE.
// A thread of execution opens socket port for debug client to connect. Through
// this connection, python commands are received from debug client and fed to
// interpreter. The output of the interpreter is written into the connection
// established between debug-client and the process that drives SAI layer of APIs.

// Singleton implementation of sai debug shell.
class debug_shell
{
public:
    static debug_shell& get_instance()
    {
        static debug_shell shell;
        return shell;
    }

    // The function starts an interactive shell with python interpreter
    // in the backend run as a new thread of execution.
    int start();
    // The function stops debug shell if already started/created
    int stop();
    // Returns true/false depending on whether debug shell is started or not.
    bool status_get();
    // Open channel of communication with debug client.
    sai_status_t run_debug_shell(uint32_t port);
    std::vector<std::shared_ptr<lsai_device>> m_device_handles;
    debug_shell(debug_shell const&) = delete;
    void operator=(debug_shell const&) = delete;

private:
    // Listens to debug client connection and facilitates
    // debug command read from client. Also send output of
    // debug interpreter to connected debug client.
    debug_shell()
    {
    }
    bool m_run_shell = false;
    uint32_t m_debug_socket_port = 12345;
};
}
}
#endif // __SAI_DEBUG_SHELL_H__
