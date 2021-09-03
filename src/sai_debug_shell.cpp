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

#include "sai_debug_shell.h"

extern "C" {
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sai.h>
}
#include "common/ranged_index_generator.h"
#include "api/types/la_common_types.h"
#include "sai_db.h"
#include <thread>
// must be at the end, since it defines ECHO, which causes errors in some NPL auto generated include file
#include <termios.h>

namespace silicon_one
{
namespace sai
{
#define logger(args...)                                                                                                            \
    do {                                                                                                                           \
        char fm_tmp[256] = {0};                                                                                                    \
        snprintf(fm_tmp, sizeof(fm_tmp), args);                                                                                    \
        FILE* fd = fopen("/tmp/debug_shell.log", "a+");                                                                            \
        fputs(fm_tmp, fd);                                                                                                         \
        fflush(fd);                                                                                                                \
        fclose(fd);                                                                                                                \
    } while (0)

// Globals for python interpreter
static int py_argc = 1;
static const wchar_t* py_argv[3] = {L"debug_shell", L" "};

// Attach slave pseudo terminal to python interpreter thread of execution
static void
set_pseudo_terminal_parameters(int fd)
{
    struct termios slave_orig_term_settings; // Saved terminal settings
    struct termios new_term_settings;        // Current terminal settings

    // Save the defaults parameters of the slave side of the PTY
    if (tcgetattr(fd, &slave_orig_term_settings) == -1) {
        logger("Error obtaining slave pseudo terminal settings, %d: %s\n", errno, strerror(errno));
    }

    // Set RAW mode on slave side of PTY
    new_term_settings = slave_orig_term_settings;
    cfmakeraw(&new_term_settings);
    if (tcsetattr(fd, TCSANOW, &new_term_settings) == -1) {
        logger("Error setting terminal propoerties of slave pseudo terminal, %d: %s\n", errno, strerror(errno));
    }

    // Set fd to stdin, stdout and stderr
    if (dup2(fd, STDIN_FILENO) != STDIN_FILENO) {
        logger("Error redirecting standard input to slave pseudo terminal, %d: %s\n", errno, strerror(errno));
    }

    if (dup2(fd, STDOUT_FILENO) != STDOUT_FILENO) {
        logger("Error redirecting standard output to slave pseudo terminal, %d: %s\n", errno, strerror(errno));
    }

    if (dup2(fd, STDERR_FILENO) != STDERR_FILENO) {
        logger("Error redirecting standard error to slave pseudo terminal, %d: %s\n", errno, strerror(errno));
    }

    setsid();
    ioctl(0, TIOCSCTTY, 1);
}

// restore terminal after python interpreter thread of execution stops.
static void
reset_pseudo_terminal_parameters(int in1, int in2, int in3)
{
    ioctl(0, TIOCNOTTY, nullptr);

    // Restore std fds
    if (dup2(in1, 0) == -1) {
        logger("Error restoring standard input of pseudo terminal %d: %s\n", errno, strerror(errno));
    }

    if (dup2(in2, 1) == -1) {
        logger("Error restoring standard output of pseudo terminal %d: %s\n", errno, strerror(errno));
    }

    if (dup2(in3, 2) == -1) {
        logger("Error restoring standard error of pseudo terminal %d: %s\n", errno, strerror(errno));
    }
}

// Launch Python interpreter.
static void
launch_py_shell()
{
    int rc;
    void* py_handle = nullptr;

    // Python C function ptrs
    void (*_py_initialize)(void) = nullptr;
    int (*_py_main)(int, const wchar_t**) = nullptr;
    void (*_py_finalize)(void) = nullptr;
    PyObject* (*_pyimport_addmodule)(const char*) = nullptr;
    PyObject* (*_pymodule_getdict)(PyObject*) = nullptr;
    PyObject* (*_pylong_fromvoidptr)(void*) = nullptr;
    int (*_pydict_setitemstring)(PyObject*, const char*, PyObject*) = nullptr;
    void (*_pyeval_initthreads)(void) = nullptr;
    PyObject* (*_pylong_fromlong)(void*) = nullptr;
    PyObject* (*_pystring_fromstring)(const char*) = nullptr;

    logger("Starting python interpreter\n");

    char* pythonlibpath = std::getenv("SAI_DEBUG_PYTHON_SO_PATH");
    if (!pythonlibpath) {
        py_handle = dlopen("libpython3.7m.so", RTLD_LAZY | RTLD_GLOBAL);
    } else {
        py_handle = dlopen(pythonlibpath, RTLD_LAZY | RTLD_GLOBAL);
    }
    if (!py_handle) {
        logger("dlopen of cpython shared library failed : %s\n", dlerror());
        return;
    }

    _py_initialize = (void (*)(void))dlsym(py_handle, "Py_Initialize");
    _py_main = (int (*)(int, const wchar_t**))dlsym(py_handle, "Py_Main");
    _py_finalize = (void (*)(void))dlsym(py_handle, "Py_Finalize");
    _pyeval_initthreads = (void (*)(void))dlsym(py_handle, "PyEval_InitThreads");
    _pyimport_addmodule = (PyObject * (*)(const char*)) dlsym(py_handle, "PyImport_AddModule");
    _pymodule_getdict = (PyObject * (*)(PyObject*)) dlsym(py_handle, "PyModule_GetDict");
    _pylong_fromvoidptr = (PyObject * (*)(void*)) dlsym(py_handle, "PyLong_FromVoidPtr");
    _pydict_setitemstring = (int (*)(PyObject*, const char*, PyObject*))dlsym(py_handle, "PyDict_SetItemString");
    _pylong_fromlong = (PyObject * (*)(void*)) dlsym(py_handle, "PyLong_FromLong");
    _pystring_fromstring = (PyObject * (*)(const char*)) dlsym(py_handle, "PyUnicode_FromString");
    // Check function ptrs
    if (!(_py_initialize && _py_main && _py_finalize && _pyimport_addmodule && _pymodule_getdict && _pylong_fromvoidptr
          && _pydict_setitemstring
          && _pylong_fromlong
          && _pystring_fromstring
          && _pyeval_initthreads)) {
        logger("Python interpreter function handle check failed\n");
        return;
    }

    // Initialize python environment
    _py_initialize();
    _pyeval_initthreads();

    PyObject* main1 = _pyimport_addmodule("__main__");
    if (main1) {
        PyObject* globals = _pymodule_getdict(main1);
        if (globals) {
            char la_device[10];
            PyObject* value = nullptr;
            debug_shell* debug_shell = &debug_shell::get_instance();
            int devinst = 0;
            for (auto it = debug_shell->m_device_handles.begin(); it != debug_shell->m_device_handles.end(); ++it, ++devinst) {
                value = _pylong_fromvoidptr(it->get());
                if (value == nullptr) {
                    logger("Python interpreter long value is invalid for device instance %d %p\n", devinst, it->get());
                    continue;
                }

                snprintf(la_device, sizeof(la_device), "saidev_%02u", (uint8_t)devinst % (100));
                // Export the device handles to Python as long objects
                if (_pydict_setitemstring(globals, la_device, value) < 0) {
                    logger("Error setting python interpreter globals\n");
                }
            }
            // Start the python interpreter
            rc = _py_main(py_argc, py_argv);
            logger("Completed Python interpreter %d\n", rc);
        } else {
            logger("Error fetching globals from python interpreter\n");
        }
    } else {
        logger("PyImport_AddModule failed when running python interpter\n");
    }

    // Cleanup the python environment
    _py_finalize();

    logger("python interpreter completed\n");

    if ((rc = dlclose(py_handle)) != 0) {
        dlerror(); // Flushing out previous errors
        logger("dclose of cpython shared library failed : %s\n", dlerror());
    }

    // Clear history file
    fclose(fopen("/tmp/.python-history", "w"));
    py_handle = nullptr;
}

// Launch Python interpreter as a seperate thread of execution.
static void
py_interpreter_start(int slave_pty_fd)
{
    // Store std fds
    int fd_stdin = dup(STDIN_FILENO);
    if (fd_stdin == -1) {
        logger("Error redirecting standard input to slave pseudo terminal, %d: %s\n", errno, strerror(errno));
        return;
    }

    int fd_stdout = dup(STDOUT_FILENO);
    if (fd_stdout == -1) {
        logger("Error redirecting standard output to slave pseudo terminal, %d: %s\n", errno, strerror(errno));
        close(fd_stdin);
        return;
    }

    int fd_stderr = dup(STDERR_FILENO);
    if (fd_stderr == -1) {
        logger("Error redirecting standard error to slave pseudo terminal, %d: %s\n", errno, strerror(errno));
        close(fd_stdin);
        close(fd_stdout);
        return;
    }

    logger("Starting python interpreter as debug sai debug shell\n");
    set_pseudo_terminal_parameters(slave_pty_fd);
    logger("Completed setting python interpreter's slave terminal setting\n");
    launch_py_shell();
    reset_pseudo_terminal_parameters(fd_stdin, fd_stdout, fd_stderr);
    logger("Stopped python interpreter\n");

    close(fd_stdin);
    close(fd_stdout);
    close(fd_stderr);
    close(slave_pty_fd);
}

// Create pseudo terminal and attach slave terminal to python interpreter.
// Master terminal is used by thread of execution that listens to commands
// from debug client. Through master terminal commands from debug client
// are passed to interpreter as well as output from the interpreter is
// collected through master terminal stdout and sent to debug client.
static int
sai_debug_attach_python_interpreter()
{
    char slave_pty_name[50];

    // Create a pseudo terminal
    int master_pty_fd = posix_openpt(O_RDWR);
    if (master_pty_fd == -1) {
        logger("Error: creating pseudo terminal during  debug shell creation %s\n", strerror(errno));
        return -1;
    }

    if (ptsname_r(master_pty_fd, slave_pty_name, sizeof(slave_pty_name)) != 0) {
        logger("Error: obtaining pseudo slave terminal name during debug shell creation %s\n", strerror(errno));
        return -1;
    }

    // Change access rights on the slave side of the pseudo terminal
    if (grantpt(master_pty_fd) == -1) {
        logger("Error: Setting permission on pseudo terminal name during debug shell creation %s\n", strerror(errno));
        return -1;
    }

    // Unlock the slave side of the pseudo terminal
    if (unlockpt(master_pty_fd) == -1) {
        logger("Error: Unlocking pseudo terminal name during debug shell creation %s\n", strerror(errno));
        return -1;
    }

    // get slave pseudo term fd
    int slave_pty_fd = open(slave_pty_name, O_RDWR);
    if (slave_pty_fd != -1) {
        std::thread py_interpreter(py_interpreter_start, slave_pty_fd);
        py_interpreter.detach();
    } else {
        logger("Error: Opening pseudo slave terminal during debug shell creation \n");
    }

    return master_pty_fd;
}

// Create socket and listen for connection from debug client.
static int
debug_shell_create_socket(uint32_t port, sockaddr_in* address)
{
    int debug_cmd_listen_sock = -1;
    int opt = 1;

    if ((debug_cmd_listen_sock = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        logger("Error: Creating debug socket  during debug shell creation\n");
        return -1;
    }

    if (setsockopt(debug_cmd_listen_sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        logger("Error: setting  debug socket options during debug shell creation \n");
        return -1;
    }

    address->sin_family = AF_INET;
    address->sin_addr.s_addr = INADDR_ANY;
    address->sin_port = htons(port);

    // Attaching socket to debug-shell-port
    if (bind(debug_cmd_listen_sock, (struct sockaddr*)address, sizeof(*address)) < 0) {
        logger("Error: binding to debug port during debug shell creation failed\n");
        return -1;
    }

    if (listen(debug_cmd_listen_sock, 3) < 0) {
        logger("Error: listen on debug socket  during debug shell creation failed\n");
        return -1;
    }

    return debug_cmd_listen_sock;
}

// Entry function for new thread creation.
static sai_status_t
start_debug_shell(uint32_t port)
{
    debug_shell* debug_shell = &debug_shell::get_instance();
    return debug_shell->run_debug_shell(port);
}

// Listens to debug client connection and facilitates
// debug command read from client. Also send output of
// debug interpreter to connected debug client.
sai_status_t
debug_shell::run_debug_shell(uint32_t port)
{
    struct sockaddr_in address;
    int master_pt_fd = -1;
    int debug_client_fd = -1;

    int debug_cmd_listen_sock = debug_shell_create_socket(port, &address);
    if (debug_cmd_listen_sock == -1) {
        logger("Error: Creating debug socket  during debug shell creation\n");
        return -1;
    }

    bool accept_new_connection = true;
    fd_set working_fds;
    FD_ZERO(&working_fds);
    while (true) {
        if (!m_run_shell) {
            // Stop listening to debug client only if debug shell
            // enabled at runtime through sai attribute
            // SAI_SWITCH_ATTR_SWITCH_SHELL_ENABLE.
            // If started through environment variable setting, then
            // keep listening for debug client to connect so that
            // multiple iteration of client connect/disconnect is possible.
            char* enable_debug_shell = std::getenv("SAI_SHELL_ENABLE");
            if (enable_debug_shell && !strcmp(enable_debug_shell, "1")) {
                // keep shell running by continuing to listen for connection
                // from debug client.
                m_run_shell = true;
            } else {
                close(debug_cmd_listen_sock);
                if (master_pt_fd != -1) {
                    close(master_pt_fd);
                }
                return SAI_STATUS_SUCCESS;
            }
        }

        FD_ZERO(&working_fds);
        FD_SET(debug_cmd_listen_sock, &working_fds);
        if (debug_client_fd != -1) {
            FD_SET(debug_client_fd, &working_fds);
        }

        if (master_pt_fd != -1) {
            FD_SET(master_pt_fd, &working_fds);
        }

        int max_fd = (master_pt_fd > debug_client_fd) ? master_pt_fd : debug_client_fd;
        max_fd = (debug_cmd_listen_sock > max_fd) ? debug_cmd_listen_sock : max_fd;
        struct timeval timeout = {.tv_sec = 4, .tv_usec = 0};
        auto rv = select(max_fd + 1, &working_fds, nullptr, nullptr, &timeout);
        if (rv == -1 || !rv) {
            continue;
        }

        for (auto fd : {debug_cmd_listen_sock, master_pt_fd, debug_client_fd}) {
            if (FD_ISSET(fd, &working_fds)) {
                if (fd == debug_cmd_listen_sock) {
                    socklen_t addrlen = sizeof(address);

                    if (!accept_new_connection) {
                        int debug_new_client_fd = -1;
                        if ((debug_new_client_fd = accept(debug_cmd_listen_sock, (struct sockaddr*)&address, &addrlen)) >= 0) {
                            const char* buf = "Debug Server: client shell session already exists";
                            write(debug_new_client_fd, buf, strlen(buf));
                            close(debug_new_client_fd);
                        }
                        continue;
                    }
                    // New debug client waiting for connection to be accepted
                    if ((debug_client_fd = accept(debug_cmd_listen_sock, (struct sockaddr*)&address, &addrlen)) < 0) {
                        logger("debug client connected to debug shell\n");
                        return -1;
                    } else {
                        accept_new_connection = false;
                        logger("Debug cilent connected\n");
                        FD_SET(debug_client_fd, &working_fds);
                        // Send all device handles of all switches created so far
                        // so that debug client can use it.
                        int devinst = 0;
                        debug_shell* debug_shell = &debug_shell::get_instance();
                        for (auto it = debug_shell->m_device_handles.begin(); it != debug_shell->m_device_handles.end();
                             ++it, ++devinst) {
                            char buf[100];
                            auto len = snprintf(buf, sizeof(buf), "Device Instance %d's Handle: %p\n", devinst, it->get());
                            write(debug_client_fd, buf, len);
                        }

                        // Create pseudo terminal and attach python interpreter.
                        if (master_pt_fd == -1) {
                            master_pt_fd = sai_debug_attach_python_interpreter();
                            if (master_pt_fd == -1) {
                                logger("Could not attach python interpreter to debug shell\n");
                                close(debug_client_fd);
                                close(debug_cmd_listen_sock);
                                return -1;
                            }
                        }
                    }
                } else if (fd == debug_client_fd) {
                    // Process commands from debug client. Any command
                    // recevied from client, write to master pseudo terminal
                    char cmdBuffer[500];
                    // assumption here is debug command are less than 500 characters
                    auto cmdLen = read(debug_client_fd, cmdBuffer, sizeof(cmdBuffer));
                    if (cmdLen && !strncmp(cmdBuffer, "quit()", strlen("quit()"))) {
                        // If quit() is sent by debug client. Do not pass it to
                        // interpreter. Currently python interpreter terminates
                        // process Py_main() does not return.
                        // Wait for debug-client to connect again.
                        accept_new_connection = true;
                    } else if (cmdLen > 0) {
                        // write to master PT
                        write(master_pt_fd, cmdBuffer, cmdLen);
                    } else if (cmdLen == 0) {
                        close(debug_client_fd);
                        debug_client_fd = -1;
                        m_run_shell = false;
                        if (master_pt_fd != -1) {
                            close(master_pt_fd);
                            master_pt_fd = -1;
                        }
                        // If EOF is sent by debug client. Get ready to accept
                        // new connection from debug client.
                        accept_new_connection = true;
                    }
                } else if (fd == master_pt_fd) {
                    // Send python interpreter output back to debug client.
                    char cmdResponseBuf[500];
                    int cmdResponseLen;
                    cmdResponseLen = read(master_pt_fd, cmdResponseBuf, sizeof(cmdResponseBuf));
                    write(debug_client_fd, cmdResponseBuf, cmdResponseLen);
                }
                FD_CLR(fd, &working_fds);
            }
        }
    }

    return SAI_STATUS_SUCCESS;
}

// The function starts an interactive shell with python interpreter
// in the backend run as a new thread of execution.
sai_status_t
debug_shell::start()
{
    extern obj_db<std::shared_ptr<lsai_device>> switches;

    if (!m_run_shell) {
        // collect handles of all switches created so far so that they can
        // be pushed to python interpreter's global dictionary.
        uint32_t device_count = 0;
        switches.get_object_count(nullptr, &device_count);
        for (unsigned devinst = 0; devinst < device_count; ++devinst) {
            std::shared_ptr<lsai_device> dev_handle;
            switches.get(devinst, dev_handle);
            m_device_handles.push_back(dev_handle);
        }
        m_run_shell = true;

        std::thread debug_shell_thread(start_debug_shell, m_debug_socket_port);
        debug_shell_thread.detach();
        return SAI_STATUS_SUCCESS;
    }
    // debug shell already created.
    return SAI_STATUS_SUCCESS;
}

// The function stops debug shell if already started/created
sai_status_t
debug_shell::stop()
{
    m_run_shell = false;
    return SAI_STATUS_SUCCESS;
}

// Returns true/false depending on whether debug shell is started or not.
bool
debug_shell::status_get()
{
    return m_run_shell;
}

} // namespace
}
