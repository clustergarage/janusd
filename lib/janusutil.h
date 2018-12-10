/**
 * MIT License
 *
 * Copyright (c) 2018 ClusterGarage
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef __JANUS_UTIL__
#define __JANUS_UTIL__

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#ifndef DEBUG
#define DEBUG 0
#endif

#define FA_BUFFER_SIZE (FAN_EVENT_METADATA_LEN + PATH_MAX + 1)

struct janusguard {
    const char *name;                 // Name of JanusGuard.
    int pid, sid;                     // PID, Subject ID.
    const char *node_name, *pod_name; // Name of node, pod in which process is running.
    int allowfd, denyfd;              // `fanotify` file descriptor.
    unsigned int allowc;              // Cached path count, including recursive traversal.
    char **allow;                     // Cached path name(s), including recursive traversal.
    unsigned int denyc;               // Ignore path pattern count.
    char **deny;                      // Ignore path patterns.
    unsigned int flags, evt_flags;    // Flags, event flags for `fanotify_init`.
    unsigned int mnt_flags;           // Optional mount flag for `fanotify_mark`.
    uint32_t event_mask;              // Event mask for `fanotify_mark`.
    uint64_t mnt_mask;                // Optional mount mask for `fanotify_mark`.
    bool only_dir;                    // Flag to watch only directories.
    bool auto_allow_owner;            // Flag to automatically allow owner pid,ppid permission.
    bool audit;                       // Flag to send events to kernel audit logs.
    int processevtfd;                 // Anonymous pipe to send watch kill signal.
    const char *tags;                 // Custom tags for printing JanusGuard event.
    const char *log_format;           // Custom logging format for printing JanusGuard event.
};

void get_ppid(const pid_t pid, pid_t *ppid);

#endif
