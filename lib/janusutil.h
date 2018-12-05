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
#include <stdint.h>
#include <unistd.h>

#ifndef DEBUG
#define DEBUG 0
#endif

struct janusguard {
    int pid, sid;          // PID, Subject ID.
    char *nodename, *podname;
    int allowfd, denyfd;   // `fanotify` file descriptor.
    int *wd;               // Array of watch descriptors (-1 if slot unused).
    unsigned int allowc;   // Cached path count, including recursive traversal.
    char **allow;          // Cached path name(s), including recursive traversal.
    unsigned int denyc;    // Ignore path pattern count.
    char **deny;           // Ignore path patterns.
    uint32_t event_mask;   // Event mask for `fanotify`.
    unsigned int flags, evtflags, mntflags;
    uint64_t mntmask;
    int processevtfd;      // Anonymous pipe to send watch kill signal.
};

void get_ppid(const pid_t pid, pid_t *ppid);

#endif
