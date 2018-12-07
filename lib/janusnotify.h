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

#ifndef __JANUS_NOTIFY__
#define __JANUS_NOTIFY__

#include <limits.h>
#include <signal.h>
#include <stdbool.h>

#include "janusutil.h"

#define JANUSNOTIFY_KILL SIGKILL

struct janusguard_event {
    struct janusguard *guard;
    uint64_t event_mask;
    char path_name[PATH_MAX];
    bool is_dir, allow;
};

static void process_fanotify_events(struct janusguard *guard, const int fd, bool allow,
    void(*logfn)(struct janusguard_event *));
void add_fanotify_mark(const struct janusguard *guard, const int fd, const char *path);
int start_fanotify_guard(char *name, int pid, int sid, char *nodename, char *podname, unsigned int allowc, char *allow[],
    unsigned int denyc, char *deny[], uint32_t mask, bool onlydir, bool autoallowowner, bool audit, int processevtfd, char *tags,
    char *logformat, void (*logfn)(struct janusguard_event *));
void send_guard_kill_signal(int processfd);

#endif
