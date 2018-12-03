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

#include <signal.h>
#include <stdbool.h>

#include "janusutil.h"

#define JANUSNOTIFY_KILL SIGKILL

static void process_fanotify_events(const int pid, int fd, bool allow);
void add_fanotify_mark(const int fd, const char *path, const uint32_t mntflags,
    const uint32_t mask, const uint64_t mntmask);
int start_fanotify_guard(const int pid, const int sid, unsigned int allowc, char *allow[],
    unsigned int denyc, char *deny[], uint32_t mask, int processevtfd);
void send_guard_kill_signal(int processfd);

#endif
