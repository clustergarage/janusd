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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <unistd.h>

#include "janusnotify.h"
#include "janusutil.h"

/**
 * Read all available `fanotify` events from the file descriptor `fd`.
 *
 * @param fd
 * @param allow
 */
static void process_fanotify_events(const struct janusguard *guard, const int fd, const bool allow,
    void(*logfn)(struct janusguard_event *)) {

    const struct fanotify_event_metadata *metadata;
    struct fanotify_event_metadata buf[200];
    struct fanotify_response response;
    char procfdpath[PATH_MAX];
    ssize_t len, pathlen;
    struct sigaction sa;

    void alarm_handler(int sig) {
        // Just interrupt `read`.
        return;
    }
    //SIGALRM handler is designed simply to interrupt `read`.
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = alarm_handler;
    sa.sa_flags = 0;
    if (sigaction(SIGALRM, &sa, NULL) == EOF) {
#if DEBUG
        perror("sigaction");
#endif
        return;
    }

    // Loop while events can be read from fanotify file descriptor.
    for (;;) {
        // Read some events.
        len = read(fd, (void *)&buf, sizeof(buf));
        if (len == EOF) {
            if (errno != EAGAIN) {
#if DEBUG
                perror("read");
#endif
            }
            return;
        } else if (len == 0) {
#if DEBUG
            fprintf(stderr, "`read` from `fanotify` fd returned 0!");
#endif
            return;
        }

        // Point to the first event in the buffer.
        metadata = buf;

        // Loop over all events in the buffer.
        while (FAN_EVENT_OK(metadata, len)) {
            // Check that run-time and compile-time structures match.
            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
#if DEBUG
                fprintf(stderr, "Mismatch of `fanotify` metadata versions.\n");
#endif
                exit(EXIT_FAILURE);
            }

            // `metadata->fd` contains either FAN_NOFD, indicating a queue
            // overflow, or a file descriptor (a non-negative integer).
            // @TODO: Don't simply ignore queue overflow event.
            if (metadata->fd == FAN_NOFD) {
#if DEBUG
                printf("FAN_NOFD queue overflow occurred\n");
                fflush(stdout);
#endif
            } else {
                // Handle permission events.
                if ((metadata->mask & FAN_OPEN_PERM) ||
                    (metadata->mask & FAN_ACCESS_PERM)) {
                    response.fd = metadata->fd;

                    // Get the callee's parent PID to compare with passed-in
                    // PID of this process being guarded.
                    int ppid;
                    get_ppid(metadata->pid, &ppid);

                    // If `pid` is the same as the callee `metadata->pid`,
                    // then always allow.
                    //
                    // @TODO: Make this an optional setting? Or have a
                    // whitelist of allowed callee processes?
                    if (metadata->pid == guard->pid ||
                        ppid == guard->pid) {
                        response.response = FAN_ALLOW;
                    } else {
                        response.response = allow ? FAN_ALLOW : FAN_DENY;
                    }
                    ssize_t writelen = sizeof(struct fanotify_response);
                    if (write(fd, &response, writelen) != writelen) {
#if DEBUG
                        perror("write");
#endif
                    }

                    struct janusguard_event jgevent = {
                        .pid = guard->pid,
                        .sid = guard->sid,
                        .node_name = guard->nodename,
                        .pod_name = guard->podname,
                        .event_mask = metadata->mask,
                        .is_dir = (bool)(metadata->mask & FAN_ONDIR),
                        .allow = allow
                    };

                    // Retrieve and print pathname of the accessed file.
                    snprintf(procfdpath, sizeof(procfdpath), "/proc/self/fd/%d", metadata->fd);
                    pathlen = readlink(procfdpath, jgevent.path_name, sizeof(jgevent.path_name) - 1);
                    if (pathlen == EOF) {
#if DEBUG
                        perror("readlink");
#endif
                        goto closemetafd;
                    }
                    jgevent.path_name[pathlen] = '\0';

                    // Call JanusdImpl log function passed into this guard.
                    logfn(&jgevent);

#if DEBUG
                    printf("  pid = %d\n", pid);
                    printf("  callee = %d; ppid = %d\n", metadata->pid, ppid);
                    fflush(stdout);
#endif
                }

closemetafd:
                // Close the file descriptor of the event.
                close(metadata->fd);
            }

            // Advance to next event.
            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}

/**
 * Add `path` to the guard list of the `fanotify` file descriptor.
 *
 * @param fd
 * @param path
 * @param mntflags
 * @param mask
 * @param mntmask
 */
void add_fanotify_mark(const struct janusguard *guard, const int fd, const char *path) {
#if DEBUG
    printf("    add mark: path = %s\n", path);
    fflush(stdout);
#endif
    if (fanotify_mark(fd, FAN_MARK_ADD | guard->mntflags, guard->event_mask | guard->mntmask,
        AT_FDCWD, path) == EOF) {
#if DEBUG
        perror("fanotify_mark");
#endif
    }
}

/**
 * Starts the `fanotify` guard process. Acts as the `main` function if this was
 * a standalone program. It is called from the main implementation of this
 * daemon in a new thread each time it is invoked. Once started up, it marks
 * the given filesystem objects for allow/deny events, and loops infinitely
 * waiting for new `fanotify` events until it receives a kill signal.
 *
 * @param pid
 * @param sid
 * @param nodename
 * @param podname
 * @param allowc
 * @param allow
 * @param denyc
 * @param deny
 * @param mask
 * @param processevtfd
 * @param logfn
 * @return
 */
int start_fanotify_guard(int pid, int sid, char *nodename, char *podname, int allowc, char *allow[],
    int denyc, char *deny[], uint32_t mask, int processevtfd, void (*logfn)(struct janusguard_event *)) {

    int pollc;
    nfds_t nfds;
    struct pollfd fds[3];
    sigset_t sigmask;
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGCHLD);

    struct janusguard guard = (struct janusguard){
        .pid = pid,
        .sid = sid,
        .nodename = nodename,
        .podname = podname,
        .allowc = allowc,
        .allow = allow,
        .denyc = denyc,
        .deny = deny,
        .event_mask = mask,
        .processevtfd = processevtfd
    };

    guard.flags = FAN_CLOEXEC | FAN_NONBLOCK | FAN_UNLIMITED_QUEUE |
        FAN_UNLIMITED_MARKS | FAN_CLASS_CONTENT; // FAN_CLASS_PRE_CONTENT
    guard.evtflags = O_RDONLY | O_LARGEFILE | O_NONBLOCK;
    guard.mntflags = 0; // FAN_MARK_MOUNT
    guard.mntmask = FAN_EVENT_ON_CHILD | FAN_ONDIR;

#if DEBUG
    printf("  Listening for events (pid = %d, sid = %d)\n", pid, sid);
    fflush(stdout);
#endif

    // Create the file descriptor for accessing the fanotify API for ALLOW
    // events.
    guard.allowfd = fanotify_init(guard.flags, guard.evtflags);
    if (guard.allowfd == EOF) {
#if DEBUG
        perror("fanotify_init");
#endif
    }
    // Create the file descriptor for accessing the fanotify API for DENY
    // events.
    guard.denyfd = fanotify_init(guard.flags, guard.evtflags);
    if (guard.denyfd == EOF) {
#if DEBUG
        perror("fanotify_init");
#endif
    }

    int i;
    for (i = 0; i < allowc; ++i) {
        add_fanotify_mark(&guard, guard.allowfd, allow[i]);
    }
    for (i = 0; i < denyc; ++i) {
        add_fanotify_mark(&guard, guard.denyfd, deny[i]);
    }

    // Prepare for polling.
    nfds = 3;
    // `fanotify` ALLOW input.
    fds[0].fd = guard.allowfd;
    fds[0].events = POLLIN;
    // `fanotify` DENY input.
    fds[1].fd = guard.denyfd;
    fds[1].events = POLLIN;
    // Anonymous pipe for manual kill.
    fds[2].fd = processevtfd;
    fds[2].events = POLLIN;

    // Wait for events.
    for (;;) {
        pollc = ppoll(fds, nfds, NULL, &sigmask);
        if (pollc == -1) {
            if (errno == EINTR) {
                continue;
            }
#if DEBUG
            perror("ppoll");
#endif
            goto exit;
        }

        if (pollc > 0) {
            if (fds[0].revents & POLLIN) {
                // `fanotify` ALLOW events are available.
                process_fanotify_events(&guard, guard.allowfd, true, logfn);
            }
            if (fds[1].revents & POLLIN) {
                // `fanotify` DENY events are available.
                process_fanotify_events(&guard, guard.denyfd, false, logfn);
            }

            if (fds[2].revents & POLLIN) {
                // Anonymous pipe events are available.
                uint64_t value;
                ssize_t len = read(fds[2].fd, &value, sizeof(uint64_t));
                if (len != EOF &&
                    (value & JANUSNOTIFY_KILL)) {
                    break;
                }
            }
        }
    }

exit:
#if DEBUG
    printf("  Listening for events stopped (pid = %d, sid = %d)\n", pid, sid);
    fflush(stdout);
#endif

    return errno ? EXIT_FAILURE : EXIT_SUCCESS;
}

/**
 * Sends the custom kill signal to break out of the `ppoll` loop that is
 * listening for active `fanotify` guard events.
 *
 * @param processfd
 */
void send_guard_kill_signal(int processfd) {
    uint64_t value = JANUSNOTIFY_KILL;
    if (write(processfd, &value, sizeof(value)) == EOF) {
#if DEBUG
        perror("write");
#endif
    }
}
