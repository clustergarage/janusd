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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "janusutil.h"

/**
 * Determine the parent PID from a given PID.
 * See: http://man7.org/linux/man-pages/man5/proc.5.html
 * section /proc/[pid]/stat
 *
 * @param pid
 * @param ppid
 */
void get_ppid(const pid_t pid, pid_t *ppid) {
    char buffer[BUFSIZ];
    sprintf(buffer, "/proc/%d/stat", pid);
    FILE *fp = fopen(buffer, "r");
    if (fp) {
        size_t size = fread(buffer, sizeof(char), sizeof(buffer), fp);
        if (size > 0) {
            strtok(buffer, " ");              // (1) pid    %d
            strtok(NULL, " ");                // (2) comm   %s
            strtok(NULL, " ");                // (3) state  %c
            char *s_ppid = strtok(NULL, " "); // (4) ppid   %d
            char *end;
            *ppid = (int)strtol(s_ppid, &end, 10);
            if (*end != '\0') {
#if DEBUG
                perror("strtol");
#endif
            }
        }
        fclose(fp);
    }
}
