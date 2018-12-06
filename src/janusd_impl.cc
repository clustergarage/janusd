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

#include "janusd_impl.h"

#include <poll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <thread>

#include <fmt/format.h>
#include <glog/logging.h>
#include <grpc/grpc.h>
#include <grpc++/server_context.h>
#include <libcontainer/container_util.h>

extern "C" {
#include <lib/janusnotify.h>
#include <lib/janusutil.h>
}

namespace janusd {
/**
 * CreateGuard is responsible for creating (or updating) a janus guard. Find
 * list of PIDs from the request's container IDs list. With the list of PIDs,
 * create `fanotify` guards by spawning a janusnotify process that handles the
 * filesystem-level instructions.
 *
 * @param context
 * @param request
 * @param response
 * @return
 */
grpc::Status JanusdImpl::CreateGuard(grpc::ServerContext *context [[maybe_unused]], const janus::JanusdConfig *request,
    janus::JanusdHandle *response) {

    auto pids = getPidsFromRequest(std::make_shared<janus::JanusdConfig>(*request));
    if (pids.empty()) {
        return grpc::Status::CANCELLED;
    }

    // Find existing guard by pid in case we need to update `fanotify_mark` is
    // designed to both add and modify depending on if a fd exists already for
    // this path.
    auto guard = findJanusdGuardByPids(request->nodename(), pids);
    LOG(INFO) << (guard == nullptr ? "Starting" : "Updating") << " `fanotify` guard ("
        << request->podname() << ":" << request->nodename() << ")";
    if (guard != nullptr) {
        // Stop existing guard polling.
        sendKillSignalToGuard(guard);

        // Wait for all processeventfd to be cleared. This indicates that the
        // fanotify threads are finished and cleaned up.
        std::unique_lock<std::mutex> lock(mux_);
        cv_.wait_until(lock, std::chrono::system_clock::now() + std::chrono::seconds(2), [=] {
            return guard->processeventfd().empty();
        });
    }

    response->set_nodename(request->nodename().c_str());
    response->set_podname(request->podname().c_str());

    for_each(pids.cbegin(), pids.cend(), [&](const int pid) {
        int i = 0;
        for_each(request->subject().cbegin(), request->subject().cend(), [&](const janus::JanusGuardSubject subject) {
            // @TODO: Check if any guards are started, if not, don't add to
            // response.
            createFanotifyGuard(request->name(), response->nodename(), response->podname(),
				std::make_shared<janus::JanusGuardSubject>(subject), pid, i,
				response->mutable_processeventfd(), request->logformat());
            ++i;
        });
        response->add_pid(pid);
    });

    if (guard == nullptr) {
        // Store new guard.
        guards_.push_back(std::make_shared<janus::JanusdHandle>(*response));
    } else {
        std::for_each(response->processeventfd().cbegin(), response->processeventfd().cend(), [&](const int processfd) {
            guard->add_processeventfd(processfd);
        });
    }

    return grpc::Status::OK;
}

/**
 * DestroyGuard is responsible for deleting a janus guard. Send kill signal to
 * the janusnotify poller to stop that child process.
 *
 * @param context
 * @param request
 * @param response
 * @return
 */
grpc::Status JanusdImpl::DestroyGuard(grpc::ServerContext *context [[maybe_unused]], const janus::JanusdConfig *request,
    janus::Empty *response [[maybe_unused]]) {

    LOG(INFO) << "Stopping `fanotify` guard (" << request->podname() << ":" << request->nodename() << ")";

    auto guard = findJanusdGuardByPids(request->nodename(), std::vector<int>(request->pid().cbegin(), request->pid().cend()));
    if (guard != nullptr) {
        // Stop existing guard polling.
        sendKillSignalToGuard(guard);
    }
    guards_.erase(remove(guards_.begin(), guards_.end(), guard), guards_.end());

    return grpc::Status::OK;
}

/**
 * GetGuardState periodically gets called by the Kubernetes controller and is
 * responsible for gathering the current guard state to send back so the
 * controller can reconcile if any guards need to be added or destroyed.
 *
 * @param context
 * @param request
 * @param writer
 * @return
 */
grpc::Status JanusdImpl::GetGuardState(grpc::ServerContext *context [[maybe_unused]], const janus::Empty *request [[maybe_unused]],
    grpc::ServerWriter<janus::JanusdHandle> *writer) {

    std::for_each(guards_.cbegin(), guards_.cend(), [&](const std::shared_ptr<janus::JanusdHandle> guard) {
        if (!writer->Write(*guard)) {
            // Broken stream.
        }
    });
    return grpc::Status::OK;
}

/**
 * Return list of PIDs looked up by container IDs from request.
 *
 * @param request
 * @return
 */
std::vector<int> JanusdImpl::getPidsFromRequest(std::shared_ptr<janus::JanusdConfig> request) {
    std::vector<int> pids;
    std::for_each(request->cid().cbegin(), request->cid().cend(), [&](std::string cid) {
        std::string runtime = clustergarage::container::Util::findContainerRuntime(cid);
        cleanContainerId(cid, runtime);
        int pid = clustergarage::container::Util::getPidForContainer(cid, runtime);
        if (pid) {
            pids.push_back(pid);
        }
    });
    return pids;
}

/**
 * Returns stored guard that pertains to a list of PIDs on a specific node.
 *
 * @param nodeName
 * @param pids
 * @return
 */
std::shared_ptr<janus::JanusdHandle> JanusdImpl::findJanusdGuardByPids(const std::string nodeName, const std::vector<int> pids) {
    auto it = find_if(guards_.cbegin(), guards_.cend(), [&](std::shared_ptr<janus::JanusdHandle> guard) {
        bool foundPid = false;
        for (const auto &pid : pids) {
            auto guardPid = std::find_if(guard->pid().cbegin(), guard->pid().cend(),
                [&](int p) { return p == pid; });
            foundPid = guardPid != guard->pid().cend();
        }
        return guard->nodename() == nodeName && foundPid;
    });
    if (it != guards_.cend()) {
        return *it;
    }
    return nullptr;
}

/**
 * Returns array of char buffer paths given a subject. These prepend
 * /proc/{PID}/root on each path so we can monitor via profs directly to allow
 * or deny permission requests.
 *
 * @param pid
 * @param subject
 * @return
 */
char **JanusdImpl::getPathArrayFromVector(const int pid, const google::protobuf::RepeatedPtrField<std::string> &vec) {
    std::vector<std::string> pathvec;
    std::for_each(vec.cbegin(), vec.cend(), [&](std::string path) {
        std::stringstream ss;
        ss << "/proc/" << pid << "/root" << path.c_str();
        pathvec.push_back(ss.str());
    });

    char **patharr = new char *[pathvec.size()];
    for(size_t i = 0; i < pathvec.size(); ++i) {
        patharr[i] = new char[pathvec[i].size() + 1];
        strcpy(patharr[i], pathvec[i].c_str());
    }
    return patharr;
}

/**
 * Returns a comma-separated list of key=value pairs for a subject tag map.
 *
 * @param subject
 * @return
 */
std::string JanusdImpl::getTagListFromSubject(std::shared_ptr<janus::JanusGuardSubject> subject) {
    std::string tags;
    for (auto tag : subject->tags()) {
        if (!tags.empty()) {
            tags += ",";
        }
        tags += tag.first + "=" + tag.second;
    }
    return tags;
}

/**
 * Returns a bitwise-OR combined event mask given a subject. The subject->event
 * can be an array of strings that match directly to an `fanotify` event.
 *
 * @param subject
 * @return
 */
uint32_t JanusdImpl::getEventMaskFromSubject(std::shared_ptr<janus::JanusGuardSubject> subject) {
    uint32_t mask = 0;
    std::for_each(subject->event().cbegin(), subject->event().cend(), [&](std::string event) {
        const char *evt = event.c_str();
        if (strcmp(evt, "all") == 0)         mask |= FAN_ACCESS_PERM | FAN_OPEN_PERM;
        else if (strcmp(evt, "access") == 0) mask |= FAN_ACCESS_PERM;
        else if (strcmp(evt, "open") == 0)   mask |= FAN_OPEN_PERM;
    });
    return mask;
}

/**
 * Create child processes as background threads for spawning a janusnotify
 * guard. We will create an anonymous pipe used to communicate to this
 * background thread later from this implementation; in the case of
 * updating/deleting an existing guard. An additional cleanup thread is created
 * to specify removing the anonymous pipe in the case of an error returned by
 * the janusnotify poller.
 *
 * @param guardName
 * @param nodeName
 * @param podName
 * @param subject
 * @param pid
 * @param sid
 * @param eventProcessfds
 * @param logFormat
 */
void JanusdImpl::createFanotifyGuard(const std::string guardName, const std::string nodeName, const std::string podName,
    std::shared_ptr<janus::JanusGuardSubject> subject, const int pid, const int sid,
    google::protobuf::RepeatedField<google::protobuf::int32> *eventProcessfds, const std::string logFormat) {

    // Create anonymous pipe to communicate with `fanotify` guard.
    const int processfd = eventfd(0, EFD_CLOEXEC);
    if (processfd == EOF) {
        return;
    }
    eventProcessfds->Add(processfd);

    std::packaged_task<int(char *, int, int, char *, char *, unsigned int, char **, unsigned int, char **, uint32_t,
        int, char *, char *, void(struct janusguard_event *))> task(start_fanotify_guard);
    std::shared_future<int> result(task.get_future());

    std::thread taskThread(std::move(task),
		convertStringToCString(guardName),
		pid, sid,
		convertStringToCString(nodeName),
		convertStringToCString(podName),
        subject->allow_size(), getPathArrayFromVector(pid, subject->allow()),
        subject->deny_size(), getPathArrayFromVector(pid, subject->deny()),
        getEventMaskFromSubject(subject),
		processfd,
		convertStringToCString(getTagListFromSubject(subject)),
		convertStringToCString(logFormat),
		logJanusGuardEvent);
    // Start as daemon process.
    taskThread.detach();

    // Once the janusnotify task begins we listen for a return status in a
    // separate, cleanup thread. When this result comes back, we do any
    // necessary cleanup here, such as destroy our anonymous pipe into the
    // janusnotify poller.
    std::thread cleanupThread([=](std::shared_future<int> res) mutable {
        res.wait();
        if (res.valid()) {
            auto guard = findJanusdGuardByPids(nodeName, std::vector<int>{pid});
            if (guard != nullptr) {
                eraseEventProcessfd(guard->mutable_processeventfd(), processfd);
                // Notify the `condition_variable` of changes.
                cv_.notify_one();
            }
        }
    }, result);
    cleanupThread.detach();
}

/**
 * Sends a message over the anonymous pipe to stop the janusnotify poller.
 *
 * @param guard
 */
void JanusdImpl::sendKillSignalToGuard(std::shared_ptr<janus::JanusdHandle> guard) {
    // Kill existing guard polls.
    std::for_each(guard->processeventfd().cbegin(), guard->processeventfd().cend(), [&](const int processfd) {
        send_guard_kill_signal(processfd);
    });
}

/**
 * Shuts down the anonymous pipe used to communicate by the janusnotify poller
 * and removes it from the stored collection of pipes.
 *
 * @param eventProcessfds
 * @param processfd
 */
void JanusdImpl::eraseEventProcessfd(google::protobuf::RepeatedField<google::protobuf::int32> *eventProcessfds, const int processfd) {
    if (eventProcessfds->empty()) {
       return;
    }
    for (auto it = eventProcessfds->cbegin(); it != eventProcessfds->cend(); ++it) {
       if (*it == processfd) {
           eventProcessfds->erase(it);
           break;
       }
    }
}
} // namespace janusd

#ifdef __cplusplus
extern "C" {
#endif
void logJanusGuardEvent(struct janusguard_event *jgevent) {
	/**
	 * Default logging format.
     *
     * @specifier pod      Name of the pod.
     * @specifier node     Name of the node.
     * @specifier allow    Evaluates to "allow" or "deny".
	 * @specifier event    `fanotify` event that was observed.
     * @specifier path     Name of the directory+file path.
     * @specifier ftype    Evaluates to "file" or "directory".
     * @specifier tags     List of custom tags in key=value comma-separated list.
	 */
    const std::string kDefaultFormat = "[{allow}] {event} {ftype} '{path}' ({pod}:{node}) {tags}";

    std::regex procRegex("/proc/[0-9]+/root");

    std::string maskStr;
    if (jgevent->event_mask & FAN_ACCESS_PERM)    maskStr = "ACCESS_PERM";
    else if (jgevent->event_mask & FAN_OPEN_PERM) maskStr = "OPEN_PERM";

    fmt::memory_buffer out;
    try {
        fmt::format_to(out, *jgevent->guard->log_format ? std::string(jgevent->guard->log_format) : kDefaultFormat,
            fmt::arg("allow", jgevent->allow ? "ALLOW" : "DENY"),
            fmt::arg("event", maskStr),
            fmt::arg("ftype", jgevent->is_dir ? "directory" : "file"),
            fmt::arg("path", std::regex_replace(jgevent->path_name, procRegex, "")),
            fmt::arg("pod", jgevent->guard->pod_name),
            fmt::arg("node", jgevent->guard->node_name),
            fmt::arg("tags", *jgevent->guard->tags ? jgevent->guard->tags : ""));
        LOG(INFO) << fmt::to_string(out);
    } catch(const std::exception &e) {
        LOG(WARNING) << "Malformed JanusGuard `.spec.logFormat`: \"" << e.what() << "\"";
    }
}
#ifdef __cplusplus
}; // extern "C"
#endif
