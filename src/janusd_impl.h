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

#ifndef __JANUSD_IMPL_H__
#define __JANUSD_IMPL_H__

#include <future>
#include <vector>

#include <janus-proto/c++/janus.grpc.pb.h>
#include <libcontainer/container_util.h>

namespace janusd {
class JanusdImpl final : public janus::Janusd::Service {
public:
    explicit JanusdImpl() = default;
    ~JanusdImpl() final = default;

    grpc::Status CreateWatch(grpc::ServerContext *context, const janus::JanusdConfig *request, janus::JanusdHandle *response) override;
    grpc::Status DestroyWatch(grpc::ServerContext *context, const janus::JanusdConfig *request, janus::Empty *response) override;
    grpc::Status GetWatchState(grpc::ServerContext *context, const janus::Empty *request, grpc::ServerWriter<janus::JanusdHandle> *writer) override;

private:
    std::vector<int> getPidsFromRequest(std::shared_ptr<janus::JanusdConfig> request);
    std::shared_ptr<janus::JanusdHandle> findJanusdWatcherByPids(std::string nodeName, std::vector<int> pids);
    char **getPathArrayFromVector(int pid, const google::protobuf::RepeatedPtrField<std::string> &vec);
    uint32_t getEventMaskFromSubject(std::shared_ptr<janus::JanusWatcherSubject> subject);
    void createFanotifyWatcher(std::string nodeName, std::string podName, std::shared_ptr<janus::JanusWatcherSubject> subject,
        int pid, int sid, google::protobuf::RepeatedField<google::protobuf::int32> *procFds);
    void sendKillSignalToWatcher(std::shared_ptr<janus::JanusdHandle> watcher);
    void eraseEventProcessfd(google::protobuf::RepeatedField<google::protobuf::int32> *eventProcessfds, int processfd);

    /**
     * Helper function to remove prepended container protocol from `containerId`
     * given a prefix; currently docker|cri-o|rkt|containerd.
     *
     * @param containerId
     * @param prefix
     */
    inline void cleanContainerId(std::string &containerId, const std::string &prefix) const {
        clustergarage::container::Util::eraseSubstr(containerId, prefix + "://");
    }

    std::vector<std::shared_ptr<janus::JanusdHandle>> watchers_;
    std::condition_variable cv_;
    std::mutex mux_;
};
} // namespace janusd

#endif
