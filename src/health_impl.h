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

#ifndef __HEALTH_IMPL_H__
#define __HEALTH_IMPL_H__

#include <janus-proto/c++/health.grpc.pb.h>

namespace janusdhealth {
class HealthImpl final : public grpc::health::v1::Health::Service {
public:
    explicit HealthImpl() = default;
    ~HealthImpl() final = default;

    grpc::Status Check(grpc::ServerContext *context, const grpc::health::v1::HealthCheckRequest *request,
        grpc::health::v1::HealthCheckResponse *response) override;
    void SetStatus(const grpc::string &service, grpc::health::v1::HealthCheckResponse::ServingStatus status);
    void SetAll(grpc::health::v1::HealthCheckResponse::ServingStatus status);
    void ClearStatus(const std::string &service);
    void ClearAll();

private:
    std::mutex mux_;
    std::map<const grpc::string, grpc::health::v1::HealthCheckResponse::ServingStatus> statuses_;
};
} // namespace janusdhealth

#endif
