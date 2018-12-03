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

#include "janusd_auth.h"

#include <string>

#include <grpc/grpc.h>
#include <grpc++/grpc++.h>

namespace janusd {
/**
 * Currently unused. Perform custom authentication actions here, if desired.
 *
 * @param authMetadata
 * @param context
 * @param consumedAuthMetadata
 * @param responseMetadata
 * @return
 */
grpc::Status JanusdAuthMetadataProcessor::Process(const grpc::AuthMetadataProcessor::InputMetadata &authMetadata,
    grpc::AuthContext *context [[maybe_unused]], grpc::AuthMetadataProcessor::OutputMetadata *consumedAuthMetadata [[maybe_unused]],
    grpc::AuthMetadataProcessor::OutputMetadata *responseMetadata [[maybe_unused]]) {

    for (const auto &meta : authMetadata) {
        std::string key(meta.first.begin(), meta.first.end());
        std::string val(meta.second.begin(), meta.second.end());
    }
    return grpc::Status::OK;
}
} // namespace janusd
