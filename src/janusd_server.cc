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

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <grpc/grpc.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/security/server_credentials.h>

#include "janusd_auth.h"
#include "janusd_impl.h"
#include "health_impl.h"

#define PORT 50051

DEFINE_bool(tls, false, "run server with TLS enabled");
DEFINE_string(tlscafile, "", "file containing trusted certificates for verifying the client");
DEFINE_string(tlscertfile, "", "file containing the server certificate for authenticating with the client");
DEFINE_string(tlskeyfile, "", "file containing the server private key for authenticating with the client");

int main(int argc, char **argv) {
    google::ParseCommandLineFlags(&argc, &argv, true);
    google::InitGoogleLogging(argv[0]);
    google::InstallFailureSignalHandler();
    FLAGS_stderrthreshold = google::INFO;
    FLAGS_colorlogtostderr = true;

    auto readfile = [](const std::string &filename) -> std::string {
        std::ifstream fh(filename);
        std::stringstream buffer;
        buffer << fh.rdbuf();
        fh.close();
        return buffer.str();
    };

    std::shared_ptr<grpc::ServerCredentials> credentials;
    if (FLAGS_tls) {
        if (FLAGS_tlscertfile.empty() ||
            FLAGS_tlskeyfile.empty()) {
            LOG(WARNING) << "Certificate/private key not supplied (with -tls flag).";
            return 1;
        }
        std::string key(readfile(FLAGS_tlskeyfile));
        std::string cert(readfile(FLAGS_tlscertfile));
        // The client must present a cert every time a call is made, else it
        // will only happen once when the first connection is made.
        // The other options can be found here:
        // http://www.grpc.io/grpc/core/grpc__security__constants_8h.html#a29ffe63a8bb3b4945ecab42d82758f09
        grpc::SslServerCredentialsOptions sslopts(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
        grpc::SslServerCredentialsOptions::PemKeyCertPair keycert = {key, cert};
        sslopts.pem_key_cert_pairs.push_back(keycert);
        if (!FLAGS_tlscafile.empty()) {
            sslopts.pem_root_certs = readfile(FLAGS_tlscafile);
        }
        credentials = grpc::SslServerCredentials(sslopts);

        //std::shared_ptr<janusd::JanusdAuthMetadataProcessor> authproc(new janusd::JanusdAuthMetadataProcessor());
        //credentials->SetAuthMetadataProcessor(authproc);
    } else {
        credentials = grpc::InsecureServerCredentials();
    }

    std::stringstream ss;
    ss << "0.0.0.0:" << PORT;
    std::string serverAddress(ss.str());
    grpc::ServerBuilder builder;
    builder.AddListeningPort(serverAddress, credentials);

    janusd::JanusdImpl janusdSvc;
    builder.RegisterService(&janusdSvc);
    janusdhealth::HealthImpl healthSvc;
    builder.RegisterService(&healthSvc);

    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    LOG(INFO) << "Server listening on " << serverAddress;
    server->Wait();

    google::ShutdownGoogleLogging();
    google::ShutDownCommandLineFlags();
    return 0;
}
