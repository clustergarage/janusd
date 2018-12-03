FROM ubuntu:bionic as builder
RUN apt-get update && \
  apt-get install -y cmake g++ gcc git make perl tar wget
ENV GRPC_HEALTH_PROBE_VERSION v0.2.0
# Do this in a new folder `dockerbuild`. `build` is ignored via .dockerignore
# for builds outside docker, so we need to make sure we name this something
# other than `build`.
WORKDIR /opt/janusd/dockerbuild
COPY . /opt/janusd
RUN cmake -DCMAKE_MAKE_PROGRAM=make \
    -DCMAKE_C_COMPILER=gcc \
    -DCMAKE_CXX_COMPILER=g++ .. && \
  # Try and minimize build times by running in parallel according
  # to the number of cores available on the host machine.
  make -j$(nproc --all)
# Include grpc_health_probe for K8s liveness/readiness checks.
RUN wget -qO/bin/grpc_health_probe \
    https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64 && \
  chmod +x /bin/grpc_health_probe

FROM alpine:latest
COPY --from=builder /opt/janusd/dockerbuild/janusd /
COPY --from=builder /bin/grpc_health_probe /bin/
# glog requires /tmp to exist as log_dir is /tmp by default.
COPY --from=builder /tmp /tmp
CMD ["/janusd"]
