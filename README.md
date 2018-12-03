# janusd

[![Docker Automated build](https://img.shields.io/docker/build/clustergarage/janusd.svg?style=flat-square)](https://hub.docker.com/r/clustergarage/janusd)

This repository implements a daemon process responsible for maintaining a collection of `fanotify`-style listeners defined by the user to gain insights into when certain key events happen at the filesystem level of their container.

## Purpose

This daemon is able to perform a series of flexible tasks combined with a rich set of configurations around watching inode events:

- Serves a gRPC endpoint running on each node, that can be communicated with by the Kubernetes [janus-controller](https://github.com/clustergarage/janus-controller).
- Extends out-of-the-box `fanotify` with recursive file tree options.
- Handles multi-threaded operations of creating watches, handling event stream message and logging them in a common, configurable way.
- Reports its current state back to the controller, which syncs current state with desired.
- Perform health checks for readiness and liveness probes in Kubernetes.

## Usage

Once cloned you should update the `janus-proto` submodule to make sure it's up-to-date with the latest shared definitions:

```
git submodule foreach git pull origin master
```

#### Prerequisites

- `C++14` &mdash; for runtime, makes use of new language features
- `cmake v3.10+` &mdash; for building the binary locally
- `gRPC` &mdash; as a communication protocol to the controller
- `Protobuf` &mdash; for a common type definition

### Building

To build a local copy of the binary to run or troubleshoot with:

```
mkdir build && cd $_
cmake ..
make -j$(nproc --all)
```

Or if you wish to build as a Docker container and run this from a local registry:

```
docker build -t clustergarage/janusd .
```

### Running

To run locally, you must do so with elevated privilege in order to access the full rights to procfs:

```
# in the build/ directory

# running without secure credentials
sudo ./janusd

# running with secure credentials
sudo ./janusd -tls \
  -tlscafile /etc/ssl/ca.pem \
  -tlscertfile /etc/ssl/cert.pem \
  -tlskeyfile /etc/ssl/key.pem
```

**Warning**: When running the daemon out-of-cluster in a VM-based Kubernetes context, it will fail to locate the PID from the container ID through numerous cgroup checks and will be unable to start any watchers. The solution to get around this is to either run a non-VM-based local Kubernetes, or to run as a pod inside the cluster. The configurations in order to do the latter option are located in the [janus](https://github.com/clustergarage/janus) repo.
