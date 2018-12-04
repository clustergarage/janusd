cmake_minimum_required(VERSION 3.10)
project(JanusD VERSION 0.1.0 LANGUAGES C CXX)

include(ExternalProject)

set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -std=c++17)
set(CMAKE_EXE_LINKER_FLAGS -static)
set(CMAKE_BUILD_TYPE Release)

find_package(Threads REQUIRED)
find_library(RT_LIBRARY NAMES librt.a rt REQUIRED)
find_library(PTHREAD_LIBRARY NAMES libpthread.a pthread REQUIRED)
find_library(DL_LIBRARY NAMES libdl.a dl REQUIRED)

# Builds c-ares project from the git repo.
ExternalProject_Add(c-ares
  PREFIX c-ares
  GIT_REPOSITORY https://github.com/c-ares/c-ares
  GIT_TAG cares-1_15_0
  CMAKE_CACHE_ARGS
    -DCARES_STATIC:BOOL=ON
    -DCARES_STATIC_PIC:BOOL=ON
    -DCARES_SHARED:BOOL=OFF
    -DCARES_BUILD_TESTS:BOOL=OFF
    -DCARES_BUILD_TOOLS:BOOL=OFF
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
)
set(CARES_LIBRARY ${CMAKE_CURRENT_BINARY_DIR}/c-ares/lib/libcares.a)

# Builds zlib project from the git repo.
ExternalProject_Add(zlib
  PREFIX zlib
  GIT_REPOSITORY https://github.com/madler/zlib
  GIT_TAG v1.2.11
  UPDATE_COMMAND ""
  CMAKE_CACHE_ARGS
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
)
set(ZLIB_LIBRARY ${CMAKE_CURRENT_BINARY_DIR}/zlib/lib/libz.a)

# Builds openssl project from the git repo.
ExternalProject_Add(openssl
  PREFIX openssl
  GIT_REPOSITORY https://github.com/openssl/openssl
  GIT_TAG OpenSSL_1_1_1
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND ./config
    --prefix=${CMAKE_CURRENT_BINARY_DIR}/openssl
    --openssldir=${CMAKE_CURRENT_BINARY_DIR}/openssl
    -fPIC
    no-async no-shared no-unit-test
  INSTALL_COMMAND make install_sw
  CMAKE_CACHE_ARGS
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
)
ExternalProject_Get_Property(openssl BINARY_DIR)
set(OPENSSL_FOUND TRUE)
set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
set(OPENSSL_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libssl.a)
set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libcrypto.a)

## Builds protobuf project from the git repo.
ExternalProject_Add(protobuf
  PREFIX protobuf
  DEPENDS zlib
  GIT_REPOSITORY https://github.com/google/protobuf
  GIT_TAG v3.6.1
  SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/protobuf/src/protobuf
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND ${CMAKE_COMMAND} cmake/
    -Dprotobuf_BUILD_SHARED_LIBS:BOOL=OFF
    -Dprotobuf_BUILD_TESTS:BOOL=OFF
    -Dprotobuf_BUILD_CONFORMANCE:BOOL=OFF
    -Dprotobuf_BUILD_EXAMPLES:BOOL=OFF
    -Dprotobuf_WITH_ZLIB:BOOL=OFF
    -Dprotobuf_MSVC_STATIC_RUNTIME:BOOL=OFF
    -DZLIB_ROOT:STRING=${ZLIB_INSTALL}
    -DCMAKE_VERBOSE_MAKEFILE:BOOL=OFF
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
  CMAKE_CACHE_ARGS
    -Dprotobuf_BUILD_SHARED_LIBS:BOOL=OFF
    -Dprotobuf_BUILD_TESTS:BOOL=OFF
    -Dprotobuf_BUILD_CONFORMANCE:BOOL=OFF
    -Dprotobuf_BUILD_EXAMPLES:BOOL=OFF
    -Dprotobuf_WITH_ZLIB:BOOL=OFF
    -Dprotobuf_MSVC_STATIC_RUNTIME:BOOL=OFF
    -DZLIB_ROOT:STRING=${ZLIB_INSTALL} -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
)
ExternalProject_Get_Property(protobuf BINARY_DIR)
set(PROTOBUF_FOUND TRUE)
set(PROTOBUF_ROOT_DIR ${CMAKE_CURRENT_BINARY_DIR}/protobuf)
set(PROTOBUF_INCLUDE_DIR ${PROTOBUF_ROOT_DIR}/include)
set(PROTOBUF_LIBRARY ${PROTOBUF_ROOT_DIR}/lib/libprotobuf.a)

# Builds gflags project from the git repo.
ExternalProject_Add(gflags
  PREFIX gflags
  GIT_REPOSITORY https://github.com/gflags/gflags
  GIT_TAG v2.2.2
  CMAKE_CACHE_ARGS
    -DBUILD_SHARED_LIBS:BOOL=OFF
    -DBUILD_STATIC_LIBS:BOOL=ON
    -DBUILD_PACKAGING:BOOL=OFF
    -DBUILD_TESTING:BOOL=OFF
    -DBUILD_NC_TESTS:BOOL=OFF
    -DBUILD_CONFIG_TESTS:BOOL=OFF
    -DBUILD_gflags_LIB:BOOL=ON
    -DINSTALL_HEADERS:BOOL=ON
    -DGFLAGS_NAMESPACE:STRING=google
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
)
set(GFLAGS_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/gflags/include)
set(GFLAGS_LIBRARY ${CMAKE_CURRENT_BINARY_DIR}/gflags/lib/libgflags.a)

# Builds grpc project from the git repo.
ExternalProject_Add(grpc
  PREFIX grpc
  DEPENDS c-ares gflags openssl protobuf zlib
  GIT_REPOSITORY https://github.com/grpc/grpc
  GIT_TAG v1.16.1
  CMAKE_CACHE_ARGS
    -DgRPC_BUILD_TESTS:BOOL=OFF
    -DgRPC_BUILD_CSHARP_EXT:BOOL=OFF
    -DgRPC_USE_PROTO_LITE:BOOL=ON
    -DgRPC_INSTALL:BOOL=ON
    -DgRPC_CARES_PROVIDER:STRING=package
    -DgRPC_GFLAGS_PROVIDER:STRING=package
    -DgRPC_PROTOBUF_PROVIDER:STRING=package
    -DgRPC_PROTOBUF_PACKAGE_TYPE:STRING=CONFIG
    -DgRPC_SSL_PROVIDER:STRING=package
    -DgRPC_ZLIB_PROVIDER:STRING=package
    -Dc-ares_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}/c-ares/lib/cmake/c-ares
    -DProtobuf_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}/protobuf/lib/cmake/protobuf
    -DZLIB_ROOT:PATH=${CMAKE_CURRENT_BINARY_DIR}/zlib
    -DOPENSSL_USE_STATIC_LIBS:BOOL=ON
    -DOPENSSL_ROOT_DIR:PATH=${OPENSSL_ROOT_DIR}
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
)
set(gRPC_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/grpc/include)
set(gRPC_LIBRARY ${CMAKE_CURRENT_BINARY_DIR}/grpc/lib/libgrpc++.a
  ${CMAKE_CURRENT_BINARY_DIR}/grpc/lib/libgrpc.a
  ${CMAKE_CURRENT_BINARY_DIR}/grpc/lib/libgpr.a
  ${CMAKE_CURRENT_BINARY_DIR}/grpc/lib/libaddress_sorting.a)

# Builds glog project from the git repo.
ExternalProject_Add(glog
  PREFIX glog
  DEPENDS gflags
  GIT_REPOSITORY https://github.com/google/glog
  GIT_TAG v0.3.5
  CMAKE_ARGS
    -DCMAKE_CXX_FLAGS="-Wl,--eh-frame-hdr"
  CMAKE_CACHE_ARGS
    -DBUILD_SHARED_LIBS:BOOL=OFF
    -DBUILD_TESTING:BOOL=OFF
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
)
set(GLOG_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/glog/include)
set(GLOG_LIBRARY ${CMAKE_CURRENT_BINARY_DIR}/glog/lib/libglog.a)

# Builds fmt project from the git repo.
ExternalProject_Add(fmt
  PREFIX fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt
  GIT_TAG 5.2.1
  CMAKE_CACHE_ARGS
    -DFMT_DOC:BOOL=OFF
    -DFMT_TEST:BOOL=OFF
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
)
set(FMT_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/fmt/include)
set(FMT_LIBRARY ${CMAKE_CURRENT_BINARY_DIR}/fmt/lib/libfmt.a)

# Builds libcontainer project from the git repo.
ExternalProject_Add(libcontainer
  PREFIX libcontainer
  GIT_REPOSITORY https://github.com/clustergarage/libcontainer
  GIT_TAG v0.1.0
  CMAKE_CACHE_ARGS
    -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
)
set(LIBCONTAINER_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/libcontainer/include)
set(LIBCONTAINER_LIBRARY ${CMAKE_CURRENT_BINARY_DIR}/libcontainer/lib/libcontainer.a)

include_directories(${CMAKE_CURRENT_BINARY_DIR}
  ${PROJECT_SOURCE_DIR}/lib
  # Include generated *.pb.h files.
  ${PROJECT_SOURCE_DIR}/janus-proto
  PRIVATE ${PROTOBUF_INCLUDE_DIR}
  PRIVATE ${GFLAGS_INCLUDE_DIR}
  PRIVATE ${GLOG_INCLUDE_DIR}
  PRIVATE ${gRPC_INCLUDE_DIR}
  PRIVATE ${FMT_INCLUDE_DIR}
  PRIVATE ${LIBCONTAINER_INCLUDE_DIR}
)
add_subdirectory(lib)
add_subdirectory(janus-proto)

set(JANUS_PROTO_SRCS ${PROJECT_SOURCE_DIR}/janus-proto/c++/janus.pb.cc
  ${PROJECT_SOURCE_DIR}/janus-proto/c++/health.pb.cc)
set(JANUS_GRPC_SRCS ${PROJECT_SOURCE_DIR}/janus-proto/c++/janus.grpc.pb.cc
  ${PROJECT_SOURCE_DIR}/janus-proto/c++/health.grpc.pb.cc)

add_executable(janusd
  src/janusd_server.cc
  src/janusd_impl.cc
  src/janusd_auth.cc
  src/health_impl.cc
  ${JANUS_PROTO_SRCS}
  ${JANUS_GRPC_SRCS}
)
add_dependencies(janusd janusnotify libcontainer grpc glog)
target_include_directories(janusd
  # Include headers from directories like <[lib|janus-proto]/file.h>.
  PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(janusd
  janusnotify
  ${LIBCONTAINER_LIBRARY}
  ${FMT_LIBRARY}
  ${gRPC_LIBRARY}
  ${GLOG_LIBRARY}
  ${GFLAGS_LIBRARY}
  ${PROTOBUF_LIBRARY}
  ${OPENSSL_LIBRARY}
  ${OPENSSL_CRYPTO_LIBRARY}
  ${ZLIB_LIBRARY}
  ${CARES_LIBRARY}
  -Wl,--whole-archive ${CMAKE_THREAD_LIBS_INIT} -Wl,--no-whole-archive
  ${RT_LIBRARY}
  ${PTHREAD_LIBRARY}
  ${DL_LIBRARY}
)

# Strip all symbols from built binary.
add_custom_command(TARGET janusd POST_BUILD
  COMMAND strip -s $<TARGET_FILE:janusd>)
