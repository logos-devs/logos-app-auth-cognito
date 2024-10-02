load("@logos//bzl:proto.bzl", "java_grpc_library", "js_grpc_client")

proto_library(
    name = "protos",
    srcs = [
        "cognito.proto",
    ],
    visibility = [
        "//app/auth/cognito:__subpackages__",
        "//app/auth/cognito/web/client:__pkg__",
    ],
)

java_proto_library(
    name = "java_proto",
    visibility = [
        "//app/auth/cognito:__subpackages__",
    ],
    deps = [":protos"],
)

java_grpc_library(
    name = "java_grpc",
    srcs = [":protos"],
    visibility = [
        "//app/auth/cognito:__subpackages__",
    ],
    deps = [":java_proto"],
)

js_grpc_client(
    name = "grpc_web",
    proto = ":protos",
    visibility = ["//app:__subpackages__"],
)
