java_library(
    name = "cognito",
    srcs = [
        "CognitoServerInterceptor.java",
    ],
    visibility = ["//app:__subpackages__"],
    deps = [
        "//app/auth/cognito/module/annotation",
        "//app/auth/cognito/module/data",
        "//app/auth/cognito/user",
        "@io_grpc_grpc_java//api",
        "@io_grpc_grpc_java//context",
        "@logos//dev/logos/stack/aws/module",
        "@logos//dev/logos/user",
        "@maven_logos//:com_google_code_gson_gson",
        "@maven_logos//:com_google_guava_guava",
        "@maven_logos//:com_google_inject_guice",
        "@maven_logos//:io_jsonwebtoken_jjwt_api",
        "@maven_logos//:io_jsonwebtoken_jjwt_impl",
        "@maven_logos//:io_jsonwebtoken_jjwt_jackson",
    ],
)
