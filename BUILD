load("@npm//:defs.bzl", "npm_link_all_packages")
load("@aspect_rules_js//npm:defs.bzl", "npm_link_package", "npm_package")
load("@aspect_bazel_lib//lib:copy_to_bin.bzl", "copy_to_bin")

npm_link_all_packages(name = "node_modules")

exports_files([
    "package.json",
    "tsconfig.json",
])

npm_link_package(
    name = "node_modules/@logos/web",
    src = "@logos//:npm",
)

copy_to_bin(
    name = "tsconfig",
    srcs = ["tsconfig.json"],
    visibility = [
        "//app:__subpackages__",
    ],
)

npm_package(
    name = "npm",
    srcs = [
        "//:package.json",
        "//app/auth/cognito/web",
    ],
    package = "@logos/app-auth-cognito",
    visibility = ["//visibility:public"],
)
