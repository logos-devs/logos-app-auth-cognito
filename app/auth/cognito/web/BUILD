load("@aspect_rules_ts//ts:defs.bzl", "ts_project")

ts_project(
    name = "web",
    srcs = [
        "components/profile-button.ts",
        "module/auth-module.ts",
        "state.ts",
    ],
    composite = True,
    declaration = True,
    resolve_json_module = True,
    source_map = True,
    transpiler = "tsc",
    tsconfig = "//:tsconfig",
    visibility = ["//visibility:public"],
    deps = [
        "//:node_modules/@spectrum-web-components/action-menu",
        "//:node_modules/@spectrum-web-components/button",
        "//:node_modules/@spectrum-web-components/menu",
        "//:node_modules/@spectrum-web-components/overlay",
        "//:node_modules/@types/node",
        "//:node_modules/grpc-web",
        "//:node_modules/inversify",
        "//:node_modules/lit",
        "//:node_modules/lit-html",
        "//:node_modules/mobx",
        "//:node_modules/reflect-metadata",
        "//app/auth/cognito/proto:grpc_web",
        "@logos//dev/logos/web",
    ],
)
