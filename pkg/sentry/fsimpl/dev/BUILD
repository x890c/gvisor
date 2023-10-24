load("//tools:defs.bzl", "go_library", "go_test")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "dev",
    srcs = [
        "dev.go",
        "save_restore.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/abi/nvgpu",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fd",
        "//pkg/fspath",
        "//pkg/lisafs",
        "//pkg/sentry/fsimpl/tmpfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/unet",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "dev_test",
    size = "small",
    srcs = ["dev_test.go"],
    library = ":dev",
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fspath",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fsimpl/tmpfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
    ],
)
