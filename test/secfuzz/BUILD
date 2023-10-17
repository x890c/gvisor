load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "secfuzz",
    testonly = 1,
    srcs = [
        "secfuzz.go",
        "secfuzz_covermeup.go",
    ],
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/abi",
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/bpf",
        "//pkg/seccomp",
    ],
)
