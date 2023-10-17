// Copyright 2023 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package filter_fuzz_test

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap"
	"gvisor.dev/gvisor/runsc/boot/filter"
	"gvisor.dev/gvisor/test/secfuzz"
)

// FuzzFilterOptimizationsResultInConsistentProgram tests that optimizations
// do not affect the behavior of the generated seccomp-bpf program.
func FuzzFilterOptimizationsResultInConsistentProgram(f *testing.F) {
	rules, denyRules := filter.Rules(filter.Options{
		Platform: &systrap.Systrap{},
	})
	ruleSets := []seccomp.RuleSet{
		{
			Rules:  denyRules,
			Action: linux.SECCOMP_RET_ERRNO,
		},
		{
			Rules:  rules,
			Action: linux.SECCOMP_RET_ALLOW,
		},
	}
	unoptimized, _, err := seccomp.BuildProgram(ruleSets, seccomp.ProgramOptions{
		DefaultAction:     seccomp.Return(linux.SECCOMP_RET_ERRNO),
		BadArchAction:     seccomp.Return(linux.SECCOMP_RET_ERRNO),
		SkipOptimizations: true,
	})
	if err != nil {
		f.Fatalf("failed to build unoptimized program: %v", err)
	}
	progUnoptimized := secfuzz.Program{
		Name:         "unoptimized",
		Instructions: unoptimized,

		// We cannot enforce full coverage on the unoptimized program,
		// because some of its checks are impossible to meet.
		// For example, it ends up checking things like
		// "if (A & 0) == 0" when checking both 32-bit halves of a
		// "masked equal" check, and the "false" branch of that can
		// never be covered.
		EnforceFullCoverage: false,
	}
	optimized, _, err := seccomp.BuildProgram(ruleSets, seccomp.ProgramOptions{
		DefaultAction:     seccomp.Return(linux.SECCOMP_RET_ERRNO),
		BadArchAction:     seccomp.Return(linux.SECCOMP_RET_ERRNO),
		SkipOptimizations: false,
	})
	if err != nil {
		f.Fatalf("failed to build optimized program: %v", err)
	}
	progOptimized := secfuzz.Program{
		Name:                "optimized",
		Instructions:        optimized,
		EnforceFullCoverage: true,
	}
	df, err := secfuzz.NewDiffFuzzer(f, &progUnoptimized, &progOptimized)
	if err != nil {
		f.Fatalf("failed to create diff fuzzer: %v", err)
	}
	df.DeriveCorpusFromRuleSets(ruleSets)
	df.Fuzz()
}
