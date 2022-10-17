// Copyright 2018 The gVisor Authors.
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

package pgalloc

import (
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
)

const (
	page     = hostarch.PageSize
	hugepage = hostarch.HugePageSize
	topPage  = (1 << 63) - page
)

// existingSegment represents a range of pages in a test MemoryFile that is not
// void or free.
type existingSegment struct {
	start uint64
	end   uint64
	state int
}

// Possible values for existingSegment.state:
const (
	existingUnspecified = iota
	existingUsed
	existingWaste
	existingReclaiming // or sub-reclaiming
)

func TestFindAllocatable(t *testing.T) {
	for _, test := range []struct {
		name string
		// Initial state:
		chunkHuge []bool
		existing  []existingSegment
		// Allocation parameters:
		length  uint64
		huge    bool
		recycle bool
		dir     Direction
		// Expected outcome:
		want uint64
	}{
		{
			name:   "initial small allocation, bottom-up",
			length: page,
			want:   0,
		},
		{
			name:   "initial small allocation, top-down",
			length: page,
			dir:    TopDown,
			want:   chunkSize - page,
		},
		{
			name:   "initial small allocation, multiple pages, top-down",
			length: 2 * page,
			dir:    TopDown,
			want:   chunkSize - 2*page,
		},
		{
			name:    "initial small allocation, recycling enabled, bottom-up",
			length:  page,
			recycle: true,
			want:    0,
		},
		{
			name:   "initial huge allocation, bottom-up",
			length: hugepage,
			huge:   true,
			want:   0,
		},
		{
			name:   "initial huge allocation, top-down",
			length: hugepage,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize - hugepage,
		},
		{
			name:   "initial huge allocation, multiple pages, top-down",
			length: 2 * hugepage,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize - 2*hugepage,
		},
		{
			name:    "initial huge allocation, recycling enabled, bottom-up",
			length:  hugepage,
			huge:    true,
			recycle: true,
			want:    0,
		},
		{
			name:      "huge allocation uses huge pages in new chunk",
			chunkHuge: []bool{false},
			length:    hugepage,
			huge:      true,
			want:      chunkSize,
		},
		{
			name:      "huge allocation uses huge pages in existing chunk",
			chunkHuge: []bool{false, true},
			length:    hugepage,
			huge:      true,
			want:      chunkSize,
		},
		{
			name:      "hugepage-sized non-huge allocation uses small pages in new chunk",
			chunkHuge: []bool{true},
			length:    hugepage,
			want:      chunkSize,
		},
		{
			name:      "hugepage-sized non-huge allocation uses small pages in existing chunk",
			chunkHuge: []bool{true, false},
			length:    hugepage,
			want:      chunkSize,
		},
		{
			name:      "bottom-up small allocation begins at start of file",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{page, 2 * page, existingUsed},
			},
			length: page,
			want:   0,
		},
		{
			name:      "top-down small allocation begins at end of last chunk",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - 2*page, chunkSize - page, existingUsed},
			},
			length: page,
			dir:    TopDown,
			want:   chunkSize - page,
		},
		{
			name:      "bottom-up huge allocation begins at start of file",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{hugepage, 2 * hugepage, existingUsed},
			},
			length: hugepage,
			huge:   true,
			want:   0,
		},
		{
			name:      "top-down huge allocation begins at end of last chunk",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - 2*hugepage, chunkSize - hugepage, existingUsed},
			},
			length: hugepage,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize - hugepage,
		},
		{
			name:      "bottom-up small allocation can extend multiple chunks",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize/2 - page, chunkSize / 2, existingUsed},
			},
			length: 2*chunkSize + chunkSize/2,
			want:   chunkSize / 2,
		},
		{
			name:      "top-down small allocation can extend multiple chunks",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize/2 - page, chunkSize / 2, existingUsed},
			},
			length: 2*chunkSize + chunkSize/2,
			dir:    TopDown,
			want:   chunkSize / 2,
		},
		{
			name:      "bottom-up huge allocation can extend multiple chunks",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize/2 - hugepage, chunkSize / 2, existingUsed},
			},
			length: 2*chunkSize + chunkSize/2,
			huge:   true,
			want:   chunkSize / 2,
		},
		{
			name:      "top-down huge allocation can extend multiple chunks",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize/2 - hugepage, chunkSize / 2, existingUsed},
			},
			length: 2*chunkSize + chunkSize/2,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize / 2,
		},
		{
			name:      "bottom-up small allocation finds first free gap",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{0, page, existingUsed},
				{2 * page, 3 * page, existingUsed},
			},
			length: page,
			want:   page,
		},
		{
			name:      "top-down small allocation finds last free gap",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - page, chunkSize, existingUsed},
				{chunkSize - 3*page, chunkSize - 2*page, existingUsed},
			},
			length: page,
			dir:    TopDown,
			want:   chunkSize - 2*page,
		},
		{
			name:      "bottom-up huge allocation finds first free gap",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, hugepage, existingUsed},
				{2 * hugepage, 3 * hugepage, existingUsed},
			},
			length: hugepage,
			huge:   true,
			want:   hugepage,
		},
		{
			name:      "top-down huge allocation finds last free gap",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - hugepage, chunkSize, existingUsed},
				{chunkSize - 3*hugepage, chunkSize - 2*hugepage, existingUsed},
			},
			length: hugepage,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize - 2*hugepage,
		},
		{
			name:      "bottom-up small allocation skips undersized free gap",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{0, page, existingUsed},
				{2 * page, 3 * page, existingUsed},
			},
			length: 2 * page,
			want:   3 * page,
		},
		{
			name:      "top-down small allocation skips undersized free gap",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - page, chunkSize, existingUsed},
				{chunkSize - 3*page, chunkSize - 2*page, existingUsed},
			},
			length: 2 * page,
			dir:    TopDown,
			want:   chunkSize - 5*page,
		},
		{
			name:      "bottom-up huge allocation skips undersized free gap",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, hugepage, existingUsed},
				{2 * hugepage, 3 * hugepage, existingUsed},
			},
			length: 2 * hugepage,
			huge:   true,
			want:   3 * hugepage,
		},
		{
			name:      "top-down huge allocation skips undersized free gap",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - hugepage, chunkSize, existingUsed},
				{chunkSize - 3*hugepage, chunkSize - 2*hugepage, existingUsed},
			},
			length: 2 * hugepage,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize - 5*hugepage,
		},
		{
			name:      "recycling bottom-up small allocation skips used pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{0, page, existingUsed},
			},
			length:  page,
			recycle: true,
			want:    page,
		},
		{
			name:      "recycling top-down small allocation skips used pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - page, chunkSize, existingUsed},
			},
			length:  page,
			recycle: true,
			dir:     TopDown,
			want:    chunkSize - 2*page,
		},
		{
			name:      "recycling bottom-up huge allocation skips used pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, hugepage, existingUsed},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			want:    hugepage,
		},
		{
			name:      "recycling top-down huge allocation skips used pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - hugepage, chunkSize, existingUsed},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			dir:     TopDown,
			want:    chunkSize - 2*hugepage,
		},
		{
			name:      "non-recycling bottom-up small allocation skips waste pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{0, page, existingWaste},
			},
			length: page,
			want:   page,
		},
		{
			name:      "non-recycling top-down small allocation skips waste pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - page, chunkSize, existingWaste},
			},
			length: page,
			dir:    TopDown,
			want:   chunkSize - 2*page,
		},
		{
			name:      "non-recycling bottom-up huge allocation skips waste pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, hugepage, existingWaste},
			},
			length: hugepage,
			huge:   true,
			want:   hugepage,
		},
		{
			name:      "non-recycling top-down huge allocation skips waste pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - hugepage, chunkSize, existingWaste},
			},
			length: hugepage,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize - 2*hugepage,
		},
		{
			name:      "recycling bottom-up small allocation recycles waste pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{0, page, existingWaste},
			},
			length:  page,
			recycle: true,
			want:    0,
		},
		{
			name:      "recycling top-down small allocation recycles waste pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - page, chunkSize, existingWaste},
			},
			length:  page,
			recycle: true,
			dir:     TopDown,
			want:    chunkSize - page,
		},
		{
			name:      "recycling bottom-up huge allocation recycles waste pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, hugepage, existingWaste},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			want:    0,
		},
		{
			name:      "recycling top-down huge allocation recycles waste pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - hugepage, chunkSize, existingWaste},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			dir:     TopDown,
			want:    chunkSize - hugepage,
		},
		{
			name:      "non-recycling bottom-up small allocation skips reclaiming pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{0, page, existingReclaiming},
			},
			length: page,
			want:   page,
		},
		{
			name:      "non-recycling top-down small allocation skips reclaiming pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - page, chunkSize, existingReclaiming},
			},
			length: page,
			dir:    TopDown,
			want:   chunkSize - 2*page,
		},
		{
			name:      "non-recycling bottom-up huge allocation skips reclaiming pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, hugepage, existingReclaiming},
			},
			length: hugepage,
			huge:   true,
			want:   hugepage,
		},
		{
			name:      "non-recycling top-down huge allocation skips reclaiming pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - hugepage, chunkSize, existingReclaiming},
			},
			length: hugepage,
			huge:   true,
			dir:    TopDown,
			want:   chunkSize - 2*hugepage,
		},
		{
			name:      "recycling bottom-up small allocation skips reclaiming pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{0, page, existingReclaiming},
			},
			length:  page,
			recycle: true,
			want:    page,
		},
		{
			name:      "recycling top-down small allocation skips reclaiming pages",
			chunkHuge: []bool{false},
			existing: []existingSegment{
				{chunkSize - page, chunkSize, existingReclaiming},
			},
			length:  page,
			recycle: true,
			dir:     TopDown,
			want:    chunkSize - 2*page,
		},
		{
			name:      "recycling bottom-up huge allocation skips reclaiming pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{0, hugepage, existingReclaiming},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			want:    hugepage,
		},
		{
			name:      "recycling top-down huge allocation skips reclaiming pages",
			chunkHuge: []bool{true},
			existing: []existingSegment{
				{chunkSize - hugepage, chunkSize, existingReclaiming},
			},
			length:  hugepage,
			huge:    true,
			recycle: true,
			dir:     TopDown,
			want:    chunkSize - 2*hugepage,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Build the fake MemoryFile.
			f := &MemoryFile{
				opts: MemoryFileOpts{
					ExpectHugepages:         true,
					DisableMemoryAccounting: true,
				},
			}
			f.initFields()
			f.chunks = make([]chunkInfo, len(test.chunkHuge))
			for i, huge := range test.chunkHuge {
				f.chunks[i].huge = huge
				chunkFR := memmap.FileRange{uint64(i) * chunkSize, uint64(i+1) * chunkSize}
				if huge {
					f.unfreeHuge.RemoveRange(chunkFR)
				} else {
					f.unfreeSmall.RemoveRange(chunkFR)
				}
			}
			for _, es := range test.existing {
				f.forEachChunk(memmap.FileRange{es.start, es.end}, func(chunk *chunkInfo, chunkFR memmap.FileRange) bool {
					unwaste, unfree := &f.unwasteSmall, &f.unfreeSmall
					if chunk.huge {
						unwaste, unfree = &f.unwasteHuge, &f.unfreeHuge
					}
					switch es.state {
					case existingUsed:
						unfree.InsertRange(chunkFR, unfreeInfo{refs: 1})
					case existingWaste:
						unfree.InsertRange(chunkFR, unfreeInfo{refs: 0})
						unwaste.RemoveRange(chunkFR)
					case existingReclaiming:
						unfree.InsertRange(chunkFR, unfreeInfo{refs: 0})
					default:
						t.Fatalf("existingSegment %+v has unknown state", es)
					}
					return true
				})
			}

			// Perform the test allocation.
			alloc := allocState{
				length: test.length,
				opts: AllocOpts{
					Huge: test.huge,
					Dir:  test.dir,
				},
				huge: test.huge,
			}
			if test.recycle {
				alloc.opts.Mode = AllocateCallerCommit
				alloc.willCommit = true
			}
			fr, err := f.findAllocatableAndMarkUsed(&alloc)
			if err != nil {
				t.Fatalf("findAllocatableAndMarkUsed(%+v): failed: %v, want: %#x\n%v", alloc, err, test.want, f)
			}
			if fr.Start != test.want {
				t.Errorf("findAllocatableAndMarkUsed(%+v): got: start=%#x, want: %#x\n%v", alloc, fr.Start, test.want, f)
			}
			if wantEnd := test.want + test.length; fr.End != wantEnd {
				t.Errorf("findAllocatableAndMarkUsed(%+v): got: end=%#x, want: %#x\n%v", alloc, fr.End, wantEnd, f)
			}
		})
	}
}

// func TestFindUnallocatedRange(t *testing.T) {
// 	for _, test := range []struct {
// 		name       string
// 		usage      *usageSegmentDataSlices
// 		fileSize   int64
// 		length     uint64
// 		alignment  uint64
// 		direction  Direction
// 		want       uint64
// 		expectFail bool
// 	}{
// 		{
// 			name:      "Initial allocation succeeds",
// 			usage:     &usageSegmentDataSlices{},
// 			length:    page,
// 			alignment: page,
// 			direction: BottomUp,
// 			want:      0,
// 		},
// 		{
// 			name:      "Initial allocation succeeds",
// 			usage:     &usageSegmentDataSlices{},
// 			length:    page,
// 			alignment: page,
// 			direction: TopDown,
// 			want:      chunkSize - page, // Grows by chunkSize, allocate down.
// 		},
// 		{
// 			name: "Allocation begins at start of file",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{page},
// 				End:    []uint64{2 * page},
// 				Values: []usageInfo{{refs: 1}},
// 			},
// 			length:    page,
// 			alignment: page,
// 			direction: BottomUp,
// 			want:      0,
// 		},
// 		{
// 			name: "Allocation finds empty space at start of file",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{page},
// 				End:    []uint64{2 * page},
// 				Values: []usageInfo{{refs: 1}},
// 			},
// 			fileSize:  2 * page,
// 			length:    page,
// 			alignment: page,
// 			direction: TopDown,
// 		},
// 		{
// 			name: "Allocation finds empty space at end of file",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{0},
// 				End:    []uint64{page},
// 				Values: []usageInfo{{refs: 1}},
// 			},
// 			fileSize:  2 * page,
// 			length:    page,
// 			alignment: page,
// 			direction: TopDown,
// 			want:      page,
// 		},
// 		{
// 			name: "In-use frames are not allocatable",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{0, page},
// 				End:    []uint64{page, 2 * page},
// 				Values: []usageInfo{{refs: 1}, {refs: 2}},
// 			},
// 			length:    page,
// 			alignment: page,
// 			direction: BottomUp,
// 			want:      2 * page,
// 		},
// 		{
// 			name: "In-use frames are not allocatable",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{0, page},
// 				End:    []uint64{page, 2 * page},
// 				Values: []usageInfo{{refs: 1}, {refs: 2}},
// 			},
// 			fileSize:  2 * page,
// 			length:    page,
// 			alignment: page,
// 			direction: TopDown,
// 			want:      3 * page, // Double fileSize, allocate top-down.
// 		},
// 		{
// 			name: "Reclaimable frames are not allocatable",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{0, page, 2 * page},
// 				End:    []uint64{page, 2 * page, 3 * page},
// 				Values: []usageInfo{{refs: 1}, {refs: 0}, {refs: 1}},
// 			},
// 			length:    page,
// 			alignment: page,
// 			direction: BottomUp,
// 			want:      3 * page,
// 		},
// 		{
// 			name: "Reclaimable frames are not allocatable",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{0, page, 2 * page},
// 				End:    []uint64{page, 2 * page, 3 * page},
// 				Values: []usageInfo{{refs: 1}, {refs: 0}, {refs: 1}},
// 			},
// 			fileSize:  3 * page,
// 			length:    page,
// 			alignment: page,
// 			direction: TopDown,
// 			want:      5 * page, // Double fileSize, grow down.
// 		},
// 		{
// 			name: "Gaps between in-use frames are allocatable",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{0, 2 * page},
// 				End:    []uint64{page, 3 * page},
// 				Values: []usageInfo{{refs: 1}, {refs: 1}},
// 			},
// 			length:    page,
// 			alignment: page,
// 			direction: BottomUp,
// 			want:      page,
// 		},
// 		{
// 			name: "Gaps between in-use frames are allocatable",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{0, 2 * page},
// 				End:    []uint64{page, 3 * page},
// 				Values: []usageInfo{{refs: 1}, {refs: 1}},
// 			},
// 			fileSize:  3 * page,
// 			length:    page,
// 			alignment: page,
// 			direction: TopDown,
// 			want:      page,
// 		},
// 		{
// 			name: "Inadequately-sized gaps are rejected",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{0, 2 * page},
// 				End:    []uint64{page, 3 * page},
// 				Values: []usageInfo{{refs: 1}, {refs: 1}},
// 			},
// 			length:    2 * page,
// 			alignment: page,
// 			direction: BottomUp,
// 			want:      3 * page,
// 		},
// 		{
// 			name: "Inadequately-sized gaps are rejected",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{0, 2 * page},
// 				End:    []uint64{page, 3 * page},
// 				Values: []usageInfo{{refs: 1}, {refs: 1}},
// 			},
// 			fileSize:  3 * page,
// 			length:    2 * page,
// 			alignment: page,
// 			direction: TopDown,
// 			want:      4 * page, // Double fileSize, grow down.
// 		},
// 		{
// 			name: "Alignment is honored at end of file",
// 			usage: &usageSegmentDataSlices{
// 				Start: []uint64{0, hugepage + page},
// 				// Hugepage-sized gap here that shouldn't be allocated from
// 				// since it's incorrectly aligned.
// 				End:    []uint64{page, hugepage + 2*page},
// 				Values: []usageInfo{{refs: 1}, {refs: 1}},
// 			},
// 			length:    hugepage,
// 			alignment: hugepage,
// 			direction: BottomUp,
// 			want:      2 * hugepage,
// 		},
// 		{
// 			name: "Alignment is honored at end of file",
// 			usage: &usageSegmentDataSlices{
// 				Start: []uint64{0, hugepage + page},
// 				// Hugepage-sized gap here that shouldn't be allocated from
// 				// since it's incorrectly aligned.
// 				End:    []uint64{page, hugepage + 2*page},
// 				Values: []usageInfo{{refs: 1}, {refs: 1}},
// 			},
// 			fileSize:  hugepage + 2*page,
// 			length:    hugepage,
// 			alignment: hugepage,
// 			direction: TopDown,
// 			want:      3 * hugepage, // Double fileSize until alignment is satisfied, grow down.
// 		},
// 		{
// 			name: "Alignment is honored before end of file",
// 			usage: &usageSegmentDataSlices{
// 				Start: []uint64{0, 2*hugepage + page},
// 				// Page will need to be shifted down from top.
// 				End:    []uint64{page, 2*hugepage + 2*page},
// 				Values: []usageInfo{{refs: 1}, {refs: 1}},
// 			},
// 			fileSize:  2*hugepage + 2*page,
// 			length:    hugepage,
// 			alignment: hugepage,
// 			direction: TopDown,
// 			want:      hugepage,
// 		},
// 		{
// 			name:      "Allocation doubles file size more than once if necessary",
// 			usage:     &usageSegmentDataSlices{},
// 			fileSize:  page,
// 			length:    4 * page,
// 			alignment: page,
// 			direction: BottomUp,
// 			want:      0,
// 		},
// 		{
// 			name:      "Allocation doubles file size more than once if necessary",
// 			usage:     &usageSegmentDataSlices{},
// 			fileSize:  page,
// 			length:    4 * page,
// 			alignment: page,
// 			direction: TopDown,
// 			want:      0,
// 		},
// 		{
// 			name: "Allocations are compact if possible",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{page, 3 * page},
// 				End:    []uint64{2 * page, 4 * page},
// 				Values: []usageInfo{{refs: 1}, {refs: 2}},
// 			},
// 			fileSize:  4 * page,
// 			length:    page,
// 			alignment: page,
// 			direction: TopDown,
// 			want:      2 * page,
// 		},
// 		{
// 			name: "Top-down allocation within one gap",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{page, 4 * page, 7 * page},
// 				End:    []uint64{2 * page, 5 * page, 8 * page},
// 				Values: []usageInfo{{refs: 1}, {refs: 2}, {refs: 1}},
// 			},
// 			fileSize:  8 * page,
// 			length:    page,
// 			alignment: page,
// 			direction: TopDown,
// 			want:      6 * page,
// 		},
// 		{
// 			name: "Top-down allocation between multiple gaps",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{page, 3 * page, 5 * page},
// 				End:    []uint64{2 * page, 4 * page, 6 * page},
// 				Values: []usageInfo{{refs: 1}, {refs: 2}, {refs: 1}},
// 			},
// 			fileSize:  6 * page,
// 			length:    page,
// 			alignment: page,
// 			direction: TopDown,
// 			want:      4 * page,
// 		},
// 		{
// 			name: "Top-down allocation with large top gap",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{page, 3 * page},
// 				End:    []uint64{2 * page, 4 * page},
// 				Values: []usageInfo{{refs: 1}, {refs: 2}},
// 			},
// 			fileSize:  8 * page,
// 			length:    page,
// 			alignment: page,
// 			direction: TopDown,
// 			want:      7 * page,
// 		},
// 		{
// 			name: "Gaps found with possible overflow",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{page, topPage - page},
// 				End:    []uint64{2 * page, topPage},
// 				Values: []usageInfo{{refs: 1}, {refs: 1}},
// 			},
// 			fileSize:  topPage,
// 			length:    page,
// 			alignment: page,
// 			direction: TopDown,
// 			want:      topPage - 2*page,
// 		},
// 		{
// 			name: "Overflow detected",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{page},
// 				End:    []uint64{topPage},
// 				Values: []usageInfo{{refs: 1}},
// 			},
// 			fileSize:   topPage,
// 			length:     2 * page,
// 			alignment:  page,
// 			direction:  BottomUp,
// 			expectFail: true,
// 		},
// 		{
// 			name: "Overflow detected",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{page},
// 				End:    []uint64{topPage},
// 				Values: []usageInfo{{refs: 1}},
// 			},
// 			fileSize:   topPage,
// 			length:     2 * page,
// 			alignment:  page,
// 			direction:  TopDown,
// 			expectFail: true,
// 		},
// 		{
// 			name: "start may be in the middle of segment",
// 			usage: &usageSegmentDataSlices{
// 				Start:  []uint64{0, 3 * page},
// 				End:    []uint64{2 * page, 4 * page},
// 				Values: []usageInfo{{refs: 1}, {refs: 2}},
// 			},
// 			length:    page,
// 			alignment: page,
// 			direction: BottomUp,
// 			want:      2 * page,
// 		},
// 	} {
// 		name := fmt.Sprintf("%s (%v)", test.name, test.direction)
// 		t.Run(name, func(t *testing.T) {
// 			f := MemoryFile{fileSize: test.fileSize}
// 			if err := f.usage.ImportSortedSlices(test.usage); err != nil {
// 				t.Fatalf("Failed to initialize usage from %v: %v", test.usage, err)
// 			}
// 			if fr, ok := f.findAvailableRange(test.length, test.alignment, test.direction); ok {
// 				if test.expectFail {
// 					t.Fatalf("findAvailableRange(%v, %x, %x, %x, %v): got: %x, want: fail", test.usage, test.fileSize, test.length, test.alignment, test.direction, fr.Start)
// 				}
// 				if fr.Start != test.want {
// 					t.Errorf("findAvailableRange(%v, %x, %x, %x, %v): got: start=%x, want: %x", test.usage, test.fileSize, test.length, test.alignment, test.direction, fr.Start, test.want)
// 				}
// 				if fr.End != test.want+test.length {
// 					t.Errorf("findAvailableRange(%v, %x, %x, %x, %v): got: end=%x, want: %x", test.usage, test.fileSize, test.length, test.alignment, test.direction, fr.End, test.want+test.length)
// 				}
// 			} else if !test.expectFail {
// 				t.Fatalf("findAvailableRange(%v, %x, %x, %x, %v): failed, want: %x", test.usage, test.fileSize, test.length, test.alignment, test.direction, test.want)
// 			}
// 		})
// 	}
// }
