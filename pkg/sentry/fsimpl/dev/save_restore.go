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

package dev

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// PreprareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
func (fs *filesystem) PrepareSave(ctx context.Context) error { return nil }

// CompleteRestore implements
// vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(ctx context.Context, opts vfs.CompleteRestoreOptions) error {
	if fs.uniqueID == "" {
		return nil
	}
	fdmapv := ctx.Value(vfs.CtxRestoreFilesystemFDMap)
	if fdmapv == nil {
		return fmt.Errorf("no server FD map available")
	}
	fdmap := fdmapv.(map[string]int)
	fd, ok := fdmap[fs.uniqueID]
	if !ok {
		return fmt.Errorf("no server FD available for filesystem with unique ID %q", fs.uniqueID)
	}
	var err error
	fs.goferFD, err = connectClient(ctx, fd)
	return err
}
