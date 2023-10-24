// Copyright 2020 The gVisor Authors.
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

// Package dev provides a filesystem implementation for /dev.
package dev

import (
	"fmt"
	"path"
	"regexp"
	"strconv"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/unet"
)

// Name is the dev filesystem name.
const Name = "dev"

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct{}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fst FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, source /* source */, tmpfs.Name, &vfs.MountOptions{GetFilesystemOptions: vfs.GetFilesystemOptions{
		Data: "mode=0755", // opts from drivers/base/devtmpfs.c:devtmpfs_init()
	}}, nil)
	if err != nil {
		return nil, nil, err
	}
	defer mntns.DecRef(ctx)

	root := mntns.Root(ctx)
	defer root.DecRef(ctx)

	iopts, _ := opts.InternalData.(InternalData) // If not provided, zero value is OK.

	// Initialize contents.
	if err := userspaceInit(ctx, vfsObj, creds, root, iopts.ShmMode); err != nil {
		return nil, nil, err
	}
	if err := vfsObj.ForEachDevice(func(pathname string, kind vfs.DeviceKind, major, minor uint32, perms uint16) error {
		if pathname == "" {
			return nil
		}
		mode := linux.FileMode(perms)
		switch kind {
		case vfs.CharDevice:
			mode |= linux.S_IFCHR
		case vfs.BlockDevice:
			mode |= linux.S_IFBLK
		default:
			panic(fmt.Sprintf("invalid DeviceKind: %v", kind))
		}
		return CreateDeviceFile(ctx, vfsObj, creds, root, pathname, major, minor, mode, nil /* uid */, nil /* gid */)
	}); err != nil {
		return nil, nil, err
	}
	var goferFD lisafs.ClientFD
	if iopts.GoferFD != nil {
		goferFD, err = connectClient(ctx, iopts.GoferFD.Release())
		if err != nil {
			return nil, nil, err
		}
		if iopts.CreateNvidiaFiles {
			if err := createNvidiaFiles(ctx, vfsObj, creds, root, goferFD, iopts.NvidiaUVMDevMajor); err != nil {
				return nil, nil, err
			}
		}
	}

	fs, err := newFilesystem(ctx, vfsObj, root.Mount().Filesystem(), goferFD, iopts.UniqueID)
	if err != nil {
		return nil, nil, err
	}
	root.Dentry().IncRef() // transferred to caller, as required by
	return &fs.vfsfs, root.Dentry(), nil
}

// Release implements vfs.FilesystemType.Release.
func (fst *FilesystemType) Release(ctx context.Context) {}

// InternalData contains internal data passed in via vfs.GetFilesystemOptions.
type InternalData struct {
	// ShmMode indicates the mode to create the /dev/shm dir with.
	ShmMode *uint16
	// GoferFD is the FD for the dev gofer connection.
	GoferFD *fd.FD

	// The following fields are only set when GoferFD is not nil.

	// UniqueID is an optional opaque string used to reassociate the filesystem
	// with a new server FD during restoration from checkpoint.
	UniqueID string
	// CreateNvidiaFiles indicates whether Nvidia device files should be created
	// using information from the gofer.
	CreateNvidiaFiles bool
	// NvidiaUVMDevMajor is the device major number used for nvidia-uvm.
	NvidiaUVMDevMajor uint32
}

// filesystem is a wrapper, which provides some devfs specific functionality.
//
// +stateify savable
type filesystem struct {
	vfsfs  vfs.Filesystem
	baseFS *vfs.Filesystem
	// This embedding is always baseFS.Impl().
	vfs.FilesystemImpl

	goferFD  lisafs.ClientFD `state:"nosave"`
	uniqueID string
}

func newFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, baseFS *vfs.Filesystem, goferFD lisafs.ClientFD, uniqueID string) (*filesystem, error) {
	fs := filesystem{
		baseFS:         baseFS,
		FilesystemImpl: baseFS.Impl(),
		goferFD:        goferFD,
		uniqueID:       uniqueID,
	}
	fs.vfsfs.Init(vfsObj, baseFS.FilesystemType(), &fs)
	fs.baseFS.IncRef() // Held by fs, and released in fs.Release().
	return &fs, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.baseFS.DecRef(ctx)
	if fs.goferFD.Ok() {
		// Close the connection to the server. This implicitly closes all FDs.
		fs.goferFD.Client().Close()
	}
}

// OpenAt implements vfs.FilesystemImpl.OpenAt. We only intercept OpenAt so we
// can make the device lisafs FD available to tmpfs.filesystem.OpenAt() ->
// VirtualFilesystem.OpenDeviceSpecialFile() implementations.
func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	if fs.goferFD.Ok() {
		// Inject our custom context, which also provides CtxDevGoferClientFD.
		ctx = fs.wrapContext(ctx)
	}
	return fs.FilesystemImpl.OpenAt(ctx, rp, opts)
}

// connectClient establishes the LISAFS connection to the dev gofer server.
// It takes ownership of fd.
func connectClient(ctx context.Context, fd int) (lisafs.ClientFD, error) {
	ctx.UninterruptibleSleepStart(false)
	defer ctx.UninterruptibleSleepFinish(false)

	sock, err := unet.NewSocket(fd)
	if err != nil {
		ctx.Warningf("failed to create socket for dev gofer client: %v", err)
		return lisafs.ClientFD{}, err
	}
	client, rootInode, rootHostFD, err := lisafs.NewClient(sock)
	if err != nil {
		ctx.Warningf("failed to create dev gofer client: %v", err)
		return lisafs.ClientFD{}, err
	}
	if rootHostFD >= 0 {
		_ = unix.Close(rootHostFD)
	}
	return client.NewFD(rootInode.ControlFD), nil
}

func createNvidiaFiles(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, goferFD lisafs.ClientFD, uvmDevMajor uint32) error {
	const nvidiaDevMode = linux.FileMode(linux.S_IFCHR | 0666)
	if err := CreateDeviceFile(ctx, vfsObj, creds, root, "nvidiactl", nvgpu.NV_MAJOR_DEVICE_NUMBER, nvgpu.NV_CONTROL_DEVICE_MINOR, nvidiaDevMode, nil /* uid */, nil /* gid */); err != nil {
		return err
	}
	if err := CreateDeviceFile(ctx, vfsObj, creds, root, "nvidia-uvm", uvmDevMajor, nvgpu.NVIDIA_UVM_PRIMARY_MINOR_NUMBER, nvidiaDevMode, nil /* uid */, nil /* gid */); err != nil {
		return err
	}
	client := goferFD.Client()
	openFDID, _, err := goferFD.OpenAt(ctx, unix.O_RDONLY)
	if err != nil {
		return fmt.Errorf("failed to open dev from gofer: %v", err)
	}
	defer client.CloseFD(ctx, openFDID, true /* flush */)
	openFD := client.NewFD(openFDID)
	nvidiaDeviceRegex := regexp.MustCompile(`^nvidia(\d+)$`)
	const count = int32(64 * 1024)
	for {
		dirents, err := openFD.Getdents64(ctx, count)
		if err != nil {
			return fmt.Errorf("failed to get dirents: %v", err)
		}
		if len(dirents) == 0 {
			break
		}
		for i := range dirents {
			name := string(dirents[i].Name)
			ms := nvidiaDeviceRegex.FindStringSubmatch(name)
			if ms == nil {
				continue
			}
			minor, err := strconv.ParseUint(ms[1], 10, 32)
			if err != nil {
				return fmt.Errorf("invalid nvidia device name %q: %w", name, err)
			}
			if err := CreateDeviceFile(ctx, vfsObj, creds, root, fmt.Sprintf("nvidia%d", minor), nvgpu.NV_MAJOR_DEVICE_NUMBER, uint32(minor), nvidiaDevMode, nil /* uid */, nil /* gid */); err != nil {
				return err
			}
		}
	}
	return nil
}

// filesystemContext implements context.Context by extending an existing
// context.Context with filesystem.
type filesystemContext struct {
	context.Context
	fs *filesystem
}

func (fs *filesystem) wrapContext(ctx context.Context) *filesystemContext {
	return &filesystemContext{
		Context: ctx,
		fs:      fs,
	}
}

// Value implements context.Context.Value.
func (fc *filesystemContext) Value(key any) any {
	switch key {
	case vfs.CtxDevGoferClientFD:
		return fc.fs.goferFD
	default:
		return fc.Context.Value(key)
	}
}

func pathOperationAt(root vfs.VirtualDentry, pathname string) *vfs.PathOperation {
	return &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(pathname),
	}
}

// CreateDeviceFile creates a device special file at the given pathname from root.
func CreateDeviceFile(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, pathname string, major, minor uint32, mode linux.FileMode, uid, gid *uint32) error {
	// Create any parent directories. See
	// devtmpfs.c:handle_create()=>create_path().
	parent := path.Dir(pathname)
	if err := vfsObj.MkdirAllAt(ctx, parent, root, creds, &vfs.MkdirOptions{
		Mode: 0755,
	}, true /* mustBeDir */); err != nil {
		return fmt.Errorf("failed to create device parent directory %q: %v", parent, err)
	}
	created := true
	pop := pathOperationAt(root, pathname)
	if err := vfsObj.MknodAt(ctx, creds, pop, &vfs.MknodOptions{Mode: mode, DevMajor: major, DevMinor: minor}); err != nil {
		if linuxerr.Equals(linuxerr.EEXIST, err) {
			// EEXIST is silently ignored; compare
			// opencontainers/runc:libcontainer/rootfs_linux.go:createDeviceNode().
			created = false
		} else {
			return fmt.Errorf("failed to create device file at %q: %w", pathname, err)
		}
	}
	if created && (uid != nil || gid != nil) {
		var opts vfs.SetStatOptions
		if uid != nil {
			opts.Stat.Mask |= linux.STATX_UID
			opts.Stat.UID = *uid
		}
		if gid != nil {
			opts.Stat.Mask |= linux.STATX_GID
			opts.Stat.GID = *gid
		}
		if err := vfsObj.SetStatAt(ctx, creds, pop, &opts); err != nil {
			return fmt.Errorf("failed to set UID/GID for device file %q: %w", pathname, err)
		}
	}
	return nil
}

// userspaceInit creates symbolic links and mount points in the devtmpfs
// instance that are created by userspace in Linux. It does not create mounts.
func userspaceInit(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, shmMode *uint16) error {
	// Initialize symlinks.
	for _, symlink := range []struct {
		source string
		target string
	}{
		// systemd: src/shared/dev-setup.c:dev_setup()
		{source: "fd", target: "/proc/self/fd"},
		{source: "stdin", target: "/proc/self/fd/0"},
		{source: "stdout", target: "/proc/self/fd/1"},
		{source: "stderr", target: "/proc/self/fd/2"},
		// /proc/kcore is not implemented.

		// Linux implements /dev/ptmx as a device node, but advises
		// container implementations to create /dev/ptmx as a symlink
		// to pts/ptmx (Documentation/filesystems/devpts.txt). Systemd
		// follows this advice (src/nspawn/nspawn.c:setup_pts()), while
		// LXC tries to create a bind mount and falls back to a symlink
		// (src/lxc/conf.c:lxc_setup_devpts()).
		{source: "ptmx", target: "pts/ptmx"},
	} {
		if err := vfsObj.SymlinkAt(ctx, creds, pathOperationAt(root, symlink.source), symlink.target); err != nil {
			return fmt.Errorf("failed to create symlink %q => %q: %v", symlink.source, symlink.target, err)
		}
	}

	// systemd: src/core/mount-setup.c:mount_table
	for _, dir := range []string{
		"shm",
		"pts",
	} {
		// "The access mode here doesn't really matter too much, since the
		// mounted file system will take precedence anyway"
		//   - systemd: src/core/mount-setup.c:mount_one()
		accessMode := linux.FileMode(0755)
		if shmMode != nil && dir == "shm" {
			accessMode = linux.FileMode(*shmMode)
		}
		if err := vfsObj.MkdirAt(ctx, creds, pathOperationAt(root, dir), &vfs.MkdirOptions{
			Mode: accessMode,
		}); err != nil {
			return fmt.Errorf("failed to create directory %q: %v", dir, err)
		}
	}

	return nil
}
