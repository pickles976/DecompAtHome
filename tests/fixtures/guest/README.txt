Guest acceptance fixture
========================

The opt-in real-KVM acceptance test boots a guest built from these inputs. The
kernel, rootfs, firecracker, and jailer binaries are NOT vendored here: they
are owner-supplied and pinned by sha256 in a manifest you point at with

    RECOMP_FIRECRACKER_TEST=1
    RECOMP_FIRECRACKER_MANIFEST=/path/to/firecracker.toml

The manifest shape is the one `recomp.firecracker.load_pinned_config()` reads:

    [firecracker]
    firecracker = "/opt/firecracker/firecracker"
    jailer = "/opt/firecracker/jailer"
    kernel = "/opt/firecracker/vmlinux"
    rootfs = "/opt/firecracker/rootfs.ext4"
    jail_root = "/var/lib/recomp/jail"          # 0700, owned by the coordinator account
    uid = 1000
    gid = 1000
    firecracker_sha256 = "<64hex>"
    jailer_sha256 = "<64hex>"
    kernel_sha256 = "<64hex>"
    rootfs_sha256 = "<64hex>"

The rootfs must contain the `recomp-guest` entry point as /usr/bin/recomp-guest
and a trusted command manifest at /opt/recomp/guest/commands.json:

    {"schema": 1, "commands": {"public-fixture.static": ["/usr/bin/recomp", "plugin", "verify"]}}

Guest probes used by the acceptance test (`generic.selftest`) report:
network_interfaces, input_drive_read_only, host_canary_readable, and
previous_run_residue. Every one of those is an isolation assertion, not a
diagnostic: a guest that can reach the network, write its input drive, read a
host canary, or observe a prior run's state is a failing guest.
