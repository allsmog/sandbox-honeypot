"""The decoy catalog (decoys/spec.md)."""

PLANTED_KINDS = ("credential-file", "socket", "endpoint")
WATCHED_KINDS = ("kernel-interface", "kernel-helper")
KINDS = PLANTED_KINDS + WATCHED_KINDS
PATH_KINDS = ("credential-file", "socket")
OPT_IN = ("container-socket", "metadata-endpoint", "docker-api")
RUNTIMES = ("gvisor", "capsem", "firecracker", "cloud-hypervisor", "libkrun",
            "kata", "generic")
HOST_PROFILES = ("linux-host", "kubernetes-node")

RUNTIME_SOCKETS = {
    "gvisor": ["/run/runsc-metrics.sock", "/run/runsc-debug.sock"],
    "capsem": ["/run/capsem-admin.sock", "/run/capsem-control.sock"],
    "firecracker": ["/run/firecracker-api.sock", "/run/firecracker-jailer.sock"],
    "cloud-hypervisor": ["/run/cloud-hypervisor-api.sock", "/run/ch-remote.sock"],
    "libkrun": ["/run/libkrun-admin.sock", "/run/krun-control.sock"],
    "kata": ["/run/kata-admin.sock", "/run/kata-monitor.sock"],
    "generic": ["/run/sandbox-admin.sock", "/run/sandbox-control.sock"],
}

# (decoy_id, kind, candidates, technique, credential_format, fs_type, fs_path)
# Candidates use "{user}" and "{gateway}" placeholders; runtime-control's come
# from RUNTIME_SOCKETS.
CATALOG = [
    ("cloud-credentials", "credential-file",
     ["/root/.aws/credentials", "/home/{user}/.aws/credentials"],
     "T1552.001", "aws-access-key", None, None),
    ("ssh-private-key", "credential-file",
     ["/root/.ssh/id_ed25519", "/home/{user}/.ssh/id_ed25519"],
     "T1552.004", "ssh-ed25519", None, None),
    ("container-socket", "socket", ["/var/run/docker.sock"], "T1552.007", None,
     None, None),
    ("metadata-endpoint", "endpoint", ["169.254.169.254:80"], "T1552.005", None,
     None, None),
    ("runtime-control", "socket", None, "T1611", None, None, None),
    ("kubeconfig", "credential-file",
     ["/root/.kube/config", "/home/{user}/.kube/config"],
     "T1552.001", "kubeconfig-token", None, None),
    ("docker-api", "endpoint", ["127.0.0.1:2375"], "T1552.007", None, None, None),
    ("gateway-ssh", "endpoint", ["{gateway}:22"], "T1021.004", None, None, None),
    ("core-pattern", "kernel-interface", ["/proc/sys/kernel/core_pattern"], "T1611",
     None, "proc", "sys/kernel/core_pattern"),
    ("modprobe-path", "kernel-interface", ["/proc/sys/kernel/modprobe"], "T1611",
     None, "proc", "sys/kernel/modprobe"),
    ("uevent-helper", "kernel-interface", ["/sys/kernel/uevent_helper"], "T1611",
     None, "sysfs", "kernel/uevent_helper"),
    ("hotplug-helper", "kernel-interface", ["/proc/sys/kernel/hotplug"], "T1611",
     None, "proc", "sys/kernel/hotplug"),
    ("poweroff-cmd", "kernel-interface", ["/proc/sys/kernel/poweroff_cmd"], "T1611",
     None, "proc", "sys/kernel/poweroff_cmd"),
    ("binfmt-register", "kernel-interface", ["/proc/sys/fs/binfmt_misc/register"],
     "T1611", None, "binfmt_misc", "register"),
    ("cgroup-release-agent", "kernel-interface", ["/sys/fs/cgroup"], "T1611", None,
     "cgroup", None),
    ("helper-exec", "kernel-helper", [], "T1611", None, None, None),
]

CATALOG_IDS = tuple(entry[0] for entry in CATALOG)
CATALOG_BY_ID = {entry[0]: entry for entry in CATALOG}
PUBLIC_SOCKETS = tuple(path for paths in RUNTIME_SOCKETS.values() for path in paths)


def location_type(kind):
    """'path' for path kinds, 'endpoint' for endpoints, None for watched."""
    if kind in PATH_KINDS:
        return "path"
    if kind == "endpoint":
        return "endpoint"
    return None
