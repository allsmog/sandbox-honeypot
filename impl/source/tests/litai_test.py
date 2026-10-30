"""Native behavior tests for the Sandbox Escape Tripwire.

CASES is the single source of truth for the generated test manifest: every
case holds its argument array and its complete expected result, written out
from the specification (credential literals were cross-checked against an
independent Ed25519 implementation). Requests and expected results are built
with small helpers that only fill in the scenario conventions of component.md.
"""

import io
import json
import os
import unittest
from contextlib import redirect_stdout

ENV_NAMES = ("SANDBOX_HONEYPOT_SEED", "SANDBOX_HONEYPOT_SENSOR_KEYS")

SEED = "tripwire-test-seed-0123456789abcdef"
P = "ba2ec3831ba77da700ae57847f4ab9f6f3cce8658ea18257e814a7aca5e00f6a"
R = "80c62308879c55c1be2dded983cd9f2563a2675da0b8a67a49371526e34b50c2"
K = "0f" * 32
V = "bab2ccfc35be2275df5965a010fb36bc5aa1fabf991659a59e31faf64e91e3c7"
OLD = "6b0d1d9c39573957d72d8c50860ae2951ebd2d3f890bc5603ab37dd8f9ca32df"
OTHER = "1" * 64
DAY = "2026-10-30T"

C = "component.md"
DEC = "decoys/spec.md"
CRED = "credentials/spec.md"
EVAL = "evaluation/spec.md"
ATTR = "attribution/spec.md"
TEL = "telemetry/spec.md"
STEALTH = "stealth/spec.md"

# Derived credentials (seed SEED), independently computed.
GV_SSH = ("1ffb9cf9c257c490718f9124c1c252851cadc33bea53b13b71407dee7a231cb0",
          "AAAAC3NzaC1lZDI1NTE5AAAAINMX2UDyxMcUK3qGiX0imnNl1ovH0VXQq6MjyKA92Dh5",
          "SHA256:PXe4dd9+L8MO6NhKTT4snE3F6+FFwnoRJAVi5xXAPKc",
          "14f4f56f397450623bb7c3e635bfcfb9b522184bd647fde271879582b53b6754")
A2_SSH_DIGEST = "cdeab87f0d257ed160ded01a57588c90cc186580ed1d70577debac9ad22ed4d4"
K8_SSH = ("acebd41eff4bc765dd7a4dcb5fb62bd59363423b0d4ad87c879d18789b65c6f2",
          "AAAAC3NzaC1lZDI1NTE5AAAAIEqc7KoGFDMZSkldlqZ14cSVoI4edQzCjVIzen5Aacy3",
          "SHA256:7aoE+l0t+JNkUolH8Nm5Q9BV8ho7xPc9SqVM5nYyJQ0",
          "649c799221f9ae2b92f7451beb81b27d623862e1a5a473306a98591088ffb55a")
K8_KUBE = ("dsu5zv.c64q9jgo1id0wgj3",
           "d3a8c5c5b50a0868f737a28b17bb0c6eaaf872bb7bda90e2b6a3a3615fceed8a")
K8_OPS1 = ("1helzq.owosf7a9dcehe9jo",
           "dc57939ce334ddda6f240f72316ee872debdc1bb75399bbb05e1ae2b3b99aee5")
K8_OPS0_DIGEST = "db4c26aa97ab843ff292fe0828a1b818d86e01f1a9cd7976698db748ec4466c6"
EDGE_SSH = ("ab19bce22cc80bad321fca4139358dc60337bb84d64d379df3c4228e4aa01b6a",
            "AAAAC3NzaC1lZDI1NTE5AAAAIBSH6e7uscAz49zOn4pJpwIh7z0zP8lfzpr48fsfi7UT",
            "SHA256:ps9W8sxIgSK30BjeuAVDePVrrMoxcIPhIrnCMpjjtCs",
            "b1829c18e2055f2f1e3e0e84e1563cbf41f44f86c35aac8293d499ec333ab1c8")
EDGE_OPS = ("432179b878ebe967c340905538b540f5269c4f9781caea097fb4e3a6e354dd02",
            "AAAAC3NzaC1lZDI1NTE5AAAAIFLNYfM39fnu0D9TlZxneSCL64OOCo03zsiykKlbtMtI",
            "SHA256:W6mEGktBVT5iX8uM2bqqJ2sKuke4CTQ9jxy3TzL9lI8",
            "99cac9afde32014186de1085b60016d6e28aeb10f9de416e5a219b6fe8be7106")
ALIAS_SSH0_DIGEST = "3302f191048e23e30390715d3baa97ed0978853342f2cfaa9b7a9ac0e48f7fd0"
ALIAS_SSH1 = ("e33fb3b6a850a8c78879c6346fc78e716e077fe98855001cb4b3a465873de834",
              "AAAAC3NzaC1lZDI1NTE5AAAAIA6E38cvdJf84q+crDyQAOF2dqZR0TJIwblb7zd8Yxjd",
              "SHA256:xcrsPsuHPG2eMOB0iBSWR2+jr1k3GpS5EF5qvxRWShU",
              "ddfe506622cf1ffc46c37da6738ae33dee5d9f8d4b62ea78267e7f479a59595e")


def ts(text):
    return text if "T" in text else DAY + text


def error(field):
    return {"error": {"code": "invalid-request", "field": field}}


# ---------------------------------------------------------------- plan inputs

def context(**changes):
    out = {"host_name": "ci-17", "dormant_user": "deploy", "aws_region": "us-east-1",
           "cluster_name": None, "api_server": None, "cluster_ca_data": None}
    out.update(changes)
    return out


KUBE_CONTEXT = {"cluster_name": "prod-east", "api_server": "10.0.0.1:6443",
                "cluster_ca_data": "Q0E="}


def gvisor_plan(**changes):
    """The gVisor cloud-VM request of decoys/spec.md."""
    out = {
        "operation": "plan", "deployment_id": "prod-agents", "runtime": "gvisor",
        "host_profile": "linux-host", "metadata_service": True,
        "include": ["container-socket", "metadata-endpoint", "docker-api"],
        "seed": SEED, "context": context(), "sandbox_gateway": "172.17.0.1",
        "exposure": {"paths": ["/root/.ssh"], "endpoints": []},
        "occupied": ["/run/docker.sock"], "path_aliases": [], "exclude": [],
        "relocate": [], "custom_decoys": [], "epochs": [],
        "provided_credentials": [{"decoy_id": "cloud-credentials",
                                  "identifier_digest": P}],
        "retired_canaries": [], "cover_files": [],
    }
    out.update(changes)
    return out


OPS_KUBE = {"decoy_id": "ops-kubeconfig", "kind": "credential-file",
            "location": "/home/ops/.kube/config", "technique": "T1552.001",
            "credential_format": "kubeconfig-token"}


def k8s_plan(**changes):
    return gvisor_plan(**dict({
        "deployment_id": "k8s-node-1", "runtime": "kata", "host_profile": "kubernetes-node",
        "metadata_service": False, "sandbox_gateway": None,
        "exposure": {"paths": [], "endpoints": []}, "occupied": [],
        "provided_credentials": [], "exclude": ["container-socket"],
        "relocate": [{"decoy_id": "runtime-control", "location": "/opt/kata/admin.sock"}],
        "custom_decoys": [OPS_KUBE],
        "epochs": [{"decoy_id": "ops-kubeconfig", "epoch": 1}],
        "context": context(**KUBE_CONTEXT)}, **changes))


# ----------------------------------------------------------- plan expectations

def d(decoy_id, kind, location, canonical="same", companions=(), listener=False,
      scope="exact", name=None, fs_type=None, fs_path=None, reachable=False,
      technique="T1611", fmt=None, epoch=None, digest=None):
    return {"decoy_id": decoy_id, "kind": kind, "location": location,
            "canonical_location": location if canonical == "same" else canonical,
            "companion_paths": list(companions), "listener": listener, "scope": scope,
            "name": name, "fs_type": fs_type, "fs_path": fs_path, "reachable": reachable,
            "technique": technique, "credential_format": fmt, "epoch": epoch,
            "canary_digest": digest}


KERNEL = [
    d("core-pattern", "kernel-interface", "/proc/sys/kernel/core_pattern",
      fs_type="proc", fs_path="sys/kernel/core_pattern"),
    d("modprobe-path", "kernel-interface", "/proc/sys/kernel/modprobe",
      fs_type="proc", fs_path="sys/kernel/modprobe"),
    d("uevent-helper", "kernel-interface", "/sys/kernel/uevent_helper",
      fs_type="sysfs", fs_path="kernel/uevent_helper"),
    d("hotplug-helper", "kernel-interface", "/proc/sys/kernel/hotplug",
      fs_type="proc", fs_path="sys/kernel/hotplug"),
    d("poweroff-cmd", "kernel-interface", "/proc/sys/kernel/poweroff_cmd",
      fs_type="proc", fs_path="sys/kernel/poweroff_cmd"),
    d("binfmt-register", "kernel-interface", "/proc/sys/fs/binfmt_misc/register",
      fs_type="binfmt_misc", fs_path="register"),
    d("cgroup-release-agent", "kernel-interface", "/sys/fs/cgroup", scope="name-beneath",
      name="release_agent", fs_type="cgroup"),
    d("helper-exec", "kernel-helper", None, canonical=None),
]


def kernel(*leave_out):
    return [entry for entry in KERNEL if entry["decoy_id"] not in leave_out]


def watch(deployment_id, runtime, profile, decoys, retired=(), aliases=()):
    return {"deployment_id": deployment_id, "runtime": runtime, "host_profile": profile,
            "path_aliases": [{"alias": "/var/run", "target": "/run"}] + list(aliases),
            "decoys": decoys, "retired": list(retired)}


def retired(decoy_id, technique, epoch, digest):
    return {"decoy_id": decoy_id, "kind": "credential-file", "technique": technique,
            "epoch": epoch, "canary_digest": digest}


def skip(decoy_id, location, reason):
    return {"decoy_id": decoy_id, "location": location, "reason": reason}


def comp(decoy_id, path, content, watched=True):
    return {"decoy_id": decoy_id, "path": path, "content": content, "watched": watched}


def ssh_material(decoy_id, values, comment, epoch=0):
    return {"decoy_id": decoy_id, "credential_format": "ssh-ed25519", "epoch": epoch,
            "private_key_seed": values[0],
            "public_key": "ssh-ed25519 %s %s" % (values[1], comment),
            "fingerprint": values[2]}


def kube_material(decoy_id, token, user, epoch=0):
    return {"decoy_id": decoy_id, "credential_format": "kubeconfig-token", "epoch": epoch,
            "token": token, "cluster": "prod-east", "server": "https://10.0.0.1:6443",
            "certificate_authority_data": "Q0E=", "user": user}


def plan_result(warnings, watch_value, material, companions, skipped):
    return {"operation": "plan", "warnings": warnings, "watch": watch_value,
            "material": material, "companions": companions, "skipped": skipped}


AWS_CONFIG = "[default]\nregion = us-east-1\n"
GV_PUB = "ssh-ed25519 %s deploy@ci-17" % GV_SSH[1]

CLOUD_HOME = d("cloud-credentials", "credential-file", "/home/deploy/.aws/credentials",
               companions=["/home/deploy/.aws/config"], technique="T1552.001",
               fmt="aws-access-key", digest=P)
SSH_HOME = d("ssh-private-key", "credential-file", "/home/deploy/.ssh/id_ed25519",
             companions=["/home/deploy/.ssh/id_ed25519.pub"], technique="T1552.004",
             fmt="ssh-ed25519", epoch=0, digest=GV_SSH[3])
RUNSC = d("runtime-control", "socket", "/run/runsc-debug.sock", listener=True)
DOCKER_API = d("docker-api", "endpoint", "127.0.0.1:2375", listener=True,
               technique="T1552.007")
GATEWAY = d("gateway-ssh", "endpoint", "172.17.0.1:22", listener=True, reachable=True,
            technique="T1021.004")

W = watch("prod-agents", "gvisor", "linux-host",
          [CLOUD_HOME, SSH_HOME, RUNSC, DOCKER_API, GATEWAY] + kernel())
GV_SKIPPED = [skip("container-socket", "/var/run/docker.sock", "occupied"),
              skip("metadata-endpoint", "169.254.169.254:80", "real-service")]
GV_RESULT = plan_result(
    ["seed-in-request", "public-socket-name"], W,
    [ssh_material("ssh-private-key", GV_SSH, "deploy@ci-17")],
    [comp("cloud-credentials", "/home/deploy/.aws/config", AWS_CONFIG),
     comp("ssh-private-key", "/home/deploy/.ssh/id_ed25519.pub", GV_PUB + "\n")],
    GV_SKIPPED)

WK = watch("k8s-node-1", "kata", "kubernetes-node", [
    d("ssh-private-key", "credential-file", "/root/.ssh/id_ed25519",
      companions=["/root/.ssh/id_ed25519.pub"], technique="T1552.004", fmt="ssh-ed25519",
      epoch=0, digest=K8_SSH[3]),
    d("metadata-endpoint", "endpoint", "169.254.169.254:80", listener=True,
      technique="T1552.005"),
    d("runtime-control", "socket", "/opt/kata/admin.sock", listener=True),
    d("kubeconfig", "credential-file", "/home/deploy/.kube/config", technique="T1552.001",
      fmt="kubeconfig-token", epoch=0, digest=K8_KUBE[1]),
    DOCKER_API,
] + kernel() + [
    d("ops-kubeconfig", "credential-file", "/home/ops/.kube/config", technique="T1552.001",
      fmt="kubeconfig-token", epoch=1, digest=K8_OPS1[1]),
], retired=[retired("ops-kubeconfig", "T1552.001", 0, K8_OPS0_DIGEST)])
K8_RESULT = plan_result(
    ["seed-in-request"], WK,
    [ssh_material("ssh-private-key", K8_SSH, "root@ci-17"),
     kube_material("kubeconfig", K8_KUBE[0], "deploy"),
     kube_material("ops-kubeconfig", K8_OPS1[0], "ops", epoch=1)],
    [comp("ssh-private-key", "/root/.ssh/id_ed25519.pub",
          "ssh-ed25519 %s root@ci-17\n" % K8_SSH[1])],
    [skip("cloud-credentials", "/root/.aws/credentials", "unprovisioned"),
     skip("container-socket", "/var/run/docker.sock", "excluded")])

A2_RESULT = plan_result(
    ["seed-in-request"],
    watch("agents-2", "capsem", "linux-host", [DOCKER_API] + kernel(),
          retired=[retired("ssh-private-key", "T1552.004", 0, A2_SSH_DIGEST)]),
    [], [],
    [skip("cloud-credentials", "/root/.aws/credentials", "exposed"),
     skip("ssh-private-key", "/root/.ssh/id_ed25519", "exposed"),
     skip("container-socket", "/var/run/docker.sock", "occupied"),
     skip("metadata-endpoint", "169.254.169.254:80", "exposed"),
     skip("runtime-control", "/run/capsem-admin.sock", "occupied")])

RUNBOOK = {"decoy_id": "cloud-credentials", "path": "/home/deploy/docs/RUNBOOK.md",
           "content": "Release cache credentials: ~/.aws/credentials\n"}
COVER_RESULT = plan_result(
    ["seed-in-request", "public-socket-name"], W,
    [ssh_material("ssh-private-key", GV_SSH, "deploy@ci-17")],
    [comp("cloud-credentials", "/home/deploy/.aws/config", AWS_CONFIG),
     comp("cloud-credentials", RUNBOOK["path"], RUNBOOK["content"], watched=False),
     comp("ssh-private-key", "/home/deploy/.ssh/id_ed25519.pub", GV_PUB + "\n")],
    GV_SKIPPED)
COVER_EXPOSED_RESULT = plan_result(
    ["seed-in-request", "public-socket-name"],
    watch("prod-agents", "gvisor", "linux-host",
          [SSH_HOME, RUNSC, DOCKER_API, GATEWAY] + kernel(),
          retired=[retired("cloud-credentials", "T1552.001", None, P)]),
    [ssh_material("ssh-private-key", GV_SSH, "deploy@ci-17")],
    [comp("ssh-private-key", "/home/deploy/.ssh/id_ed25519.pub", GV_PUB + "\n")],
    [skip("cloud-credentials", "/root/.aws/credentials", "exposed")] + GV_SKIPPED)
NO_DORMANT_RESULT = plan_result(
    ["seed-in-request", "public-socket-name"],
    watch("prod-agents", "gvisor", "linux-host", [
        d("cloud-credentials", "credential-file", "/root/.aws/credentials",
          companions=["/root/.aws/config"], technique="T1552.001", fmt="aws-access-key",
          digest=P),
        RUNSC, DOCKER_API, GATEWAY] + kernel(),
        retired=[retired("ssh-private-key", "T1552.004", 0, GV_SSH[3])]),
    [],
    [comp("cloud-credentials", "/root/.aws/config", AWS_CONFIG)],
    [skip("ssh-private-key", "/root/.ssh/id_ed25519", "exposed")] + GV_SKIPPED)

# Extra plan: IPv6 gateway behind a real SSH server, open egress, a custom SSH
# decoy sharing a cover file, an exclusion, and an unprovisioned AWS decoy.
KEYS_MD = "Rotate host keys quarterly.\n"
EDGE_REQUEST = gvisor_plan(
    deployment_id="edge-9", runtime="firecracker", metadata_service=False,
    include=["metadata-endpoint", "docker-api"],
    context=context(host_name="edge-9", dormant_user="svc"),
    sandbox_gateway="fd00::1", exposure={"paths": [], "endpoints": ["*:*"]},
    occupied=["0.0.0.0:22"], exclude=["poweroff-cmd"], provided_credentials=[],
    custom_decoys=[{"decoy_id": "ops-key", "kind": "credential-file",
                    "location": "/srv/ops/.ssh/id_ed25519", "technique": "T1552.004",
                    "credential_format": "ssh-ed25519"}],
    cover_files=[{"decoy_id": "ssh-private-key", "path": "/srv/docs/KEYS.md",
                  "content": KEYS_MD},
                 {"decoy_id": "ops-key", "path": "/srv/docs/KEYS.md",
                  "content": KEYS_MD}])
EDGE_RESULT = plan_result(
    ["seed-in-request", "public-socket-name"],
    watch("edge-9", "firecracker", "linux-host", [
        d("ssh-private-key", "credential-file", "/root/.ssh/id_ed25519",
          companions=["/root/.ssh/id_ed25519.pub"], technique="T1552.004",
          fmt="ssh-ed25519", epoch=0, digest=EDGE_SSH[3]),
        d("runtime-control", "socket", "/run/firecracker-jailer.sock", listener=True),
        DOCKER_API,
        d("gateway-ssh", "endpoint", "[fd00::1]:22", listener=False, reachable=True,
          technique="T1021.004"),
    ] + kernel("poweroff-cmd") + [
        d("ops-key", "credential-file", "/srv/ops/.ssh/id_ed25519",
          companions=["/srv/ops/.ssh/id_ed25519.pub"], technique="T1552.004",
          fmt="ssh-ed25519", epoch=0, digest=EDGE_OPS[3]),
    ]),
    [ssh_material("ssh-private-key", EDGE_SSH, "root@edge-9"),
     ssh_material("ops-key", EDGE_OPS, "svc@edge-9")],
    [comp("ssh-private-key", "/root/.ssh/id_ed25519.pub",
          "ssh-ed25519 %s root@edge-9\n" % EDGE_SSH[1]),
     comp("ssh-private-key", "/srv/docs/KEYS.md", KEYS_MD, watched=False),
     comp("ops-key", "/srv/ops/.ssh/id_ed25519.pub",
          "ssh-ed25519 %s svc@edge-9\n" % EDGE_OPS[1])],
    [skip("cloud-credentials", "/root/.aws/credentials", "unprovisioned"),
     skip("metadata-endpoint", "169.254.169.254:80", "exposed"),
     skip("poweroff-cmd", "/proc/sys/kernel/poweroff_cmd", "excluded")])

# Extra plan: symlinked homes aliased, relocation through the built-in alias
# onto a public socket name, rotation, and retired canaries.
ALIAS_REQUEST = gvisor_plan(
    deployment_id="alias-host", include=[], metadata_service=False, sandbox_gateway=None,
    context=context(host_name="alias-host"),
    path_aliases=[{"alias": "/home", "target": "/var/home"}],
    exposure={"paths": ["/var/home/deploy/.aws"], "endpoints": []}, occupied=[],
    relocate=[{"decoy_id": "ssh-private-key", "location": "/home/deploy/.ssh/id_ed25519"},
              {"decoy_id": "runtime-control", "location": "/var/run/kata-admin.sock"}],
    epochs=[{"decoy_id": "ssh-private-key", "epoch": 1}],
    retired_canaries=[{"decoy_id": "old-vault", "technique": "T1552.001",
                       "canary_digest": OLD},
                      {"decoy_id": "kubeconfig", "technique": None,
                       "canary_digest": OTHER}])
ALIAS_RESULT = plan_result(
    ["seed-in-request", "public-socket-name"],
    watch("alias-host", "gvisor", "linux-host", [
        d("cloud-credentials", "credential-file", "/root/.aws/credentials",
          companions=["/root/.aws/config"], technique="T1552.001", fmt="aws-access-key",
          digest=P),
        d("ssh-private-key", "credential-file", "/home/deploy/.ssh/id_ed25519",
          canonical="/var/home/deploy/.ssh/id_ed25519",
          companions=["/var/home/deploy/.ssh/id_ed25519.pub"], technique="T1552.004",
          fmt="ssh-ed25519", epoch=1, digest=ALIAS_SSH1[3]),
        d("runtime-control", "socket", "/var/run/kata-admin.sock",
          canonical="/run/kata-admin.sock", listener=True),
    ] + kernel(), retired=[
        retired("ssh-private-key", "T1552.004", 0, ALIAS_SSH0_DIGEST),
        retired("old-vault", "T1552.001", None, OLD),
        retired("kubeconfig", "T1552.001", None, OTHER),
    ], aliases=[{"alias": "/home", "target": "/var/home"}]),
    [ssh_material("ssh-private-key", ALIAS_SSH1, "deploy@alias-host", epoch=1)],
    [comp("cloud-credentials", "/root/.aws/config", AWS_CONFIG),
     comp("ssh-private-key", "/home/deploy/.ssh/id_ed25519.pub",
          "ssh-ed25519 %s deploy@alias-host\n" % ALIAS_SSH1[1])],
    [])


# ------------------------------------------------------------ evaluate inputs

UNBOUND_INODE = {"device": "2050", "inode": "999999"}
_DEFAULT = object()


def proc(pid, ticks):
    return {"pid": pid, "start_ticks": ticks}


def actor(process=None, ancestry=(), helper_depth=None, executable=None,
          executable_digest=None, uid=None, comm=None, environment_names=None,
          sandbox_id=None):
    return {"process": proc(*process) if process else None,
            "ancestry": [proc(*p) for p in ancestry], "helper_depth": helper_depth,
            "executable": executable, "executable_digest": executable_digest, "uid": uid,
            "comm": comm, "environment_names": environment_names, "sandbox_id": sandbox_id}


def ev(event_id, action, target, time="12:00:00Z", received=None, source="ebpf",
       instance="boot-1", sequence=None, target_inode=_DEFAULT, target_fs=None,
       target_digest=None, written_digest=None, act=None, deployment="prod-agents",
       mac=None, **extra):
    """An event with the scenario defaults; sequence None is auto-numbered."""
    if target_inode is _DEFAULT:
        target_inode = dict(UNBOUND_INODE) if target.startswith("/") else None
    out = {"event_id": event_id, "deployment_id": deployment, "time": ts(time),
           "received": ts(received or time), "source": source,
           "sensor_instance": instance, "sequence": sequence, "action": action,
           "target": target, "mac": mac, "target_inode": target_inode,
           "target_fs": target_fs, "target_digest": target_digest,
           "written_digest": written_digest, "actor": act or actor()}
    out.update(extra)
    return out


def source(name, signer="sensor", silence=None, delay=300):
    return {"source": name, "signer": signer, "max_silence_seconds": silence,
            "max_delay_seconds": delay}


def evaluate(watch_value, events, sources=None, window=(DAY + "00:00:00Z",
             "2026-10-31T00:00:00Z"), **fields):
    numbering = {}
    named = []
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        if event.get("event_id") is None:
            event["event_id"] = "u%d" % index
        key = (event.get("source"), event.get("sensor_instance"))
        numbering[key] = numbering.get(key, 0) + 1
        if "sequence" in event and event["sequence"] is None:
            event["sequence"] = numbering[key]
        if event.get("source") not in named:
            named.append(event.get("source"))
    if sources is None:
        sources = [source(n, "collector" if n == "cloudtrail" else "sensor")
                   for n in named if isinstance(n, str)]
    out = {"operation": "evaluate", "watch": watch_value, "sandboxes": [],
           "suppressions": [], "expected_helpers": [], "ignore_stat": [],
           "harness_signatures": [], "sources": sources, "probe": None,
           "corroboration": None, "authentication": "off",
           "max_clock_skew_seconds": 300, "carry": None,
           "window": {"start": ts(window[0]), "end": ts(window[1])},
           "decoy_inodes": [], "events": events}
    out.update(fields)
    return out


SBX1 = {"sandbox_id": "sbx-1", "runtime_processes": [proc(4100, 500)],
        "harness_processes": [proc(3000, 400)]}


# -------------------------------------------------------- evaluate expectations

def alert(event_id, decoy_id, kind, location, observed, verdict, techniques,
          sandbox_id=None, attribution=None, harness=None, executable=None, uid=None,
          comm=None, time="12:00:00Z", source_name="ebpf", alert_id=None):
    return {"alert_id": alert_id or event_id + "/" + decoy_id, "event_id": event_id,
            "decoy_id": decoy_id, "kind": kind, "location": location,
            "observed_target": observed, "severity": "critical", "verdict": verdict,
            "techniques": techniques, "sandbox_id": sandbox_id, "attribution": attribution,
            "harness": harness, "executable": executable, "uid": uid, "comm": comm,
            "time": ts(time), "source": source_name}


def incident(sandbox_id, first, last, alert_ids):
    return {"sandbox_id": sandbox_id, "first_seen": ts(first), "last_seen": ts(last),
            "alert_ids": alert_ids}


def seq(source_name, instance, highest, last_received, missing=()):
    return {"source": source_name, "sensor_instance": instance, "highest": highest,
            "missing": [{"from": a, "to": b} for a, b in missing],
            "last_received": ts(last_received)}


def carry(window_end="2026-10-31T00:00:00Z", sequences=(), last_seen=(), last_probe=(),
          recent_hits=(), pending=()):
    return {"window_end": ts(window_end), "sequences": list(sequences),
            "last_seen": list(last_seen), "last_probe": list(last_probe),
            "recent_hits": list(recent_hits), "pending": list(pending)}


def recent(event_id, decoy_id, source_name, time, received=None, missing=None):
    out = {"event_id": event_id, "decoy_id": decoy_id, "source": source_name,
           "time": ts(time), "received": ts(received or time)}
    if missing is not None:
        out["missing_sources"] = missing
    return out


TAMPER = ("sequence_gaps", "late_fills", "sequence_duplicates", "sensor_restarts",
          "silence_gaps", "watch_gaps", "uncorroborated", "clock_skew")


def result(breached, degraded, carry_value, warnings=("unauthenticated",
           "missing-inode-binding"), deployment_id="prod-agents", alerts=(),
           incidents=(), suppressed=(), rejected=(), repaired=(), rejected_hits=(),
           duplicate_event_ids=(), probe_hits=0, ignored=0, **tamper):
    out = {"operation": "evaluate", "deployment_id": deployment_id,
           "warnings": list(warnings), "breached": breached, "degraded": degraded,
           "alerts": list(alerts), "incidents": list(incidents),
           "suppressed": list(suppressed), "rejected": list(rejected),
           "repaired": list(repaired), "rejected_hits": list(rejected_hits),
           "duplicate_event_ids": list(duplicate_event_ids)}
    for name in TAMPER:
        out[name] = list(tamper.pop(name, ()))
    assert not tamper, "unknown result fields: %r" % sorted(tamper)
    out["carry"] = carry_value
    out["probe_hits"] = probe_hits
    out["ignored"] = ignored
    return out


CREDS = "/home/deploy/.aws/credentials"
RUNSC_PATH = "/run/runsc-debug.sock"
CLOUD_LOC = CREDS
ABSTAIN = {"harness_id": None, "matched": [], "abstained": True}


def host_breach_creds(event_id, time="12:00:00Z", **kw):
    return alert(event_id, "cloud-credentials", "credential-file", CREDS,
                 kw.pop("observed", CREDS), kw.pop("verdict", "host-breach"),
                 kw.pop("techniques", ["T1611", "T1552.001"]), time=time, **kw)


def runsc_alert(event_id, verdict="host-breach", time="12:00:00Z", observed=RUNSC_PATH,
                **kw):
    return alert(event_id, "runtime-control", "socket", RUNSC_PATH, observed, verdict,
                 ["T1611"], time=time, **kw)


# ------------------------------------------------------------------- the cases

CASES = []


def case(case_id, category, refs, request, expected):
    CASES.append({"case_id": case_id, "category": category,
                  "specification_refs": list(refs), "arguments": [request],
                  "expected_result": expected})


# --- decoys/spec.md and credentials/spec.md plan scenarios
case("plan-gvisor-cloud-vm", "example", [DEC, CRED, C], gvisor_plan(), GV_RESULT)
case("plan-host-share-open-egress", "example", [DEC, CRED],
     gvisor_plan(deployment_id="agents-2", runtime="capsem", metadata_service=False,
                 sandbox_gateway=None, provided_credentials=[],
                 exposure={"paths": ["/root", "/home"], "endpoints": ["169.254.0.0/16:*"]},
                 occupied=["/var/run"]),
     A2_RESULT)
case("plan-kubernetes-tailored", "example", [DEC, CRED], k8s_plan(), K8_RESULT)
case("plan-cover-story", "example", [CRED, DEC], gvisor_plan(cover_files=[RUNBOOK]),
     COVER_RESULT)
case("plan-cover-story-exposed", "example", [CRED, DEC],
     gvisor_plan(cover_files=[RUNBOOK],
                 exposure={"paths": ["/root/.ssh", "/home/deploy/docs"], "endpoints": []}),
     COVER_EXPOSED_RESULT)
case("plan-no-dormant-account", "example", [CRED, DEC],
     gvisor_plan(context=context(dormant_user=None)), NO_DORMANT_RESULT)
case("plan-ipv6-gateway-shared-cover", "boundary", [DEC, CRED, STEALTH], EDGE_REQUEST,
     EDGE_RESULT)
case("plan-aliases-rotation-retired", "invariant", [DEC, CRED], ALIAS_REQUEST,
     ALIAS_RESULT)

# --- component.md fail-closed scenarios
case("reject-guest-relative-exposure", "example", [C, DEC],
     gvisor_plan(exposure={"paths": ["workspace"], "endpoints": []}),
     error("/exposure/paths/0"))
case("reject-host-name-exposure", "example", [C, DEC],
     gvisor_plan(exposure={"paths": ["/root/.ssh"], "endpoints": ["metadata.internal:80"]}),
     error("/exposure/endpoints/0"))
case("reject-chained-alias-target", "example", [C, DEC],
     gvisor_plan(path_aliases=[{"alias": "/srv/run", "target": "/var/run/app"}]),
     error("/path_aliases/0/target"))
case("reject-chained-alias-alias", "example", [C, DEC],
     gvisor_plan(path_aliases=[{"alias": "/run/app", "target": "/srv/app"}]),
     error("/path_aliases/0/alias"))
case("reject-weak-seed", "example", [C], gvisor_plan(seed="test-seed"), error("/seed"))
case("reject-unknown-suppression-decoy", "example", [C, EVAL],
     evaluate(W, [], suppressions=[{"decoy_id": "kubeconfig", "executable": "/usr/bin/restic",
                                    "executable_digests": [R], "uid": 0,
                                    "value_digest": None}]),
     error("/suppressions/0/decoy_id"))
case("reject-kernel-interface-relocation", "example", [C, DEC],
     gvisor_plan(relocate=[{"decoy_id": "core-pattern", "location": "/opt/core"}]),
     error("/relocate/0/decoy_id"))
case("reject-custom-kubeconfig-without-cluster", "example", [C, CRED],
     gvisor_plan(custom_decoys=[OPS_KUBE],
                 context=context(**dict(KUBE_CONTEXT, cluster_name=None))),
     error("/context/cluster_name"))
case("reject-revealing-cover-file", "example", [C, CRED],
     gvisor_plan(cover_files=[{"decoy_id": "cloud-credentials",
                               "path": "/home/deploy/docs/NOTES.md",
                               "content": "This host is a Honeypot.\n"}]),
     error("/cover_files/0/content"))
case("reject-missing-sensor-keys", "example", [C, TEL],
     evaluate(W, [], authentication="required"), error("/sensor_keys"))

# --- plan validation boundaries
case("reject-unknown-top-level-field", "boundary", [C], gvisor_plan(zeta=1), error("/zeta"))
_no_context = gvisor_plan()
del _no_context["context"]
case("reject-missing-context", "boundary", [C], _no_context, error("/context"))
case("reject-repeated-include", "boundary", [C, DEC],
     gvisor_plan(include=["docker-api", "docker-api"]), error("/include/1"))
case("reject-unspecified-gateway", "boundary", [DEC],
     gvisor_plan(sandbox_gateway="0.0.0.0"), error("/sandbox_gateway"))
case("reject-catalog-custom-id", "boundary", [DEC],
     gvisor_plan(custom_decoys=[{"decoy_id": "core-pattern", "kind": "socket",
                                 "location": "/run/x.sock", "technique": "T1611",
                                 "credential_format": None}]),
     error("/custom_decoys/0/decoy_id"))
case("reject-unknown-runtime", "boundary", [DEC], gvisor_plan(runtime="docker"),
     error("/runtime"))
case("reject-oversized-ipv6-prefix", "boundary", [DEC],
     gvisor_plan(exposure={"paths": [], "endpoints": ["[::1]/129:22"]}),
     error("/exposure/endpoints/0"))
case("reject-uppercase-dormant-user", "boundary", [CRED],
     gvisor_plan(context=context(dormant_user="Deploy")), error("/context/dormant_user"))
case("reject-cover-file-for-boundary-decoy", "boundary", [CRED, C],
     gvisor_plan(cover_files=[{"decoy_id": "gateway-ssh", "path": "/srv/README",
                               "content": "ssh gateway\n"}]),
     error("/cover_files/0/decoy_id"))
case("reject-epoch-for-provided-credential", "boundary", [CRED, C],
     gvisor_plan(epochs=[{"decoy_id": "cloud-credentials", "epoch": 1}]),
     error("/epochs/0/decoy_id"))
case("reject-former-custom-without-technique", "boundary", [CRED, C],
     gvisor_plan(retired_canaries=[{"decoy_id": "old-vault", "technique": None,
                                    "canary_digest": OLD}]),
     error("/retired_canaries/0/technique"))
case("reject-repeated-canary-digest", "invariant", [CRED, C],
     gvisor_plan(retired_canaries=[{"decoy_id": "ssh-private-key", "technique": None,
                                    "canary_digest": P}]),
     error("/retired_canaries/0/canary_digest"))
case("reject-footprint-collision", "invariant", [DEC, C],
     gvisor_plan(relocate=[{"decoy_id": "runtime-control", "location": "/opt/sock/a.sock"}],
                 custom_decoys=[{"decoy_id": "aux-socket", "kind": "socket",
                                 "location": "/opt/sock", "technique": "T1611",
                                 "credential_format": None}]),
     error("/custom_decoys/0/location"))
case("reject-relocation-wrong-location-type", "boundary", [DEC, C],
     gvisor_plan(relocate=[{"decoy_id": "ssh-private-key", "location": "10.0.0.5:22"}]),
     error("/relocate/0/location"))
case("reject-field-errors-before-cross-field", "invariant", [C],
     gvisor_plan(path_aliases=[{"alias": "/run/app", "target": "/srv/app"}],
                 cover_files=[{"decoy_id": "cloud-credentials", "path": "/srv/decoy.txt",
                               "content": "x"}]),
     error("/cover_files/0/path"))
case("reject-unknown-operation", "boundary", [C],
     {"operation": "destroy", "deployment_id": "prod-agents"}, error("/operation"))
case("reject-non-object-request", "boundary", [C], "plan", error(""))

# --- component.md and attribution/spec.md evaluate scenarios
case("metadata-reconnaissance", "example", [C, STEALTH, EVAL],
     evaluate(W, [ev("s1", "stat", CREDS)]),
     result(True, True, carry(sequences=[seq("ebpf", "boot-1", 1, "12:00:00Z")]),
            alerts=[host_breach_creds("s1")],
            incidents=[incident(None, "12:00:00Z", "12:00:00Z", ["s1/cloud-credentials"])]))

RESTIC_SUPPRESSION = {"decoy_id": "cloud-credentials", "executable": "/usr/bin/restic",
                      "executable_digests": [R], "uid": 0, "value_digest": None}
case("escape-runtime-impostor-exfiltration", "example", [ATTR, EVAL],
     evaluate(W, [
         ev("e1", "connect", RUNSC_PATH, act=actor((4242, 900), [(4100, 500), (3000, 400),
                                                                 (1, 1)],
                                                    executable="/usr/bin/python3")),
         ev("e2", "read", CREDS, time="12:01:00Z",
            act=actor(executable="/usr/bin/restic", executable_digest=R, uid=0)),
         ev("e3", "read", CREDS, time="12:02:00Z",
            act=actor((5000, 1000), [(4100, 777), (1, 1)], comm="restic",
                      executable="/tmp/.x/restic", uid=0)),
         ev("e4", "open", CREDS, time="12:03:00Z", act=actor((4100, 500))),
         ev("e5", "credential-use", P, time="12:05:00Z", source="cloudtrail"),
     ], sandboxes=[SBX1], suppressions=[RESTIC_SUPPRESSION]),
     result(True, True, carry(sequences=[seq("cloudtrail", "boot-1", 1, "12:05:00Z"),
                                         seq("ebpf", "boot-1", 4, "12:03:00Z")]),
            alerts=[
                runsc_alert("e1", "escape-confirmed", sandbox_id="sbx-1",
                            attribution="ancestry", executable="/usr/bin/python3"),
                host_breach_creds("e3", time="12:02:00Z", executable="/tmp/.x/restic",
                                  uid=0, comm="restic"),
                host_breach_creds("e4", time="12:03:00Z", verdict="runtime-mediated",
                                  sandbox_id="sbx-1", attribution="runtime"),
                host_breach_creds("e5", time="12:05:00Z", observed=None,
                                  verdict="credential-exfiltrated",
                                  techniques=["T1552.001", "T1078"],
                                  source_name="cloudtrail"),
            ],
            incidents=[incident("sbx-1", "12:00:00Z", "12:03:00Z",
                                ["e1/runtime-control", "e4/cloud-credentials"]),
                       incident(None, "12:02:00Z", "12:05:00Z",
                                ["e3/cloud-credentials", "e5/cloud-credentials"])],
            suppressed=[{"event_id": "e2", "decoy_id": "cloud-credentials"}]))

SIGNATURES = [{"harness_id": "claude-code", "environment_names": ["CLAUDECODE"],
               "executables": ["claude"]},
              {"harness_id": "aider", "environment_names": ["AIDER_MODEL"],
               "executables": ["aider"]}]
case("harness-escape-identified", "example", [ATTR],
     evaluate(W, [
         ev("h1", "read", CREDS, act=actor((3100, 450), [(3000, 400), (1, 1)],
                                           executable="/usr/bin/python3",
                                           environment_names=["CLAUDECODE", "HOME", "PATH"])),
         ev("h2", "connect", RUNSC_PATH, time="12:01:00Z",
            act=actor((4300, 980), [(4100, 500), (3000, 400), (1, 1)],
                      environment_names=["PATH"])),
     ], sandboxes=[SBX1], harness_signatures=SIGNATURES),
     result(True, True, carry(sequences=[seq("ebpf", "boot-1", 2, "12:01:00Z")]),
            alerts=[
                host_breach_creds("h1", verdict="harness-escape", sandbox_id="sbx-1",
                                  attribution="harness", executable="/usr/bin/python3",
                                  harness={"harness_id": "claude-code",
                                           "matched": ["env:CLAUDECODE"],
                                           "abstained": False}),
                runsc_alert("h2", "escape-confirmed", time="12:01:00Z", sandbox_id="sbx-1",
                            attribution="ancestry", harness=ABSTAIN),
            ],
            incidents=[incident("sbx-1", "12:00:00Z", "12:01:00Z",
                                ["h1/cloud-credentials", "h2/runtime-control"])]))

case("kernel-helper-escapes", "example", [ATTR, EVAL, DEC],
     evaluate(W, [
         ev("k0", "read", "/proc/sys/kernel/core_pattern"),
         ev("k1", "write", "/tmp/cgrp/release_agent",
            target_fs={"type": "cgroup", "path": "release_agent"},
            act=actor((6100, 950), [(4100, 500)])),
         ev("k2", "exec", "/tmp/p", time="12:00:05Z", act=actor((7000, 1200), helper_depth=0)),
         ev("k3", "read", CREDS, time="12:00:06Z", act=actor((7001, 1210), helper_depth=1)),
         ev("k4", "exec", "/usr/bin/kmod", target_digest=R, act=actor(helper_depth=0)),
     ], sandboxes=[SBX1], expected_helpers=[{"path": "/usr/bin/kmod", "digests": [R]}]),
     result(True, True, carry(sequences=[seq("ebpf", "boot-1", 5, "12:00:06Z")]),
            alerts=[
                alert("k1", "cgroup-release-agent", "kernel-interface", "/sys/fs/cgroup",
                      "/tmp/cgrp/release_agent", "escape-confirmed", ["T1611"],
                      sandbox_id="sbx-1", attribution="ancestry"),
                alert("k2", "helper-exec", "kernel-helper", None, "/tmp/p",
                      "escape-confirmed", ["T1611"], attribution="kernel-helper",
                      time="12:00:05Z"),
                host_breach_creds("k3", time="12:00:06Z", verdict="escape-confirmed",
                                  attribution="kernel-helper"),
            ],
            incidents=[incident("sbx-1", "12:00:00Z", "12:00:00Z",
                                ["k1/cgroup-release-agent"]),
                       incident(None, "12:00:05Z", "12:00:06Z",
                                ["k2/helper-exec", "k3/cloud-credentials"])],
            ignored=2))

case("sandbox-reaches-host-ssh", "example", [ATTR],
     evaluate(W, [ev("g1", "connect", "172.17.0.1:22", act=actor(sandbox_id="sbx-1"))],
              sandboxes=[SBX1]),
     result(True, True, carry(sequences=[seq("ebpf", "boot-1", 1, "12:00:00Z")]),
            alerts=[alert("g1", "gateway-ssh", "endpoint", "172.17.0.1:22",
                          "172.17.0.1:22", "escape-attempt", ["T1611", "T1021.004"],
                          sandbox_id="sbx-1", attribution="sensor")],
            incidents=[incident("sbx-1", "12:00:00Z", "12:00:00Z", ["g1/gateway-ssh"])]))

case("alias-path-simultaneous-alerts", "example", [ATTR, EVAL],
     evaluate(W, [ev("a2", "read", CREDS),
                  ev("a1", "connect", "/var/run/runsc-debug.sock",
                     act=actor(sandbox_id="sbx-1"))], sandboxes=[SBX1]),
     result(True, True, carry(sequences=[seq("ebpf", "boot-1", 2, "12:00:00Z")]),
            alerts=[runsc_alert("a1", "escape-confirmed", observed="/var/run/runsc-debug.sock",
                                sandbox_id="sbx-1", attribution="sensor"),
                    host_breach_creds("a2")],
            incidents=[incident("sbx-1", "12:00:00Z", "12:00:00Z", ["a1/runtime-control"]),
                       incident(None, "12:00:00Z", "12:00:00Z", ["a2/cloud-credentials"])]))

ROOT_KEY = "/root/.ssh/id_ed25519"
case("endpoint-spellings-companion-hard-link", "example", [ATTR, EVAL, DEC],
     evaluate(WK, [
         ev("n1", "connect", "[::ffff:169.254.169.254]:80", deployment="k8s-node-1"),
         ev("n2", "read", "/tmp/k", target_inode={"device": "2049", "inode": "1234"},
            deployment="k8s-node-1"),
         ev("n3", "connect", "0.0.0.0:2375", deployment="k8s-node-1"),
         ev("n4", "stat", ROOT_KEY + ".pub", deployment="k8s-node-1"),
     ], decoy_inodes=[{"decoy_id": "ssh-private-key", "path": ROOT_KEY, "device": "2049",
                       "inode": "1234"}]),
     result(True, True, carry(sequences=[seq("ebpf", "boot-1", 4, "12:00:00Z")]),
            deployment_id="k8s-node-1",
            alerts=[
                alert("n1", "metadata-endpoint", "endpoint", "169.254.169.254:80",
                      "[::ffff:169.254.169.254]:80", "host-breach", ["T1611", "T1552.005"]),
                alert("n2", "ssh-private-key", "credential-file", ROOT_KEY, "/tmp/k",
                      "host-breach", ["T1611", "T1552.004"]),
                alert("n3", "docker-api", "endpoint", "127.0.0.1:2375", "0.0.0.0:2375",
                      "host-breach", ["T1611", "T1552.007"]),
                alert("n4", "ssh-private-key", "credential-file", ROOT_KEY,
                      ROOT_KEY + ".pub", "host-breach", ["T1611", "T1552.004"]),
            ],
            incidents=[incident(None, "12:00:00Z", "12:00:00Z",
                                ["n1/metadata-endpoint", "n2/ssh-private-key",
                                 "n3/docker-api", "n4/ssh-private-key"])]))

case("stolen-before-rotation", "example", [CRED, ATTR],
     evaluate(WK, [ev("r1", "credential-use", K8_OPS0_DIGEST, source="token-webhook",
                      deployment="k8s-node-1")],
              sources=[source("token-webhook", "collector")]),
     result(True, True, carry(sequences=[seq("token-webhook", "boot-1", 1, "12:00:00Z")]),
            deployment_id="k8s-node-1",
            alerts=[alert("r1", "ops-kubeconfig", "credential-file", None, None,
                          "credential-exfiltrated", ["T1552.001", "T1078"],
                          source_name="token-webhook")],
            incidents=[incident(None, "12:00:00Z", "12:00:00Z", ["r1/ops-kubeconfig"])]))

# --- telemetry/spec.md scenarios
M1 = {"event_id": "m1", "deployment_id": "prod-agents", "time": "2026-10-30T12:00:00Z",
      "source": "ebpf", "sensor_instance": "boot-1", "sequence": 7, "action": "connect",
      "target": "/run/runsc-debug.sock", "target_inode": None, "target_fs": None,
      "target_digest": None, "written_digest": None,
      "actor": {"process": None, "ancestry": [], "helper_depth": None, "executable": None,
                "executable_digest": None, "uid": None, "comm": None,
                "environment_names": None, "sandbox_id": None}}
M1_MAC = "99f9d0d11b0a32fe2a390c6b2f6418459161cd833ded595ad7f26ec45aedab12"


def signed_events():
    m1 = dict(M1, mac=M1_MAC, received="2026-10-30T12:00:02Z")
    m2 = dict(m1, event_id="m2", sequence=8, target=CREDS)
    return [m1, m2]


case("forged-and-authentic-events", "example", [TEL, EVAL],
     evaluate(W, signed_events(), authentication="required", sensor_keys={"ebpf": K},
              max_clock_skew_seconds=30),
     result(True, True,
            carry(sequences=[seq("ebpf", "boot-1", 7, "12:00:02Z", missing=[(1, 6)])]),
            warnings=["keys-in-request", "missing-inode-binding"],
            alerts=[runsc_alert("m1")],
            incidents=[incident(None, "12:00:00Z", "12:00:00Z", ["m1/runtime-control"])],
            rejected=[{"index": 1, "field": "/mac"}],
            rejected_hits=[{"index": 1, "decoy_id": "cloud-credentials"}],
            sequence_gaps=[{"source": "ebpf", "sensor_instance": "boot-1", "after": 0,
                            "before": 7}]))

case("late-external-log", "example", [TEL],
     evaluate(W, [ev("c1", "credential-use", P, time="12:04:00Z", received="12:09:00Z",
                     source="cloudtrail")],
              sources=[source("cloudtrail", "collector", delay=900)],
              window=("12:05:00Z", "12:10:00Z")),
     result(True, True,
            carry("12:10:00Z", sequences=[seq("cloudtrail", "boot-1", 1, "12:09:00Z")]),
            alerts=[host_breach_creds("c1", time="12:04:00Z", observed=None,
                                      verdict="credential-exfiltrated",
                                      techniques=["T1552.001", "T1078"],
                                      source_name="cloudtrail")],
            incidents=[incident(None, "12:04:00Z", "12:04:00Z", ["c1/cloud-credentials"])]))

case("backdated-event", "example", [TEL],
     evaluate(W, [ev("d1", "heartbeat", "", time="12:00:00Z", received="12:05:00Z")],
              sources=[source("ebpf", delay=60)]),
     result(False, True, carry(sequences=[seq("ebpf", "boot-1", 1, "12:05:00Z")]),
            clock_skew=["d1"]))

case("malformed-and-repaired-events", "example", [TEL, EVAL],
     evaluate(W, [ev(None, "connect", RUNSC_PATH, time="2026-10-30 12:00"),
                  ev(None, "connect", RUNSC_PATH, act=dict(actor(), process=proc(0, 0)))]),
     result(True, True,
            carry(sequences=[seq("ebpf", "boot-1", 2, "12:00:00Z", missing=[(1, 1)])]),
            alerts=[runsc_alert("u1")],
            incidents=[incident(None, "12:00:00Z", "12:00:00Z", ["u1/runtime-control"])],
            rejected=[{"index": 0, "field": "/time"}],
            repaired=[{"index": 1, "field": "/actor/process"}],
            rejected_hits=[{"index": 0, "decoy_id": "runtime-control"}],
            sequence_gaps=[{"source": "ebpf", "sensor_instance": "boot-1", "after": 0,
                            "before": 2}]))

case("duplicate-event-ids", "example", [TEL, EVAL],
     evaluate(W, [ev("x", "read", CREDS), ev("x", "connect", RUNSC_PATH)]),
     result(True, True, carry(sequences=[seq("ebpf", "boot-1", 2, "12:00:00Z")]),
            alerts=[host_breach_creds("x", alert_id="x/cloud-credentials#0"),
                    runsc_alert("x", alert_id="x/runtime-control#1")],
            incidents=[incident(None, "12:00:00Z", "12:00:00Z",
                                ["x/cloud-credentials#0", "x/runtime-control#1"])],
            duplicate_event_ids=["x"]))

PROBE = {"executable": "/usr/libexec/fs-audit", "executable_digest": R, "uid": 0,
         "max_interval_seconds": 600}
PROBE_ACTOR = actor(executable="/usr/libexec/fs-audit", executable_digest=R, uid=0)


def probe_events():
    events = []
    for minute in ("00", "10", "20", "30", "40", "50"):
        time = "12:%s:00Z" % minute
        events.append(ev(None, "read", CREDS, time=time, act=PROBE_ACTOR))
        events.append(ev(None, "read", "/home/deploy/.ssh/id_ed25519", time=time,
                         act=PROBE_ACTOR))
        events.append(ev(None, "connect", "127.0.0.1:2375", time=time, act=PROBE_ACTOR))
        events.append(ev(None, "connect", "172.17.0.1:22", time=time, act=PROBE_ACTOR))
        if minute == "00":
            events.append(ev(None, "connect", RUNSC_PATH, time=time, act=PROBE_ACTOR))
            events.append(ev(None, "connect", RUNSC_PATH, time="12:05:00Z",
                             act=PROBE_ACTOR))
    return events


case("broken-decoy-monitoring", "example", [TEL, EVAL],
     evaluate(W, probe_events(), probe=PROBE, window=("12:00:00Z", "13:00:00Z")),
     result(False, True, carry("13:00:00Z",
                               sequences=[seq("ebpf", "boot-1", 26, "12:50:00Z")],
                               last_probe=[
                                   {"decoy_id": "cloud-credentials", "received": ts("12:50:00Z")},
                                   {"decoy_id": "ssh-private-key", "received": ts("12:50:00Z")},
                                   {"decoy_id": "runtime-control", "received": ts("12:05:00Z")},
                                   {"decoy_id": "docker-api", "received": ts("12:50:00Z")},
                                   {"decoy_id": "gateway-ssh", "received": ts("12:50:00Z")}]),
            watch_gaps=[{"decoy_id": "runtime-control", "from": ts("12:05:00Z"),
                         "to": ts("13:00:00Z")}],
            probe_hits=26))

BATCH1_CARRY = carry(sequences=[seq("ebpf", "boot-1", 2, "12:00:00Z")])
case("sequences-batch-1", "example", [TEL],
     evaluate(W, [ev(None, "heartbeat", ""), ev(None, "heartbeat", "")]),
     result(False, True, BATCH1_CARRY))
D31 = "2026-10-31T"
D01 = "2026-11-01T"
BATCH2_CARRY = carry(D01 + "00:00:00Z", sequences=[
    seq("ebpf", "boot-1", 5, D31 + "12:00:00Z", missing=[(3, 4)]),
    seq("ebpf", "boot-2", 1, D31 + "12:00:00Z")])
case("sequences-batch-2", "example", [TEL],
     evaluate(W, [ev(None, "heartbeat", "", time=D31 + "12:00:00Z", sequence=5),
                  ev(None, "heartbeat", "", time=D31 + "12:00:00Z", sequence=2),
                  ev(None, "heartbeat", "", time=D31 + "12:00:00Z", instance="boot-2",
                     sequence=1)],
              window=(D31 + "00:00:00Z", D01 + "00:00:00Z"), carry=BATCH1_CARRY),
     result(False, True, BATCH2_CARRY,
            sequence_gaps=[{"source": "ebpf", "sensor_instance": "boot-1", "after": 2,
                            "before": 5}],
            sequence_duplicates=[{"source": "ebpf", "sensor_instance": "boot-1",
                                  "sequence": 2}],
            sensor_restarts=[{"source": "ebpf", "sensor_instance": "boot-2"}]))
case("sequences-batch-3", "example", [TEL],
     evaluate(W, [ev("h3", "heartbeat", "", time=D01 + "12:00:00Z", sequence=3)],
              window=(D01 + "00:00:00Z", "2026-11-02T00:00:00Z"), carry=BATCH2_CARRY),
     result(False, True, carry("2026-11-02T00:00:00Z", sequences=[
         seq("ebpf", "boot-1", 5, D01 + "12:00:00Z", missing=[(4, 4)]),
         seq("ebpf", "boot-2", 1, D31 + "12:00:00Z")]),
            late_fills=["h3"]))

case("silent-sensor", "example", [TEL],
     evaluate(W, [ev(None, "heartbeat", ""), ev(None, "heartbeat", "", time="12:10:00Z")],
              sources=[source("ebpf", silence=600)], window=("12:00:00Z", "13:00:00Z")),
     result(False, True, carry("13:00:00Z",
                               sequences=[seq("ebpf", "boot-1", 2, "12:10:00Z")],
                               last_seen=[{"source": "ebpf", "received": ts("12:10:00Z")}]),
            silence_gaps=[{"source": "ebpf", "from": ts("12:10:00Z"),
                           "to": ts("13:00:00Z")}]))

CORROBORATE = {"window_seconds": 5,
               "decoys": [{"decoy_id": "runtime-control", "sources": ["ebpf", "lsm"]}]}
TWO_SOURCES = [source("ebpf"), source("lsm")]
BLIND1_CARRY = carry(sequences=[seq("ebpf", "boot-1", 2, "23:59:58Z")],
                     recent_hits=[recent("b2", "runtime-control", "ebpf", "23:59:58Z")],
                     pending=[recent("b2", "runtime-control", "ebpf", "23:59:58Z",
                                     missing=["lsm"])])
case("blinded-sensor-batch-1", "example", [TEL],
     evaluate(W, [ev("b1", "connect", RUNSC_PATH),
                  ev("b2", "connect", RUNSC_PATH, time="23:59:58Z")],
              sources=TWO_SOURCES, corroboration=CORROBORATE),
     result(True, True, BLIND1_CARRY,
            alerts=[runsc_alert("b1"), runsc_alert("b2", time="23:59:58Z")],
            incidents=[incident(None, "12:00:00Z", "23:59:58Z",
                                ["b1/runtime-control", "b2/runtime-control"])],
            uncorroborated=[{"event_id": "b1", "decoy_id": "runtime-control",
                             "missing_sources": ["lsm"]}]))
case("blinded-sensor-batch-2", "example", [TEL],
     evaluate(W, [ev("b3", "connect", RUNSC_PATH, time=D31 + "00:00:01Z", source="lsm")],
              sources=TWO_SOURCES, corroboration=CORROBORATE, carry=BLIND1_CARRY,
              window=(D31 + "00:00:00Z", D01 + "00:00:00Z")),
     result(True, True, carry(D01 + "00:00:00Z", sequences=[
         seq("ebpf", "boot-1", 2, "23:59:58Z"),
         seq("lsm", "boot-1", 1, D31 + "00:00:01Z")]),
            alerts=[runsc_alert("b3", time=D31 + "00:00:01Z", source_name="lsm")],
            incidents=[incident(None, D31 + "00:00:01Z", D31 + "00:00:01Z",
                                ["b3/runtime-control"])]))

# --- evaluation boundaries and invariants
FULL_BINDINGS = [
    {"decoy_id": "cloud-credentials", "path": CREDS, "device": "2049", "inode": "101"},
    {"decoy_id": "cloud-credentials", "path": "/home/deploy/.aws/config", "device": "2049",
     "inode": "102"},
    {"decoy_id": "ssh-private-key", "path": "/home/deploy/.ssh/id_ed25519",
     "device": "2049", "inode": "103"},
    {"decoy_id": "ssh-private-key", "path": "/home/deploy/.ssh/id_ed25519.pub",
     "device": "2049", "inode": "104"},
    {"decoy_id": "runtime-control", "path": RUNSC_PATH, "device": "25", "inode": "7"},
]
case("clean-batch-fully-bound", "invariant", [EVAL, TEL],
     evaluate(W, [ev(None, "heartbeat", "")], decoy_inodes=FULL_BINDINGS),
     result(False, False, carry(sequences=[seq("ebpf", "boot-1", 1, "12:00:00Z")]),
            warnings=["unauthenticated"]))

case("inode-binding-mismatch-and-hard-link", "invariant", [EVAL],
     evaluate(W, [ev(None, "read", CREDS, target_inode={"device": "2049", "inode": "555"}),
                  ev(None, "read", "/tmp/copy", target_inode={"device": "2049",
                                                               "inode": "103"})],
              decoy_inodes=FULL_BINDINGS),
     result(True, True, carry(sequences=[seq("ebpf", "boot-1", 2, "12:00:00Z")]),
            warnings=["unauthenticated", "inode-binding-mismatch"],
            alerts=[host_breach_creds("u0"),
                    alert("u1", "ssh-private-key", "credential-file",
                          "/home/deploy/.ssh/id_ed25519", "/tmp/copy", "host-breach",
                          ["T1611", "T1552.004"])],
            incidents=[incident(None, "12:00:00Z", "12:00:00Z",
                                ["u0/cloud-credentials", "u1/ssh-private-key"])]))

case("ignore-stat-trades-metadata-detection", "boundary", [EVAL, STEALTH],
     evaluate(W, [ev(None, "stat", CREDS), ev(None, "stat", "/home/deploy/.aws/config"),
                  ev(None, "open", CREDS)], ignore_stat=["cloud-credentials"]),
     result(True, True, carry(sequences=[seq("ebpf", "boot-1", 3, "12:00:00Z")]),
            alerts=[host_breach_creds("u2")],
            incidents=[incident(None, "12:00:00Z", "12:00:00Z", ["u2/cloud-credentials"])],
            ignored=2))

case("mount-and-notify-mark-on-parent", "boundary", [EVAL],
     evaluate(W, [ev(None, "mount", "/home/deploy/.ssh"),
                  ev(None, "notify-mark", "/home/deploy/.aws/"),
                  ev(None, "read", "/home/deploy/.ssh"),
                  ev(None, "stat", "/home/deploy")]),
     result(True, True, carry(sequences=[seq("ebpf", "boot-1", 4, "12:00:00Z")]),
            alerts=[alert("u0", "ssh-private-key", "credential-file",
                          "/home/deploy/.ssh/id_ed25519", "/home/deploy/.ssh",
                          "host-breach", ["T1611", "T1552.004"]),
                    host_breach_creds("u1", observed="/home/deploy/.aws/")],
            incidents=[incident(None, "12:00:00Z", "12:00:00Z",
                                ["u0/ssh-private-key", "u1/cloud-credentials"])],
            ignored=2))

SYSCTL = "/usr/lib/systemd/systemd-sysctl"
SYSCTL_ACTOR = actor(executable=SYSCTL, executable_digest=R, uid=0)
case("kernel-interface-value-bound-suppression", "invariant", [EVAL, STEALTH],
     evaluate(W, [
         ev(None, "write", "/proc/sys/kernel/core_pattern", written_digest=V, act=SYSCTL_ACTOR),
         ev(None, "write", "/proc/sys/kernel/core_pattern", written_digest=OTHER,
            act=SYSCTL_ACTOR),
         ev(None, "write", "/tmp/p/sys/kernel/modprobe",
            target_fs={"type": "proc", "path": "sys/kernel/modprobe"}),
         ev(None, "truncate", "/proc/sys/kernel/core_pattern", act=SYSCTL_ACTOR),
         ev(None, "read", "/proc/sys/kernel/core_pattern", act=SYSCTL_ACTOR),
     ], suppressions=[{"decoy_id": "core-pattern", "executable": SYSCTL,
                       "executable_digests": [R], "uid": 0, "value_digest": V}]),
     result(True, True, carry(sequences=[seq("ebpf", "boot-1", 5, "12:00:00Z")]),
            alerts=[alert("u1", "core-pattern", "kernel-interface",
                          "/proc/sys/kernel/core_pattern", "/proc/sys/kernel/core_pattern",
                          "host-breach", ["T1611"], executable=SYSCTL, uid=0),
                    alert("u2", "modprobe-path", "kernel-interface",
                          "/proc/sys/kernel/modprobe", "/tmp/p/sys/kernel/modprobe",
                          "host-breach", ["T1611"])],
            incidents=[incident(None, "12:00:00Z", "12:00:00Z",
                                ["u1/core-pattern", "u2/modprobe-path"])],
            suppressed=[{"event_id": "u0", "decoy_id": "core-pattern"},
                        {"event_id": "u3", "decoy_id": "core-pattern"}],
            ignored=1))

case("probe-loader-variable-is-not-trusted", "invariant", [EVAL, TEL],
     evaluate(W, [
         ev(None, "stat", CREDS, act=dict(PROBE_ACTOR, environment_names=["PATH"])),
         ev(None, "stat", CREDS, act=dict(PROBE_ACTOR,
                                          environment_names=["LD_PRELOAD", "PATH"])),
         ev(None, "stat", "/home/deploy/.aws/config", act=PROBE_ACTOR),
     ], probe=PROBE, window=("12:00:00Z", "12:10:00Z")),
     result(True, True, carry("12:10:00Z",
                              sequences=[seq("ebpf", "boot-1", 3, "12:00:00Z")],
                              last_probe=[{"decoy_id": n, "received": ts("12:00:00Z")}
                                          for n in ("cloud-credentials", "ssh-private-key",
                                                    "runtime-control", "docker-api",
                                                    "gateway-ssh")]),
            alerts=[host_breach_creds("u1", executable="/usr/libexec/fs-audit", uid=0)],
            incidents=[incident(None, "12:00:00Z", "12:00:00Z", ["u1/cloud-credentials"])],
            probe_hits=2))

SBX2 = {"sandbox_id": "sbx-2", "runtime_processes": [proc(4200, 600)],
        "harness_processes": [proc(3000, 400)]}
case("shared-harness-names-no-sandbox", "boundary", [ATTR],
     evaluate(W, [ev(None, "read", CREDS, act=actor((3000, 400))),
                  ev(None, "connect", "127.0.0.1:2375", time="12:00:01Z",
                     act=actor((4200, 600))),
                  ev(None, "connect", RUNSC_PATH, time="12:00:02Z",
                     act=actor((9, 9), [(3000, 400)]))],
              sandboxes=[SBX1, SBX2]),
     result(True, True, carry(sequences=[seq("ebpf", "boot-1", 3, "12:00:02Z")]),
            alerts=[host_breach_creds("u0", verdict="harness-escape", attribution="harness"),
                    alert("u1", "docker-api", "endpoint", "127.0.0.1:2375", "127.0.0.1:2375",
                          "escape-attempt", ["T1611", "T1552.007"], sandbox_id="sbx-2",
                          attribution="runtime", time="12:00:01Z"),
                    runsc_alert("u2", "harness-escape", time="12:00:02Z",
                                attribution="harness")],
            incidents=[incident(None, "12:00:00Z", "12:00:02Z",
                                ["u0/cloud-credentials", "u2/runtime-control"]),
                       incident("sbx-2", "12:00:01Z", "12:00:01Z", ["u1/docker-api"])]))

case("unexpected-kernel-helpers", "boundary", [EVAL, ATTR],
     evaluate(W, [ev(None, "exec", "/usr/bin/kmod", target_digest=OTHER,
                     act=actor(helper_depth=0)),
                  ev(None, "exec", "/sbin/modprobe", target_digest=R,
                     act=actor(helper_depth=0)),
                  ev(None, "exec", "/bin/sh", act=actor(helper_depth=1))],
              expected_helpers=[{"path": "/usr/bin/kmod", "digests": [R]}]),
     result(True, True, carry(sequences=[seq("ebpf", "boot-1", 3, "12:00:00Z")]),
            alerts=[alert("u0", "helper-exec", "kernel-helper", None, "/usr/bin/kmod",
                          "escape-confirmed", ["T1611"], attribution="kernel-helper"),
                    alert("u1", "helper-exec", "kernel-helper", None, "/sbin/modprobe",
                          "escape-confirmed", ["T1611"], attribution="kernel-helper")],
            incidents=[incident(None, "12:00:00Z", "12:00:00Z",
                                ["u0/helper-exec", "u1/helper-exec"])],
            ignored=1))


def rejection_events():
    nested = []
    for _ in range(7):
        nested = [nested]
    return [
        "garbage",
        ev(None, "read", CREDS, deployment="other-host"),
        ev(None, "heartbeat", "", time="2026-10-29T23:59:59Z"),
        ev(None, "connect", RUNSC_PATH, source="audit"),
        ev(None, "teleport", "/proc/sys/kernel/modprobe"),
        ev(None, "credential-use", CREDS),
        {k: val for k, val in ev(None, "connect", "172.17.0.1:22").items() if k != "mac"},
        ev(None, "stat", "/home/deploy/.ssh/id_ed25519.pub",
           act=dict(actor(), process={"pid": 77, "start_ticks": 1, "ns": 5}), extra=True),
        {k: val for k, val in ev(None, "heartbeat", "",
                                 act={k2: v2 for k2, v2 in actor().items()
                                      if k2 != "comm"}).items()
         if k != "target_digest"},
        ev(None, "read", CREDS, x=[nested]),
    ]


case("rejected-and-repaired-events", "invariant", [EVAL, TEL],
     evaluate(W, rejection_events(), sources=[source("ebpf")]),
     result(True, True,
            carry(sequences=[seq("ebpf", "boot-1", 7, "12:00:00Z", missing=[(1, 5)])]),
            alerts=[alert("u7", "ssh-private-key", "credential-file",
                          "/home/deploy/.ssh/id_ed25519", "/home/deploy/.ssh/id_ed25519.pub",
                          "host-breach", ["T1611", "T1552.004"])],
            incidents=[incident(None, "12:00:00Z", "12:00:00Z", ["u7/ssh-private-key"])],
            rejected=[{"index": 0, "field": ""}, {"index": 1, "field": "/deployment_id"},
                      {"index": 2, "field": "/received"}, {"index": 3, "field": "/source"},
                      {"index": 4, "field": "/action"}, {"index": 5, "field": "/target"},
                      {"index": 6, "field": "/mac"},
                      {"index": 9, "field": "/x/0/0/0/0/0/0/0"}],
            repaired=[{"index": 7, "field": "/actor/process/ns"},
                      {"index": 7, "field": "/extra"},
                      {"index": 8, "field": "/actor/comm"},
                      {"index": 8, "field": "/target_digest"}],
            rejected_hits=[{"index": 1, "decoy_id": "cloud-credentials"},
                           {"index": 3, "decoy_id": "runtime-control"},
                           {"index": 4, "decoy_id": "modprobe-path"},
                           {"index": 6, "decoy_id": "gateway-ssh"},
                           {"index": 9, "decoy_id": "cloud-credentials"}],
            sequence_gaps=[{"source": "ebpf", "sensor_instance": "boot-1", "after": 0,
                            "before": 6}]))

SILENCE_CARRY = carry("12:00:00Z", sequences=[seq("ebpf", "boot-1", 10, "11:55:00Z")],
                      last_seen=[{"source": "ebpf", "received": ts("11:55:00Z")},
                                 {"source": "lsm", "received": ts("11:00:00Z")}])
case("silence-across-batches", "boundary", [TEL],
     evaluate(W, [ev(None, "heartbeat", "", time="12:08:00Z", sequence=11),
                  ev(None, "heartbeat", "", time="12:30:00Z", sequence=12)],
              sources=[source("ebpf", silence=600), source("lsm", silence=1800)],
              window=("12:00:00Z", "13:00:00Z"), carry=SILENCE_CARRY),
     result(False, True, carry("13:00:00Z",
                               sequences=[seq("ebpf", "boot-1", 12, "12:30:00Z")],
                               last_seen=[{"source": "ebpf", "received": ts("12:30:00Z")},
                                          {"source": "lsm", "received": ts("11:00:00Z")}]),
            silence_gaps=[{"source": "ebpf", "from": ts("11:55:00Z"), "to": ts("12:08:00Z")},
                          {"source": "ebpf", "from": ts("12:08:00Z"), "to": ts("12:30:00Z")},
                          {"source": "ebpf", "from": ts("12:30:00Z"), "to": ts("13:00:00Z")},
                          {"source": "lsm", "from": ts("11:00:00Z"), "to": ts("13:00:00Z")}]))

case("corroboration-within-batch", "boundary", [TEL],
     evaluate(W, [ev(None, "connect", RUNSC_PATH),
                  ev(None, "connect", RUNSC_PATH, time="12:00:03Z", source="lsm"),
                  ev(None, "connect", RUNSC_PATH, time="12:00:10Z"),
                  ev(None, "connect", RUNSC_PATH, time="12:07:00Z")],
              sources=TWO_SOURCES, corroboration=CORROBORATE,
              window=("12:00:00Z", "12:10:00Z")),
     result(True, True, carry("12:10:00Z",
                              sequences=[seq("ebpf", "boot-1", 3, "12:07:00Z"),
                                         seq("lsm", "boot-1", 1, "12:00:03Z")],
                              recent_hits=[recent("u3", "runtime-control", "ebpf",
                                                  "12:07:00Z")],
                              pending=[recent("u3", "runtime-control", "ebpf", "12:07:00Z",
                                              missing=["lsm"])]),
            alerts=[runsc_alert("u0"), runsc_alert("u1", time="12:00:03Z", source_name="lsm"),
                    runsc_alert("u2", time="12:00:10Z"), runsc_alert("u3", time="12:07:00Z")],
            incidents=[incident(None, "12:00:00Z", "12:07:00Z",
                                ["u0/runtime-control", "u1/runtime-control",
                                 "u2/runtime-control", "u3/runtime-control"])],
            uncorroborated=[{"event_id": "u2", "decoy_id": "runtime-control",
                             "missing_sources": ["lsm"]}]))

# --- evaluate validation boundaries
case("reject-empty-window", "boundary", [EVAL, C],
     evaluate(W, [], window=("12:00:00Z", "12:00:00.000Z")), error("/window/end"))
case("reject-carry-from-another-window", "boundary", [TEL, C],
     evaluate(W, [], carry=carry("2026-10-29T00:00:00Z")), error("/window/start"))
case("reject-inode-binding-off-decoy", "boundary", [EVAL, C],
     evaluate(W, [], decoy_inodes=[{"decoy_id": "cloud-credentials",
                                    "path": "/home/deploy/.aws", "device": "1",
                                    "inode": "2"}]),
     error("/decoy_inodes/0/path"))
case("reject-undeclared-corroboration-source", "boundary", [TEL, C],
     evaluate(W, [], corroboration={"window_seconds": 5, "decoys": [
         {"decoy_id": "runtime-control", "sources": ["ebpf", "lsm"]}]},
              sources=[source("ebpf")]),
     error("/corroboration/decoys/0/sources/1"))
case("reject-repeated-source", "boundary", [TEL, C],
     evaluate(W, [], sources=[source("ebpf"), source("ebpf", delay=60)]),
     error("/sources/1/source"))
case("reject-tampered-watch", "invariant", [EVAL, C],
     evaluate(dict(W, decoys=[dict(RUNSC, canonical_location="/var/run/runsc-debug.sock")]
                   + kernel()), []),
     error("/watch/decoys/0/canonical_location"))
case("reject-harness-also-runtime", "boundary", [EVAL, C],
     evaluate(W, [], sandboxes=[{"sandbox_id": "sbx-1", "runtime_processes": [proc(1, 2)],
                                 "harness_processes": [proc(1, 2)]}]),
     error("/sandboxes/0/harness_processes/0"))
case("reject-keys-for-wrong-sources", "boundary", [TEL, C],
     evaluate(W, [], authentication="required", sensor_keys={"lsm": K}),
     error("/sensor_keys"))
case("reject-malformed-request-key", "boundary", [TEL],
     evaluate(W, [], sensor_keys={"ebpf": "0F" * 32}), error("/sensor_keys/ebpf"))
case("reject-value-digest-on-file-decoy", "boundary", [EVAL, C],
     evaluate(W, [], suppressions=[dict(RESTIC_SUPPRESSION, value_digest=V)]),
     error("/suppressions/0/value_digest"))
case("reject-empty-harness-signature", "boundary", [ATTR, C],
     evaluate(W, [], harness_signatures=[{"harness_id": "x", "environment_names": [],
                                          "executables": []}]),
     error("/harness_signatures/0/executables"))

# --- further layout, binding, and carry invariants
case("plan-relocation-displaces-layout", "invariant", [DEC, CRED],
     gvisor_plan(exposure={"paths": [], "endpoints": []},
                 relocate=[{"decoy_id": "runtime-control",
                            "location": "/root/.ssh/id_ed25519"}]),
     plan_result(["seed-in-request"],
                 watch("prod-agents", "gvisor", "linux-host", [
                     CLOUD_HOME, SSH_HOME,
                     d("runtime-control", "socket", "/root/.ssh/id_ed25519", listener=True),
                     DOCKER_API, GATEWAY] + kernel()),
                 [ssh_material("ssh-private-key", GV_SSH, "deploy@ci-17")],
                 [comp("cloud-credentials", "/home/deploy/.aws/config", AWS_CONFIG),
                  comp("ssh-private-key", "/home/deploy/.ssh/id_ed25519.pub", GV_PUB + "\n")],
                 GV_SKIPPED))

case("plan-loopback-and-mapped-exposure", "boundary", [DEC],
     gvisor_plan(exposure={"paths": ["/root/.ssh"],
                           "endpoints": ["127.0.0.0/8:2375", "[::ffff:172.17.0.0]/112:22"]}),
     plan_result(["seed-in-request", "public-socket-name"],
                 watch("prod-agents", "gvisor", "linux-host",
                       [CLOUD_HOME, SSH_HOME, RUNSC, GATEWAY] + kernel()),
                 [ssh_material("ssh-private-key", GV_SSH, "deploy@ci-17")],
                 [comp("cloud-credentials", "/home/deploy/.aws/config", AWS_CONFIG),
                  comp("ssh-private-key", "/home/deploy/.ssh/id_ed25519.pub", GV_PUB + "\n")],
                 GV_SKIPPED + [skip("docker-api", "127.0.0.1:2375", "exposed")]))

PREVIOUS_BINDINGS = [
    {"decoy_id": "cloud-credentials", "path": CREDS, "device": "2049", "inode": "201"},
    {"decoy_id": "cloud-credentials", "path": CREDS, "device": "2049", "inode": "200"},
    {"decoy_id": "ssh-private-key", "path": "/home/deploy/.ssh/id_ed25519",
     "device": "2049", "inode": "200"},
]
case("previous-binding-yields-to-current", "invariant", [EVAL],
     evaluate(W, [ev(None, "read", "/tmp/x", target_inode={"device": "2049", "inode": "200"}),
                  ev(None, "read", "/tmp/y", target_inode={"device": "2049", "inode": "201"})],
              decoy_inodes=PREVIOUS_BINDINGS),
     result(True, True, carry(sequences=[seq("ebpf", "boot-1", 2, "12:00:00Z")]),
            alerts=[alert("u0", "ssh-private-key", "credential-file",
                          "/home/deploy/.ssh/id_ed25519", "/tmp/x", "host-breach",
                          ["T1611", "T1552.004"]),
                    host_breach_creds("u1", observed="/tmp/y")],
            incidents=[incident(None, "12:00:00Z", "12:00:00Z",
                                ["u0/ssh-private-key", "u1/cloud-credentials"])]))

case("reject-third-inode-entry", "boundary", [EVAL, C],
     evaluate(W, [], decoy_inodes=PREVIOUS_BINDINGS[:2] + [dict(PREVIOUS_BINDINGS[0],
                                                                inode="202")]),
     error("/decoy_inodes/2"))
case("reject-shared-current-inode", "boundary", [EVAL, C],
     evaluate(W, [], decoy_inodes=[PREVIOUS_BINDINGS[0],
                                   dict(PREVIOUS_BINDINGS[2], inode="201")]),
     error("/decoy_inodes/1"))

case("pending-without-corroboration-listing", "boundary", [TEL],
     evaluate(W, [], sources=TWO_SOURCES, window=(D31 + "00:00:00Z", D01 + "00:00:00Z"),
              carry=carry(D31 + "00:00:00Z",
                          sequences=[seq("ebpf", "boot-1", 4, "23:59:00Z")],
                          recent_hits=[recent("p1", "runtime-control", "ebpf", "23:59:00Z")],
                          pending=[recent("p1", "runtime-control", "ebpf", "23:59:00Z",
                                          missing=["lsm"])])),
     result(False, True, carry(D01 + "00:00:00Z",
                               sequences=[seq("ebpf", "boot-1", 4, "23:59:00Z")]),
            uncorroborated=[{"event_id": "p1", "decoy_id": "runtime-control",
                             "missing_sources": ["lsm"]}]))

SMOKE_CASE = "metadata-reconnaissance"


# ------------------------------------------------------------------- running

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class _CleanEnv:
    """Remove the ambient variables while a case runs, then restore them."""

    def __init__(self, **values):
        self.values = values

    def __enter__(self):
        self.saved = {n: os.environ.pop(n) for n in ENV_NAMES if n in os.environ}
        os.environ.update(self.values)

    def __exit__(self, *exc):
        for name in ENV_NAMES:
            os.environ.pop(name, None)
        os.environ.update(self.saved)


def _app():
    try:
        from main import main as app_main
    except ImportError:  # pragma: no cover - the archive always ships main.py
        from tripwire.engine import run

        def app_main(request):
            return run(request, os.environ)
    return app_main


def run_case(app_main, entry):
    with _CleanEnv():
        actual = app_main(*json.loads(json.dumps(entry["arguments"])))
    return canonical(actual) == canonical(entry["expected_result"]), actual


def smoke_arguments():
    for entry in CASES:
        if entry["case_id"] == SMOKE_CASE:
            return json.loads(json.dumps(entry["arguments"]))
    raise LookupError(SMOKE_CASE)


class GeneratedCases(unittest.TestCase):
    """One test method per manifest case."""


def _make_test(entry):
    def test(self):
        ok, actual = run_case(_app(), entry)
        self.assertEqual(canonical(actual), canonical(entry["expected_result"]))
        self.assertTrue(ok)
    return test


for _entry in CASES:
    setattr(GeneratedCases, "test_" + _entry["case_id"].replace("-", "_"),
            _make_test(_entry))


class EnvironmentAndProcess(unittest.TestCase):
    """Behaviors that need the environment or the process boundary, which
    the manifest's argument arrays cannot express."""

    def run_app(self, request, **env):
        with _CleanEnv(**env):
            return _app()(request)

    def test_environment_seed(self):
        request = gvisor_plan()
        del request["seed"]
        out = self.run_app(request, SANDBOX_HONEYPOT_SEED="x" * 40)
        self.assertEqual(out["warnings"], ["public-socket-name"])

    def test_seed_in_both_places(self):
        self.assertEqual(self.run_app(gvisor_plan(), SANDBOX_HONEYPOT_SEED="x" * 40),
                         error("/seed"))

    def test_public_seed_only_in_request(self):
        request = gvisor_plan()
        del request["seed"]
        self.assertEqual(self.run_app(request, SANDBOX_HONEYPOT_SEED=SEED), error("/seed"))

    def test_environment_sensor_keys(self):
        request = evaluate(W, signed_events()[:1], authentication="required")
        out = self.run_app(request, SANDBOX_HONEYPOT_SENSOR_KEYS=json.dumps({"ebpf": K}))
        self.assertEqual(out["warnings"], ["missing-inode-binding"])
        self.assertEqual([a["alert_id"] for a in out["alerts"]], ["m1/runtime-control"])
        self.assertEqual(out["rejected"], [])

    def test_malformed_environment_keys(self):
        request = evaluate(W, [], authentication="required")
        self.assertEqual(self.run_app(request, SANDBOX_HONEYPOT_SENSOR_KEYS="{\"ebpf\":1}"),
                         error("/sensor_keys"))

    def test_keys_in_both_places(self):
        request = evaluate(W, [], authentication="required", sensor_keys={"ebpf": K})
        self.assertEqual(self.run_app(request, SANDBOX_HONEYPOT_SENSOR_KEYS="{}"),
                         error("/sensor_keys"))

    def test_environment_ignored_when_off(self):
        out = self.run_app(evaluate(W, []), SANDBOX_HONEYPOT_SENSOR_KEYS="not json")
        self.assertEqual(out["warnings"], ["unauthenticated", "missing-inode-binding"])

    def cli(self, *argv):
        try:
            import main as app_module
        except ImportError:  # pragma: no cover - packaging without main.py
            self.skipTest("main.py is not importable as a module")
        buffer = io.BytesIO()

        class Out:
            def __init__(self):
                self.buffer = buffer

            def write(self, text):
                buffer.write(text.encode("utf-8"))

            def flush(self):
                pass

        with _CleanEnv(), redirect_stdout(Out()):
            status = app_module._cli(["main.py"] + list(argv))
        return status, buffer.getvalue().decode("utf-8")

    def test_cli_success_and_failure_status(self):
        status, text = self.cli(json.dumps([gvisor_plan()]))
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(text), GV_RESULT)
        status, text = self.cli(json.dumps([gvisor_plan(seed="short")]))
        self.assertEqual(status, 2)
        self.assertEqual(text, '{"error":{"code":"invalid-request","field":"/seed"}}\n')

    def test_cli_rejects_bare_object_and_bad_json(self):
        for arg in (json.dumps(gvisor_plan()), "[{", "[1e400]", "[NaN]"):
            status, text = self.cli(arg)
            self.assertEqual((status, json.loads(text)), (2, error("")))

    def test_cli_repeated_keys(self):
        status, text = self.cli('[{"operation":"plan","operation":"plan"}]')
        self.assertEqual((status, json.loads(text)), (2, error("")))
        request = evaluate(W, [ev("q1", "read", CREDS)])
        text_req = json.dumps([request]).replace('"event_id": "q1"',
                                                 '"event_id": "q1", "event_id": "q2"')
        status, text = self.cli(text_req)
        out = json.loads(text)
        self.assertEqual(status, 0)
        self.assertEqual(out["rejected"], [{"index": 0, "field": ""}])
        self.assertEqual(out["rejected_hits"], [{"index": 0, "decoy_id": "cloud-credentials"}])

    def test_cli_number_forms(self):
        request = evaluate(W, [ev("q1", "read", CREDS, sequence=7)])
        text_req = json.dumps([request]).replace('"sequence": 7', '"sequence": 7e0')
        status, text = self.cli(text_req)
        out = json.loads(text)
        self.assertEqual(out["carry"]["sequences"][0]["highest"], 7)
        self.assertEqual(out["rejected"], [])
        text_req = json.dumps([request]).replace('"sequence": 7', '"sequence": 1e400')
        out = json.loads(self.cli(text_req)[1])
        self.assertEqual(out["rejected"], [{"index": 0, "field": "/sequence"}])
        self.assertEqual(out["rejected_hits"], [{"index": 0, "decoy_id": "cloud-credentials"}])

    def test_cli_deep_event_rejects_only_that_event(self):
        request = evaluate(W, [ev("q1", "read", CREDS, deep=None), ev("q2", "read", CREDS)])
        text_req = json.dumps([request]).replace('"deep": null',
                                                 '"deep": ' + "[" * 5000 + "]" * 5000)
        out = json.loads(self.cli(text_req)[1])
        self.assertEqual(out["rejected"], [{"index": 0, "field": "/deep/0/0/0/0/0/0/0"}])
        self.assertEqual([a["alert_id"] for a in out["alerts"]], ["q2/cloud-credentials"])

    def test_mac_ignores_received_and_escapes(self):
        from tripwire.events import compute_mac
        event = dict(M1, mac="ignored", received="2026-10-30T12:00:59Z")
        self.assertEqual(compute_mac(event, K), M1_MAC)

    def test_jcs_numbers(self):
        from tripwire.common import jcs
        self.assertEqual(jcs([7.0, 1e21, 1.5e-7, 0.000001, 123456789012345680000.0, -0.0]),
                         "[7,1e+21,1.5e-7,0.000001,123456789012345680000,0]")


NATIVE_ONLY = (EnvironmentAndProcess,)


def run_generated_cases(app_main):
    """Run every manifest case through app_main, then the native-only tests.
    Returns (report, all_passed)."""
    cases = []
    all_ok = True
    for entry in CASES:
        try:
            ok, _ = run_case(app_main, entry)
        except Exception:  # a crash is a failed case, never a pass
            ok = False
        all_ok = all_ok and ok
        cases.append({"case_id": entry["case_id"], "outcome": "passed" if ok else "failed"})
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for test_class in NATIVE_ONLY:
        suite.addTests(loader.loadTestsFromTestCase(test_class))
    outcome = unittest.TestResult()
    suite.run(outcome)
    if not outcome.wasSuccessful():
        all_ok = False
    return {"schema": "literate-ai/generated-test-results@1", "cases": cases}, all_ok


if __name__ == "__main__":
    unittest.main()
