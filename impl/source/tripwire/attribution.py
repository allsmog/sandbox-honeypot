"""Attribution rules, verdicts, techniques, and passive harness identification."""


class Sandboxes:
    def __init__(self, sandboxes):
        self.runtime = {}           # identity -> sandbox_id
        self.harness = {}           # identity -> [sandbox_id, ...]
        self.ids = set()
        for sandbox in sandboxes:
            sid = sandbox["sandbox_id"]
            self.ids.add(sid)
            for proc in sandbox["runtime_processes"]:
                self.runtime[_key(proc)] = sid
            for proc in sandbox["harness_processes"]:
                owners = self.harness.setdefault(_key(proc), [])
                if sid not in owners:
                    owners.append(sid)

    def harness_sandbox(self, identity):
        owners = self.harness[identity]
        return owners[0] if len(owners) == 1 else None

    def is_runtime_or_harness(self, identity):
        return identity in self.runtime or identity in self.harness

    def lineage_trusted_out(self, actor):
        """True when the actor is, or descends from, a runtime or harness."""
        process = actor["process"]
        if process is not None and self.is_runtime_or_harness(process):
            return True
        return any(self.is_runtime_or_harness(item) for item in actor["ancestry"])

    def attribute(self, actor):
        """Return (sandbox_id, attribution)."""
        process = actor["process"]
        if process is not None and process in self.runtime:
            return self.runtime[process], "runtime"
        if process is not None and process in self.harness:
            return self.harness_sandbox(process), "harness"
        for item in actor["ancestry"]:
            if item in self.runtime:
                return self.runtime[item], "ancestry"
            if item in self.harness:
                return self.harness_sandbox(item), "harness"
        if actor["helper_depth"] is not None:
            return None, "kernel-helper"
        if actor["sandbox_id"] is not None and actor["sandbox_id"] in self.ids:
            return actor["sandbox_id"], "sensor"
        return None, None


def _key(proc):
    return (int(proc["pid"]), int(proc["start_ticks"]))


def verdict(action, decoy_kind, attribution):
    if action == "credential-use":
        return "credential-exfiltrated"
    if attribution == "harness":
        return "harness-escape"
    if decoy_kind == "endpoint" and attribution in ("runtime", "sensor"):
        return "escape-attempt"
    if attribution == "runtime":
        return "runtime-mediated"
    if attribution in ("ancestry", "kernel-helper", "sensor"):
        return "escape-confirmed"
    return "host-breach"


def techniques(verdict_name, technique):
    if verdict_name == "credential-exfiltrated":
        return [technique, "T1078"]
    if technique == "T1611":
        return ["T1611"]
    return ["T1611", technique]


def identify_harness(signatures, actor):
    if not signatures:
        return None
    names = actor["environment_names"]
    executable = actor["executable"]
    final = executable.rsplit("/", 1)[-1] if executable is not None else None
    best = []
    best_count = 0
    for signature in signatures:
        matched = []
        if names is not None:
            matched += ["env:" + n for n in signature["environment_names"] if n in names]
        if final is not None:
            matched += ["exe:" + e for e in signature["executables"] if e == final]
        if len(matched) > best_count:
            best, best_count = [(signature["harness_id"], matched)], len(matched)
        elif len(matched) == best_count:
            best.append((signature["harness_id"], matched))
    if best_count > 0 and len(best) == 1:
        harness_id, matched = best[0]
        return {"harness_id": harness_id, "matched": sorted(matched), "abstained": False}
    return {"harness_id": None, "matched": [], "abstained": True}
