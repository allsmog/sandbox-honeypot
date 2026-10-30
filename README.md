# sandbox-honeypot

Defense-in-depth tripwire for workload sandboxes such as gVisor, Capsem, Firecracker
and Kata. The sandbox remains the isolation boundary; this project plants **host
decoys** outside it (credential files, control sockets, a metadata endpoint) that no
legitimate sandboxed workload can reach. Any contact with a decoy means the boundary
failed, so the tripwire reports it as a breakout.

This is a [Literate AI](https://github.com/jordanhubbard/literate-ai) project: the
specification is the authority and source code is generated from it.

| Component | What it does |
| --- | --- |
| [`components/sandbox-tripwire`](components/sandbox-tripwire/component.md) | `plan` places host decoys outside every path and endpoint the sandbox exposes; `evaluate` turns host sensor events that touch them into attributed alerts and incidents. |

Version 0.1.0 is a pure decision engine: it does not write decoy files, open
listeners or run sensors. Operators materialize the `plan` result and feed host
sensor events (fanotify, auditd, eBPF, flow or cloud audit logs) into `evaluate`.

## Working on it

```console
litai status --project .
litai verify .
litai rebuild --project . --allow-host-execution
```

`rebuild` generates, builds, tests and runs code on this host; review the plan first.
