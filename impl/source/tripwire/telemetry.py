"""Sequences, restarts, silence, self-test watch gaps, corroboration, carry."""

from .common import NS

MAX_INSTANCES = 4
MAX_MISSING = 16
MAX_RECENT = 16
MAX_PENDING = 16


def _latest(pairs):
    """pairs of (instant, text); the latest, first among equal instants."""
    best = None
    for pair in pairs:
        if best is None or pair[0] > best[0]:
            best = pair
    return best


def sequences(accepted, carry, declared):
    """accepted: views in index order. Returns a dict of tamper lists and
    the carried sequence state."""
    state = {}
    order_known = []
    for entry in (carry["sequences"] if carry else []):
        key = (entry["source"], entry["sensor_instance"])
        if entry["source"] not in declared or key in state:
            continue
        state[key] = {
            "highest": int(entry["highest"]),
            "missing": [[int(r["from"]), int(r["to"])] for r in entry["missing"]],
            "last_received": entry["last_received_pair"],
        }
        order_known.append(key)
    known = set(state)
    restarts = []
    groups = {}
    for view in accepted:
        key = (view.source, view.sensor_instance)
        if key not in known:
            if any(other[0] == key[0] for other in known):
                restarts.append({"source": key[0], "sensor_instance": key[1]})
            known.add(key)
        groups.setdefault(key, []).append(view)
    gaps, late, duplicates = [], [], []
    for key, views in groups.items():
        st = state.setdefault(key, {"highest": 0, "missing": [], "last_received": None})
        for view in sorted(views, key=lambda x: (x.sequence, x.index)):
            seq = view.sequence
            if seq > st["highest"]:
                if seq > st["highest"] + 1:
                    gaps.append({"source": key[0], "sensor_instance": key[1],
                                 "after": st["highest"], "before": seq})
                    st["missing"].append([st["highest"] + 1, seq - 1])
                st["highest"] = seq
                continue
            for pos, (low, high) in enumerate(st["missing"]):
                if low <= seq <= high:
                    pieces = []
                    if low < seq:
                        pieces.append([low, seq - 1])
                    if seq < high:
                        pieces.append([seq + 1, high])
                    st["missing"][pos:pos + 1] = pieces
                    late.append((view.index, view.event_id))
                    break
            else:
                duplicates.append({"source": key[0], "sensor_instance": key[1],
                                   "sequence": seq})
        candidates = [v.received for v in views]
        if st["last_received"] is not None:
            candidates.insert(0, st["last_received"])
        st["last_received"] = _latest(candidates)
    gaps.sort(key=lambda g: (g["source"], g["sensor_instance"], g["after"]))
    duplicates.sort(key=lambda d: (d["source"], d["sensor_instance"], d["sequence"]))
    late.sort()
    carried = []
    by_source = {}
    for key, st in state.items():
        by_source.setdefault(key[0], []).append((key, st))
    for source, entries in by_source.items():
        entries.sort(key=lambda e: (e[1]["last_received"][0], e[0][1]), reverse=True)
        for key, st in entries[:MAX_INSTANCES]:
            missing = sorted(st["missing"], key=lambda r: r[1], reverse=True)[:MAX_MISSING]
            missing.sort(key=lambda r: r[0])
            carried.append({"source": key[0], "sensor_instance": key[1],
                            "highest": st["highest"],
                            "missing": [{"from": a, "to": b} for a, b in missing],
                            "last_received": st["last_received"][1]})
    carried.sort(key=lambda c: (c["source"], c["sensor_instance"]))
    return {"sequence_gaps": gaps, "late_fills": [eid for _, eid in late],
            "sequence_duplicates": duplicates, "sensor_restarts": restarts,
            "carry": carried}


def gaps_between(start, times, end, limit_seconds):
    """start/end/times are (instant, text). Returns ([(from, to)], latest)."""
    points = [start] + sorted(times, key=lambda t: t[0]) + [end]
    out = []
    for a, b in zip(points, points[1:]):
        if b[0] - a[0] > limit_seconds * NS:
            out.append((a[1], b[1]))
    return out, points[-2]


def silence(accepted, sources, carry, window_start, window_end):
    carried = {}
    for entry in (carry["last_seen"] if carry else []):
        carried.setdefault(entry["source"], entry["received_pair"])
    gaps, last_seen = [], []
    for source in sorted(sources):
        limit = sources[source]["max_silence_seconds"]
        if limit is None:
            continue
        start = carried.get(source, window_start)
        times = [v.received for v in accepted if v.source == source]
        found, latest = gaps_between(start, times, window_end, limit)
        gaps += [{"source": source, "from": a, "to": b} for a, b in found]
        last_seen.append({"source": source, "received": latest[1]})
    return gaps, last_seen


def watch_gaps(planted_ids, probe, probe_times, carry, window_start, window_end):
    """probe_times: decoy_id -> [(instant, text)] of own-location probe hits."""
    if probe is None:
        return [], []
    carried = {}
    for entry in (carry["last_probe"] if carry else []):
        carried.setdefault(entry["decoy_id"], entry["received_pair"])
    gaps, last_probe = [], []
    for decoy_id in planted_ids:
        start = carried.get(decoy_id, window_start)
        found, latest = gaps_between(start, probe_times.get(decoy_id, []), window_end,
                                     probe["max_interval_seconds"])
        gaps += [{"decoy_id": decoy_id, "from": a, "to": b} for a, b in found]
        last_probe.append({"decoy_id": decoy_id, "received": latest[1]})
    return gaps, last_probe


class Hit:
    def __init__(self, event_id, decoy_id, source, time, received, index=None,
                 missing=None):
        self.event_id = event_id
        self.decoy_id = decoy_id
        self.source = source
        self.time = time            # (instant, text)
        self.received = received    # (instant, text)
        self.index = index          # event index, None when carried
        self.missing = missing      # carried missing_sources

    def order(self):
        return (self.time[0], self.event_id)

    def as_recent(self):
        return {"event_id": self.event_id, "decoy_id": self.decoy_id,
                "source": self.source, "time": self.time[1],
                "received": self.received[1]}


def corroborate(corroboration, sources, batch_hits, carry, window_end):
    """batch_hits: Hit objects (accepted non-credential-use hits) in event
    order. Returns (uncorroborated, recent_hits, pending)."""
    listing = {}
    window = 0
    if corroboration is not None:
        window = int(corroboration["window_seconds"]) * NS
        for entry in corroboration["decoys"]:
            listing[entry["decoy_id"]] = list(entry["sources"])

    def horizon(decoy_id):
        delays = [int(sources[s]["max_delay_seconds"]) for s in listing[decoy_id]]
        return window + max(delays) * NS

    def listed(hit):
        return (hit.decoy_id in listing and hit.source in sources
                and hit.source in listing[hit.decoy_id])

    batch = [h for h in batch_hits if listed(h)]
    carried_recent = []
    carried_pending = []
    if carry:
        carried_recent = [h for h in carry["recent_hits_objs"] if listed(h)]
        carried_pending = list(carry["pending_objs"])
    pool = batch + carried_recent

    def missing_for(hit):
        out = []
        for source in listing[hit.decoy_id]:
            if source == hit.source:
                continue
            if not any(o.decoy_id == hit.decoy_id and o.source == source
                       and abs(o.time[0] - hit.time[0]) <= window for o in pool):
                out.append(source)
        return sorted(out)

    unc_carried = []
    unc_batch = []
    pending = []
    for hit in carried_pending:
        if not listed(hit):
            missing = missing_for(hit) if hit.decoy_id in listing else sorted(hit.missing)
            unc_carried.append((hit, missing))
            continue
        missing = missing_for(hit)
        if not missing:
            continue
        if window_end[0] - hit.received[0] <= horizon(hit.decoy_id):
            pending.append((hit, missing))
        else:
            unc_carried.append((hit, missing))
    for hit in batch:
        missing = missing_for(hit)
        if not missing:
            continue
        if window_end[0] - hit.received[0] <= horizon(hit.decoy_id):
            pending.append((hit, missing))
        else:
            unc_batch.append((hit, missing))
    # Cap pending per decoy, keeping the latest by time then event ID.
    kept = []
    by_decoy = {}
    for item in pending:
        by_decoy.setdefault(item[0].decoy_id, []).append(item)
    for items in by_decoy.values():
        items.sort(key=lambda it: it[0].order(), reverse=True)
        kept += items[:MAX_PENDING]
        for hit, missing in items[MAX_PENDING:]:
            (unc_carried if hit.index is None else unc_batch).append((hit, missing))
    unc_carried.sort(key=lambda it: it[0].order())
    unc_batch.sort(key=lambda it: it[0].index)
    uncorroborated = [{"event_id": h.event_id, "decoy_id": h.decoy_id,
                       "missing_sources": m} for h, m in unc_carried + unc_batch]
    recent = [h for h in pool
              if window_end[0] - h.received[0] <= horizon(h.decoy_id)]
    capped = []
    by_pair = {}
    for hit in recent:
        by_pair.setdefault((hit.decoy_id, hit.source), []).append(hit)
    for hits in by_pair.values():
        hits.sort(key=lambda h: h.order(), reverse=True)
        capped += hits[:MAX_RECENT]
    capped.sort(key=lambda h: h.order())
    kept.sort(key=lambda it: it[0].order())
    pending_out = []
    for hit, missing in kept:
        entry = hit.as_recent()
        entry["missing_sources"] = missing
        pending_out.append(entry)
    return uncorroborated, [h.as_recent() for h in capped], pending_out
