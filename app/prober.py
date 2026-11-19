"""Background prober: is the authoritative UDP server still answering
according to the currently published version?

A daemon thread sends a real A query for the configured in-zone name to the
configured local UDP port every ``interval`` seconds. The response's RCODE,
CNAME chain and A set are compared against the answer the *same published
version* should produce (computed from the immutable snapshot captured at
send time).

State machine (per epoch):

* 2 consecutive matches                -> ``ok``
* 2 consecutive timeouts/mismatches    -> ``fault``
* otherwise / right after any change   -> ``pending``

Every publish or settings change starts a new epoch: probes sent before the
change are discarded even if their answers arrive late, and the status goes
back to ``pending`` until enough probes of the new epoch have landed. Probe
state lives in memory only -- after a restart, probing continues from the
persisted settings but a previous ``ok`` is never inherited.

The prober never blocks publishing or DNS serving: all network I/O happens
on its own thread with its own socket, and the state lock is only held for
brief bookkeeping.
"""

import collections
import sys
import threading
from datetime import datetime, timezone

import dnslib

from .zone import resolve

PENDING = "pending"
OK = "ok"
FAULT = "fault"

NEEDED = 2  # consecutive equal outcomes required to leave pending / flip state


def log(msg):
    print(f"[zonedns] {msg}", file=sys.stderr, flush=True)


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def expected_answer(snapshot, name):
    """What an A query for ``name`` must return according to ``snapshot``."""
    if snapshot is None:
        return {"rcode": "SERVFAIL", "chain": [], "a_set": frozenset()}
    rcode, answers = resolve(snapshot, name, "A")
    chain = [(n, v) for n, t, v, _ in answers if t == "CNAME"]
    a_set = frozenset(v for n, t, v, _ in answers if t == "A")
    return {"rcode": rcode, "chain": chain, "a_set": a_set}


def parse_response(packet):
    """Extract (rcode, CNAME chain, A set) from a raw DNS response packet."""
    resp = dnslib.DNSRecord.parse(packet)
    chain, a_set = [], set()
    for rr in resp.rr:
        rtype = dnslib.QTYPE[rr.rtype]
        if rtype == "CNAME":
            chain.append((str(rr.rname).lower(), str(rr.rdata).lower()))
        elif rtype == "A":
            a_set.add(str(rr.rdata))
    return dnslib.RCODE[resp.header.rcode], chain, frozenset(a_set)


def fmt_chain(chain):
    if not chain:
        return "(无 CNAME)"
    owners = [o for o, _ in chain]
    targets = [t for _, t in chain]
    if targets[:-1] == owners[1:]:  # well-formed chain: show as a path
        return " → ".join([owners[0]] + targets)
    return ", ".join(f"{o}→{t}" for o, t in chain)


def fmt_aset(a_set):
    return "{" + ", ".join(sorted(a_set)) + "}" if a_set else "{空}"


def compare(expected, rcode, chain, a_set):
    """None if the response matches the published version, else the reason."""
    if rcode != expected["rcode"]:
        return f"RCODE 不符：期望 {expected['rcode']}，实际 {rcode}"
    if list(chain) != list(expected["chain"]):
        return (f"CNAME 链不符：期望 {fmt_chain(expected['chain'])}，"
                f"实际 {fmt_chain(chain)}")
    if a_set != expected["a_set"]:
        return (f"A 集合不符：期望 {fmt_aset(expected['a_set'])}，"
                f"实际 {fmt_aset(a_set)}")
    return None


class ProbeEngine:
    def __init__(self, get_snapshot, host="127.0.0.1", interval=2.0,
                 timeout=1.5, history_size=10):
        self._get_snapshot = get_snapshot
        self._host = host
        self.interval = interval
        self.timeout = timeout
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._settings = None  # {"name": ..., "port": ...} currently in effect
        self._epoch = 0
        self._status = PENDING
        self._ok_streak = 0
        self._bad_streak = 0
        self._expected_version = None
        self._history = collections.deque(maxlen=history_size)
        self._seq = 0
        self._last_change = "尚未配置探测"

    # ---------------- configuration changes (each starts a new epoch) -------

    def apply_settings(self, name, port, note=None):
        """Put persisted settings into effect.

        Called only after the settings were safely written; a failed write
        never reaches here, so the old settings simply keep running.
        """
        with self._lock:
            self._settings = {"name": name, "port": int(port)}
            self._reset_locked(note or f"探测设置已保存：{name} @ 端口 {port}")
        self._wake.set()

    def note_publish(self, version_id):
        """A new zone version just went live: in-flight probes are now stale."""
        with self._lock:
            self._reset_locked(f"已发布版本 v{version_id}，等待新探测确认")
        self._wake.set()

    def _reset_locked(self, note):
        self._epoch += 1
        self._status = PENDING
        self._ok_streak = 0
        self._bad_streak = 0
        snap = self._get_snapshot()
        self._expected_version = snap.version_id if snap else None
        self._history.clear()
        self._last_change = note
        self._history.appendleft({"ts": utcnow(), "outcome": "event", "reason": note})

    # ---------------- background loop ---------------------------------------

    def run(self):
        while True:
            try:
                self.probe_once()
            except Exception as exc:  # the prober thread must never die
                log(f"probe: unexpected error {exc!r}")
            self._wake.wait(self.interval)
            self._wake.clear()

    def probe_once(self):
        with self._lock:
            settings = dict(self._settings) if self._settings else None
            epoch = self._epoch
        if settings is None:
            return  # nothing configured yet: stay idle
        snap = self._get_snapshot()
        version = snap.version_id if snap else None
        with self._lock:
            if epoch == self._epoch and version != self._expected_version:
                # version flipped out-of-band (DB re-sync): same as a publish
                self._reset_locked(f"检测到当前版本变为 v{version}，等待新探测确认")
                epoch = self._epoch
        expected = expected_answer(snap, settings["name"])
        # Real UDP query on our own socket, outside any lock: publishing and
        # normal DNS serving are never blocked by a probe.
        try:
            packet = dnslib.DNSRecord.question(settings["name"], "A").send(
                self._host, settings["port"], timeout=self.timeout)
            rcode, chain, a_set = parse_response(packet)
            problem = compare(expected, rcode, chain, a_set)
            if problem is None:
                outcome = "match"
                reason = f"RCODE、CNAME 链、A 集合均与 v{version} 一致"
            else:
                outcome, reason = "mismatch", problem
        except TimeoutError:
            outcome = "timeout"
            reason = f"UDP 查询超时（{self.timeout:g}s 内无应答）"
        except Exception as exc:
            outcome = "error"
            reason = f"UDP 查询失败：{exc}"
        self._record(epoch, version, outcome, reason)

    # ---------------- state machine -----------------------------------------

    def _record(self, epoch, version, outcome, reason):
        with self._lock:
            # A late answer to a probe sent before a publish/settings change
            # must not affect the new state.
            if epoch != self._epoch or version != self._expected_version:
                return
            self._seq += 1
            self._history.appendleft(
                {"seq": self._seq, "ts": utcnow(),
                 "outcome": outcome, "reason": reason})
            if outcome == "match":
                self._ok_streak += 1
                self._bad_streak = 0
                if self._ok_streak >= NEEDED:
                    self._status = OK
            else:
                self._bad_streak += 1
                self._ok_streak = 0
                if self._bad_streak >= NEEDED:
                    self._status = FAULT

    # ---------------- reporting ----------------------------------------------

    def status(self):
        with self._lock:
            return {
                "configured": self._settings is not None,
                "settings": dict(self._settings) if self._settings else None,
                "status": self._status if self._settings else "unconfigured",
                "host": self._host,
                "interval": self.interval,
                "timeout": self.timeout,
                "epoch": self._epoch,
                "ok_streak": self._ok_streak,
                "bad_streak": self._bad_streak,
                "expected_version": self._expected_version,
                "last_change": self._last_change,
                "history": list(self._history),
            }
