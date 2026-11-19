#!/usr/bin/env python3
"""End-to-end verification for the svc.test. zone publisher.

Covers:
  0. store-level transaction atomicity (failed publish leaves no half version)
  1. cold start with empty DB (SERVFAIL), publish v1, real UDP DNS answers
  2. CNAME chain resolution, NXDOMAIN / REFUSED / NODATA behaviour
  3. whole-version rejection: dangling / cycle / external target / conflicts
  4. publish v2: new queries use the new version
  5. consistency: answers during concurrent publishes never mix versions
  6. write failure: old version keeps serving, DB untouched, recovery works
  7. probe engine: settings, healthy/fault/recovery, publish reset, rogue
     server mismatch, config write failure keeps old settings
  8. restart: committed version is reloaded, probe settings survive but the
     old probe success state is not inherited

Run with the project venv python:  /tmp/testvenv/bin/python tests/e2e_test.py
"""

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

import dnslib
import httpx
from dnslib.server import BaseResolver, DNSServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.prober import ProbeEngine, compare, expected_answer  # noqa: E402
from app.store import Store  # noqa: E402
from app.zone import Snapshot, ZoneError, parse_zone_text  # noqa: E402

WEB = "http://127.0.0.1:18000"
DNS_PORT = 15353
ROGUE_PORT = 15399
LOG = "/tmp/zonedns-e2e-server.log"

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    mark = "PASS" if cond else "FAIL"
    line = f"[{mark}] {name}"
    if detail and not cond:
        line += f"  -- {detail}"
    print(line, flush=True)


def dns_query(name, qtype="A"):
    pkt = dnslib.DNSRecord.question(name, qtype).send("127.0.0.1", DNS_PORT, timeout=3)
    return dnslib.DNSRecord.parse(pkt)


def answers_of(resp):
    return sorted(
        (str(rr.rname), dnslib.QTYPE[rr.rtype], str(rr.rdata)) for rr in resp.rr
    )


def publish(text, note=""):
    return httpx.post(WEB + "/publish", data={"zone_text": text, "note": note}, timeout=10)


def save_probe(name, port):
    return httpx.post(WEB + "/probe/settings",
                      data={"name": name, "port": str(port)}, timeout=10)


def probe_status():
    return httpx.get(WEB + "/api/probe", timeout=5).json()


def wait_probe_status(want, timeout=20):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            st = probe_status()
            last = st
            if st.get("status") == want:
                return st
        except Exception:
            pass
        time.sleep(0.3)
    print(f"  (probe status never became {want}; last={str(last)[:300]})")
    return None


class RogueResolver(BaseResolver):
    """Answers every A query with a fixed wrong address (no CNAME chain)."""

    def resolve(self, request, handler):
        reply = request.reply()
        reply.add_answer(dnslib.RR(str(request.q.qname), dnslib.QTYPE.A,
                                   rclass=1, ttl=30, rdata=dnslib.A("9.9.9.9")))
        return reply


def wait_ready(proc, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"app exited early with {proc.returncode}; see {LOG}")
        try:
            if httpx.get(WEB + "/api/current", timeout=2).status_code == 200:
                dns_query("svc.test.", "A")  # UDP socket answers (any rcode)
                return
        except Exception:
            pass
        time.sleep(0.3)
    raise RuntimeError("app did not become ready; see " + LOG)


def start_app(dbpath):
    env = dict(
        os.environ,
        ZONE_DB=dbpath,
        DNS_BIND="127.0.0.1",
        DNS_PORT=str(DNS_PORT),
        WEB_HOST="127.0.0.1",
        WEB_PORT="18000",
        REFRESH_INTERVAL="0.5",
        PROBE_INTERVAL="0.5",
        PROBE_TIMEOUT="1.0",
    )
    proc = subprocess.Popen(
        [sys.executable, "-m", "app.main"],
        cwd=ROOT,
        env=env,
        stdout=open(LOG, "ab"),
        stderr=subprocess.STDOUT,
    )
    wait_ready(proc)
    return proc


def stop_app(proc):
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


# ---------------------------------------------------------------- unit: store
def test_store_atomicity(tmp):
    db = os.path.join(tmp, "unit.db")
    store = Store(db)
    store.init()
    vid, _ = store.publish([("web.svc.test.", "A", "10.0.0.1", 60)], note="v1")
    check("unit: first publish becomes current", store.current_version_id() == vid)
    try:
        store.publish(
            [("x.svc.test.", "A", "10.0.0.2", 60), ("x.svc.test.", "A", "10.0.0.2", 60)]
        )
        check("unit: duplicate rows violate UNIQUE -> publish raises", False)
    except Exception:
        check("unit: duplicate rows violate UNIQUE -> publish raises", True)
    check("unit: pointer unchanged after failed txn", store.current_version_id() == vid)
    check("unit: no orphan version row", store.load_version(vid + 1) is None)
    cur = store.load_current()
    check("unit: old records intact", len(cur["rows"]) == 1)


def test_validation():
    bad = {
        "dangling": "app CNAME missing\n",
        "cycle": "a CNAME b\nb CNAME a\n",
        "self cycle": "loop CNAME loop\n",
        "external target": "app CNAME www.example.com.\n",
        "A+CNAME conflict": "web A 10.0.0.1\napp A 10.0.0.2\napp CNAME web\n",
        "bad ipv4": "web A 999.1.1.1\n",
        "out-of-zone name": "evil.other.com. A 10.0.0.1\n",
        "dangling chain end": "a CNAME b\nb CNAME c\n",
    }
    for name, text in bad.items():
        try:
            parse_zone_text(text)
            check(f"unit: reject {name}", False, "parsed without error")
        except ZoneError:
            check(f"unit: reject {name}", True)
    ok = parse_zone_text("web A 10.0.0.1\napp CNAME web\n# comment\n\n")
    check("unit: valid zone parses", set(ok) == {"web.svc.test.", "app.svc.test."})


def test_probe_state_machine():
    snap = Snapshot(7, "ts", {"app.svc.test.": {"A": ["10.0.0.1"], "CNAME": None, "ttl": 60}})
    eng = ProbeEngine(lambda: snap, interval=0.1, timeout=0.1)
    eng.apply_settings("app.svc.test.", DNS_PORT)
    st = eng.status()
    check("unit: fresh probe settings -> pending", st["status"] == "pending")
    check("unit: probe expected version from snapshot", st["expected_version"] == 7)
    ep = st["epoch"]
    eng._record(ep - 1, 7, "match", "late answer from before the change")
    eng._record(ep, 6, "match", "answered by an older version")
    st = eng.status()
    check("unit: stale probes cannot change state",
          st["status"] == "pending" and st["ok_streak"] == 0
          and len(st["history"]) == 1, str(st)[:200])
    eng._record(ep, 7, "match", "m1")
    check("unit: one match still pending", eng.status()["status"] == "pending")
    eng._record(ep, 7, "match", "m2")
    check("unit: two consecutive matches -> ok", eng.status()["status"] == "ok")
    eng._record(ep, 7, "timeout", "t1")
    check("unit: single bad result keeps ok", eng.status()["status"] == "ok")
    eng._record(ep, 7, "match", "m3")
    eng._record(ep, 7, "timeout", "t2")
    check("unit: non-consecutive bad results keep ok", eng.status()["status"] == "ok")
    eng._record(ep, 7, "mismatch", "bad")
    check("unit: two consecutive bad -> fault", eng.status()["status"] == "fault")
    eng._record(ep, 7, "match", "m4")
    check("unit: single match keeps fault", eng.status()["status"] == "fault")
    eng._record(ep, 7, "match", "m5")
    check("unit: two consecutive matches recover", eng.status()["status"] == "ok")
    eng.note_publish(8)
    st = eng.status()
    check("unit: publish resets probe to pending",
          st["status"] == "pending" and st["ok_streak"] == 0)
    check("unit: publish clears old probe results",
          len(st["history"]) == 1 and st["history"][0]["outcome"] == "event")


def test_probe_compare():
    snap = Snapshot(3, "ts", {
        "web.svc.test.": {"A": ["10.0.0.10", "10.0.0.11"], "CNAME": None, "ttl": 60},
        "app.svc.test.": {"A": [], "CNAME": "web.svc.test.", "ttl": 60},
    })
    exp = expected_answer(snap, "app.svc.test.")
    check("unit: expected answer from snapshot",
          exp["rcode"] == "NOERROR"
          and exp["chain"] == [("app.svc.test.", "web.svc.test.")]
          and exp["a_set"] == frozenset({"10.0.0.10", "10.0.0.11"}), str(exp))
    check("unit: compare match (A order irrelevant)",
          compare(exp, "NOERROR", [("app.svc.test.", "web.svc.test.")],
                  frozenset({"10.0.0.11", "10.0.0.10"})) is None)
    check("unit: compare rcode mismatch",
          "RCODE" in compare(exp, "NXDOMAIN", exp["chain"], exp["a_set"]))
    check("unit: compare chain mismatch",
          "CNAME" in compare(exp, "NOERROR", [], exp["a_set"]))
    check("unit: compare A set mismatch",
          "A 集合" in compare(exp, "NOERROR", exp["chain"], frozenset({"9.9.9.9"})))


# ------------------------------------------------------------------ e2e flow
def main():
    tmp = tempfile.mkdtemp(prefix="zonedns-e2e-")
    db = os.path.join(tmp, "zone.db")
    open(LOG, "w").close()

    test_store_atomicity(tmp)
    test_validation()
    test_probe_state_machine()
    test_probe_compare()

    proc = start_app(db)
    try:
        # 1. empty DB: nothing published yet
        r = httpx.get(WEB + "/api/current", timeout=5)
        check("e2e: empty DB -> no current version", r.json()["version"] is None)
        resp = dns_query("web.svc.test.", "A")
        check("e2e: empty DB -> SERVFAIL", dnslib.RCODE[resp.header.rcode] == "SERVFAIL")

        # 2. publish v1
        v1 = "web A 10.0.0.10 60\nweb A 10.0.0.11 60\napi CNAME web\napp CNAME api\ndb A 10.0.1.5 120\n"
        r = publish(v1, note="v1")
        check("e2e: publish v1 -> 303", r.status_code == 303, f"got {r.status_code}: {r.text[:200]}")
        cur = httpx.get(WEB + "/api/current", timeout=5).json()
        check("e2e: current is v1 with 5 records",
              cur["version"] == 1 and len(cur["records"]) == 5, str(cur)[:200])

        # 3. real DNS answers from v1
        resp = dns_query("app.svc.test.", "A")
        want = sorted([
            ("app.svc.test.", "CNAME", "api.svc.test."),
            ("api.svc.test.", "CNAME", "web.svc.test."),
            ("web.svc.test.", "A", "10.0.0.10"),
            ("web.svc.test.", "A", "10.0.0.11"),
        ])
        check("e2e: chain app->api->web + A addresses",
              dnslib.RCODE[resp.header.rcode] == "NOERROR" and answers_of(resp) == want,
              str(answers_of(resp)))
        check("e2e: authoritative bit set", resp.header.aa == 1)

        resp = dns_query("api.svc.test.", "CNAME")
        check("e2e: CNAME qtype returns the alias only",
              answers_of(resp) == [("api.svc.test.", "CNAME", "web.svc.test.")],
              str(answers_of(resp)))

        resp = dns_query("db.svc.test.", "CNAME")
        check("e2e: CNAME qtype on A-only name -> NODATA",
              dnslib.RCODE[resp.header.rcode] == "NOERROR" and not resp.rr)

        resp = dns_query("nope.svc.test.", "A")
        check("e2e: unknown name -> NXDOMAIN",
              dnslib.RCODE[resp.header.rcode] == "NXDOMAIN")

        resp = dns_query("other.com.", "A")
        check("e2e: out-of-zone -> REFUSED",
              dnslib.RCODE[resp.header.rcode] == "REFUSED")

        resp = dns_query("svc.test.", "A")
        check("e2e: zone apex -> NOERROR/NODATA",
              dnslib.RCODE[resp.header.rcode] == "NOERROR" and not resp.rr)

        r = httpx.get(WEB + "/query", params={"name": "app", "qtype": "A"}, timeout=5)
        check("e2e: web query page issues real query",
              r.status_code == 200 and "10.0.0.10" in r.text and "NOERROR" in r.text)

        # 4. invalid versions rejected wholesale; v1 keeps serving
        bad_zones = {
            "dangling": "app CNAME missing\nweb A 10.0.0.1\n",
            "cycle": "a CNAME b\nb CNAME a\n",
            "external": "app CNAME www.example.com.\n",
            "conflict": "web A 10.0.0.1\napp A 10.0.0.2\napp CNAME web\n",
        }
        for name, text in bad_zones.items():
            r = publish(text)
            check(f"e2e: invalid zone ({name}) -> 400", r.status_code == 400,
                  f"got {r.status_code}")
        cur = httpx.get(WEB + "/api/current", timeout=5).json()
        check("e2e: current still v1 after rejections", cur["version"] == 1)
        resp = dns_query("app.svc.test.", "A")
        check("e2e: DNS still serves v1 after rejections", answers_of(resp) == want)

        # 5. publish v2: new queries use the new version
        v2 = "web2 A 10.0.0.2 60\napp CNAME web2\n"
        r = publish(v2, note="v2")
        check("e2e: publish v2 -> 303", r.status_code == 303)
        resp = dns_query("app.svc.test.", "A")
        want2 = sorted([
            ("app.svc.test.", "CNAME", "web2.svc.test."),
            ("web2.svc.test.", "A", "10.0.0.2"),
        ])
        check("e2e: new queries use v2", answers_of(resp) == want2, str(answers_of(resp)))
        resp = dns_query("web.svc.test.", "A")
        check("e2e: names dropped in v2 -> NXDOMAIN",
              dnslib.RCODE[resp.header.rcode] == "NXDOMAIN")

        # 6. consistency: hammer queries while flipping between two versions
        zone_a = "app CNAME web1\nweb1 A 10.0.0.1 30\n"
        zone_b = "app CNAME web2\nweb2 A 10.0.0.2 30\n"
        consistent = {("web1.svc.test.", "10.0.0.1"), ("web2.svc.test.", "10.0.0.2")}
        errors, samples = [], [0]
        stop = threading.Event()

        def hammer():
            while not stop.is_set():
                try:
                    r2 = dns_query("app.svc.test.", "A")
                    rc = dnslib.RCODE[r2.header.rcode]
                    cn = [str(rr.rdata) for rr in r2.rr if dnslib.QTYPE[rr.rtype] == "CNAME"]
                    ip = [str(rr.rdata) for rr in r2.rr if dnslib.QTYPE[rr.rtype] == "A"]
                    samples[0] += 1
                    if rc != "NOERROR" or len(cn) != 1 or len(ip) != 1 \
                            or (cn[0], ip[0]) not in consistent:
                        errors.append((rc, cn, ip))
                except Exception as exc:  # noqa: BLE001
                    errors.append(("EXC", repr(exc)))

        threads = [threading.Thread(target=hammer) for _ in range(4)]
        for t in threads:
            t.start()
        for i in range(8):
            r = publish(zone_a if i % 2 == 0 else zone_b, note=f"flip{i}")
            if r.status_code != 303:
                errors.append(("publish", r.status_code))
            time.sleep(0.1)
        stop.set()
        for t in threads:
            t.join()
        check("e2e: answers during publishes never mix versions",
              not errors and samples[0] > 50,
              f"errors={errors[:3]} samples={samples[0]}")

        # 7. write failure: DB path replaced by a directory -> publish must fail
        versions_before = httpx.get(WEB + "/api/versions", timeout=5).json()
        current_before = httpx.get(WEB + "/api/current", timeout=5).json()
        os.rename(db, db + ".real")
        os.mkdir(db)  # sqlite can no longer open the database file
        try:
            r = publish(zone_a, note="must fail")
            check("e2e: write failure -> 500", r.status_code == 500,
                  f"got {r.status_code}: {r.text[:120]}")
            check("e2e: write failure page says old version stays",
                  "写入失败" in r.text)
            resp = dns_query("app.svc.test.", "A")
            cn = [str(rr.rdata) for rr in resp.rr if dnslib.QTYPE[rr.rtype] == "CNAME"]
            ip = [str(rr.rdata) for rr in resp.rr if dnslib.QTYPE[rr.rtype] == "A"]
            check("e2e: DNS keeps serving during write failure",
                  (cn[0], ip[0]) in consistent, f"{cn} {ip}")
        finally:
            os.rmdir(db)
            os.rename(db + ".real", db)
        time.sleep(1.2)  # let the refresh loop re-read the restored DB
        check("e2e: current version unchanged by failed write",
              httpx.get(WEB + "/api/current", timeout=5).json()["version"]
              == current_before["version"])
        check("e2e: no half-written version in DB",
              httpx.get(WEB + "/api/versions", timeout=5).json() == versions_before)
        r = publish(zone_b, note="recovered")
        check("e2e: publish works again after recovery", r.status_code == 303,
              f"got {r.status_code}")

        # 8. probe engine: settings, healthy, fault, recovery, publish reset
        r = httpx.get(WEB + "/", timeout=5)
        check("e2e: index shows probe section", "权威 UDP 探测" in r.text)

        r = save_probe("evil.other.com.", DNS_PORT)
        check("e2e: probe name outside zone -> 400", r.status_code == 400)
        r = save_probe("app", "70000")
        check("e2e: probe port out of range -> 400", r.status_code == 400)

        r = save_probe("app.svc.test.", DNS_PORT)
        check("e2e: save probe settings -> 303", r.status_code == 303)
        st = probe_status()
        check("e2e: probe configured with saved settings",
              st["configured"]
              and st["settings"] == {"name": "app.svc.test.", "port": DNS_PORT},
              str(st)[:200])
        check("e2e: fresh probe settings -> pending", st["status"] == "pending",
              st["status"])
        st = wait_probe_status("ok")
        check("e2e: probe confirms healthy after 2 matches", st is not None)
        check("e2e: probe history shows match reasons",
              st is not None and any(h["outcome"] == "match" and "一致" in h["reason"]
                                     for h in st["history"]))
        r = httpx.get(WEB + "/", timeout=5)
        check("e2e: index shows probe status and recent results",
              "正常" in r.text and "最近结果" in r.text)

        # fault: probe a port where nothing answers
        r = save_probe("app.svc.test.", 15999)
        check("e2e: save dead-port settings -> 303", r.status_code == 303)
        st = wait_probe_status("fault")
        check("e2e: unanswered port -> fault after 2 bad probes", st is not None)
        check("e2e: fault history shows timeout/error reasons",
              st is not None and any(h["outcome"] in ("timeout", "error")
                                     for h in st["history"]),
              str(st["history"][:2]) if st else "")

        # recovery: back to the real DNS port
        r = save_probe("app.svc.test.", DNS_PORT)
        check("e2e: restore good port -> 303", r.status_code == 303)
        st = wait_probe_status("ok")
        check("e2e: probe recovers after 2 matches", st is not None)

        # publish resets the probe; stale results must not leak into new state
        r = publish("app CNAME web2\nweb2 A 10.0.0.2 30\n", note="probe reset")
        check("e2e: publish during probing -> 303", r.status_code == 303)
        st = probe_status()
        check("e2e: publish resets probe to pending", st["status"] == "pending",
              st["status"])
        check("e2e: probe tracks the newly published version",
              st["expected_version"]
              == httpx.get(WEB + "/api/current", timeout=5).json()["version"])
        check("e2e: old probe results cleared on publish",
              st["history"] and st["history"][-1]["outcome"] == "event")
        st = wait_probe_status("ok")
        check("e2e: probe re-confirms after publish", st is not None)

        # fault: a rogue server answers with wrong data -> mismatch
        rogue = DNSServer(RogueResolver(), port=ROGUE_PORT,
                          address="127.0.0.1", tcp=False)
        rogue.start_thread()
        try:
            r = save_probe("app.svc.test.", ROGUE_PORT)
            check("e2e: point probe at rogue server -> 303", r.status_code == 303)
            st = wait_probe_status("fault")
            check("e2e: wrong answers -> fault", st is not None)
            check("e2e: mismatch reason recorded",
                  st is not None and any(h["outcome"] == "mismatch"
                                         and "不符" in h["reason"]
                                         for h in st["history"]),
                  str(st["history"][:2]) if st else "")
        finally:
            rogue.stop()

        r = save_probe("app.svc.test.", DNS_PORT)
        check("e2e: restore good port again -> 303", r.status_code == 303)
        st = wait_probe_status("ok")
        check("e2e: probe healthy again before restart", st is not None)

        # config write failure: DB path replaced by a directory -> 500,
        # old settings keep running untouched
        os.rename(db, db + ".real")
        os.mkdir(db)
        try:
            r = save_probe("web2.svc.test.", 15999)
            check("e2e: probe settings write failure -> 500", r.status_code == 500,
                  f"got {r.status_code}")
            check("e2e: probe write failure page keeps old settings",
                  "沿用原" in r.text)
        finally:
            os.rmdir(db)
            os.rename(db + ".real", db)
        st = probe_status()
        check("e2e: old probe settings still in effect after failed write",
              st["settings"] == {"name": "app.svc.test.", "port": DNS_PORT},
              str(st["settings"]))
        check("e2e: prober still healthy after failed write",
              st["status"] == "ok", st["status"])

        # 9. restart: committed version is reloaded; nothing partial appears
        last = httpx.get(WEB + "/api/current", timeout=5).json()
        n_versions = len(httpx.get(WEB + "/api/versions", timeout=5).json())
    finally:
        stop_app(proc)

    proc = start_app(db)  # same DB file
    try:
        cur = httpx.get(WEB + "/api/current", timeout=5).json()
        check("e2e: restart reloads last committed version",
              cur["version"] == last["version"], f"{cur['version']} != {last['version']}")
        resp = dns_query("app.svc.test.", "A")
        ip = [str(rr.rdata) for rr in resp.rr if dnslib.QTYPE[rr.rtype] == "A"]
        check("e2e: restart serves reloaded version", ip == ["10.0.0.2"], str(ip))
        check("e2e: restart leaves no partial versions",
              len(httpx.get(WEB + "/api/versions", timeout=5).json()) == n_versions)
        r = httpx.get(WEB + "/", timeout=5)
        check("e2e: UI renders after restart", r.status_code == 200 and "当前版本" in r.text)

        # probing continues from saved settings, but old success is not inherited
        st = probe_status()
        check("e2e: probe settings survive restart",
              st["configured"]
              and st["settings"] == {"name": "app.svc.test.", "port": DNS_PORT},
              str(st)[:200])
        check("e2e: old probe success not inherited after restart",
              st["epoch"] == 1 and "启动" in st["last_change"],
              str(st)[:300])
        st = wait_probe_status("ok")
        check("e2e: probing resumes and re-confirms after restart", st is not None)
    finally:
        stop_app(proc)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed checks:")
        for name in FAIL:
            print("  -", name)
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
