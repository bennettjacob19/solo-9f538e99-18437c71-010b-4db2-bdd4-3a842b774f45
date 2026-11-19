"""FastAPI operations UI: publish full zone versions, view the current
version, issue real DNS queries against the running UDP server, and
configure/observe the background authoritative-UDP prober."""

import html
import sys

import dnslib
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from .deps import runtime
from .zone import Snapshot, ZoneError, flatten_records, fqdn, parse_zone_text

app = FastAPI(title="svc.test. zone publisher", docs_url=None, redoc_url=None)

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 960px; color: #222; }}
 h1 {{ font-size: 1.4rem; }} h2 {{ font-size: 1.1rem; margin-top: 2rem; }}
 table {{ border-collapse: collapse; }} td, th {{ border: 1px solid #ccc; padding: 4px 10px; }}
 textarea {{ width: 100%; font-family: ui-monospace, monospace; }}
 input[type=text] {{ width: 24rem; }}
 .ok {{ background: #e6f7e6; border: 1px solid #8c8; padding: .6rem; }}
 .err {{ background: #fde8e8; border: 1px solid #c88; padding: .6rem; white-space: pre-wrap; }}
 .muted {{ color: #777; font-size: .9rem; }}
 code {{ background: #f2f2f2; padding: 0 4px; }}
</style></head><body>
<h1>svc.test. 区域发布 <span class="muted">zone publisher</span></h1>
{body}
</body></html>"""


def esc(s):
    return html.escape(str(s), quote=True)


def page(body, title="svc.test. zone publisher", status_code=200):
    return HTMLResponse(PAGE.format(title=esc(title), body=body), status_code=status_code)


def current_snapshot():
    return runtime.holder.get()


def versions_table():
    rows = []
    for v in runtime.store.list_versions():
        mark = " ✅ current" if v["current"] else ""
        rows.append(
            f"<tr><td>{v['id']}</td><td>{esc(v['created_at'])}</td>"
            f"<td>{v['records']}</td><td>{esc(v['note'])}{mark}</td></tr>"
        )
    if not rows:
        return "<p class='muted'>尚未发布任何版本。</p>"
    return ("<table><tr><th>版本</th><th>发布时间 (UTC)</th><th>记录数</th><th>备注</th></tr>"
            + "".join(rows) + "</table>")


def records_table(snap):
    if snap is None:
        return "<p class='muted'>当前没有已发布版本。</p>"
    rows = []
    for name in sorted(snap.records):
        rec = snap.records[name]
        for ip in rec["A"]:
            rows.append(f"<tr><td>{esc(name)}</td><td>A</td><td>{esc(ip)}</td><td>{rec['ttl']}</td></tr>")
        if rec["CNAME"]:
            rows.append(
                f"<tr><td>{esc(name)}</td><td>CNAME</td><td>{esc(rec['CNAME'])}</td><td>{rec['ttl']}</td></tr>"
            )
    body = "".join(rows) or "<tr><td colspan=4 class='muted'>(空区域)</td></tr>"
    return ("<table><tr><th>名称</th><th>类型</th><th>值</th><th>TTL</th></tr>" + body + "</table>")


PROBE_STATUS_LABELS = {"ok": "正常", "fault": "故障",
                       "pending": "待确认", "unconfigured": "未配置"}
PROBE_STATUS_COLORS = {"ok": ("#e6f7e6", "#1e7e34"),
                       "fault": ("#fde8e8", "#b02a37"),
                       "pending": ("#fff7dd", "#946400"),
                       "unconfigured": ("#eeeeee", "#555555")}
PROBE_OUTCOME_LABELS = {"event": "事件", "match": "吻合", "mismatch": "不符",
                        "timeout": "超时", "error": "错误"}


def probe_form(st):
    snap = current_snapshot()
    if snap is None or not snap.records:
        return "<p class='muted'>尚未发布版本，没有可选择的区域内名称。</p>"
    current = st.get("settings") or {}
    options = []
    for name in sorted(snap.records):
        sel = " selected" if name == current.get("name") else ""
        options.append("<option value='" + esc(name) + "'" + sel + ">"
                       + esc(name) + "</option>")
    port = current.get("port", runtime.dns_query_port)
    return ("<form method='post' action='/probe/settings'>"
            "区域内名称 <select name='name'>" + "".join(options) + "</select>　"
            "本机 UDP 端口 <input type='text' name='port' value='"
            + str(port) + "' size='6'>　"
            "<button type='submit'>保存探测设置</button></form>")


def probe_block():
    if runtime.prober is None:
        return "<p class='muted'>探测引擎未启动。</p>"
    st = runtime.prober.status()
    status = st["status"]
    bg, fg = PROBE_STATUS_COLORS[status]
    badge = (f"<span style='background:{bg};color:{fg};padding:3px 12px;"
             f"border-radius:4px;font-weight:bold'>{PROBE_STATUS_LABELS[status]}</span>")
    parts = ["<p>当前状态：" + badge + "</p>"]
    if st["configured"]:
        s = st["settings"]
        ver = (f"v{st['expected_version']}" if st["expected_version"] is not None
               else "（无已发布版本）")
        parts.append(
            "<p>探测目标：<code>" + esc(s["name"]) + "</code> A → <code>"
            + esc(st["host"]) + ":" + str(s["port"]) + "</code>　"
            "比对版本：" + ver + "　"
            "连续吻合 " + str(st["ok_streak"]) + " 次 / 连续异常 "
            + str(st["bad_streak"]) + " 次<br>"
            "<span class='muted'>每 " + f"{st['interval']:g}" + "s 探测一次，超时 "
            + f"{st['timeout']:g}" + "s；连续 2 次吻合判正常，"
            "连续 2 次超时或不符判故障；发布新版或修改设置后重新累计。</span></p>"
            "<p class='muted'>最近状态重置：" + esc(st["last_change"]) + "</p>")
    else:
        parts.append("<p class='muted'>尚未保存探测设置；选择名称与端口后开始探测。</p>")
    parts.append(probe_form(st))
    rows = []
    for h in st["history"]:
        label = PROBE_OUTCOME_LABELS.get(h["outcome"], h["outcome"])
        rows.append("<tr><td>" + esc(h["ts"]) + "</td><td>" + esc(label)
                    + "</td><td>" + esc(h["reason"]) + "</td></tr>")
    if rows:
        parts.append("<p><b>最近结果</b></p><table><tr><th>时间 (UTC)</th>"
                     "<th>结果</th><th>原因</th></tr>" + "".join(rows) + "</table>")
    return "".join(parts)


def index_body(msg="", err=""):
    snap = current_snapshot()
    banner = ""
    if msg:
        banner += f"<div class='ok'>{esc(msg)}</div>"
    if err:
        banner += f"<div class='err'>{esc(err)}</div>"
    if snap is None:
        version_info = "<p><b>当前版本:</b> 无（DNS 对区域内查询返回 SERVFAIL）</p>"
        prefill = "web A 10.0.0.1 60\napp CNAME web\n"
    else:
        version_info = (
            f"<p><b>当前版本:</b> v{snap.version_id} "
            f"<span class='muted'>发布于 {esc(snap.created_at)}</span></p>"
        )
        prefill = snap.zone_text()
    return f"""
{banner}
<h2>当前版本记录</h2>
{version_info}
{records_table(snap)}

<h2>权威 UDP 探测 <span class="muted">本机应答是否仍按已发布版本</span></h2>
{probe_block()}

<h2>发起真实查询（UDP → 本机权威 DNS）</h2>
<form method="get" action="/query">
  <input type="text" name="name" placeholder="web 或 web.svc.test." required>
  <select name="qtype">
    <option>A</option><option>CNAME</option><option>ANY</option>
  </select>
  <button type="submit">查询</button>
</form>

<h2>发布新版（整版提交，校验/写入任一失败则整版拒绝）</h2>
<form method="post" action="/publish">
  <p class="muted">每行一条：<code>名称 A|CNAME 值 [TTL]</code>，# 为注释。
  CNAME 只能指向本区域内已定义的名称，循环或悬空将整版拒绝。</p>
  <textarea name="zone_text" rows="12">{esc(prefill)}</textarea>
  <p><input type="text" name="note" placeholder="备注（可选）"></p>
  <button type="submit">校验并发布</button>
</form>

<h2>版本历史</h2>
{versions_table()}
"""


@app.get("/", response_class=HTMLResponse)
def index(msg: str = ""):
    return page(index_body(msg=msg))


@app.post("/publish", response_class=HTMLResponse)
def publish(zone_text: str = Form(...), note: str = Form("")):
    # 1) validate the whole candidate version; reject entirely on any problem
    try:
        parsed = parse_zone_text(zone_text)
    except ZoneError as exc:
        body = ("<div class='err'>校验失败，整版已拒绝，当前版本不受影响：\n"
                + esc("\n".join(exc.errors)) + "</div>"
                + "<p><a href='/'>返回</a></p>")
        return page(body, title="校验失败", status_code=400)

    rows = flatten_records(parsed)
    # 2) single atomic transaction; on write failure the old version stays current
    with runtime.publish_lock:
        try:
            vid, created = runtime.store.publish(rows, note=note.strip())
        except Exception as exc:  # sqlite3.Error or IO failure
            print(f"publish write failed: {exc!r}", file=sys.stderr)
            body = (f"<div class='err'>写入失败（{esc(type(exc).__name__)}: {esc(exc)}），\n"
                    "整版未提交，当前版本继续生效。</div>"
                    "<p><a href='/'>返回</a></p>")
            return page(body, title="写入失败", status_code=500)
        # 3) commit succeeded: swap the in-memory snapshot for new queries
        runtime.holder.set(Snapshot(vid, created, parsed))
    # probes sent against the old version are now stale; re-confirm anew
    if runtime.prober is not None:
        runtime.prober.note_publish(vid)
    return RedirectResponse(url=f"/?msg=已发布版本+v{vid}", status_code=303)


@app.get("/query", response_class=HTMLResponse)
def query(name: str = "", qtype: str = "A"):
    qtype = qtype.upper()
    if qtype not in ("A", "CNAME", "ANY"):
        return page("<div class='err'>仅支持 A / CNAME / ANY 查询</div><p><a href='/'>返回</a></p>",
                    status_code=400)
    try:
        qname = fqdn(name)
    except ValueError:
        qname = name.strip().lower().rstrip(".") + "."  # let the server REFUSE it
    try:
        pkt = dnslib.DNSRecord.question(qname, qtype).send(
            runtime.dns_query_host, runtime.dns_query_port, timeout=3
        )
        resp = dnslib.DNSRecord.parse(pkt)
    except Exception as exc:
        body = f"<div class='err'>查询失败: {esc(exc)}</div><p><a href='/'>返回</a></p>"
        return page(body, title="查询失败", status_code=502)

    rcode = dnslib.RCODE[resp.header.rcode]
    lines = [f";; ->>HEADER<<- rcode: {rcode}, aa: {resp.header.aa}"]
    for rr in resp.rr:
        lines.append(f"{rr.rname} {rr.ttl} IN {dnslib.QTYPE[rr.rtype]} {rr.rdata}")
    if not resp.rr:
        lines.append(";; (no answer records)")
    body = (f"<h2>查询 {esc(qname)} {qtype}</h2><pre>{esc(chr(10).join(lines))}</pre>"
            "<p><a href='/'>返回</a></p>")
    return page(body, title=f"query {qname}")


@app.post("/probe/settings", response_class=HTMLResponse)
def probe_settings(name: str = Form(...), port: str = Form(...)):
    # 1) validate: in-zone name + a usable UDP port
    try:
        qname = fqdn(name)
    except ValueError as exc:
        body = (f"<div class='err'>名称无效：{esc(exc)}</div>"
                "<p><a href='/'>返回</a></p>")
        return page(body, title="设置无效", status_code=400)
    try:
        port_n = int(str(port).strip())
        if not (1 <= port_n <= 65535):
            raise ValueError
    except ValueError:
        body = ("<div class='err'>端口必须是 1-65535 的整数</div>"
                "<p><a href='/'>返回</a></p>")
        return page(body, title="设置无效", status_code=400)
    # 2) persist first; on write failure the old settings stay in effect
    try:
        runtime.store.save_probe_settings(qname, port_n)
    except Exception as exc:
        print(f"probe settings write failed: {exc!r}", file=sys.stderr)
        body = (f"<div class='err'>配置写入失败（{esc(type(exc).__name__)}: {esc(exc)}），\n"
                "沿用原探测设置，正在进行的探测不受影响。</div>"
                "<p><a href='/'>返回</a></p>")
        return page(body, title="写入失败", status_code=500)
    # 3) only now apply: starts a new probe epoch, old in-flight probes go stale
    if runtime.prober is not None:
        runtime.prober.apply_settings(qname, port_n)
    return RedirectResponse(url="/?msg=探测设置已保存", status_code=303)


@app.get("/api/probe")
def api_probe():
    if runtime.prober is None:
        return {"configured": False, "status": "unconfigured", "history": []}
    return runtime.prober.status()


@app.get("/api/current")
def api_current():
    snap = current_snapshot()
    if snap is None:
        return {"version": None, "records": []}
    records = []
    for name in sorted(snap.records):
        rec = snap.records[name]
        for ip in rec["A"]:
            records.append({"name": name, "type": "A", "value": ip, "ttl": rec["ttl"]})
        if rec["CNAME"]:
            records.append({"name": name, "type": "CNAME", "value": rec["CNAME"], "ttl": rec["ttl"]})
    return {"version": snap.version_id, "created_at": snap.created_at, "records": records}


@app.get("/api/versions")
def api_versions():
    return runtime.store.list_versions()
