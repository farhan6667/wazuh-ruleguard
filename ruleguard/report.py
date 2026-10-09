"""Readable HTML and Markdown reports. Everything is escaped, nothing loads remote assets or runs scripts."""
import html

CSS = (
    ":root{color-scheme:dark}*{box-sizing:border-box}"
    "body{background:#070d1b;color:#e6eeff;font:16px/1.55 system-ui,'Segoe UI',sans-serif;max-width:1080px;margin:0 auto;padding:32px 20px 64px}"
    "h1{font-size:30px;margin:0 0 4px;letter-spacing:-.5px}h1 span{color:#00d1ff}h2{margin:36px 0 12px;font-size:20px}"
    ".sub{color:#9fb3dc;margin:0 0 24px}.cards{display:flex;gap:14px;flex-wrap:wrap;margin:0 0 8px}"
    ".card{background:#0d1730;border:1px solid #243764;border-radius:14px;padding:14px 20px;min-width:150px}"
    ".card b{display:block;font-size:30px;line-height:1.1}.card span{color:#9fb3dc;font-size:13px;letter-spacing:.08em;text-transform:uppercase}"
    ".card b.m{font-size:16px;line-height:1.6;word-break:break-all;padding-top:6px}.ok{color:#38e0ad}.bad{color:#ff6b86}.warn{color:#ffbf5e}"
    "table{border-collapse:collapse;width:100%;background:#0b1428;border:1px solid #243764;border-radius:12px;overflow:hidden}"
    "th,td{padding:11px 14px;text-align:left;vertical-align:top;border-bottom:1px solid #1b2a4d;font-size:14.5px}"
    "th{background:#101c38;color:#9fb3dc;font-weight:600;font-size:12.5px;letter-spacing:.07em;text-transform:uppercase}"
    "tr:last-child td{border-bottom:0}code{font:13.5px Consolas,'Cascadia Mono',monospace;color:#cfe0ff}"
    ".pill{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12.5px;font-weight:700}"
    ".pill.pass{background:#1fbf8f33;color:#38e0ad}.pill.fail,.pill.error{background:#ff4d6d33;color:#ff6b86}"
    ".pill.k{background:#4f7dff33;color:#9db8ff}.note{background:#0d1730;border-left:4px solid #00d1ff;padding:12px 16px;border-radius:8px;color:#c4d3f2;margin:18px 0}"
    ".kv{margin:0;padding:0;list-style:none}.kv li{white-space:nowrap}.kv i{color:#7e93c4;font-style:normal}"
    ".before{border-left:3px solid #7e93c4;padding-left:10px}.after{border-left:3px solid #ff6b86;padding-left:10px}"
    "footer{margin-top:40px;color:#7e93c4;font-size:13px}"
)

PAGE = (
    "<!doctype html><html lang='en'><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
    "<title>@@TITLE@@</title><style>" + CSS + "</style><body>@@BODY@@"
    "<footer>Generated offline by Wazuh RuleGuard. Reports leave out raw event text and tokens, but case names and rule metadata can still be sensitive.</footer></body></html>"
)

E = html.escape


def _page(title, body):
    return PAGE.replace("@@TITLE@@", title).replace("@@BODY@@", "".join(body))


def _kv(d, keys):
    items = []
    for k in keys:
        if d is not None and k in d:
            v = d[k]
            if isinstance(v, list):
                v = ", ".join(map(str, v)) or "none"
            items.append(f"<li><i>{E(k)}</i> <code>{E(str(v))}</code></li>")
    return "<ul class='kv'>" + "".join(items) + "</ul>" if items else "<span class='warn'>none</span>"


def run_html(report):
    rows = report["results"]
    passed, failed = report["passed"], report["failed"]
    body = ["<h1><span>Wazuh</span> RuleGuard</h1><p class='sub'>Detection check report</p>",
            "<div class='cards'>"
            f"<div class='card'><b class='ok'>{passed}</b><span>passed</span></div>"
            f"<div class='card'><b class='{'bad' if failed else 'ok'}'>{failed}</b><span>failed or error</span></div>"
            f"<div class='card'><b class='m'>{E(str(report['mode']))}</b><span>mode</span></div></div>"]
    if str(report["mode"]).startswith("offline-replay"):
        body.append("<div class='note'>Replay checks stored observations. It does not evaluate detection rules or establish what a Wazuh manager does today.</div>")
    body.append("<h2>Cases</h2><table><tr><th>Case</th><th>Step</th><th>Status</th><th>Expected</th><th>Actual</th><th>Why it failed</th></tr>")
    for r in rows:
        actual = r.get("actual")
        why = "<br>".join(E(f) for f in r.get("failures", [])) or "&nbsp;"
        body.append(
            f"<tr><td><code>{E(str(r['case_id']))}</code></td><td>{E(str(r['step'] if r['step'] is not None else '-'))}</td>"
            f"<td><span class='pill {E(r['status'])}'>{E(r['status'])}</span></td>"
            f"<td>{_kv(r.get('expected'), ['rule_id', 'level', 'alert', 'decoder', 'forbidden_rule_ids', 'groups_contains', 'mitre_contains'])}</td>"
            f"<td>{_kv(actual, ['rule_id', 'level', 'alert', 'decoder', 'groups', 'mitre', 'warning_count']) if actual else '<span class=warn>no result</span>'}</td>"
            f"<td>{why}</td></tr>")
    body.append("</table>")
    return _page("RuleGuard report", body)


def compare_html(report):
    ch = report["changes"]
    body = ["<h1><span>Wazuh</span> RuleGuard</h1><p class='sub'>Comparison report: baseline vs candidate</p>",
            "<div class='cards'>"
            f"<div class='card'><b class='{'bad' if ch else 'ok'}'>{len(ch)}</b><span>changes</span></div>"
            f"<div class='card'><b class='m'>{E(str(report.get('before_mode')))}</b><span>before mode</span></div>"
            f"<div class='card'><b class='m'>{E(str(report.get('after_mode')))}</b><span>after mode</span></div></div>"]
    if not ch:
        body.append("<div class='note'>No differences between the two runs for the cases they share.</div>")
    else:
        body.append("<div class='note'>A changed rule ID is not automatically a regression. Review every change, and review input changes separately from behavior changes.</div>"
                    "<h2>Changes</h2><table><tr><th>Case</th><th>Step</th><th>Kind</th><th>Before</th><th>After</th></tr>")
        keys = ['rule_id', 'level', 'alert', 'decoder', 'groups', 'mitre', 'warning_count']
        for c in ch:
            body.append(
                f"<tr><td><code>{E(str(c['case_id']))}</code></td><td>{E(str(c['step']))}</td>"
                f"<td><span class='pill k'>{E(c['kind'])}</span></td>"
                f"<td class='before'>{_kv(c.get('before'), keys)}</td><td class='after'>{_kv(c.get('after'), keys)}</td></tr>")
        body.append("</table>")
    return _page("RuleGuard comparison", body)


def _md(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def run_markdown(report):
    lines = ["## Wazuh RuleGuard", "",
             f"**{report['passed']} passed, {report['failed']} failed or error** · mode `{_md(report['mode'])}`", "",
             "| Case | Step | Status | Actual rule | Level | Alert | Why it failed |", "|---|---|---|---|---|---|---|"]
    for r in report["results"]:
        a = r.get("actual") or {}
        lines.append(f"| `{_md(r['case_id'])}` | {_md(r['step'] if r['step'] is not None else '-')} | {_md(r['status'])} | "
                     f"{_md(a.get('rule_id', '-'))} | {_md(a.get('level', '-'))} | {_md(a.get('alert', '-'))} | {_md('; '.join(r.get('failures', [])) or '-')} |")
    return "\n".join(lines) + "\n"


def compare_markdown(report):
    ch = report["changes"]
    lines = ["## Wazuh RuleGuard comparison", "", f"**{len(ch)} changes** between `{_md(report.get('before_mode'))}` and `{_md(report.get('after_mode'))}`", ""]
    if ch:
        lines += ["| Case | Step | Kind | Before rule | After rule | Alert before | Alert after |", "|---|---|---|---|---|---|---|"]
        for c in ch:
            b, a = c.get("before") or {}, c.get("after") or {}
            lines.append(f"| `{_md(c['case_id'])}` | {_md(c['step'])} | {_md(c['kind'])} | {_md(b.get('rule_id', '-'))} | {_md(a.get('rule_id', '-'))} | {_md(b.get('alert', '-'))} | {_md(a.get('alert', '-'))} |")
    else:
        lines.append("No differences.")
    return "\n".join(lines) + "\n"
