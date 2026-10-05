"""HTTPS adapter and explicit offline replay, never a pretend Wazuh engine."""
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .core import GuardError, fingerprint, normalize


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class APIBackend:
    mode = "live-api"

    def __init__(self, url, token, ca_file=None, timeout=15):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
            raise GuardError("API URL must be an HTTPS origin, without credentials, path or query")
        if not token or any(c.isspace() for c in token):
            raise GuardError("Set a valid JWT in WAZUH_API_TOKEN")
        if timeout <= 0:
            raise GuardError("Timeout must be positive")
        self.url, self.jwt, self.timeout = url.rstrip("/"), token, timeout
        try:
            context = ssl.create_default_context(cafile=ca_file)
        except (OSError, ssl.SSLError) as exc:
            raise GuardError("Cannot load CA certificate") from exc
        # Ignore environment proxy settings: credentials stay on the specified origin.
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=context))
        self.session = None

    def request(self, method, path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.url + path, data=body, method=method,
                headers={"Authorization": "Bearer " + self.jwt, "Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise GuardError("API response exceeds 4 MiB")
                result = json.loads(raw)
        except urllib.error.HTTPError as exc:
            raise GuardError(f"Wazuh API HTTP {exc.code}; inspect access, token and endpoint") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise GuardError("API connection/TLS/JSON failure; no retry to preserve event counts") from None
        if not isinstance(result, dict) or result.get("error") != 0:
            raise GuardError("Wazuh API reported an error")
        return result

    def start(self, case):
        self.session = None

    def process(self, event):
        payload = {"event": event["event"], "location": event.get("location", "ruleguard"),
                   "log_format": event.get("log_format", "syslog")}
        if self.session:
            payload["token"] = self.session
        response = self.request("PUT", "/logtest", payload)
        data = response.get("data", {})
        token = data.get("token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise GuardError("Missing logtest session token")
        previous = self.session
        self.session = token  # Even a replacement session must be cleaned up.
        if previous is not None and token != previous:
            raise GuardError("Logtest session changed unexpectedly; correlation result is invalid")
        return normalize(response)

    def close(self):
        if self.session:
            token, self.session = self.session, None
            self.request("DELETE", "/logtest/sessions/" + urllib.parse.quote(token, safe=""))


class ReplayBackend:
    mode = "offline-replay"

    def __init__(self, report):
        if not isinstance(report, dict) or report.get("schema_version") != 1:
            raise GuardError("Replay file must be a RuleGuard report")
        self.entries = {}
        if not isinstance(report.get("results"), list) or not report["results"]:
            raise GuardError("Replay needs a non-empty results array")
        for row in report["results"]:
            if not isinstance(row, dict) or row.get("actual") is None or row.get("status") == "error":
                raise GuardError("Replay requires complete recorded results")
            if not isinstance(row.get("case_id"), str) or type(row.get("step")) is not int or row["step"] < 1:
                raise GuardError("Malformed replay case id or step")
            key = (row["case_id"], row["step"])
            if key in self.entries:
                raise GuardError("Duplicate replay step")
            self.entries[key] = row

    def start(self, case):
        self.case, self.index = case, 0
        found = {step for name, step in self.entries if name == case["id"]}
        if found != set(range(1, len(case["events"]) + 1)):
            raise GuardError("Replay step count does not match case")

    def process(self, event):
        self.index += 1
        row = self.entries[(self.case["id"], self.index)]
        if row.get("fingerprint") != fingerprint(self.case):
            raise GuardError("Replay input differs from recorded events")
        actual = row["actual"]
        if not isinstance(actual, dict) or set(actual) != {"rule_id", "level", "alert", "decoder", "groups", "mitre", "warning_count"}:
            raise GuardError("Malformed recorded observation")
        if type(actual["alert"]) is not bool or type(actual["warning_count"]) is not int or actual["warning_count"] < 0:
            raise GuardError("Malformed recorded observation")
        for key in ("groups", "mitre"):
            if not isinstance(actual[key], list) or not all(isinstance(x, str) for x in actual[key]):
                raise GuardError("Malformed recorded metadata")
        return actual

    def close(self):
        pass
