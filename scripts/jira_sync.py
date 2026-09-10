#!/usr/bin/env python3
"""Push docs/backlog.yml into Jira Cloud. Idempotent: re-running updates.

Environment:
    JIRA_SITE   https://<your-site>.atlassian.net
    JIRA_EMAIL  Atlassian account email
    JIRA_TOKEN  API token from https://id.atlassian.com/manage-profile/security/api-tokens

Usage:
    scripts/jira_sync.py             create project, epics, stories, sprints
    scripts/jira_sync.py --dry-run   print what would happen, no writes

State lives in docs/jira-map.json (local key -> Jira key/id). Delete an
entry there to recreate that item. Stdlib only, plus PyYAML.
"""

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def ssl_context():
    # python.org builds of Python ship without system CA certificates.
    # Prefer certifi's bundle when it is installed; otherwise fall back to
    # whatever the interpreter has.
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()

BACKLOG = ROOT / "docs" / "backlog.yml"
MAP = ROOT / "docs" / "jira-map.json"
PROJECT_KEY = "SIG"
# Team-managed Scrum. Falls back to company-managed if the site rejects it.
TEMPLATES = [
    "com.pyxis.greenhopper.jira:gh-simplified-agility-scrum",
    "com.pyxis.greenhopper.jira:gh-scrum-template",
]


class Jira:
    def __init__(self, site, email, token, dry_run=False):
        self.site = site.rstrip("/")
        self.auth = base64.b64encode(f"{email}:{token}".encode()).decode()
        self.dry_run = dry_run
        self.ctx = ssl_context()

    def call(self, method, path, body=None, params=None):
        url = self.site + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        if self.dry_run and method != "GET":
            print(f"  [dry-run] {method} {path} {json.dumps(body)[:160]}")
            return {}
        req = urllib.request.Request(url, method=method)
        req.add_header("Authorization", "Basic " + self.auth)
        req.add_header("Accept", "application/json")
        data = None
        if body is not None:
            req.add_header("Content-Type", "application/json")
            data = json.dumps(body).encode()
        try:
            with urllib.request.urlopen(req, data, context=self.ctx) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")
            raise RuntimeError(f"{method} {path} -> {e.code}: {detail[:500]}") from None


# ---------------------------------------------------------------- ADF helpers

def p(text):
    return {"type": "paragraph", "content": [{"type": "text", "text": text}]}


def h(text):
    return {"type": "heading", "attrs": {"level": 3},
            "content": [{"type": "text", "text": text}]}


def bullets(items):
    return {"type": "bulletList", "content": [
        {"type": "listItem", "content": [p(i)]} for i in items]}


def adf(*blocks):
    return {"type": "doc", "version": 1, "content": list(blocks)}


def story_description(s):
    blocks = [p(s["story"]), h("Acceptance criteria"), bullets(s["acceptance"])]
    if s.get("plan"):
        blocks += [h("Plan"), p(s["plan"])]
    return adf(*blocks)


# ---------------------------------------------------------------- steps

def load_map():
    return json.loads(MAP.read_text()) if MAP.exists() else {}


def save_map(m, dry_run):
    if not dry_run:
        MAP.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")


def ensure_project(j, backlog):
    try:
        proj = j.call("GET", f"/rest/api/3/project/{PROJECT_KEY}")
        print(f"project {PROJECT_KEY} exists (id {proj['id']})")
        return proj
    except RuntimeError as e:
        if "404" not in str(e):
            raise
    me = j.call("GET", "/rest/api/3/myself")
    last = None
    for tpl in TEMPLATES:
        body = {
            "key": PROJECT_KEY,
            "name": backlog["project"]["name"],
            "projectTypeKey": "software",
            "projectTemplateKey": tpl,
            "leadAccountId": me["accountId"],
            "description": "Sigma detection engine with a proven v1 to v2 cutover.",
        }
        try:
            proj = j.call("POST", "/rest/api/3/project", body)
            print(f"created project {PROJECT_KEY} with template {tpl}")
            return proj
        except RuntimeError as e:
            last = e
            print(f"template {tpl} rejected, trying next")
    raise last


def issue_type_ids(j):
    try:
        meta = j.call("GET", f"/rest/api/3/project/{PROJECT_KEY}", params={"expand": "issueTypes"})
    except RuntimeError as e:
        if j.dry_run and "404" in str(e):
            return {"epic": "DRY-epic", "story": "DRY-story"}
        raise
    types = {t["name"].lower(): t["id"] for t in meta.get("issueTypes", [])}
    for needed in ("epic", "story"):
        if needed not in types:
            raise RuntimeError(f"project has no {needed} issue type; have {sorted(types)}")
    return types


def story_points_field(j):
    for f in j.call("GET", "/rest/api/3/field"):
        if f["name"].lower() in ("story point estimate", "story points"):
            return f["id"]
    return None


def find_existing(j, summary):
    jql = f'project = {PROJECT_KEY} AND summary ~ "\\"{summary}\\""'
    res = j.call("GET", "/rest/api/3/search/jql", params={"jql": jql, "fields": "summary", "maxResults": 5})
    for issue in res.get("issues", []):
        if issue["fields"]["summary"] == summary:
            return issue["key"]
    return None


def upsert_issue(j, m, local_key, fields):
    summary = fields["summary"]
    key = m.get(local_key, {}).get("key")
    if not key:
        try:
            key = find_existing(j, summary)
        except RuntimeError as e:
            if not (j.dry_run and "400" in str(e)):
                raise
    if key:
        j.call("PUT", f"/rest/api/3/issue/{key}", {"fields": fields})
        print(f"  updated {key}  {local_key}  {summary}")
    else:
        res = j.call("POST", "/rest/api/3/issue", {"fields": fields})
        key = res.get("key", f"DRY-{local_key}")
        print(f"  created {key}  {local_key}  {summary}")
    m[local_key] = {"key": key}
    return key


def board_id(j):
    if j.dry_run:
        try:
            res = j.call("GET", "/rest/agile/1.0/board", params={"projectKeyOrId": PROJECT_KEY})
        except RuntimeError:
            return "DRY-board"
    else:
        res = j.call("GET", "/rest/agile/1.0/board", params={"projectKeyOrId": PROJECT_KEY})
    values = res.get("values", [])
    if not values and j.dry_run:
        return "DRY-board"
    # Team-managed boards report type "simple", so do not filter on type;
    # prefer the board located in this project.
    for b in values:
        if b.get("location", {}).get("projectKey") == PROJECT_KEY:
            return b["id"]
    if not values:
        raise RuntimeError("no board for project; open the project in Jira once to create it")
    return values[0]["id"]


def ensure_sprints(j, m, backlog, bid):
    existing = {}
    start = 0
    while True:
        if str(bid).startswith("DRY"):
            break
        res = j.call("GET", f"/rest/agile/1.0/board/{bid}/sprint", params={"startAt": start, "maxResults": 50})
        for s in res.get("values", []):
            existing[s["name"]] = s["id"]
        if res.get("isLast", True):
            break
        start += len(res.get("values", []))
    for sp in backlog["sprints"]:
        local = f"sprint-{sp['id']}"
        sid = m.get(local, {}).get("id") or existing.get(sp["name"])
        body = {"name": sp["name"], "goal": sp["goal"]}
        if sid:
            j.call("POST", f"/rest/agile/1.0/sprint/{sid}", body)
            print(f"  updated sprint {sid}  {sp['name']}")
        else:
            res = j.call("POST", "/rest/agile/1.0/sprint", {**body, "originBoardId": bid})
            sid = res.get("id", f"DRY-{local}")
            print(f"  created sprint {sid}  {sp['name']}")
        m[local] = {"id": sid, "name": sp["name"]}


def assign_sprints(j, m, backlog):
    by_sprint = {}
    for e in backlog["epics"]:
        for s in e["stories"]:
            by_sprint.setdefault(s["sprint"], []).append(m[s["key"]]["key"])
    for sprint_no, keys in sorted(by_sprint.items()):
        sid = m[f"sprint-{sprint_no}"]["id"]
        for i in range(0, len(keys), 50):
            j.call("POST", f"/rest/agile/1.0/sprint/{sid}/issue", {"issues": keys[i:i + 50]})
        print(f"  sprint {sprint_no}: {len(keys)} stories")


def validate(backlog):
    # An unquoted colon in a YAML list item silently becomes a mapping, which
    # Jira then rejects as invalid ADF. Catch it here with a useful message.
    bad = []
    for e in backlog["epics"]:
        for s in e["stories"]:
            for f in ("title", "story"):
                if not isinstance(s.get(f), str):
                    bad.append(f"{s['key']}.{f}")
            for i, a in enumerate(s["acceptance"]):
                if not isinstance(a, str) or not a.strip():
                    bad.append(f"{s['key']}.acceptance[{i}] (quote lines containing a colon)")
    if bad:
        sys.exit("backlog.yml has non-string text:\n  " + "\n  ".join(bad))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    missing = [k for k in ("JIRA_SITE", "JIRA_EMAIL", "JIRA_TOKEN") if not os.environ.get(k)]
    if missing:
        sys.exit(f"missing env: {', '.join(missing)}")

    j = Jira(os.environ["JIRA_SITE"], os.environ["JIRA_EMAIL"], os.environ["JIRA_TOKEN"], args.dry_run)
    backlog = yaml.safe_load(BACKLOG.read_text())
    validate(backlog)
    m = load_map()

    print("== project")
    ensure_project(j, backlog)
    types = issue_type_ids(j)
    points_field = story_points_field(j)
    if not points_field:
        print("  no story points field found; points will be skipped")

    print("== epics")
    for e in backlog["epics"]:
        fields = {
            "project": {"key": PROJECT_KEY},
            "issuetype": {"id": types["epic"]},
            "summary": f"{e['key']}: {e['name']}",
            "description": adf(p(e["summary"]), *( [h("Plan"), p(e["plan"])] if e.get("plan") else [] )),
        }
        upsert_issue(j, m, e["key"], fields)
    save_map(m, args.dry_run)

    print("== stories")
    for e in backlog["epics"]:
        epic_key = m[e["key"]]["key"]
        for s in e["stories"]:
            fields = {
                "project": {"key": PROJECT_KEY},
                "issuetype": {"id": types["story"]},
                "summary": s["title"],
                "description": story_description(s),
                "parent": {"key": epic_key},
                "labels": [f"sprint-{s['sprint']}", s["key"]],
            }
            if points_field:
                fields[points_field] = s["points"]
            upsert_issue(j, m, s["key"], fields)
    save_map(m, args.dry_run)

    print("== sprints")
    bid = board_id(j)
    ensure_sprints(j, m, backlog, bid)
    assign_sprints(j, m, backlog)
    save_map(m, args.dry_run)
    print("done")


if __name__ == "__main__":
    main()
