#!/usr/bin/env python3
"""Validate docs/backlog.yml before jira_sync.py ever sees it.

Fails on: unparseable YAML, duplicate story or epic keys, a story missing a
required field, or a story pointing at a sprint that is not declared.
"""

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
BACKLOG = ROOT / "docs" / "backlog.yml"

STORY_FIELDS = ("key", "sprint", "title", "story", "acceptance", "points")
EPIC_FIELDS = ("key", "name", "summary", "stories")


def main() -> int:
    try:
        data = yaml.safe_load(BACKLOG.read_text()) or {}
    except yaml.YAMLError as exc:
        print(f"{BACKLOG}: {exc}", file=sys.stderr)
        return 1
    errors = []
    sprint_ids = [s.get("id") for s in data.get("sprints") or []]
    sprints = set(sprint_ids)
    if len(sprints) != len(sprint_ids):
        errors.append("duplicate sprint id")
    seen = set()

    for epic in data.get("epics") or []:
        if not isinstance(epic, dict):
            errors.append(f"epic is not a mapping: {epic!r}")
            continue
        for field in EPIC_FIELDS:
            if field not in epic:
                errors.append(f"epic {epic.get('key', '?')}: missing {field}")
        key = epic.get("key")
        if key in seen:
            errors.append(f"duplicate key {key}")
        seen.add(key)

        for story in epic.get("stories") or []:
            if not isinstance(story, dict):
                errors.append(f"epic {key}: story is not a mapping: {story!r}")
                continue
            skey = story.get("key", "?")
            for field in STORY_FIELDS:
                if field not in story:
                    errors.append(f"story {skey}: missing {field}")
            if skey in seen:
                errors.append(f"duplicate key {skey}")
            seen.add(skey)
            if story.get("sprint") not in sprints:
                errors.append(f"story {skey}: unknown sprint {story.get('sprint')}")
            if not isinstance(story.get("acceptance"), list) or not story.get("acceptance"):
                errors.append(f"story {skey}: acceptance must be a non-empty list")

    for err in errors:
        print(err, file=sys.stderr)
    if errors:
        return 1
    print(f"backlog ok: {len(seen)} keys, {len(sprints)} sprints")
    return 0


if __name__ == "__main__":
    sys.exit(main())
