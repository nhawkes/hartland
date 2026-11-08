"""Writes the keyring a trusted builder uses: itself at its own commit, plus
the commits of the same workflow listed in hartland's keys/builders.json.

Usage: make-keyring.py <workflow> <commit> <builders.json>
"""
import json
import os
import sys

wf, sha, extra = sys.argv[1:4]
commits = [sha]
if os.path.exists(extra):
    for b in json.load(open(extra)).get("builders", []):
        if b["workflow"] == wf:
            commits += [c for c in b["commits"] if c not in commits]
print(json.dumps({"builders": [{"workflow": wf, "commits": commits}]}))
