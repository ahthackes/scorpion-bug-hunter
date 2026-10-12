# Scope files

Each file here is `<program-name>.json` and holds the in-scope / out-of-scope
rules for one bug bounty program, e.g. pulled from HackerOne/Bugcrowd via
`bbscope` or entered by hand. `core/scope_guard.py` loads the file matching
a target's program before any active (Tier 1+) module runs.

Expected shape (filled in once `core/scope_guard.py` is implemented):

```json
{
  "program": "example-corp",
  "in_scope": ["*.example.com"],
  "out_of_scope": ["blog.example.com"],
  "max_tier": 2,
  "notes": ""
}
```

This directory is git-ignored except for this README -- scope data is
specific to programs you're hunting on and shouldn't be committed.
