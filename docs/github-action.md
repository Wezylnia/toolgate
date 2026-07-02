# GitHub Action

The repository includes a composite action that fails a job when a policy manifest removes
security controls.

```yaml
name: Policy check

on:
  pull_request:

permissions:
  contents: read

jobs:
  toolgate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: Wezylnia/toolgate@v1.0.3
        with:
          base: policy-manifest.main.json
          head: policy-manifest.pr.json
          fail-on: danger
```

Generate or retrieve both manifest files before invoking the action. The action deliberately does
not assume how a project builds its manifest.

Thresholds:

- `danger` fails only when controls are loosened.
- `warning` also fails when tools are added or timeouts increase.
- `info` fails for any declared policy change.

The action runs the pinned `toolgate-mcp@1.0.3` CLI on Node.js 24. Override
`toolgate-version` only when testing a newer compatible package release.
