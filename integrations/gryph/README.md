# gryph → depguard

`0001-stream-http-target.patch` adds an `http` stream target to
[safedep/gryph](https://github.com/safedep/gryph) (Apache-2.0). It is intended to be
upstreamed; until then build gryph from a fork with the patch applied:

```sh
git clone https://github.com/safedep/gryph && cd gryph
git am /path/to/depguard/integrations/gryph/0001-stream-http-target.patch
go install .
```

Configure gryph (`~/.config/gryph/config.yaml`) to stream to depguard. The endpoint id comes
from `depguard agent` (printed on first check-in):

```yaml
streams:
  targets:
    - name: depguard
      type: http
      enabled: true
      config:
        url: https://api.example.com/v1/endpoints/<endpoint-id>/agent-events
        token_env: DEPGUARD_API_KEY
```

Then `gryph stream sync` ships new events. Without the patch, `depguard agent` falls back to
`gryph export` to collect events.
