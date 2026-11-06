# Trace Format v1

Normative specification of the session trace format (spec §7.8):

- [Session metadata (`meta.json`)](session-v1.md) — implemented by
  `starforge-format::SessionMeta`; JSON Schema: `schema/session-v1.json`.
- [Events](events-v1.md) — normalized event stream (JSONL per segment);
  JSON Schema: `schema/events-v1.json`.

Implementations: `starforge-format` (encoding, segmentation) and
`starforge-redact` (secret scrubbing), both MIT OR Apache-2.0.

## Export bundle layout

`starforge export` writes one directory per exported session bundle:

```text
<dir>/
  bundle.json                              format version 1, server URL, exported_at
  <owner>__<repo>/<ulid>/
    session.json                           the API metadata, as returned
    events.jsonl                           the normalized transcript (via /events)
    segments/<n>.raw.zst                   stored bytes when the API serves raw;
                                           otherwise the re-segmentation of the redacted /events stream
    links.json                             commit links (via /links)
```

`starforge import <dir> --repo <owner/repo>` uploads each session through the
normal upload API, preserving ULIDs and re-creating `cli_claim` links from
`links.json`; a ULID already present in the target repository is reported
`exists` and skipped.
