# internal/license/data

## osadl-matrix.json

- **What:** OSADL Open Source License Checklists — license compatibility matrix.
  Shape: `{"<leading license>": {"<subordinate license>": "Yes" | "No" | "Unknown" | "Check dependency" | "Same"}}`
  plus top-level `timeformat` / `timestamp` keys. 119 licenses (SPDX ids).
  "Leading" is the license of the combined work (your project), "subordinate" the
  license of the included component (a dependency).
- **Source:** https://www.osadl.org/fileadmin/checklists/matrix.json
  (described at https://www.osadl.org/Access-to-raw-data.oss-compliance-raw-data-access.0.html)
- **Fetched:** 2026-10-03, upstream `timestamp` 2026-09-23T08:44:00+0000, unmodified.
- **License:** Creative Commons Attribution 4.0 International (CC-BY-4.0),
  https://creativecommons.org/licenses/by/4.0/ —
  © 2017 - 2024 Open Source Automation Development Lab (OSADL) eG and contributors.
  Redistribution (embedding) is permitted with attribution.
- **Required attribution text** (must appear on depguard's `/attributions` page):

  > A project by the Open Source Automation Development Lab (OSADL) eG. For further
  > information about the project see the description at www.osadl.org/checklists.

To refresh: download the URL above over this file; keep the README date in sync.
