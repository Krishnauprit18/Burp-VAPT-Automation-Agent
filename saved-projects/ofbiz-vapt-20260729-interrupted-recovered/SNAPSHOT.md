# OFBiz VAPT Burp project snapshot

- Source run: `artifacts/run-20260729-170226`
- Snapshot state: recovered after unexpected laptop shutdown; task paused
- Target: `https://localhost:8443`
- Burp project contains the Site map tree, request/response contents, issues,
  and saved Dashboard task state.

## Integrity

- `burp-project.burp`
  - Size: `1207959552` bytes
  - SHA-256: `49a08b0053e2d4088bdcb53e5757614be8bb1734f63130db6b1d7143efa8d917`
- `burp-project.burp.backup`
  - Size: `805306368` bytes
  - SHA-256: `862146a1bbb1ffbba310e71ec8566f510949f2300ba4d6df5f0163ad33690766`

This directory is independent of `artifacts/` and is not removed by the
project's `--stop-clean` command. Burp project files are tracked by Git LFS.
