# Coordinator setup and operations

The coordinator is the only component that holds secrets, touches `/dev/kvm`,
and merges pull requests. It runs on **your** Linux machine. Nothing in this
guide puts a key, token, or target byte into a repository.

Every command below is implemented; check it with `--help` before running it.

## 1. Host prerequisites

| Requirement | Why | Check |
| --- | --- | --- |
| Linux | jailer/Firecracker and KVM are Linux-only | `uname -s` |
| `/dev/kvm` read+write for the service account | microVM verification | `ls -l /dev/kvm` |
| Git ≥ 2.38 | `git merge-tree --write-tree` | `git --version` |
| OpenSSL ≥ 3.0 | GitHub App JWT signing | `openssl version` |
| e2fsprogs (`mke2fs`, `debugfs`) ≥ 1.46 | guest drives, verdict extraction | `mke2fs -V` |
| Docker or Podman | building the contributor toolchain image | `docker --version` |
| Firecracker + jailer + guest kernel + rootfs | the verification guest | pinned by sha256 |

```bash
recomp coordinator doctor --owner <you> --repository <repo>
```

The fastest path is the generated recipe, which pins every download by
content hash and repairs a damaged `/dev/null`:

```bash
recomp coordinator machine-setup --output coordinator-machine-setup.sh
bash coordinator-machine-setup.sh        # uses sudo for packages, kvm group, /dev/null
```

Review the pins in the script before running it; it never writes outside
`~/.local/share/recomp/firecracker` except through the three explicit sudo
lines it prints about.

`doctor` prints a JSON report with stable check IDs (`platform`, `kvm`,
`firecracker`, `jailer`, `kernel`, `rootfs`, `git`, `openssl`, `mke2fs`,
`app-key`), a sanitized observed value, and exact remediation text. It exits
non-zero if any finding has severity `error`. It never prints key bytes.

## 2. Customize the workflow in your fork

```bash
recomp plugin new my-workflow --capability work
recomp plugin check my-workflow
recomp plugin test my-workflow
recomp workflow lock
```

`[verify]` in the plugin manifest decides whether public verification is even
possible:

```toml
[verify]
mode = "static"          # or "bytematch" / "behavioral"
public = true
timeout_seconds = 30
max_artifact_bytes = 1048576
```

`behavioral` additionally requires `candidate_build`, `candidate_run`,
`oracle_run` argv lists and a `[verify.protocol]` table with `version = 1` and
a non-empty `cases` list. A plugin without a separable public plan is
maintainer-only: `verify_candidate(..., require_public=True)` refuses it.

## 3. Build and pin the toolchain image

```bash
recomp toolchain build --source toolchain \
  --base-image docker.io/library/python@sha256:<64hex> \
  --destination ghcr.io/<you>/<game>-toolchain:build-1
```

stdout is exactly one line — the immutable reference — so it can be passed
straight to `recomp init`. Build logs go to stderr. A failed push or a missing
registry digest produces no project configuration. Verify any host's copy:

```bash
recomp toolchain inspect ghcr.io/<you>/<game>-toolchain@sha256:<64hex>
```

## 4. Create the project repository

```bash
recomp init ../mygame --bin /path/to/game.exe --goal structure \
  --owner <you> --repository mygame \
  --toolchain-image ghcr.io/<you>/<game>-toolchain@sha256:<64hex> \
  --framework-action <you>/RecompAtHome@<40hex> \
  --trusted-actor-id <app-bot-user-id>
```

The generated tree contains no target bytes, no `bin/`, no `server/`, and no
secrets. `recomp.toml` pins the target by `filename`, `sha256`, and `size`.
Commit and push it as its own GitHub repository.

`--trusted-actor-id` is the numeric user id of your App's bot account
(`https://api.github.com/users/<app-slug>%5Bbot%5D`). It is the trust anchor:
task records and lease transitions are only believed when that id authored
them, so a contributor cannot forge a claim by posting a lookalike comment.

## 5. GitHub App

Create an App you own, installed only on the project repository.

Repository permissions: Issues **read & write**, Pull requests **read &
write**, Contents **read & write**, Checks **read & write**, Metadata
**read**. Subscribe to no webhooks: the coordinator polls.

Do **not** grant Administration. Repository administration (rulesets, Actions
policy) is done once, by you, through your own session — the runtime App must
not be able to weaken its own guardrails.

Store the private key at the path `doctor` reports:

```
~/.config/recomp/coordinators/<owner>__<repo>/app-private-key.pem   # 0600
~/.config/recomp/coordinators/<owner>__<repo>/config.toml           # 0600
~/.local/state/recomp/coordinators/<owner>__<repo>/                 # 0700
~/.cache/recomp/coordinators/<owner>__<repo>/                       # 0700
```

The config file stores paths and public ids only; `write_coordinator_config()`
refuses any key whose name contains `token` or `secret`, writes with
`O_NOFOLLOW`, and refuses a symlinked path.

A temporary owner token (for the one-time repository administration step) is
accepted only from a 0600 file or `gh auth token` stdout — never from argv,
never written to disk.

## 6. Repository settings to apply once

- Branch ruleset on `main`: require pull requests, require the `recomp
  verification` check, require the `preflight` check, block force-push and
  deletion, and allow your App to merge.
- Actions: allow only the actions your workflows reference, pinned by SHA.
  Set workflow permissions to read-only by default.
- `.github/CODEOWNERS` (generated) protects every trusted root.
- Labels: `recomp task bootstrap` ensures `recomp-task`, `open`, `claimed`,
  `verifying`, `done`, `blocked`.

## 7. Publish work

```bash
cd ../mygame
recomp github bootstrap
recomp github sync-tasks --target /path/to/game.exe
```

`sync-tasks` refuses to run against a stale policy lock, validates your target
against the pinned hash, computes the work plan with the project plugin, and
creates one Issue per unpublished task plus its trusted task-record comment.
Re-running is idempotent: tasks already carrying a marker are skipped.

## 8. Install the service

```bash
recomp coordinator install-service --owner <you> --repository mygame \
  --user recomp --output /tmp/recomp-coordinator.service
```

It writes a hardened unit and prints the exact commands to install it:
`NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`,
`ProtectHome=yes`, `RestrictSUIDSGID=yes`, `DevicePolicy=closed` with
`DeviceAllow=/dev/kvm rw`, `Restart=on-failure`, explicit `ReadWritePaths`,
and `LoadCredential=app-key:<path>` so the key is never an environment
variable or a command-line argument.

## 9. Day-to-day operation

- Logs: `journalctl -u recomp-coordinator -f`
- Stop/start: `sudo systemctl stop|start recomp-coordinator`
- Health: the loop writes a schema-versioned JSON file atomically into the
  state directory after every pass (`schema`, `last_reconcile_at`, `pending`,
  `admitted_total`). The coordinator never opens an inbound listener.
- Rate limits: a 403 with a reset time backs the loop off until the reset;
  other failures use capped exponential backoff with jitter.

## 10. Upgrades and policy repinning

1. Edit the plugin or toolchain in the project repository.
2. `recomp workflow lock` and commit the lockfile.
3. `recomp github sync-tasks --target ...` to publish newly planned tasks.
4. Restart the coordinator.

In-flight pull requests produced under the old policy now fail preflight with
a stale-policy code. That is intended: contributors re-read the prompt and
re-claim.

## 11. Backup, rotation, and rebuild

- Back up: `~/.config/recomp/coordinators/<owner>__<repo>/`. That is the only
  irreplaceable state — the queue database is disposable by design and
  rebuilds from GitHub on the next pass.
- Rotate the App key: generate a new key in GitHub, replace the 0600 file,
  restart the service, then delete the old key in GitHub.
- Rebuild on a new machine: install prerequisites, restore the config
  directory, run `doctor`, start the service. No state migration needed.

## 12. Break-glass and incident response

- **Stop admitting work:** stop the service. GitHub keeps every claim and
  Issue; nothing is lost.
- **A bad merge landed:** open a revert pull request (never rewrite history),
  let it merge, then let the coordinator append a new task generation and
  reopen the Issue so the work returns to the pool.
- **Suspected key compromise:** delete the App installation, rotate the key,
  review the merge history for commits whose trailers do not match a known
  attestation, revert anything unexplained.
- **Suspected guest escape:** stop the service, preserve
  `~/.local/state/recomp/...`, rebuild the host, rotate the key. Report the
  Firecracker version and reproducer upstream.

## 13. Uninstall

```bash
sudo systemctl disable --now recomp-coordinator
sudo rm /etc/systemd/system/recomp-coordinator.service && sudo systemctl daemon-reload
rm -rf ~/.config/recomp/coordinators/<owner>__<repo> \
       ~/.local/state/recomp/coordinators/<owner>__<repo> \
       ~/.cache/recomp/coordinators/<owner>__<repo>
```

Delete the GitHub App installation last, so no automation runs against a
repository you are no longer watching.
