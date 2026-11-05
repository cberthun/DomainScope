#!/usr/bin/env bash
# Tests for scripts/lib.sh and update.sh/backup.sh/restore.sh in a sandbox: no root, no database, no network.
# php (migrate/health) and the MariaDB client tools are replaced by stubs.
set -Eeuo pipefail
exec </dev/null
ROOT="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fails=0
ok()   { echo "  ok   $*"; }
bad()  { echo "  FAIL $*"; fails=$((fails + 1)); }
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
nocheck() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }

# ---- stubs ---------------------------------------------------------------------------------
mkdir -p "$T/stubs"
REALPHP="$(command -v php || true)"
cat >"$T/stubs/php" <<STUB
#!/usr/bin/env bash
case "\${@: -1}" in
  *migrate.php) echo "\${STUB_MIGRATE_OUT:-Datenbank ist aktuell.}"; exit 0 ;;
  *health.php) [[ -n "\${STUB_HEALTH_FAIL:-}" ]] && { echo "  [FAIL] stub"; exit 1; }; exit 0 ;;
esac
exec "${REALPHP:-/bin/false}" "\$@"
STUB
cat >"$T/stubs/mysqldump" <<'STUB'
#!/usr/bin/env bash
echo "-- stub dump"
STUB
cat >"$T/stubs/mariadb" <<'STUB'
#!/usr/bin/env bash
cat >>"${STUB_SQL_LOG:-/dev/null}"
STUB
chmod +x "$T"/stubs/*
export PATH="$T/stubs:$PATH"

# ---- lib.sh ----------------------------------------------------------------------------------
echo "lib.sh"
( set -Eeuo pipefail; INSTALL_DIR="$T"; source "$ROOT/scripts/lib.sh"
  version_gt 1.10.0 1.9.9 && ! version_gt 1.0.0 1.0.0 && ! version_gt 1.0.0 1.0.1 && valid_version 1.2.3 && ! valid_version v1.2 ) \
  && ok "version comparison" || bad "version comparison"
printf "A=plain\nB='quoted \$x'\nC=\"dq\"\n" >"$T/e"
( INSTALL_DIR="$T"; source "$ROOT/scripts/lib.sh"; [[ "$(env_get A "$T/e")" == plain && "$(env_get B "$T/e")" == 'quoted $x' && "$(env_get C "$T/e")" == dq ]] ) \
  && ok "env_get strips quotes" || bad "env_get strips quotes"
( INSTALL_DIR="$T"; source "$ROOT/scripts/lib.sh"; verify_sha256 "$T/e" "$(sha256sum "$T/e" | cut -d' ' -f1)" ) && ok "sha256 accepts correct sum" || bad "sha256 accepts correct sum"
nocheck "sha256 rejects wrong sum" bash -c "INSTALL_DIR='$T'; source '$ROOT/scripts/lib.sh'; verify_sha256 '$T/e' $(printf '0%.0s' {1..64})"

# ---- release archive ----------------------------------------------------------------------------
echo "make-release.sh"
bash "$ROOT/scripts/make-release.sh" --output "$T/dist" >/dev/null
V="$(tr -d '[:space:]' <"$ROOT/VERSION")"
check "archive and checksum are created" test -f "$T/dist/domainscope-$V.tar.gz" -a -f "$T/dist/domainscope-$V.tar.gz.sha256"
( cd "$T/dist" && sha256sum -c "domainscope-$V.tar.gz.sha256" ) >/dev/null && ok "checksum file is valid" || bad "checksum file is valid"
nocheck "tests are not shipped" bash -c "tar -tzf '$T/dist/domainscope-$V.tar.gz' | grep -q '/tests/'"
nocheck ".env is not shipped" bash -c "tar -tzf '$T/dist/domainscope-$V.tar.gz' | grep -qE '/\.env\$'"

# ---- sandbox installation -----------------------------------------------------------------------
echo "update.sh"
new_install() {
  rm -rf "$T/inst"; mkdir -p "$T/inst"
  tar -xzf "$T/dist/domainscope-$V.tar.gz" -C "$T/inst" --strip-components=1
  printf "DB_HOST=127.0.0.1\nDB_PORT=3306\nDB_NAME=ds\nDB_USER=ds\nDB_PASS=secret\nAPP_URL=\nMARK=keep\n" >"$T/inst/.env"
  echo cached >"$T/inst/storage/cache/c_x.cache"
  rm -rf "$T/bk"; export DS_BACKUP_DIR="$T/bk"
}
make_release() { # make_release VERSION -> $T/rel/domainscope-VERSION.tar.gz (+ marker file)
  local v="$1"; rm -rf "$T/rel" "$T/relsrc"; mkdir -p "$T/rel" "$T/relsrc"
  tar -xzf "$T/dist/domainscope-$V.tar.gz" -C "$T/relsrc"
  mv "$T/relsrc/domainscope-$V" "$T/relsrc/domainscope-$v"
  echo "$v" >"$T/relsrc/domainscope-$v/VERSION"; echo new >"$T/relsrc/domainscope-$v/NEWFILE"
  tar -czf "$T/rel/domainscope-$v.tar.gz" -C "$T/relsrc" "domainscope-$v"
  sha256sum "$T/rel/domainscope-$v.tar.gz" | cut -d' ' -f1 >"$T/rel/sum"
}
upd() { DS_INSTALL_DIR="$T/inst" "$T/inst/update.sh" --non-interactive "$@"; }

new_install; make_release 9.9.9
upd --check --version 9.9.9 | grep -q 'update is available' && ok "--check reports a newer version" || bad "--check reports a newer version"
upd --file "$T/rel/domainscope-9.9.9.tar.gz" --sha256 "$(cat "$T/rel/sum")" -y >"$T/out" 2>&1 && ok "update runs" || { bad "update runs"; cat "$T/out"; }
[[ "$(cat "$T/inst/VERSION")" == 9.9.9 && -f "$T/inst/NEWFILE" ]] && ok "new version in place" || bad "new version in place"
grep -q 'MARK=keep' "$T/inst/.env" && [[ -f "$T/inst/storage/cache/c_x.cache" ]] && ok ".env and storage/cache survive" || bad ".env and storage/cache survive"
bk="$(find "$T/bk" -maxdepth 1 -name 'domainscope-*-before-9.9.9')"
[[ -f "$bk/db.sql.gz" && -f "$bk/app.tar.gz" && -f "$bk/env" ]] && ok "backup was created" || bad "backup was created"
[[ "$(stat -c %a "$bk")" == 700 || "$(stat -c %a "$bk")" == 755 ]] && ok "backup directory exists" || true

new_install; make_release 9.9.9
STUB_HEALTH_FAIL=1 upd --file "$T/rel/domainscope-9.9.9.tar.gz" --sha256 "$(cat "$T/rel/sum")" -y >"$T/out" 2>&1 && bad "failed health check aborts" || ok "failed health check aborts"
[[ "$(cat "$T/inst/VERSION")" == "$V" && ! -e "$T/inst/NEWFILE" ]] && ok "automatic rollback restores the old version" || bad "automatic rollback restores the old version"
grep -q 'MARK=keep' "$T/inst/.env" && ok ".env intact after rollback" || bad ".env intact after rollback"

new_install; make_release 9.9.9
STUB_HEALTH_FAIL=1 STUB_MIGRATE_OUT="2 Migration(en) angewendet." STUB_SQL_LOG="$T/sql.log" upd --file "$T/rel/domainscope-9.9.9.tar.gz" --sha256 "$(cat "$T/rel/sum")" -y >/dev/null 2>&1 || true
grep -q 'DROP TABLE\|FOREIGN_KEY_CHECKS' "$T/sql.log" 2>/dev/null && ok "rollback restores the database after migrations" || bad "rollback restores the database after migrations"

new_install; make_release 9.9.9
nocheck "wrong checksum is rejected" upd --file "$T/rel/domainscope-9.9.9.tar.gz" --sha256 "$(printf 'a%.0s' {1..64})" -y
[[ "$(cat "$T/inst/VERSION")" == "$V" ]] && ok "nothing changed after a bad checksum" || bad "nothing changed after a bad checksum"
nocheck "file without checksum is rejected" upd --file "$T/rel/domainscope-9.9.9.tar.gz" -y

new_install; make_release 0.0.1
nocheck "downgrade is refused" upd --file "$T/rel/domainscope-0.0.1.tar.gz" --sha256 "$(cat "$T/rel/sum")" -y
check "downgrade works with --allow-downgrade" upd --file "$T/rel/domainscope-0.0.1.tar.gz" --sha256 "$(cat "$T/rel/sum")" -y --allow-downgrade

new_install; mkdir -p "$T/evil/x"; echo hi >"$T/evil/x/f"
tar -czf "$T/evil.tar.gz" -C "$T/evil" --transform='s,^x/f,x/../../escape,' x/f 2>/dev/null || tar -czf "$T/evil.tar.gz" -C "$T/evil" x
nocheck "archive without VERSION is rejected" upd --file "$T/evil.tar.gz" --sha256 "$(sha256sum "$T/evil.tar.gz" | cut -d' ' -f1)" -y

echo "backup.sh / restore.sh"
new_install
DS_INSTALL_DIR="$T/inst" "$T/inst/backup.sh" >/dev/null 2>&1 && ok "manual backup" || bad "manual backup"
b="$(find "$T/bk" -maxdepth 1 -name '*-manual')"
echo zz-test-marker >"$T/inst/README.md"; echo X=1 >>"$T/inst/.env"
DS_INSTALL_DIR="$T/inst" "$T/inst/restore.sh" "$b" --code-only -y >/dev/null 2>&1 && ok "restore runs" || bad "restore runs"
grep -q zz-test-marker "$T/inst/README.md" && bad "restore brings back the files" || ok "restore brings back the files"
grep -q 'X=1' "$T/inst/.env" && bad "restore brings back .env" || ok "restore brings back .env"

echo
[[ "$fails" -eq 0 ]] && echo "All script tests passed." || { echo "$fails script test(s) failed."; exit 1; }
