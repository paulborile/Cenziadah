#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Paul Borile
#
# Publish the committed gitlab tree to the public GitHub repo, in two steps.
# The git commit/tag/push in between is done by hand.
#
#   release-production.sh prepare          (make production)
#       checks, tests, builds the packages, syncs the COMMITTED tree (minus
#       packaging/production-exclude) into the GitHub clone, writes the release
#       notes and checksums, and prints the git commands to run. It changes no
#       git state anywhere. DRY_RUN=1 only shows what the sync would change.
#   release-production.sh github-release   (make github-release)
#       after the tag is pushed: creates the GitHub release with the .deb, .rpm
#       and checksums attached.
#
# PROD_REPO is the GitHub clone (default ../../git/Cenziadah).
set -euo pipefail

SRC=$(cd "$(dirname "$0")/.." && pwd)
DEST=${PROD_REPO:-$SRC/../../git/Cenziadah}
DRY_RUN=${DRY_RUN:-0}

VERSION=$(sed -n 's/^const Version = "v\(.*\)"/\1/p' "$SRC/internal/version/version.go")
TAG=v$VERSION
DEB=$SRC/dist/cenziadah_${VERSION}-1_amd64.deb
RPM=$SRC/dist/cenziadah-${VERSION}-1.x86_64.rpm
NOTES=$SRC/dist/release-notes-$TAG.md
SUMS=$SRC/dist/SHA256SUMS-$TAG

die() { echo "production: $*" >&2; exit 1; }

[ -n "$VERSION" ] || die "cannot read the version from internal/version/version.go"
[ -d "$DEST/.git" ] || die "$DEST is not a git clone (set PROD_REPO)"
DEST=$(cd "$DEST" && pwd)

# owner/repo of the clone's GitHub origin
github_repo() {
    git -C "$DEST" remote get-url origin |
        sed -E 's#^(git@github\.com:|https://github\.com/)##; s#\.git$##'
}

prepare() {
    # The release is exactly the committed tree: refuse uncommitted changes so
    # what is published is what gitlab has (untracked files are never copied).
    if ! git -C "$SRC" diff --quiet || ! git -C "$SRC" diff --cached --quiet; then
        [ "$DRY_RUN" = 1 ] || die "uncommitted changes in $SRC: commit them first (only committed files are released)"
        echo "production: warning: uncommitted changes are NOT part of the release (dry run)"
    fi
    grep -q "^## \[$TAG\]" "$SRC/CHANGELOG.md" || die "CHANGELOG.md has no '## [$TAG]' section"
    if git -C "$DEST" rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
        die "tag $TAG already exists in $DEST: bump the version first"
    fi
    if [ -n "$(git -C "$DEST" status --porcelain)" ]; then
        [ "$DRY_RUN" = 1 ] || die "$DEST has uncommitted changes: commit or discard them first"
    fi

    echo "production: $TAG from $(git -C "$SRC" rev-parse --short HEAD) -> $DEST ($(github_repo))"
    make -C "$SRC" all packages
    [ -f "$DEB" ] && [ -f "$RPM" ] || die "packages missing: $DEB $RPM"

    stage=$(mktemp -d)
    excl=$(mktemp)
    trap 'rm -rf "$stage" "$excl"' EXIT
    git -C "$SRC" archive HEAD | tar -x -C "$stage"
    grep -vE '^[[:space:]]*(#|$)' "$SRC/packaging/production-exclude" >"$excl"
    rsync_opts=(-a --delete --exclude=/.git/ --exclude-from="$excl")
    if [ "$DRY_RUN" = 1 ]; then
        echo "production: dry run, changes the sync would make in $DEST:"
        rsync "${rsync_opts[@]}" --dry-run --itemize-changes "$stage/" "$DEST/"
        return
    fi
    rsync "${rsync_opts[@]}" "$stage/" "$DEST/"

    # release notes: this version's CHANGELOG section
    awk -v tag="$TAG" '
        $0 ~ "^## \\[" tag "\\]" { on = 1; next }
        on && /^## \[/ { exit }
        on { print }' "$SRC/CHANGELOG.md" >"$NOTES"
    (cd "$SRC/dist" && sha256sum "$(basename "$DEB")" "$(basename "$RPM")") >"$SUMS"

    cat <<EOF

production: $DEST now holds $TAG. Review, then commit, tag and push:
  cd $DEST
  git status
  git add -A && git commit -m "cenziadah $TAG"
  git tag -a $TAG -m "cenziadah $TAG"
  git push origin HEAD $TAG
and publish the GitHub release (.deb, .rpm, checksums, notes from CHANGELOG):
  make github-release
EOF
}

github_release() {
    repo=$(github_repo)
    for f in "$DEB" "$RPM" "$NOTES" "$SUMS"; do
        [ -f "$f" ] || die "$f missing: run make production first"
    done
    git -C "$DEST" ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null ||
        die "tag $TAG is not on GitHub yet: push it first (git push origin $TAG)"
    if gh release view "$TAG" --repo "$repo" >/dev/null 2>&1; then
        die "release $TAG already exists on $repo"
    fi
    gh release create "$TAG" "$DEB" "$RPM" "$SUMS" \
        --repo "$repo" --verify-tag --title "cenziadah $TAG" --notes-file "$NOTES"
}

case "${1:-}" in
prepare) prepare ;;
github-release) github_release ;;
*) die "usage: $0 prepare|github-release" ;;
esac
