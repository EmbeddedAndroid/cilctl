#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# scrub.sh [dir...]: fail if a file in the given trees (default: this
# repository), or the history, authors and commit messages of a tree that
# is a git work tree, holds a private address, an internal host name, a
# key or a credential. Runs in CI and before every push. Prints each hit.
#
# Site-specific names go in an untracked file, one extended regex per
# line ($SCRUB_EXTRA, default tools/scrub-extra.txt); a line starting with
# "allow:" is a regex for text that is fine even though a pattern matches.
set -u
top=$(cd "$(dirname "$0")/.." && pwd)
[ $# -gt 0 ] || set -- "$top"
pat='\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b|\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b'
pat=$pat'|\b172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b|\b100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}\b'
pat=$pat'|[a-z0-9-]\.(internal|corp|intranet|lan)\b|BEGIN [A-Z ]*PRIVATE KEY'
pat=$pat'|(password|passwd|token|secret|api_key)=|/home/[a-z]+/|/Users/[a-z]+/|[A-Z]:\\Users\\'
pat=$pat'|\blease[ #_-]*[0-9]{2,}'
allow='^$'
extra=${SCRUB_EXTRA:-$top/tools/scrub-extra.txt}
if [ -r "$extra" ]; then
	p=$(grep -v '^#' "$extra" | grep -v '^allow:' | grep . | paste -sd'|' -)
	a=$(sed -n 's/^allow://p' "$extra" | grep . | paste -sd'|' -)
	[ -z "$p" ] || pat="$pat|$p"
	[ -z "$a" ] || allow=$a
fi
pat="($pat)"
# drop allowed text from each line, then look again
check() { sed -E "s/$allow/<allowed>/gI" | grep -iE "$pat"; }
rc=0
for d in "$@"; do
	[ -e "$d" ] || { echo "scrub: no such path: $d"; rc=1; continue; }
	if [ -d "$d" ]; then
		# relative to the tree, so the tree's own path never matches
		hits=$(cd "$d" && grep -rniIE "$pat" --exclude-dir=.git --exclude=.git --exclude=scrub.sh --exclude=scrub-extra.txt -- . |
			check | sed "s|^\./|$d/|" || true)
	else
		hits=$(grep -niIE "$pat" -- "$d" | check || true)
	fi
	if [ -d "$d" ] && git -C "$d" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
		# messages and authors of every commit, diffs of all but this file
		hist=$({ git -C "$d" log --all --format='commit %H%nauthor %an <%ae>%ncommitter %cn <%ce>%n%B'
			git -C "$d" log --all -p --format='commit %H' -- . ':!tools/scrub.sh'; } 2>/dev/null |
			check | sed 's/^/history:/' || true)
		[ -z "$hist" ] || hits=$(printf '%s\n%s' "$hits" "$hist")
	fi
	if [ -n "$(printf "%s" "$hits" | tr -d '[:space:]')" ]; then
		printf "%s\n" "$hits" | sed '/^$/d'
		rc=1
	fi
	nb=$(find "$d" -type f -not -path '*/.git/*' -not -name .git | while read -r f; do grep -qI . "$f" 2>/dev/null || echo "$f"; done | wc -l)
	[ "$nb" -eq 0 ] || echo "scrub: $d: $nb binary or empty files not scanned"
done
if [ $rc -ne 0 ]; then
	echo "scrub: FAIL"
	exit 1
fi
echo "scrub: clean ($(for d in "$@"; do find "$d" -type f -not -path '*/.git/*' -not -name .git; done | wc -l | tr -d ' ') files)"
