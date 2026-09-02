#!/usr/bin/env bash
#
# Re-extract, merge and compile the message catalogs.
#
# The flags are the point of this file. Run by hand with different ones and the
# resulting diff is thousands of lines of moved text with no changed message in it,
# which is unreviewable — a translation that was quietly dropped looks exactly like
# the churn around it. Three of them decide that:
#
#   --sort-output              Order entries by msgid. Without it the catalog follows
#                              source order, so moving a template rewrites the whole
#                              file. This is the flag whose absence produced a
#                              20 000-line diff containing one real change.
#   --add-location=file        Keep the filename in the '#:' comment, drop the line
#                              number. The number is stale the moment anything above
#                              it moves, and re-numbering every reference is the other
#                              half of the churn. The filename is the part a
#                              translator actually navigates by.
#   -w 88                      Fix the wrap column. The default is 76; these catalogs
#                              were written at 88, and changing it re-wraps every long
#                              message.
#
# --ignore-pot-creation-date keeps the header timestamp out of the diff when nothing
# else changed, so a no-op run is a no-op commit.
#
# Usage: scripts/update_translations.sh [--check]
#   --check   fail if the catalogs are not up to date, without writing them.

set -euo pipefail

cd "$(dirname "$0")/.."

POT="messages.pot"        # gitignored: a build artefact, not a source of truth
LOCALE_DIR="app/translations"

pybabel extract -F babel.cfg --sort-output --add-location=file -o "$POT" .

if [[ "${1:-}" == "--check" ]]; then
    pybabel update -i "$POT" -d "$LOCALE_DIR" --ignore-pot-creation-date -w 88 --check
    exit $?
fi

pybabel update -i "$POT" -d "$LOCALE_DIR" --ignore-pot-creation-date -w 88

# Compile last and always. gettext reads the .mo, never the .po, so a translation
# edited and not compiled is a translation that does not exist at runtime — and the
# .po diff in review looks complete.
pybabel compile -d "$LOCALE_DIR"

echo
echo "Catalogs updated. Fill in any empty msgstr in $LOCALE_DIR/*/LC_MESSAGES/messages.po,"
echo "then run this script again so the .mo files match."
