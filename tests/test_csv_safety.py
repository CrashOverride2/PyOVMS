"""
CSV formula injection.

Vehicle names, notification texts and raw V2 log payloads all end up in exported CSVs, and
all of them are user-controlled. A cell beginning `=`, `+`, `-` or `@` is executed as a
formula by Excel and LibreOffice when the file is opened — by whoever asked for the export,
which in an admin export is an administrator.

app/utils/csv_safety.py exists because this was previously a private helper next to one of
three CSV writers and the other two did not use it. That is the specific failure the last
test in this file guards against.
"""

import pathlib

import pytest

from app.utils.csv_safety import sanitize_csv_cell, sanitize_csv_row

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
APP_DIR = REPO_ROOT / "app"


class TestFormulaPrefixes:
    @pytest.mark.parametrize("payload", ["=1+1", "+1", "-1", "@SUM(A1)"])
    def test_the_four_prefixes_are_neutralised(self, payload):
        result = sanitize_csv_cell(payload)
        assert result.startswith("'"), f"{payload!r} is still a formula"
        assert result == f"'{payload}", "the original value must be preserved, only prefixed"

    def test_the_classic_payload(self):
        """The DDE form — what a real exploit looks like rather than a synthetic `=1+1`."""
        payload = '=cmd|\'/c calc\'!A0'
        assert sanitize_csv_cell(payload).startswith("'")

    @pytest.mark.parametrize("leader", ["\t", "\r", "\n"])
    def test_leading_whitespace_cannot_hide_a_prefix(self, leader):
        """Excel and LibreOffice strip a leading tab or carriage return *before* deciding
        whether the cell is a formula, so a four-character check on the raw string lets
        `\\t=cmd|...` through untouched. This is the bug the module was written for."""
        payload = f"{leader}=cmd|'/c calc'!A0"
        assert sanitize_csv_cell(payload).startswith("'"), (
            f"{leader!r} before the '=' defeated the check"
        )

    @pytest.mark.parametrize("leader", ["\t", "\r", "\n"])
    def test_leading_whitespace_is_neutralised_on_its_own(self, leader):
        """Not a formula, but a leading tab survives into the cell and shifts the column
        in anything that splits on tabs."""
        assert sanitize_csv_cell(f"{leader}harmless").startswith("'")


class TestPassThrough:
    @pytest.mark.parametrize(
        "value", ["My Car", "EV1234", "", "a=b", "Model 3 (Long Range)", "1+1"]
    )
    def test_ordinary_values_are_returned_unchanged(self, value):
        """A sanitiser that quotes everything makes every exported name unreadable. `a=b`
        and `1+1` are safe: the prefix must be the *first* character."""
        assert sanitize_csv_cell(value) == value

    @pytest.mark.parametrize("value", [42, 3.14, None, True, -5])
    def test_non_strings_pass_through_untouched(self, value):
        """Including the negative number. Coercing -5 to "'-5" would change the column
        type in the output and break every spreadsheet formula over that column — and a
        number cannot start a formula in the first place."""
        assert sanitize_csv_cell(value) is value


class TestRows:
    def test_every_cell_of_a_row_is_processed(self):
        row = ["safe", "=EVIL()", 42, "\t=ALSO_EVIL()"]
        assert sanitize_csv_row(row) == ["safe", "'=EVIL()", 42, "'\t=ALSO_EVIL()"]

    def test_an_empty_row_is_handled(self):
        assert sanitize_csv_row([]) == []


def test_every_module_that_writes_csv_knows_about_the_sanitiser():
    """
    The rule this module exists to enforce.

    Deliberately a coarse check — it asserts that a module building a csv.writer also
    imports from app.utils.csv_safety, not that every individual writerow() call is
    wrapped. The failure being guarded against is a *new export endpoint written in a new
    module* by someone who did not know the rule existed; that is what happened before,
    and this catches it. Verifying each call site would need to follow values through
    local variables, and a check that subtle is one people stop trusting.
    """
    offenders = []
    for path in sorted(APP_DIR.rglob("*.py")):
        source = path.read_text()
        if "csv.writer" not in source and "csv.DictWriter" not in source:
            continue
        if "csv_safety" not in source:
            offenders.append(str(path.relative_to(REPO_ROOT)))

    assert offenders == [], (
        f"These modules write CSV without importing the sanitiser: {offenders}. Every "
        "user-controlled cell must go through sanitize_csv_row() or sanitize_csv_cell() "
        "before it reaches writerow()."
    )
