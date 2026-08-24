"""
One definition of what a CSV cell may start with.

Spreadsheet applications treat a cell whose first character is `=`, `+`, `-` or `@`
as a formula, and Excel and LibreOffice additionally strip a leading tab or carriage
return before making that decision — so `\t=cmd|'/c calc'!A0` is a formula the
original four-character check let through untouched. The exported data is vehicle
names, notification texts and log payloads, all of which a user controls, and the
file is opened by whoever asked for the export.

This lives in its own module because it was previously a private helper next to one
of the three CSV writers in the tree, and the other two did not use it. A rule that
has to be remembered at each writer is a rule that will be missed at the next one.
"""
from typing import Any

# Characters that make a spreadsheet read the cell as a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@")

# Whitespace that is discarded before the formula check, so it cannot be used to hide
# one of the prefixes above.
_STRIPPED_LEADERS = ("\t", "\r", "\n")


def sanitize_csv_cell(value: Any) -> Any:
    """
    Return `value` safe to write into a CSV cell.

    Non-strings pass through: a number cannot start a formula, and coercing them
    would change the column type in the output.
    """
    if not isinstance(value, str):
        return value

    if value.lstrip("".join(_STRIPPED_LEADERS)).startswith(_FORMULA_PREFIXES):
        return f"'{value}"

    # A leading tab or CR is worth neutralising on its own: it survives into the cell
    # and shifts the column in tools that split on tabs.
    if value.startswith(_STRIPPED_LEADERS):
        return f"'{value}"

    return value


def sanitize_csv_row(row: list) -> list:
    """Apply sanitize_csv_cell() to every cell of a row."""
    return [sanitize_csv_cell(cell) for cell in row]
