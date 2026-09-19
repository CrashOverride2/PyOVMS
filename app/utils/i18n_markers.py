"""
gettext_noop — mark a string for extraction without translating it here.

Some user-facing strings are written where no request locale exists: a pydantic
validator's message, the detail of an HTTPException that an API caller receives as
English JSON and a UI route later shows on a translated page. The string is only
*marked* here so pybabel extracts it (`N_` is one of pybabel's default keywords),
and whoever displays it translates at that point — `_(str(e.detail))` on a redirect,
`_(error_detail)` in `error.html`, `format_validation_error()` for pydantic errors.

No imports on purpose: it is used from `app/models/api.py`, which everything imports.
"""


def N_(message: str) -> str:
    return message
