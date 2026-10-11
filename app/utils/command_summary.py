"""What of a vehicle command may be written down: the verb, never the arguments,
since the audit and the server log are read by every admin."""

import re
import unicodedata
from typing import Optional

_SUMMARY_WORDS = 2
_SUMMARY_CHARS = 40
_V2_COMMAND = re.compile(r"^(\d+)(?:,(.*))?$", re.DOTALL)


def summarize_command(command: Optional[str]) -> str:
    """The first words of a command, without control characters, for the audit and the log.

    A V2 command is `<code>,<args>` with no space in it — `3,4,<new password>` sets
    a parameter — so its first "word" is the whole command. Only the code is kept
    there; `7,` (the shell) is summarized by the words of the shell command it wraps.
    """
    text = "".join(
        ch for ch in (command or "")
        if unicodedata.category(ch) not in ("Cc", "Cf", "Zl", "Zp")
    ).strip()
    v2 = _V2_COMMAND.match(text)
    if v2:
        code, rest = v2.group(1), v2.group(2)
        if code != "7":
            return code[:_SUMMARY_CHARS]
        return f"7,{summarize_command(rest)}"[:_SUMMARY_CHARS]
    words = text.split()[:_SUMMARY_WORDS]
    return " ".join(words)[:_SUMMARY_CHARS]
