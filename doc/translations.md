# Translations

← Back to [Development](../Readme.md#translations-i18n)

PyOVMS uses Babel for internationalization. Translation files live in `app/translations/<lang>/LC_MESSAGES/`.

The workflow has four steps: extract strings → update language files → translate → compile.

## The short version

```bash
scripts/update_translations.sh        # steps 1, 2 and 4
# ...fill in the empty msgstr entries...
scripts/update_translations.sh        # recompile
```

`scripts/update_translations.sh --check` reports whether the catalogs are current
without writing anything.

**Use the script rather than the raw commands below.** It pins three flags that the
bare `pybabel` invocations do not:

| Flag | Why |
| --- | --- |
| `--sort-output` | Orders entries by msgid. Without it the catalog follows source order, so moving one template rewrites the whole file — this is what once produced a 20 000-line diff containing a single real change. |
| `--add-location=file` | Keeps the filename in the `#:` comment and drops the line number, which goes stale the moment anything above it moves. |
| `-w 88` | Fixes the wrap column. The default is 76; these catalogs are written at 88, and changing it re-wraps every long message. |

The reason this matters is reviewability: when a diff is thousands of lines of moved
text, a translation that was quietly lost looks exactly like the churn around it.

The steps below are what the script runs, for when you need to do something it does not
cover (adding a language, in particular).

---

## Step 1 — Extract translatable strings

Scan all files listed in `babel.cfg` and write a `messages.pot` template. Run this whenever you add or change translatable strings in code or templates.

```bash
pybabel extract -F babel.cfg --sort-output --add-location=file -o messages.pot .
```

---

## Step 2 — Create or update language files

### Adding a new language

Run `init` only the first time for a language. This creates `app/translations/<lang>/LC_MESSAGES/messages.po`.

```bash
pybabel init -i messages.pot -d app/translations -l de
```

> ⚠️ Do not run `init` again for a language that already has a `.po` file — it overwrites existing translations. Use `update` instead.

### Updating an existing language

Merge new strings from `messages.pot` into the existing `.po` file, preserving all current translations:

```bash
pybabel update -i messages.pot -d app/translations --ignore-pot-creation-date -w 88
```

`--ignore-pot-creation-date` keeps the header timestamp out of the diff when nothing
else changed, so a run that finds no new strings produces no commit.

---

## Step 3 — Translate

Open the relevant `.po` file (e.g. `app/translations/de/LC_MESSAGES/messages.po`) and fill in the `msgstr` for each untranslated string:

```po
msgid "Login"
msgstr "Anmelden"

msgid "Your username"
msgstr "Ihr Benutzername"
```

---

## Step 4 — Compile

Convert the human-readable `.po` file into the binary `.mo` file that the server loads:

```bash
pybabel compile -d app/translations
```

Restart the server after compiling for the changes to take effect.

Never skip this step. gettext reads the `.mo` and never the `.po`, so a translation
edited and not compiled does not exist at runtime — while the `.po` diff in review looks
complete.

---

## Adding a new locale to the UI

After adding and compiling a new language, add its locale code to `SUPPORTED_LOCALES` in `.env`:

```dotenv
SUPPORTED_LOCALES="en,de,fr"
```

→ See **[Configuration](CONFIGURATION.md#internationalization)** for the full i18n settings reference.
