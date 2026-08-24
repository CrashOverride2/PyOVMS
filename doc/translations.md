# Translations

← Back to [Development](../Readme.md#translations-i18n)

PyOVMS uses Babel for internationalization. Translation files live in `app/translations/<lang>/LC_MESSAGES/`.

The workflow has four steps: extract strings → update language files → translate → compile.

---

## Step 1 — Extract translatable strings

Scan all files listed in `babel.cfg` and write a `messages.pot` template. Run this whenever you add or change translatable strings in code or templates.

```bash
pybabel extract -F babel.cfg -o messages.pot .
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
pybabel update -i messages.pot -d app/translations
```

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

---

## Adding a new locale to the UI

After adding and compiling a new language, add its locale code to `SUPPORTED_LOCALES` in `.env`:

```dotenv
SUPPORTED_LOCALES="en,de,fr"
```

→ See **[Configuration](CONFIGURATION.md#internationalization)** for the full i18n settings reference.
