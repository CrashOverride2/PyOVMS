# Tailwind CSS

← Back to [Development](../Readme.md#tailwind-css)

The pre-built CSS (`app/static/css/main.css`) is committed to the repository. You only need to rebuild it if you modify template files or add new Tailwind classes.

**Requirements:** Node.js 18+

---

## Setup

Install the Node.js dependencies once:

```bash
npm install
```

---

## Building CSS

**During development** — watch for changes and rebuild automatically on every template save:

```bash
npm run watch
```

**Before deploying** — generate an optimized production build:

```bash
npm run build
```

The build command scans all `.html` files in `app/templates/`, collects the Tailwind classes in use, and outputs a minified CSS file to `app/static/css/main.css`.
