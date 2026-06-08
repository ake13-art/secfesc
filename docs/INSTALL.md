<div align="center">

```
   ________  _____/ __/__  __________
  / ___/ _ \/ ___/ /_/ _ \/ ___/ ___/
 (__  )  __/ /__/ __/  __(__  ) /__
/____/\___/\___/_/  \___/____/\___/
```

[← README](../README.md) · [Usage](USAGE.md) · [Configuration](CONFIG.md) · [Architecture](ARCHITECTURE.md)

# Installation

![Python](https://img.shields.io/badge/python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white&labelColor=0d1117)
![Platform](https://img.shields.io/badge/platform-Linux-FCC624?style=flat-square&logo=linux&logoColor=white&labelColor=0d1117)

*Requirements: Python 3.8+, Linux*

</div>

---

## pipx (Recommended)

Installs secfesc in its own isolated environment — no conflicts with system packages.

```bash
pipx install secfesc
```

Upgrade later:

```bash
pipx upgrade secfesc
```

---

## pip

```bash
pip install secfesc
```

Or inside a virtual environment:

```bash
python -m venv .venv && source .venv/bin/activate
pip install secfesc
```

---

## From source

```bash
git clone https://github.com/ake13-art/secfesc.git
cd secfesc
pipx install -e .
```

Run tests without installing:

```bash
uv run pytest
```

---

## Verify

```bash
secfetch help
secscan --version
```

---

## Startup integration

Show your security status every time you open a terminal — like fastfetch, but for security.

**1. Add to your shell RC file**

```bash
# ~/.bashrc  or  ~/.zshrc
secfetch --short
```

**2. Choose your logo** in `~/.config/secfesc/checks.conf`:

```ini
[display]
logo = arch        # arch | debian | ubuntu | fedora | secfesc | none
```

The first run creates the config file automatically.

> [!TIP]
> If `secfetch --short` is slow to start, switch to `secfetch fastscan --short`. Edit `~/.config/secfesc/checks.conf` to enable only the checks you care about — startup will be instant.

---

## Uninstall

```bash
pipx uninstall secfesc
# or:
pip uninstall secfesc
```

---

<div align="center">

[← README](../README.md) · [Usage](USAGE.md) · [Configuration](CONFIG.md) · [Architecture](ARCHITECTURE.md)

</div>
