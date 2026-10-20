# Development

## Local setup

Use Python 3.11 or newer and install the pinned development dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Run tests and static checks from the repository root:

```powershell
python -m pytest -v
python -m ruff check .
python -m ruff format --check .
python -m pip check
```

The optional synthetic fixture evaluation is `python tools/evaluate_synthetic.py`.
The existing 100,000-line benchmark is `python benchmark.py`; its wall time
depends on the machine and should be measured rather than copied from an older
run. To launch the local dashboard, use
`streamlit run dashboard.py --server.address 127.0.0.1`.

Keep real logs and secrets outside the repository. Use documentation-range IPs
in synthetic fixtures and update expected outputs only with an explained,
reviewed behavior change. See [CONTRIBUTING.md](CONTRIBUTING.md) for the rule
addition walkthrough.
