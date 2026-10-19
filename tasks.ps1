param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("test", "lint", "run", "dashboard", "benchmark")]
    [string]$Task
)

$ErrorActionPreference = "Stop"

switch ($Task) {
    "test" {
        .\.venv\Scripts\python.exe -m pytest -v
    }
    "lint" {
        .\.venv\Scripts\python.exe -m ruff check .
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        .\.venv\Scripts\python.exe -m ruff format --check .
    }
    "run" {
        .\.venv\Scripts\sshlog-analyzer.exe --file sample_logs/auth.log --year 2026
    }
    "dashboard" {
        .\.venv\Scripts\streamlit.exe run dashboard.py --server.address 127.0.0.1
    }
    "benchmark" {
        .\.venv\Scripts\python.exe benchmark.py
    }
}

exit $LASTEXITCODE
