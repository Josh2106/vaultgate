<#
.SYNOPSIS
  Windows equivalent of the Makefile.
.EXAMPLE
  ./scripts/tasks.ps1 install
  ./scripts/tasks.ps1 test
  ./scripts/tasks.ps1 run
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('help', 'install', 'lint', 'fmt', 'typecheck', 'test', 'cov', 'run',
                 'migrate', 'verify-audit', 'lock', 'docker-build', 'compose-up',
                 'compose-down', 'clean')]
    [string]$Task = 'help'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Bin = Join-Path $Root '.venv\Scripts'

function Invoke-Tool([string]$Exe, [string[]]$Arguments) {
    & (Join-Path $Bin "$Exe.exe") @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe exited with code $LASTEXITCODE" }
}

switch ($Task) {
    'help' {
        Get-Help $PSCommandPath -Detailed | Out-Host
        'Tasks: install lint fmt typecheck test cov run migrate verify-audit lock docker-build compose-up compose-down clean'
    }
    'install' {
        python -m venv .venv
        Invoke-Tool 'python' @('-m', 'pip', 'install', '-r', 'requirements-dev.lock')
        Invoke-Tool 'python' @('-m', 'pip', 'install', '--no-deps', '-e', '.')
        Invoke-Tool 'pre-commit' @('install')
    }
    'lint' {
        Invoke-Tool 'ruff' @('check', '.')
        Invoke-Tool 'ruff' @('format', '--check', '.')
    }
    'fmt' {
        Invoke-Tool 'ruff' @('check', '--fix', '.')
        Invoke-Tool 'ruff' @('format', '.')
    }
    'typecheck' { Invoke-Tool 'mypy' @() }
    'test' { Invoke-Tool 'pytest' @('-n', 'auto') }
    'cov' { Invoke-Tool 'pytest' @('-n', 'auto', '--cov=app', '--cov-report=term-missing', '--cov-report=html') }
    'run' {
        Invoke-Tool 'alembic' @('upgrade', 'head')
        $env:VG_LOG_JSON = 'false'
        Invoke-Tool 'uvicorn' @('app.main:app_factory', '--factory', '--reload')
    }
    'migrate' { Invoke-Tool 'alembic' @('upgrade', 'head') }
    'verify-audit' { Invoke-Tool 'vaultgate' @('verify-audit-chain') }
    'lock' {
        Invoke-Tool 'uv' @('pip', 'compile', 'pyproject.toml', '--python-version', '3.12',
            '--python-platform', 'linux', '--generate-hashes', '-o', 'requirements.lock')
        Invoke-Tool 'uv' @('pip', 'compile', 'pyproject.toml', '--extra', 'dev', '--python-version',
            '3.12', '--python-platform', 'linux', '-o', 'requirements-dev.lock')
    }
    'docker-build' { docker build -t vaultgate:local . }
    'compose-up' { docker compose up --build -d }
    'compose-down' { docker compose down -v }
    'clean' {
        '.pytest_cache', '.mypy_cache', '.ruff_cache', '.hypothesis', 'htmlcov' |
            Where-Object { Test-Path $_ } | ForEach-Object { Remove-Item -Recurse -Force $_ }
        Get-ChildItem -Filter '.coverage*' | Remove-Item -Force
    }
}
