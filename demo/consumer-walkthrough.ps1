# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

# Consumer workflow walkthrough for ai-catalog (PowerShell).
#
# Covers the full CLI surface:
#   Author:   validate (text/json/stdin), format, trust inspect (text/json)
#   Consumer: catalog add/list/update/remove, search (text/json/regex/limit),
#             show (text/json/scoped), pull (inline-data/file-url)
#
# Runs entirely offline using file:// URLs.
# Uses AI_CATALOG_CACHE_DIR to keep all state in a temp directory so the
# walkthrough never touches the user's ~/.ai-catalog/ registry.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step {
    param([string]$Message)
    Write-Host ''
    Write-Host "== $Message =="
}

function Require-Tool {
    param([string]$Tool)
    if (-not (Get-Command $Tool -ErrorAction SilentlyContinue)) {
        throw "$Tool is required for this walkthrough"
    }
}

function Invoke-Cli {
    param([string[]]$Arguments)
    & cargo run -q -p ai-catalog-cli -- @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "ai-catalog exited with status $LASTEXITCODE"
    }
}

function Invoke-CliStdin {
    param([string[]]$Arguments, [string]$InputText)
    $InputText | & cargo run -q -p ai-catalog-cli -- @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "ai-catalog exited with status $LASTEXITCODE"
    }
}

function New-TemporaryDirectory {
    param([string]$Prefix)
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ("$Prefix-" + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $path | Out-Null
    return $path
}

Require-Tool 'cargo'

$scriptRoot     = Split-Path -Parent $MyInvocation.MyCommand.Path
$workspaceRoot  = (Resolve-Path (Join-Path $scriptRoot '..')).Path
$tmpRoot        = New-TemporaryDirectory 'ai-catalog-consumer-demo'
$env:AI_CATALOG_CACHE_DIR = Join-Path $tmpRoot 'cache'

$originalLocation = Get-Location

try {
    Set-Location $workspaceRoot

    # ── Write fixture files ────────────────────────────────────────────────────

    $evalSuitePath    = Join-Path $tmpRoot 'eval-suite-v3.jsonl'
    $nestedCatalogPath = Join-Path $tmpRoot 'datasets-catalog.json'
    $rootCatalogPath  = Join-Path $tmpRoot 'demo-catalog.json'
    $pullDir          = Join-Path $tmpRoot 'pulled'
    New-Item -ItemType Directory -Path $pullDir | Out-Null

    # A small pullable artifact (JSONL file) referenced by the nested catalog
    [System.IO.File]::WriteAllText($evalSuitePath, @'
{"prompt": "What is 2+2?", "expected": "4"}
{"prompt": "Translate 'hello' to French", "expected": "bonjour"}
{"prompt": "Summarise the A2A protocol in one sentence", "expected": "A2A enables AI agents to communicate using JSON-RPC 2.0 over HTTP."}
'@)

    # Nested catalog with two dataset entries
    $evalSuiteUrl = 'file://' + $evalSuitePath.Replace('\', '/')
    [System.IO.File]::WriteAllText($nestedCatalogPath, @"
{
  "specVersion": "1.0",
  "host": {
    "displayName": "Demo Dataset Registry"
  },
  "entries": [
    {
      "identifier": "urn:demo:dataset:training-corpus-2025",
      "displayName": "Training Corpus 2025",
      "type": "application/parquet",
      "description": "Curated instruction-following dataset for 2025 model training",
      "tags": ["dataset", "training", "instruction-following", "nlp"],
      "url": "https://example.com/datasets/training-corpus-2025.parquet"
    },
    {
      "identifier": "urn:demo:dataset:eval-suite-v3",
      "displayName": "Evaluation Suite v3",
      "type": "application/jsonl",
      "description": "Benchmark prompt/answer pairs for language model evaluation",
      "tags": ["dataset", "evaluation", "benchmark", "nlp"],
      "url": "$evalSuiteUrl"
    }
  ]
}
"@)

    # Root catalog with three leaf entries and a nested catalog reference
    $nestedCatalogUrl = 'file://' + $nestedCatalogPath.Replace('\', '/')
    [System.IO.File]::WriteAllText($rootCatalogPath, @"
{
  "specVersion": "1.0",
  "host": {
    "displayName": "Demo AI Registry",
    "identifier": "did:example:demo-registry",
    "documentationUrl": "https://docs.example.com/ai-registry"
  },
  "entries": [
    {
      "identifier": "urn:demo:agent:conversational-v1",
      "displayName": "Conversational Agent v1",
      "type": "application/a2a-agent-card+json",
      "description": "A general-purpose conversational AI agent implementing the A2A protocol",
      "tags": ["agent", "chat", "nlp", "a2a"],
      "url": "https://example.com/agents/conversational-v1.json",
      "version": "1.0.0",
      "trustManifest": {
        "identity": "urn:demo:agent:conversational-v1",
        "identityType": "urn"
      }
    },
    {
      "identifier": "urn:demo:model:embeddings-v2",
      "displayName": "Embeddings Model v2",
      "type": "application/gguf",
      "description": "Lightweight 128-dimensional text embedding model",
      "tags": ["model", "embeddings", "nlp"],
      "url": "https://example.com/models/embeddings-v2.gguf",
      "version": "2.0.0"
    },
    {
      "identifier": "urn:demo:config:default-settings",
      "displayName": "Default Agent Settings",
      "type": "application/json",
      "description": "Shared default configuration for all demo agents",
      "tags": ["config", "settings"],
      "data": {
        "timeout_ms": 30000,
        "max_retries": 3,
        "log_level": "info",
        "supported_protocols": ["a2a", "rest"]
      }
    },
    {
      "identifier": "urn:demo:catalog:datasets",
      "displayName": "Demo Dataset Catalog",
      "type": "application/ai-catalog+json",
      "description": "Nested catalog of training and evaluation datasets",
      "url": "$nestedCatalogUrl"
    }
  ]
}
"@)

    # ── Author commands ────────────────────────────────────────────────────────

    Write-Step '1. Validate the catalog (text output)'
    Invoke-Cli @('validate', $rootCatalogPath)

    Write-Step '2. Validate the catalog (JSON output)'
    Invoke-Cli @('validate', '--json', $rootCatalogPath)

    Write-Step '3. Validate from stdin'
    $catalogContent = [System.IO.File]::ReadAllText($rootCatalogPath)
    Invoke-CliStdin @('validate', '--json', '-') $catalogContent

    Write-Step '4. Format / pretty-print the catalog'
    Invoke-Cli @('format', $rootCatalogPath)

    Write-Step '5. Inspect trust manifests (text output)'
    Invoke-Cli @('trust', 'inspect', $rootCatalogPath)

    Write-Step '6. Inspect trust manifests (JSON output)'
    Invoke-Cli @('trust', 'inspect', '--json', $rootCatalogPath)

    # ── Consumer commands: catalog management ──────────────────────────────────

    Write-Step '7. Register the catalog (fetches and caches locally)'
    $rootCatalogUrl = 'file://' + $rootCatalogPath.Replace('\', '/')
    Invoke-Cli @('catalog', 'add', 'demo-registry', $rootCatalogUrl)

    Write-Step '8. List registered catalogs (text)'
    Invoke-Cli @('catalog', 'list')

    Write-Step '9. List registered catalogs (JSON)'
    Invoke-Cli @('catalog', 'list', '--json')

    # ── Consumer commands: search ──────────────────────────────────────────────

    Write-Step "10. Search by keyword: 'agent' (text table)"
    Invoke-Cli @('search', 'agent')

    Write-Step "11. Search by keyword: 'dataset' (JSON output)"
    Invoke-Cli @('search', '--json', 'dataset')

    Write-Step '12. Search with regex: A2A agents and datasets'
    Invoke-Cli @('search', '--regex', 'urn:demo:(agent|dataset).*')

    Write-Step '13. Search with result limit (-n 2)'
    Invoke-Cli @('search', '-n', '2', 'nlp')

    # ── Consumer commands: show ────────────────────────────────────────────────

    Write-Step '14. Show entry details (text table): conversational agent'
    Invoke-Cli @('show', 'urn:demo:agent:conversational-v1')

    Write-Step '15. Show entry details (JSON): conversational agent'
    Invoke-Cli @('show', '--json', 'urn:demo:agent:conversational-v1')

    Write-Step '16. Show entry scoped to a specific registered catalog'
    Invoke-Cli @('show', '--scope', 'demo-registry', 'urn:demo:dataset:eval-suite-v3')

    # ── Consumer commands: pull ────────────────────────────────────────────────

    Write-Step '17. Pull inline-data entry (config) to disk'
    Invoke-Cli @('pull', '--output', $pullDir, 'urn:demo:config:default-settings')
    $pulledConfig = Join-Path $pullDir 'default-settings.json'
    Write-Host 'pulled file:'
    Write-Host ([System.IO.File]::ReadAllText($pulledConfig))

    Write-Step '18. Pull file-URL entry (eval suite JSONL) to disk'
    Invoke-Cli @('pull', '--output', $pullDir, 'urn:demo:dataset:eval-suite-v3')
    $pulledEval = Join-Path $pullDir 'eval-suite-v3.json'
    Write-Host 'pulled file:'
    Write-Host ([System.IO.File]::ReadAllText($pulledEval))

    # ── Consumer commands: update and remove ───────────────────────────────────

    Write-Step "19. Update the catalog (content unchanged — reports 'up to date')"
    Invoke-Cli @('catalog', 'update', 'demo-registry')

    Write-Step '20. Remove the catalog from the local registry'
    Invoke-Cli @('catalog', 'remove', 'demo-registry')

    Write-Step '21. List catalogs after removal'
    Invoke-Cli @('catalog', 'list')

    Write-Step 'Consumer walkthrough complete'
    Write-Host "all temporary files were cleaned up from $tmpRoot"
}
finally {
    Set-Location $originalLocation
    if (Test-Path $tmpRoot) {
        Remove-Item -LiteralPath $tmpRoot -Recurse -Force
    }
}
