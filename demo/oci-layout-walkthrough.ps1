Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:OrasBin = if ($env:ORAS_BIN) { $env:ORAS_BIN } else { 'oras' }
$script:CosignBin = if ($env:COSIGN_BIN) { $env:COSIGN_BIN } else { 'cosign' }

if (-not $env:COSIGN_PASSWORD) {
    $env:COSIGN_PASSWORD = ''
}

$env:AI_CATALOG_ORAS_BIN = $script:OrasBin
$env:AI_CATALOG_COSIGN_BIN = $script:CosignBin

$script:TrustManifestArtifactType = 'application/vnd.ai-catalog.trust-manifest.v1+json'
$script:CosignSignatureArtifactType = 'application/vnd.ai-catalog.cosign.signature.v1'
$script:CosignPublicKeyArtifactType = 'application/vnd.ai-catalog.cosign.public-key.v1'

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

function Invoke-CheckedCommand {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$FilePath exited with status $exitCode"
    }
}

function Invoke-CapturedCommand {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    $output = & $FilePath @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $text = ($output | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) {
            $_.ToString()
        } else {
            [string]$_
        }
    }) -join [Environment]::NewLine

    if ($exitCode -ne 0) {
        if ($text) {
            throw "$FilePath $($Arguments -join ' ') exited with status $exitCode`n$text"
        }

        throw "$FilePath $($Arguments -join ' ') exited with status $exitCode"
    }

    return $text
}

function Convert-JsonDocument {
    param([string]$Payload)

    return $Payload | ConvertFrom-Json -Depth 100
}

function Get-JsonProperty {
    param(
        [object]$Object,
        [string]$Key
    )

    $property = $Object.PSObject.Properties[$Key]
    if (-not $property) {
        throw "missing property $Key"
    }

    return $property.Value
}

function Get-ReferrersFromDiscoverOutput {
    param([string]$Payload)

    $document = Convert-JsonDocument $Payload
    $referrers = Get-JsonProperty $document 'referrers'

    if ($null -eq $referrers) {
        throw 'missing referrers'
    }

    return @($referrers)
}

function Assert-DiscoveryContainsVerificationMaterial {
    param([string]$Payload)

    $artifactTypes = @(Get-ReferrersFromDiscoverOutput $Payload | ForEach-Object { $_.artifactType })
    foreach ($requiredType in @(
        $script:TrustManifestArtifactType,
        $script:CosignSignatureArtifactType,
        $script:CosignPublicKeyArtifactType
    )) {
        if ($artifactTypes -notcontains $requiredType) {
            throw "missing referrer for artifact type $requiredType"
        }
    }
}

function Get-FirstDigestInArray {
    param(
        [string]$Payload,
        [string]$ArrayKey
    )

    $document = Convert-JsonDocument $Payload
    $items = Get-JsonProperty $document $ArrayKey

    if ($null -eq $items) {
        throw "missing array $ArrayKey"
    }

    $itemList = @($items)
    if ($itemList.Count -eq 0) {
        throw "missing digest in $ArrayKey"
    }

    $digest = $itemList[0].digest
    if ([string]::IsNullOrWhiteSpace($digest)) {
        throw "missing digest in $ArrayKey"
    }

    return $digest
}

function Get-ManifestLayerDigest {
    param([string]$ManifestJson)

    return Get-FirstDigestInArray $ManifestJson 'layers'
}

function Get-ManifestAnnotation {
    param(
        [string]$ManifestJson,
        [string]$Key
    )

    $document = Convert-JsonDocument $ManifestJson
    $annotations = Get-JsonProperty $document 'annotations'
    $property = $annotations.PSObject.Properties[$Key]

    if (-not $property) {
        throw "missing annotation $Key"
    }

    return [string]$property.Value
}

function Discover-ReferrerDigestByType {
    param(
        [string]$SubjectRef,
        [string]$ArtifactType
    )

    $discoverOutput = Invoke-CapturedCommand $script:OrasBin @(
        'discover',
        '--oci-layout',
        $SubjectRef,
        '--format',
        'json'
    )

    $referrer = @(Get-ReferrersFromDiscoverOutput $discoverOutput | Where-Object {
        $_.artifactType -eq $ArtifactType
    } | Select-Object -First 1)

    if ($referrer.Count -eq 0 -or [string]::IsNullOrWhiteSpace($referrer[0].digest)) {
        throw "missing referrer for artifact type $ArtifactType"
    }

    return $referrer[0].digest
}

function Print-CosignVerificationMaterial {
    param(
        [string]$LayoutPath,
        [string]$SubjectDigest
    )

    $subjectRef = "${LayoutPath}@${SubjectDigest}"
    $signatureReferrerDigest = Discover-ReferrerDigestByType $subjectRef $script:CosignSignatureArtifactType
    $publicKeyReferrerDigest = Discover-ReferrerDigestByType $subjectRef $script:CosignPublicKeyArtifactType
    $signatureManifestRef = "${LayoutPath}@${signatureReferrerDigest}"
    $publicKeyManifestRef = "${LayoutPath}@${publicKeyReferrerDigest}"
    $signatureManifestJson = Invoke-CapturedCommand $script:OrasBin @('manifest', 'fetch', '--oci-layout', $signatureManifestRef)
    $publicKeyManifestJson = Invoke-CapturedCommand $script:OrasBin @('manifest', 'fetch', '--oci-layout', $publicKeyManifestRef)
    $signatureLayerDigest = Get-ManifestLayerDigest $signatureManifestJson
    $publicKeyLayerDigest = Get-ManifestLayerDigest $publicKeyManifestJson
    $signature = Invoke-CapturedCommand $script:OrasBin @('blob', 'fetch', '--oci-layout', '--output', '-', "${LayoutPath}@${signatureLayerDigest}")
    $publicKeyIdentity = Get-ManifestAnnotation $publicKeyManifestJson 'ai-catalog.identity'
    $publicKey = Invoke-CapturedCommand $script:OrasBin @('blob', 'fetch', '--oci-layout', '--output', '-', "${LayoutPath}@${publicKeyLayerDigest}")

    Write-Host "signature artifact digest: $signatureReferrerDigest"
    Write-Host "signature: $signature"
    Write-Host "public key artifact digest: $publicKeyReferrerDigest"
    Write-Host "public key identity: $publicKeyIdentity"
    Write-Host 'public key:'
    Write-Host $publicKey
}

function New-TemporaryDirectory {
    param([string]$Prefix)

    $path = Join-Path ([System.IO.Path]::GetTempPath()) ("$Prefix-" + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $path | Out-Null
    return $path
}

Require-Tool $script:OrasBin
Require-Tool $script:CosignBin
Require-Tool 'cargo'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$workspaceRoot = (Resolve-Path (Join-Path $scriptRoot '..')).Path
$tmpRoot = New-TemporaryDirectory 'ai-catalog-demo'
$catalogJson = Join-Path $tmpRoot 'trusted-catalog.json'
$layoutDir = Join-Path $tmpRoot 'layout'
$copiedLayoutDir = Join-Path $tmpRoot 'copied-layout'
$roundtripJson = Join-Path $tmpRoot 'roundtrip.json'
$cosignKeyPrefix = Join-Path $tmpRoot 'cosign'
$cosignKey = "$cosignKeyPrefix.key"
$cosignPub = "$cosignKeyPrefix.pub"
$targetRef = 'example.com/ai-catalog-demo:walkthrough'
$originalLocation = Get-Location

try {
    [System.IO.File]::WriteAllText($catalogJson, @'
{
  "specVersion": "1.0",
  "metadata": {
    "demo": "oci-layout-walkthrough"
  },
  "entries": [
    {
      "identifier": "urn:example:inline",
      "displayName": "Inline Entry",
      "type": "application/json",
      "data": {
        "name": "inline",
        "version": 1
      },
      "trustManifest": {
        "identity": "urn:example:inline"
      }
    }
  ]
}
'@)

    Set-Location $workspaceRoot

    Write-Step 'Validate the demo catalog'
    Invoke-CheckedCommand 'cargo' @('run', '-q', '-p', 'ai-catalog-cli', '--', 'validate', $catalogJson)

    Write-Step 'Generate a temporary Cosign key pair'
    Invoke-CheckedCommand $script:CosignBin @('generate-key-pair', '--output-key-prefix', $cosignKeyPrefix)
    Get-Item $cosignKey, $cosignPub | ForEach-Object { $_.FullName }

    Write-Step 'Export a standard OCI image layout with Cosign verification artifacts'
    Invoke-CheckedCommand 'cargo' @(
        'run', '-q', '-p', 'ai-catalog-cli', '--', 'oci', 'export-layout',
        '--tag', 'walkthrough',
        '--cosign-key', $cosignKey,
        '--cosign-public-key', $cosignPub,
        $catalogJson,
        $layoutDir
    )
    Get-ChildItem -Path $layoutDir -File -Recurse | Sort-Object FullName | ForEach-Object { $_.FullName }

    Write-Step 'Fetch the root catalog artifact with ORAS'
    Invoke-CheckedCommand $script:OrasBin @('manifest', 'fetch', '--oci-layout', "${layoutDir}:walkthrough", '--descriptor')

    $rootManifestJson = Invoke-CapturedCommand $script:OrasBin @('manifest', 'fetch', '--oci-layout', "${layoutDir}:walkthrough")
    $entryDigest = Get-FirstDigestInArray $rootManifestJson 'manifests'

    Write-Step 'Discover trust-manifest, Cosign signature, and public-key referrers for the entry'
    Write-Host "entry digest: $entryDigest"
    $discoverOutput = Invoke-CapturedCommand $script:OrasBin @('discover', '--oci-layout', "${layoutDir}@${entryDigest}", '--format', 'json')
    Write-Host $discoverOutput
    Assert-DiscoveryContainsVerificationMaterial $discoverOutput

    Write-Step 'Print the detached Cosign signature and public key identity'
    Print-CosignVerificationMaterial $layoutDir $entryDigest

    Write-Step 'Import the OCI layout back into AI Catalog JSON'
    $roundtripContent = Invoke-CapturedCommand 'cargo' @(
        'run', '-q', '-p', 'ai-catalog-cli', '--', 'oci', 'unpack-layout',
        '--ref-name', 'walkthrough',
        $layoutDir
    )
    [System.IO.File]::WriteAllText($roundtripJson, $roundtripContent)
    Write-Host ([System.IO.File]::ReadAllText($roundtripJson))
    Write-Host 'note: Cosign verification artifacts remain in the OCI layout as referrers and are not projected into AI Catalog JSON'

    Write-Step 'Validate the imported catalog'
    Invoke-CheckedCommand 'cargo' @('run', '-q', '-p', 'ai-catalog-cli', '--', 'validate', $roundtripJson)

    Write-Step 'Push the catalog into a second OCI layout with ORAS mediation and Cosign artifacts'
    Invoke-CheckedCommand 'cargo' @(
        'run', '-q', '-p', 'ai-catalog-cli', '--', 'oci', 'push',
        '--cosign-key', $cosignKey,
        '--cosign-public-key', $cosignPub,
        $catalogJson,
        $targetRef,
        '--to-oci-layout-path', $copiedLayoutDir
    )
    Invoke-CheckedCommand $script:OrasBin @('manifest', 'fetch', $targetRef, '--oci-layout-path', $copiedLayoutDir, '--descriptor')

    Write-Step 'Verify the copied layout still exposes the trust and Cosign referrers'
    $copiedDiscoverOutput = Invoke-CapturedCommand $script:OrasBin @('discover', '--oci-layout', "${copiedLayoutDir}@${entryDigest}", '--format', 'json')
    Write-Host $copiedDiscoverOutput
    Assert-DiscoveryContainsVerificationMaterial $copiedDiscoverOutput

    Write-Step 'Print the copied Cosign signature and public key identity'
    Print-CosignVerificationMaterial $copiedLayoutDir $entryDigest

    Write-Step 'Walkthrough complete'
    Write-Host "temporary demo files were created under $tmpRoot during execution"
}
finally {
    Set-Location $originalLocation

    if (Test-Path $tmpRoot) {
        Remove-Item -LiteralPath $tmpRoot -Recurse -Force
    }
}