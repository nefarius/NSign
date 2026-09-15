#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PackageDirectory,

    [Parameter(Mandatory = $true)]
    [string] $LayoutDirectory,

    [Parameter()]
    [switch] $Repack
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$entries = @(
    'tools/net8.0/any/nsign.dll'
    'tools/net9.0/any/nsign.dll'
    'tools/net10.0/any/nsign.dll'
)

$nupkgs = @(Get-ChildItem -Path $PackageDirectory -Filter 'Nefarius.Tools.NSign.*.nupkg' |
    Where-Object { $_.Name -notlike '*.symbols.nupkg' } |
    Sort-Object LastWriteTime -Descending)
if ($nupkgs.Count -lt 1) {
    throw "Expected at least one nupkg in $PackageDirectory."
}

$nupkg = $nupkgs[0]

function Get-NupkgEntry {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Compression.ZipArchive] $Archive,

        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    $entry = $Archive.GetEntry($Name)
    if ($entry) {
        return $entry
    }

    return $Archive.GetEntry($Name.Replace('/', '\'))
}

function Get-LayoutPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name
    )

    Join-Path $LayoutDirectory ($Name -replace '/', [System.IO.Path]::DirectorySeparatorChar)
}

if (-not $Repack) {
    if (Test-Path -LiteralPath $LayoutDirectory) {
        Remove-Item -LiteralPath $LayoutDirectory -Recurse -Force
    }

    New-Item -ItemType Directory -Path $LayoutDirectory | Out-Null

    $zip = [System.IO.Compression.ZipFile]::OpenRead($nupkg.FullName)
    try {
        foreach ($name in $entries) {
            $entry = Get-NupkgEntry -Archive $zip -Name $name
            if (-not $entry) {
                throw "Package $($nupkg.Name) is missing $name"
            }

            $dest = Get-LayoutPath -Name $name
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dest, $true)
        }
    }
    finally {
        $zip.Dispose()
    }

    Write-Host "Extracted $($entries.Count) assemblies from $($nupkg.Name) to $LayoutDirectory"
    return
}

$zip = [System.IO.Compression.ZipFile]::Open($nupkg.FullName, [System.IO.Compression.ZipArchiveMode]::Update)
try {
    foreach ($name in $entries) {
        $src = Get-LayoutPath -Name $name
        if (-not (Test-Path -LiteralPath $src)) {
            throw "Signed assembly missing: $src"
        }

        $existing = Get-NupkgEntry -Archive $zip -Name $name
        if (-not $existing) {
            throw "Package $($nupkg.Name) is missing $name"
        }

        $entryName = $existing.FullName
        $existing.Delete()
        [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
            $zip,
            $src,
            $entryName,
            [System.IO.Compression.CompressionLevel]::Optimal)
    }
}
finally {
    $zip.Dispose()
}

Write-Host "Updated $($entries.Count) assemblies in $($nupkg.Name)"
