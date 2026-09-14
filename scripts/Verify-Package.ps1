#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PackageDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$nupkgs = @(Get-ChildItem -Path $PackageDirectory -Filter 'Nefarius.Tools.NSign.*.nupkg' |
    Where-Object { $_.Name -notlike '*.symbols.nupkg' } |
    Sort-Object LastWriteTime -Descending)
if ($nupkgs.Count -lt 1) {
    throw "Expected at least one nupkg in $PackageDirectory."
}

$snupkgs = @(Get-ChildItem -Path $PackageDirectory -Filter 'Nefarius.Tools.NSign.*.snupkg' |
    Sort-Object LastWriteTime -Descending)
if ($snupkgs.Count -lt 1) {
    throw "Expected at least one snupkg in $PackageDirectory."
}

$nupkg = $nupkgs[0]
$extract = Join-Path ([System.IO.Path]::GetTempPath()) ("nsign-nupkg-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $extract | Out-Null
try {
    $zip = Join-Path $extract 'package.zip'
    Copy-Item -LiteralPath $nupkg.FullName -Destination $zip
    Expand-Archive -Path $zip -DestinationPath $extract -Force
    Remove-Item -LiteralPath $zip

    foreach ($required in @('README.md', 'THIRD-PARTY-NOTICES.md', 'NSS-128x128.png')) {
        $path = Join-Path $extract $required
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Package is missing $required"
        }
    }

    $nuspec = Get-ChildItem -Path $extract -Filter '*.nuspec' | Select-Object -First 1
    if (-not $nuspec) {
        throw 'Package is missing a nuspec file.'
    }

    [xml] $manifest = Get-Content -LiteralPath $nuspec.FullName
    $ns = New-Object System.Xml.XmlNamespaceManager($manifest.NameTable)
    $ns.AddNamespace('n', $manifest.DocumentElement.NamespaceURI)

    $readme = $manifest.SelectSingleNode('/n:package/n:metadata/n:readme', $ns)?.InnerText
    if ($readme -ne 'README.md') {
        throw "nuspec readme was '$readme', expected README.md"
    }

    $icon = $manifest.SelectSingleNode('/n:package/n:metadata/n:icon', $ns)?.InnerText
    if ($icon -ne 'NSS-128x128.png') {
        throw "nuspec icon was '$icon', expected NSS-128x128.png"
    }

    $repo = $manifest.SelectSingleNode('/n:package/n:metadata/n:repository', $ns)
    if (-not $repo) {
        throw 'nuspec is missing repository metadata.'
    }

    $repoUrl = $repo.GetAttribute('url')
    if ($repoUrl -notlike 'https://github.com/nefarius/NSign*') {
        throw "Unexpected repository url: $repoUrl"
    }

    foreach ($tfm in @('net8.0', 'net9.0', 'net10.0')) {
        $toolDir = Join-Path $extract "tools/$tfm/any"
        if (-not (Test-Path -LiteralPath (Join-Path $toolDir 'nsign.dll'))) {
            throw "Package is missing tools/$tfm/any/nsign.dll"
        }
    }

    Write-Host "Verified $($nupkg.Name) and $($snupkgs[0].Name)"
}
finally {
    Remove-Item -LiteralPath $extract -Recurse -Force -ErrorAction SilentlyContinue
}
