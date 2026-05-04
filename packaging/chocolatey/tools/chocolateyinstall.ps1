$ErrorActionPreference = 'Stop'
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$packageArgs = @{
    packageName   = 'morphkatz'
    unzipLocation = $toolsDir
    url64bit      = 'https://github.com/0xMohammedHassan/morphkatz/releases/download/v0.1.0/morphkatz-v0.1.0-win-x64.zip'
    checksum64    = '0000000000000000000000000000000000000000000000000000000000000000'
    checksumType64= 'sha256'
}

Install-ChocolateyZipPackage @packageArgs

# Expose morphkatz.exe on PATH via the standard shim mechanism.
Install-BinFile -Name 'morphkatz' -Path (Join-Path $toolsDir 'morphkatz.exe')
