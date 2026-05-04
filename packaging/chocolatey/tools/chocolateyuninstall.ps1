$ErrorActionPreference = 'SilentlyContinue'
$toolsDir   = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
Uninstall-BinFile -Name 'morphkatz' -Path (Join-Path $toolsDir 'morphkatz.exe')
