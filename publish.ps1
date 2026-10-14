# Builds a self-contained win-x64 release of ServerCloak (UI + service) into .\publish, runs the unit tests,
# optionally signs the files and builds the Inno Setup installer into .\publish-installer.
# Uses Visual Studio's MSBuild because the firewall code has a COM reference (NetFwTypeLib).
#
#   .\publish.ps1
#   .\publish.ps1 -CertThumbprint 0123ABCD...            # sign with a certificate from the store
#   .\publish.ps1 -SkipTests -SkipInstaller
param(
    [string]$Output = "$PSScriptRoot\publish",
    [string]$CertThumbprint,
    [string]$TimestampUrl = 'http://timestamp.digicert.com',
    [switch]$SkipTests,
    [switch]$SkipInstaller
)
$ErrorActionPreference = 'Stop'

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$msbuild = & $vswhere -latest -prerelease -products * -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild) { throw 'Visual Studio MSBuild was not found.' }

[xml]$props = Get-Content "$PSScriptRoot\Directory.Build.props"
$version = $props.Project.PropertyGroup.Version

if (-not $SkipTests) {
    & $msbuild "$PSScriptRoot\tests\ServerCloak.Tests\ServerCloak.Tests.csproj" -restore -v:m -nologo -p:Configuration=Release
    if ($LASTEXITCODE -ne 0) { throw 'Test build failed' }
    $testExe = Get-ChildItem "$PSScriptRoot\tests\ServerCloak.Tests\bin\Release" -Recurse -Filter ServerCloak.Tests.exe | Select-Object -First 1
    & $testExe.FullName
    if ($LASTEXITCODE -ne 0) { throw 'Unit tests failed' }
}

if (Test-Path $Output) { Remove-Item $Output -Recurse -Force }

foreach ($project in 'src\ServerCloak.Service\ServerCloak.Service.csproj', 'src\ServerCloak.App\ServerCloak.App.csproj') {
    & $msbuild "$PSScriptRoot\$project" -restore -t:Publish -v:m -nologo `
        -p:Configuration=Release -p:RuntimeIdentifier=win-x64 -p:SelfContained=true `
        -p:PublishDir="$Output\\" -p:DebugType=none
    if ($LASTEXITCODE -ne 0) { throw "Publish failed for $project" }
}
Write-Host "Published ServerCloak $version to $Output"

# Code signing (SmartScreen trusts signed files; an EV or established OV certificate avoids the warning).
$signtool = $null
if ($CertThumbprint) {
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw 'signtool.exe was not found. Install the Windows SDK.' }
    $files = Get-ChildItem $Output -Include 'ServerCloak.exe', 'ServerCloakService.exe', 'ServerCloak.*.dll', 'ServerCloakService.dll' -Recurse
    & $signtool.FullName sign /sha1 $CertThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $files.FullName
    if ($LASTEXITCODE -ne 0) { throw 'Signing failed' }
    Write-Host "Signed $($files.Count) files"
}

# Installer
if (-not $SkipInstaller) {
    $iscc = @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") |
        Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $iscc) {
        Write-Warning 'Inno Setup 6 was not found (winget install JRSoftware.InnoSetup); the installer was not built.'
    }
    else {
        $isccArgs = @("/DAppVersion=$version", "/DPublishDir=$Output")
        if ($signtool) {
            $isccArgs += '/DSign'
            $isccArgs += "/Ssigntool=`"$($signtool.FullName)`" sign /sha1 $CertThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 `$f"
        }
        & $iscc @isccArgs "$PSScriptRoot\installer\ServerCloak.iss"
        if ($LASTEXITCODE -ne 0) { throw 'Installer build failed' }
        Write-Host "Installer: $PSScriptRoot\publish-installer\ServerCloak-Setup-$version.exe"
    }
}
