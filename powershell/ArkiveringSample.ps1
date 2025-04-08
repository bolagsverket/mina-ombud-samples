Import-Module $PSScriptRoot/MinaOmbud.psm1

$ErrorActionPreference = 'Stop'
#$PSDefaultParameterValues['Get-MinaOmbudConfig:Debug']=$true

$AccessToken = Get-MinaOmbudAccessToken -Scope fullmakt:arkivering
$Tredjeman = Get-MinaOmbudConfig SampleTredjeman
$BaseUrl = Get-MinaOmbudConfig ApiUrl

$Headers = @{
    "content-type" = "application/json"
    "authorization" = "Bearer $AccessToken"
    "x-request-id" = "$(New-Guid)"
    "x-service-name" = "ArkiveringSample.ps1"
}

$Response = Invoke-RestMethod "$BaseUrl/tredjeman/$Tredjeman/arkivering/paket" -Headers $Headers
ConvertTo-PrettyJson $Response

$OutputDir = "archive"
New-Item $OutputDir -ItemType Directory -Force | Out-Null
foreach ($Pkg in $Response.paket)
{
    $Id = $Pkg.id
    $ZipDir = Join-Path $OutputDir $Pkg.namn
    New-Item $ZipDir -ItemType Directory -Force
    $ZipPath = Join-Path $ZipDir "$Id.zip"
    $ZipResponse = Invoke-WebRequest "$BaseUrl/tredjeman/$Tredjeman/arkivering/paket/$Id" -Headers $Headers
    [io.file]::WriteAllBytes($ZipPath, $ZipResponse.Content)
    Expand-Archive $ZipPath -DestinationPath $ZipDir -Force

    #Invoke-RestMethod -Method DELETE "$BaseUrl/tredjeman/$Tredjeman/arkivering/paket/$Id" -Headers $Headers
}
