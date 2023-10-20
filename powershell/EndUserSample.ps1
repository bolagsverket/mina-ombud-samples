Import-Module $PSScriptRoot/MinaOmbud.psm1

$ErrorActionPreference = 'Stop'
#$PSDefaultParameterValues['Get-MinaOmbudConfig:Debug']=$true

$Ssn = Get-MinaOmbudConfig SampleUser
$IdToken = Get-MinaOmbudSampleIdToken $Ssn
$AccessToken = Get-MinaOmbudAccessToken -Scope user:self
$Tredjeman = Get-MinaOmbudConfig SampleTredjeman
$Service = Get-MinaOmbudConfig SampleService
$BaseUrl = Get-MinaOmbudConfig ApiUrl

$Headers = @{
    "content-type" = "application/json"
    "authorization" = "Bearer $AccessToken"
    "x-id-token" = $IdToken
    "x-request-id" = "$(New-Guid)"
    "x-service-name" = $Service
}

$Body = @{
    tredjeman = $Tredjeman
    fullmaktshavare = @{ id = $Ssn; typ = "pnr" }
    fullmaktsgivarroll = @("ORGANISATION")
    page = @{ page = 0; size = 100 }
} | ConvertTo-Json

$Response = Invoke-RestMethod -Method POST "$BaseUrl/sok/behorigheter" -Headers $Headers -Body $Body
ConvertTo-PrettyJson $Response

<#
foreach ($kontext in $Response.kontext)
{
    $givare = $kontext.fullmaktsgivare
    $havare = $kontext.fullmaktshavare[0]
    $behorigheter = $kontext.behorigheter | Select-Object -ExpandProperty kod
    Write-Output "=== fullmaktsgivare=$($givare.namn), fullmaktshavare=$($havare.fornamn) $($havare.namn) ==="
    foreach ($behorighet in $kontext.behorigheter)
    {
        Write-Output "- kod=$($behorighet.kod) fullmakt=$($behorighet.fullmakt)"
    }
}
#>
