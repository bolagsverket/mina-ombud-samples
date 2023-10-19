$ErrorActionPreference = 'Stop'
#$DebugPreference = 'Continue'
$TokenCache = @{}

function GetEnv($Name, $Default)
{
    if (Test-Path "env:$Name") { (Get-Item "env:$Name").Value } else { $Default }
}

function Get-MinaOmbudConfig()
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'ClientId',
            'ClientSecret',
            'TokenUrl',
            'ApiUrl',
            'SampleService',
            'SampleIssuer',
            'SampleData',
            'SampleUser',
            'SampleTredjeman'
        )]
        [string]$Name
    )

    $val = Switch ($Name)
    {
        'ClientId' { GetEnv MINA_OMBUD_API_CLIENT_ID 'mina-ombud-sample' }
        'ClientSecret' { GetEnv MINA_OMBUD_API_CLIENT_SECRET '3392d044-d0f2-491d-a40d-edda4f1361c0' }
        'TokenUrl' { GetEnv MINA_OMBUD_API_TOKEN_URL 'https://auth-accept.minaombud.se/auth/realms/dfm-accept2/protocol/openid-connect/token' }
        'ApiUrl' { GetEnv MINA_OMBUD_API_URL 'https://fullmakt-test.minaombud.se/dfm/formedlare/v2' }
        'SampleService' { GetEnv MINA_OMBUD_SAMPLE_SERVICE 'mina-ombud-sample' }
        'SampleIssuer' { GetEnv MINA_OMBUD_SAMPLE_ISSUER 'http://localhost' }
        'SampleTredjeman' { GetEnv MINA_OMBUD_TREDJE_MAN '2120000829' }
        'SampleUser' { GetEnv MINA_OMBUD_USER_PNR '198602262381' }
        'SampleData' {
            if (Test-Path env:MINA_OMBUD_SAMPLE_DATA) {
                return $env:MINA_OMBUD_SAMPLE_DATA
            }

            Join-Path -Resolve $PSScriptRoot ../data
        }
        default {
            Write-Error "Invalid config: $Name"
        }
    }

    Write-Debug "Config $Name=$val"
    $val
}

function Get-MinaOmbudSampleIdToken {
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName="Claims", Position=0)]
        $Claims
    )

    if (-not $Claims)
    {
        $Claims = Get-MinaOmbudConfig SampleUser
    }

    $AuthUrl = GetEnv MINA_OMBUD_SAMPLE_AUTH_URL 'https://fullmakt-test.minaombud.se/sample'
    $ContentType = "application/json"
    if ($Claims -is [string])
    {
        $Body = $Claims
        if (-not $Body.StartsWith("{"))
        {
            $ContentType = "text/plain"
        }
    }
    else
    {
        $Body = ConvertTo-Json -Depth 100 $Claims
    }
    $Response = Invoke-WebRequest -Method POST -Uri "$AuthUrl/user" `
        -ContentType $ContentType -Body $Body
    $Token = $Response.Content
    if (-not ($Token -is [string]))
    {
        $Token = [Text.Encoding]::UTF8.GetString($Token)
    }
    $Token
}

Export-ModuleMember Get-MinaOmbudConfig, Get-MinaOmbudSampleIdToken

function Clear-MinaOmbudAccessTokens {
    $TokenCache.Clear()
}

function Get-MinaOmbudAccessToken
{
    [CmdletBinding(PositionalBinding=$false)]
    param(
        [PSCredential]$ClientCredentials,
        [string]$ClientId,
        [object]$ClientSecret,

        [Parameter(Mandatory)]
        [string]$Scope,

        [Parameter()]
        [string]$TokenUrl
    )

    if (-not $TokenUrl)
    {
        $TokenUrl = Get-MinaOmbudConfig TokenUrl
    }

    if ($ClientCredentials)
    {
        $ClientId = $ClientCredentials.UserName
    }
    elseif (-not $ClientId)
    {
        $ClientId = Get-MinaOmbudConfig ClientId
    }

    $CacheKey = $ClientId + $Scope + $TokenUrl
    $CacheValue = $TokenCache[$CacheKey]
    $Now = Get-Date
    if ($CacheValue -and ($Now -lt $CacheValue.ExpiresAt))
    {
        $AccessToken = $CacheValue.AccessToken
        Write-Debug "Reusing token: ExpiresAt=$(Get-Date $CacheValue.ExpiresAt -UFormat '%Y-%m-%d %H:%M:%S') Scope=$Scope ClientId=$($ClientId)"
        return $AccessToken
    }

    if (-not $ClientCredentials)
    {
        if (-not $ClientSecret)
        {
            $ClientSecret = Get-MinaOmbudConfig ClientSecret
        }

        if ($ClientSecret -is [string])
        {
            $ClientSecret = ConvertTo-SecureString -AsPlainText -Force $ClientSecret
        }

        $ClientCredentials = New-Object System.Management.Automation.PsCredential($ClientId, $ClientSecret)
    }

    Write-Debug "Requesting new token: ClientId=$ClientId Scope=$Scope TokenUrl=$TokenUrl"

    if ($PSVersionTable.PSVersion.Major -ge 6)
    {
        $TokenResponse = Invoke-RestMethod `
            -Credential $ClientCredentials -Authentication Basic `
            -Method POST -Uri $TokenUrl -ContentType "application/x-www-form-urlencoded" `
            -Body @{grant_type="client_credentials"; scope=$Scope}
    }
    else
    {
        # Hack since PS < 6 Invoke-RestMethod doesn't support -Authentication and
        # doesn't send the credentials unless the remote server sends an authentication challenge.
        $ClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret))
        $TokenResponse = Invoke-RestMethod `
            -Method POST -Uri $TokenUrl -ContentType "application/x-www-form-urlencoded" `
            -Body @{grant_type="client_credentials"; client_id=$ClientId; client_secret=$ClientSecret; scope=$Scope}
    }

    $AccessToken = $TokenResponse.access_token
    $ExpiresAt = $Now.AddSeconds($TokenResponse.expires_in)
    $TokenCache[$CacheKey] = [pscustomobject]@{
        AccessToken = $AccessToken;
        ExpiresAt = $ExpiresAt;
    }

    Write-Debug "Access token: $AccessToken"
    Write-Debug "Expires at: $(Get-Date $ExpiresAt -UFormat '%Y-%m-%d %H:%M:%S')"

    return $AccessToken
}

function Format-Json([Parameter(Mandatory)][string] $json) {
  # https://github.com/PowerShell/PowerShell/issues/2736
  $indent = 0;
  ($json -Split '\n' |
    ForEach-Object {
      if ($_ -match '[\}\]]') {
        # This line contains  ] or }, decrement the indentation level
        $indent--
      }
      $line = (' ' * $indent * 2) + $_.TrimStart().Replace(':  ', ': ')
      if ($_ -match '[\{\[]') {
        # This line contains [ or {, increment the indentation level
        $indent++
      }
      $line
  }) -Join "`n"
}

function ConvertTo-PrettyJson([Parameter(Mandatory, ValueFromPipeline)][object] $obj)
{
    $json = ConvertTo-Json -Depth 100 $obj
    if ($PSVersionTable.PSVersion.Major -ge 6)
    {
        $json
    }
    else
    {
        Format-Json $json
    }
}

Export-ModuleMember Clear-MinaOmbudAccessTokens, ConvertTo-PrettyJson, Get-MinaOmbudAccessToken
