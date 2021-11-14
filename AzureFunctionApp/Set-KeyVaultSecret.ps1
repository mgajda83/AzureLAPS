using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

#Generuj Token do Key Vault
$VaultTokenUri = 'https://vault.azure.net'
$ApiVersion = '2017-09-01'
$AuthToken = Invoke-RestMethod -Method Get -Headers @{ 'Secret' = $env:MSI_SECRET } -Uri "$($env:MSI_ENDPOINT)?resource=$VaultTokenUri&api-version=$ApiVersion"

$AuthHeader = @{ Authorization = "Bearer $($AuthToken.access_token)" }

#Generuj logowe hasło
Function New-Password {
    $alphabets = 'a,b,c,d,e,f,g,h,i,j,k,m,n,p,q,r,t,u,v,w,x,y,z'
    $numbers = 2..9
    $specialCharacters = '!,@,#,$,%,&,*,?,+'
    $array = @()
    $array += $alphabets.Split(',') | Get-Random -Count 10
    $array[0] = $array[0].ToUpper()
    $array[-1] = $array[-1].ToUpper()
    $array += $numbers | Get-Random -Count 3
    $array += $specialCharacters.Split(',') | Get-Random -Count 3
    ($array | Get-Random -Count $array.Count) -join ""
}

$Password = New-Password

#Create Request to Key Vault
$Body = $Request.body | Select-Object -Property * -ExcludeProperty KeyName
$Body | Add-Member -NotePropertyName value -NotePropertyValue "$Password"
$Body = $Body | ConvertTo-Json

#Send Request
$KeyVaultName = "<KeyVault Name>"
$VaultSecretUri = "https://$KeyVaultName.vault.azure.net/secrets/$($Request.Body.KeyName)/?api-version=2016-10-01"

$null = Invoke-RestMethod -Method PUT -Body $Body -Uri $VaultSecretUri -ContentType 'application/json' -Headers $AuthHeader -ErrorAction Stop

#Send event to Log Analytics
$WorkspaceID= "<Workspace ID>"  
$SharedKey = "<Shared Key>"
$LogType = "LAPSEvents"

$json = @"
{  "UserPrincipalName": "SYSTEM",
    "ComputerName": "$($Request.Body.KeyName)",
    "Action": "LAPSSet",
    "CreatedOn": "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.000Z')",
    "Result": "Success",
    "Id": ""
}
"@

# Create the function to create the authorization signature
Function Build-Signature ($WorkspaceID, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $WorkspaceID,$encodedHash
    return $authorization
}

# Create the function to create and post the request
Function Post-LogAnalyticsData($WorkspaceID, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -WorkspaceID $WorkspaceID `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $WorkspaceID + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = "";
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}

# Submit the data to the API endpoint
Post-LogAnalyticsData -WorkspaceID $WorkspaceID -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType

#Return Password to workstation
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    Body = $Password
})
