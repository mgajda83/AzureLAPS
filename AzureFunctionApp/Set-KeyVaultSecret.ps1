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
$KeyVaultName = "KeyVault-LAPS-PSMVP"
$VaultSecretUri = "https://$KeyVaultName.vault.azure.net/secrets/$($Request.Body.KeyName)/?api-version=2016-10-01"

$null = Invoke-RestMethod -Method PUT -Body $Body -Uri $VaultSecretUri -ContentType 'application/json' -Headers $AuthHeader -ErrorAction Stop

#Return Password to workstation
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    Body = $Password
})
