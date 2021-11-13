Param
(
    $UserName = "Adminek"
)

# Use TLS 1.2 connection
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Uri = 'https://functionapp-laps-psmvp.azurewebsites.net/api/Set-KeyVaultSecret?code=cL7TGRJAIN6pbN1hGISN0r6M3bE9pD7bbZPMJnFFNMpfvUhRVtjhSQ=='

$Body = @"
    {
        "keyName": "$env:COMPUTERNAME",
        "contentType": "LAPS",
        "tags": {
            "UserName": "$UserName"
        }
    }
"@


# Trigger Azure Function.
try {
    $password = Invoke-RestMethod -Uri $uri -Method POST -Body $body -ContentType 'application/json' -ErrorAction Stop
}
catch {
    Write-Error "Failed to submit Local Administrator configuration. StatusCode: $($_.Exception.Response.StatusCode.value__). StatusDescription: $($_.Exception.Response.StatusDescription)"
}

# Convert password to Secure String
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force

# Create a new Local User, change the password if it already exists.
try {
    New-LocalUser -Name $UserName -Password $securePassword -PasswordNeverExpires:$true -AccountNeverExpires:$true -ErrorAction Stop
}
catch {
    # If it already exists, catch it and continue.
    if ($_.CategoryInfo.Reason -eq 'UserExistsException') {
        Write-Output "Local Admin '$UserName' already exists. Changing password."
        $userExists = $true
    } else {
        $exitCode = -1
        Write-Error $_
    }
}

if ($userExists) {
    # Change the password of the Local Administrator
    try {
        Set-LocalUser -Name $UserName -Password $securePassword
        Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $UserName -ErrorAction SilentlyContinue
        Write-Output "Added Local User '$UserName' to Local Administrators Group"
    }
    catch {
        $exitCode = -1
        Write-Error $_
    }
} else {
    # Add the new Local User to the Local Administrators group
    try {
        Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $UserName
        Write-Output "Added Local User '$UserName' to Local Administrators Group"
    }
    catch {
        $exitCode = -1
        Write-Error $_
    }
}

exit $exitCode
