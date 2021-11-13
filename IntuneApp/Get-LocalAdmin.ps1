$UserName = "admin"
$PasswordChangeableDate = -60

$LocalUser = Get-LocalUser $UserName

if($LocalUser.PasswordLastSet -lt (Get-Date).AddDays($PasswordChangeableDate))
{
    Write-Host "Hasło nie zmienione od ponad $PasswordChangeableDate dni"
    exit -1
} else {
    Write-Host "Hasło zmienione w przeciągu $PasswordChangeableDate dni"
    exit 0
}
