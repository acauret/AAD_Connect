
$MFARegistrationGroup = Get-MsolGroup -SearchString "Multi-factor authentication registration"
$Users = Get-MsolGroupMember -GroupObjectId ($MFARegistrationGroup).ObjectId.Guid

Foreach ($User in $Users){
    if ((Get-MsolUser -UserPrincipalName $User.EmailAddress | Select-Object StrongAuthenticationMethods).StrongAuthenticationMethods.Count -gt 0) {
        Write-Output "$($User.DisplayName) is already registered for MFA and can therefore be removed from the intial registration group"
        Remove-MsolGroupMember -GroupObjectId ($MFARegistrationGroup).ObjectId.Guid -GroupMemberObjectId $User.ObjectId -Verbose
    }
    else {
        Write-Output "$($User.DisplayName) has still to register for MFA"
    }
}