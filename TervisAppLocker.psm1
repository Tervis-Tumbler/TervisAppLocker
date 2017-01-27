#requires -modules AppLocker

function Add-FileToAppLockerPolicy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ParameterSetName="SingleFile")]$PathToFile,
        [Parameter(Mandatory=$true,ParameterSetName="MultiFile")]$PathToDirectory,
        [Parameter(Mandatory=$true)]$AffectedUsers
    )
    
    if ($PathToFile) {
        $AppLockerFileInfo = Get-AppLockerFileInformation -Path $PathToFile 
    } elseif ($PathToDirectory) {
        $AppLockerFileInfo = Get-AppLockerFileInformation -Directory $PathToDirectory -FileType Exe -Recurse
    }

    # This is not creating Publisher rule types as expected.
    $AppLockerPolicy = New-AppLockerPolicy -FileInformation $AppLockerFileInfo -User $AffectedUsers -RuleType Publisher,Hash -RuleNamePrefix "PS_Generated_$env:USERNAME" -Optimize

    $AppLockerPolicyGUID = "{F5D1AC24-EF4A-41BB-9D8C-81404B9869C7}"
    $AppLockerPolicyDistinguishedName = Get-ADObject -Filter {Name -like $AppLockerPolicyGUID} | select -ExpandProperty DistinguishedName
    $DCHostName = Get-ADDomainController | select -ExpandProperty HostName

    Set-AppLockerPolicy -PolicyObject $AppLockerPolicy -Ldap "LDAP://$DCHostName/$AppLockerPolicyDistinguishedName" -Merge

}

function Invoke-GPUpdateOnComputersWithLocalAdmins {
    [CmdletBinding()]
    param ()
    $ComputersAllowedToHaveLocalAdmins = Get-ADGroupMember -Identity "Local - Computer Admin Group Exception" |
        where objectClass -EQ Computer | 
        where Name -EQ HAMTESTWIN10

    foreach ($Computer in $ComputersAllowedToHaveLocalAdmins) {
        Invoke-GPUpdate -Computer $Computer.Name -Force -Verbose
    }
}