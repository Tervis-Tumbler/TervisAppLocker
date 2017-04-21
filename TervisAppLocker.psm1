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

function Add-TervisAppLockerPolicyFromXMLFile {
    param (
        [Parameter(Mandatory)]$Path
    )
    $AppLockerPolicyGUID = "{F5D1AC24-EF4A-41BB-9D8C-81404B9869C7}"
    $AppLockerPolicyDistinguishedName = Get-ADObject -Filter {Name -like $AppLockerPolicyGUID} | select -ExpandProperty DistinguishedName
    $DCHostName = Get-ADDomainController | select -ExpandProperty HostName
    Set-AppLockerPolicy -XmlPolicy $Path -Ldap "LDAP://$DCHostName/$AppLockerPolicyDistinguishedName" -Merge -Verbose
}

function New-TervisAppLockerPolicyXMLFileFromDirectory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]$ExePath,
        [Parameter(Mandatory)]$XmlDestination,
        [Parameter(Mandatory)]$XmlFileRootName,
        $User = "Everyone"
    )
    if (-not (Test-Path -Path $ExePath)) {
        throw "ExePath directory does not exist."
    }
    $XmlPolicyFileByPublisher = Join-Path -Path $XmlDestination -ChildPath "$($XMLFileRootName)_ByPublisher.xml"
    $XmlPolicyFileByHash = Join-Path -Path $XmlDestination -ChildPath "$($XMLFileRootName)_ByHash.xml"
    Write-Verbose "Retrieving AppLocker file information"
    $AppLockerFileInformation = Get-AppLockerFileInformation -Directory $ExePath -FileType Exe -Recurse
    Write-Verbose "$AppLockerFileInformation"
    Write-Verbose "Generating file: $XmlPolicyFileByPublisher"
    $AppLockerFileInformation | 
        where Publisher -NE $null | 
        New-AppLockerPolicy -RuleType Publisher -RuleNamePrefix PS_$env:USERNAME -User $User -Optimize -Xml -IgnoreMissingFileInformation |
        Out-File -FilePath $XmlPolicyFileByPublisher -Encoding utf8 -Force
    Write-Verbose "Generating file: $XmlPolicyFileByHash"
    $AppLockerFileInformation | 
        where Publisher -EQ $null |
        New-AppLockerPolicy -RuleType Hash -RuleNamePrefix PS_$env:USERNAME -User $User -Optimize -Xml |
        Out-File -FilePath $XmlPolicyFileByHash -Encoding utf8 -Force
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

function Get-AppLockerEvents {
    param (
    $LogServer = "INF-AppLockLog"
    )
    
    $AppLockerEvents = Get-WinEvent -ComputerName $LogServer -LogName ForwardedEvents | where Id -NE 111
    
    foreach ($Event in $AppLockerEvents) {
        [xml]$EventXML = $Event.toXML()
        [DateTime]$TimeCreated = $EventXML.Event.System.TimeCreated.SystemTime
        $RecordId = $Event.Event.System.EventRecordID
        $ComputerName = $EventXML.Event.System.Computer
        $EventFilePath = $EventXML.Event.UserData.RuleAndFileData.FilePath
        $EventFileHash = $EventXML.Event.UserData.RuleAndFileData.FileHash
        $EventPublisher = $EventXML.Event.UserData.RuleAndFileData.FQBN.Split("\")[0]

        [PSCustomObject][Ordered]@{
            TimeCreated = $TimeCreated
            RecordId = $RecordId
            ComputerName = $ComputerName
            EventPublisher = $EventPublisher
            EventFileHash = $EventFileHash
            EventFilePath = $EventFilePath
        }
    }        
}



<#

[XML]$AppLockerPolicyXML = Get-Content C:\bwilkinson.xml
[xml]$AppLockerPolicyXML = Get-AppLockerFileInformation -Directory 'C:\Program Files\Microsoft Office' -FileType Exe -Recurse  | New-AppLockerPolicy -RuleType Publisher,Hash -RuleNamePrefix Test_ -User Everyone -Xml -Optimize
$FileHashes = $AppLockerPolicyXML.AppLockerPolicy.RuleCollection.FileHashRule.Conditions.FileHashCondition.FileHash | % {$_.clone()}
$FileHashRule = $AppLockerPolicyXML.AppLockerPolicy.RuleCollection.FileHashRule | select -First 1
$AppLockerPolicyXML.AppLockerPolicy.RuleCollection.RemoveAll()
$FileHashRule.Conditions.FileHashCondition.FileHash.RemoveAll()
#$FileHashRule.Conditions.FileHashCondition.FileHash.Remove()
$FileHashRule.Conditions.FileHashCondition.RemoveChild(
    $($FileHashRule.Conditions.FileHashCondition.ChildNodes|
    select -First 1)
)

$FileHashRule.Conditions.FileHashCondition 
ForEach ($FileHash in $FileHashes) {
    #$FileHashRule.Conditions.FileHashCondition.AppendChild($FileHash) | Out-Null
    $($FileHashRule.Conditions.ChildNodes | select -First 1).AppendChild($FileHash) | Out-Null
}




$AppLockerPolicyXML.AppLockerPolicy.RuleCollection.FileHashRule.Conditions.FileHashCondition.FileHash | measure
$AppLockerPolicyXML.AppLockerPolicy.RuleCollection.FileHashRule | measure



$FileHashRule.Conditions.FileHashCondition.FileHash.RemoveChild()

$FileHashes |select -First 10 | % { $_.outerxml}
$FileHashRule.Conditions.FileHashCondition.OuterXml

#>