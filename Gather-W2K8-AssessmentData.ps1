<# *******************************************************************************************************************
*******************************************************************************************************************
Purpose of Script:
        Gather Information relevant to assessing Upgrade feasability of Windows 2008 VMs

        Report on:
            -	Identify if there are local groups and/or users on the machine and provide a list (including last logon date)
            -	Identifies who the last logged on users were and when, including CIHS C3 support accounts.
            -	Try to figure out what application is on the server and/or what purpose it has.
            -	See if an add-on product that has its own life cycle that could break following, or interfere with, a W2K8 to W2K12 in-place upgrade (SQLServer falls into this category, but there may be other things).
            -	Identify anything else that may be relevant to a change in operating system, or to the approach taken.

   
*******************************************************************************************************************  
Authored Date:  Dec 18th, 2017
Original Author:  Graham Jensen
*************************
Development Environment: W2K12

Additional Modules Required:

Usage:

OutPut:

= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
Update Log:Please use this section to document changes made to this script
= = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
-----------------------------------------------------------------------------
Update < Date >
Author:< Name > 
Description of Change:
< Description >
-----------------------------------------------------------------------------
Update < Date >
Author:< Name >
Description of Change:
< Description >
-----------------------------------------------------------------------------
*******************************************************************************************************************
Operational Notes
-----------------
****Location of other scripts called:* ***


****Scripts Called and passed parameters * ***
+++++++++++++++++++++++++++++++++++
+ Script Name + Parameters Passed +
+++++++++++++++++++++++++++++++++++

#>


# -----------------------
# Define Global Variables
# -----------------------
$Global:Folder = "c:\temp\w2k8Assessment\"
#$Global:WorkFolder = $null
$Global:WorkFolder = $Global:Folder
$Global:FileShare = "\\cihs.ad.gov.on.ca\tbs\Groups\ITS\DCO\ITSM\ITSM\Wintel GA\W2K8Assessments"



#*************************************************
# Check for Folder Structure if not present create
#*************************************************
Function Verify-Folders {
    [CmdletBinding()]
    Param($CheckFolder)
     
    If (!(Test-Path $CheckFolder)) {
        "Building Local folder structure"
        New-Item $CheckFolder -type Directory
        "Folder Structure built"
        }
     
}
#***************************
# EndFunction Verify-Folders
#***************************

#****************************
# BeginFunction ConvertTo-SID
#****************************
Function ConvertTo-SID {
    Param([byte[]]$BinarySID)
    (New-Object  System.Security.Principal.SecurityIdentifier($BinarySID,0)).Value
}
#**************************
# EndFunction ConvertTo-SID
#**************************

#***********************************
# BeginFunction Get-LocalGroupMember
#***********************************
Function Get-LocalGroupMember {
    Param  ($Group)
    $group.Invoke('members')  | ForEach {
        $_.GetType().InvokeMember("Name",  'GetProperty',  $null,  $_, $null)
    }
}
#*********************************
# EndFunction Get-LocalGroupMember
#*********************************

#**************************
# BeginFunction Remove-File
#**************************
Function Remove-File {
    [CmdletBinding()]
    Param($FileToRemove)
    if (Test-Path $FileToRemove) {
        Remove-Item $FileToRemove
    }
}
#************************
# EndFunction Remove-File
#************************

#*****************************
# BeginFunction Get-LocalUsers
#*****************************
Function Get-LocalUsers {
    [CmdletBinding()]
    Param()
    
    ([ADSI]"WinNT://$Env:COMPUTERNAME").Children | ?{$_.SchemaClassName -eq 'user'} | %{
        $groups = $_.Groups() | %{$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}
        $_ | Select @{n='UserName';e={$_.Name}},
        @{n='Active';e={if($_.PasswordAge -like 0){$false} else{$true}}},
        @{n='PasswordExpired';e={if($_.PasswordExpired){$true} else{$false}}},
        @{n='PasswordAgeDays';e={[math]::Round($_.PasswordAge[0]/86400,0)}},
        @{n='LastLogin';e={$_.LastLogin}},
        @{n='Groups';e={$groups -join ';'}},
        @{n='Description';e={$_.Description}}
        }|Export-Csv -NoTypeInformation $Global:WorkFolder\LocalUsers.csv
    }
#***************************
# EndFunction Get-LocalUsers
#***************************

#******************************
# BeginFunction Get-LocalGroups
#******************************
Function Get-LocalGroups {
    [CmdletBinding()]
    Param()
    Remove-File $Global:WorkFolder\LocalGroups.csv
    $groups=([ADSI]"WinNT://$Env:COMPUTERNAME").Children | ?{$_.SchemaClassName -eq 'group'}
    $groups  | ForEach {
        [pscustomobject]@{
        #Computername = $Computer
            Name = $_.Name[0]
            Members = ((Get-LocalGroupMember  -Group $_))  -join ', '
            SID = (ConvertTo-SID -BinarySID $_.ObjectSID[0])
            }|Export-Csv -NoTypeInformation -Append $Global:WorkFolder\LocalGroups.csv
        }
}    
#****************************
# EndFunction Get-LocalGroups
#****************************

#*****************************
# BeginFunction Get-LastLogons
#*****************************
Function Get-LastLogons {
    [CmdletBinding()]
    Param()
    $startDate = (Get-Date) - (New-TimeSpan -Day 30)
    $UserLoginTypes = 2,4,10
    Get-WinEvent  -FilterHashtable @{Logname='Security';ID=4624;StartTime=$startDate} |
        SELECT TimeCreated, @{N='Username'; E={$_.Properties[5].Value}}, @{N='LogonType'; E={$_.Properties[8].Value}} | 
        WHERE {$UserLoginTypes -contains $_.LogonType}  | 
        Sort-Object TimeCreated |
        Export-Csv -NoTypeInformation -Append $Global:WorkFolder\LastLogons.csv
}
#***************************
# EndFunction Get-LastLogons
#***************************

#***************************
# BeginFunction Get-Software
#***************************
Function Get-Software {
    [CmdletBinding()]
    Param()
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
        Export-Csv -NoTypeInformation $Global:WorkFolder\Software.csv

    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |  
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | 
        Export-Csv -NoTypeInformation -Append $Global:WorkFolder\Software.csv
    
}
#*************************
# EndFunction Get-Software
#*************************

#*******************************
# BeginFunction MoveData-ToShare
#*******************************
Function MoveData-ToShare {
    [CmdletBinding()]
    Param()
    $Credentials = Get-Credential
    New-PSDrive -Name REMOTE -PSProvider FileSystem -Root $Global:FileShare -Credential $Credentials > $null
    Verify-Folders REMOTE:\$Env:COMPUTERNAME > $null
    Move-Item $Global:WorkFolder\*.* REMOTE:\$Env:COMPUTERNAME
    Remove-PSDrive REMOTE
}
#*****************************
# EndFunction MoveData-ToShare
#*****************************


#***************
# Execute Script
#***************
Verify-Folders $Global:WorkFolder
Get-Localusers
Get-LocalGroups
Get-LastLogons
Get-Software
MoveData-ToShare