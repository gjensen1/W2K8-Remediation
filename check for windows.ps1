#********************
# Check-For-WindowsOS
#********************
Function Check-For-WindowsOS {
    [CmdletBinding()]
    Param($s)
    "Checking if VM $s is running Windows"
    $OSType = Get-VMGuest -vm $s
    If($OSType.OSFullName -match 'Microsoft Windows'){
        return $True
        }
    Else {
        return $False
         }
 }
#****************************
# EndFunction Delete-Snapshot
#****************************

