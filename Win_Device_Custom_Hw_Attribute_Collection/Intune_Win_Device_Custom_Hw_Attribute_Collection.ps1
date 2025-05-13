<#
.Author             - Vishal Navgire
.Created on         - 12-May-2025
.Co-Author(s)       - N/A
.Reviwer(s)         - N/A
.Intended Audience  - 
.Target Device Type - Windows Machines. 

.DESCRIPTION 
    Collect custom hardware inventory from Intune managed device windows machine and add relevant Windows Reg Entry in the path 
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        Local administrator group membership.
        Last boot-up time.
        Time zone.
        User profiles.
        Sys temp folder consumed space in GB.
        User temp folder Consumed space in GB.
        Windows OS License Info.
    IME agent would read these values and show on the 'Discovered Apps' on the Intune console.

Pre-reqs:
N/A

Version Control:
 12-May-2025 :: v1.0
#>

Function Invoke-LocalAdminMembers 
    {
        <#
        .Author             - Vishal Navgire
        .Created on         - 12-May-2025
        .Co-Author(s)       - N/A
        .Reviwer(s)         - N/A
        .Intended Audience  - 
        .Target Device Type - Windows Machines.
        .SYNOPSIS
            Retrieves members of the local Administrators group and returns them in a hashtable.

        .DESCRIPTION
            This function identifies the local Administrators group by SID, lists its members,
            filters out system entries, and returns a hashtable with the group name and members.

        .OUTPUTS
            [hashtable] - Contains the group name and a comma-separated list of members.
        #>

        [CmdletBinding()]
            param ()

            $LocalAdmin_Members =  @()

            Try 
                {
                    # Get the local Administrators group name using its SID
                    $Local_Admin_GroupName = (Get-CimInstance -Namespace root/CIMV2 -ClassName Win32_Group -ErrorAction Stop | Where-Object { $_.SID -like "S-1-5-32-544*" }).Name

                    # Get members of the group
                    $Admin_Group_Members = Get-LocalGroupMember -Group $Local_Admin_GroupName -ErrorAction SilentlyContinue

                    Foreach ($Mem in $Admin_Group_Members) 
                        {
                            $LocalAdmin_Members += [PSCustomObject]@{
                                                                        'Account_Name' = $Mem.Name
                                                                        'Source'       = $Mem.PrincipalSource
                                                                    }
                        }
                    
                }
            Catch 
                    {
                    
                        Write-Warning "Failed to retrieve local administrator members: $_"
                        return @()
                    }

                    Return $($LocalAdmin_Members)

    }

Function Get-AllUserProfiles 
    {

         <#
        .Author             - Vishal Navgire
        .Created on         - 12-May-2025
        .Co-Author(s)       - N/A
        .Reviwer(s)         - N/A
        .Intended Audience  - 
        .Target Device Type - Windows Machines.

        .DESCRIPTION
            This PowerShell function retrieves all user profiles registered on a Windows system by reading from the Windows Registry. 
            It maps each profile's Security Identifier (SID) to a username and provides the profile path.
            Accesses the registry path: 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'.
        #>

        [CmdletBinding()]
        param ()

        $profiles = @()

        # Get user profile information from the registry
        $profileListPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        $profileKeys = Get-ChildItem -Path $profileListPath

        Foreach ($key in $profileKeys) 
            { 
                $sid = $key.PSChildName
                If (($sid.length) -gt 8) 
                    {
                        $ProfilePath = (Get-ItemProperty -Path $key.PSPath).ProfileImagePath
            
                        Try 
                            {
                                $User = New-Object System.Security.Principal.SecurityIdentifier($sid)
                                $Account = $user.Translate([System.Security.Principal.NTAccount])
                            } 
                        Catch 
                            {
                                $Account = "Unknown"
                            }
            
                        $Profiles += [PSCustomObject]@{
                            
                                                        Username      = $account
                                                        ProfilePath   = $profilePath
                                                        
                                                    }
                    }
            }
                


        Return $Profiles
    }

Function Get-LastRebootTime 
    {
        <#

        .Author             - Vishal Navgire
        .Created on         - 12-May-2025
        .Co-Author(s)       - N/A
        .Reviwer(s)         - N/A
        .Intended Audience  - 
        .Target Device Type - Windows Machines.
        .SYNOPSIS
            Get the last reboot time of the device, considering fast boot settings.
    
        .DESCRIPTION
            This function retrieves the last reboot time of the device, taking into account the fast boot settings.
            It utilizes WMI and Windows Event Logs to determine the most accurate last reboot time.
    
        .PARAMETER LogFile
            Specifies the path to the log file where the output information will be appended.
    
        #>
    
        # Get LastBootUpTime from WMI
        $LastBootUpTime_WMI = Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime
    
        # Check if fast boot is enabled
        $CheckFastBoot = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -ErrorAction SilentlyContinue).HiberbootEnabled
    
        # Set default value for $LastBootUpTime_Event
        $LastBootUpTime_Event = $null
    
        # Check fast boot status and set $LastBootUpTime_Event accordingly
        If ($CheckFastBoot -eq 0) 
            {
                $BootEvent = Get-WinEvent -ProviderName 'Microsoft-Windows-Kernel-Boot' | Where-Object { $_.ID -eq 27 -and $_.Message -like "*0x0*" }
            }
        Elseif ($CheckFastBoot -eq 1) 
            {
                $BootEvent = Get-WinEvent -ProviderName 'Microsoft-Windows-Kernel-Boot' | Where-Object { $_.ID -eq 27 -and $_.Message -like "*0x1*" }
            }
    
        # If $BootEvent is not null, set $LastBootUpTime_Event
        If ($BootEvent) 
            {
                $LastBootUpTime_Event = $BootEvent[0].TimeCreated
            }
    
        # Determine final uptime value
        $LastBootUptime = If ($LastBootUpTime_Event -and $LastBootUpTime_WMI -lt $LastBootUpTime_Event) 
                            {
                                $LastBootUpTime_Event
                            } 
                        Else 
                            {
                                $LastBootUpTime_WMI
                            }
    
        # Display the final device's reboot time.
        $Reboot_Date = $LastBootUptime.ToLongDateString()
        $Reboot_Time = $LastBootUptime.ToLongTimeString()
        $Actual_Device_Restarted_Date_Time = $($Reboot_Date + " " + $Reboot_Time)
    
        Return $Actual_Device_Restarted_Date_Time
    
    }

Function Invoke-WindowsOSLicenseInfo 
    {
        <#
        .Author             - Vishal Navgire
        .Created on         - 12-May-2025
        .Co-Author(s)       - N/A
        .Reviwer(s)         - N/A
        .Intended Audience  - 
        .Target Device Type - Windows Machines.

        .DESCRIPTION
            This function retrieves and displays detailed information about the Windows operating system license on the current machine. 
            It filters for valid, active licenses and presents key details such as the license name, description, product key channel, and license status.

        .OUTPUTS
        Returns an array of objects with:

            License_Name – Name of the Windows license.
            Description – Description of the license.
            Product_Key_Channel – Channel through which the product key was issued (e.g., Retail, OEM).
            License_Status – Human-readable license status.


        #>
        [CmdletBinding()]
        param ()

        $Windows_OS_License_Details = @()

        Try 
        {
            $licenses = Get-CimInstance -ClassName SoftwareLicensingProduct |
                        Where-Object {
                                        $_.PartialProductKey -ne $null -and
                                        $_.Name -like "*Windows*" -and
                                        $_.LicenseStatus -eq 1
                                    }

            Foreach ($license in $licenses) 
                {
                    $Windows_OS_License_Details += [PSCustomObject]@{
                                                                        License_Name        = $license.Name
                                                                        Description         = $license.Description
                                                                        Product_Key_Channel = $license.ProductKeyChannel
                                                                        License_Status      = Switch ($license.LicenseStatus) 
                                                                                                {
                                                                                                    0 { "Unlicensed" }
                                                                                                    1 { "Licensed" }
                                                                                                    2 { "Out-of-Box Grace Period" }
                                                                                                    3 { "Out-of-Tolerance Grace Period" }
                                                                                                    4 { "Non-Genuine Grace Period" }
                                                                                                    5 { "Notification" }
                                                                                                    6 { "Extended Grace" }
                                                                                                    default { "Unknown" }
                                                                                                }
                                                                    }
                }
        } 
        Catch 
            {
                Write-Warning "Failed to retrieve license information: $_"
            }

        Return $Windows_OS_License_Details
    }

$Win_OS_license = Invoke-WindowsOSLicenseInfo

Function Get-FolderSizeGB 
        {
            <#
             .Author             - Vishal Navgire
            .Created on         - 12-May-2025
            .Co-Author(s)       - N/A
            .Reviwer(s)         - N/A
            .Intended Audience  - 
            .Target Device Type - Windows Machines.
            
            .DESCRIPTION
            This function calculates the total size of a specified folder (including all its subfolders and files) and returns the result in gigabytes (GB), rounded to two decimal places.

            .OUTPUTS
            A numeric value representing the folder size in GB, rounded to two decimal places.
            Returns 0 if the folder does not exist.
            #>
            param (
                        [string]$Path = $Null
                       
                    )
            If (Test-Path $Path) 
                {
                    $bytes = (Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
                    
                    return [math]::Round($bytes / 1GB, 2) 
                } 
            Else 
                {
                    return 0
                }
        }

$User_Temp_Path = $ENV:TEMP
$Sys_Temp_Path = "C:\Windows\Temp"
   
$userTempSizeGB = Get-FolderSizeGB -Path $($User_Temp_Path)
$systemTempSizeGB = Get-FolderSizeGB -Path $($Sys_Temp_Path)


Function Set-CustomHwInventory
    {
           
        <#
        .SYNOPSIS
            Generates custom software inventory entries for Add/Remove Programs and Installed Apps, enabling custom inventory tracking in Intune.

        .DESCRIPTION
            This script creates custom entries under HKLM or HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall with properties such as DisplayName, DisplayVersion, Publisher, InstallDate, NoModify, NoRepair, and NoRemove.

            These entries are detected by the Intune Management Extension and reported as part of the software inventory, allowing for the creation of custom inventory items in Intune.
        #>

        [CmdletBinding()]

                        param 
                            (
                                [Parameter(Mandatory = $False)] 
                                [ValidateLength(1,15)] [String] $Prefix_Text    = "Custom_Hw_INV",
                                [Parameter(Mandatory = $False)] 
                                [ValidateLength(1,1)] [String]  $Separator = ":- ",
                                [Parameter(Mandatory = $False)] 
                                [ValidateLength(1,64)] [String] $Developer = "Intune_Team_Windows",
                                [Parameter(Mandatory = $True)]  
                                [ValidateLength(1,256)] [String] $Name,
                                [Parameter(Mandatory = $True)]  
                                [String] $Value
                            )

        $Actual_RegPath = "{0}:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -f {HKLM}

        # Prepare Vars
        $KeyName = "$Prefix_Text$Separator$Name"
    
        $RegCreationDateTime =(Get-Date).ToString("ddd, MMMM d, yyyy h:mm:ss tt")

        # Create a new Registry key
        $RegKey = New-Item -Path $Actual_RegPath -Name $KeyName -Force
      
        # DisplayName as Variable Name
        $RegKey | Set-ItemProperty -Name "DisplayName" -Value $KeyName -Force
      
        
        # DisplayVersion as Variable Value
        $RegKey | Set-ItemProperty -Name "DisplayVersion" -Value $Value -Force
       
        
        # Publisher to the Prefix
        $RegKey | Set-ItemProperty -Name "Developer" -Value $Developer -Force
    
    
        # Set InstallDate in the yyyymmdd format
        $RegKey | Set-ItemProperty -Name "Reg_Entry_InstallDate" -Value $RegCreationDateTime -Force

    }

$Custom_Hw_Inventory = @{
                            "Last_Custom_Hw_Inv_Sync"  = (Get-Date).ToString("ddd, MMMM d, yyyy h:mm:ss tt")
                            "Last_Reboot_DateTime"     =  Get-LastRebootTime
                            "Device_Current_TimeZone"  = (Get-TimeZone).Id
                            "Local_Admin_Members"      = (Invoke-LocalAdminMembers | Select-Object -Property Account_Name).Account_Name
                            "User_Profiles"            = (Get-AllUserProfiles | Select-Object -Property ProfilePath).ProfilePath
                            "User_Temp_Folder_Size_GB" = $UserTempSizeGB
                            "Sys_Temp_Folder_Size_GB"  = $SystemTempSizeGB
                            "Windows_OS_License_Info"  = $Win_Os_License | ConvertTo-Json -Compress
                        }


ForEach ($CustomHwInv in $Custom_Hw_Inventory.GetEnumerator())
    {
        Set-CustomHwInventory -Name $($CustomHwInv.Name) -Value $($CustomHwInv.Value -Join "; ")
    }