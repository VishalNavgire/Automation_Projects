<#
.Author - Vishal Navgire
.Created on - 03-April-2025
.Co-Author(s)       - N/A
.Reviwer(s)         - N/A
.Intended Audience  - 
.Target Device Type - Windows Machines. 

.DESCRIPTION 
 Checks device's reboot status and it will create a Log file 
 "C:\ProgramData\Microsoft\IntuneManagementExtension\Win_Device_Pending_Reboot_GUI\Track_Win_Device_Last_Rebooted_Status_LogFile.Log".

Pre-reqs:
N/A

Version Control:
 03-April-2025 :: v1.0
#>


#Mention the log file path. For Ex: "C:\Temp\Track_Win_Device_Last_Rebooted_10_Days_Ago_Status" OR "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Track_Win_Device_Last_Rebooted_Status_LogFile.Log"
$Global:LogFile = "C:\ProgramData\Microsoft\IntuneManagementExtension\Win_Device_Pending_Reboot_GUI\Track_Win_Device_Last_Rebooted_Status_LogFile.Log"

Function Write-Log()
{

    <#
        .Author         - Vishal Navgire
        .Created on     - 05-Mar-2025
        .Co-Author(s)   - NA
        .Reviwer(s)     - NA


        .DESCRIPTION


            Script is designed to write custom log messages to a particular location.


        Pre-reqs:
            N/A


        Version Control:
            05-Mar-2025 : v1.0
    #>


        [CmdletBinding()]
        param
        (
            [Parameter(Mandatory=$True,ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNullOrEmpty()]
            [Alias("LogContent")]
            [string]$Message,

            [Parameter(Mandatory=$False)]
            # [ValidateScript({$_ -like 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\*'})]
            # [Alias("LogFileLocation")]
            [string]$LogFile = $Global:LogFile,

            [Parameter(Mandatory=$False)]
            [ValidateSet("Error","Warning","Info")]
            [string]$Level = "Info"
        )
        Begin
            {
            }
        Process
        {
            If (Test-Path $LogFile)
                {
                    $LogSize = (Get-Item -Path $LogFile).Length/1MB
                    $MaxLogFileSize = 10

                    # Check for file size of the log. If greater than 10MB, it will delete the old and create a new one.
                        If (($LogSize -gt $MaxLogFileSize))
                            {
                                Remove-Item $LogFile -Recurse -Force | Out-Null
                                New-Item $LogFile -Force -ItemType File | Out-Null
                            }
                }

            # If attempting to write to a log file in a folder path that doesn't exist create the file including the path.
           Else
                {
                    New-Item $LogFile -Force -ItemType File | Out-Null
                }

            # Write message to error, warning, or verbose pipeline and specify $LevelText
            Switch ($Level)
                {
                    'Error'
                        {
                            $LevelText = 'ERROR:'
                        }
                    'Warning'
                        {
                            $LevelText = 'WARNING:'
                        }
                    'Info'
                        {
                            $LevelText = 'INFO:'
                        }
                }


            # Write log entry to $LogFile
            "$(Get-Date -Format "dd:MMMM:yyyy hh:mm:ss tt ")[$((Get-TimeZone).StandardName)]____$LevelText $Message" | Out-File -PSPath $LogFile -Append -Force
        }
        End
        {


        }
}

Function Get-LastRebootTime 
        {
                <#
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
            $LastBootUptime
}

    # Actual Date and Time when device was last reboot.
        $Reboot_Date = $(Get-LastRebootTime).ToLongDateString()
        $Reboot_Time = $(Get-LastRebootTime).ToLongTimeString()
        $Actual_Device_Restarted_Date_Time = $($Reboot_Date + " " + $Reboot_Time)

    #Check if the previous was done 10 days ago.
    $Number_Of_Days_Since_Last_Reboot = ((Get-Date) - (Get-LastRebootTime)).Days
    # $Number_Of_Hours_Since_Last_Reboot = ((Get-Date) - (Get-LastRebootTime)).Hours

    #Hold previous System Restarted Events
    $Hold_Device_Restarted_System_Events = @()

#Delete previous Old log file.

If (Test-Path -Path $Global:LogFile)
    {
    #   Remove-Item -PsPath $Global:LogFile -Force | Out-Null
      Start-Sleep 10
      Write-Log -Message "Detection Ps code started from root directory: '$($PSScriptRoot)'." 
      " " | Out-File -FilePath $Global:LogFile -Append -Force
    #   "INFO: $(Get-Date -Format "dd:MMMM:yyyy hh:mm:ss tt")____Detection Ps code started from root directory: '$($PSScriptRoot)'." | Out-File -FilePath $Global:LogFile -Append -Force
    #   " " | Out-File -FilePath $Global:LogFile -Append -Force
    }

If ($Number_Of_Days_Since_Last_Reboot -ge 10)
    {
        Write-Log -Message "Device $($ENV:COMPUTERNAME) was last rebooted $($Number_Of_Days_Since_Last_Reboot) days ago on: '$($Actual_Device_Restarted_Date_Time)'." -Level Warning

        $Device_Restarted_System_Events = Get-WinEvent -FilterHashTable @{LogName = "System"} -ErrorAction SilentlyContinue | Where-Object {($_.Id -eq "1074")} | Select-Object -First 25


        If ($Device_Restarted_System_Events.Count -gt 0)
            {
                Try 
                {
                    ForEach ($Event in $Device_Restarted_System_Events)
                    {
                        $Event_Id_Counter +=1
                        $Hold_Device_Restarted_System_Events += [PSCustomObject]@{
                                                                                    Event_Sequence_Number            = $Event_Id_Counter
                                                                                    Event_Recorded_From_Device_Name  = $Event.MachineName
                                                                                    Event_Created_On                 = $Event.TimeCreated
                                                                                    Event_Id                         = $Event.Id
                                                                                    Event_Message                    = ($Event | Select-Object -ExpandProperty Message)
                                                                                }
                    }
                }
                Catch 
                {
                    Write-Log -Message "Below Error has occured:" -Level Error
                    $($Error[0].Message) | Out-File -FilePath $Global:LogFile -Append
                }
            }
        "--------------------------------------------------------------"   | Out-File -FilePath $Global:LogFile -Append
        "Previous Events showing Device restarted at various Intervals : " | Out-File -FilePath $Global:LogFile -Append
        " " | Out-File -FilePath $Global:LogFile -Append

        $Hold_Device_Restarted_System_Events | Format-List | Out-File $Global:LogFile -Append -Force
        '====================================================================================================' | Out-File -LiteralPath $Global:LogFile -Append -Force

        Write-Log -Message "Calling GUI prompt for user to read and take appropriate action as per reboot notification !!!" -Level Warning

        #Calling Remediation to display 'Mandatory Device Reboot Prompt' to an End user.
        Start-Process -FilePath "C:\ProgramData\Microsoft\IntuneManagementExtension\Win_Device_Pending_Reboot_GUI\Windows_Device_Reboot_Prompt_Python_GUI.exe"
    }
Else 
    {
        Try
            {
                Write-Log -Message "Device '$($ENV:COMPUTERNAME)' was last rebooted $($Number_Of_Days_Since_Last_Reboot) days ago on: '$($Actual_Device_Restarted_Date_Time)'."
                $Device_Restarted_System_Events = Get-WinEvent -FilterHashTable @{LogName = "System"} -ErrorAction SilentlyContinue | Where-Object {($_.Id -eq "1074")} | Select-Object -First 25

                If ($Device_Restarted_System_Events.Count -gt 0)
                    {
                        Try 
                        {
                            ForEach ($Event in $Device_Restarted_System_Events)
                            {
                                $Event_Id_Counter +=1
                                $Hold_Device_Restarted_System_Events += [PSCustomObject]@{
                                                                                            
                                                                                            Event_Sequence_Number            = $Event_Id_Counter
                                                                                            Event_Recorded_From_Device_Name  = $Event.MachineName
                                                                                            Event_Created_On                 = $Event.TimeCreated
                                                                                            Event_Id                         = $Event.Id
                                                                                            Event_Message                    = ($Event | Select-Object -ExpandProperty Message)
                                                                                        }
                            }
                        }
                        Catch 
                            {
                                Write-Log -Message "Below Error has occured:" -Level Error
                                $($Error[0].Message) | Out-File -FilePath $Global:LogFile -Append
                            }
                    }
                "--------------------------------------------------------------"   | Out-File -FilePath $Global:LogFile -Append
                "Previous Events showing Device restarted at various Intervals : " | Out-File -FilePath $Global:LogFile -Append
                " " | Out-File -FilePath $Global:LogFile -Append

                $Hold_Device_Restarted_System_Events | Format-List | Out-File $Global:LogFile -Append -Force
                '====================================================================================================' | Out-File -LiteralPath $Global:LogFile -Append -Force
            #All good, not need to call Remediation Ps Code.
                # Exit 0
            }
        
        Catch 
        {
        Write-Log -Message "Below Error has occured:" -Level Error
        $($Error[0]) | Out-File -FilePath $Global:LogFile -Append
        }
    }