<#
.Author - Vishal Navgire
.Created on - 03-April-2025
.Co-Author(s)       - N/A
.Reviwer(s)         - N/A
.Intended Audience  - 
.Target Device Type - Windows Machines. 

.DESCRIPTION 
Copies following files to 'C:\ProgramData\Microsoft\IntuneManagementExtension\Win_Device_Pending_Reboot_GUI' and then register Task Scheduler as 'Custom_Win_Device_Reboot_GUI_Prompt', and it will create
a Log file "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Track_Win_Device_Last_Rebooted_Status_LogFile.Log"

    1.Background_Logo.png
    2.Copy&CreateTaskSchd.Ps1
    3.Custom_Win_Device_Reboot_GUI_Prompt.xml
    4.Delete&RemoveTaskSchd.Ps1
    5.Detect_Pending_Win_Device_Reboot_Status.ps1
    6.Restart_Logo.png
    7.Windows_Device_Reboot_Prompt_Python_GUI.Py

Pre-reqs:
N/A

Version Control:
 03-April-2025 :: v1.0
 22-April*2025 :: v1.1 - Updated the log file path. 
#>

$Global:SourceRootDirectory = $PSScriptRoot
$Global:DestinationRootDirectory = "C:\ProgramData\Microsoft\IntuneManagementExtension\Win_Device_Pending_Reboot_GUI"
$LogFileName = "\Track_Win_Device_Last_Rebooted_Status_LogFile.Log"

$Global:LogFile = Join-Path -Path $DestinationRootDirectory -ChildPath $LogFileName

Function Set-Destinationfolder 
    {
            <#
        .Author         - Vishal Navgire
        .Created on     - 05-Mar-2025
        .Co-Author(s)   - NA
        .Reviwer(s)     - NA

        .DESCRIPTION 

            Script is designed to create a new folder in the specific location.

        Pre-reqs:
            N/A

        Version Control:
            05-Mar-2025 : v1.0
    #> 

        [CmdletBinding()]
        param
            (
            
                [Parameter(Mandatory=$False)]
                [Alias("DestinationRootPath")]
                [string]$DestinationRootFolder = $Global:DestinationRootDirectory
            )

        If (!(Test-Path -Path $DestinationRootFolder))
            {
                New-Item -Path $DestinationRootFolder -ItemType Directory -Force | Out-Null
                Start-Sleep 10
                Return $True

            }
        Else 
            {Return $False}
    }
Function Write-LogMessage
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
                # [ValidateScript({$_ -like 'C:\Temp\Intune_Data_BackUp_*'})]
                #[ValidateScript({$_ -like 'C:\Temp\Demo\*'})] 
                [Alias("LogFileLocation")]
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
                            If ((Test-Path $LogFile) -AND ($LogSize -gt $MaxLogFileSize))
                                {
                                    Remove-Item $LogFile -Recurse -Force | Out-Null
                                    New-Item $LogFile -Force -ItemType File | Out-Null
                                }
                            Else 
                                {
                                    $Null
                                }
                    }

                # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
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

$IsDestRootFolderCreated = Set-Destinationfolder
    If ($IsDestRootFolderCreated) 
        {
            Write-LogMessage -Message "Created a new folder: '$($DestinationRootDirectory)' for copying the required Windows device reboot and custom GUI files."
        }
    Else 
        {
            Write-LogMessage -Message "Folder: '$($DestinationRootDirectory)' already exists for copying required Windows device reboot and custom GUI files."
        }
Function Copy-WinDeviceRebootFiles
        {
            [CmdletBinding()]
            param
            (
                [Parameter(Mandatory=$False)]
                [Alias("SourceRootPath")]
                [string]$CopyFromSourceFolder = $Global:SourceRootDirectory, 

                [Parameter(Mandatory=$False)]
                [Alias("DestinationRootPath")]
                [string]$DestinationRootFolder = $Global:DestinationRootDirectory
            )

            Try 
            {
                Copy-Item -Path "$CopyFromSourceFolder\*" -Destination $DestinationRootFolder -Recurse -ErrorAction Stop -Force
                Write-LogMessage -Message "Copying files and folders from source directory: $($CopyFromSourceFolder) ."
                # Write-LogMessage -Message "Copied file name '$CopyFromSourceFolder\*' to $($DestinationRootFolder)"
                Start-Sleep 10

                $Confirm_Restore_Files_Created = (Get-ChildItem -Path $($Global:DestinationRootDirectory)).Count

                "=="*25 | Out-File -LiteralPath $Global:LogFile -Append -Force 

                If ($Confirm_Restore_Files_Created -gt 0)
                    {   $Counter = 0

                        Write-LogMessage -Message "Following files copied to the path '$($Global:DestinationRootDirectory)'on local device '$($ENV:ComputerName)'."
                        " " | Out-File -LiteralPath $($Global:LogFile) -Append -Force
                        $All_Child_Items = (Get-ChildItem -Path $($Global:DestinationRootDirectory) | Where-Object {$_.Name -notlike "Track_Win_Device_Last_Rebooted_Status_LogFile.Log"}).Name
                        
                        Foreach ($Item in $All_Child_Items) 
                            {
                                $Counter+=1
                                "[$($Counter)] $($Item)." | Out-File -LiteralPath $($Global:LogFile) -Append -Force
                            }
                    }

                "=="*25 | Out-File -LiteralPath $Global:LogFile -Append -Force 
            }

        Catch 
            {
                Write-LogMessage -Message "An Error occured: $($Error[0])" -Level Error   
            }

        }

Copy-WinDeviceRebootFiles

Function Register-ScheduledTaskFromXML 

    {
        param 
            (
                [Parameter(Mandatory=$True)]
                [string]$XMLFilePath
            )

        Try 
            {
                $NewSchdTask = Register-ScheduledTask -Xml (Get-Content -LiteralPath $($XMLFilePath) | Out-String) -TaskName "Custom_Win_Device_Reboot_GUI_Prompt_TaskSchd" -ErrorAction Stop
                Start-Sleep 30
                If ($($NewSchdTask.Name -eq "Custom_Win_Device_Reboot_GUI_Prompt_TaskSchd") -And $($NewSchdTask.State -eq "Ready"))
                    {
                        Write-LogMessage -LogFile "Successfullly registered task scheduler as: $($NewSchdTask.Name) with state as $($NewSchdTask.State)."
                    }

            } 
        Catch 
            {
                Write-Error "Failed to register the task: $_"
            }
    }

# Example usage
Register-ScheduledTaskFromXML -XMLFilePath "C:\ProgramData\Microsoft\IntuneManagementExtension\Win_Device_Pending_Reboot_GUI\Custom_Win_Device_Reboot_GUI_Prompt_TaskSchd.xml"