<#
.Author - Vishal Navgire
.Created on - 03-April-2025
.Co-Author(s)       - N/A
.Reviwer(s)         - N/A
.Intended Audience  - 
.Target Device Type - Windows Machines. 

.DESCRIPTION 
Deletes folder 'C:\ProgramData\Microsoft\IntuneManagementExtension\Win_Device_Pending_Reboot_GUI' that contains followings files and unregister Task Scheduler as '\Microsoft\Intune\Custom_Win_Device_Reboot_GUI_Prompt_TaskSchd'.
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
#>

Function Remove-TempRebootAndCleanup 
 {
    <#
        .SYNOPSIS
            Recursively deletes the specified folder and its contents, and also deletes a specified Scheduled Task.

        .DESCRIPTION
            This advanced PowerShell function, Remove-TempRebootAndCleanup, safely and robustly
            deletes the target folder 'C:\ProgramData\Microsoft\IntuneManagementExtension\Win_Device_Pending_Reboot_GUI' and all
            files and subfolders within it. 
            It also attempts to delete the Scheduled Task named "Custom_Win_Device_Reboot_GUI_Prompt_TaskSchd". 
    #>

    # Define the target folder path and task name
    $TargetFolder = "C:\ProgramData\Microsoft\IntuneManagementExtension\Win_Device_Pending_Reboot_GUI"
    $SchdTaskName = "Custom_Win_Device_Reboot_GUI_Prompt_TaskSchd"

    # --- Delete the Folder ---

    # Check if the target folder exists
    If (Test-Path -Path $TargetFolder -PathType Container) 
        {
            # Write-Verbose "Attempting to delete '$TargetFolder' and its contents..."

            Try 
                {
                    Remove-Item -Path $TargetFolder -Recurse -Force -ErrorAction Stop
                    Write-Information "Successfully deleted folder '$targetFolder' and all its contents." -Tags "Success"
                }
            Catch 
                {
                    Write-Error "An error occurred while trying to delete folder '$targetFolder': $($_.Exception.Message)"
                    # Optionally log the detailed error to a file
                    # $_.Exception | Out-File -Append "C:\Logs\DeleteTempFolderError.log"
                }
        } 
        
    Else 
        {
            # Write-Warning "Target folder '$targetFolder' does not exist. Skipping folder deletion."
        }

    # --- Delete the Scheduled Task ---

    # Check if the scheduled task exists
    $ScheduledTask = Get-ScheduledTask -TaskName $SchdTaskName
    if ($ScheduledTask) 
        {
            Write-Verbose "Attempting to delete Scheduled Task '$SchdTaskName'..."
            Try 
                {
                    Unregister-ScheduledTask -TaskName $SchdTaskName -Confirm:$false -ErrorAction Stop
                    Start-Sleep 30
                    # Write-Information "Successfully deleted Scheduled Task '$SchdTaskName'." -Tags "Success"
                }
            Catch 
                {
                    Write-Error "An error occurred while trying to delete Scheduled Task '$SchdTaskName': $($_.Exception.Message)"
                    # Optionally log the detailed error to a file
                    # $_.Exception | Out-File -Append "C:\Logs\DeleteScheduledTaskError.log"
                }
        } 
    Else 
        {
            # Write-Warning "Scheduled Task '$SchdTaskName' does not exist. Skipping task deletion."
        }
}

Remove-TempRebootAndCleanup