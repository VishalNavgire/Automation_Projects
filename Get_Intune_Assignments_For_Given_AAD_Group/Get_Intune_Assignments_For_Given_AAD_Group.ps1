<#
.Author         - Vishal Navgire [VishalNavgire54@Gmail.Com]
.Company        - 
.Created on     - 04-Dec-2024
.Co-Author(s)   -
.Reviewer(s)    -  

.Requirement
    1. Microsoft Entra App needs to be registered in to your Tenant first with permission type as 'Delegated'. After you complete App's registration please 
        update App's ID in the line no# 22 👉  $Registered_Entra_App_ID = "App ID". To read more on how to create / register an MS Entra App Id with Delegated rights - https://learn.microsoft.com/en-us/graph/auth-register-app-v2#register-an-application 
    2. Set API Permission - 'DeviceManagementApps.Read.All'. To read more about this API permission - https://learn.microsoft.com/en-us/graph/permissions-reference#devicemanagementappsreadall
    3. Use an account that has Admin rights to run this script on a device.
    4. To interact with Intune's data, log in with an account that has sufficient permissions to read Assignments like Configuration Profiles, Apps, Compliance Policies, etc...

.Description
    Get all types Intune assignments done to a given Azure AD (Microsoft Entra ID) Group.

.Version Control:
04-Dec-2024 :: v1.0
02-Jan-2025 :: v2.0 - Added logic to display all Azure AD / MS Entra ID groups in the tenant and prompt the user to make a intended group's selection.
28-Jan-2025 :: v3.0 -   
                    1. IN PROGRESS :: To Add a logic to process a given user or a device and then fetch all relevant Intune assignment where a given user or a device is a member of.
                    2. Saves HTML report to default director i.e. 'C:\Temp\Intune_Assignment_Reports' with Date&TimeStamp.
                    3. Displays if any Filters used on AAD group for the Win32 App assignments.
#>


Function Set-HostBackgroundColor 
{
    param (
        [Parameter(Mandatory=$true)]
        [string]$Color
    )

    Clear-Host
    $Host.UI.RawUI.BackgroundColor = $Color
    $SetBG_Colour = $Color

    While ($Host.UI.RawUI.BackgroundColor -ne $SetBG_Colour) 
        {
            $Host.UI.RawUI.BackgroundColor = $Color
            Start-Sleep -Seconds 5
        }

    Clear-Host
    Start-Sleep 5
}

Set-HostBackgroundColor -Color "Black"

#Enter valid MS Entra Registered Application ID. 
$Registered_Entra_App_ID = $null

#Global variabled
$GraphApiVersion = "Beta"

# Install MS Graph Intune Module and Connect to MS Graph for Authentication.
Function Install-MSGraphIntuneModule
    {
        [CmdletBinding()]
                param (
                    [Parameter(Mandatory=$false)]
                    [string]$InstallModuleName = "Microsoft.Graph.Intune",
                    
                    [Parameter(Mandatory = $false)]
                    [string]$ApiVersion = "Beta",

                    [Parameter(Mandatory = $false)]
                    $Application_Id = $Registered_Entra_App_ID
                )

        # Clear-Host

        $Module = Get-Module -Name $InstallModuleName -ListAvailable
        $IntuneId = $Null

        If ($Module.Count -eq 0) 
            {
                #Start Logging
                Write-Host  ("-----"*5 + "Powershell code execution started" +"-----"*5 ) -ForegroundColor Green
                Write-Host " "
                Write-Host "Microsoft Intune Graph Module not found. " -NoNewline -ForegroundColor Red
                Write-Host "Required module will be installed to device '$($Env:COMPUTERNAME)'. Installing '$InstallModuleName' module, please wait...." -ForegroundColor Yellow

                Try 
                    {
                        Install-Module -Name $InstallModuleName -Repository PSGallery -Force -ErrorAction Stop
                        "`n"
                        Write-Host "Enter your credentials to connect to Microsoft Intune..." -ForegroundColor Cyan
                        "`n"
                        Update-MSGraphEnvironment -AppId $($Application_Id) -SchemaVersion $ApiVersion -Quiet -ErrorAction Stop
                        $IntuneId = Connect-MSGraph -ErrorAction Stop
                        $TenantId = ($IntuneId.TenantId).ToUpper()
                        If (![string]::IsNullOrEmpty($IntuneId)) 
                            {
                                Write-Host "Connected to Microsoft Tenant ID $TenantId using $($IntuneId.UPN)" -ForegroundColor Green
                                "`n"
                            }
                        Else 
                            {
                                Write-Host "Connection to Microsoft Intune Tenant ID $TenantId failed on device '$($Env:COMPUTERNAME)'. Try again..." -ForegroundColor Red
                                "`n"
                                $($Error.Exception.Message)
                                "`n"
                                $(Write-Host "Press ENTER key to exit from PowerShell console!!!" -ForegroundColor Red; Read-Host)
                                Exit
                            }

                    } 
                Catch 
                    {
                        Write-Host "Failed to install module name: $InstallModuleName." -ForegroundColor Red
                        "`n"
                        Write-Host "Error Details: $($_.Exception.Message)" -ForegroundColor Yellow
                        $(Write-Host "Press ENTER key to exit from PowerShell console!!!" -ForegroundColor Yellow; Read-Host)
                        Exit
                    }
            }
        
        Elseif ($Module.Count -eq 1) 
            {
                #Start Logging
                Write-Host  ("-----"*5 + "Powershell code execution started" +"-----"*5 ) -ForegroundColor Green
                Write-Host " "
                Try 
                    {
                            "`n"
                            Write-Host "Enter your credentials to connect to Microsoft Intune..." -ForegroundColor Cyan
                            "`n"
                            Update-MSGraphEnvironment -AppId $($Application_Id) -SchemaVersion $ApiVersion -Quiet -ErrorAction Stop
                            $IntuneId = Connect-MSGraph -ErrorAction Stop
                            $TenantId = ($IntuneId.TenantId).ToUpper()
                        If (![string]::IsNullOrEmpty($IntuneId)) 
                            {
                                Write-Host "Connected to Microsoft Tenant ID $TenantId using $($IntuneId.UPN)" -ForegroundColor Green
                                "`n"
                            }
                        Else 
                            {
                                Write-Host "Connection to Microsoft Intune Tenant ID $TenantId failed on device '$($Env:COMPUTERNAME)'. Try again..." -ForegroundColor Red
                                "`n"
                                $($Error.Exception.Message)
                                "`n"
                                $(Write-Host "Press ENTER key to exit from PowerShell console!!!" -ForegroundColor Red; Read-Host)
                                Exit
                            }

                    }
                Catch 
                    {
                        Write-Host "Connection to Microsoft Intune Tenant ID $TenantId failed on device $($Env:COMPUTERNAME). Try again..." -ForegroundColor Yellow
                        "`n"
                        Write-Host "Error Details: $($_.Exception.Message)" -ForegroundColor Red
                        $(Write-Host "Press ENTER key to exit from PowerShell console!!!" -ForegroundColor Yellow; Read-Host)
                        Exit
                    }
            }

            Return $IntuneId
    }

#Install-MSGraphIntuneModule
$Capture_UserLogin_And_Tenant_ID = Install-MSGraphIntuneModule

Write-Host "`n"

#Check to ensure valid AAD group name is entered, else prompt re-appears asking to enter valid AAD group name. 
$GroupName = "" # Initialize $GroupName to an empty string to enter the loop

# Start the while loop
While ([string]::IsNullOrEmpty($GroupName)) 
  {
    # Prompt for the AAD group name
    #$GroupName = $(Write-Host "Enter Azure AD (Microsoft Entra ID) Group Name here without single or double qoutes and Press Enter Key:" -f White; Read-Host)
    Write-Host "Search and Select Azure AD (Microsoft Entra ID) Group Name from the displayed list on screen and Press OK:" -f White
    Write-Host "`n"
    Start-Sleep 5

    # Check if the group name is valid
    $Valid_AAD_Group_Check = (Get-AADGroup | Select-Object -Property @{Name="Azure AD / MS Entra ID Groups"; Expression={$_.DisplayName}})."Azure AD / MS Entra ID Groups" | Sort-Object -Property "Azure AD / MS Entra ID Groups" | Out-GridView -Title "Connected to Tenant ID: '$TenantId' using '$($IntuneId.UPN)'. Please search and select AAD group name from the displayed list: " -PassThru

    #Valid_AAD_Group_Check =  
    If ([string]::IsNullOrEmpty($Valid_AAD_Group_Check)) 
      {
        Write-Host "You selected Azure AD group name as: $($GroupName) which is not valid." -F Red
        Write-Host "`n"

        # Clear $GroupName to ensure the loop continues
        $GroupName = "" 
      } 

    Else 
      {
            $GroupName = $Valid_AAD_Group_Check
            $Group = Get-AADGroup -Filter "displayname eq '$GroupName'"
            $GroupId = $($Group.id).ToUpper()
            Write-host "You are querying Intune's Assignment for Azure AD (Microsoft Entra ID) Group Name: '$($Group.displayName)' whose Azure AD (Microsoft Entra ID) Group ID is : '$($GroupId)' ." -ForegroundColor Yellow
            Write-Host "`n"

      }
  }

#Creates a default directory to save HTML report.
Function Set-IntuneReportsFolder
    {
        <#
            .SYNOPSIS
            Creates a folder for storing Intune assignment report.

            .DESCRIPTION
            Creates a folder for storing Intune assignment report.
        #>

        [CmdletBinding()]
            param 
                (
                    [Parameter(Mandatory = $False)]
                    [string]$BasePath = "C:\Temp",

                    [Parameter(Mandatory = $False)]
                    [string]$BackupNamePrefix = "Intune_Assignment_Reports"
                )

        Try 
            {
                # Ensure the base path exists or create it
                    If (!(Test-Path -Path $BasePath)) 
                        {
                            New-Item -ItemType Directory -Path $BasePath -ErrorAction Stop | Out-Null
                            # Write-Verbose "Base path created: $BasePath"
                        }
                    Else 
                        {
                            $Null
                        }

                # Create the full path for the new folder
                $NewFolderPath = Join-Path -Path $($BasePath) -ChildPath $($BackupNamePrefix)

                # Check if the folder already exists
                If (!(Test-Path -Path $NewFolderPath)) 
                    {
                        New-Item -ItemType Directory -Path $NewFolderPath | Out-Null
                        # Write-Output "Backup folder created: $NewFolderPath"
                    }
                Else 
                    {
                        $Null
                    }

                # Return the created folder path
                Return $NewFolderPath
            } 
        Catch 
            {
                Write-Error "An error occurred: $_"
                throw
                Write-Host "`n"
                Write-Host "This Powershell session will terminate. Please fix the error and re-run the code." -F Red
                Start-Sleep 5
                Write-Host "`n"
                Exit
            }
    }

#Check if the dedicated folder to save HTML report is present or not.
If ([string]::IsNullOrEmpty($(Set-IntuneReportsFolder))) 
    {
        Write-Error "There is a no folder path 'C:\Temp\Intune_Assignment_Reports' to save HTML Report !!!"
        Start-Sleep 5
        Exit
        
    }
Else 
    {
        $Location_To_Save_HTML_Report = 'C:\Temp\Intune_Assignment_Reports'
    }

# Get the current date and time
$CurrentDateTime = Get-Date

#HTML File Name 
$HTML_FileName = "\Intune_Assigments_For_GroupName_'$($GroupName)'_$($CurrentDateTime.ToString("dd_MMM_yyyy_hh_mm_ss_tt")).HTML"

# Create the full path for the new folder
$ActualHTMLReportFolderPath = Join-Path -Path $($Location_To_Save_HTML_Report) -ChildPath $($HTML_FileName)

Write-Host ("=" * 80) -F Yellow
Write-Host "HTML report will be saved to 'C:\Temp\Intune_Assignment_Reports' ." -f White
Write-Host "`n"
Write-Host "HTML Report's Full File path is '$($ActualHTMLReportFolderPath)' ." -f Magenta
Write-Host "`n"
Write-Host ("=" * 80) -F Yellow

#########################

    # Add Logic to check with code implementer to know if they wish to retrieve Data for an USER; Device Or AAD Group.

#########################

Function Get-IntuneFilterDisplayName 
    {
        <#
            .SYNOPSIS
            Retrieves the display name(s) of Intune filters using MS Graph API.

            #>

            [CmdletBinding()]
            Param 
                (
                    [Parameter(Mandatory = $False)]
                    [ValidateSet("v1.0", "Beta")]
                    [string]$ApiVersion = "Beta", 

                    [Parameter(Mandatory = $False)]
                    [string]$AssignFilterURL = "https://graph.microsoft.com/$($ApiVersion)/deviceManagement/assignmentFilters",

                    [Parameter(Mandatory = $False)]
                    [ValidateSet("GET", "POST", "PATCH", "DELETE")]
                    [string]$HTTPMethod = "GET",

                    [Parameter(Mandatory = $True)]
                    [string]$IntuneFilterID


                )


                Try 
                    {
                        $IntunFilter_DisplayName = Invoke-MSGraphRequest -Url $($AssignFilterURL+"/$($IntuneFilterID)") -HttpMethod $($HTTPMethod)

                        Return $IntunFilter_DisplayName.DisplayName
                        
                    }
                Catch 
                    {
                        Write-Error "An error occurred while retrieving Intune filter display name: $_"
                        throw

                    }
    }

# # # # # # # # # # # # # # # # # # # # # 
#                                       #
#   Retrieve Application deployments    #
#                                       #
# # # # # # # # # # # # # # # # # # # # # 
$Win32_Apps_Resource = "DeviceAppManagement/MobileApps"
$Uri = "https://graph.microsoft.com/Beta/$($Win32_Apps_Resource)?`$expand=assignments"
$Win32AppDeployment = Try {
                            Invoke-MSGraphRequest -HttpMethod GET -Url $Uri -ErrorAction Stop | Get-MSGraphAllPages
                          } 
                    Catch {
                            # Display error message
                            Write-Host "Error occurred while checking for Win32 Intune Apps :" -ForegroundColor Red
                            Write-Host "`n"
                            If (![string]::IsNullOrEmpty($Error[0].ToString()))
                                {
                                    Write-Host "URL:" $Error[0].TargetObject.Request.URL -ForegroundColor Yellow
                                    Write-Host "HTTP Status Code:" $Error[0].TargetObject.Response.HttpStatusCode -ForegroundColor Yellow
                                    Write-Host "HTTP Status Phrase:" $Error[0].TargetObject.Response.HttpStatusPhrase -ForegroundColor Yellow
                                } 
                            Else {
                                     Write-Host "An unexpected error occurred." -ForegroundColor Yellow
                                }
                        }


#Array to hold all data processed
$AllWin32AppDeployments = @()

$AllWin32AppDeployments += $Win32AppDeployment | Where-Object {$_.assignments -match $GroupID} | ForEach-Object {
                                                                                                                        $Name = $_
                                                                                                                        [PSCustomObject] @{

                                                                                                                                    Name           = ($Name.DisplayName).ToUpper()
                                                                                                                                    App_Type       = (($Name."@odata.type").Substring(17)).ToUpper()
                                                                                                                                    Version        = ($Name.DisplayVersion)
                                                                                                                                    Id             = ($Name.Id).ToUpper()
                                                                                                                                    LastUpdatedDateTime = ($Name.LastModifiedDateTime)
                                                                                                                                    Assignments     = ($Name.Assignments.Target) | Where-Object {$_.GroupID  -eq $GroupID -And ($_.'@odata.type' -Eq "#microsoft.graph.groupAssignmentTarget" -OR $_.'@odata.type' -Ne "#microsoft.graph.groupAssignmentTarget")}
                                                                                                                                    Intent          = (($Name.Assignments | Where-Object {$_.ID  -match $GroupID})).Intent.ToUpper()

                                                                                                                                }
                                                                                                                    }
If ($AllWin32AppDeployments.Count -gt 0) 
    {
        Write-Host "Gathering details for Intune Application's Assignment...." -F Gray
        Write-Host "`n"

        $Final_AllWin32AppDeployments = @()

        # Finalize processed data
        Foreach ($Each_Win32_App in $AllWin32AppDeployments) 
            {
                Try 
                    {
                        $AppAssigned = If ($Each_Win32_App.Assignments.'@odata.type' -eq "#microsoft.graph.groupAssignmentTarget") 
                                            {
                                                "Inclusion"
                                            } 
                                        Else 
                                            {
                                                "Exclusion"
                                            }
                                        
                        $FilterIDCheck = Try {$(Get-IntuneFilterDisplayName -IntuneFilterID $($Each_Win32_App.Assignments.deviceAndAppManagementAssignmentFilterId))} Catch {$null}
                        $Filter_Name = If ($FilterIDCheck)
                                                {
                                                    $FilterIDCheck
                                                }
                                        Else 
                                            {
                                                "NONE"
                                            }

                        $Filter_ID = If ($FilterIDCheck)
                                            {
                                                ($Each_Win32_App.Assignments.deviceAndAppManagementAssignmentFilterId)
                                            }
                                    Else 
                                        {
                                            "NONE"
                                        }
                
                        $Final_AllWin32AppDeployments += [PSCustomObject] @{
                                                                            App_Name              = $Each_Win32_App.Name
                                                                            App_Type              = $Each_Win32_App.App_Type
                                                                            App_Version           = $Each_Win32_App.Version
                                                                            App_Intent            = $Each_Win32_App.Intent
                                                                            App_Id                = $Each_Win32_App.Id
                                                                            App_LastUpdatedDateTime = $Each_Win32_App.LastUpdatedDateTime
                                                                            App_Assigned          = $AppAssigned
                                                                            Filter_Name           = $Filter_Name
                                                                            Filter_ID             = $Filter_ID
                                                                            Filter_Type           = $($Each_Win32_App.Assignments.deviceAndAppManagementAssignmentFilterType)
                                                                        }
                                                                    } 
                Catch 
                    {
                        Write-Error "Error processing app: $($_.Exception.Message)"
                    }
            }
        
        If ($Final_AllWin32AppDeployments.Count -gt 0)
            {
                Write-Host "Gathering details for Intune Application's Assignment completed." -F Green
                Write-Host "`n"
            }

    }
Else 
    {
        Write-Host "No Win32 Application assignment found." -F Magenta
        Write-Host "`n"
    }
Write-Host ("------"*20)
# # # # # # # # # # # # # # # # # # # # # # # # 
#                                             #
#  Device Configuration Profile Assignments   #
#                                             #
# # # # # # # # # # # # # # # # # # # # # # # #

$Device_Config_Profile_Resource = "deviceManagement/deviceConfigurations"
$DeviceConfigProfileUri = "https://graph.microsoft.com/$graphApiVersion/$($Device_Config_Profile_Resource)?`$expand=groupAssignments"
$AllDeviceConfigProfiles = Try {(Invoke-MSGraphRequest -HttpMethod GET -Url $DeviceConfigProfileUri -ErrorAction Stop).Value | Where-Object {$_.Groupassignments -match $Group.id}}
                          Catch {
                                # Display error message
                                Write-Host "Error occurred while checking for Intune's Device Configuration Profiles :" -ForegroundColor Red
                                Write-Host "`n"
                                If (![string]::IsNullOrEmpty($Error[0].ToString()))
                                    {
                                        Write-Host "URL:" $Error[0].TargetObject.Request.URL -ForegroundColor Yellow
                                        Write-Host "HTTP Status Code:" $Error[0].TargetObject.Response.HttpStatusCode -ForegroundColor Yellow
                                        Write-Host "HTTP Status Phrase:" $Error[0].TargetObject.Response.HttpStatusPhrase -ForegroundColor Yellow
                                    } 
                                Else {
                                        Write-Host "An unexpected error occurred." -ForegroundColor Yellow
                                    }
                            }


If (($AllDeviceConfigProfiles.Count) -gt 0)
    {

        #Array to hold all data processed
        $DeviceConfig_Profile_Assignments = @()

        Write-Host "Gathering details for Device Configuration Profile Assignment...." -F Gray
        Write-Host "`n"
        Foreach ($DeviceConfig in $AllDeviceConfigProfiles)
        {
            Try 
                    {
                        If ($DeviceConfig.Groupassignments | Where-Object { $_.ExcludeGroup -Eq $False -and $_.TargetGroupId -match $($Group.id)})
                                {
                                    $DeviceConfig_Profile_Assignments  += 
                                    [PSCustomObject] @{
                                        DisplayName = ($DeviceConfig.DisplayName).ToUpper()
                                        DeviceConfigurations_ID = ($DeviceConfig.Id).ToUpper()
                                        Description = ($DeviceConfig.Description).ToUpper()
                                        LastModifiedDateTime = $DeviceConfig.lastModifiedDateTime
                                        Entity_Type = ($DeviceConfig.'@odata.type').ToUpper()
                                        Assingment_Type = "Inclusion"
    
                                    }
    
                                }
                        ElseIf($DeviceConfig.Groupassignments | Where-Object { $_.ExcludeGroup -Eq $True -and $_.TargetGroupId -match $($Group.id)})
                                {
                                    $DeviceConfig_Profile_Assignments += 
                                    [PSCustomObject] @{
                                        DisplayName = ($DeviceConfig.DisplayName).ToUpper()
                                        DeviceConfigurations_ID = ($DeviceConfig.Id).ToUpper()
                                        Description = ($DeviceConfig.Description).ToUpper()
                                        LastModifiedDateTime = $DeviceConfig.lastModifiedDateTime
                                        Entity_Type = ($DeviceConfig.'@odata.type').ToUpper()
                                        Assingment_Type = "Exclusion"
                                    }
                                }
    
                    }
            Catch 
                    {
                                If ($DeviceConfig.Groupassignments | Where-Object { $_.ExcludeGroup -Eq $False -and $_.TargetGroupId -match $($Group.id)})
                                {
                                    $DeviceConfig_Profile_Assignments  += 
                                    [PSCustomObject] @{
                                        DisplayName = ($DeviceConfig.DisplayName).ToUpper()
                                        DeviceConfigurations_ID = ($DeviceConfig.Id).ToUpper()
                                        #Description = ($DeviceConfig.Description).ToUpper()
                                        LastModifiedDateTime = $DeviceConfig.lastModifiedDateTime
                                        Entity_Type = ($DeviceConfig.'@odata.type').ToUpper()
                                        Assingment_Type = "Inclusion"
    
                                    }
    
                                }
                        ElseIf($DeviceConfig.Groupassignments | Where-Object { $_.ExcludeGroup -Eq $True -and $_.TargetGroupId -match $($Group.id)})
                                {
                                    $DeviceConfig_Profile_Assignments += 
                                    [PSCustomObject] @{
                                        DisplayName = ($DeviceConfig.DisplayName).ToUpper()
                                        DeviceConfigurations_ID = ($DeviceConfig.Id).ToUpper()
                                        #Description = ($DeviceConfig.Description).ToUpper()
                                        LastModifiedDateTime = $DeviceConfig.lastModifiedDateTime
                                        Entity_Type = ($DeviceConfig.'@odata.type').ToUpper()
                                        Assingment_Type = "Exclusion"
                                    }
                                }
    
                    }
        }

        If (($DeviceConfig_Profile_Assignments.Count) -gt 0)
            {
                Write-Host "Gathering details for Device Configuration Profile Assignment completed." -F Green
                Write-Host "`n"
            }

    }

Else 
    {
        Write-Host "No Device Configuration Profile Assignments found." -F Magenta
        Write-Host "`n"
    }
Write-Host ("------"*20)


    # # # # # # # # # # # # # # # # # # # # # # # # 
    #                                             #
    #   Device Compliance Policy Assignments      #
    #                                             #
    # # # # # # # # # # # # # # # # # # # # # # # #
$AllDeviceCompliance = Get-IntuneDeviceCompliancePolicy -Select id, Description, displayName, lastModifiedDateTime, assignments -Expand assignments | Where-Object {$_.assignments -match $Group.id -AND $_."@odata.type" -Like "*#microsoft.graph.windows*"}

If (($AllDeviceCompliance | Measure-Object).Count -gt 0)
    {
        #Array to hold all data processed
        $DeviceCompliance_Status = @()

        Write-Host "Gathering details for Device Compliance Policy Assignment...."  -F Gray
        Write-Host "`n"

        Foreach ($Compliance in $AllDeviceCompliance) 
            {
                    If (($Compliance.assignments.Target | Where-Object { $_.'@odata.type' -Eq '#microsoft.graph.groupAssignmentTarget' -and $_.groupId -match $($Group.id)}))
                            {
                                $DeviceCompliance_Status += [PSCustomObject] @{ 
                                    DisplayName = ($Compliance.DisplayName).ToUpper()
                                    CompliancePolicy_ID = ($Compliance.Id).ToUpper()
                                    Description = If ([string]::IsNullOrEmpty($Compliance.Description)) { "Nothing To Show" } Else {($Compliance.Description.ToUpper())}
                                    LastModifiedDateTime = $Compliance.lastModifiedDateTime
                                    Entity_Type = ($Compliance.'@odata.type').ToUpper()
                                    Assingment_Type = "Inclusion" }
                            }
                    ElseIf (($Compliance.assignments.Target | Where-Object { $_.'@odata.type' -Ne '#microsoft.graph.groupAssignmentTarget' -and $_.groupId -match $($Group.id)}))
                            {
                                $DeviceCompliance_Status += [PSCustomObject] @{ 
                                    DisplayName = ($Compliance.DisplayName).ToUpper()
                                    CompliancePolicy_ID = ($Compliance.Id).ToUpper()
                                    Description = If ([string]::IsNullOrEmpty($Compliance.Description)) { "Nothing To Show" } Else {($Compliance.Description.ToUpper())} #($Compliance.Description).ToUpper()
                                    LastModifiedDateTime = $Compliance.lastModifiedDateTime
                                    Entity_Type = ($Compliance.'@odata.type').ToUpper()
                                    Assingment_Type = "Exclusion"}

                            }
            }

        If (($DeviceCompliance_Status.Count) -gt 0)
            {
                Write-Host "Gathering details for Device Compliance Policy Assignment completed. "  -F Green
                Write-Host "`n"
            }

    }
Else 
    {
        Write-Host "No Device Compliance Assignment found." -F Magenta
        Write-Host "`n"
    }

Write-Host ("------"*20)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                                                               #
#  Device Configuration Profile Settings Catalog Assignments    #
#                                                               #
# # # # # # # # # # # # # # # # # # # # # # # # # # # ## # # # #

$Device_Config_Profile_Settings_Catalog_Resource = "deviceManagement/configurationPolicies"
$uri = "https://graph.microsoft.com/$graphApiVersion/$($Device_Config_Profile_Settings_Catalog_Resource)?`$expand=Assignments"
$SettingsCatalog = Try {Invoke-MSGraphRequest -HttpMethod GET -Url $uri -ErrorAction Stop}
                    Catch {
                        # Display error message
                        Write-Host "Error occurred while checking for Device Config Profile Settings Catalog :" -ForegroundColor Red
                        Write-Host "`n"
                                If (![string]::IsNullOrEmpty($Error[0].ToString()))
                                    {
                                        Write-Host "URL:" $Error[0].TargetObject.Request.URL -ForegroundColor Yellow
                                        Write-Host "HTTP Status Code:" $Error[0].TargetObject.Response.HttpStatusCode -ForegroundColor Yellow
                                        Write-Host "HTTP Status Phrase:" $Error[0].TargetObject.Response.HttpStatusPhrase -ForegroundColor Yellow
                                    } 
                                Else {
                                        Write-Host "An unexpected error occurred." -ForegroundColor Yellow
                                    }
                    }

If (($SettingsCatalog.Value.Count) -gt 0)
    {
        Write-Host "Gathering details for Device Config Profile Settings Catalog Assignment...." -F Gray
        Write-Host "`n"
        #Array to hold all data processed
        $AllDeviceConfigSettingsCatalog_Included = @()

        While ($SettingsCatalog.'@odata.nextLink')
                {
                    $AllDeviceConfigSettingsCatalog_Included += $SettingsCatalog.value | Where-Object {$_.assignments -match $Group.id} | ForEach-Object {
                        $Name = $_
                        [PSCustomObject] @{
                                    Name           = ($Name.Name).ToUpper()
                                    Id             = ($Name.Id).ToUpper()
                                    Description    = ($Name.Description).ToUpper()
                                    LastUpdatedDateTime = ($Name.LastModifiedDateTime)
                                    Assignments = ($Name.Assignments.Target) | Where-Object {$_.GroupID  -eq $Group.id -And ($_.'@odata.type' -Eq "#microsoft.graph.groupAssignmentTarget" -OR $_.'@odata.type' -Ne "#microsoft.graph.groupAssignmentTarget")}

                                }
                    }
                    # Get the next page of results
                    $SettingsCatalog = Invoke-MSGraphRequest -HttpMethod GET -Url $SettingsCatalog.'@odata.nextLink'
                }

        # Process the last page (if any)
        $AllDeviceConfigSettingsCatalog_Included += $SettingsCatalog.value | Where-Object {$_.assignments -match $Group.id} | ForEach-Object {
                    $Name = $_ 
                    [PSCustomObject] @{
                        Name           = ($Name.Name).ToUpper()
                        Id             = ($Name.Id).ToUpper()
                        Description    = ($Name.Description).ToUpper()
                        LastUpdatedDateTime = ($Name.LastModifiedDateTime)
                        Assignments = ($Name.Assignments.Target) | Where-Object {$_.GroupID  -eq $Group.id -And ($_.'@odata.type' -Eq "#microsoft.graph.groupAssignmentTarget" -OR $_.'@odata.type' -Ne "#microsoft.graph.groupAssignmentTarget")}
                    }
                }
        #Write-host "Total Number of Device Config Profile Settings Catalog Assignment/s found is: $($AllDeviceConfigSettingsCatalog_Included.Name.Count)." -ForegroundColor cyan
        #$AllDeviceConfigSettingsCatalog_Included

        $Final_Device_Setting_Catalogs = @()
        Foreach ($Device_Setting_Catalog in $AllDeviceConfigSettingsCatalog_Included)
                    {
                        If ($Device_Setting_Catalog.Assignments.'@odata.type' -Eq "#microsoft.graph.groupAssignmentTarget" )
                        {
                            $Final_Device_Setting_Catalogs += [PSCustomObject] @{
                                ProfileName = $Device_Setting_Catalog.Name
                                ProfileName_Id = $Device_Setting_Catalog.Id
                                ProfileName_Description = $Device_Setting_Catalog.Description
                                ProfileName_LastUpdatedDateTime = $Device_Setting_Catalog.LastUpdatedDateTime
                                Assigned = "True"
                            }
                        }

                        Else 
                        {
                                    $Final_Device_Setting_Catalogs += [PSCustomObject] @{
                                        ProfileName = $Device_Setting_Catalog.Name
                                        ProfileName_Id = $Device_Setting_Catalog.Id 
                                        ProfileName_Description = $Device_Setting_Catalog.Description
                                        ProfileName_LastUpdatedDateTime = $Device_Setting_Catalog.LastUpdatedDateTime
                                        Assigned = "False"
                                }
                    
                            }
                    }

        If (($Final_Device_Setting_Catalogs.Count) -gt 0) 
            {
                Write-Host "Gathering details for Device Config Profile Settings Catalog Assignment completed." -F Green
                Write-Host "`n"
            }
    }

Else 
    {
        Write-Host "No Device Config Profile Settings Catalog Assignment found." -F Magenta
        Write-Host "`n"
    }

Write-Host ("------"*20)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
#                                                                    #
#  Device Configuration Profile Administrative Templates Assignments #
#                                                                    #
# # # # # # # # # # # # # # # # # # # # # # # # # # # ## # # # # # # #

$Device_Config_Admmin_Template_Resource = "deviceManagement/groupPolicyConfigurations"
$uri = "https://graph.microsoft.com/$graphApiVersion/$($Device_Config_Admmin_Template_Resource)?`$expand=Assignments"
$AdmTemplates = Try {Invoke-MSGraphRequest -HttpMethod GET -Url $uri -ErrorAction Stop}

                Catch {
                    # Display error message
                    Write-Host "Error occurred while checking for Device Configuration Administrative templates :" -ForegroundColor Red
                    Write-Host "`n"
                    If (![string]::IsNullOrEmpty($Error[0].ToString()))
                        {
                            Write-Host "URL:" $Error[0].TargetObject.Request.URL -ForegroundColor Yellow
                            Write-Host "HTTP Status Code:" $Error[0].TargetObject.Response.HttpStatusCode -ForegroundColor Yellow
                            Write-Host "HTTP Status Phrase:" $Error[0].TargetObject.Response.HttpStatusPhrase -ForegroundColor Yellow
                        } 
                    Else {
                            Write-Host "An unexpected error occurred." -ForegroundColor Yellow
                        }
                }

$AdmTemplates_Value = $AdmTemplates.value | Where-Object {$_.assignments -match $Group.id}

If (($AdmTemplates_Value.Count) -gt 0)
    {
        
        Write-Host "Gathering Details of Device Config Administrative Template Assignment...."  -F Gray
        Write-Host "`n"
        #Array to hold all data processed
        $AllAdmTemplates = @()

        Foreach ($EachAdmTemplate in $AdmTemplates_Value) 
            {
            
                $AllAdmTemplates += $AdmTemplates_Value | Where-Object {$_.assignments -match $Group.id} | ForEach-Object {
                                    $Name = $_
                                    [PSCustomObject] @{
                                                Name           = ($Name.DisplayName).ToUpper()
                                                Description        = ($Name.description).ToUpper()
                                                Id             = ($Name.Id).ToUpper()
                                                LastUpdatedDateTime = ($Name.LastUpdatedDateTime)
                                                Assignments = ($Name.Assignments.Target) | Where-Object {$_.GroupID  -eq $Group.id -And ($_.'@odata.type' -Eq "#microsoft.graph.groupAssignmentTarget" -OR $_.'@odata.type' -Ne "#microsoft.graph.groupAssignmentTarget")}
                    
                                            }
                                }

            }

        $Final_Admin_Templates = @()

        Foreach ($Each_Adm_Template in $AllAdmTemplates)
                        {
                            Try 
                                {
                                    If ($Each_Adm_Template.Assignments.'@odata.type' -Eq "#microsoft.graph.groupAssignmentTarget" )
                                        {
                                            $Final_Admin_Templates += [PSCustomObject] @{
                                                Adm_Template_Name = $Each_Adm_Template.Name
                                                Adm_Template_Id = $Each_Adm_Template.Id 
                                                Adm_Template_Description = $Each_Adm_Template.Description
                                                #Win32_App_Install_Type = $Each_Win32_App.Install_Type
                                                Adm_Template_LastUpdatedDateTime = $Each_Win32_App.LastUpdatedDateTime
                                                Adm_Template_Assigned = "Inclusion"
                                            }
                                        }
                    
                                    Else 
                                    {
                                        $Final_Admin_Templates += [PSCustomObject] @{
                                            Adm_Template_Name = $Each_Adm_Template.Name
                                            Adm_Template_Id = $Each_Adm_Template.Id 
                                            Adm_Template_Description = $Each_Adm_Template.Description
                                            #Win32_App_Install_Type = $Each_Win32_App.Install_Type
                                            Adm_Template_LastUpdatedDateTime = $Each_Win32_App.LastUpdatedDateTime
                                            Adm_Template_Assigned = "Exclusion" 
                                            }
                                
                                        }
                                }
                            Catch 
                                {
                                    Write-Output $Error.Exception[0].Message
                                }
                        }
        If ($Final_Admin_Templates.Count -gt 0)
            {
                Write-Host "Gathering Details for Device Config Administrative Template Assignment completed."  -F Green
                Write-Host "`n"
            }
    }
Else 
    {
        Write-Host "No Device Configuration Administrative Templates Assignment found." -F Magenta
        Write-Host "`n"
    }

Write-Host ("------"*20)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
#                                                                    #
#             Intune Powershell Scripts Assignments                  #
#                                                                    #
# # # # # # # # # # # # # # # # # # # # # # # # # # # ## # # # # # # #

 # ********* Platform scripts in Intune are a way to use PowerShell scripts to manage and configure Windows devices *********. Working Code- Update HTML report to include this Info

 $Platform_Scripts_Resource = "deviceManagement/deviceManagementScripts"
 $uri = "https://graph.microsoft.com/$GraphApiVersion/$($Platform_Scripts_Resource)?`$expand=Assignments"
 $Platform_Script = Try {Invoke-MSGraphRequest -HttpMethod GET -Url $uri -ErrorAction Stop}
                    Catch {
                        # Display error message
                        Write-Host "Error occurred while checking for Platform Scripts :" -ForegroundColor Red
                        Write-Host "`n"
                        If (![string]::IsNullOrEmpty($Error[0].ToString()))
                            {
                                Write-Host "URL:" $Error[0].TargetObject.Request.URL -ForegroundColor Yellow
                                Write-Host "HTTP Status Code:" $Error[0].TargetObject.Response.HttpStatusCode -ForegroundColor Yellow
                                Write-Host "HTTP Status Phrase:" $Error[0].TargetObject.Response.HttpStatusPhrase -ForegroundColor Yellow
                            } 
                        Else {
                                Write-Host "An unexpected error occurred." -ForegroundColor Yellow
                            }
                    }
                        
 $All_Platform_Scripts = $Platform_Script | Get-MSGraphAllPages | Where-Object {$_.Assignments -match $Group.id}
 
 
 If (($All_Platform_Scripts.count) -gt 0)
     {
          #Array to hold all data processed
         $Platform_Scripts_Assignments = @()

         Write-Host "Gathering Details for Platform Scripts Assgnment...." -F Gray
         Write-Host "`n"
 
         Foreach ($Each_Platform_Script in $All_Platform_Scripts)
             {
                $Platform_Scripts_AssignmentType = ""

                    # Determine the Assignment Type
                If ($Each_Platform_Script.assignments.Target | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $_.groupId -match $GroupId }) 
                    {
                        $Platform_Scripts_AssignmentType = "Inclusion"
                    }
                ElseIf ($Each_Platform_Script.assignments.Target | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget' -and $_.groupId -match $GroupId }) 
                    {
                        $Platform_Scripts_AssignmentType = "Exclusion"
                    } 
                Else
                    {
                        $Platform_Scripts_AssignmentType = $Each_HealthScript.assignments.Target.'@odata.type'
                    }

                 $Platform_Scripts_Assignments +=
                             [PSCustomObject] @{
                                 DisplayName = ($Each_Platform_Script.DisplayName).ToUpper()
                                 Id          = ($Each_Platform_Script.Id).ToUpper()
                                 Description = If ([string]::IsNullOrEmpty($Each_HealthScript.Description)) { "Nothing To Show" } Else { ($Each_Platform_Script.Description).ToUpper()}
                                 Last_Modified_DateTime = $Each_Platform_Script.lastModifiedDateTime
                                 RunAsAccount = ($Each_Platform_Script.RunAsAccount).ToUpper()
                                 Assignment_Type        = $($Platform_Scripts_AssignmentType)
                             }
             }
        If ($Platform_Scripts_Assignments.count -gt 0)
            {
                Write-Host "Gathering Details for Platform Scripts Assgnment completed." -F Green
                Write-Host "`n"
            }
 
     }
 Else 
     {
         Write-Host "No Platform Code Assignment found." -F Magenta
         Write-Host "`n"
     }

Write-Host ("------"*20)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
#                                                                    #
#      Intune Powershell Remediation Scripts Assignments             #
#                                                                    #
# # # # # # # # # # # # # # # # # # # # # # # # # # # ## # # # # # # #

# *********Health (Remediation) Scripts********* Working Code - Update HTML report to include this Info.
$HealthScripts_Resource = "deviceManagement/deviceHealthScripts"
$uri = "https://graph.microsoft.com/$GraphApiVersion/$($HealthScripts_Resource)?`$expand=Assignments"
$PsScripts = Try {Invoke-MSGraphRequest -HttpMethod GET -Url $uri -ErrorAction Stop}
                Catch {
                    # Display error message
                    Write-Host "Error occurred while checking for Health (Proactive Remediation) Scripts :" -ForegroundColor Red
                    Write-Host "`n"
                    If (![string]::IsNullOrEmpty($Error[0].ToString()))
                        {
                            Write-Host "URL:" $Error[0].TargetObject.Request.URL -ForegroundColor Yellow
                            Write-Host "HTTP Status Code:" $Error[0].TargetObject.Response.HttpStatusCode -ForegroundColor Yellow
                            Write-Host "HTTP Status Phrase:" $Error[0].TargetObject.Response.HttpStatusPhrase -ForegroundColor Yellow
                        } 
                    Else {
                            Write-Host "An unexpected error occurred." -ForegroundColor Yellow
                        }
                }

$All_Health_Scripts = $PsScripts | Get-MSGraphAllPages | Where-Object {$_.Assignments -match $Group.id}

# Write-host "Total Number of Powershell Scripts found is: $($AllPSScripts.DisplayName.Count)." -ForegroundColor cyan

If (($All_Health_Scripts.count) -gt 0)
    {
         #Array to hold all data processed
        $Health_Scripts_Assignments = @()

        Write-Host "Gathering Details of Health (Proactive Remediation) Scripts Assignment...." -F Gray
        Write-Host "`n"

        Foreach ($Each_HealthScript in $All_Health_Scripts)
            {

               $AssignmentType = ""

               # Determine the Assignment Type
               If ($Each_HealthScript.assignments.Target | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget' -and $_.groupId -match $GroupId }) 
                   {
                       $AssignmentType = "Inclusion"
                   }
               ElseIf ($Each_HealthScript.assignments.Target | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget' -and $_.groupId -match $GroupId }) 
                   {
                       $AssignmentType = "Exclusion"
                   } 
               Else
                   {
                       $AssignmentType = $Each_HealthScript.assignments.Target.'@odata.type'
                   }

               $Health_Scripts_Assignments += [PSCustomObject]@{
                   DisplayName            = ($Each_HealthScript.DisplayName).ToUpper()
                   Id                     = ($Each_HealthScript.Id).ToUpper()
                   Version                = ($Each_HealthScript.Version).ToUpper()
                   Published_By           = ($Each_HealthScript.publisher).ToUpper()
                   Description            = If ([string]::IsNullOrEmpty($Each_HealthScript.Description)) { "Nothing To Show" } Else { ($Each_HealthScript.Description).ToUpper() }
                   Last_Modified_DateTime = $Each_HealthScript.lastModifiedDateTime
                   RunAsAccount           = ($Each_HealthScript.RunAsAccount).ToUpper()
                   Assignment_Type        = $($AssignmentType)
               }

            }
        If (($Health_Scripts_Assignments.count) -gt 0)
            {
                Write-Host "Gathering Details of Health (Proactive Remediation) Scripts Assignment completed." -F Green
                Write-Host "`n"
            }

    }
Else 
    {
        Write-Host "No Health (Proactive Remediation) Code Assignment found." -F Magenta
        Write-Host "`n"
    }
Write-Host ("------"*20)
#Report in HTML Format
$header = @"
<style>
    h1 {
        font-family: cursive;
        color: #cfe600;
        font-size: 28px;
    }

    h2 {
        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 16px;
    }

    table {
        font-size: 12px;
        border-collapse: collapse;
        font-family: Arial, Helvetica, sans-serif;
    }

    td, th {
        padding: 8px;
        border: 1px solid #ccc;
    }

    th {
        background: #395870;
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
    }

    tbody tr:nth-child(even) {
        background: #f0f0f2;
    }

    #CreationDate {

        font-family: cursive;
        color: #000000;
        font-size: 16px;
    }

    .DeviceComplianceExclusionStatus {

        color: #ff0000;
      }
     
   
      .DeviceComplianceInclusionStatus {
 
          color: #008000;
     }

     .DeviceConfigExclusionStatus {

        color: #ff0000;
      }
     
   
      .DeviceConfigInclusionStatus {
 
          color: #008000;
     }


     .Device_Setting_CatalogExclusionStatus {

        color: #ff0000;
      }
     
   
      .Device_Setting_CatalogInclusionStatus {
 
          color: #008000;
     }

     .DeviceConfig_AdminTemplateExclusionStatus {

        color: #ff0000;
      }
     
   
      .DeviceConfig_AdminTemplateInclusionStatus {
 
          color: #008000;
     }


     .AppDeploymentExclusionStatus {

        color: #ff0000;
      }
     
   
      .AppDeploymentInclusionStatus {
 
          color: #008000;
     }

    .HealthScriptExclusionStatus {

        color: #ff0000;
      }
     
   
    .HealthScriptInclusionStatus {
 
          color: #008000;
     }


    .PlatformScriptExclusionStatus {

        color: #ff0000;
      }
     
   
    .PlatformScriptInclusionStatus {
 
          color: #008000;
     }

</style>
"@


$HTMLReportTitle = "<h1> Status Of Intune Assignment/s for Microsoft Entra ID Group: {$($GroupName)}</h1>"

$DeviceCompliance_Status_Report = $DeviceCompliance_Status | ConvertTo-HTML -Property DisplayName,CompliancePolicy_ID,Description,LastModifiedDateTime,Entity_Type,Assingment_Type -Fragment -PreContent "<h2>Device Compliance Status </h2>"
$DeviceCompliance_Status_Report = $DeviceCompliance_Status_Report -replace '<td>Inclusion</td>','<td class="DeviceComplianceInclusionStatus">Inclusion</td>' 
$DeviceCompliance_Status_Report = $DeviceCompliance_Status_Report -replace '<td>Exclusion</td>','<td class="DeviceComplianceExclusionStatus">Exclusion</td>'

$DeviceConfig_Profile_Assignments_Report = $DeviceConfig_Profile_Assignments | ConvertTo-HTML  -Property DisplayName,DeviceConfigurations_ID,Description,LastModifiedDateTime,Entity_Type,Assingment_Type -Fragment -PreContent "<h2>Device Configuration Assignments</h2>"
$DeviceConfig_Profile_Assignments_Report = $DeviceConfig_Profile_Assignments_Report -replace '<td>Inclusion</td>','<td class="DeviceConfigInclusionStatus">Inclusion</td>' 
$DeviceConfig_Profile_Assignments_Report = $DeviceConfig_Profile_Assignments_Report -replace '<td>Exclusion</td>','<td class="DeviceConfigExclusionStatus">Exclusion</td>'

#$PsScripts_Assignment = $PsScripts_Assignments | ConvertTo-HTML  -Property DisplayName,PsScript_Id,Description,LastModifiedDateTime,RunAsAccount -Fragment -PreContent "<h2>Powershell Scripts Assignment</h2>"
#$PsScripts_Assignment = $PsScripts_Assignment -replace
#$PsScripts_Assignment = $PsScripts_Assignment -replace

$Final_Device_Setting_Catalog = $Final_Device_Setting_Catalogs | ConvertTo-HTML  -Property ProfileName,ProfileName_Id,ProfileName_Description,ProfileName_LastUpdatedDateTime,Assigned -Fragment -PreContent "<h2>Device Configuration Settings Catalog Assignments</h2>"
$Final_Device_Setting_Catalog = $Final_Device_Setting_Catalog -replace '<td>TRUE</td>','<td class="Device_Setting_CatalogInclusionStatus">TRUE</td>' 
$Final_Device_Setting_Catalog = $Final_Device_Setting_Catalog -replace '<td>FALSE</td>','<td class="Device_Setting_CatalogExclusionStatus">FALSE</td>'

$Final_Admin_Template = $Final_Admin_Templates | ConvertTo-HTML  -Property Adm_Template_Name,Adm_Template_Id,Adm_Template_Description,Adm_Template_LastUpdatedDateTime,Adm_Template_Assigned -Fragment -PreContent "<h2>Device Configuration Administrative Templates Assignments</h2>"
$Final_Admin_Template = $Final_Admin_Template -replace '<td>Inclusion</td>','<td class="DeviceConfig_AdminTemplateInclusionStatus">Inclusion</td>' 
$Final_Admin_Template = $Final_Admin_Template -replace '<td>Exclusion</td>','<td class="DeviceConfig_AdminTemplateExclusionStatus">Exclusion</td>'

$Final_AllWin32AppDeployment = $Final_AllWin32AppDeployments | ConvertTo-HTML -Property App_Name,App_Type,App_Version,App_Intent,App_Id,App_LastUpdatedDateTime,App_Assigned,Filter_Name,Filter_ID,Filter_Type  -Fragment -PreContent "<h2>Application Assignments</h2>"
$Final_AllWin32AppDeployment = $Final_AllWin32AppDeployment -replace '<td>Inclusion</td>','<td class="AppDeploymentInclusionStatus">Inclusion</td>' 
$Final_AllWin32AppDeployment = $Final_AllWin32AppDeployment -replace '<td>Exclusion</td>','<td class="AppDeploymentExclusionStatus">Exclusion</td>'

$Final_Health_Scripts_Assignment = $Health_Scripts_Assignments | ConvertTo-HTML -Property DisplayName, Id, Version, Published_By, Description, Last_Modified_DateTime, RunAsAccount, Assignment_Type -Fragment -PreContent "<h2>Health (Proactive Remediation) Script Assignments</h2>"
$Final_Health_Scripts_Assignment = $Final_Health_Scripts_Assignment -replace '<td>Inclusion</td>','<td class="HealthScriptInclusionStatus">Inclusion</td>' 
$Final_Health_Scripts_Assignment = $Final_Health_Scripts_Assignment -replace '<td>Exclusion</td>','<td class="HealthScriptExclusionStatus">Exclusion</td>'


$Final_Platform_Scripts_Assignment = $Platform_Scripts_Assignments | ConvertTo-HTML -Property DisplayName, Id, Description, Last_Modified_DateTime, RunAsAccount, Assignment_Type -Fragment -PreContent "<h2>Platform Script Assignments</h2>"
$Final_Platform_Scripts_Assignment = $Final_Platform_Scripts_Assignment -replace '<td>Inclusion</td>','<td class="PlatformScriptInclusionStatus">Inclusion</td>' 
$Final_Platform_Scripts_Assignment = $Final_Platform_Scripts_Assignment -replace '<td>Exclusion</td>','<td class="PlatformScriptExclusionStatus">Exclusion</td>'

#Date & Time
$Current_Date_Time = (Get-Date -Format "dd:MMMM:yyyy hh:mm:ss tt")

#TimeZone
$Current_TimeZone = (Get-TimeZone).Id #-replace " ", "_"

$All_Intune_Assigments_HTMLReport = ConvertTo-HTML -Head $header -Body "$HTMLReportTitle $Final_AllWin32AppDeployment $DeviceConfig_Profile_Assignments_Report $DeviceCompliance_Status_Report $Final_Device_Setting_Catalog $Final_Admin_Template $Final_Platform_Scripts_Assignment $Final_Health_Scripts_Assignment" -Title "Intune Assignment Status Report" -PostContent "<p id='CreationDate'>Report created by $($Capture_UserLogin_And_Tenant_ID.UPN.ToUpper()) on $($Current_Date_Time) $($Current_TimeZone).</p>"

$All_Intune_Assigments_HTMLReport | Out-File -FilePath $ActualHTMLReportFolderPath

#Lauch File explorer where HTML Report was saved.
Start-Process $($Location_To_Save_HTML_Report)