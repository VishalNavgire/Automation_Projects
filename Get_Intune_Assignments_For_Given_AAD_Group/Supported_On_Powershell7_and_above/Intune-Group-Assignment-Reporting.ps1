<#
.Author         - Vishal Navgire [VishalNavgire54@Gmail.Com]
.Version Control:
04-Dec-2024 :: v1.0
02-Jan-2025 :: v2.0 - Added logic to display all Azure AD / MS Entra ID groups.
28-Jan-2025 :: v3.0 - Saves HTML report, shows Win32 App filters.
14-Mar-2026 :: v4.0 - Upgraded to PS7 (Microsoft.Graph SDK), added App Protection & Autopilot assignments.
#>

Function Set-HostBackgroundColor 
    {
        param ([Parameter(Mandatory=$true)][string]$Color)
        Clear-Host
        $Host.UI.RawUI.BackgroundColor = $Color
        $SetBG_Colour = $Color
        While ($Host.UI.RawUI.BackgroundColor -ne $SetBG_Colour) 
            {
                $Host.UI.RawUI.BackgroundColor = $Color
                Start-Sleep -Seconds 2
            }
        Clear-Host
    }

Set-HostBackgroundColor -Color "Black"

$GraphApiVersion = "Beta"

# Helper Function for Graph Pagination
Function Get-MgGraphAllPages 
    {
        [CmdletBinding()]
        param ([Parameter(Mandatory=$true)][string]$Uri)
        
        $Results = @()
        Try 
            {
                $Response = Invoke-MgGraphRequest -Method GET -Uri $Uri -ErrorAction Stop
                if ($null -ne $Response.value) 
                    { 
                        $Results += $Response.value 
                    } 
                else 
                    { 
                        $Results += $Response 
                    }
                
                While ($Response.'@odata.nextLink') 
                    {
                        Write-Host "Processing the next page on URL: $($Response.'@odata.nextLink') "
                        $Response = Invoke-MgGraphRequest -Method GET -Uri $Response.'@odata.nextLink' -ErrorAction Stop
                        $Results += $Response.value
                    }
            } 
        Catch 
            {
                Write-Host "Failed to query $Uri : $($_.Exception.Message)" -ForegroundColor Red
            }
        Write-Host "AAD Groups Data Fetched Successfully" -ForegroundColor Green
        Return $Results
    }

# Install MS Graph Module and Connect
Function Install-MgGraph-WithUsageTracking
    {
        <#
            .Author - Vishal Navgire
            .Created on - 31-May-2025
            .Co-Author(s)       - N/A
            .Reviwer(s)         - N/A
            .Intended Audience  - Intune, MS Entra Admin, M365 Admins.
            .Target Device Type - Windows Machines.

        .DESCRIPTION

         1. Installs Microsoft Graph module that contains following sub modules :
                Microsoft.Graph
                Microsoft.Graph.Applications
                Microsoft.Graph.Authentication
                Microsoft.Graph.BackupRestore
                Microsoft.Graph.Beta.DeviceManagement
                Microsoft.Graph.Bookings
                Microsoft.Graph.Calendar
                Microsoft.Graph.ChangeNotifications
                Microsoft.Graph.CloudCommunications
                Microsoft.Graph.Compliance
                Microsoft.Graph.CrossDeviceExperiences
                Microsoft.Graph.DeviceManagement
                Microsoft.Graph.DeviceManagement.Administration
                Microsoft.Graph.DeviceManagement.Enrollment
                Microsoft.Graph.DeviceManagement.Functions
                Microsoft.Graph.Devices.CloudPrint
                Microsoft.Graph.Devices.CorporateManagement
                Microsoft.Graph.Devices.ServiceAnnouncement
                Microsoft.Graph.DirectoryObjects
                Microsoft.Graph.Education
                Microsoft.Graph.Files
                Microsoft.Graph.Groups
                Microsoft.Graph.Identity.DirectoryManagement
                Microsoft.Graph.Identity.Governance
                Microsoft.Graph.Identity.Partner
                Microsoft.Graph.Identity.SignIns
                Microsoft.Graph.Mail
                Microsoft.Graph.Notes
                Microsoft.Graph.People
                Microsoft.Graph.PersonalContacts
                Microsoft.Graph.Planner
                Microsoft.Graph.Reports
                Microsoft.Graph.SchemaExtensions
                Microsoft.Graph.Search
                Microsoft.Graph.Security
                Microsoft.Graph.Sites
                Microsoft.Graph.Teams
                Microsoft.Graph.Users
                Microsoft.Graph.Users.Actions
                Microsoft.Graph.Users.Functions

            2. Scope of module installation : 
            The scope (CurrentUser vs AllUsers) only determines where the module is installed:
            CurrentUser: Installs to the user's profile ($env:USERPROFILE\Documents\PowerShell\Modules)
            AllUsers: Installs to a system-wide location (C:\Program Files\PowerShell\Modules)

            3. Tracks N/w consumption.

    Pre-reqs :
    Register an Enterprise application in your tenant with Delegated access.

    Version Control:
    31-May-2025 :: v1.0

        #>

        [CmdletBinding()]
            Param
                (
                    [Parameter(Mandatory=$true)]
                    [string]$TenantId,

                    [Parameter(Mandatory=$true)]
                    [string]$EnterpriseAppId
                )

        Function Get-NetworkUsage
            {
                $Stats = Get-NetAdapterStatistics
                return  ($Stats | Measure-Object -Property ReceivedBytes -Sum).Sum +
                        ($Stats | Measure-Object -Property SentBytes -Sum).Sum
            }

        # Ensure script is running as Administrator
        If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
            {
                Write-Error "Please run this script as Administrator."
                return
            }
        # Record network usage before operation
        $BeforeUsage = Get-NetworkUsage
        # Check Microsoft.Graph module status
        $InstalledVersion = (Get-InstalledModule -Name Microsoft.Graph -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version)
        $OnlineVersion    = (Find-Module -Name Microsoft.Graph -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version)

        If ($InstalledVersion -eq $OnlineVersion)
            {
                Write-Host "Microsoft.Graph module version '$InstalledVersion' is already installed.`n" -ForegroundColor Cyan
            }
        Else
            {
                Write-Host "Installing or updating Microsoft.Graph module..." -ForegroundColor Yellow
                Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force -AllowClobber

                $AfterUsage = Get-NetworkUsage
                $DataUsedBytes = $AfterUsage - $BeforeUsage
                $DataUsedMB = [math]::Round($DataUsedBytes / 1MB, 2)
                $DataUsedGB = [math]::Round($DataUsedBytes / 1GB, 2)
                Write-Host "Data consumed for Microsoft.Graph module installation: $DataUsedMB MB / $DataUsedGB GB. `n" -ForegroundColor Green
            }

        # Connect to Microsoft Graph
        Try
            {
                Write-Host "Authentication with Microsoft Graph is in progress. Please wait....`n" -F Yellow
                # Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All", "Reports.Read.All" -TenantId $TenantId -ClientId $EnterpriseAppId -NoWelcome -ErrorAction Stop
                Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All" -TenantId $TenantId -ClientId $EnterpriseAppId -NoWelcome -ErrorAction Stop
                $Authenticated_UPN = (Get-MgContext | Select-Object -Property Account).Account
                # Check if $Authenticated_UPN has a value (is NOT null or empty)
                If (!([string]::IsNullOrEmpty($Authenticated_UPN)))
                    {
                        # If $Authenticated_UPN is NOT null or empty (meaning it has a value), then return $True
                        Return $True
                    }
            }
        Catch
            {
                Write-Warning "Failed to connect to Microsoft Graph. Check credentials or permissions.`n"
                Return $False
            }
    }

$TenantId   = Read-Host "`nEnter you Tenant ID here without single or double quote/s"
$Ent_App_Id = Read-Host "`nEnter you Enterprise App ID here without single or double quote/s"
$Ms_Garph_Connection = Install-MgGraph-WithUsageTracking -TenantId $TenantId -EnterpriseAppId $Ent_App_Id

If ($Ms_Garph_Connection -eq $True)
    {
        # $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Host ("---" * 25) -F Yellow
        Write-Host "`nConnected to Microsoft Graph:`n" -ForegroundColor Green
        Get-MgContext | Select-Object -Property Account, TenantId, ClientId, AppName, AuthType | Format-List
        Write-Host ("---" * 25) -F Yellow

        Write-Host "`n"

    # Group Selection Logic
    $Group = $null
    While ($null -eq $Group) 
        {
            # $SearchStr = Read-Host "Enter part of the Entra ID Group Name to search."
            $GroupUri = "https://graph.microsoft.com/v1.0/groups?$select=id,displayName"
            # if (![string]::IsNullOrWhiteSpace($SearchStr)) 
            #     {
            #         $GroupUri += "&`$filter=startswith(displayName,'$SearchStr')"
            #     }

            Write-Host "Fetching groups..." -ForegroundColor Gray
            $Groups = Get-MgGraphAllPages -Uri $GroupUri
            
            # $SelectedGroup = $Groups | Select-Object @{Name="Group Name"; Expression={$_.displayName}}, Id | Out-GridView -Title "Select Entra ID Group" -PassThru
            $SelectedGroup = ($Groups | Select-Object -Property @{Name="Azure AD / MS Entra ID Groups"; Expression={$_.DisplayName}})."Azure AD / MS Entra ID Groups" | Sort-Object -Property "Azure AD / MS Entra ID Groups" | Out-GridView -Title "Connected to Tenant ID: '$TenantId' using '$($IntuneId.UPN)'. Please search and select AAD group name from the displayed list: " -PassThru
            
            If ([string]::IsNullOrEmpty($SelectedGroup)) 
                {
                    Write-Host "No group selected. Try again." -ForegroundColor Red
                    $Group = $null
                } 
            Else 
                {
                    $Group = $SelectedGroup
                    $GroupId = $Group.Id
                    $GroupName = $Group."Group Name"
                    Write-Host "Querying Assignments for Group: '$GroupName' (ID: '$GroupId')" -ForegroundColor Yellow
                }
        }

    # Directory for HTML Report
    $Location_To_Save_HTML_Report = 'C:\Temp\Intune_Assignment_Reports'
    If (!(Test-Path -Path $Location_To_Save_HTML_Report)) 
        { 
            New-Item -ItemType Directory -Path $Location_To_Save_HTML_Report | Out-Null 
        }
    $CurrentDateTime = Get-Date
    $HTML_FileName = "\Intune_Assigments_For_GroupName_'$($GroupName)'_$($CurrentDateTime.ToString("dd_MMM_yyyy_hh_mm_ss_tt")).HTML"
    $ActualHTMLReportFolderPath = Join-Path -Path $Location_To_Save_HTML_Report -ChildPath $HTML_FileName

    Write-Host "`nHTML Report will be saved to: $ActualHTMLReportFolderPath `n" -ForegroundColor Magenta

    # Function to evaluate assignment intent
    Function Get-AssignmentType ($Assignments, $GroupId) 
        {
            $Target = $Assignments | Where-Object { $_.target.groupId -eq $GroupId -or $_.groupId -eq $GroupId }
            if ($null -eq $Target) 
                {
                    return $null 
                }
            
            $TypeStr = $Target.target.'@odata.type'
            if ($null -eq $TypeStr) 
                { 
                    $TypeStr = $Target.'@odata.type' 
                }

            if ($TypeStr -match "exclusion") 
                { 
                    return "Exclusion" 
                }
            if ($TypeStr -match "inclusion" -or $TypeStr -match "groupAssignmentTarget") 
                { 
                    return "Inclusion" 
                }
            return "Inclusion"
        }

    # 1. Win32 App Deployments
    Write-Host "Gathering details for Intune Applications..." -ForegroundColor Yellow
    $Win32Uri = "https://graph.microsoft.com/$GraphApiVersion/deviceAppManagement/mobileApps?`$expand=assignments"
    $AllApps = Get-MgGraphAllPages -Uri $Win32Uri
    $Final_Apps = @()

    Foreach ($App in $AllApps) 
        {
            $Assigned = $App.assignments | Where-Object {$_.target.groupId -eq $GroupId}
            if ($Assigned) 
                {
                    $Assigned | ForEach-Object 
                        {
                            $FilterName = "NONE"
                            if ($_.target.deviceAndAppManagementAssignmentFilterId) 
                                {
                                    try 
                                        {
                                            $FilterData = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters/$($_.target.deviceAndAppManagementAssignmentFilterId)"
                                            $FilterName = $FilterData.displayName
                                        } 
                                    catch {}
                                }
                            $Final_Apps += [PSCustomObject]@{
                                                            App_Name = $App.displayName
                                                            App_Type = ($App.'@odata.type' -replace "#microsoft.graph.","")
                                                            Intent = $_.intent
                                                            Assignment_Type = Get-AssignmentType -Assignments $_ -GroupId $GroupId
                                                            Filter_Name = $FilterName
                                                        }
                        }
                }
        }

    # 2. Device Configuration Profiles
    Write-Host "Gathering details for Device Configuration Profiles..." -ForegroundColor Yellow
    $ConfigUri = "https://graph.microsoft.com/$GraphApiVersion/deviceManagement/deviceConfigurations?`$expand=assignments"
    $AllConfigs = Get-MgGraphAllPages -Uri $ConfigUri
    $Final_Configs = @()
    Foreach ($Config in $AllConfigs) 
        {
            $Assigned = $Config.assignments | Where-Object {$_.target.groupId -eq $GroupId}
            if ($Assigned) 
                {
                    $Final_Configs += [PSCustomObject]@{
                                                        DisplayName = $Config.displayName
                                                        Platform = $Config.platforms
                                                        Assignment_Type = Get-AssignmentType -Assignments $Assigned -GroupId $GroupId
                                                    }
                }
        }

    # 3. App Protection Policies (NEW)
    Write-Host "Gathering details for App Protection Policies..." -ForegroundColor Yellow
    $AppProtectionUri = "https://graph.microsoft.com/$GraphApiVersion/deviceAppManagement/managedAppPolicies?`$expand=assignments"
    $AllAppProt = Get-MgGraphAllPages -Uri $AppProtectionUri
    $Final_AppProt = @()
    Foreach ($Policy in $AllAppProt)
        {
            $Assigned = $Policy.assignments | Where-Object { $_.target.groupId -eq $GroupId }
            if ($Assigned) 
                {
                    $Final_AppProt += [PSCustomObject]@{
                                                        DisplayName = $Policy.displayName
                                                        Type = ($Policy.'@odata.type' -replace "#microsoft.graph.","")
                                                        Assignment_Type = Get-AssignmentType -Assignments $Assigned -GroupId $GroupId
                                                    }
                }
        }

    # 4. Windows Autopilot Profiles (NEW)
    Write-Host "Gathering details for Windows Autopilot Profiles..." -ForegroundColor Yellow
    $AutopilotUri = "https://graph.microsoft.com/$GraphApiVersion/deviceManagement/windowsAutopilotDeploymentProfiles?`$expand=assignments"
    $AllAutopilot = Get-MgGraphAllPages -Uri $AutopilotUri
    $Final_Autopilot = @()
    Foreach ($Profile in $AllAutopilot) 
        {
            $Assigned = $Profile.assignments | Where-Object { $_.target.groupId -eq $GroupId }
            if ($Assigned) 
                {
                    $Final_Autopilot += [PSCustomObject]@{
                                                            DisplayName = $Profile.displayName
                                                            DeploymentMode = $Profile.deploymentMode
                                                            Assignment_Type = Get-AssignmentType -Assignments $Assigned -GroupId $GroupId
                                                        }
                }
        }

    # 5. Settings Catalog
    Write-Host "Gathering details for Settings Catalog..." -ForegroundColor Yellow
    $SettingsUri = "https://graph.microsoft.com/$GraphApiVersion/deviceManagement/configurationPolicies?`$expand=assignments"
    $AllSettings = Get-MgGraphAllPages -Uri $SettingsUri
    $Final_Settings = @()
    Foreach ($Setting in $AllSettings) 
        {
            $Assigned = $Setting.assignments | Where-Object { $_.target.groupId -eq $GroupId }
            if ($Assigned) 
                {
                    $Final_Settings += [PSCustomObject]@{
                                                            DisplayName = $Setting.name
                                                            Technologies = $Setting.technologies
                                                            Assignment_Type = Get-AssignmentType -Assignments $Assigned -GroupId $GroupId
                                                        }
                }
        }

# HTML Generation
$header = @"
<style>
    body { font-family: Arial, sans-serif; }
    h1 { color: #395870; font-size: 24px; border-bottom: 2px solid #395870; padding-bottom: 5px; }
    h2 { color: #000099; font-size: 18px; margin-top: 20px; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #395870; color: white; }
    tr:nth-child(even) { background-color: #f2f2f2; }
    .Inclusion { color: green; font-weight: bold; }
    .Exclusion { color: red; font-weight: bold; }
</style>
"@

    $HTMLReportTitle = "<h1>Intune Assignment Status for Group: $($GroupName)</h1>"

    Function Format-HtmlTable ($Data, $Title) 
        {
            if ($Data.Count -eq 0) 
                { 
                    return "<h2>$Title</h2><p>No assignments found.</p>"
                }
            $Html = $Data | ConvertTo-Html -Fragment -PreContent "<h2>$Title</h2>"
            $Html = $Html -replace '<td>Inclusion</td>','<td class="Inclusion">Inclusion</td>'
            $Html = $Html -replace '<td>Exclusion</td>','<td class="Exclusion">Exclusion</td>'
            return $Html
        }

    $HtmlBody = $HTMLReportTitle + 
                (Format-HtmlTable $Final_Apps "Application Deployments") +
                (Format-HtmlTable $Final_Configs "Device Configuration Profiles") +
                (Format-HtmlTable $Final_Settings "Settings Catalog") +
                (Format-HtmlTable $Final_AppProt "App Protection Policies") +
                (Format-HtmlTable $Final_Autopilot "Windows Autopilot Profiles")

    $Footer = "<p style='margin-top:30px; font-size:12px; color:gray;'>Report generated by $($GraphContext.Account) on $(Get-Date)</p>"

    ConvertTo-Html -Head $header -Body $HtmlBody -Title "Intune Assignment Report" -PostContent $Footer | Out-File -FilePath $ActualHTMLReportFolderPath

    Write-Host "Report generation complete! Opening folder..." -ForegroundColor Green
    Start-Process $Location_To_Save_HTML_Report
    }
Else 
    {
        Write-Error "Authentication Failed"
    }