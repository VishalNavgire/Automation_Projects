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
    }