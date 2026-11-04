# ============================================================================
# DECLARE VARIOUS PARAMETERS
# ============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Number of audit entries to retrieve")]
    [ValidateRange(1, 1000)]
    [int]$NumberOfEntries = 500,

    [Parameter(Mandatory = $false, HelpMessage = "Number of days back to search")]
    [ValidateRange(1, 30)]
    [int]$DaysBack = 30,

    [Parameter(Mandatory = $false, HelpMessage = "Filter by user (supports wildcards)")]
    [string]$FilterByUser,

    [Parameter(Mandatory = $false, HelpMessage = "Filter by activity name (supports wildcards)")]
    [string]$FilterByActivity,

    [Parameter(Mandatory = $false, HelpMessage = "Filter by category")]
    [ValidateSet("Application", "Device", "Role", "User", "Policy", "Compliance", "Enrollment", "All")]
    [string]$FilterByCategory = "All",

    [Parameter(Mandatory = $false, HelpMessage = "Show only failed operations")]
    [switch]$OnlyFailures,

    [Parameter(Mandatory = $false, HelpMessage = "Export results to CSV")]
    [switch]$ExportToCsv,

    [Parameter(Mandatory = $false, HelpMessage = "Export results to HTML")]
    [switch]$ExportToHtml,

    [Parameter(Mandatory = $false, HelpMessage = "Output path for exports")]
    [string]$OutputPath = ".",

    [Parameter(Mandatory = $false, HelpMessage = "Open HTML report after generation")]
    [switch]$OpenReport,

    [Parameter(Mandatory = $false, HelpMessage = "Show detailed properties for each entry")]
    [switch]$DetailedView
)
# ============================================================================
# MICROSOFT GRAPH API MODULES DETECTION; SETUP AND AUTHENTICATION
# ============================================================================

Function Test-IsAdmin 
    {
        try 
            {
                $id = [Security.Principal.WindowsIdentity]::GetCurrent()
                $p  = New-Object Security.Principal.WindowsPrincipal($id)
                return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            } 
        catch 
            {
               
                return $false
            }
    }

If (-not (Test-IsAdmin))
    {
        throw "Current logged in user '$($ENV:UserName)' on device '$(Hostname)' must be Local Admin to Install the MS Graph Modules.Run PowerShell as an administrator."
    }
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

        1. Installs Microsoft.Graph.Authentication :
                Microsoft.Graph.Authentication - This provides Connect-MgGraph; Get-MgContext; Disconnect-MgGraph and Invoke-MgGraphRequest.
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
        # If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
        #     {
        #         Write-Error "Please run this script as Administrator."
        #         return
        #     }
        # Record network usage before operation
        $BeforeUsage = Get-NetworkUsage

        $ModuleName = "Microsoft.Graph.Authentication"
        If (-not (Get-Module -ListAvailable -Name $ModuleName)) 
            {
                Write-Host "Installing $ModuleName..." -ForegroundColor Yellow
                Install-Module -Name $ModuleName -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
                $AfterUsage = Get-NetworkUsage
                $DataUsedBytes = $AfterUsage - $BeforeUsage
                $DataUsedMB = [math]::Round($DataUsedBytes / 1MB, 2)
                $DataUsedGB = [math]::Round($DataUsedBytes / 1GB, 2)
                Write-Host "Data consumed for Microsoft.Graph module installation: $DataUsedMB MB / $DataUsedGB GB. `n" -ForegroundColor Green
            }

        Import-Module $ModuleName -ErrorAction Stop
        # Connect to Microsoft Graph
        Try
            {

                $Scopes = @(
                    "DeviceManagementApps.Read.All",
                    "DeviceManagementConfiguration.Read.All",
                    "DeviceManagementManagedDevices.Read.All"
                )
                Write-Host "Authentication with Microsoft Graph is in progress. Please wait....`n" -F Yellow
                # Connect-MgGraph -Scopes "DeviceManagementManagedDevices.Read.All", "Reports.Read.All" -TenantId $TenantId -ClientId $EnterpriseAppId -NoWelcome -ErrorAction Stop
                Connect-MgGraph -Scopes $Scopes -TenantId $TenantId -ClientId $EnterpriseAppId -NoWelcome -ErrorAction Stop
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
                Write-Warning "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
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
Else 
    {
        throw "Microsoft Graph authentication failed. Audit log retrieval cannot continue."
    }

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

Function Get-MgGraphAllPage 
    {
        param(
            [string]$Uri,
            [int]$Top = 0,
            [int]$DelayMs = 100
        )

        $AllResults = @()
        $NextLink = $Uri
        $RequestCount = 0
        $RetrievedCount = 0

        Do 
        {
            Try 
                {
                    If ($RequestCount -gt 0) 
                        {
                            Start-Sleep -Milliseconds $DelayMs
                        }

                    $Response = Invoke-MgGraphRequest -Uri $NextLink -Method GET
                    $RequestCount++

                    If ($Null -ne $Response.value)
                        {
                            If ($Top -gt 0) 
                                {
                                    $Remaining = $Top - $RetrievedCount
                                    If ($Remaining -le 0) 
                                        {break}

                                    $ToTake = [Math]::Min($Response.value.Count, $Remaining)
                                    $AllResults += $Response.value[0..($ToTake - 1)]
                                    $RetrievedCount += $ToTake
                                }
                            Else 
                                {
                                    $AllResults += $Response.value
                                    $RetrievedCount += $Response.value.Count
                                }
                        }

                    $NextLink = $Response.'@odata.nextLink'

                    If (($RequestCount % 10) -eq 0) 
                        {
                            Write-Verbose "Retrieved $retrievedCount Intune audit entries..."
                        }
                }
            Catch 
                {
                    If ($_.Exception.Message -like "*429*") 
                        {
                            # Write-Output "Encountered '429' in the response message.Retrying after $($RetryAfter)."
                            $RetryAfter = $_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds
                            If (-Not $RetryAfter)
                                {
                                    $RetryAfter = 60
                                }
                            # Write-Information "Rate limit hit, waiting $($RetryAfter) seconds..." -InformationAction Continue
                            Write-Information "Microsoft Graph throttling detected. Retrying after $RetryAfter seconds." -InformationAction Continue
                            Start-Sleep -Seconds $RetryAfter
                            Continue
                        }
                    throw "Error fetching data: $($_.Exception.Message)"
                }
        }

        While ($NextLink -and ($Top -eq 0 -or $RetrievedCount -lt $Top))

        # Comma prevents unrolling so single-element results stay arrays
        Return , $AllResults
    }

Function Format-IntuneAuditEntries
    {
        param($Entry)

        # fix issue with timestamp parsing
        If ($Entry.activityDateTime -is [DateTime]) 
            {
                $Timestamp = $Entry.activityDateTime.ToLocalTime()
            }
        Else 
            {
                $Timestamp = [DateTime]::ParseExact($Entry.activityDateTime, @("MM/dd/yyyy HH:mm:ss", "yyyy-MM-ddTHH:mm:ss", "yyyy-MM-ddTHH:mm:ssZ", "yyyy-MM-ddTHH:mm:ss.fffffffZ"), [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal).ToLocalTime()
            }

        # $Actor = If ($Entry.actor.userPrincipalName) 
        #             {
        #                 $Entry.actor.userPrincipalName
        #             }

        #         Else 
        #             { 
        #                 $Entry.actor.applicationDisplayName 
        #             }

        $Actor = If ($Entry.actor.userPrincipalName)
                    {
                        $Entry.actor.userPrincipalName
                    }
                ElseIf ($Entry.actor.applicationDisplayName)
                    {
                        $Entry.actor.applicationDisplayName
                    }
                ElseIf ($Entry.actor.servicePrincipalName)
                    {
                        $Entry.actor.servicePrincipalName
                    }
                Else
                    {
                        "Unknown"
                    }
        $Result = If ($Entry.activityResult -eq "Success") {"✓"} Else {"✗"}
        $ResultColor = If ($Entry.activityResult -eq "Success") {"Green"} Else {"Red"}

        # Extract resource information

        [System.Collections.Generic.List[Object]]$resources = @()
        Foreach ($Resource in $Entry.resources) 
            {
                If ($Resource.displayName) 
                    {
                        $Resources.Add($Resource.displayName)
                    }
            }
        $ResourceText = If ($resources.Count -gt 0)
                            { 
                                $resources -join ", " 
                            } 
                        Else { "N/A" }

        # Build output
        # $Output = @{
        #                 Timestamp    = $Timestamp.ToString("yyyy-MM-dd HH:mm:ss")
        #                 Actor        = $Actor
        #                 Activity     = $Entry.displayName
        #                 Category     = $Entry.category
        #                 Resources    = $ResourceText
        #                 Result       = $Entry.activityResult
        #                 ResultSymbol = $Result
        #                 ResultColor  = $ResultColor
        #             }

        $Output = [PSCustomObject][ordered]@{
                                                Timestamp    = $Timestamp.ToString("yyyy-MM-dd HH:mm:ss")
                                                Actor        = $Actor
                                                Activity     = $Entry.displayName
                                                Category     = $Entry.category
                                                Resources    = $ResourceText
                                                Result       = $Entry.activityResult
                                                ResultSymbol = $Result
                                                ResultColor  = $ResultColor
                                            }

        If ($DetailedView -and $Entry.activityOperationType) 
            {
                $Output.OperationType = $Entry.activityOperationType
            }

        Return $Output
    }

Function Export-AuditToHtml
{
    param($AuditEntries, $FilePath)

    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Intune Audit Log Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .summary { background-color: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .filters { background-color: #e3f2fd; padding: 10px; border-radius: 4px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background-color: #0078d4; color: white; padding: 12px; text-align: left; font-weight: 600; }
        td { padding: 10px 12px; border-bottom: 1px solid #e1e5e9; }
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e3f2fd; }
        .success { color: #28a745; font-weight: bold; }
        .failure { color: #dc3545; font-weight: bold; }
        .timestamp { color: #6c757d; }
        .category { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; background-color: #e1e5e9; }
        .footer { margin-top: 20px; text-align: center; color: #6c757d; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Intune Audit Log Report</h1>
        <p>Generated on: $(Get-Date -Format "dddd, MMMM dd, yyyy 'at' HH:mm:ss")</p>
    </div>

    <div class="summary">
        <h2>Summary</h2>
        <p>Total Entries: $($AuditEntries.Count)</p>
        <p>Date Range: $($AuditEntries[-1].Timestamp) to $($AuditEntries[0].Timestamp)</p>
"@

    if ($FilterByUser -or $FilterByActivity -or $FilterByCategory -ne "All") {
        $htmlContent += @"
        <div class="filters">
            <strong>Applied Filters:</strong>
"@
        if ($FilterByUser) { $htmlContent += " User: $FilterByUser |" }
        if ($FilterByActivity) { $htmlContent += " Activity: $FilterByActivity |" }
        if ($FilterByCategory -ne "All") { $htmlContent += " Category: $FilterByCategory |" }
        $htmlContent = $htmlContent.TrimEnd(" |") + "</div>"
    }

    $htmlContent += @"
    </div>

    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>User/Application</th>
                <th>Activity</th>
                <th>Category</th>
                <th>Resources</th>
                <th>Result</th>
            </tr>
        </thead>
        <tbody>
"@

    Foreach ($Entry in $AuditEntries)
    {
        $ResultClass = If ($Entry.Result -eq "Success") 
                            {"Success"} 
                        Else 
                            {"Failure"}
        $htmlContent += @"
            <tr>
                <td class="timestamp">$($entry.Timestamp)</td>
                <td>$($entry.Actor)</td>
                <td>$($entry.Activity)</td>
                <td><span class="category">$($entry.Category)</span></td>
                <td>$($entry.Resources)</td>
                <td class="$resultClass">$($entry.ResultSymbol) $($entry.Result)</td>
            </tr>
"@
    }

    $htmlContent += @"
        </tbody>
    </table>

    <div class="footer">
        <p>Report generated by Intune Audit Log Script v1.0</p>
    </div>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $FilePath -Encoding UTF8
}

# ============================================================================
# EXECUTION OF MAIN SCRIPT
# ============================================================================

Try 
    {
        Write-Output "Fetching Intune audit logs for Tenant Name ..."

        # Calculate date filter in UTC so it matches Graph timestamps
        # $StartDate = (Get-Date).ToUniversalTime().AddDays(-$DaysBack).ToString("yyyy-MM-dd")
        # $DateFilter = "ActivityDateTime ge $startDate"

        $StartDate = (Get-Date).ToUniversalTime().AddDays(-$DaysBack).ToString("o")
        $DateFilter = "activityDateTime ge $StartDate"

        # Build filter query
        $Filters = @($DateFilter)

        If ($OnlyFailures) 
            {
                $Filters += "ActivityResult eq 'Failure'"
            }

        # Construct URI
        $BaseUri = "https://graph.microsoft.com/V1.0/deviceManagement/auditEvents"
        $FilterQuery = $Filters -join " and "
        $Uri = "$BaseUri`?`$filter=$FilterQuery&`$orderby=activityDateTime desc"

        If ($NumberOfEntries -lt 100)
            {
                $Uri += "&`$top=$NumberOfEntries"
            }

        Write-Verbose "Query URI: $Uri"

        # Get audit events
        $AuditEvents = Get-MgGraphAllPage -Uri $uri -Top $NumberOfEntries

        Write-Output "✓ Retrieved $($auditEvents.Count) Intune audit entries"

        # Use Additional Filters as Applicable
        if ($FilterByUser) 
            {
                $AuditEvents = $AuditEvents | Where-Object {
                    ($_.actor.userPrincipalName -like $FilterByUser) -or
                    ($_.actor.applicationDisplayName -like $FilterByUser)
                }
            }

        If ($FilterByActivity)
            {
                $AuditEvents = $AuditEvents | Where-Object {$_.displayName -like $FilterByActivity}
            }

        If ($FilterByCategory -ne "All") 
            {
                $AuditEvents = $AuditEvents | Where-Object {$_.category -eq $FilterByCategory}
            }

        # Format entries; skip malformed records instead of aborting the report
        $FormattedEntries = @()
        Foreach ($AuditEvent in $AuditEvents) 
            {
                Try 
                    {
                        $FormattedEntries += Format-IntuneAuditEntries -Entry $AuditEvent
                    }
                Catch 
                    {
                        Write-Warning "Skipping malformed audit entry '$($auditEvent.id)': $($_.Exception.Message)"
                    }
            }

        # Display results
        If ($formattedEntries.Count -eq 0) 
            {
                Write-Output "No audit entries found matching the specified criteria."
            }
        Else 
            {
                Write-Output "`n📋 INTUNE AUDIT LOG ENTRIES"
                Write-Output ("=" * 80)

                Foreach ($entry in $formattedEntries) 
                    {
                        Write-Output "`n[$($Entry.Timestamp)] $($Entry.ResultSymbol) $($Entry.Activity)"
                        Write-Output "   Actor: $($Entry.Actor)"
                        Write-Output "   Category: $($Entry.Category)"
                        Write-Output "   Resources: $($Entry.Resources)"
                        If (($DetailedView) -and ($Entry.OperationType)) 
                            {
                                Write-Output "   Operation: $($Entry.OperationType)"
                            }
                    }

                Write-Output "`n"
                Write-Output ("=" * 80)
                Write-Output "Total entries displayed: $($formattedEntries.Count)"
            }

        # Export if requested
        $Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

        # Create output directory if it does not exist
        If (($ExportToCsv -or $ExportToHtml) -and -not (Test-Path $OutputPath)) 
            {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                Write-Output "Created output directory: $OutputPath"
            }

        If ($ExportToCsv) 
            {
                $CsvPath = Join-Path $OutputPath "Intune_Audit_Log_$timestamp.csv"
                $FormattedEntries | Select-Object Timestamp, Actor, Activity, Category, Resources, Result |
                Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
                Write-Output "✓ CSV report saved: $csvPath"
            }

        If ($ExportToHtml) 
            {
                $htmlPath = Join-Path $OutputPath "Intune_Audit_Log_$timestamp.html"
                Export-AuditToHtml -AuditEntries $formattedEntries -FilePath $htmlPath
                Write-Output "✓ HTML report saved: $htmlPath"

                If ($OpenReport) 
                    {
                        Try 
                            {
                                Start-Process $htmlPath
                            }
                        Catch 
                            {
                                Write-Warning "Could not open the report automatically: $($_.Exception.Message)"
                            }
                    }
            }
    }
Catch 
    {
        Write-Error "Script execution failed: $($_.Exception.Message)"
        Exit 1
    }
Finally
    {
        Try 
            {
                Disconnect-MgGraph | Out-Null
                Write-Output "✓ Disconnected from Microsoft Graph"
            }
        Catch 
            {
                Write-Verbose "Graph disconnection completed"
            }
    }
