<#
.Author         - Vishal Navgire [VishalNavgire54@Gmail.Com]
.Company        - 
.Created on     - 06-Feb-2025
.Co-Author(s)   - 
.Reviwer(s)     -

.DESCRIPTION 

Compares and displays common, uncommon Azure AD groups of two given users or windows devices in the HTML Report.
HTML report will be saved to 'C:\Temp\Compare_AAD_Groups'.
 
Pre-reqs:
    1. Microsoft Entra App needs to be registered in to your Tenant first with permission type as 'Delegated'. After you complete App's registration please 
        update App's ID in the line no# 84 👉  $Registered_Entra_App_ID = "App ID". To read more on how to create / register an MS Entra App Id with Delegated rights - https://learn.microsoft.com/en-us/graph/auth-register-app-v2#register-an-application 
    2. Set API Permission - 'DeviceManagementApps.Read.All'. To read more about this API permission - https://learn.microsoft.com/en-us/graph/permissions-reference#devicemanagementappsreadall
    3. Use an account that has Admin rights to run this script on a device.
    4. To interact with Intune's data, log in with an account that has sufficient permissions to read User's or device's properties from Intune. 

Version Control:
    06-Feb-2025 : v1.0

Types of assignments you can make to an Azure AD group from Azure or Intune:

    Role-Based Access Control (RBAC): Assign permissions to Azure resources.
    Licenses: Assign licenses for Microsoft 365 services.
    Applications: Deploy and manage applications.
    Device Configuration: Configure settings on managed devices.
    Compliance Policies: Define device compliance rules.
    Conditional Access: Control access based on conditions.

Below are some practical use cases and Real-World Scenarios where this script Saves Time can significantly reduce troubleshooting time and efforts:

✅ Intune Policy Not Applying to a User or Device
Example: User X reports that their BitLocker encryption policy or Compliance Policy is not being enforced, while User Z (same role, same department) has the correct policies applied.
➡ By running this script, you can quickly identify that User X is missing a required AAD group that enforces Intune compliance policies, allowing engineers to correct the issue in minutes instead of hours.

✅ Application Access Denied for a User
Example: User X cannot access Microsoft Teams, OneDrive, or a third-party enterprise application, while User Z (same department) has no issues.
➡ Instead of manually reviewing all assigned groups, this script will instantly highlight missing groups (such as an App Access group), pinpointing the root cause immediately.

✅ Device Configuration Issues After Enrollment
Example: Two laptops are enrolled into Intune, but Device A receives all required security configurations, VPN profiles, Wi-Fi settings, and Defender policies, while Device B is missing them.
➡ This script will compare AAD group memberships for both devices and show whether Device B missed an assignment that was applied to Device A.

✅ RBAC Role Not Working for an IT Admin
Example: An IT admin (User X) complains that they cannot perform certain privileged tasks in Intune, while their colleague (User Z) has no issues.
➡ Running this script will instantly show if User X is missing an Azure AD role assignment group, ensuring that the correct permissions are granted.

✅ Conditional Access Policy Blocks a User from Logging In
Example: User X cannot access Microsoft 365 services due to a Conditional Access Policy preventing logins from their location or device, while User Z has no issues.
➡ The script will compare both users’ group memberships to identify whether User X was excluded from an “Allow Access” group, helping resolve the issue efficiently.

✅ VPN or Remote Access Not Working for a User
Example: A user complains that they cannot establish a VPN connection to the corporate network, while another user from the same team has no problems.
➡ Running this script will reveal whether the affected user is missing a required VPN access group, eliminating the need for extensive manual investigation.
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
                        Write-Host " "
                        Write-Host "Enter your credentials to connect to Microsoft Intune..." -ForegroundColor Cyan
                        Write-Host " "
                        Update-MSGraphEnvironment -AppId $($Application_Id) -SchemaVersion $ApiVersion -Quiet -ErrorAction Stop
                        $IntuneId = Connect-MSGraph -ErrorAction Stop
                        $TenantId = ($IntuneId.TenantId).ToUpper()
                        If (![string]::IsNullOrEmpty($IntuneId)) 
                            {
                                Write-Host "Connected to Microsoft Tenant ID '$TenantId' using user account '$($IntuneId.UPN)'" -ForegroundColor Green
                                Write-Host " "
                            }
                        Else 
                            {
                                Write-Host "Connection to Microsoft Intune Tenant ID $TenantId failed on device '$($Env:COMPUTERNAME)'. Try again..." -ForegroundColor Red
                                Write-Host " "
                                $($Error.Exception.Message)
                                Write-Host " "
                                $(Write-Host "Press ENTER key to exit from PowerShell console!!!" -ForegroundColor Red; Read-Host)
                                Exit
                            }

                    } 
                Catch 
                    {
                        Write-Host "Failed to install module name: $InstallModuleName." -ForegroundColor Red
                        Write-Host " "
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
                            Write-Host " "
                            Write-Host "Enter your credentials to connect to Microsoft Intune..." -ForegroundColor Cyan
                            Write-Host " "
                            Update-MSGraphEnvironment -AppId $($Application_Id) -SchemaVersion $ApiVersion -Quiet -ErrorAction Stop
                            $IntuneId = Connect-MSGraph -ErrorAction Stop
                            $TenantId = ($IntuneId.TenantId).ToUpper()
                        If (![string]::IsNullOrEmpty($IntuneId)) 
                            {
                                Write-Host "Connected to Microsoft Tenant ID '$TenantId' using user account '$($IntuneId.UPN)'" -ForegroundColor Green
                                Write-Host " "
                            }
                        Else 
                            {
                                Write-Host "Connection to Microsoft Intune Tenant ID $TenantId failed on device '$($Env:COMPUTERNAME)'. Try again..." -ForegroundColor Red
                                Write-Host " "
                                $($Error.Exception.Message)
                                Write-Host " "
                                $(Write-Host "Press ENTER key to exit from PowerShell console!!!" -ForegroundColor Red; Read-Host)
                                Exit
                            }

                    }
                Catch 
                    {
                        Write-Host "Connection to Microsoft Intune Tenant ID $TenantId failed on device $($Env:COMPUTERNAME). Try again..." -ForegroundColor Yellow
                        Write-Host " "
                        Write-Host "Error Details: $($_.Exception.Message)" -ForegroundColor Red
                        $(Write-Host "Press ENTER key to exit from PowerShell console!!!" -ForegroundColor Yellow; Read-Host)
                        Exit
                    }
            }

            Return $IntuneId
    }

$Tenant_Connection_Details = Install-MSGraphIntuneModule

$Tenant_Connection_Details | Out-Null
#####################################################
Function Get-AllMSEntraIDUserDetails
    {
        <#
            .SYNOPSIS
         Retrieves all end user's details by making Graph API calls.

            #>

            [CmdletBinding()]
            Param 
                (
                    [Parameter(Mandatory = $False)]
                    [ValidateSet("v1.0", "Beta")]
                    [string]$ApiVersion = "Beta", 

                    [Parameter(Mandatory = $False)]
                    [string]$MsEntraIDUserAPI = "https://graph.microsoft.com/$($ApiVersion)/Users",

                    [Parameter(Mandatory = $False)]
                    [ValidateSet("GET", "POST", "PATCH", "DELETE")]
                    [string]$HTTPMethod = "GET"

                )


                Try 
                    {
                        $MsEntraIDUser_Details = Invoke-MSGraphRequest -Url $MsEntraIDUserAPI -HttpMethod $HTTPMethod | Get-MSGraphAllPages

                        Return $MsEntraIDUser_Details
                        
                    }
                Catch 
                    {
                        Write-Error "An error occurred while retrieving Intune filter display name: $_"
                        throw

                    }
    }

#####################################################

Function Get-AllMSEntraIDGroupsOfUser
    {
        <#
            .SYNOPSIS
         Retrieves all Direct and Transistive groups of an user by making Graph API calls.

            #>

            [CmdletBinding()]
            Param 
                (
                    [Parameter(Mandatory = $False)]
                    [ValidateSet("v1.0", "Beta")]
                    [string]$ApiVersion = "Beta", 

                    [Parameter(Mandatory = $True)]
                    [string]$UserID = "",

                    [Parameter(Mandatory = $False)]
                    [string]$MsEntraIDGroupMembersAPI = "https://graph.microsoft.com/$($ApiVersion)/Users/$($UserID)/transitiveMemberOf",

                    [Parameter(Mandatory = $False)]
                    [ValidateSet("GET", "POST", "PATCH", "DELETE")]
                    [string]$HTTPMethod = "GET"

                )


                Try 
                    {
                        $MsEntraIDGroups_Details = Invoke-MSGraphRequest -Url $MsEntraIDGroupMembersAPI -HttpMethod $HTTPMethod | Get-MSGraphAllPages

                        Return $MsEntraIDGroups_Details
                        
                    }
                Catch 
                    {
                        Write-Error "An error occurred while retrieving Intune filter display name: $_"
                        throw

                    }
    }

#####################################################
Function Get-AllIntuneManagedDevices
    {
        <#
            .SYNOPSIS
            Retrieves all Intune managed endpoints by making Graph API calls.

            #>

            [CmdletBinding()]
            Param 
                (
                    [Parameter(Mandatory = $False)]
                    [ValidateSet("v1.0", "Beta")]
                    [string]$ApiVersion = "Beta", 

                    [Parameter(Mandatory = $False)]
                    [string]$ManagedDevicesAPI = "https://graph.microsoft.com/$($ApiVersion)/deviceManagement/managedDevices",

                    [Parameter(Mandatory = $False)]
                    [ValidateSet("GET", "POST", "PATCH", "DELETE")]
                    [string]$HTTPMethod = "GET"

                )


                Try 
                    {
                        $IntuneManagedEndpoints = Invoke-MSGraphRequest -Url $ManagedDevicesAPI -HttpMethod $HTTPMethod | Get-MSGraphAllPages

                        Return $IntuneManagedEndpoints
                        
                    }
                Catch 
                    {
                        Write-Error "An error occurred while retrieving Intune filter display name: $_"
                        throw

                    }
    }

#####################################################
Function Get-ADObjectIdOfAnIntuneManagedDevice
    {
        
            <#
            .SYNOPSIS
            Retrieves Azure AD Object Id of an Intune managed endpoint by making Graph API calls.
            This is need to check where all given Intune managed endpoint is a member of Azure AD Security Groups.

            #>

            [CmdletBinding()]
            Param 
                (
                    [Parameter(Mandatory = $False)]
                    [ValidateSet("v1.0", "Beta")]
                    [string]$ApiVersion = "Beta", 

                    [Parameter(Mandatory = $False)]
                    [string]$ManagedDevicesAPI = "https://graph.microsoft.com/$($ApiVersion)/devices",

                    [Parameter(Mandatory = $False)]
                    [ValidateSet("GET", "POST", "PATCH", "DELETE")]
                    [string]$HTTPMethod = "GET", 

                    [Parameter(Mandatory = $True)]
                    [string]$IntuneAzureADDeviceID
                )

                
            Try 
                {
                    $IntuneManagedEndpoint_AzureADObjectID = Invoke-MSGraphRequest -Url $ManagedDevicesAPI -HttpMethod $HTTPMethod | Get-MSGraphAllPages | Where-Object {$_.DeviceID -eq $IntuneAzureADDeviceID}

                    Return $IntuneManagedEndpoint_AzureADObjectID
                    
                }
            Catch 
                {
                    Write-Error "An error occurred while retrieving Intune filter display name: $_"
                    throw

                }
           
    }
#####################################################

Function Get-AllGroupsOfAnIntuneManagedDevice
    {
        
        <#
            .SYNOPSIS
            Retrieves all AD Security groups & administrative units of an Intune managed endpoint by making Graph API calls.

        #>

            [CmdletBinding()]
            Param 
                (
                    [Parameter(Mandatory = $False)]
                    [ValidateSet("v1.0", "Beta")]
                    [string]$ApiVersion = "Beta", 

                    [Parameter(Mandatory = $True)]
                    [string]$AzureActiveDirectoryObjectID,

                    [Parameter(Mandatory = $False)]
                    [string]$ManagedDevicesAPI = "https://graph.microsoft.com/$($ApiVersion)/devices/$($AzureActiveDirectoryObjectID)/transitiveMemberOf",

                    [Parameter(Mandatory = $False)]
                    [ValidateSet("GET", "POST", "PATCH", "DELETE")]
                    [string]$HTTPMethod = "GET"
                )


                Try 
                {
                    $MsEntraIDGroups_Details_Device = Invoke-MSGraphRequest -Url $ManagedDevicesAPI -HttpMethod $HTTPMethod | Get-MSGraphAllPages | Where-Object {$_.'@odata.type' -eq "#microsoft.graph.group"}

                    Return $MsEntraIDGroups_Details_Device
                    
                }
            Catch 
                {
                    Write-Error "An error occurred while retrieving Intune filter display name: $_"
                    throw

                }
           
    }

#####################################################

Function Invoke-HTMLReportFolder
{

param (
        [String]$EntityName = $null
)

#Creates a default directory to save HTML report.
Function Set-ReportsFolder
    {
        <#
            .SYNOPSIS
            Creates a folder for storing AAD Groups Comparison report.

            .DESCRIPTION
            Creates a folder for storing AAD Groups Comparison report.
        #>

        [CmdletBinding()]
            param 
                (
                    [Parameter(Mandatory = $False)]
                    [string]$BasePath = "C:\Temp",

                    [Parameter(Mandatory = $False)]
                    [string]$NamePrefix = "Compare_AAD_Groups"
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
                $NewFolderPath = Join-Path -Path $($BasePath) -ChildPath $($NamePrefix)

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
If ([string]::IsNullOrEmpty($(Set-ReportsFolder))) 
    {
        Write-Error "There is a no folder path 'C:\Temp\Compare_AAD_Groups' to save HTML Report !!!"
        Start-Sleep 5
        Exit
        
    }
Else 
    {
        $Location_To_Save_HTML_Report = 'C:\Temp\Compare_AAD_Groups'
    }

# Get the current date and time
$CurrentDateTime = Get-Date

#HTML File Name 
$HTML_FileName = "\Compare_AAD_Groups_For_'$($EntityName)'_$($CurrentDateTime.ToString("dd_MMM_yyyy_hh_mm_ss_tt")).HTML"

# Create the full path for the new folder
$ActualHTMLReportFolderPath = Join-Path -Path $($Location_To_Save_HTML_Report) -ChildPath $($HTML_FileName)

Write-Host ("=" * 80) -F Yellow
Write-Host "HTML report will be saved to 'C:\Temp\Compare_AAD_Groups' ." -f White
Write-Host "`n"
Write-Host "HTML Report's Full File path is '$($ActualHTMLReportFolderPath)' ." -f Magenta
Write-Host "`n"
Write-Host ("=" * 80) -F Yellow

Return @{

        ReportFolderPath = $Location_To_Save_HTML_Report
        ReportFilePath   = $ActualHTMLReportFolderPath
}

}

#####################################################

#Comparison HTML Report's CSS Format.
$CSS_Header = @"
    <style>
    body {
        font-family: Arial, sans-serif;
        background-color: #f4f4f4;
        margin: 20px;
    }

    h1 {
        font-family: cursive;
        #color: #cfe600;
        color:black;
        font-size: 28px;
        text-align: center;
        border-bottom: 4px solid #3498DB;
        padding-bottom: 10px;
    }

    h2 {
        font-family: Arial, Helvetica, sans-serif;
        color: #4169E1; /* Royal Blue for a professional look */
        font-size: 18px;
        margin-top: 20px;
        text-decoration: underline;
        font-weight: bold;
    }

    .info-banner {
        background-color: #3498DB;
        color: white;
        padding: 10px;
        text-align: center;
        font-size: 16px;
        font-weight: bold;
        border-radius: 5px;
        margin-bottom: 20px;
    }

    table {
        width: 100%;
        border-collapse: collapse;
        font-size: 14px;
        font-family: Arial, Helvetica, sans-serif;
        background: white;
        box-shadow: 0px 5px 10px rgba(0, 0, 0, 0.1);
        margin-bottom: 20px;
    }

    th {
        background: linear-gradient(to right, #395870, #2C3E50);
        color: white;
        padding: 12px;
        text-transform: uppercase;
        text-align: left;
        font-size: 12px;
    }

    td {
        padding: 10px;
        border-bottom: 1px solid #ddd;
    }

    tbody tr:nth-child(even) {
        background: #f0f0f2;
    }

    tbody tr:hover {
        background-color: #f1c40f;
        color: #000;
        transition: 0.3s ease-in-out;
    }

    #CreationDate {
        font-family: cursive;
        color: #000;
        font-size: 16px;
        text-align: center;
        padding: 10px;
        background: #2C3E50;
        color: white;
        border-radius: 5px;
        font-weight: bold;
        margin-top: 20px;
    }

    .DynamicMembershipType{

       color: #FF9800;
       font-weight: bold;
    }

    .StaticMembershipType{

       color:#28A745;
       font-weight: bold;
    }

</style>
"@

#####################################################
Function Show-SelectionMenu 
    {
        Write-Host " "
        Write-Host ("===="*20)
        Write-Host "AzureAD / Ms Entra ID Groups Comparision Menu Options :" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "  1. User." -F Cyan
        Write-Host "  2. Device." -F White
        Write-Host "  3. Exit." -ForegroundColor Red
        Write-Host " " 
        Write-Host ("===="*20)
    }


Start-Sleep 5

Clear-Host

Show-SelectionMenu
Write-Host " "
$Make_A_Selection = $(Write-Host "Please make a selection and enter the relevant digit here (1 - 3)" -F Yellow; Read-Host)

#Switch Function to begin with User or Device group membership comparision.
Switch ($Make_A_Selection)
    {
        #User's AAD Group Comparision.
        "1" 
        {
            Write-Host "You chose option '$($Make_A_Selection)' for comparing Azure AD / Ms Entra ID group membership of Users....." -F Cyan
            Write-Host " "
            Write-Host "Search and Select AzureAD (Microsoft Entra ID) User Account Name from the displayed list on screen and Press OK:" -f White
            Start-Sleep 2
            
            $Enter_Users_Object = $(Get-AllMSEntraIDUserDetails | Select-Object -Property @{Name="UserDisplayName";Expression={$_.DisplayName.ToUpper()}}, 
             @{Name="UPN";Expression={$_.UserPrincipalName.ToUpper()}},
             @{Name="UserObjectID";Expression={$_.ID.ToUpper()}} | Out-GridView -Title "Select two user accounts to compare thier AzureAD<Microsoft Entra ID> group(s) membership" -OutputMode Multiple)
            Write-Host " "
            Start-Sleep 2
            $UserObjectIds = $($Enter_Users_Object.UserObjectID)

            #Initialize Empty array to hold groups.
             $User1_All_Groups = @()
             $User2_All_Groups = @()

            IF ($UserObjectIds.count -eq 2)
                {
                     $Setup_Folder_And_HTML_File = Invoke-HTMLReportFolder -EntityName "USERS"
                 Write-Host "Processing AzureAD Group Membership comparison for User1 - '$($Enter_Users_Object.UserDisplayName[0])<$($Enter_Users_Object.UPN[0])>' with User2 - '$($Enter_Users_Object.UserDisplayName[1])<$($Enter_Users_Object.UPN[1])>' " -F Yellow
                 Write-Host " "
                 Start-Sleep 2

                    #Gather Azure AD group details for User1
                    $User1_Email_Address = $($Enter_Users_Object.UPN[0]) 
                    $Users1_Group_Names = $(Get-AllMSEntraIDGroupsOfUser -UserID $($Enter_Users_Object.UserObjectID[0])) | Where-Object {$_.'@odata.type' -eq  '#microsoft.graph.group' -and $_.SecurityEnabled -eq $True} | Select-Object -Property Id, displayName, groupTypes, membershipRule, securityEnabled
                    $User1_All_Groups = ($Users1_Group_Names).DisplayName

                    #Gather Azure AD group details for User2
                    $User2_Email_Address = $($Enter_Users_Object.UPN[1])
                    $Users2_Group_Names = $(Get-AllMSEntraIDGroupsOfUser -UserID $($Enter_Users_Object.UserObjectID[1]))  | Where-Object {$_.'@odata.type' -eq '#microsoft.graph.group' -and $_.SecurityEnabled -eq $True} | Select-Object -Property Id, displayName, groupTypes, membershipRule, securityEnabled
                    $User2_All_Groups = ($Users2_Group_Names).DisplayName

                    #Stores compared Azure AD groups into a Variable
                    Try 
                        {
                                $AzureAD_Group_Comparision_Between_Two_Users = Compare-Object -ReferenceObject $($User1_All_Groups) -DifferenceObject $($User2_All_Groups) -IncludeEqual -ErrorAction Stop
                        }
                    Catch 
                        {
                            Write-Host "Error Occured while comparing two users group membership: $($Error[0])" -F Red
                        }
                           

                    $CommonValues = $AzureAD_Group_Comparision_Between_Two_Users | Where-Object { $_.SideIndicator -eq '==' } | Select-Object -ExpandProperty InputObject -Unique

                    If (($CommonValues| Measure-Object).Count -gt 0) 
                        {
                            Write-Host ("---" * 25)
                            Write-Host "User <$User1_Email_Address> and <$User2_Email_Address> has '$(($CommonValues| Measure-Object).Count)' AzureAD<Microsoft Entra ID>Group(s) in common : " -F White
                            Write-Host " "
                            $Common_AAD_Groups = @()
                            $Common_Counter = 0
                            ForEach ($CommonValue in $CommonValues)
                                {
                                    $Common_Counter+=1
                                    Write-Host "[$($Common_Counter)] $($CommonValue)" -F Green

                                    $FoundGroupDetails = Get-AADGroup -Filter "DisplayName Eq '$CommonValue'" | Where-Object {$_.SecurityEnabled -eq $True} | Select-Object @{n="Group_Object_ID";e={$_.Id}},
                                    @{n="Group_Name";e={$_.displayName}},
                                    @{n="Group_Type";e={$_.groupTypes}},
                                    @{n="Membership_Rule";e={$_.membershipRule}},
                                    @{n="Is_It_A_Security_Group";e={$_.securityEnabled}}

                                    If ($FoundGroupDetails) 
                                        {
                                            $Common_AAD_Groups += [PSCustomObject]@{

                                                                                            "Group_Object_ID" = $FoundGroupDetails.Group_Object_ID.ToUpper()
                                                                                            "Group_Name"      = $FoundGroupDetails.Group_Name
                                                                                            "Group_Type"      = If ($FoundGroupDetails.Group_Type) {$FoundGroupDetails.Group_Type} Else {"Static / Assigned"}
                                                                                            "Membership_Rule" = If ($FoundGroupDetails.Membership_Rule) {$FoundGroupDetails.Membership_Rule} Else {"Null"}
                                                                                            "Is_It_A_Security_Group" = $FoundGroupDetails.Is_It_A_Security_Group
        
                                                                                        }
                                    }

                                }
                            
                                # Write-Output $Common_AAD_Groups | Format-Table
                        }
                    Else 
                        {
                            Write-Host ("---" * 25)
                            Write-Host "User <$User1_Email_Address> and <$User2_Email_Address> has no AzureAD<Microsoft Entra ID>Group(s) in common. " -F Red
                        }

                    Write-Host " "

                    #User1's group only.
                    $Unique_AADGroups_User1 = $AzureAD_Group_Comparision_Between_Two_Users | Where-Object { $_.SideIndicator -eq '<=' } | Select-Object -ExpandProperty InputObject
                    If (($Unique_AADGroups_User1 | Measure-Object).Count -gt 0) 
                        {
                            Write-Host ("---" * 25)
                            Write-Host "User <$User1_Email_Address> is a member of below AzureAD<Microsoft Entra ID>Group(s), but not User <$User2_Email_Address>:" -F Cyan
                            Write-Host " "
                            $User1_Unique_AAD_Groups = @()
                            $User1_Counter = 0
                            ForEach ($EachUnique_AADGroup_User1 in $Unique_AADGroups_User1)
                                    {
                                        $User1_Counter+=1
                                        Write-Host "[$($User1_Counter)] $($EachUnique_AADGroup_User1)" -F Yellow
                                        Write-Host " "
                                        $Found_Unique_AADGroups_User1 = Get-AADGroup -Filter "DisplayName Eq '$EachUnique_AADGroup_User1'"  | Where-Object {$_.SecurityEnabled -eq $True} | Select-Object @{n="Group_Object_ID";e={$_.Id}},
                                        @{n="Group_Name";e={$_.displayName}},
                                        @{n="Group_Type";e={$_.groupTypes}},
                                        @{n="Membership_Rule";e={$_.membershipRule}},
                                        @{n="Is_It_A_Security_Group";e={$_.securityEnabled}}

                                        If ($Found_Unique_AADGroups_User1) 
                                            {

                                                $User1_Unique_AAD_Groups += [PSCustomObject]@{

                                                    "Group_Object_ID"   = $Found_Unique_AADGroups_User1.Group_Object_ID.ToUpper()
                                                    "Group_Name"        = $Found_Unique_AADGroups_User1.Group_Name
                                                    "Group_Type"        = If ($Found_Unique_AADGroups_User1.Group_Type) {$Found_Unique_AADGroups_User1.Group_Type} Else {"Static / Assigned"}
                                                    "Membership_Rule"   = If ($Found_Unique_AADGroups_User1.Membership_Rule) {$Found_Unique_AADGroups_User1.Membership_Rule} Else {"Null"}
                                                    "Is_It_A_Security_Group"   = $Found_Unique_AADGroups_User1.Is_It_A_Security_Group
                                                }
                                    }

                                    }

                                    # Write-Output $User1_Unique_AAD_Groups | Format-Table
                        }

                    Write-Host " "

                     #User2's group only.

                    $Unique_AADGroups_User2 = $AzureAD_Group_Comparision_Between_Two_Users | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject
                    If (($Unique_AADGroups_User2| Measure-Object).Count -gt 0) 
                        {
                            Write-Host ("---" * 25)
                            Write-Host "User <$User2_Email_Address> is a member of below AzureAD<Microsoft Entra ID>Group(s), but not User <$User1_Email_Address>:" -F White
                            Write-Host " "
                            $User2_Unique_AAD_Groups = @()
                            #$Found_Unique_AADGroups_User2 = @{}
                            $User2_Counter = 0
                            ForEach ($EachUnique_AADGroup_User2 in $Unique_AADGroups_User2)
                                {
                                    $User2_Counter+=1
                                    Write-Host "[$($User2_Counter)] $($EachUnique_AADGroup_User2)" -F Magenta
                                    Write-Host " "
                                    $Found_Unique_AADGroups_User2 = Get-AADGroup -Filter "DisplayName Eq '$EachUnique_AADGroup_User2'"  | Where-Object {$_.SecurityEnabled -eq $True} | Select-Object @{n="Group_Object_ID";e={$_.Id}},
                                    @{n="Group_Name";e={$_.displayName}},
                                    @{n="Group_Type";e={$_.groupTypes}},
                                    @{n="Membership_Rule";e={$_.membershipRule}},
                                    @{n="Is_It_A_Security_Group";e={$_.securityEnabled}}

                                    If ($Found_Unique_AADGroups_User2)
                                        {
                                            $User2_Unique_AAD_Groups += [PSCustomObject]@{

                                                "Group_Object_ID"   = $Found_Unique_AADGroups_User2.Group_Object_ID.ToUpper()
                                                "Group_Name"        = $Found_Unique_AADGroups_User2.Group_Name
                                                "Group_Type"        = If ($Found_Unique_AADGroups_User2.Group_Type) {$Found_Unique_AADGroups_User2.Group_Type} Else {"Static / Assigned"}
                                                "Membership_Rule"   = If ($Found_Unique_AADGroups_User2.Membership_Rule) {$Found_Unique_AADGroups_User2.Membership_Rule} Else {"Null"}
                                                "Is_It_A_Security_Group"   = $Found_Unique_AADGroups_User2.Is_It_A_Security_Group
                                            }
                                    }
                                }
                            #Write-Output $User2_Unique_AAD_Groups| Format-Table
                        }

                    Write-Host " "
                }
            Else
                 {
                    Write-Host "You selected '$($UserObjectIds.count)' user's for the group comparison, see below. Please re-run the script and select just two user accounts for their Group membership comparision." -F Red
                    Write-Host ("---" * 30) -F Yellow
                    Write-Output $($Enter_Users_Object)
                    Write-Host " "
                    Start-Sleep 5
                    Exit
                }
            
            $HTML_Report_Common_AAD_Groups = $Common_AAD_Groups | ConvertTo-Html -Property Group_Name, Group_Object_ID, Group_Type, Membership_Rule, Is_It_A_Security_Group -Fragment -PreContent "<h2> User1 and User2 has '$(($CommonValues| Measure-Object).Count)' AzureAD<Microsoft Entra ID>Group(s) in common </h2>"
            $HTML_Report_Common_AAD_Groups = $HTML_Report_Common_AAD_Groups -replace '<td>DynamicMembership</td>','<td class="DynamicMembershipType">DynamicMembership</td>'
            $HTML_Report_Common_AAD_Groups = $HTML_Report_Common_AAD_Groups -replace '<td>Static / Assigned</td>','<td class="StaticMembershipType">Static / Assigned</td>'

            $HTML_Report_User1_Unique_AAD_Groups = $User1_Unique_AAD_Groups | ConvertTo-Html -Property Group_Name, Group_Object_ID, Group_Type, Membership_Rule,Is_It_A_Security_Group -Fragment -PreContent "<h2> User1 is a member of below AzureAD<Microsoft Entra ID>Group(s), but not User2 </h2>"
            $HTML_Report_User1_Unique_AAD_Groups = $HTML_Report_User1_Unique_AAD_Groups -replace '<td>DynamicMembership</td>','<td class="DynamicMembershipType">DynamicMembership</td>'
            $HTML_Report_User1_Unique_AAD_Groups = $HTML_Report_User1_Unique_AAD_Groups -replace '<td>Static / Assigned</td>','<td class="StaticMembershipType">Static / Assigned</td>'

            $HTML_Report_User2_Unique_AAD_Groups = $User2_Unique_AAD_Groups | ConvertTo-Html -Property Group_Name, Group_Object_ID, Group_Type, Membership_Rule,Is_It_A_Security_Group -Fragment -PreContent "<h2> User2 is a member of below AzureAD<Microsoft Entra ID>Group(s), but not User1 </h2>"
            $HTML_Report_User2_Unique_AAD_Groups = $HTML_Report_User2_Unique_AAD_Groups -replace '<td>DynamicMembership</td>','<td class="DynamicMembershipType">DynamicMembership</td>'
            $HTML_Report_User2_Unique_AAD_Groups = $HTML_Report_User2_Unique_AAD_Groups -replace '<td>Static / Assigned</td>','<td class="StaticMembershipType">Static / Assigned</td>'

            #Date & Time
            $Current_Date_Time_For_HTMLReport = (Get-Date -Format "dd:MMMM:yyyy hh:mm:ss tt")

            #TimeZone
            $Current_TimeZone = (Get-TimeZone).Id #-replace " ", "_"

            # $HTMLReportTitle = "<h1> Status Of Intune Assignment/s for Microsoft Entra ID Group: {$($GroupName)}</h1>"
            $HTMLReportTitle = "<h1> AzureAD <MS Entra ID> Groups comparison between User1 '$($User1_Email_Address)' & User2 '$($User2_Email_Address)' </h1>"
            
            $Final_HTML_Report = ConvertTo-Html -Body "$HTMLReportTitle $HTML_Report_Common_AAD_Groups $HTML_Report_User1_Unique_AAD_Groups $HTML_Report_User2_Unique_AAD_Groups" -Head $CSS_Header -PostContent "<p id='CreationDate'>Report created by $($Tenant_Connection_Details.UPN.ToUpper()) on $($Current_Date_Time_For_HTMLReport) $($Current_TimeZone).</p>"
            $Final_HTML_Report | Out-File -FilePath $($Setup_Folder_And_HTML_File.ReportFilePath)

            Start-Process -FilePath $($Setup_Folder_And_HTML_File.ReportFilePath)
            Start-Sleep 2

        }

         #Device's AAD Group Comparision.
        "2" 
         {
                Write-Host "You chose option '$($Make_A_Selection)' for comparing Azure AD / Ms Entra ID group membership of Intune Managed Devices....." -F Cyan
                "`n"
                Write-Host " "
                Write-Host "Search and Select Intune Managed Device from the displayed list on screen and Press OK:" -f White
                Start-Sleep 2

                $Enter_IntuneManagedDevices_Object = $(Get-AllIntuneManagedDevices | Select-Object -Property @{Name="IntuneDeviceName";Expression={$_.DeviceName.ToUpper()}}, 
                @{Name="OperatingSystem";Expression={$_.OperatingSystem.ToUpper()}},
                @{Name="LastSyncDateTime";Expression={$_.LastSyncDateTime}},
                @{Name="AzureADDeviceId";Expression={$_.AzureADDeviceId.ToUpper()}},
                @{Name="ManagedDeviceOwnerType";Expression={$_.ManagedDeviceOwnerType.ToUpper()}}, 
                @{Name="ManagementAgent";Expression={$_.ManagementAgent.ToUpper()}}  | Out-GridView -Title "Please search and select two Intune Managed Endpoint(Device) name from the displayed list and Press OK for their AAD Group Comparison: " -OutputMode Multiple)
                Write-Host " "
                Start-Sleep 2

                $Selected_IntuneManaged_Device_Count = $Enter_IntuneManagedDevices_Object.AzureADDeviceId

                # $Selected_Object_DisplayName =  $Selected_Device.IntuneDeviceName
                $Selected_Intune_Managed_Device_AzureADDeviceID = $($Enter_IntuneManagedDevices_Object.AzureADDeviceId)
                $Device01_AzureAD_Object_ID = (Get-ADObjectIdOfAnIntuneManagedDevice -IntuneAzureADDeviceID $($Selected_Intune_Managed_Device_AzureADDeviceID[0])).Id
                $Device02_AzureAD_Object_ID = (Get-ADObjectIdOfAnIntuneManagedDevice -IntuneAzureADDeviceID $($Selected_Intune_Managed_Device_AzureADDeviceID[1])).Id

                #Initialize Empty array to hold groups.
                $Device01_All_Groups = @()
                $Device02_All_Groups = @()

                If ($Selected_IntuneManaged_Device_Count.Count -eq 2)
                    {
                        $Setup_Folder_And_HTML_File = Invoke-HTMLReportFolder -EntityName "IntuneManagedDevices"
                        Write-Host "Processing AzureAD Group Membership comparison for Device1 - '$($Enter_IntuneManagedDevices_Object.IntuneDeviceName[0])' with Device2 - '$($Enter_IntuneManagedDevices_Object.IntuneDeviceName[1])' " -F Yellow
                        Write-Host " "
                        Start-Sleep 2

                        #Gather Azure AD group details for Device 01
                        $Device01_AADGroups = $(Get-AllGroupsOfAnIntuneManagedDevice -AzureActiveDirectoryObjectID $($Device01_AzureAD_Object_ID))  | Select-Object -Property Id, displayName, groupTypes, membershipRule, securityEnabled
                        $Device01_All_Groups = $Device01_AADGroups.DisplayName

                        #Gather Azure AD group details for Device 02
                        $Device02_AADGroups = $(Get-AllGroupsOfAnIntuneManagedDevice -AzureActiveDirectoryObjectID $($Device02_AzureAD_Object_ID))  | Select-Object -Property Id, displayName, groupTypes, membershipRule, securityEnabled
                        $Device02_All_Groups = $Device02_AADGroups.DisplayName

                        #Stores compared Azure AD groups into a Variable
                        Try 
                            {
                                $AzureAD_Group_Comparision_Between_Two_Devices = Compare-Object -ReferenceObject $($Device01_All_Groups) -DifferenceObject $($Device02_All_Groups) -IncludeEqual -ErrorAction Stop
                            }
                        Catch 
                            {
                                Write-Host "Error Occured while comparing Devices group membership: $($Error[0])" -F Red
                            }

                        $CommonValues = $AzureAD_Group_Comparision_Between_Two_Devices | Where-Object { $_.SideIndicator -eq '==' } | Select-Object -ExpandProperty InputObject -Unique

                        If (($CommonValues| Measure-Object).Count -gt 0) 
                            {
                                Write-Host ("---" * 25)
                                Write-Host "Device1 - '$($Enter_IntuneManagedDevices_Object.IntuneDeviceName[0])' and Device2 - '$($Enter_IntuneManagedDevices_Object.IntuneDeviceName[1])' has '$(($CommonValues| Measure-Object).Count)' AzureAD<Microsoft Entra ID>Group(s) in common : " -F White
                                Write-Host " "
                                $IntuneManagedDevices_Common_AAD_Groups = @()
                                $Common_Counter = 0
                                ForEach ($CommonValue in $CommonValues)
                                {
                                    $Common_Counter+=1
                                    Write-Host "[$($Common_Counter)] $($CommonValue)" -F Green

                                    $FoundGroupDetails = Get-AADGroup -Filter "DisplayName Eq '$CommonValue'" | Where-Object {$_.SecurityEnabled -eq $True} | Select-Object @{n="Group_Object_ID";e={$_.Id}},
                                    @{n="Group_Name";e={$_.displayName}},
                                    @{n="Group_Type";e={$_.groupTypes}},
                                    @{n="Membership_Rule";e={$_.membershipRule}},
                                    @{n="Is_It_A_Security_Group";e={$_.securityEnabled}}

                                    If ($FoundGroupDetails) 
                                        {
                                            $IntuneManagedDevices_Common_AAD_Groups += [PSCustomObject]@{

                                                                                            "Group_Object_ID" = $FoundGroupDetails.Group_Object_ID.ToUpper()
                                                                                            "Group_Name"      = $FoundGroupDetails.Group_Name
                                                                                            "Group_Type"      = If ($FoundGroupDetails.Group_Type) {$FoundGroupDetails.Group_Type} Else {"Static / Assigned"}
                                                                                            "Membership_Rule" = If ($FoundGroupDetails.Membership_Rule) {$FoundGroupDetails.Membership_Rule} Else {"Null"}
                                                                                            "Is_It_A_Security_Group" = $FoundGroupDetails.Is_It_A_Security_Group
        
                                                                                        }
                                    }

                                }
                            

                            }
                        Else 
                            {
                                Write-Host ("---" * 25)
                                Write-Host "Device1 - '$($Enter_IntuneManagedDevices_Object.IntuneDeviceName[0])' and Device2 - '$($Enter_IntuneManagedDevices_Object.IntuneDeviceName[1])' has no AzureAD<Microsoft Entra ID>Group(s) in common. " -F Red
                            }

                        Write-Host " "

                        #AAD groups associated with Device01 only.
                        $Unique_AADGroups_Device01 = $AzureAD_Group_Comparision_Between_Two_Devices | Where-Object { $_.SideIndicator -eq '<=' } | Select-Object -ExpandProperty InputObject

                        If (($Unique_AADGroups_Device01 | Measure-Object).Count -gt 0) 
                            {
                                Write-Host ("---" * 25)
                                Write-Host "Device1 - '$($Enter_IntuneManagedDevices_Object.IntuneDeviceName[0])' is a member of below AzureAD<Microsoft Entra ID>Group(s), but not Device2 - '$($Enter_IntuneManagedDevices_Object.IntuneDeviceName[1])':" -F Cyan
                                Write-Host " "
                                $Device01_Unique_AAD_Groups = @()
                                $Device01_Counter = 0
                                ForEach ($EachUnique_AADGroup_Device01 in $Unique_AADGroups_Device01)
                                    {
                                        $Device01_Counter+=1
                                        Write-Host "[$($Device01_Counter)] $($EachUnique_AADGroup_Device01)" -F Yellow
                                        Write-Host " "

                                        $Found_Unique_AADGroups_Device01 = Get-AADGroup -Filter "DisplayName Eq '$EachUnique_AADGroup_Device01'"  | Where-Object {$_.SecurityEnabled -eq $True} | Select-Object @{n="Group_Object_ID";e={$_.Id}},
                                        @{n="Group_Name";e={$_.displayName}},
                                        @{n="Group_Type";e={$_.groupTypes}},
                                        @{n="Membership_Rule";e={$_.membershipRule}},
                                        @{n="Is_It_A_Security_Group";e={$_.securityEnabled}}


                                        If ($Found_Unique_AADGroups_Device01) 
                                        {

                                            $Device01_Unique_AAD_Groups += [PSCustomObject]@{

                                                "Group_Object_ID"          = $Found_Unique_AADGroups_Device01.Group_Object_ID.ToUpper()
                                                "Group_Name"               = $Found_Unique_AADGroups_Device01.Group_Name
                                                "Group_Type"               = If ($Found_Unique_AADGroups_Device01.Group_Type) {$Found_Unique_AADGroups_Device01.Group_Type} Else {"Static / Assigned"}
                                                "Membership_Rule"          = If ($Found_Unique_AADGroups_Device01.Membership_Rule) {$Found_Unique_AADGroups_Device01.Membership_Rule} Else {"Null"}
                                                "Is_It_A_Security_Group"   = $Found_Unique_AADGroups_Device01.Is_It_A_Security_Group
                                            }
                                        }


                                    }


                            }
                        Else 
                            {
                                $null
                            }

                        Write-Host " "

                        #AAD groups associated with Device02 only.
                        $Unique_AADGroups_Device02 = $AzureAD_Group_Comparision_Between_Two_Devices | Where-Object { $_.SideIndicator -eq '=>' } | Select-Object -ExpandProperty InputObject

                        If (($Unique_AADGroups_Device02 | Measure-Object).Count -gt 0) 
                            {
                                Write-Host ("---" * 25)
                                Write-Host "Device2 - '$($Enter_IntuneManagedDevices_Object.IntuneDeviceName[1])' is a member of below AzureAD<Microsoft Entra ID>Group(s), but not Device1 - '$($Enter_IntuneManagedDevices_Object.IntuneDeviceName[0])':" -F Cyan
                                Write-Host " "
                                $Device02_Unique_AAD_Groups = @()
                                $Device02_Counter = 0
                                ForEach ($EachUnique_AADGroup_Device02 in $Unique_AADGroups_Device02)
                                    { 
                                        $Device02_Counter+=1
                                        Write-Host "[$($Device02_Counter)] $($EachUnique_AADGroup_Device02)" -F Yellow
                                        Write-Host " "

                                        $Found_Unique_AADGroups_Device02 = Get-AADGroup -Filter "DisplayName Eq '$EachUnique_AADGroup_Device02'"  | Where-Object {$_.SecurityEnabled -eq $True} | Select-Object @{n="Group_Object_ID";e={$_.Id}},
                                        @{n="Group_Name";e={$_.displayName}},
                                        @{n="Group_Type";e={$_.groupTypes}},
                                        @{n="Membership_Rule";e={$_.membershipRule}},
                                        @{n="Is_It_A_Security_Group";e={$_.securityEnabled}}

                                        If ($Found_Unique_AADGroups_Device02) 
                                            {

                                                $Device02_Unique_AAD_Groups += [PSCustomObject]@{

                                                    "Group_Object_ID"          = $Found_Unique_AADGroups_Device02.Group_Object_ID.ToUpper()
                                                    "Group_Name"               = $Found_Unique_AADGroups_Device02.Group_Name
                                                    "Group_Type"               = If ($Found_Unique_AADGroups_Device02.Group_Type) {$Found_Unique_AADGroups_Device02.Group_Type} Else {"Static / Assigned"}
                                                    "Membership_Rule"          = If ($Found_Unique_AADGroups_Device02.Membership_Rule) {$Found_Unique_AADGroups_Device02.Membership_Rule} Else {"Null"}
                                                    "Is_It_A_Security_Group"   = $Found_Unique_AADGroups_Device02.Is_It_A_Security_Group
                                                }
                                            }

                                    }

                            }

                        Else 
                            {
                                $Null
                            }

                            Write-Host " "
                        
                    }

                Else
                    {
                       Write-Host "You selected '$($Selected_IntuneManaged_Device_Count.Count)' Intune Managed Devices for the group comparison, see below. Please re-run the script and select just two Endpoints for their Group membership comparision." -F Red
                       Write-Host ("---" * 30) -F Yellow
                       Write-Output $($Enter_IntuneManagedDevices_Object)
                       Write-Host " "
                       Start-Sleep 5
                       Exit
                    }

                $HTML_Report_IntuneManagedDevices_Common_AAD_Groups = $IntuneManagedDevices_Common_AAD_Groups | ConvertTo-Html -Property Group_Name, Group_Object_ID, Group_Type, Membership_Rule, Is_It_A_Security_Group -Fragment -PreContent "<h2> Device01 and Device02 has '$(($CommonValues| Measure-Object).Count)' AzureAD<Microsoft Entra ID>Group(s) in common </h2>"
                $HTML_Report_IntuneManagedDevices_Common_AAD_Groups = $HTML_Report_IntuneManagedDevices_Common_AAD_Groups -replace '<td>DynamicMembership</td>','<td class="DynamicMembershipType">DynamicMembership</td>'
                $HTML_Report_IntuneManagedDevices_Common_AAD_Groups = $HTML_Report_IntuneManagedDevices_Common_AAD_Groups -replace '<td>Static / Assigned</td>','<td class="StaticMembershipType">Static / Assigned</td>'
    
                $HTML_Report_Device01_Unique_AAD_Groups = $Device01_Unique_AAD_Groups | ConvertTo-Html -Property Group_Name, Group_Object_ID, Group_Type, Membership_Rule,Is_It_A_Security_Group -Fragment -PreContent "<h2> Device01 is a member of below AzureAD<Microsoft Entra ID>Group(s), but not Device02 </h2>"
                $HTML_Report_Device01_Unique_AAD_Groups = $HTML_Report_Device01_Unique_AAD_Groups -replace '<td>DynamicMembership</td>','<td class="DynamicMembershipType">DynamicMembership</td>'
                $HTML_Report_Device01_Unique_AAD_Groups = $HTML_Report_Device01_Unique_AAD_Groups -replace '<td>Static / Assigned</td>','<td class="StaticMembershipType">Static / Assigned</td>'
    
                $HTML_Report_Device02_Unique_AAD_Groups = $Device02_Unique_AAD_Groups | ConvertTo-Html -Property Group_Name, Group_Object_ID, Group_Type, Membership_Rule,Is_It_A_Security_Group -Fragment -PreContent "<h2> Device02 is a member of below AzureAD<Microsoft Entra ID>Group(s), but not Device01 </h2>"
                $HTML_Report_Device02_Unique_AAD_Groups = $HTML_Report_Device02_Unique_AAD_Groups -replace '<td>DynamicMembership</td>','<td class="DynamicMembershipType">DynamicMembership</td>'
                $HTML_Report_Device02_Unique_AAD_Groups = $HTML_Report_Device02_Unique_AAD_Groups -replace '<td>Static / Assigned</td>','<td class="StaticMembershipType">Static / Assigned</td>'

                #Date & Time
                $Current_Date_Time_For_HTMLReport = (Get-Date -Format "dd:MMMM:yyyy hh:mm:ss tt")

                #TimeZone
                $Current_TimeZone = (Get-TimeZone).Id #-replace " ", "_"

                # $HTMLReportTitle = "<h1> Status Of Intune Assignment/s for Microsoft Entra ID Group: {$($GroupName)}</h1>"
                $HTMLReportTitle = "<h1> AzureAD <MS Entra ID> Groups comparison between Device1 - '$($Enter_IntuneManagedDevices_Object.IntuneDeviceName[0])' & Device2 - '$($Enter_IntuneManagedDevices_Object.IntuneDeviceName[1])' </h1>"

                $Final_HTML_Report = ConvertTo-Html -Body "$HTMLReportTitle $HTML_Report_IntuneManagedDevices_Common_AAD_Groups$HTML_Report_Device01_Unique_AAD_Groups $HTML_Report_Device02_Unique_AAD_Groups" -Head $CSS_Header -PostContent "<p id='CreationDate'>Report created by $($Tenant_Connection_Details.UPN.ToUpper()) on $($Current_Date_Time_For_HTMLReport) $($Current_TimeZone).</p>"
                $Final_HTML_Report | Out-File -FilePath $($Setup_Folder_And_HTML_File.ReportFilePath)
    
                Start-Process -FilePath $($Setup_Folder_And_HTML_File.ReportFilePath)
                Start-Sleep 2
         }

          #EXIT to terminate current Powershell session.
         "3"
            {
                Write-Host "You selected option '$Make_A_Selection'." -F Red -NoNewline 
                Write-Host " Exiting the session on device name $($Env:COMPUTERNAME). Goodbye !" -ForegroundColor Green
                Write-Host " "
                Start-Sleep 10
            }

        Default
            {
                Write-Host "Entered input is invalid: '$($Make_A_Selection)'" -F Red
                Write-Host "Please rerun the script with valid input. This script will exit in 5 seconds !!!" -F Yellow
                Start-Sleep 5
                Exit
            }
    }

#End
Write-Host  ("-----"*5 + "Powershell code execution completed" +"-----"*5 ) -ForegroundColor Green
