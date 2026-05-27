Function Send-TeamsNotification {

    [CmdletBinding()]
    param (

        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("INFO","WARN","ERROR","FAILURE")]
        [string]$Severity = "INFO",

        [string]$PipelineName = "GitHub Pipeline",

        [string]$Repository,

        [string]$Branch,

        [string]$Committer,

        [string]$WorkflowUrl
    )

    Try {

        # -------------------------------------------------
        # Select Webhook Based On Severity
        # -------------------------------------------------

        $WebhookMap = @{
            "INFO"    = $env:TEAMS_INFO_WEBHOOK
            "WARN"    = $env:TEAMS_WARN_WEBHOOK
            "ERROR"   = $env:TEAMS_ERROR_WEBHOOK
            "FAILURE" = $env:TEAMS_FAILURE_WEBHOOK
        }

        $WebhookUrl = $WebhookMap[$Severity]

        if ([string]::IsNullOrWhiteSpace($WebhookUrl)) {
            throw "Webhook URL missing for severity: $Severity"
        }

        # -------------------------------------------------
        # Teams Card Colors
        # -------------------------------------------------

        $ColorMap = @{
            "INFO"    = "0076D7"
            "WARN"    = "FFA500"
            "ERROR"   = "FF0000"
            "FAILURE" = "8B0000"
        }

        $ThemeColor = $ColorMap[$Severity]

        # -------------------------------------------------
        # Build Teams Payload
        # -------------------------------------------------

        $Body = @{
            "@type"    = "MessageCard"
            "@context" = "http://schema.org/extensions"

            summary    = "$Severity Notification"

            themeColor = $ThemeColor

            title      = "[$Severity] $PipelineName"

            sections   = @(
                @{
                    facts = @(
                        @{
                            name  = "Repository"
                            value = $Repository
                        },
                        @{
                            name  = "Branch"
                            value = $Branch
                        },
                        @{
                            name  = "Committer"
                            value = $Committer
                        },
                        @{
                            name  = "Severity"
                            value = $Severity
                        }
                    )

                    text = $Message
                }
            )

            potentialAction = @(
                @{
                    "@type" = "OpenUri"
                    name    = "View Pipeline"

                    targets = @(
                        @{
                            os  = "default"
                            uri = $WorkflowUrl
                        }
                    )
                }
            )
        }

        # -------------------------------------------------
        # Send Notification
        # -------------------------------------------------

        Invoke-RestMethod `
            -Method POST `
            -Uri $WebhookUrl `
            -Body ($Body | ConvertTo-Json -Depth 10) `
            -ContentType 'application/json'

        Write-Host "Teams notification sent successfully."

    }
    Catch {

        Write-Error "Failed to send Teams notification."
        Write-Error $_.Exception.Message
    }
}