Function Write-StructuredLog {

    param (
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","FAILURE")]
        [string]$Severity = "INFO"
    )

    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Write-Host "[$TimeStamp] [$Severity] $Message"
}