<#
    .SYNOPSIS
        Bootstrapping WinRM script for Packer-to-Ansible handoff.
#>
write-output "Configuring WinRM for Ansible deployment automation..."

# Create self-signed certificate for local WinRM HTTPS listener
$Cert = New-SelfSignedCertificate -CertstoreLocation Cert:\LocalMachine\My -DnsName "packer-builder-vm"

# Remove HTTP listener to strictly enforce encrypted paths
Remove-Item -Path WSMan:\LocalHost\Listener\* -Recurse -Force -ErrorAction SilentlyContinue

# Configure WSMan Listener for WinRM HTTPS
New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbprint $Cert.Thumbprint -Force

# Tweak WinRM service behaviors for high load configuration transfers
Set-Item -Path WSMan:\LocalHost\Service\Auth\Basic -Value $true
Set-Item -Path WSMan:\LocalHost\Service\AllowUnencrypted -Value $false
Set-Item -Path WSMan:\LocalHost\MaxTimeoutms -Value 1800000
Set-Item -Path WSMan:\LocalHost\Service\MaxConcurrentOperationsPerUser -Value 400

# Open Local Advanced Firewall Policies
Restart-Service winrm
New-NetFirewallRule -Name "Allow_WinRM_HTTPS" -DisplayName "WinRM HTTPS (Ansible Automation)" -Enabled True -Profile Any -Action Allow -Direction Inbound -LocalPort 5986 -Protocol TCP