packer {
  required_plugins {
    azure = {
      source  = "github.com/hashicorp/azure"
      version = "~> 2"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = "~> 1"
    }
  }
}

source "azure-arm" "windows_factory" {
  # Authentication details
  client_id       = var.client_id
  tenant_id       = var.tenant_id
  subscription_id = var.subscription_id

  # Build VM environment configuration
  managed_image_resource_group_name = var.resource_group
  managed_image_name                 = "${var.gallery_image_name}-raw"
  
  os_type         = "Windows"
  image_publisher = "MicrosoftWindowsServer"
  image_offer     = "WindowsServer"
  image_sku       = "2022-Datacenter-Azure-Edition"
  
  vm_size         = "Standard_D2s_v5"
  location        = var.location

  # WinRM Connection configurations used by Packer & Ansible
  communicator   = "winrm"
  winrm_username = "packeradmin"
  winrm_password = var.client_secret
  winrm_use_ssl  = true
  winrm_insecure = true

  # Managed Bootstrapping Settings
  shared_image_gallery_destination {
    subscription        = var.subscription_id
    resource_group      = var.resource_group
    gallery_name        = var.gallery_name
    image_name          = var.gallery_image_name
    image_version       = "1.0.0"
    replication_regions = [var.location]
  }
}

build {
  sources = ["source.azure-arm.windows_factory"]

  # Step 1: Bootstrap WinRM securely via custom script payload
  provisioner "powershell" {
    script = "../scripts/Setup-WinRM.ps1"
  }

  # Step 2: Hand over VM to Ansible for Enterprise Configuration Management
  provisioner "ansible" {
    playbook_file    = "../ansible/playbooks/configure-windows.yml"
    user             = "packeradmin"
    use_proxy        = false
    ansible_env_vars = [
      "ANSIBLE_CONFIG=../ansible/ansible.cfg"
    ]
    extra_arguments  = [
      "-e", "ansible_password=${var.client_secret}",
      "-e", "ansible_connection=winrm",
      "-e", "ansible_winrm_server_cert_validation=ignore"
    ]
  }

  # Step 3: Deprovision & Sysprep image for clean generalized cloning
  provisioner "powershell" {
    inline = [
      "Write-Output 'Executing System Deprovisioning / Sysprep...'",
      "& $env:SystemRoot\\System32\\Sysprep\\Sysprep.exe /oobe /generalize /quiet /quit /mode:vm",
      "while ((Get-Service sysprep, sshd -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'}).Count -gt 0) { Start-Sleep -Seconds 2 }"
    ]
  }
}