variable "client_id" {
  type        = string
  description = "The Azure Service Principal Client ID"
}

variable "tenant_id" {
  type        = string
  description = "The Azure Tenant ID"
}

variable "subscription_id" {
  type        = string
  description = "The Azure Subscription ID"
}

variable "client_secret" {
  type        = string
  description = "WinRM local administrator password fetched from Key Vault"
  sensitive   = true
}

variable "location" {
  type    = string
  default = "East US"
}

variable "gallery_name" {
  type    = string
  default = "gal_enterprise_images"
}

variable "gallery_image_name" {
  type    = string
  default = "win-server-2022-hardened"
}

variable "resource_group" {
  type    = string
  default = "rg-image-factory-prod"
}