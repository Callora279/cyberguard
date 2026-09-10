variable "environment" { type = string }
variable "region" { type = string }

resource "digitalocean_vpc" "this" {
  name     = "cyberguard-${var.environment}"
  region   = var.region
  ip_range = "10.20.0.0/16"
}

resource "digitalocean_project" "this" {
  name        = "cyberguard-${var.environment}"
  description = "CyberGuard AI - unified cyber risk platform"
  purpose     = "Web Application"
  environment = title(var.environment)
}

output "vpc_id" { value = digitalocean_vpc.this.id }
output "project_id" { value = digitalocean_project.this.id }
