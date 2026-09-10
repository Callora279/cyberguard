terraform {
  required_version = ">= 1.6"
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.40"
    }
  }
}

variable "do_token" { type = string, sensitive = true }
variable "region" {
  type    = string
  default = "lon1"
}
variable "environment" {
  type    = string
  default = "production"
}

provider "digitalocean" {
  token = var.do_token
}

module "networking" {
  source      = "./modules/networking"
  environment = var.environment
  region      = var.region
}

module "compute" {
  source      = "./modules/compute"
  environment = var.environment
  region      = var.region
  vpc_id      = module.networking.vpc_id
}

output "api_endpoint" { value = module.compute.api_endpoint }
output "database_uri" {
  value     = module.compute.database_uri
  sensitive = true
}
