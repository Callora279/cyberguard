variable "environment" { type = string }
variable "region" { type = string }
variable "vpc_id" { type = string }

resource "digitalocean_kubernetes_cluster" "this" {
  name    = "cyberguard-${var.environment}"
  region  = var.region
  version = "1.30.1-do.0"
  vpc_uuid = var.vpc_id

  node_pool {
    name       = "worker-pool"
    size       = "s-2vcpu-4gb"
    node_count = 3
    auto_scale = true
    min_nodes  = 3
    max_nodes  = 6
  }
}

resource "digitalocean_database_cluster" "postgres" {
  name       = "cyberguard-${var.environment}-pg"
  engine     = "pg"
  version    = "16"
  size       = "db-s-1vcpu-2gb"
  region     = var.region
  node_count = 1
  private_network_uuid = var.vpc_id
}

resource "digitalocean_database_cluster" "redis" {
  name       = "cyberguard-${var.environment}-redis"
  engine     = "redis"
  version    = "7"
  size       = "db-s-1vcpu-1gb"
  region     = var.region
  node_count = 1
  private_network_uuid = var.vpc_id
}

output "api_endpoint" { value = digitalocean_kubernetes_cluster.this.endpoint }
output "database_uri" {
  value     = digitalocean_database_cluster.postgres.private_uri
  sensitive = true
}
