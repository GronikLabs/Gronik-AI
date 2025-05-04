# ENTERPRISE INFRASTRUCTURE AS CODE (v5.3.0)
# NIST SP 800-204 | Terraform 1.5+ | Cross-Cloud Orchestration

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.16.2"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.23.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "3.19.0"
    }
  }
}

# Multi-Cloud Provider Configuration
provider "aws" {
  region = var.primary_region
  assume_role {
    role_arn = "arn:aws:iam::${var.account_id}:role/EnlivenAgentDeployer"
  }
}

provider "kubernetes" {
  host                   = module.enterprise_cluster.cluster_endpoint
  cluster_ca_certificate = base64decode(module.enterprise_cluster.cluster_certificate_authority_data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws-iam-authenticator"
    args        = ["token", "-i", module.enterprise_cluster.cluster_name]
  }
}

provider "vault" {
  address = "https://vault.${var.primary_region}.enliven.prod"
  auth_login {
    path = "auth/aws/login"
    parameters = {
      role = "enliven-agent-prod"
    }
  }
}

# Core Infrastructure Modules
module "enterprise_cluster" {
  source  = "terraform-aws-modules/eks/aws"
  version = "19.16.0"

  cluster_name    = "enliven-agent-prod"
  cluster_version = "1.28"
  vpc_id          = module.security_vpc.vpc_id
  subnet_ids      = module.security_vpc.private_subnets

  cluster_enabled_log_types = ["api", "audit", "authenticator"]

  node_groups = {
    cognitive_nodes = {
      desired_capacity = 5
      max_capacity     = 50
      min_capacity     = 5
      instance_types   = ["m6i.4xlarge"]
      gpu              = true
      k8s_labels = {
        workload-type = "ai-processing"
      }
    }
    stateful_nodes = {
      desired_capacity = 3
      instance_types   = ["r6i.2xlarge"]
      k8s_labels = {
        workload-type = "stateful"
      }
      taints = [{
        key    = "dedicated"
        value  = "stateful"
        effect = "NO_SCHEDULE"
      }]
    }
  }

  cluster_encryption_config = [{
    provider_key_arn = aws_kms_key.cluster_encryption.arn
    resources        = ["secrets"]
  }]
}

module "security_vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"

  name = "enliven-agent-prod-vpc"
  cidr = "10.255.0.0/16"

  azs             = ["${var.primary_region}a", "${var.primary_region}b"]
  private_subnets = ["10.255.1.0/24", "10.255.2.0/24"]
  public_subnets  = ["10.255.101.0/24", "10.255.102.0/24"]

  enable_nat_gateway   = true
  enable_dns_hostnames = true

  vpc_tags = {
    compliance-level = "nist-800-204"
  }
}

# Enterprise Security Infrastructure
resource "aws_kms_key" "cluster_encryption" {
  description             = "Enliven AGENT Cluster Encryption Key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.kms_policy.json
}

resource "vault_mount" "agent_secrets" {
  path        = "enliven/agent"
  type        = "kv-v2"
  description = "Secrets store for Enliven AGENT components"
}

# Service Mesh Configuration
module "istio_mesh" {
  source = "terraform-aws-modules/istio/aws"
  version = "3.4.0"

  cluster_name     = module.enterprise_cluster.cluster_name
  cluster_endpoint = module.enterprise_cluster.cluster_endpoint

  mesh_config = {
    enable_mtls          = true
    cert_manager_enabled = true
    auto_scaling = {
      min_replicas = 3
      max_replicas = 10
    }
  }
}

# Observability Stack
module "monitoring" {
  source  = "terraform-aws-modules/observability/aws"
  version = "2.8.0"

  cluster_name = module.enterprise_cluster.cluster_name
  enable_metrics = {
    prometheus = true
    cloudwatch = true
  }
  enable_logging = {
    fluent_bit = true
  }
  enable_tracing = {
    xray = true
  }

  retention_period = 731 # 2 years
}

# Database Tier
module "cognitive_db" {
  source  = "terraform-aws-modules/rds/aws"
  version = "6.1.1"

  identifier = "enliven-cognitive-db"

  engine               = "postgres"
  engine_version       = "15"
  major_engine_version = "15"
  instance_class       = "db.r6g.4xlarge"

  allocated_storage     = 1024
  max_allocated_storage = 2048

  multi_az               = true
  db_subnet_group_name   = module.security_vpc.database_subnet_group_name
  vpc_security_group_ids = [module.security_vpc.default_security_group_id]

  maintenance_window = "Sat:03:00-Sat:05:00"
  backup_window      = "05:00-07:00"

  tags = {
    data-classification = "restricted"
  }
}

# Output Definitions
output "cluster_endpoint" {
  description = "EKS Cluster API endpoint"
  value       = module.enterprise_cluster.cluster_endpoint
  sensitive   = true
}

output "database_connection" {
  description = "Cognitive DB connection string"
  value       = "postgres://${module.cognitive_db.db_instance_username}:@${module.cognitive_db.db_instance_endpoint}/${module.cognitive_db.db_instance_name}"
  sensitive   = true
}

output "vault_mount_path" {
  description = "Vault secrets engine path"
  value       = vault_mount.agent_secrets.path
}
