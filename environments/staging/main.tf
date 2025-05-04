# ENTERPRISE STAGING INFRASTRUCTURE (v4.2.0)
# Terraform 1.5+ | Multi-Cloud Ready | NIST SP 800-204

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.16.2"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "3.71.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.23.0"
    }
  }
}

# Hybrid Cloud Configuration
provider "aws" {
  region = var.aws_region
  assume_role {
    role_arn = "arn:aws:iam::${var.aws_account_id}:role/EnlivenAgentStaging"
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.azure_subscription_id
}

provider "kubernetes" {
  config_path = "~/.kube/staging-config"
}

# Core Networking
module "global_network" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.2"

  name = "enliven-staging-global"
  cidr = "10.128.0.0/16"

  azs             = ["${var.aws_region}a", "${var.aws_region}b"]
  private_subnets = ["10.128.1.0/24", "10.128.2.0/24"]
  public_subnets  = ["10.128.101.0/24", "10.128.102.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  tags = {
    Environment = "staging"
  }
}

# Multi-Cloud Kubernetes
module "staging_cluster" {
  source  = "terraform-aws-modules/eks/aws"
  version = "19.16.0"

  cluster_name    = "enliven-staging"
  cluster_version = "1.28"
  vpc_id          = module.global_network.vpc_id
  subnet_ids      = module.global_network.private_subnets

  node_groups = {
    core_nodes = {
      desired_capacity = 3
      max_capacity     = 10
      min_capacity     = 3
      instance_types   = ["m6i.large"]
    }
  }

  cluster_encryption_config = [{
    provider_key_arn = aws_kms_key.staging_encryption.arn
    resources        = ["secrets"]
  }]
}

# Azure Complementary Services
module "azure_services" {
  source  = "Azure/compute/azurerm"
  version = "5.0.0"

  resource_group_name = "enliven-staging-rg"
  location            = var.azure_region

  virtual_network_name = "staging-vnet"
  address_space       = ["10.129.0.0/16"]

  vm_instances = {
    cognitive_gpu = {
      vm_size              = "Standard_NC6"
      storage_account_type = "Premium_LRS"
      count                = 2
    }
  }
}

# Unified Monitoring
module "cross_cloud_monitoring" {
  source  = "terraform-aws-modules/cloudwatch/aws"
  version = "4.2.0"

  namespace = "EnlivenStaging"
  
  metrics = {
    cpu_utilization = {
      name       = "CPUUtilization"
      statistic = "Average"
      period    = 300
    }
    memory_usage = {
      name       = "MemoryUsage"
      statistic = "Maximum"
      period    = 300
    }
  }
  
  azure_monitor_integration = {
    enabled          = true
    workspace_id     = var.azure_log_analytics_id
    primary_shared_key = var.azure_log_analytics_key
  }
}

# Security Foundation
resource "aws_kms_key" "staging_encryption" {
  description             = "Enliven Staging Encryption Key"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.staging_kms_policy.json
}

resource "aws_secretsmanager_secret" "cross_cloud_creds" {
  name                    = "enliven-staging-secrets"
  description             = "Cross-cloud credentials storage"
  kms_key_id              = aws_kms_key.staging_encryption.arn
  recovery_window_in_days = 7
}

# CI/CD Pipeline
module "staging_pipeline" {
  source  = "terraform-aws-modules/codepipeline/aws"
  version = "5.0.0"

  name          = "enliven-staging-deployment"
  role_arn      = aws_iam_role.codepipeline_role.arn
  artifact_store = {
    location = aws_s3_bucket.pipeline_artifacts.bucket
    type     = "S3"
  }

  stage {
    name = "Source"
    action {
      name             = "GitHub"
      category         = "Source"
      owner            = "ThirdParty"
      provider         = "GitHub"
      version          = "1"
      output_artifacts = ["source_output"]
      configuration = {
        Owner      = var.github_org
        Repo       = var.github_repo
        Branch     = "staging"
        OAuthToken = var.github_token
      }
    }
  }

  stage {
    name = "Build"
    action {
      name             = "Build"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      input_artifacts  = ["source_output"]
      output_artifacts = ["build_output"]
      version          = "1"
      configuration = {
        ProjectName = aws_codebuild_project.staging_build.name
      }
    }
  }
}

# Output Configuration
output "cluster_endpoint" {
  description = "EKS Cluster API endpoint"
  value       = module.staging_cluster.cluster_endpoint
  sensitive   = true
}

output "azure_gpu_nodes" {
  description = "Azure GPU node connection details"
  value       = module.azure_services.vm_public_ips
}
