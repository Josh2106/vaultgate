terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }

  # Remote state with locking. Bucket/table are created out-of-band (bootstrap).
  backend "s3" {
    bucket         = "vaultgate-tfstate"
    key            = "prod/terraform.tfstate"
    region         = "ap-south-1"
    dynamodb_table = "vaultgate-tflock"
    encrypt        = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "vaultgate"
      ManagedBy = "terraform"
      Env       = var.environment
    }
  }
}
