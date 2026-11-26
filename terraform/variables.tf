variable "region" {
  description = "AWS region."
  type        = string
  default     = "ap-south-1"
}

variable "environment" {
  description = "Deployment environment name."
  type        = string
  default     = "prod"
}

variable "vpc_id" {
  description = "Existing VPC to deploy into (networking is managed elsewhere)."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets for Fargate tasks."
  type        = list(string)
}

variable "alb_security_group_id" {
  description = "Security group of the (externally managed) ALB allowed to reach the tasks."
  type        = string
}

variable "image_tag" {
  description = "Image tag (prefer an immutable digest) to deploy."
  type        = string
  default     = "0.1.0"
}

variable "desired_count" {
  description = "Number of API tasks."
  type        = number
  default     = 2
}

variable "secrets_arns" {
  description = "Secrets Manager ARNs injected into the task (database-url, redis-url, ...)."
  type        = map(string)
}
