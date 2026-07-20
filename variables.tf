variable "environment" {
  type        = string
  default     = "dev"
  description = "the type of environment (dev,staging/prod)"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "region" {
  default = "us-east-1"
}

variable "db_username" {
  type        = string
  sensitive   = true
  description = "Database administrator username"
}

variable "db_password" {
  type      = string
  sensitive = true
  validation {
    condition     = length(var.db_password) >= 16
    error_message = "The db_password must be at least 16 characters."
  }
}

variable "default_tags" {
  default     = {}
  description = "default tags to resources"
}