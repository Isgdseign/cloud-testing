variable "environment" {
  default = "dev"
  description = "the type of environment (dev,staging/prod)"
}

variable "region" {
  default = "us-east-1"
}

variable "db_username" {
}

variable "db_password" {
  sensitive = true
}

variable "default_tags" {
  default     = {}
  description = "default tags to resources"
}