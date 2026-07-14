# =============================================================================
# GRAVIA-TEST: Vulnerable AWS Infrastructure
# This file intentionally contains the TOP 10 vulnerabilities from owasp_context.json
# for security scanning and remediation testing purposes.
# =============================================================================

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket = "gravia-terraform-state-prod"
    key    = "infrastructure/terraform.tfstate"
    region = "us-east-1"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY V-01: HARDCODED AWS KEYS (CRITICAL)
# Base64-encoded fragments in provider block that auto-decode
# ═══════════════════════════════════════════════════════════════════════════════
provider "aws" {
  region = var.aws_region

  # ❌ CRITICAL: Hardcoded credentials (base64 encoded fragments)
  # These decode to actual AWS access keys at runtime
  access_key = base64decode("QUtJQVhYWFhYWFhYWFhYWFhYWFg=")  # AKIAXXXXXXXXXXXXXXXX
  secret_key = base64decode("eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA==")

  default_tags {
    tags = {
      Environment = var.environment
      Project     = "gravia-test"
      ManagedBy   = "terraform"
    }
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY V-02: S3 BUCKET PUBLIC READ ACL (CRITICAL)
# Conditional public-read when env != "prod"
# ═══════════════════════════════════════════════════════════════════════════════
resource "aws_s3_bucket" "app_data" {
  bucket = "${var.project_name}-${var.environment}-data"

  # ❌ CRITICAL: force_destroy enabled (V-03 - BONUS)
  force_destroy = true

  tags = {
    Name = "Application Data Bucket"
  }
}

resource "aws_s3_bucket_acl" "app_data_acl" {
  bucket = aws_s3_bucket.app_data.id

  # ❌ CRITICAL: Public read in non-prod environments
  acl = var.environment != "prod" ? "public-read" : "private"
}

resource "aws_s3_bucket_versioning" "app_data_versioning" {
  bucket = aws_s3_bucket.app_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY V-04 & V-05: SECURITY GROUP WIDE OPEN (CRITICAL)
# SSH from 0.0.0.0/0 + All ports (-1) from 0.0.0.0/0 via dynamic for_each
# ═══════════════════════════════════════════════════════════════════════════════
locals {
  ingress_rules = {
    ssh = {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "SSH access"
    }
    all_traffic = {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"  # All protocols
      cidr_blocks = ["0.0.0.0/0"]
      description = "Allow all traffic"
    }
  }
}

resource "aws_security_group" "app_sg" {
  name_prefix = "${var.project_name}-app-sg-"
  vpc_id      = aws_vpc.main.id
  description = "Application security group"

  # ❌ CRITICAL: Dynamic rules opening everything to the world
  dynamic "ingress" {
    for_each = local.ingress_rules
    content {
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
      description = ingress.value.description
    }
  }

  # ❌ HIGH: Outbound all traffic to 0.0.0.0/0 (V-06 - BONUS)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = {
    Name = "app-security-group"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY V-07: IAM ROLE TRUST POLICY - PRINCIPAL = "*" (CRITICAL)
# Any AWS account can assume this role
# ═══════════════════════════════════════════════════════════════════════════════
resource "aws_iam_role" "app_role" {
  name = "${var.project_name}-app-role"

  # ❌ CRITICAL: Wildcard principal - any AWS account can assume
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "*"
        }
      }
    ]
  })

  tags = {
    Name = "app-role"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY V-08: IAM INLINE POLICY - "*":"*" ADMIN ACCESS (CRITICAL)
# merge() function grants full admin in non-prod
# ═══════════════════════════════════════════════════════════════════════════════
locals {
  base_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = "*"
      }
    ]
  }

  # ❌ CRITICAL: Admin policy merged in for non-prod environments
  admin_policy = var.environment != "prod" ? {
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  } : {}
}

resource "aws_iam_role_policy" "app_policy" {
  name = "${var.project_name}-app-policy"
  role = aws_iam_role.app_role.id

  # ❌ CRITICAL: merge() injects "*":"*" admin access
  policy = jsonencode(merge(local.base_policy, local.admin_policy))
}

# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY V-10: RDS PUBLICLY ACCESSIBLE (CRITICAL)
# Database exposed to the internet
# ═══════════════════════════════════════════════════════════════════════════════
resource "aws_db_instance" "app_database" {
  identifier = "${var.project_name}-${var.environment}-db"

  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"

  allocated_storage     = 100
  max_allocated_storage = 200

  db_name  = "appdatabase"
  username = "dbadmin"
  password = var.db_password

  # ❌ CRITICAL: Publicly accessible database
  publicly_accessible = true

  # ❌ HIGH: No encryption (V-11 - BONUS)
  storage_encrypted = false

  # ❌ HIGH: No backups (V-12 - BONUS)
  backup_retention_period = 0

  # ❌ HIGH: No deletion protection (V-25 - BONUS)
  deletion_protection = false

  # ❌ HIGH: Single AZ only (V-26 - BONUS)
  multi_az = false

  vpc_security_group_ids = [aws_security_group.app_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.app_db_subnet.name

  skip_final_snapshot = true

  tags = {
    Name = "app-database"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY V-13: EC2 USER DATA - HARDCODED PLAINTEXT DB PASSWORD (CRITICAL)
# Password visible in instance metadata
# ═══════════════════════════════════════════════════════════════════════════════
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["self", "099720109477"]  # ❌ MEDIUM: "self" in owners (V-16 - BONUS)

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "app_server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.medium"
  subnet_id     = aws_subnet.public_a.id

  vpc_security_group_ids = [aws_security_group.app_sg.id]
  key_name               = var.ssh_key_name

  # ❌ CRITICAL: Hardcoded plaintext DB password in user_data
  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y docker.io

              # Database configuration
              export DB_HOST="${aws_db_instance.app_database.address}"
              export DB_PORT="5432"
              export DB_NAME="appdatabase"
              export DB_USER="dbadmin"
              export DB_PASSWORD="SuperSecretPassword123!"  # ❌ HARDCODED PASSWORD

              docker run -d \
                -e DB_HOST=$DB_HOST \
                -e DB_PORT=$DB_PORT \
                -e DB_NAME=$DB_NAME \
                -e DB_USER=$DB_USER \
                -e DB_PASSWORD=$DB_PASSWORD \
                -p 8080:8080 \
                ${var.app_image}
              EOF

  # ❌ MEDIUM: IMDSv1 allowed (V-14 - BONUS)
  # metadata_options block missing entirely

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
    # ❌ HIGH: Root volume unencrypted (V-15 - BONUS)
    encrypted = false
  }

  tags = {
    Name = "app-server"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY V-35: ECS TASK DEFINITION - HARDCODED SECRETS (CRITICAL)
# Plaintext secrets in environment variables
# ═══════════════════════════════════════════════════════════════════════════════
resource "aws_ecs_task_definition" "app_task" {
  family                   = "${var.project_name}-app-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.app_role.arn
  task_role_arn            = aws_iam_role.app_role.arn

  container_definitions = jsonencode([
    {
      name  = "app-container"
      image = var.app_image
      portMappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]
      environment = [
        {
          name  = "NODE_ENV"
          value = var.environment
        },
        {
          name  = "API_KEY"
          value = "sk-live-abc123def456ghi789"  # ❌ CRITICAL: Hardcoded API key
        },
        {
          name  = "STRIPE_SECRET"
          value = "sk_test_51HxYvKLmNO2SecretKeyHere"  # ❌ CRITICAL: Hardcoded Stripe secret
        },
        {
          name  = "JWT_SECRET"
          value = "my-super-secret-jwt-key-2024"  # ❌ CRITICAL: Hardcoded JWT secret
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.app_logs.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "app"
        }
      }
    }
  ])

  tags = {
    Name = "app-task-definition"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# VULNERABILITY V-36: EKS CLUSTER API ENDPOINT PUBLIC (CRITICAL)
# Kubernetes API accessible from 0.0.0.0/0
# ═══════════════════════════════════════════════════════════════════════════════
resource "aws_eks_cluster" "app_cluster" {
  name     = "${var.project_name}-${var.environment}-cluster"
  role_arn = aws_iam_role.app_role.arn

  vpc_config {
    subnet_ids = [
      aws_subnet.public_a.id,
      aws_subnet.public_b.id,
      aws_subnet.private_a.id,
      aws_subnet.private_b.id
    ]

    # ❌ CRITICAL: Public API endpoint enabled
    endpoint_public_access = true

    # ❌ CRITICAL: 0.0.0.0/0 allowed
    public_access_cidrs = ["0.0.0.0/0"]

    endpoint_private_access = false
  }

  # ❌ MEDIUM: Control plane logging disabled (V-37 - BONUS)
  enabled_cluster_log_types = []

  depends_on = [aws_iam_role_policy.app_policy]

  tags = {
    Name = "app-eks-cluster"
  }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SUPPORTING RESOURCES (VPC, Subnets, etc.)
# ═══════════════════════════════════════════════════════════════════════════════
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet-a"
    Type = "Public"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet-b"
    Type = "Public"
  }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "private-subnet-a"
    Type = "Private"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "${var.aws_region}b"

  tags = {
    Name = "private-subnet-b"
    Type = "Private"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "public-route-table"
  }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_db_subnet_group" "app_db_subnet" {
  name       = "${var.project_name}-db-subnet"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  tags = {
    Name = "DB subnet group"
  }
}

resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/ecs/${var.project_name}-app"
  retention_in_days = 7

  # ❌ LOW: Short retention, but at least it's set (V-27 partially addressed)
}

# ═══════════════════════════════════════════════════════════════════════════════
# VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "staging"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "gravia-test"
}

variable "db_password" {
  description = "Database password"
  type        = string
  default     = "ChangeMe123!"  # ❌ Default password in variables
  sensitive   = true
}

variable "ssh_key_name" {
  description = "SSH key pair name"
  type        = string
  default     = "gravia-deploy-key"
}

variable "app_image" {
  description = "Application Docker image"
  type        = string
  default     = "gravia/app:latest"
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUTS
# ═══════════════════════════════════════════════════════════════════════════════
output "database_endpoint" {
  description = "RDS database endpoint"
  value       = aws_db_instance.app_database.endpoint
}

output "app_server_ip" {
  description = "Application server public IP"
  value       = aws_instance.app_server.public_ip
}

output "eks_cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = aws_eks_cluster.app_cluster.endpoint
}
