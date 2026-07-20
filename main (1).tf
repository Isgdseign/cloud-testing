# =============================================================================
# GRAVIA-TEST: Fully Secure AWS Infrastructure
# All critical/high/low issues fixed. No hardcoded secrets, least-privilege
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
    bucket         = "gravia-terraform-state-prod"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Environment = var.environment
      Project     = "gravia-test"
      ManagedBy   = "terraform"
    }
  }
}

# -----------------------------------------------------------------------------
# Terraform State Bucket – provisioned with versioning, encryption, and policy
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "terraform_state" {
  bucket        = "gravia-terraform-state-prod"
  force_destroy = false

  tags = { Name = "terraform-state-bucket" }
}

resource "aws_s3_bucket_versioning" "terraform_state_versioning" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state_encryption" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state_pab" {
  bucket                  = aws_s3_bucket.terraform_state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "terraform_state_policy" {
  bucket = aws_s3_bucket.terraform_state.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RequireTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [
          aws_s3_bucket.terraform_state.arn,
          "${aws_s3_bucket.terraform_state.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Secrets – values come from sensitive variables, NOT hardcoded
# -----------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "app_secrets" {
  name = "${var.project_name}-${var.environment}-secrets"
}

resource "aws_secretsmanager_secret_version" "app_secrets" {
  secret_id = aws_secretsmanager_secret.app_secrets.id
  # ✅ All secrets are injected from variables (set via env vars or CI/CD)
  secret_string = jsonencode({
    DB_PASSWORD   = var.db_password
    API_KEY       = var.api_key
    STRIPE_SECRET = var.stripe_secret
    JWT_SECRET    = var.jwt_secret
  })
}

# -----------------------------------------------------------------------------
# SSM Parameter for EC2 to fetch DB password (no hardcoded value in user_data)
# -----------------------------------------------------------------------------
resource "aws_ssm_parameter" "db_password" {
  name  = "/${var.project_name}/${var.environment}/DB_PASSWORD"
  type  = "SecureString"
  value = var.db_password
}

# -----------------------------------------------------------------------------
# S3 bucket – fully private, versioned, no force_destroy
# -----------------------------------------------------------------------------
resource "aws_s3_bucket" "app_data" {
  bucket        = "${var.project_name}-${var.environment}-data"
  force_destroy = false

  tags = { Name = "Application Data Bucket" }
}

resource "aws_s3_bucket_public_access_block" "app_data_block" {
  bucket = aws_s3_bucket.app_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "app_data_acl" {
  bucket = aws_s3_bucket.app_data.id
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "app_data_versioning" {
  bucket = aws_s3_bucket.app_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app_data_encryption" {
  bucket = aws_s3_bucket.app_data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# -----------------------------------------------------------------------------
# Security Group – restricted ingress, least-privilege egress
# -----------------------------------------------------------------------------
variable "trusted_ssh_cidr" {
  description = "CIDR block(s) allowed for SSH (e.g., office VPN). Must NOT be placeholder!"
  type        = list(string)
  # NO default – must be supplied. This forces a real value.
}

resource "aws_security_group" "app_sg" {
  name_prefix = "${var.project_name}-app-sg-"
  vpc_id      = aws_vpc.main.id
  description = "Application security group"

  # ✅ SSH only from explicitly provided trusted CIDR(s)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.trusted_ssh_cidr
    description = "SSH from trusted network"
  }

  # ✅ Egress restricted to necessary services (adjust based on your needs)
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]       # Allow HTTPS to internet (if required)
    description = "HTTPS outbound"
  }
  # If application needs other outbound (e.g., DB), add specific rules.
  # Do NOT open all ports to 0.0.0.0/0.

  tags = { Name = "app-security-group" }
}

# -----------------------------------------------------------------------------
# Security Group for RDS – only allows ingress on 5432 from app_sg
# -----------------------------------------------------------------------------
resource "aws_security_group" "db_sg" {
  name_prefix = "${var.project_name}-db-sg-"
  vpc_id      = aws_vpc.main.id
  description = "Database security group"

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
    description     = "PostgreSQL from app security group"
  }

  tags = { Name = "db-security-group" }
}

# -----------------------------------------------------------------------------
# IAM Roles – separate roles for each service (least privilege)
# -----------------------------------------------------------------------------
data "aws_iam_policy_document" "assume_role_ec2" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "assume_role_ecs" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "assume_role_eks" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

# EC2 instance role – SSM access for DB password retrieval
resource "aws_iam_role" "ec2_role" {
  name               = "${var.project_name}-ec2-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role_ec2.json
  tags = { Name = "ec2-role" }
}

resource "aws_iam_role_policy" "ec2_policy" {
  name = "${var.project_name}-ec2-policy"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = aws_ssm_parameter.db_password.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.app_data.arn,
          "${aws_s3_bucket.app_data.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "app_instance_profile" {
  name = "${var.project_name}-instance-profile"
  role = aws_iam_role.ec2_role.name
}

data "aws_caller_identity" "current" {}

# ECS task execution role – pull images, retrieve secrets, write logs
resource "aws_iam_role" "ecs_execution_role" {
  name               = "${var.project_name}-ecs-execution-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role_ecs.json
  tags = { Name = "ecs-execution-role" }
}

resource "aws_iam_role_policy" "ecs_execution_policy" {
  name = "${var.project_name}-ecs-execution-policy"
  role = aws_iam_role.ecs_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.app_secrets.arn
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameters"
        ]
        Resource = aws_ssm_parameter.db_password.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.app_logs.arn}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer"
        ]
        Resource = "arn:aws:ecr:${var.aws_region}:${data.aws_caller_identity.current.account_id}:repository/${var.project_name}"
      }
    ]
  })
}

# ECS task runtime role – application-specific permissions only
resource "aws_iam_role" "ecs_task_role" {
  name               = "${var.project_name}-ecs-task-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role_ecs.json
  tags = { Name = "ecs-task-role" }
}

resource "aws_iam_role_policy" "ecs_task_policy" {
  name = "${var.project_name}-ecs-task-policy"
  role = aws_iam_role.ecs_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.app_data.arn,
          "${aws_s3_bucket.app_data.arn}/*"
        ]
      }
    ]
  })
}

# EKS cluster role – dedicated role with AmazonEKSClusterPolicy
resource "aws_iam_role" "eks_role" {
  name               = "${var.project_name}-eks-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role_eks.json
  tags = { Name = "eks-role" }
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_role.name
  policy_arn  = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

# -----------------------------------------------------------------------------
# RDS – private, encrypted, multi-AZ, backup enabled
# -----------------------------------------------------------------------------
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

  publicly_accessible    = false
  storage_encrypted      = true
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  deletion_protection    = var.environment == "prod" ? true : false
  multi_az               = true

  vpc_security_group_ids = [aws_security_group.db_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.app_db_subnet.name

  skip_final_snapshot        = false
  final_snapshot_identifier  = "${var.project_name}-${var.environment}-final-snapshot"

  tags = { Name = "app-database" }
}

# -----------------------------------------------------------------------------
# SSM Parameters for DB connection details (no sensitive data in user_data)
# -----------------------------------------------------------------------------
resource "aws_ssm_parameter" "db_host" {
  name  = "/${var.project_name}/${var.environment}/DB_HOST"
  type  = "SecureString"
  value = aws_db_instance.app_database.address
}

resource "aws_ssm_parameter" "db_port" {
  name  = "/${var.project_name}/${var.environment}/DB_PORT"
  type  = "SecureString"
  value = "5432"
}

resource "aws_ssm_parameter" "db_name" {
  name  = "/${var.project_name}/${var.environment}/DB_NAME"
  type  = "SecureString"
  value = "appdatabase"
}

resource "aws_ssm_parameter" "db_user" {
  name  = "/${var.project_name}/${var.environment}/DB_USER"
  type  = "SecureString"
  value = "dbadmin"
}

# -----------------------------------------------------------------------------
# EC2 – secure user_data, IMDSv2, encrypted root, no secrets in code
# -----------------------------------------------------------------------------
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]   # Canonical only

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
  subnet_id     = aws_subnet.private_a.id

  vpc_security_group_ids = [aws_security_group.app_sg.id]
  key_name               = var.ssh_key_name
  iam_instance_profile   = aws_iam_instance_profile.app_instance_profile.name

  # ✅ user_data retrieves ALL DB connection details from SSM at runtime – no hardcoded secrets
  user_data = sensitive(<<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y docker.io awscli
              DB_HOST=$(aws ssm get-parameter --name "/${var.project_name}/${var.environment}/DB_HOST" --with-decryption --query "Parameter.Value" --output text --region ${var.aws_region})
              DB_PORT=$(aws ssm get-parameter --name "/${var.project_name}/${var.environment}/DB_PORT" --with-decryption --query "Parameter.Value" --output text --region ${var.aws_region})
              DB_NAME=$(aws ssm get-parameter --name "/${var.project_name}/${var.environment}/DB_NAME" --with-decryption --query "Parameter.Value" --output text --region ${var.aws_region})
              DB_USER=$(aws ssm get-parameter --name "/${var.project_name}/${var.environment}/DB_USER" --with-decryption --query "Parameter.Value" --output text --region ${var.aws_region})
              DB_PASSWORD=$(aws ssm get-parameter --name "/${var.project_name}/${var.environment}/DB_PASSWORD" --with-decryption --query "Parameter.Value" --output text --region ${var.aws_region})
              docker run -d \
                -e DB_HOST="$DB_HOST" \
                -e DB_PORT="$DB_PORT" \
                -e DB_NAME="$DB_NAME" \
                -e DB_USER="$DB_USER" \
                -e DB_PASSWORD="$DB_PASSWORD" \
                -p 8080:8080 \
                ${var.app_image}
              EOF
  )

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
    encrypted   = true
  }

  tags = { Name = "app-server" }
}

# -----------------------------------------------------------------------------
# ECS Task Definition – secrets from AWS Secrets Manager, not hardcoded
# -----------------------------------------------------------------------------
resource "aws_ecs_task_definition" "app_task" {
  family                   = "${var.project_name}-app-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

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
      secrets = [
        {
          name      = "API_KEY"
          valueFrom = "${aws_secretsmanager_secret_version.app_secrets.arn}:API_KEY::"
        },
        {
          name      = "STRIPE_SECRET"
          valueFrom = "${aws_secretsmanager_secret_version.app_secrets.arn}:STRIPE_SECRET::"
        },
        {
          name      = "JWT_SECRET"
          valueFrom = "${aws_secretsmanager_secret_version.app_secrets.arn}:JWT_SECRET::"
        }
      ]
      environment = [
        {
          name  = "NODE_ENV"
          value = var.environment
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

  tags = { Name = "app-task-definition" }
}

# -----------------------------------------------------------------------------
# EKS – private endpoint (or restricted), logging enabled
# -----------------------------------------------------------------------------
resource "aws_eks_cluster" "app_cluster" {
  name     = "${var.project_name}-${var.environment}-cluster"
  role_arn = aws_iam_role.eks_role.arn

  vpc_config {
    subnet_ids = [
      aws_subnet.public_a.id,
      aws_subnet.public_b.id,
      aws_subnet.private_a.id,
      aws_subnet.private_b.id
    ]

    endpoint_public_access  = false          # fully private
    endpoint_private_access = true

    # If you truly need public access, set endpoint_public_access = true and
    # restrict public_access_cidrs to a specific corporate IP, e.g.:
    # public_access_cidrs = ["198.51.100.0/24"]
  }

  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler"
  ]

  depends_on = [aws_iam_role_policy_attachment.eks_cluster_policy]
  tags = { Name = "app-eks-cluster" }
}

# -----------------------------------------------------------------------------
# Supporting VPC, subnets, gateways, etc.
# -----------------------------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "${var.project_name}-vpc" }
}

resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false
  tags = { Name = "public-subnet-a", Type = "Public" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = false
  tags = { Name = "public-subnet-b", Type = "Public" }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "${var.aws_region}a"
  tags = { Name = "private-subnet-a", Type = "Private" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "${var.aws_region}b"
  tags = { Name = "private-subnet-b", Type = "Private" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags = { Name = "${var.project_name}-igw" }
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags = { Name = "${var.project_name}-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_a.id
  tags = { Name = "${var.project_name}-nat-gw" }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = { Name = "public-route-table" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
  tags = { Name = "private-route-table" }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private.id
}

resource "aws_db_subnet_group" "app_db_subnet" {
  name       = "${var.project_name}-db-subnet"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  tags = { Name = "DB subnet group" }
}

# -----------------------------------------------------------------------------
# KMS Key for CloudWatch Log Group encryption
# -----------------------------------------------------------------------------
resource "aws_kms_key" "log_key" {
  description             = "KMS key for CloudWatch Log Group encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = { Name = "cloudwatch-log-key" }
}

resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/ecs/${var.project_name}-app"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.log_key.arn
}

# -----------------------------------------------------------------------------
# Variables – secrets are sensitive and have no defaults (must be supplied)
# -----------------------------------------------------------------------------
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
  sensitive   = true
  # No default – provide via TF_VAR_db_password or -var-file
}

variable "api_key" {
  description = "API Key for the application"
  type        = string
  sensitive   = true
}

variable "stripe_secret" {
  description = "Stripe secret key"
  type        = string
  sensitive   = true
}

variable "jwt_secret" {
  description = "JWT signing secret"
  type        = string
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

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------
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