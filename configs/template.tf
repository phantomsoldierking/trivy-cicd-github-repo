# need to test and validate the code for tall the usecases

# variables.tf
variable "trivy_container_name" {
  description = "Container name to be populated by CodeBuild"
  type        = string
  default     = "trivy-test"
}

variable "github_repo_owner" {
  description = "GitHub repository owner"
  type        = string
}

variable "github_repo_name" {
  description = "GitHub repository name"
  type        = string
}

variable "github_oauth_token" {
  description = "GitHub personal access token"
  type        = string
  sensitive   = true
}

# main.tf
provider "aws" {
  region = "us-east-1"  # Update this to your preferred region
}

resource "aws_ecr_repository" "trivy_ecr" {}

resource "aws_iam_role" "codebuild_service_role" {
  name = "codebuild_service_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = { Service = "codebuild.amazonaws.com" },
        Action    = "sts:AssumeRole"
      }
    ]
  })

  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser"]

  inline_policy {
    name   = "CodeBuildServiceRolePolicy"
    policy = jsonencode({
      Version = "2012-10-17",
      Statement = [
        { Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource = "*" },
        { Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:GetBucketAcl", "s3:GetBucketLocation"], Resource = "*" },
        { Effect = "Allow", Action = ["securityhub:BatchImportFindings"], Resource = "*" },
        { Effect = "Allow", Action = [
          "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage", "ecr:BatchCheckLayerAvailability", "ecr:PutImage",
          "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload"
        ], Resource = aws_ecr_repository.trivy_ecr.arn }
      ]
    })
  }
}

resource "aws_iam_role" "codepipeline_service_role" {
  name = "codepipeline_service_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = { Service = "codepipeline.amazonaws.com" },
        Action    = "sts:AssumeRole"
      }
    ]
  })

  inline_policy {
    name   = "CodePipelineServiceRolePolicy"
    policy = jsonencode({
      Version = "2012-10-17",
      Statement = [
        { Effect = "Allow", Action = ["cloudwatch:*", "s3:*"], Resource = "*" },
        { Effect = "Allow", Action = ["codebuild:BatchGetBuilds", "codebuild:StartBuild"], Resource = aws_codebuild_project.trivy_codebuild.arn }
      ]
    })
  }
}

resource "aws_s3_bucket" "trivy_codepipeline_artifact_bucket" {
  bucket = "trivy-codepipeline-artifacts-${data.aws_caller_identity.current.account_id}"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  public_access_block_configuration {
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

resource "aws_codebuild_project" "trivy_codebuild" {
  name          = "trivy-cicd-build-project-${data.aws_caller_identity.current.account_id}"
  description   = "For Security Hub Trivy Vuln Scanning Blog"
  service_role  = aws_iam_role.codebuild_service_role.arn

  artifacts {
    type = "CODEPIPELINE"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_LARGE"
    image                       = "aws/codebuild/standard:3.0"
    type                        = "LINUX_CONTAINER"
    privileged_mode             = true
    environment_variable {
      name  = "docker_img_name"
      value = var.trivy_container_name
    }
    environment_variable {
      name  = "docker_tag"
      value = "latest"
    }
    environment_variable {
      name  = "ecr_repo"
      value = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${data.aws_region.current.name}.amazonaws.com/${aws_ecr_repository.trivy_ecr.name}"
    }
  }

  logs_config {
    cloudwatch_logs {
      status = "ENABLED"
    }
  }

  source {
    type = "CODEPIPELINE"
  }
}

resource "aws_codepipeline" "trivy_codepipeline" {
  name     = "trivy-scan-cicd-pipeline-${data.aws_caller_identity.current.account_id}"
  role_arn = aws_iam_role.codepipeline_service_role.arn

  artifact_store {
    location = aws_s3_bucket.trivy_codepipeline_artifact_bucket.bucket
    type     = "S3"
  }

  stage {
    name = "Source"

    action {
      name             = "SourceAction"
      category         = "Source"
      owner            = "ThirdParty"
      provider         = "GitHub"
      version          = "1"
      output_artifacts = ["SourceOutput"]

      configuration = {
        Owner      = var.github_repo_owner
        Repo       = var.github_repo_name
        Branch     = "master"
        OAuthToken = var.github_oauth_token
      }
    }
  }

  stage {
    name = "Build"

    action {
      name             = "BuildAction"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["SourceOutput"]
      configuration    = { ProjectName = aws_codebuild_project.trivy_codebuild.name }
    }
  }
}
