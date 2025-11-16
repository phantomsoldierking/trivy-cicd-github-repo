#!/bin/bash

echo "Initializing LocalStack resources..."

# Wait for LocalStack to be ready
sleep 5

# Create S3 bucket
awslocal s3 mb s3://security-artifacts

# Create ECR repository
awslocal ecr create-repository --repository-name security-scans

echo "LocalStack initialization complete!"
