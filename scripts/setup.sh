#!/bin/bash
#
# Container Security ML Pipeline - Setup Script
# Initializes the complete environment
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
echo "======================================================================"
echo "  Container Security ML Pipeline - Setup"
echo "======================================================================"
echo -e "${NC}"

# Check prerequisites
echo -e "${YELLOW}Checking prerequisites...${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker not found. Please install Docker first.${NC}"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Docker Compose not found. Please install Docker Compose first.${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker and Docker Compose found${NC}"

# Create directory structure
echo -e "${YELLOW}Creating directory structure...${NC}"

mkdir -p localstack scanner ml dashboard database/migrations scripts test_images
mkdir -p models/trained logs

echo -e "${GREEN}✓ Directories created${NC}"

# Create Dockerfiles
echo -e "${YELLOW}Creating Dockerfiles...${NC}"

# Scanner Dockerfile
cat > scanner/Dockerfile <<'EOF'
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    apt-transport-https \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - && \
    echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | tee -a /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y trivy && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["tail", "-f", "/dev/null"]
EOF

# ML Dockerfile
cat > ml/Dockerfile <<'EOF'
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["tail", "-f", "/dev/null"]
EOF

# Dashboard Dockerfile
cat > dashboard/Dockerfile <<'EOF'
FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.address", "0.0.0.0"]
EOF

echo -e "${GREEN}✓ Dockerfiles created${NC}"

# Create requirements files
echo -e "${YELLOW}Creating requirements files...${NC}"

cat > scanner/requirements.txt <<'EOF'
psycopg2-binary==2.9.9
boto3==1.28.0
requests==2.31.0
EOF

cat > ml/requirements.txt <<'EOF'
psycopg2-binary==2.9.9
pandas==2.0.3
numpy==1.24.3
scikit-learn==1.3.0
mlflow==2.7.1
matplotlib==3.7.2
seaborn==0.12.2
EOF

cat > dashboard/requirements.txt <<'EOF'
streamlit==1.28.0
psycopg2-binary==2.9.9
pandas==2.0.3
plotly==5.17.0
numpy==1.24.3
EOF

echo -e "${GREEN}✓ Requirements files created${NC}"

# Create LocalStack initialization script
echo -e "${YELLOW}Creating LocalStack initialization script...${NC}"

cat > localstack/init-aws.sh <<'EOF'
#!/bin/bash

echo "Initializing LocalStack resources..."

# Wait for LocalStack to be ready
sleep 5

# Create S3 bucket
awslocal s3 mb s3://security-artifacts

# Create ECR repository
awslocal ecr create-repository --repository-name security-scans

echo "LocalStack initialization complete!"
EOF

chmod +x localstack/init-aws.sh

echo -e "${GREEN}✓ LocalStack initialization script created${NC}"

# Create test Dockerfile
echo -e "${YELLOW}Creating test images...${NC}"

cat > test_images/Dockerfile.vulnerable <<'EOF'
FROM composer:1.7.2

# Install vulnerable packages
RUN git clone https://github.com/aquasecurity/trivy-ci-test.git && \
    cd trivy-ci-test && \
    rm -f Cargo.lock Pipfile.lock

CMD ["sh"]
EOF

cat > test_images/Dockerfile.secure <<'EOF'
FROM alpine:latest

RUN apk add --no-cache python3 py3-pip

WORKDIR /app

CMD ["sh"]
EOF

echo -e "${GREEN}✓ Test images created${NC}"

# Create pipeline script
echo -e "${YELLOW}Creating pipeline execution scripts...${NC}"

cat > scripts/run_pipeline.sh <<'EOF'
#!/bin/bash

set -e

echo "======================================================================"
echo "  Running Complete Security Pipeline"
echo "======================================================================"

# Build and scan test image
echo "Building test image..."
docker build -f test_images/Dockerfile.vulnerable -t test-app:vulnerable .

# Run scan
echo "Running Trivy scan..."
docker-compose exec -T scanner python trivy_scanner.py test-app vulnerable

# Extract features
echo "Extracting ML features..."
SCAN_ID=$(docker-compose exec -T postgres psql -U security_user -d security_db -t -c "SELECT scan_id FROM scan_results ORDER BY scan_timestamp DESC LIMIT 1" | tr -d ' ')

docker-compose exec -T ml_service python -c "
from feature_engineering import FeatureEngineer
import os

db_config = {
    'host': os.getenv('DB_HOST', 'postgres'),
    'port': os.getenv('DB_PORT', '5432'),
    'database': os.getenv('DB_NAME', 'security_db'),
    'user': os.getenv('DB_USER', 'security_user'),
    'password': os.getenv('DB_PASSWORD', 'security_pass')
}

engineer = FeatureEngineer(db_config)
engineer.connect_db()
features = engineer.extract_features_for_scan('$SCAN_ID')
print('Features extracted:', len(features))
engineer.close()
"

# Make predictions
echo "Running ML predictions..."
docker-compose exec -T ml_service python predict.py $SCAN_ID

echo "======================================================================"
echo "  Pipeline Complete!"
echo "  View results at: http://localhost:8501"
echo "  MLflow UI at: http://localhost:5000"
echo "======================================================================"
EOF

chmod +x scripts/run_pipeline.sh

cat > scripts/train_model.sh <<'EOF'
#!/bin/bash

set -e

echo "======================================================================"
echo "  Training ML Models"
echo "======================================================================"

docker-compose exec ml_service python train_model.py

echo "======================================================================"
echo "  Training Complete!"
echo "  View models at: http://localhost:5000"
echo "======================================================================"
EOF

chmod +x scripts/train_model.sh

cat > scripts/demo.sh <<'EOF'
#!/bin/bash

set -e

echo "======================================================================"
echo "  Container Security ML - Demo"
echo "======================================================================"

# Generate synthetic scan data
echo "Generating demo scan data..."
docker-compose exec -T ml_service python -c "
import psycopg2
import uuid
from datetime import datetime, timedelta
import random

db_config = {
    'host': 'postgres',
    'port': '5432',
    'database': 'security_db',
    'user': 'security_user',
    'password': 'security_pass'
}

conn = psycopg2.connect(**db_config)
cursor = conn.cursor()

images = ['app-frontend', 'app-backend', 'app-database', 'app-cache', 'app-worker']
tags = ['v1.0', 'v1.1', 'v1.2', 'latest']

for i in range(50):
    scan_id = str(uuid.uuid4())
    image = random.choice(images)
    tag = random.choice(tags)
    timestamp = datetime.now() - timedelta(days=random.randint(0, 30))
    
    critical = random.randint(0, 5)
    high = random.randint(2, 15)
    medium = random.randint(5, 25)
    low = random.randint(10, 40)
    total = critical + high + medium + low
    
    cursor.execute('''
        INSERT INTO scan_results (
            scan_id, image_name, image_tag, scan_timestamp,
            total_vulnerabilities, critical_count, high_count,
            medium_count, low_count, scan_duration_seconds
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ''', (scan_id, image, tag, timestamp, total, critical, high, medium, low, 
          random.uniform(10, 60)))

conn.commit()
cursor.close()
conn.close()
print('Generated 50 demo scans')
"

# Extract features for all scans
echo "Extracting features..."
docker-compose exec -T ml_service python -c "
from feature_engineering import FeatureEngineer
import psycopg2

db_config = {
    'host': 'postgres',
    'port': '5432',
    'database': 'security_db',
    'user': 'security_user',
    'password': 'security_pass'
}

conn = psycopg2.connect(**db_config)
cursor = conn.cursor()
cursor.execute('SELECT scan_id FROM scan_results ORDER BY scan_timestamp DESC LIMIT 50')
scan_ids = [row[0] for row in cursor.fetchall()]
cursor.close()
conn.close()

engineer = FeatureEngineer(db_config)
engineer.connect_db()

for scan_id in scan_ids:
    try:
        engineer.extract_features_for_scan(scan_id)
    except:
        pass

engineer.close()
print(f'Extracted features for {len(scan_ids)} scans')
"

# Train models
echo "Training ML models..."
./scripts/train_model.sh

# Generate predictions
echo "Generating predictions..."
docker-compose exec -T ml_service python -c "
from predict import SecurityPredictor
import psycopg2

db_config = {
    'host': 'postgres',
    'port': '5432',
    'database': 'security_db',
    'user': 'security_user',
    'password': 'security_pass'
}

predictor = SecurityPredictor(db_config)
predictor.connect_db()

conn = psycopg2.connect(**db_config)
cursor = conn.cursor()
cursor.execute('SELECT scan_id FROM ml_features ORDER BY feature_timestamp DESC LIMIT 30')
scan_ids = [row[0] for row in cursor.fetchall()]
cursor.close()
conn.close()

for scan_id in scan_ids:
    try:
        predictor.predict_for_scan(scan_id)
    except Exception as e:
        print(f'Prediction failed for {scan_id}: {e}')

predictor.close()
print(f'Generated predictions for {len(scan_ids)} scans')
"

echo "======================================================================"
echo "  Demo Complete!"
echo "  Dashboard: http://localhost:8501"
echo "  MLflow: http://localhost:5000"
echo "  PostgreSQL: localhost:5432"
echo "======================================================================"
EOF

chmod +x scripts/demo.sh

echo -e "${GREEN}✓ Pipeline scripts created${NC}"

# Create .env file
cat > .env <<'EOF'
# Database Configuration
DB_HOST=postgres
DB_PORT=5432
DB_NAME=security_db
DB_USER=security_user
DB_PASSWORD=security_pass

# LocalStack Configuration
AWS_ENDPOINT_URL=http://localstack:4566
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
AWS_DEFAULT_REGION=us-east-1

# MLflow Configuration
MLFLOW_TRACKING_URI=http://mlflow:5000
EOF

echo -e "${GREEN}✓ Environment file created${NC}"

# Start services
echo -e "${YELLOW}Starting services...${NC}"
docker-compose up -d

echo -e "${GREEN}✓ Services starting...${NC}"

# Wait for services
echo -e "${YELLOW}Waiting for services to be ready...${NC}"
sleep 15

# Check service health
echo -e "${YELLOW}Checking service health...${NC}"

if docker-compose ps | grep -q "Up"; then
    echo -e "${GREEN}✓ Services are running${NC}"
else
    echo -e "${RED}✗ Some services failed to start${NC}"
    docker-compose ps
    exit 1
fi

echo -e "${GREEN}"
echo "======================================================================"
echo "  Setup Complete!"
echo "======================================================================"
echo -e "${NC}"
echo ""
echo "Services running:"
echo "  - Dashboard:   http://localhost:8501"
echo "  - MLflow UI:   http://localhost:5000"
echo "  - PostgreSQL:  localhost:5432"
echo "  - LocalStack:  http://localhost:4566"
echo ""
echo "Next steps:"
echo "  1. Run demo: ./scripts/demo.sh"
echo "  2. View dashboard: open http://localhost:8501"
echo "  3. Run your own scan: ./scripts/run_pipeline.sh"
echo ""
echo "For help: cat README.md"
echo ""