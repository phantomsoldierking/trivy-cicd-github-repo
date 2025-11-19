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
