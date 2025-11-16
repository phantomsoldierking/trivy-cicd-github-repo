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
