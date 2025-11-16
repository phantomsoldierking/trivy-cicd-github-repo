# Complete Setup and Usage Guide

## Table of Contents
1. [Prerequisites Installation](#prerequisites-installation)
2. [Project Setup](#project-setup)
3. [File Structure Creation](#file-structure-creation)
4. [Running the Pipeline](#running-the-pipeline)
5. [Understanding the Results](#understanding-the-results)
6. [Advanced Usage](#advanced-usage)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites Installation

### On Ubuntu/Debian
```bash
# Update system
sudo apt-get update

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Log out and back in for group changes to take effect
```

### On macOS
```bash
# Install Docker Desktop from https://www.docker.com/products/docker-desktop
# Docker Compose is included with Docker Desktop
```

### On Windows
1. Install Docker Desktop from https://www.docker.com/products/docker-desktop
2. Enable WSL 2 backend
3. Docker Compose is included

### Verify Installation
```bash
docker --version          # Should show Docker version
docker-compose --version  # Should show Docker Compose version
docker ps                 # Should list running containers (none initially)
```

---

## Project Setup

### Step 1: Create Project Directory
```bash
# Create main project directory
mkdir -p ~/container-security-ml
cd ~/container-security-ml
```

### Step 2: Create All Subdirectories
```bash
# Create directory structure
mkdir -p localstack scanner ml dashboard database/migrations scripts test_images models/trained logs

# Verify structure
tree -L 1  # or ls -R
```

### Step 3: Create Core Files

#### 3.1 Docker Compose (docker-compose.yml)
Copy the complete docker-compose.yml content provided in the artifacts.

#### 3.2 Database Schema (database/init.sql)
Copy the complete init.sql content provided in the artifacts.

#### 3.3 Scanner Code (scanner/trivy_scanner.py)
Copy the complete trivy_scanner.py content provided in the artifacts.

#### 3.4 Feature Engineering (ml/feature_engineering.py)
Copy the complete feature_engineering.py content provided in the artifacts.

#### 3.5 Model Training (ml/train_model.py)
Copy the complete train_model.py content provided in the artifacts.

#### 3.6 Prediction Module (ml/predict.py)
Copy the complete predict.py content provided in the artifacts.

#### 3.7 Dashboard (dashboard/app.py)
Copy the complete app.py content provided in the artifacts.

#### 3.8 Setup Script (scripts/setup.sh)
Copy the complete setup.sh content provided in the artifacts.

```bash
# Make scripts executable
chmod +x scripts/*.sh
chmod +x localstack/init-aws.sh
```

---

## Running the Pipeline

### Method 1: Automated Setup (Recommended)

```bash
# Run the setup script
./scripts/setup.sh

# Wait for all services to start (about 30 seconds)

# Run the demo to generate sample data
./scripts/demo.sh

# Access the dashboard
open http://localhost:8501  # macOS
xdg-open http://localhost:8501  # Linux
start http://localhost:8501  # Windows
```

### Method 2: Manual Step-by-Step

#### Step 1: Start Services
```bash
docker-compose up -d
```

Wait 30 seconds for all services to initialize.

#### Step 2: Verify Services
```bash
docker-compose ps

# Should show all services as "Up":
# - localstack
# - postgres
# - mlflow
# - scanner
# - ml_service
# - dashboard
```

#### Step 3: Check Service Health
```bash
# Test PostgreSQL
docker-compose exec postgres psql -U security_user -d security_db -c "SELECT 1;"

# Test MLflow
curl http://localhost:5000/health

# Test Dashboard
curl http://localhost:8501
```

#### Step 4: Build Test Image
```bash
# Build vulnerable test image
docker build -f test_images/Dockerfile.vulnerable -t test-app:vulnerable .

# Or build secure test image
docker build -f test_images/Dockerfile.secure -t test-app:secure .
```

#### Step 5: Run Initial Scan
```bash
# Scan the test image
docker-compose exec scanner python trivy_scanner.py test-app vulnerable

# Check scan results
docker-compose exec postgres psql -U security_user -d security_db -c \
  "SELECT scan_id, image_name, total_vulnerabilities FROM scan_results;"
```

#### Step 6: Extract Features
```bash
# Get the latest scan_id
SCAN_ID=$(docker-compose exec postgres psql -U security_user -d security_db -t -c \
  "SELECT scan_id FROM scan_results ORDER BY scan_timestamp DESC LIMIT 1" | tr -d ' \n')

echo "Processing scan: $SCAN_ID"

# Extract features
docker-compose exec ml_service python -c "
from feature_engineering import FeatureEngineer
import os

db_config = {
    'host': 'postgres',
    'port': '5432',
    'database': 'security_db',
    'user': 'security_user',
    'password': 'security_pass'
}

engineer = FeatureEngineer(db_config)
engineer.connect_db()
features = engineer.extract_features_for_scan('$SCAN_ID')
print(f'Extracted {len(features)} features')
engineer.close()
"
```

#### Step 7: Train Models (First Time)
```bash
# Generate synthetic training data and train models
./scripts/demo.sh

# Or train manually after collecting real scans
./scripts/train_model.sh
```

#### Step 8: Make Predictions
```bash
# Make prediction on the scan
docker-compose exec ml_service python predict.py $SCAN_ID

# Or run predictions on all recent scans
docker-compose exec ml_service python -c "
from predict import SecurityPredictor
import psycopg2

db_config = {
    'host': 'postgres',
    'port': '5432',
    'database': 'security_db',
    'user': 'security_user',
    'password': 'security_pass'
}

conn = psycopg2.connect(**db_config)
cur = conn.cursor()
cur.execute('SELECT scan_id FROM ml_features ORDER BY feature_timestamp DESC LIMIT 10')
scan_ids = [row[0] for row in cur.fetchall()]
cur.close()
conn.close()

predictor = SecurityPredictor(db_config)
predictor.connect_db()

for sid in scan_ids:
    try:
        pred = predictor.predict_for_scan(sid)
        print(f'{sid}: Risk={pred[\"risk_score\"]:.0f}, Anomaly={pred[\"is_anomaly\"]}')
    except Exception as e:
        print(f'{sid}: Error - {e}')

predictor.close()
"
```

#### Step 9: View Results
```bash
# Open dashboard
open http://localhost:8501

# Open MLflow
open http://localhost:5000
```

---

## Understanding the Results

### Dashboard Sections

#### 1. Overview Page
- **Total Vulnerabilities**: Sum across all recent scans
- **Critical Count**: High-priority vulnerabilities requiring immediate attention
- **Anomalies Detected**: Scans flagged by ML as unusual
- **Avg Risk Score**: 0-100 scale, where >80 is critical

**Charts:**
- Risk Scores by Image: Bar chart showing risk levels
- Vulnerability Trends: 30-day historical trend

#### 2. Scan Details Page
Select a specific scan to see:
- Complete vulnerability list
- ML analysis with anomaly detection
- Risk gauge (0-100)
- Top contributing features
- Actionable recommendations

#### 3. Alerts Page
Active security alerts including:
- Anomaly alerts (unusual patterns)
- High-risk alerts (score ≥80)
- Exploit availability alerts

#### 4. Analytics Page
- Severity distribution (pie chart)
- Risk category breakdown
- Historical timeline
- Customizable time ranges

### MLflow UI

Navigate to http://localhost:5000

**Key Sections:**
1. **Experiments**: View all model training runs
2. **Models**: Registered model versions
3. **Metrics**: Training accuracy, F1 score, etc.
4. **Parameters**: Model hyperparameters
5. **Artifacts**: Saved model files

### Database Queries

```bash
# Connect to database
docker-compose exec postgres psql -U security_user -d security_db

# View recent scans
SELECT 
    scan_timestamp,
    image_name,
    image_tag,
    total_vulnerabilities,
    critical_count,
    high_count
FROM scan_results
ORDER BY scan_timestamp DESC
LIMIT 10;

# View predictions with details
SELECT 
    sr.image_name,
    sr.total_vulnerabilities,
    mp.risk_score,
    mp.risk_category,
    mp.is_anomaly,
    mp.confidence_score
FROM ml_predictions mp
JOIN scan_results sr ON mp.scan_id = sr.scan_id
ORDER BY mp.prediction_timestamp DESC
LIMIT 10;

# View active alerts
SELECT 
    alert_timestamp,
    alert_type,
    severity,
    title,
    status
FROM security_alerts
WHERE status IN ('open', 'acknowledged')
ORDER BY alert_timestamp DESC;

# View vulnerability details for a scan
SELECT 
    cve_id,
    package_name,
    severity,
    cvss_score,
    exploit_available
FROM vulnerabilities
WHERE scan_id = 'YOUR_SCAN_ID'
ORDER BY cvss_score DESC;
```

---

## Advanced Usage

### Scanning Your Own Images

```bash
# Pull your image
docker pull myregistry/myapp:latest

# Scan it
docker-compose exec scanner python trivy_scanner.py myregistry/myapp latest

# Process through pipeline
SCAN_ID=$(docker-compose exec postgres psql -U security_user -d security_db -t -c \
  "SELECT scan_id FROM scan_results ORDER BY scan_timestamp DESC LIMIT 1" | tr -d ' \n')

# Extract features and predict
docker-compose exec ml_service python -c "
from feature_engineering import FeatureEngineer
from predict import SecurityPredictor
import os

db_config = {
    'host': 'postgres',
    'port': '5432',
    'database': 'security_db',
    'user': 'security_user',
    'password': 'security_pass'
}

# Extract features
engineer = FeatureEngineer(db_config)
engineer.connect_db()
features = engineer.extract_features_for_scan('$SCAN_ID')
engineer.close()

# Make prediction
predictor = SecurityPredictor(db_config)
predictor.connect_db()
prediction = predictor.predict_for_scan('$SCAN_ID')
predictor.close()

print(f'Risk Score: {prediction[\"risk_score\"]:.0f}/100')
print(f'Risk Category: {prediction[\"risk_category\"]}')
print(f'Is Anomaly: {prediction[\"is_anomaly\"]}')
print(f'Recommendations:')
for rec in prediction['recommendations']:
    print(f'  - {rec}')
"
```

### Batch Scanning Multiple Images

```bash
# Create a list of images
cat > images.txt <<EOF
nginx:latest
redis:alpine
postgres:13
python:3.9-slim
node:16-alpine
EOF

# Scan all images
while IFS= read -r image; do
    echo "Scanning $image..."
    docker pull $image
    IFS=':' read -r name tag <<< "$image"
    docker-compose exec -T scanner python trivy_scanner.py "$name" "$tag"
done < images.txt

# Process all scans
docker-compose exec ml_service python -c "
from feature_engineering import FeatureEngineer
from predict import SecurityPredictor
import psycopg2

db_config = {
    'host': 'postgres',
    'port': '5432',
    'database': 'security_db',
    'user': 'security_user',
    'password': 'security_pass'
}

# Get unprocessed scans
conn = psycopg2.connect(**db_config)
cur = conn.cursor()
cur.execute('''
    SELECT sr.scan_id 
    FROM scan_results sr
    LEFT JOIN ml_features mf ON sr.scan_id = mf.scan_id
    WHERE mf.scan_id IS NULL
''')
scan_ids = [row[0] for row in cur.fetchall()]
cur.close()
conn.close()

print(f'Processing {len(scan_ids)} scans...')

# Extract features
engineer = FeatureEngineer(db_config)
engineer.connect_db()
for sid in scan_ids:
    engineer.extract_features_for_scan(sid)
engineer.close()

# Make predictions
predictor = SecurityPredictor(db_config)
predictor.connect_db()
for sid in scan_ids:
    predictor.predict_for_scan(sid)
predictor.close()

print('Batch processing complete!')
"
```

### Scheduling Automatic Scans

```bash
# Create cron job for daily scans
crontab -e

# Add this line (runs at 2 AM daily):
0 2 * * * cd ~/container-security-ml && ./scripts/run_pipeline.sh >> logs/cron.log 2>&1
```

### Exporting Results

```bash
# Export scan results to CSV
docker-compose exec postgres psql -U security_user -d security_db -c \
  "COPY (SELECT * FROM scan_results) TO STDOUT WITH CSV HEADER" > scan_results.csv

# Export predictions to JSON
docker-compose exec postgres psql -U security_user -d security_db -t -A -c \
  "SELECT json_agg(row_to_json(t)) FROM (SELECT * FROM ml_predictions) t" > predictions.json

# Export alerts
docker-compose exec postgres psql -U security_user -d security_db -c \
  "COPY (SELECT * FROM security_alerts) TO STDOUT WITH CSV HEADER" > alerts.csv
```

### Customizing ML Models

Edit `ml/train_model.py` to tune hyperparameters:

```python
# Anomaly Detection - Adjust sensitivity
self.anomaly_model = IsolationForest(
    n_estimators=200,        # More trees = better accuracy
    contamination=0.05,      # Lower = fewer anomalies detected
    max_samples='auto',
    random_state=42
)

# Risk Scoring - Adjust complexity
self.risk_model = RandomForestClassifier(
    n_estimators=300,        # More trees = better accuracy
    max_depth=15,            # Deeper = more complex patterns
    min_samples_split=10,    # Higher = more conservative
    class_weight='balanced'
)
```

Then retrain:
```bash
./scripts/train_model.sh
```

---

## Troubleshooting

### Issue: Services Won't Start

```bash
# Check Docker daemon
sudo systemctl status docker
sudo systemctl start docker

# Check Docker Compose
docker-compose --version

# View logs
docker-compose logs

# Restart everything
docker-compose down -v
docker-compose up -d
```

### Issue: Database Connection Errors

```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Check logs
docker-compose logs postgres

# Test connection
docker-compose exec postgres pg_isready -U security_user

# Recreate database
docker-compose down -v
docker-compose up -d postgres
sleep 10
# Database will auto-initialize from init.sql
```

### Issue: Trivy Scan Fails

```bash
# Update Trivy database
docker-compose exec scanner trivy image --download-db-only

# Check Trivy version
docker-compose exec scanner trivy --version

# Test with simple image
docker pull alpine:latest
docker-compose exec scanner trivy image alpine:latest
```

### Issue: ML Models Not Loading

```bash
# Check if models exist
docker-compose exec ml_service ls -la /models/

# Retrain models
./scripts/train_model.sh

# Check MLflow
curl http://localhost:5000/health

# View MLflow logs
docker-compose logs mlflow
```

### Issue: Dashboard Shows No Data

```bash
# Check if scans exist
docker-compose exec postgres psql -U security_user -d security_db -c \
  "SELECT COUNT(*) FROM scan_results;"

# Run demo to generate data
./scripts/demo.sh

# Restart dashboard
docker-compose restart dashboard

# Check dashboard logs
docker-compose logs dashboard
```

### Issue: Out of Disk Space

```bash
# Clean Docker
docker system prune -a --volumes

# Clean specific components
docker-compose down -v
docker volume rm $(docker volume ls -q | grep container-security)

# Restart
./scripts/setup.sh
```

### Issue: Port Already in Use

```bash
# Find process using port
sudo lsof -i :8501  # For dashboard
sudo lsof -i :5000  # For MLflow
sudo lsof -i :5432  # For PostgreSQL

# Kill process or change port in docker-compose.yml
# Example: Change dashboard port from 8501 to 8502
ports:
  - "8502:8501"
```

---

## Next Steps

1. **Production Deployment**
   - Replace LocalStack with real AWS/Azure/GCP
   - Add authentication to dashboard and MLflow
   - Set up HTTPS
   - Implement backup strategy

2. **Integration**
   - Add CI/CD pipeline integration
   - Set up Slack/email notifications
   - Create API endpoints for programmatic access

3. **Enhancement**
   - Add more ML models (LSTM for time-series)
   - Implement drift detection
   - Add A/B testing for model improvements
   - Create custom feature extractors

4. **Scaling**
   - Use Kubernetes for orchestration
   - Add caching layer (Redis)
   - Implement job queue (Celery)
   - Horizontal scaling of services

---

##  Resources

- **Documentation**: README.md in project root
- **ML Models**: Check MLflow UI at http://localhost:5000
- **Database Schema**: database/init.sql
- **Logs**: `docker-compose logs <service>`
- **Trivy Docs**: https://aquasecurity.github.io/trivy/
- **MLflow Docs**: https://mlflow.org/docs/latest/index.html

---