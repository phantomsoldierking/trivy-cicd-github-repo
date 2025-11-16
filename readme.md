# Container Security ML Pipeline 

An advanced, end-to-end container vulnerability scanning and anomaly detection system powered by machine learning. Runs entirely on LocalStack for cost-free development and testing.

##  Features

### Core Capabilities
- **Automated Vulnerability Scanning**: Uses Trivy to scan container images for CVEs
- **ML-Powered Anomaly Detection**: Identifies unusual vulnerability patterns using Isolation Forest
- **Risk Scoring**: Predicts exploitation probability with Random Forest classifier
- **Real-time Dashboard**: Interactive Streamlit dashboard for visualization and monitoring
- **Historical Analysis**: Tracks vulnerability trends over time
- **Intelligent Alerting**: Context-aware alerts with reduced false positives
- **Complete LocalStack Integration**: No cloud costs, runs entirely local

### Machine Learning Models
1. **Anomaly Detector** (Isolation Forest)
   - Detects unusual vulnerability patterns
   - Identifies potential supply chain attacks
   - Spots configuration anomalies
   - 15+ engineered features

2. **Risk Scorer** (Random Forest)
   - Predicts exploitation likelihood
   - Risk score 0-100
   - Confidence intervals
   - Feature importance analysis

### Technology Stack
- **Scanning**: Trivy (vulnerability scanner)
- **Storage**: PostgreSQL (scan results, features, predictions)
- **ML**: Scikit-learn (models), MLflow (tracking)
- **Orchestration**: Docker Compose
- **Cloud Simulation**: LocalStack
- **Visualization**: Streamlit, Plotly
- **Languages**: Python 3.9+

##  Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum
- 10GB disk space

##  Quick Start

### 1. Clone and Setup

```bash
# Clone the repository
git clone <your-repo-url>
cd container-security-ml

# Make setup script executable and run
chmod +x scripts/setup.sh
./scripts/setup.sh
```

The setup script will:
- Create all necessary directories
- Generate Dockerfiles and requirements
- Start all services (PostgreSQL, LocalStack, MLflow, Scanner, ML Service, Dashboard)
- Initialize the database schema

### 2. Run Demo

```bash
# Generate sample data and train models
./scripts/demo.sh
```

This will:
- Generate 50 synthetic scan records
- Extract ML features
- Train anomaly detection and risk scoring models
- Generate predictions and alerts

### 3. Access Services

- **Dashboard**: http://localhost:8501
- **MLflow UI**: http://localhost:5000
- **PostgreSQL**: localhost:5432 (user: security_user, password: security_pass)
- **LocalStack**: http://localhost:4566

## 📖 Usage Guide

### Scanning a Container Image

#### Method 1: Using the Pipeline Script

```bash
# Scan a public image
docker pull nginx:latest
./scripts/run_pipeline.sh
```

#### Method 2: Manual Scan

```bash
# Pull an image to scan
docker pull alpine:3.14

# Run scan
docker-compose exec scanner python trivy_scanner.py alpine 3.14

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
# Get latest scan_id from database first
import psycopg2
conn = psycopg2.connect(**db_config)
cur = conn.cursor()
cur.execute('SELECT scan_id FROM scan_results ORDER BY scan_timestamp DESC LIMIT 1')
scan_id = cur.fetchone()[0]
features = engineer.extract_features_for_scan(scan_id)
engineer.close()
print('Features extracted')
"

# Make prediction
docker-compose exec ml_service python -c "
from predict import SecurityPredictor
import os, psycopg2
db_config = {
    'host': 'postgres',
    'port': '5432',
    'database': 'security_db',
    'user': 'security_user',
    'password': 'security_pass'
}
conn = psycopg2.connect(**db_config)
cur = conn.cursor()
cur.execute('SELECT scan_id FROM scan_results ORDER BY scan_timestamp DESC LIMIT 1')
scan_id = cur.fetchone()[0]
predictor = SecurityPredictor(db_config)
predictor.connect_db()
prediction = predictor.predict_for_scan(scan_id)
predictor.close()
print(f'Risk Score: {prediction[\"risk_score\"]:.0f}/100')
print(f'Anomaly: {prediction[\"is_anomaly\"]}')
"
```

### Training Models

```bash
# Train/retrain ML models
./scripts/train_model.sh
```

This will:
- Load all available feature data
- Train Isolation Forest for anomaly detection
- Train Random Forest for risk scoring
- Log models and metrics to MLflow
- Save models to `/models` directory

### Viewing Results

1. **Dashboard** (Recommended)
   - Navigate to http://localhost:8501
   - View overview, scan details, alerts, and analytics
   - Interactive charts and filters

2. **MLflow UI**
   - Navigate to http://localhost:5000
   - View model metrics, parameters, and artifacts
   - Compare model runs

3. **Database**
   ```bash
   # Connect to PostgreSQL
   docker-compose exec postgres psql -U security_user -d security_db
   
   # Query scans
   SELECT image_name, image_tag, total_vulnerabilities, critical_count 
   FROM scan_results 
   ORDER BY scan_timestamp DESC 
   LIMIT 10;
   
   # Query predictions
   SELECT sr.image_name, mp.risk_score, mp.risk_category, mp.is_anomaly
   FROM ml_predictions mp
   JOIN scan_results sr ON mp.scan_id = sr.scan_id
   ORDER BY mp.prediction_timestamp DESC
   LIMIT 10;
   
   # Query active alerts
   SELECT * FROM security_alerts WHERE status = 'open';
   ```

##  Project Structure

```
container-security-ml/
├── docker-compose.yml              # Service orchestration
├── .env                            # Environment variables
├── README.md                       # This file
│
├── localstack/
│   └── init-aws.sh                # Initialize LocalStack resources
│
├── scanner/
│   ├── Dockerfile                 # Scanner service image
│   ├── requirements.txt           # Python dependencies
│   └── trivy_scanner.py           # Enhanced Trivy wrapper
│
├── ml/
│   ├── Dockerfile                 # ML service image
│   ├── requirements.txt           # Python dependencies
│   ├── feature_engineering.py     # Feature extraction
│   ├── train_model.py             # Model training
│   └── predict.py                 # Real-time predictions
│
├── dashboard/
│   ├── Dockerfile                 # Dashboard image
│   ├── requirements.txt           # Python dependencies
│   └── app.py                     # Streamlit dashboard
│
├── database/
│   ├── init.sql                   # Database schema
│   └── migrations/                # Future migrations
│
├── scripts/
│   ├── setup.sh                   # Initial setup
│   ├── run_pipeline.sh            # Full pipeline execution
│   ├── train_model.sh             # Model training
│   └── demo.sh                    # Demo with synthetic data
│
├── test_images/
│   ├── Dockerfile.vulnerable      # Test image with vulnerabilities
│   └── Dockerfile.secure          # Secure test image
│
└── models/
    └── trained/                   # Saved ML models
```

##  How It Works

### 1. Vulnerability Scanning
- Trivy scans container images for known CVEs
- Results stored in PostgreSQL with full details
- Tracks CVE ID, severity, CVSS score, package info

### 2. Feature Engineering
Extracts 17+ features from scan data:
- **Density Features**: Vulnerabilities per package, severity ratios
- **Trend Features**: Growth rate, new critical vulnerabilities
- **Risk Features**: CVSS scores, exploitability, EPSS scores
- **Historical Features**: Days since last scan, scan frequency
- **Distribution Features**: Severity entropy, package diversity

### 3. ML Models

#### Anomaly Detection
- Algorithm: Isolation Forest
- Purpose: Detect unusual patterns
- Features: 11 key indicators
- Output: Binary (anomaly/normal) + score

#### Risk Scoring
- Algorithm: Random Forest Classifier
- Purpose: Predict exploitation risk
- Features: 12 vulnerability characteristics
- Output: Risk score 0-100 + confidence

### 4. Predictions & Alerts
- Real-time predictions on new scans
- Automatic alert generation for:
  - Detected anomalies
  - High risk scores (≥80)
  - Known exploits present
- Actionable recommendations

##  Dashboard Features

### Overview Page
- Key metrics (total vulnerabilities, critical count, anomalies)
- Recent scans with risk scores
- 30-day vulnerability trends
- Active alerts summary

### Scan Details Page
- Detailed vulnerability list
- ML analysis results
- Risk gauge visualization
- Recommendations
- Filterable by severity

### Alerts Page
- All active security alerts
- Filter by type and severity
- Alert descriptions and recommendations

### Analytics Page
- Severity distribution pie chart
- Risk category distribution
- Historical timeline
- Customizable time ranges

##  Configuration

### Environment Variables (.env)
```bash
# Database
DB_HOST=postgres
DB_PORT=5432
DB_NAME=security_db
DB_USER=security_user
DB_PASSWORD=security_pass

# AWS (LocalStack)
AWS_ENDPOINT_URL=http://localstack:4566
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test
AWS_DEFAULT_REGION=us-east-1

# MLflow
MLFLOW_TRACKING_URI=http://mlflow:5000
```

### Model Parameters
Edit `ml/train_model.py`:
```python
# Anomaly Detector
IsolationForest(
    n_estimators=200,
    contamination=0.1,  # Expected anomaly rate
    random_state=42
)

# Risk Scorer
RandomForestClassifier(
    n_estimators=200,
    max_depth=10,
    min_samples_split=5
)
```

##  Troubleshooting

### Services won't start
```bash
# Check Docker resources
docker system df

# Check service logs
docker-compose logs <service_name>

# Restart all services
docker-compose down
docker-compose up -d
```

### Database connection errors
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Verify database
docker-compose exec postgres psql -U security_user -d security_db -c "\\dt"
```

### Model training fails
```bash
# Check if enough data
docker-compose exec postgres psql -U security_user -d security_db -c "SELECT COUNT(*) FROM ml_features;"

# Generate synthetic data
./scripts/demo.sh

# Check MLflow logs
docker-compose logs mlflow
```

### Trivy scan fails
```bash
# Update Trivy database
docker-compose exec scanner trivy image --download-db-only

# Check Docker socket
ls -la /var/run/docker.sock
```

##  Performance Tips

### For Large-Scale Scanning
1. Increase PostgreSQL resources in `docker-compose.yml`:
   ```yaml
   postgres:
     deploy:
       resources:
         limits:
           memory: 2G
   ```

2. Batch predictions:
   ```bash
   # Process multiple scans
   docker-compose exec ml_service python -c "
   from predict import SecurityPredictor
   # ... batch processing code
   "
   ```

3. Enable database indexing (already done in init.sql)

### For Model Training
1. Use more CPU cores:
   ```yaml
   ml_service:
     deploy:
       resources:
         limits:
           cpus: '4'
   ```

2. Increase training data retention
3. Tune model hyperparameters

##  Security Considerations

This is a development/educational tool running on LocalStack. For production:

1. **Use real AWS services** (or other cloud providers)
2. **Secure database credentials** (use secrets management)
3. **Enable authentication** on dashboard and MLflow
4. **Use HTTPS** for all endpoints
5. **Implement access controls**
6. **Regular backup strategy**
7. **Audit logging**

## Acknowledgments

- Trivy by Aqua Security
- MLflow by Databricks
- LocalStack team
- Scikit-learn community

## Support

For issues or questions:
1. Check troubleshooting section
2. Review Docker logs
3. Check MLflow UI for model issues
4. Inspect PostgreSQL data

---
