-- Database initialization script

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Scan Results Table
CREATE TABLE IF NOT EXISTS scan_results (
    id SERIAL PRIMARY KEY,
    scan_id UUID DEFAULT uuid_generate_v4(),
    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    image_name VARCHAR(255) NOT NULL,
    image_tag VARCHAR(100) NOT NULL,
    total_vulnerabilities INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    unknown_count INTEGER DEFAULT 0,
    scan_duration_seconds DECIMAL(10, 2),
    scan_status VARCHAR(50) DEFAULT 'completed',
    metadata JSONB
);

-- Individual Vulnerabilities Table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_id UUID REFERENCES scan_results(scan_id) ON DELETE CASCADE,
    cve_id VARCHAR(50) NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    installed_version VARCHAR(100),
    fixed_version VARCHAR(100),
    severity VARCHAR(20) NOT NULL,
    cvss_score DECIMAL(3, 1),
    description TEXT,
    reference_urls TEXT[],
    published_date TIMESTAMP,
    last_modified_date TIMESTAMP,
    exploit_available BOOLEAN DEFAULT FALSE,
    epss_score DECIMAL(5, 4),  -- Exploit Prediction Scoring System
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ML Features Table
CREATE TABLE IF NOT EXISTS ml_features (
    id SERIAL PRIMARY KEY,
    scan_id UUID REFERENCES scan_results(scan_id) ON DELETE CASCADE,
    feature_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Vulnerability density features
    vuln_per_package DECIMAL(10, 4),
    critical_ratio DECIMAL(5, 4),
    high_ratio DECIMAL(5, 4),
    medium_ratio DECIMAL(5, 4),
    low_ratio DECIMAL(5, 4),
    
    -- Trend features
    vuln_growth_rate DECIMAL(10, 4),
    new_critical_count INTEGER,
    severity_trend_score DECIMAL(10, 4),
    
    -- Package features
    unique_packages INTEGER,
    packages_with_vulns INTEGER,
    avg_cvss_score DECIMAL(3, 1),
    max_cvss_score DECIMAL(3, 1),
    
    -- Exploit features
    exploitable_count INTEGER,
    avg_epss_score DECIMAL(5, 4),
    high_epss_count INTEGER,
    
    -- Time features
    days_since_last_scan INTEGER,
    scan_frequency DECIMAL(10, 4),
    
    features_json JSONB
);

-- ML Predictions Table
CREATE TABLE IF NOT EXISTS ml_predictions (
    id SERIAL PRIMARY KEY,
    scan_id UUID REFERENCES scan_results(scan_id) ON DELETE CASCADE,
    prediction_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    model_version VARCHAR(50),
    
    -- Anomaly detection
    is_anomaly BOOLEAN,
    anomaly_score DECIMAL(5, 4),
    anomaly_threshold DECIMAL(5, 4),
    
    -- Risk scoring
    risk_score DECIMAL(5, 2),  -- 0-100
    risk_category VARCHAR(20),  -- low, medium, high, critical
    confidence_score DECIMAL(5, 4),
    
    -- Feature importance
    top_contributing_features JSONB,
    
    -- Recommendations
    recommendations TEXT[],
    priority_actions TEXT[]
);

-- Security Alerts Table
CREATE TABLE IF NOT EXISTS security_alerts (
    id SERIAL PRIMARY KEY,
    alert_id UUID DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scan_results(scan_id) ON DELETE CASCADE,
    alert_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    alert_type VARCHAR(50) NOT NULL,  -- anomaly, high_risk, exploit_available
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    affected_packages TEXT[],
    recommended_actions TEXT[],
    status VARCHAR(20) DEFAULT 'open',  -- open, acknowledged, resolved, false_positive
    acknowledged_by VARCHAR(100),
    acknowledged_at TIMESTAMP,
    resolved_at TIMESTAMP,
    metadata JSONB
);

-- Model Performance Metrics Table
CREATE TABLE IF NOT EXISTS model_metrics (
    id SERIAL PRIMARY KEY,
    metric_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(50) NOT NULL,
    
    -- Training metrics
    training_samples INTEGER,
    validation_samples INTEGER,
    training_accuracy DECIMAL(5, 4),
    validation_accuracy DECIMAL(5, 4),
    
    -- Performance metrics
    precision_score DECIMAL(5, 4),
    recall_score DECIMAL(5, 4),
    f1_score DECIMAL(5, 4),
    roc_auc DECIMAL(5, 4),
    
    -- Drift detection
    data_drift_score DECIMAL(5, 4),
    concept_drift_detected BOOLEAN,
    
    metrics_json JSONB
);

-- Create indexes for better query performance
CREATE INDEX idx_scan_results_timestamp ON scan_results(scan_timestamp);
CREATE INDEX idx_scan_results_image ON scan_results(image_name, image_tag);
CREATE INDEX idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX idx_vulnerabilities_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_ml_features_scan_id ON ml_features(scan_id);
CREATE INDEX idx_ml_predictions_scan_id ON ml_predictions(scan_id);
CREATE INDEX idx_security_alerts_status ON security_alerts(status);
CREATE INDEX idx_security_alerts_timestamp ON security_alerts(alert_timestamp);

-- Create views for common queries

-- Latest scan results per image
CREATE OR REPLACE VIEW latest_scans AS
SELECT DISTINCT ON (image_name, image_tag)
    sr.*,
    mp.risk_score,
    mp.risk_category,
    mp.is_anomaly
FROM scan_results sr
LEFT JOIN ml_predictions mp ON sr.scan_id = mp.scan_id
ORDER BY image_name, image_tag, scan_timestamp DESC;

-- High-risk vulnerabilities view
CREATE OR REPLACE VIEW high_risk_vulnerabilities AS
SELECT 
    v.*,
    sr.image_name,
    sr.image_tag,
    sr.scan_timestamp,
    mp.risk_score
FROM vulnerabilities v
JOIN scan_results sr ON v.scan_id = sr.scan_id
LEFT JOIN ml_predictions mp ON v.scan_id = mp.scan_id
WHERE v.severity IN ('CRITICAL', 'HIGH')
   OR v.exploit_available = TRUE
   OR v.epss_score > 0.5
ORDER BY sr.scan_timestamp DESC, v.cvss_score DESC;

-- Active alerts view
CREATE OR REPLACE VIEW active_alerts AS
SELECT 
    sa.*,
    sr.image_name,
    sr.image_tag,
    sr.scan_timestamp
FROM security_alerts sa
JOIN scan_results sr ON sa.scan_id = sr.scan_id
WHERE sa.status IN ('open', 'acknowledged')
ORDER BY sa.alert_timestamp DESC;

-- Model performance summary
CREATE OR REPLACE VIEW model_performance_summary AS
SELECT 
    model_name,
    model_version,
    MAX(metric_timestamp) as last_updated,
    AVG(validation_accuracy) as avg_accuracy,
    AVG(f1_score) as avg_f1_score,
    COUNT(*) as evaluation_count
FROM model_metrics
GROUP BY model_name, model_version
ORDER BY last_updated DESC;

-- Insert sample data for testing
INSERT INTO scan_results (image_name, image_tag, total_vulnerabilities, critical_count, high_count, medium_count, low_count) 
VALUES 
    ('test-app', 'v1.0', 0, 0, 0, 0, 0),
    ('test-app', 'v1.1', 5, 1, 2, 2, 0);

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO security_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO security_user;