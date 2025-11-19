-- ============================================================
-- Database Initialization Script
-- ============================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================
-- Scan Results Table
-- ============================================================
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

-- Add UNIQUE constraint for foreign key references
ALTER TABLE scan_results
    ADD CONSTRAINT scan_results_scan_id_key UNIQUE (scan_id);

-- ============================================================
-- Vulnerabilities Table
-- ============================================================
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
    epss_score DECIMAL(5, 4),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- ML Features Table
-- ============================================================
CREATE TABLE IF NOT EXISTS ml_features (
    id SERIAL PRIMARY KEY,
    scan_id UUID REFERENCES scan_results(scan_id) ON DELETE CASCADE,
    feature_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    vuln_per_package DECIMAL(10, 4),
    critical_ratio DECIMAL(5, 4),
    high_ratio DECIMAL(5, 4),
    medium_ratio DECIMAL(5, 4),
    low_ratio DECIMAL(5, 4),

    vuln_growth_rate DECIMAL(10, 4),
    new_critical_count INTEGER,
    severity_trend_score DECIMAL(10, 4),

    unique_packages INTEGER,
    packages_with_vulns INTEGER,
    avg_cvss_score DECIMAL(3, 1),
    max_cvss_score DECIMAL(3, 1),

    exploitable_count INTEGER,
    avg_epss_score DECIMAL(5, 4),
    high_epss_count INTEGER,

    days_since_last_scan INTEGER,
    scan_frequency DECIMAL(10, 4),

    features_json JSONB
);

-- ============================================================
-- ML Predictions Table
-- ============================================================
CREATE TABLE IF NOT EXISTS ml_predictions (
    id SERIAL PRIMARY KEY,
    scan_id UUID REFERENCES scan_results(scan_id) ON DELETE CASCADE,
    prediction_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    model_version VARCHAR(50),

    is_anomaly BOOLEAN,
    anomaly_score DECIMAL(5, 4),
    anomaly_threshold DECIMAL(5, 4),

    risk_score DECIMAL(5, 2),
    risk_category VARCHAR(20),
    confidence_score DECIMAL(5, 4),

    top_contributing_features JSONB,
    recommendations TEXT[],
    priority_actions TEXT[]
);

-- ============================================================
-- Security Alerts Table
-- ============================================================
CREATE TABLE IF NOT EXISTS security_alerts (
    id SERIAL PRIMARY KEY,
    alert_id UUID DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES scan_results(scan_id) ON DELETE CASCADE,
    alert_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    alert_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,

    affected_packages TEXT[],
    recommended_actions TEXT[],
    status VARCHAR(20) DEFAULT 'open',

    acknowledged_by VARCHAR(100),
    acknowledged_at TIMESTAMP,
    resolved_at TIMESTAMP,

    metadata JSONB
);

-- ============================================================
-- Model Metrics Table
-- ============================================================
CREATE TABLE IF NOT EXISTS model_metrics (
    id SERIAL PRIMARY KEY,
    metric_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(50) NOT NULL,

    training_samples INTEGER,
    validation_samples INTEGER,
    training_accuracy DECIMAL(5, 4),
    validation_accuracy DECIMAL(5, 4),

    precision_score DECIMAL(5, 4),
    recall_score DECIMAL(5, 4),
    f1_score DECIMAL(5, 4),
    roc_auc DECIMAL(5, 4),

    data_drift_score DECIMAL(5, 4),
    concept_drift_detected BOOLEAN,

    metrics_json JSONB
);

-- ============================================================
-- Indexes
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_scan_results_timestamp ON scan_results(scan_timestamp);
CREATE INDEX IF NOT EXISTS idx_scan_results_image ON scan_results(image_name, image_tag);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_ml_features_scan_id ON ml_features(scan_id);
CREATE INDEX IF NOT EXISTS idx_ml_predictions_scan_id ON ml_predictions(scan_id);
CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_security_alerts_timestamp ON security_alerts(alert_timestamp);

-- ============================================================
-- Views
-- ============================================================

-- Latest scan per image
CREATE OR REPLACE VIEW latest_scans AS
SELECT DISTINCT ON (image_name, image_tag)
    sr.*,
    mp.risk_score,
    mp.risk_category,
    mp.is_anomaly
FROM scan_results sr
LEFT JOIN ml_predictions mp ON sr.scan_id = mp.scan_id
ORDER BY image_name, image_tag, scan_timestamp DESC;

-- High-risk vulnerabilities
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

-- Active alerts
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
    MAX(metric_timestamp) AS last_updated,
    AVG(validation_accuracy) AS avg_accuracy,
    AVG(f1_score) AS avg_f1_score,
    COUNT(*) AS evaluation_count
FROM model_metrics
GROUP BY model_name, model_version
ORDER BY last_updated DESC;

-- ============================================================
-- Sample Data
-- ============================================================
INSERT INTO scan_results (image_name, image_tag, total_vulnerabilities, critical_count, high_count, medium_count, low_count)
VALUES 
    ('test-app', 'v1.0', 0, 0, 0, 0, 0),
    ('test-app', 'v1.1', 5, 1, 2, 2, 0);

-- ============================================================
-- Permissions
-- ============================================================
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO security_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO security_user;
