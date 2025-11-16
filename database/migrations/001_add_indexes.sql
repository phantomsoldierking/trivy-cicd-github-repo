-- Migration 001: Additional Performance Indexes
-- Run this migration to improve query performance on large datasets

-- Add composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_scan_results_image_timestamp 
ON scan_results(image_name, image_tag, scan_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity_cvss 
ON vulnerabilities(severity, cvss_score DESC) 
WHERE severity IN ('CRITICAL', 'HIGH');

CREATE INDEX IF NOT EXISTS idx_ml_predictions_risk_anomaly 
ON ml_predictions(risk_score DESC, is_anomaly);

-- Add index for alert queries
CREATE INDEX IF NOT EXISTS idx_alerts_status_timestamp 
ON security_alerts(status, alert_timestamp DESC);

-- Add GIN index for JSONB fields (for faster JSON queries)
CREATE INDEX IF NOT EXISTS idx_ml_features_json 
ON ml_features USING GIN (features_json);

CREATE INDEX IF NOT EXISTS idx_ml_predictions_json 
ON ml_predictions USING GIN (top_contributing_features);

-- Add partial indexes for active alerts only
CREATE INDEX IF NOT EXISTS idx_active_alerts 
ON security_alerts(alert_timestamp DESC) 
WHERE status IN ('open', 'acknowledged');

-- Add index for vulnerability package lookups
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_package 
ON vulnerabilities(package_name, severity);

-- Add index for CVE lookups
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_scan 
ON vulnerabilities(cve_id, scan_id);

-- Add covering index for scan summary queries
CREATE INDEX IF NOT EXISTS idx_scan_results_summary 
ON scan_results(scan_id, image_name, image_tag, total_vulnerabilities, 
                critical_count, high_count, scan_timestamp);

-- Add index for time-based queries
CREATE INDEX IF NOT EXISTS idx_scan_results_recent 
ON scan_results(scan_timestamp DESC) 
WHERE scan_status = 'completed';

-- Statistics update
ANALYZE scan_results;
ANALYZE vulnerabilities;
ANALYZE ml_features;
ANALYZE ml_predictions;
ANALYZE security_alerts;

-- Verify indexes
SELECT 
    schemaname,
    tablename,
    indexname,
    indexdef
FROM pg_indexes 
WHERE schemaname = 'public'
ORDER BY tablename, indexname;