-- Migration 002: Add EPSS (Exploit Prediction Scoring System) Support
-- Enhances vulnerability tracking with exploit prediction scores

-- Add EPSS percentile column
ALTER TABLE vulnerabilities 
ADD COLUMN IF NOT EXISTS epss_percentile DECIMAL(5, 4);

-- Add last updated timestamp for EPSS data
ALTER TABLE vulnerabilities 
ADD COLUMN IF NOT EXISTS epss_updated_at TIMESTAMP;

-- Add vulnerability age tracking
ALTER TABLE vulnerabilities 
ADD COLUMN IF NOT EXISTS days_since_published INTEGER 
GENERATED ALWAYS AS (
    EXTRACT(DAY FROM CURRENT_DATE - published_date::date)
) STORED;

-- Add fix available flag
ALTER TABLE vulnerabilities 
ADD COLUMN IF NOT EXISTS fix_available BOOLEAN 
GENERATED ALWAYS AS (
    fixed_version IS NOT NULL AND fixed_version != '' AND fixed_version != 'N/A'
) STORED;

-- Create function to calculate vulnerability priority score
CREATE OR REPLACE FUNCTION calculate_priority_score(
    p_severity TEXT,
    p_cvss_score NUMERIC,
    p_epss_score NUMERIC,
    p_exploit_available BOOLEAN,
    p_fix_available BOOLEAN
) RETURNS NUMERIC AS $$
DECLARE
    priority_score NUMERIC := 0;
BEGIN
    -- Base score from severity
    priority_score := CASE 
        WHEN p_severity = 'CRITICAL' THEN 40
        WHEN p_severity = 'HIGH' THEN 30
        WHEN p_severity = 'MEDIUM' THEN 20
        WHEN p_severity = 'LOW' THEN 10
        ELSE 5
    END;
    
    -- Add CVSS component (max 25 points)
    IF p_cvss_score IS NOT NULL THEN
        priority_score := priority_score + (p_cvss_score * 2.5);
    END IF;
    
    -- Add EPSS component (max 20 points)
    IF p_epss_score IS NOT NULL THEN
        priority_score := priority_score + (p_epss_score * 20);
    END IF;
    
    -- Boost if exploit available (add 15 points)
    IF p_exploit_available THEN
        priority_score := priority_score + 15;
    END IF;
    
    -- Reduce if no fix available (subtract 10 points)
    IF NOT p_fix_available THEN
        priority_score := priority_score - 10;
    END IF;
    
    -- Normalize to 0-100 scale
    RETURN GREATEST(0, LEAST(100, priority_score));
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Add priority score column
ALTER TABLE vulnerabilities 
ADD COLUMN IF NOT EXISTS priority_score NUMERIC 
GENERATED ALWAYS AS (
    calculate_priority_score(
        severity, 
        cvss_score, 
        epss_score, 
        exploit_available, 
        fix_available
    )
) STORED;

-- Create view for prioritized vulnerabilities
CREATE OR REPLACE VIEW prioritized_vulnerabilities AS
SELECT 
    v.id,
    v.scan_id,
    sr.image_name,
    sr.image_tag,
    v.cve_id,
    v.package_name,
    v.severity,
    v.cvss_score,
    v.epss_score,
    v.exploit_available,
    v.fix_available,
    v.priority_score,
    v.days_since_published,
    v.description,
    v.fixed_version,
    sr.scan_timestamp
FROM vulnerabilities v
JOIN scan_results sr ON v.scan_id = sr.scan_id
WHERE sr.scan_status = 'completed'
ORDER BY v.priority_score DESC, sr.scan_timestamp DESC;

-- Create materialized view for performance (refresh periodically)
CREATE MATERIALIZED VIEW IF NOT EXISTS vulnerability_statistics AS
SELECT 
    DATE_TRUNC('day', sr.scan_timestamp) as date,
    COUNT(DISTINCT v.cve_id) as unique_cves,
    COUNT(*) as total_vulns,
    AVG(v.cvss_score) as avg_cvss,
    AVG(v.epss_score) as avg_epss,
    SUM(CASE WHEN v.severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
    SUM(CASE WHEN v.severity = 'HIGH' THEN 1 ELSE 0 END) as high_count,
    SUM(CASE WHEN v.exploit_available THEN 1 ELSE 0 END) as exploitable_count,
    SUM(CASE WHEN v.fix_available THEN 1 ELSE 0 END) as fixable_count,
    AVG(v.priority_score) as avg_priority_score
FROM vulnerabilities v
JOIN scan_results sr ON v.scan_id = sr.scan_id
WHERE sr.scan_timestamp > CURRENT_DATE - INTERVAL '90 days'
GROUP BY DATE_TRUNC('day', sr.scan_timestamp)
ORDER BY date DESC;

-- Create index on materialized view
CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_stats_date 
ON vulnerability_statistics(date);

-- Create function to refresh statistics
CREATE OR REPLACE FUNCTION refresh_vulnerability_statistics()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY vulnerability_statistics;
END;
$$ LANGUAGE plpgsql;

-- Add index for priority-based queries
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_priority 
ON vulnerabilities(priority_score DESC) 
WHERE priority_score > 70;

-- Add index for EPSS queries
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_epss 
ON vulnerabilities(epss_score DESC) 
WHERE epss_score > 0.5;

-- Update statistics
ANALYZE vulnerabilities;

-- Create comment
COMMENT ON COLUMN vulnerabilities.priority_score IS 
'Calculated priority score (0-100) based on severity, CVSS, EPSS, exploit availability, and fix availability';

COMMENT ON FUNCTION calculate_priority_score IS 
'Calculates a unified priority score for vulnerability remediation prioritization';

-- Display summary
SELECT 'Migration 002 completed successfully' as status;