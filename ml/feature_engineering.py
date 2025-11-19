#!/usr/bin/env python3
"""
Feature Engineering for ML-based Anomaly Detection
Extracts meaningful features from vulnerability scan data
"""

import json
from decimal import Decimal
import psycopg2
import psycopg2.extras
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def convert_decimals(obj):
    """
    Recursively convert Decimal -> float so json.dumps() and ML libs don't choke.
    """
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, dict):
        return {k: convert_decimals(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [convert_decimals(i) for i in obj]
    return obj


class FeatureEngineer:
    """Extract ML features from vulnerability scan data"""
    
    def __init__(self, db_config: Dict[str, str]):
        """
        Initialize feature engineer
        
        Args:
            db_config: Database connection parameters
        """
        self.db_config = db_config
        self.conn = None
    
    def connect_db(self):
        """Establish database connection"""
        self.conn = psycopg2.connect(**self.db_config)
        logger.info("Connected to database")
    
    def extract_features_for_scan(self, scan_id: str) -> Dict:
        """
        Extract features for a specific scan
        
        Args:
            scan_id: UUID of the scan
            
        Returns:
            Dictionary of features
        """
        cursor = self.conn.cursor()
        
        # Get scan details
        cursor.execute("""
            SELECT image_name, image_tag, scan_timestamp, total_vulnerabilities,
                   critical_count, high_count, medium_count, low_count
            FROM scan_results
            WHERE scan_id = %s
        """, (scan_id,))
        
        scan_data = cursor.fetchone()
        if not scan_data:
            cursor.close()
            raise ValueError(f"Scan {scan_id} not found")
        
        image_name, image_tag, scan_timestamp, total_vulns, critical, high, medium, low = scan_data
        
        # Get vulnerability details
        cursor.execute("""
            SELECT cve_id, package_name, severity, cvss_score, 
                   exploit_available, epss_score
            FROM vulnerabilities
            WHERE scan_id = %s
        """, (scan_id,))
        
        vulnerabilities = cursor.fetchall()
        
        # Extract features
        features = self._compute_features(
            scan_id, image_name, image_tag, scan_timestamp,
            total_vulns, critical, high, medium, low,
            vulnerabilities, cursor
        )
        
        # Store features in database
        self._store_features(scan_id, features)
        
        cursor.close()
        return features
    
    def _compute_features(
        self, scan_id, image_name, image_tag, scan_timestamp,
        total_vulns, critical, high, medium, low,
        vulnerabilities, cursor
    ) -> Dict:
        """Compute all features"""
        
        features = {}
        
        # Basic vulnerability density features
        unique_packages = len(set([v[1] for v in vulnerabilities])) if vulnerabilities else 1
        features['vuln_per_package'] = float(total_vulns) / max(unique_packages, 1)
        features['unique_packages'] = unique_packages
        features['packages_with_vulns'] = unique_packages
        
        # Severity ratio features
        total = max(int(total_vulns or 0), 1)
        features['critical_ratio'] = float(critical) / total if total else 0.0
        features['high_ratio'] = float(high) / total if total else 0.0
        features['medium_ratio'] = float(medium) / total if total else 0.0
        features['low_ratio'] = float(low) / total if total else 0.0
        
        # CVSS score statistics
        cvss_scores = [float(v[3]) for v in vulnerabilities if v[3] is not None]
        if cvss_scores:
            features['avg_cvss_score'] = float(np.mean(cvss_scores))
            features['max_cvss_score'] = float(np.max(cvss_scores))
            features['std_cvss_score'] = float(np.std(cvss_scores))
            features['median_cvss_score'] = float(np.median(cvss_scores))
        else:
            features['avg_cvss_score'] = 0.0
            features['max_cvss_score'] = 0.0
            features['std_cvss_score'] = 0.0
            features['median_cvss_score'] = 0.0
        
        # Exploit features
        exploit_count = sum([1 for v in vulnerabilities if v[4]])
        features['exploitable_count'] = exploit_count
        features['exploit_ratio'] = float(exploit_count) / total if total else 0.0
        
        # EPSS features
        epss_scores = [float(v[5]) for v in vulnerabilities if v[5] is not None]
        if epss_scores:
            features['avg_epss_score'] = float(np.mean(epss_scores))
            features['max_epss_score'] = float(np.max(epss_scores))
            features['high_epss_count'] = int(sum([1 for s in epss_scores if s > 0.5]))
        else:
            features['avg_epss_score'] = 0.0
            features['max_epss_score'] = 0.0
            features['high_epss_count'] = 0
        
        # Historical trend features
        trend_features = self._compute_trend_features(
            cursor, image_name, image_tag, scan_timestamp
        )
        features.update(trend_features)
        
        # Severity distribution entropy (measure of uncertainty)
        severity_dist = [int(critical or 0), int(high or 0), int(medium or 0), int(low or 0)]
        if sum(severity_dist) > 0:
            probs = np.array(severity_dist) / sum(severity_dist)
            probs = probs[probs > 0]  # Remove zeros
            features['severity_entropy'] = float(-np.sum(probs * np.log2(probs)))
        else:
            features['severity_entropy'] = 0.0
        
        # Package and CVE diversity
        unique_cves = len(set([v[0] for v in vulnerabilities]))
        features['unique_cves'] = unique_cves
        features['cves_per_package'] = float(features['unique_cves']) / max(unique_packages, 1)
        
        # Risk concentration
        package_severities = {}
        for vuln in vulnerabilities:
            pkg = vuln[1]
            severity = vuln[2]
            package_severities.setdefault(pkg, []).append(severity)
        
        high_risk_packages = sum([
            1 for pkg, sevs in package_severities.items()
            if any(s in ('CRITICAL', 'HIGH') for s in sevs)
        ])
        features['high_risk_package_ratio'] = float(high_risk_packages) / max(unique_packages, 1)
        
        # Keep original summary counts for convenience
        features['total_vulnerabilities'] = int(total_vulns or 0)
        features['critical_count'] = int(critical or 0)
        features['high_count'] = int(high or 0)
        features['medium_count'] = int(medium or 0)
        features['low_count'] = int(low or 0)
        
        # Any additional features you computed can go into features_json
        return features
    
    def _compute_trend_features(
        self, cursor, image_name, image_tag, current_timestamp
    ) -> Dict:
        """Compute historical trend features"""
        
        features = {}
        # Get previous scans for this image (last 30 days), most recent first
        cursor.execute("""
            SELECT scan_timestamp, total_vulnerabilities, critical_count, high_count
            FROM scan_results
            WHERE image_name = %s AND image_tag = %s
              AND scan_timestamp < %s
              AND scan_timestamp > %s
            ORDER BY scan_timestamp DESC
            LIMIT 10
        """, (
            image_name, image_tag, current_timestamp,
            current_timestamp - timedelta(days=30)
        ))
        historical = cursor.fetchall()
        
        if historical:
            # last scan timestamp
            last_scan_ts = historical[0][0]
            features['days_since_last_scan'] = int((current_timestamp - last_scan_ts).days)
            
            # scan frequency (per week) using available history range (if >1)
            if len(historical) > 1:
                oldest_ts = historical[-1][0]
                days_range = max((current_timestamp - oldest_ts).days, 1)
                features['scan_frequency'] = float(len(historical)) / (days_range / 7.0)
            else:
                features['scan_frequency'] = 0.0
            
            # Vulnerability growth rate: compare latest historical total to current total
            prev_total = int(historical[0][1] or 0)
            # fetch current total_vulnerabilities for the scan (should be present)
            cursor.execute("""
                SELECT total_vulnerabilities FROM scan_results
                WHERE image_name = %s AND image_tag = %s AND scan_timestamp = %s
            """, (image_name, image_tag, current_timestamp))
            row = cursor.fetchone()
            curr_total = int(row[0]) if row and row[0] is not None else 0
            features['vuln_growth_rate'] = float(curr_total - prev_total) / max(prev_total, 1)
            
            # New critical count: difference between current and previous critical_count
            cursor.execute("""
                SELECT critical_count FROM scan_results
                WHERE image_name = %s AND image_tag = %s AND scan_timestamp = %s
            """, (image_name, image_tag, current_timestamp))
            row_curr = cursor.fetchone()
            curr_critical = int(row_curr[0]) if row_curr and row_curr[0] is not None else 0
            prev_critical = int(historical[0][2] or 0)
            features['new_critical_count'] = max(0, curr_critical - prev_critical)
            
            # Severity trend score: weighted change
            prev_critical = int(historical[0][2] or 0)
            prev_high = int(historical[0][3] or 0)
            features['severity_trend_score'] = float((curr_critical - prev_critical) * 2 + (0) * 1)
        else:
            features['days_since_last_scan'] = 0
            features['scan_frequency'] = 0.0
            features['vuln_growth_rate'] = 0.0
            features['new_critical_count'] = 0
            features['severity_trend_score'] = 0.0
        
        return features
    
    def _store_features(self, scan_id, features):
        """
        Store key features into ml_features table and stash full features JSON
        """
        # Convert Decimals -> floats recursively
        clean_features = convert_decimals(features)
        
        # Prepare insert payload: map expected columns, put rest into features_json
        payload = {
            'scan_id': scan_id,
            'vuln_per_package': clean_features.get('vuln_per_package', 0.0),
            'critical_ratio': clean_features.get('critical_ratio', 0.0),
            'high_ratio': clean_features.get('high_ratio', 0.0),
            'medium_ratio': clean_features.get('medium_ratio', 0.0),
            'low_ratio': clean_features.get('low_ratio', 0.0),
            'vuln_growth_rate': clean_features.get('vuln_growth_rate', 0.0),
            'new_critical_count': int(clean_features.get('new_critical_count', 0)),
            'severity_trend_score': clean_features.get('severity_trend_score', 0.0),
            'unique_packages': int(clean_features.get('unique_packages', 0)),
            'packages_with_vulns': int(clean_features.get('packages_with_vulns', 0)),
            'avg_cvss_score': clean_features.get('avg_cvss_score', 0.0),
            'max_cvss_score': clean_features.get('max_cvss_score', 0.0),
            'exploitable_count': int(clean_features.get('exploitable_count', 0)),
            'avg_epss_score': clean_features.get('avg_epss_score', 0.0),
            'high_epss_count': int(clean_features.get('high_epss_count', 0)),
            'days_since_last_scan': int(clean_features.get('days_since_last_scan', 0)),
            'scan_frequency': clean_features.get('scan_frequency', 0.0),
            'features_json': json.dumps(clean_features)
        }
        
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO ml_features (
                scan_id, vuln_per_package, critical_ratio, high_ratio, medium_ratio,
                low_ratio, vuln_growth_rate, new_critical_count, severity_trend_score,
                unique_packages, packages_with_vulns, avg_cvss_score, max_cvss_score,
                exploitable_count, avg_epss_score, high_epss_count,
                days_since_last_scan, scan_frequency, features_json
            ) VALUES (
                %(scan_id)s, %(vuln_per_package)s, %(critical_ratio)s, %(high_ratio)s, %(medium_ratio)s,
                %(low_ratio)s, %(vuln_growth_rate)s, %(new_critical_count)s, %(severity_trend_score)s,
                %(unique_packages)s, %(packages_with_vulns)s, %(avg_cvss_score)s, %(max_cvss_score)s,
                %(exploitable_count)s, %(avg_epss_score)s, %(high_epss_count)s,
                %(days_since_last_scan)s, %(scan_frequency)s, %(features_json)s
            )
        """, payload)
        self.conn.commit()
        cursor.close()
        logger.info(f"Stored features for scan {scan_id}")
    
    def get_training_data(self, limit: int = 1000) -> Tuple[pd.DataFrame, np.ndarray]:
        """
        Get training data from database
        
        Args:
            limit: Maximum number of records to fetch
            
        Returns:
            Tuple of (features DataFrame, labels array)
        """
        query = """
            SELECT 
                vuln_per_package, critical_ratio, high_ratio, medium_ratio,
                low_ratio, vuln_growth_rate, new_critical_count,
                severity_trend_score, unique_packages, packages_with_vulns,
                avg_cvss_score, max_cvss_score, exploitable_count,
                avg_epss_score, high_epss_count, days_since_last_scan,
                scan_frequency
            FROM ml_features
            ORDER BY feature_timestamp DESC
            LIMIT %s
        """
        
        # pandas accepts a connection object here — warning may appear but it works
        df = pd.read_sql_query(query, self.conn, params=(limit,))
        
        # For unsupervised learning, we don't have labels
        return df, None
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


def main():
    """Test feature extraction"""
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
    
    try:
        # Get training data
        X, _ = engineer.get_training_data()
        print(f"Extracted {len(X)} training samples")
        print(f"Features: {list(X.columns)}")
        print(f"\nFeature statistics:\n{X.describe()}")
    finally:
        engineer.close()


if __name__ == "__main__":
    main()
