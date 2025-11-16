#!/usr/bin/env python3
"""
Feature Engineering for ML-based Anomaly Detection
Extracts meaningful features from vulnerability scan data
"""

import psycopg2
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


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
        features['vuln_per_package'] = total_vulns / max(unique_packages, 1)
        features['unique_packages'] = unique_packages
        features['packages_with_vulns'] = unique_packages
        
        # Severity ratio features
        total = max(total_vulns, 1)
        features['critical_ratio'] = critical / total
        features['high_ratio'] = high / total
        features['medium_ratio'] = medium / total
        features['low_ratio'] = low / total
        
        # CVSS score statistics
        cvss_scores = [v[3] for v in vulnerabilities if v[3] is not None]
        if cvss_scores:
            features['avg_cvss_score'] = np.mean(cvss_scores)
            features['max_cvss_score'] = np.max(cvss_scores)
            features['std_cvss_score'] = np.std(cvss_scores)
            features['median_cvss_score'] = np.median(cvss_scores)
        else:
            features['avg_cvss_score'] = 0.0
            features['max_cvss_score'] = 0.0
            features['std_cvss_score'] = 0.0
            features['median_cvss_score'] = 0.0
        
        # Exploit features
        exploit_count = sum([1 for v in vulnerabilities if v[4]])  # exploit_available
        features['exploitable_count'] = exploit_count
        features['exploit_ratio'] = exploit_count / total
        
        # EPSS (Exploit Prediction Scoring System) features
        epss_scores = [v[5] for v in vulnerabilities if v[5] is not None]
        if epss_scores:
            features['avg_epss_score'] = np.mean(epss_scores)
            features['max_epss_score'] = np.max(epss_scores)
            features['high_epss_count'] = sum([1 for s in epss_scores if s > 0.5])
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
        severity_dist = [critical, high, medium, low]
        if sum(severity_dist) > 0:
            probs = np.array(severity_dist) / sum(severity_dist)
            probs = probs[probs > 0]  # Remove zeros
            features['severity_entropy'] = -np.sum(probs * np.log2(probs))
        else:
            features['severity_entropy'] = 0.0
        
        # Package diversity features
        features['unique_cves'] = len(set([v[0] for v in vulnerabilities]))
        features['cves_per_package'] = features['unique_cves'] / max(unique_packages, 1)
        
        # Risk concentration (how concentrated are high-severity vulns in few packages)
        package_severities = {}
        for vuln in vulnerabilities:
            pkg = vuln[1]
            severity = vuln[2]
            if pkg not in package_severities:
                package_severities[pkg] = []
            package_severities[pkg].append(severity)
        
        high_risk_packages = sum([
            1 for pkg, sevs in package_severities.items()
            if 'CRITICAL' in sevs or 'HIGH' in sevs
        ])
        features['high_risk_package_ratio'] = high_risk_packages / max(unique_packages, 1)
        
        return features
    
    def _compute_trend_features(
        self, cursor, image_name, image_tag, current_timestamp
    ) -> Dict:
        """Compute historical trend features"""
        
        # Get previous scans for this image (last 30 days)
        cursor.execute("""
            SELECT scan_timestamp, total_vulnerabilities, critical_count, 
                   high_count, medium_count, low_count
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
        
        features = {}
        
        if historical:
            # Calculate days since last scan
            last_scan = historical[0][0]
            features['days_since_last_scan'] = (current_timestamp - last_scan).days
            
            # Calculate scan frequency (scans per week)
            if len(historical) > 1:
                first_scan = historical[-1][0]
                days_range = (current_timestamp - first_scan).days
                features['scan_frequency'] = len(historical) / max(days_range / 7, 1)
            else:
                features['scan_frequency'] = 0.0
            
            # Vulnerability growth rate
            prev_total = historical[0][1]
            curr_total = cursor.execute("""
                SELECT total_vulnerabilities FROM scan_results
                WHERE image_name = %s AND image_tag = %s
                  AND scan_timestamp = %s
            """, (image_name, image_tag, current_timestamp))
            
            cursor.execute("""
                SELECT total_vulnerabilities FROM scan_results
                WHERE image_name = %s AND image_tag = %s
                  AND scan_timestamp = %s
            """, (image_name, image_tag, current_timestamp))
            
            current_row = cursor.fetchone()
            curr_total = current_row[0] if current_row else 0
            
            features['vuln_growth_rate'] = (curr_total - prev_total) / max(prev_total, 1)
            
            # New critical vulnerabilities
            features['new_critical_count'] = max(0, cursor.fetchone()[0] if cursor.fetchone() else 0)
            
            # Severity trend score (weighted change in severity distribution)
            prev_critical, prev_high = historical[0][2], historical[0][3]
            cursor.execute("""
                SELECT critical_count, high_count FROM scan_results
                WHERE image_name = %s AND image_tag = %s
                  AND scan_timestamp = %s
            """, (image_name, image_tag, current_timestamp))
            
            curr_row = cursor.fetchone()
            if curr_row:
                curr_critical, curr_high = curr_row
                features['severity_trend_score'] = (
                    (curr_critical - prev_critical) * 2 +
                    (curr_high - prev_high) * 1
                )
            else:
                features['severity_trend_score'] = 0.0
                
        else:
            # First scan for this image
            features['days_since_last_scan'] = 0
            features['scan_frequency'] = 0.0
            features['vuln_growth_rate'] = 0.0
            features['new_critical_count'] = 0
            features['severity_trend_score'] = 0.0
        
        return features
    
    def _store_features(self, scan_id: str, features: Dict):
        """Store computed features in database"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT INTO ml_features (
                scan_id, vuln_per_package, critical_ratio, high_ratio,
                medium_ratio, low_ratio, vuln_growth_rate, new_critical_count,
                severity_trend_score, unique_packages, packages_with_vulns,
                avg_cvss_score, max_cvss_score, exploitable_count,
                avg_epss_score, high_epss_count, days_since_last_scan,
                scan_frequency, features_json
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
        """, (
            scan_id,
            features.get('vuln_per_package', 0),
            features.get('critical_ratio', 0),
            features.get('high_ratio', 0),
            features.get('medium_ratio', 0),
            features.get('low_ratio', 0),
            features.get('vuln_growth_rate', 0),
            features.get('new_critical_count', 0),
            features.get('severity_trend_score', 0),
            features.get('unique_packages', 0),
            features.get('packages_with_vulns', 0),
            features.get('avg_cvss_score', 0),
            features.get('max_cvss_score', 0),
            features.get('exploitable_count', 0),
            features.get('avg_epss_score', 0),
            features.get('high_epss_count', 0),
            features.get('days_since_last_scan', 0),
            features.get('scan_frequency', 0),
            psycopg2.extras.Json(features)
        ))
        
        self.conn.commit()
        cursor.close()
        logger.info(f"Stored {len(features)} features for scan {scan_id}")
    
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
        
        df = pd.read_sql_query(query, self.conn, params=(limit,))
        
        # For unsupervised learning, we don't have labels
        # We'll use all data for training
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