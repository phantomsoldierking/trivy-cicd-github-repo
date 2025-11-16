#!/usr/bin/env python3
"""
ML Prediction Module for Real-time Anomaly Detection
Applies trained models to new scan results
"""

import os
import json
import pickle
import numpy as np
import psycopg2
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurityPredictor:
    """Make predictions on new vulnerability scans"""
    
    def __init__(self, db_config: dict, model_dir: str = "/models"):
        """
        Initialize predictor
        
        Args:
            db_config: Database connection parameters
            model_dir: Directory containing trained models
        """
        self.db_config = db_config
        self.model_dir = model_dir
        self.conn = None
        
        self.anomaly_model = None
        self.risk_model = None
        self.scaler = None
        
        self._load_models()
    
    def _load_models(self):
        """Load trained models from disk"""
        try:
            # Load metadata
            metadata_path = os.path.join(self.model_dir, "latest_models.json")
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                # Load anomaly model
                if metadata.get('anomaly_model') and os.path.exists(metadata['anomaly_model']):
                    with open(metadata['anomaly_model'], 'rb') as f:
                        self.anomaly_model = pickle.load(f)
                    logger.info("Loaded anomaly detection model")
                
                # Load scaler
                if metadata.get('scaler') and os.path.exists(metadata['scaler']):
                    with open(metadata['scaler'], 'rb') as f:
                        self.scaler = pickle.load(f)
                    logger.info("Loaded feature scaler")
                
                # Load risk model
                if metadata.get('risk_model') and os.path.exists(metadata['risk_model']):
                    with open(metadata['risk_model'], 'rb') as f:
                        self.risk_model = pickle.load(f)
                    logger.info("Loaded risk scoring model")
            else:
                logger.warning("No trained models found. Please run training first.")
        
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
    
    def connect_db(self):
        """Establish database connection"""
        self.conn = psycopg2.connect(**self.db_config)
        logger.info("Connected to database")
    
    def predict_for_scan(self, scan_id: str) -> dict:
        """
        Make predictions for a specific scan
        
        Args:
            scan_id: UUID of the scan
            
        Returns:
            Dictionary containing predictions
        """
        if not self.anomaly_model or not self.risk_model:
            logger.error("Models not loaded. Cannot make predictions.")
            return {}
        
        # Get features
        features = self._get_features(scan_id)
        if not features:
            logger.error(f"No features found for scan {scan_id}")
            return {}
        
        # Prepare feature vector for anomaly detection
        anomaly_features = [
            features['vuln_per_package'],
            features['critical_ratio'],
            features['high_ratio'],
            features['vuln_growth_rate'],
            features['new_critical_count'],
            features['severity_trend_score'],
            features['avg_cvss_score'],
            features['max_cvss_score'],
            features['exploitable_count'],
            features['avg_epss_score'],
            features['high_epss_count']
        ]
        
        # Prepare feature vector for risk scoring
        risk_features = [
            features['total_vulnerabilities'],
            features['critical_count'],
            features['high_count'],
            features['vuln_per_package'],
            features['critical_ratio'],
            features['high_ratio'],
            features['avg_cvss_score'],
            features['max_cvss_score'],
            features['exploitable_count'],
            features['avg_epss_score'],
            features['high_epss_count'],
            features['vuln_growth_rate']
        ]
        
        # Scale features
        X_anomaly = self.scaler.transform([anomaly_features])
        X_risk = np.array([risk_features])
        
        # Anomaly detection
        anomaly_pred = self.anomaly_model.predict(X_anomaly)[0]
        anomaly_score = self.anomaly_model.score_samples(X_anomaly)[0]
        is_anomaly = (anomaly_pred == -1)
        
        # Normalize anomaly score to 0-1 range
        anomaly_score_norm = 1 / (1 + np.exp(anomaly_score))  # Sigmoid
        
        # Risk scoring
        risk_pred = self.risk_model.predict(X_risk)[0]
        risk_proba = self.risk_model.predict_proba(X_risk)[0]
        risk_score = risk_proba[1] * 100  # Convert to 0-100 scale
        
        # Determine risk category
        if risk_score >= 80:
            risk_category = 'critical'
        elif risk_score >= 60:
            risk_category = 'high'
        elif risk_score >= 40:
            risk_category = 'medium'
        else:
            risk_category = 'low'
        
        # Get feature importance (top contributing features)
        feature_importance = self.risk_model.feature_importances_
        feature_names = [
            'total_vulnerabilities', 'critical_count', 'high_count',
            'vuln_per_package', 'critical_ratio', 'high_ratio',
            'avg_cvss_score', 'max_cvss_score', 'exploitable_count',
            'avg_epss_score', 'high_epss_count', 'vuln_growth_rate'
        ]
        
        top_features = sorted(
            zip(feature_names, feature_importance, risk_features),
            key=lambda x: x[1] * abs(x[2]),  # Importance * value
            reverse=True
        )[:5]
        
        top_contributing = {
            feat: {'importance': float(imp), 'value': float(val)}
            for feat, imp, val in top_features
        }
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            features, is_anomaly, risk_score, risk_category
        )
        
        # Prepare prediction result
        prediction = {
            'scan_id': scan_id,
            'is_anomaly': is_anomaly,
            'anomaly_score': float(anomaly_score_norm),
            'risk_score': float(risk_score),
            'risk_category': risk_category,
            'confidence_score': float(max(risk_proba)),
            'top_contributing_features': top_contributing,
            'recommendations': recommendations,
            'model_version': 'v1.0'
        }
        
        # Store prediction in database
        self._store_prediction(prediction)
        
        # Generate alerts if needed
        self._generate_alerts(scan_id, prediction, features)
        
        return prediction
    
    def _get_features(self, scan_id: str) -> dict:
        """Get features for a scan from database"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT 
                sr.total_vulnerabilities,
                sr.critical_count,
                sr.high_count,
                mf.vuln_per_package,
                mf.critical_ratio,
                mf.high_ratio,
                mf.medium_ratio,
                mf.low_ratio,
                mf.vuln_growth_rate,
                mf.new_critical_count,
                mf.severity_trend_score,
                mf.unique_packages,
                mf.packages_with_vulns,
                mf.avg_cvss_score,
                mf.max_cvss_score,
                mf.exploitable_count,
                mf.avg_epss_score,
                mf.high_epss_count,
                mf.days_since_last_scan,
                mf.scan_frequency
            FROM ml_features mf
            JOIN scan_results sr ON mf.scan_id = sr.scan_id
            WHERE mf.scan_id = %s
        """, (scan_id,))
        
        row = cursor.fetchone()
        cursor.close()
        
        if not row:
            return {}
        
        return {
            'total_vulnerabilities': row[0] or 0,
            'critical_count': row[1] or 0,
            'high_count': row[2] or 0,
            'vuln_per_package': row[3] or 0,
            'critical_ratio': row[4] or 0,
            'high_ratio': row[5] or 0,
            'medium_ratio': row[6] or 0,
            'low_ratio': row[7] or 0,
            'vuln_growth_rate': row[8] or 0,
            'new_critical_count': row[9] or 0,
            'severity_trend_score': row[10] or 0,
            'unique_packages': row[11] or 0,
            'packages_with_vulns': row[12] or 0,
            'avg_cvss_score': row[13] or 0,
            'max_cvss_score': row[14] or 0,
            'exploitable_count': row[15] or 0,
            'avg_epss_score': row[16] or 0,
            'high_epss_count': row[17] or 0,
            'days_since_last_scan': row[18] or 0,
            'scan_frequency': row[19] or 0
        }
    
    def _generate_recommendations(
        self, features: dict, is_anomaly: bool, risk_score: float, risk_category: str
    ) -> list:
        """Generate actionable recommendations"""
        recommendations = []
        
        if is_anomaly:
            recommendations.append(
                "⚠️ ANOMALY DETECTED: This scan shows unusual vulnerability patterns. "
                "Investigate for potential supply chain attacks or configuration issues."
            )
        
        if risk_score >= 80:
            recommendations.append(
                "🔴 CRITICAL RISK: Immediate action required. "
                "Review and remediate critical vulnerabilities within 24 hours."
            )
        
        if features['critical_count'] > 0:
            recommendations.append(
                f"Found {features['critical_count']} critical vulnerabilities. "
                "Prioritize patching these packages immediately."
            )
        
        if features['exploitable_count'] > 0:
            recommendations.append(
                f"⚡ {features['exploitable_count']} vulnerabilities have known exploits. "
                "These are actively being exploited in the wild."
            )
        
        if features['vuln_growth_rate'] > 0.5:
            recommendations.append(
                f"📈 Vulnerability count increased by {features['vuln_growth_rate']:.0%}. "
                "Review recent changes and dependencies."
            )
        
        if features['avg_epss_score'] > 0.3:
            recommendations.append(
                "High EPSS scores indicate elevated exploitation probability. "
                "Prioritize remediation based on EPSS rankings."
            )
        
        if not recommendations:
            recommendations.append(
                "✅ No critical issues detected. Continue monitoring and maintain regular scans."
            )
        
        return recommendations
    
    def _store_prediction(self, prediction: dict):
        """Store prediction in database"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT INTO ml_predictions (
                scan_id, model_version, is_anomaly, anomaly_score,
                risk_score, risk_category, confidence_score,
                top_contributing_features, recommendations
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            prediction['scan_id'],
            prediction['model_version'],
            prediction['is_anomaly'],
            prediction['anomaly_score'],
            prediction['risk_score'],
            prediction['risk_category'],
            prediction['confidence_score'],
            psycopg2.extras.Json(prediction['top_contributing_features']),
            prediction['recommendations']
        ))
        
        self.conn.commit()
        cursor.close()
        logger.info(f"Stored prediction for scan {prediction['scan_id']}")
    
    def _generate_alerts(self, scan_id: str, prediction: dict, features: dict):
        """Generate security alerts based on predictions"""
        cursor = self.conn.cursor()
        
        alerts = []
        
        # Anomaly alert
        if prediction['is_anomaly']:
            alerts.append({
                'type': 'anomaly',
                'severity': 'high',
                'title': 'Anomalous Vulnerability Pattern Detected',
                'description': (
                    f"The scan shows unusual characteristics with an anomaly score of "
                    f"{prediction['anomaly_score']:.2f}. This may indicate supply chain "
                    f"attacks, malicious dependencies, or configuration issues."
                )
            })
        
        # High risk alert
        if prediction['risk_score'] >= 80:
            alerts.append({
                'type': 'high_risk',
                'severity': 'critical',
                'title': 'Critical Risk Score Detected',
                'description': (
                    f"Risk score of {prediction['risk_score']:.0f}/100 requires immediate "
                    f"attention. {features['critical_count']} critical and "
                    f"{features['high_count']} high severity vulnerabilities found."
                )
            })
        
        # Exploit available alert
        if features['exploitable_count'] > 0:
            alerts.append({
                'type': 'exploit_available',
                'severity': 'high',
                'title': f'{features["exploitable_count"]} Exploitable Vulnerabilities Found',
                'description': (
                    f"Found {features['exploitable_count']} vulnerabilities with known "
                    f"exploits that are actively being used in the wild."
                )
            })
        
        # Store alerts
        for alert in alerts:
            cursor.execute("""
                INSERT INTO security_alerts (
                    scan_id, alert_type, severity, title, description,
                    recommended_actions
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                scan_id,
                alert['type'],
                alert['severity'],
                alert['title'],
                alert['description'],
                prediction['recommendations']
            ))
        
        self.conn.commit()
        cursor.close()
        
        if alerts:
            logger.info(f"Generated {len(alerts)} alerts for scan {scan_id}")
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


def main():
    """Test prediction on latest scan"""
    import sys
    
    db_config = {
        'host': os.getenv('DB_HOST', 'postgres'),
        'port': int(os.getenv('DB_PORT', '5432')),
        'database': os.getenv('DB_NAME', 'security_db'),
        'user': os.getenv('DB_USER', 'security_user'),
        'password': os.getenv('DB_PASSWORD', 'security_pass')
    }
    
    predictor = SecurityPredictor(db_config)
    predictor.connect_db()
    
    try:
        # Get scan_id from arguments or use latest
        if len(sys.argv) > 1:
            scan_id = sys.argv[1]
        else:
            cursor = predictor.conn.cursor()
            cursor.execute("SELECT scan_id FROM scan_results ORDER BY scan_timestamp DESC LIMIT 1")
            row = cursor.fetchone()
            cursor.close()
            
            if not row:
                logger.error("No scans found in database")
                return
            
            scan_id = row[0]
        
        logger.info(f"Making prediction for scan: {scan_id}")
        prediction = predictor.predict_for_scan(scan_id)
        
        # Print results
        print("\n" + "="*60)
        print("PREDICTION RESULTS")
        print("="*60)
        print(f"Scan ID: {prediction['scan_id']}")
        print(f"Is Anomaly: {prediction['is_anomaly']}")
        print(f"Anomaly Score: {prediction['anomaly_score']:.4f}")
        print(f"Risk Score: {prediction['risk_score']:.2f}/100")
        print(f"Risk Category: {prediction['risk_category'].upper()}")
        print(f"Confidence: {prediction['confidence_score']:.4f}")
        print(f"\nTop Contributing Features:")
        for feat, data in prediction['top_contributing_features'].items():
            print(f"  {feat}: {data['value']:.2f} (importance: {data['importance']:.4f})")
        print(f"\nRecommendations:")
        for i, rec in enumerate(prediction['recommendations'], 1):
            print(f"  {i}. {rec}")
        print("="*60)
        
    finally:
        predictor.close()


if __name__ == "__main__":
    main()