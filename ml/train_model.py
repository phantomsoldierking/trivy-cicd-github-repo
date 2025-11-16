#!/usr/bin/env python3
"""
ML Model Training for Vulnerability Anomaly Detection
Trains Isolation Forest and Risk Scoring models
"""

import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, roc_auc_score
import mlflow
import mlflow.sklearn
from datetime import datetime
import logging
import psycopg2

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurityMLTrainer:
    """Train ML models for security anomaly detection"""
    
    def __init__(self, db_config: dict, mlflow_uri: str):
        """
        Initialize trainer
        
        Args:
            db_config: Database connection parameters
            mlflow_uri: MLflow tracking URI
        """
        self.db_config = db_config
        self.conn = None
        
        # Setup MLflow
        mlflow.set_tracking_uri(mlflow_uri)
        mlflow.set_experiment("container-security-ml")
        
        self.anomaly_model = None
        self.risk_model = None
        self.scaler = None
        
    def connect_db(self):
        """Establish database connection"""
        self.conn = psycopg2.connect(**self.db_config)
        logger.info("Connected to database")
    
    def load_training_data(self) -> pd.DataFrame:
        """Load feature data from database"""
        query = """
            SELECT 
                mf.scan_id,
                sr.image_name,
                sr.image_tag,
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
            ORDER BY mf.feature_timestamp DESC
        """
        
        df = pd.read_sql_query(query, self.conn)
        logger.info(f"Loaded {len(df)} training samples")
        
        if len(df) < 10:
            logger.warning("Insufficient training data. Generating synthetic samples...")
            df = self._generate_synthetic_data(100)
        
        return df
    
    def _generate_synthetic_data(self, n_samples: int) -> pd.DataFrame:
        """Generate synthetic training data for demonstration"""
        np.random.seed(42)
        
        data = {
            'scan_id': [f"synthetic-{i}" for i in range(n_samples)],
            'image_name': ['test-image'] * n_samples,
            'image_tag': ['latest'] * n_samples,
            'total_vulnerabilities': np.random.poisson(15, n_samples),
            'critical_count': np.random.poisson(2, n_samples),
            'high_count': np.random.poisson(5, n_samples),
            'vuln_per_package': np.random.gamma(2, 2, n_samples),
            'critical_ratio': np.random.beta(2, 8, n_samples),
            'high_ratio': np.random.beta(3, 5, n_samples),
            'medium_ratio': np.random.beta(4, 4, n_samples),
            'low_ratio': np.random.beta(5, 3, n_samples),
            'vuln_growth_rate': np.random.normal(0, 0.3, n_samples),
            'new_critical_count': np.random.poisson(1, n_samples),
            'severity_trend_score': np.random.normal(0, 2, n_samples),
            'unique_packages': np.random.poisson(10, n_samples),
            'packages_with_vulns': np.random.poisson(8, n_samples),
            'avg_cvss_score': np.random.uniform(4, 8, n_samples),
            'max_cvss_score': np.random.uniform(6, 10, n_samples),
            'exploitable_count': np.random.poisson(2, n_samples),
            'avg_epss_score': np.random.beta(2, 8, n_samples),
            'high_epss_count': np.random.poisson(1, n_samples),
            'days_since_last_scan': np.random.poisson(7, n_samples),
            'scan_frequency': np.random.gamma(2, 1, n_samples)
        }
        
        # Add some anomalies (10% of data)
        n_anomalies = int(n_samples * 0.1)
        anomaly_indices = np.random.choice(n_samples, n_anomalies, replace=False)
        
        for idx in anomaly_indices:
            # Make anomalies have extreme values
            data['critical_count'][idx] = np.random.poisson(10)
            data['vuln_growth_rate'][idx] = np.random.uniform(2, 5)
            data['new_critical_count'][idx] = np.random.poisson(5)
            data['avg_cvss_score'][idx] = np.random.uniform(8, 10)
        
        return pd.DataFrame(data)
    
    def train_anomaly_detector(self, df: pd.DataFrame):
        """Train Isolation Forest for anomaly detection"""
        logger.info("Training anomaly detection model...")
        
        # Select features for anomaly detection
        feature_cols = [
            'vuln_per_package', 'critical_ratio', 'high_ratio',
            'vuln_growth_rate', 'new_critical_count', 'severity_trend_score',
            'avg_cvss_score', 'max_cvss_score', 'exploitable_count',
            'avg_epss_score', 'high_epss_count'
        ]
        
        X = df[feature_cols].fillna(0)
        
        # Scale features
        self.scaler = RobustScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        with mlflow.start_run(run_name="anomaly_detector"):
            # Train Isolation Forest
            self.anomaly_model = IsolationForest(
                n_estimators=200,
                contamination=0.1,  # Expect 10% anomalies
                max_samples='auto',
                random_state=42,
                n_jobs=-1
            )
            
            self.anomaly_model.fit(X_scaled)
            
            # Get anomaly scores
            anomaly_scores = self.anomaly_model.score_samples(X_scaled)
            predictions = self.anomaly_model.predict(X_scaled)
            
            # Log parameters
            mlflow.log_param("model_type", "IsolationForest")
            mlflow.log_param("n_estimators", 200)
            mlflow.log_param("contamination", 0.1)
            mlflow.log_param("features", feature_cols)
            
            # Log metrics
            n_anomalies = np.sum(predictions == -1)
            anomaly_rate = n_anomalies / len(predictions)
            mlflow.log_metric("anomaly_rate", anomaly_rate)
            mlflow.log_metric("n_samples", len(X))
            mlflow.log_metric("n_features", len(feature_cols))
            
            # Log model
            mlflow.sklearn.log_model(self.anomaly_model, "anomaly_model")
            mlflow.sklearn.log_model(self.scaler, "scaler")
            
            logger.info(f"Trained on {len(X)} samples")
            logger.info(f"Detected {n_anomalies} anomalies ({anomaly_rate:.2%})")
            
            # Feature importance (approximation using feature variance)
            feature_importance = np.var(X_scaled, axis=0)
            feature_importance = feature_importance / feature_importance.sum()
            
            for feat, imp in zip(feature_cols, feature_importance):
                mlflow.log_metric(f"feature_importance_{feat}", imp)
                logger.info(f"  {feat}: {imp:.4f}")
        
        return self.anomaly_model, self.scaler
    
    def train_risk_scorer(self, df: pd.DataFrame):
        """Train Random Forest for risk scoring"""
        logger.info("Training risk scoring model...")
        
        feature_cols = [
            'total_vulnerabilities', 'critical_count', 'high_count',
            'vuln_per_package', 'critical_ratio', 'high_ratio',
            'avg_cvss_score', 'max_cvss_score', 'exploitable_count',
            'avg_epss_score', 'high_epss_count', 'vuln_growth_rate'
        ]
        
        X = df[feature_cols].fillna(0)
        
        # Create synthetic risk labels based on severity
        # High risk: critical > 3 OR high > 8 OR exploitable > 2
        y = (
            (df['critical_count'] > 3) | 
            (df['high_count'] > 8) | 
            (df['exploitable_count'] > 2)
        ).astype(int)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        with mlflow.start_run(run_name="risk_scorer"):
            # Train Random Forest
            self.risk_model = RandomForestClassifier(
                n_estimators=200,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'
            )
            
            self.risk_model.fit(X_train, y_train)
            
            # Predictions
            y_pred = self.risk_model.predict(X_test)
            y_proba = self.risk_model.predict_proba(X_test)[:, 1]
            
            # Log parameters
            mlflow.log_param("model_type", "RandomForestClassifier")
            mlflow.log_param("n_estimators", 200)
            mlflow.log_param("max_depth", 10)
            
            # Log metrics
            accuracy = np.mean(y_pred == y_test)
            mlflow.log_metric("accuracy", accuracy)
            
            if len(np.unique(y_test)) > 1:
                auc = roc_auc_score(y_test, y_proba)
                mlflow.log_metric("auc_roc", auc)
                logger.info(f"AUC-ROC: {auc:.4f}")
            
            # Cross-validation
            cv_scores = cross_val_score(
                self.risk_model, X_train, y_train, cv=5, scoring='accuracy'
            )
            mlflow.log_metric("cv_accuracy_mean", cv_scores.mean())
            mlflow.log_metric("cv_accuracy_std", cv_scores.std())
            
            # Feature importance
            feature_importance = self.risk_model.feature_importances_
            for feat, imp in zip(feature_cols, feature_importance):
                mlflow.log_metric(f"feature_importance_{feat}", imp)
            
            # Log model
            mlflow.sklearn.log_model(self.risk_model, "risk_model")
            
            logger.info(f"Accuracy: {accuracy:.4f}")
            logger.info(f"CV Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
            logger.info("\nTop 5 Most Important Features:")
            for feat, imp in sorted(
                zip(feature_cols, feature_importance), 
                key=lambda x: x[1], 
                reverse=True
            )[:5]:
                logger.info(f"  {feat}: {imp:.4f}")
        
        return self.risk_model
    
    def save_models(self, output_dir: str = "/models"):
        """Save trained models to disk"""
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save anomaly detector
        if self.anomaly_model:
            anomaly_path = os.path.join(output_dir, f"anomaly_model_{timestamp}.pkl")
            with open(anomaly_path, 'wb') as f:
                pickle.dump(self.anomaly_model, f)
            logger.info(f"Saved anomaly model to {anomaly_path}")
        
        # Save scaler
        if self.scaler:
            scaler_path = os.path.join(output_dir, f"scaler_{timestamp}.pkl")
            with open(scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            logger.info(f"Saved scaler to {scaler_path}")
        
        # Save risk scorer
        if self.risk_model:
            risk_path = os.path.join(output_dir, f"risk_model_{timestamp}.pkl")
            with open(risk_path, 'wb') as f:
                pickle.dump(self.risk_model, f)
            logger.info(f"Saved risk model to {risk_path}")
        
        # Save metadata
        metadata = {
            'timestamp': timestamp,
            'anomaly_model': anomaly_path if self.anomaly_model else None,
            'scaler': scaler_path if self.scaler else None,
            'risk_model': risk_path if self.risk_model else None
        }
        
        metadata_path = os.path.join(output_dir, "latest_models.json")
        import json
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()


def main():
    """Main training pipeline"""
    db_config = {
        'host': os.getenv('DB_HOST', 'postgres'),
        'port': int(os.getenv('DB_PORT', '5432')),
        'database': os.getenv('DB_NAME', 'security_db'),
        'user': os.getenv('DB_USER', 'security_user'),
        'password': os.getenv('DB_PASSWORD', 'security_pass')
    }
    
    mlflow_uri = os.getenv('MLFLOW_TRACKING_URI', 'http://mlflow:5000')
    
    trainer = SecurityMLTrainer(db_config, mlflow_uri)
    
    try:
        trainer.connect_db()
        
        # Load data
        df = trainer.load_training_data()
        
        # Train models
        logger.info("\n" + "="*60)
        logger.info("TRAINING ANOMALY DETECTION MODEL")
        logger.info("="*60)
        trainer.train_anomaly_detector(df)
        
        logger.info("\n" + "="*60)
        logger.info("TRAINING RISK SCORING MODEL")
        logger.info("="*60)
        trainer.train_risk_scorer(df)
        
        # Save models
        trainer.save_models()
        
        logger.info("\n" + "="*60)
        logger.info("TRAINING COMPLETE")
        logger.info("="*60)
        logger.info("Models saved to /models directory")
        logger.info(f"MLflow UI: {mlflow_uri}")
        
    except Exception as e:
        logger.error(f"Training failed: {e}", exc_info=True)
        raise
    finally:
        trainer.close()


if __name__ == "__main__":
    main()