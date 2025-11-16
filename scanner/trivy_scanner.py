#!/usr/bin/env python3
"""
Enhanced Trivy Scanner with Database Integration
Scans container images and stores results in PostgreSQL
"""

import json
import subprocess
import sys
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional
import psycopg2
from psycopg2.extras import Json
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TrivyScanner:
    """Enhanced Trivy vulnerability scanner with database integration"""
    
    def __init__(self, db_config: Dict[str, str]):
        """
        Initialize scanner with database configuration
        
        Args:
            db_config: Database connection parameters
        """
        self.db_config = db_config
        self.conn = None
        self.scan_id = None
        
    def connect_db(self):
        """Establish database connection"""
        try:
            self.conn = psycopg2.connect(
                host=self.db_config['host'],
                port=self.db_config['port'],
                database=self.db_config['database'],
                user=self.db_config['user'],
                password=self.db_config['password']
            )
            logger.info("Database connection established")
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise
    
    def scan_image(self, image_name: str, image_tag: str = "latest") -> Dict:
        """
        Scan container image with Trivy
        
        Args:
            image_name: Name of the container image
            image_tag: Image tag (default: latest)
            
        Returns:
            Dictionary containing scan results
        """
        full_image = f"{image_name}:{image_tag}"
        logger.info(f"Starting scan for image: {full_image}")
        
        start_time = time.time()
        self.scan_id = str(uuid.uuid4())
        
        try:
            # Run Trivy scan
            cmd = [
                "trivy", "image",
                "--format", "json",
                "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
                "--timeout", "10m",
                full_image
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            scan_duration = time.time() - start_time
            
            if result.returncode != 0 and result.returncode != 1:
                logger.error(f"Trivy scan failed: {result.stderr}")
                return self._create_error_result(image_name, image_tag, result.stderr)
            
            # Parse results
            scan_data = json.loads(result.stdout) if result.stdout else {}
            
            # Process and store results
            processed_results = self._process_scan_results(
                scan_data, image_name, image_tag, scan_duration
            )
            
            logger.info(f"Scan completed in {scan_duration:.2f} seconds")
            logger.info(f"Found {processed_results['total_vulnerabilities']} vulnerabilities")
            
            return processed_results
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            return self._create_error_result(image_name, image_tag, str(e))
    
    def _process_scan_results(
        self, 
        scan_data: Dict, 
        image_name: str, 
        image_tag: str,
        scan_duration: float
    ) -> Dict:
        """Process and store scan results"""
        
        vulnerabilities = []
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'UNKNOWN': 0
        }
        
        # Extract vulnerabilities from scan data
        results = scan_data.get('Results', [])
        for result in results:
            vulns = result.get('Vulnerabilities', [])
            for vuln in vulns:
                severity = vuln.get('Severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                vulnerabilities.append({
                    'cve_id': vuln.get('VulnerabilityID', 'N/A'),
                    'package_name': vuln.get('PkgName', 'N/A'),
                    'installed_version': vuln.get('InstalledVersion', 'N/A'),
                    'fixed_version': vuln.get('FixedVersion', 'N/A'),
                    'severity': severity,
                    'cvss_score': self._extract_cvss_score(vuln),
                    'description': vuln.get('Description', '')[:1000],
                    'references': vuln.get('References', []),
                    'published_date': vuln.get('PublishedDate'),
                    'last_modified_date': vuln.get('LastModifiedDate')
                })
        
        # Store in database
        if self.conn:
            self._store_results(
                image_name, image_tag, vulnerabilities, 
                severity_counts, scan_duration
            )
        
        return {
            'scan_id': self.scan_id,
            'image_name': image_name,
            'image_tag': image_tag,
            'total_vulnerabilities': len(vulnerabilities),
            'severity_counts': severity_counts,
            'vulnerabilities': vulnerabilities,
            'scan_duration': scan_duration,
            'scan_timestamp': datetime.now().isoformat()
        }
    
    def _extract_cvss_score(self, vuln: Dict) -> Optional[float]:
        """Extract CVSS score from vulnerability data"""
        cvss = vuln.get('CVSS', {})
        if isinstance(cvss, dict):
            # Try different CVSS versions
            for version in ['nvd', 'redhat', 'ghsa']:
                if version in cvss:
                    v3_score = cvss[version].get('V3Score')
                    if v3_score:
                        return float(v3_score)
        return None
    
    def _store_results(
        self,
        image_name: str,
        image_tag: str,
        vulnerabilities: List[Dict],
        severity_counts: Dict,
        scan_duration: float
    ):
        """Store scan results in database"""
        try:
            cursor = self.conn.cursor()
            
            # Insert scan result
            cursor.execute("""
                INSERT INTO scan_results (
                    scan_id, image_name, image_tag, total_vulnerabilities,
                    critical_count, high_count, medium_count, low_count, 
                    unknown_count, scan_duration_seconds
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                self.scan_id, image_name, image_tag, len(vulnerabilities),
                severity_counts.get('CRITICAL', 0),
                severity_counts.get('HIGH', 0),
                severity_counts.get('MEDIUM', 0),
                severity_counts.get('LOW', 0),
                severity_counts.get('UNKNOWN', 0),
                scan_duration
            ))
            
            # Insert vulnerabilities
            for vuln in vulnerabilities:
                cursor.execute("""
                    INSERT INTO vulnerabilities (
                        scan_id, cve_id, package_name, installed_version,
                        fixed_version, severity, cvss_score, description,
                        references, published_date, last_modified_date
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    self.scan_id,
                    vuln['cve_id'],
                    vuln['package_name'],
                    vuln['installed_version'],
                    vuln['fixed_version'],
                    vuln['severity'],
                    vuln['cvss_score'],
                    vuln['description'],
                    vuln['references'],
                    vuln['published_date'],
                    vuln['last_modified_date']
                ))
            
            self.conn.commit()
            logger.info(f"Stored {len(vulnerabilities)} vulnerabilities in database")
            
        except Exception as e:
            logger.error(f"Database storage error: {e}")
            self.conn.rollback()
            raise
        finally:
            cursor.close()
    
    def _create_error_result(self, image_name: str, image_tag: str, error: str) -> Dict:
        """Create error result structure"""
        return {
            'scan_id': str(uuid.uuid4()),
            'image_name': image_name,
            'image_tag': image_tag,
            'total_vulnerabilities': 0,
            'severity_counts': {},
            'vulnerabilities': [],
            'scan_duration': 0,
            'error': error,
            'scan_timestamp': datetime.now().isoformat()
        }
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")


def main():
    """Main execution function"""
    import os
    
    # Database configuration from environment
    db_config = {
        'host': os.getenv('DB_HOST', 'postgres'),
        'port': os.getenv('DB_PORT', '5432'),
        'database': os.getenv('DB_NAME', 'security_db'),
        'user': os.getenv('DB_USER', 'security_user'),
        'password': os.getenv('DB_PASSWORD', 'security_pass')
    }
    
    if len(sys.argv) < 2:
        print("Usage: python trivy_scanner.py <image_name> [tag]")
        sys.exit(1)
    
    image_name = sys.argv[1]
    image_tag = sys.argv[2] if len(sys.argv) > 2 else "latest"
    
    scanner = TrivyScanner(db_config)
    
    try:
        scanner.connect_db()
        results = scanner.scan_image(image_name, image_tag)
        
        # Print summary
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Image: {results['image_name']}:{results['image_tag']}")
        print(f"Scan ID: {results['scan_id']}")
        print(f"Total Vulnerabilities: {results['total_vulnerabilities']}")
        print(f"\nSeverity Breakdown:")
        for severity, count in results['severity_counts'].items():
            print(f"  {severity}: {count}")
        print(f"\nScan Duration: {results['scan_duration']:.2f} seconds")
        print("="*60)
        
        # Save detailed results
        output_file = f"scan_results_{results['scan_id']}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nDetailed results saved to: {output_file}")
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)
    finally:
        scanner.close()


if __name__ == "__main__":
    main()