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
        """Scan container image with Trivy"""
        full_image = f"{image_name}:{image_tag}"
        logger.info(f"Starting scan for image: {full_image}")
        
        start_time = time.time()
        self.scan_id = str(uuid.uuid4())
        
        try:
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
            
            if result.returncode not in (0, 1):
                logger.error(f"Trivy scan failed: {result.stderr}")
                return self._create_error_result(image_name, image_tag, result.stderr)
            
            scan_data = json.loads(result.stdout) if result.stdout else {}
            
            processed_results = self._process_scan_results(
                scan_data, image_name, image_tag, scan_duration
            )
            
            logger.info(f"Scan completed in {scan_duration:.2f} seconds")
            logger.info(f"Found {processed_results['total_vulnerabilities']} vulnerabilities")
            
            return processed_results
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            return self._create_error_result(image_name, image_tag, str(e))
    
    def _process_scan_results(self, scan_data, image_name, image_tag, scan_duration):
        """Process Trivy results"""
        
        vulnerabilities = []
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'UNKNOWN': 0
        }
        
        results = scan_data.get('Results', [])
        for result in results:
            vulns = result.get('Vulnerabilities', [])
            for vuln in vulns:
                severity = vuln.get('Severity', 'UNKNOWN')
                severity_counts[severity] += 1
                
                vulnerabilities.append({
                    'cve_id': vuln.get('VulnerabilityID', 'N/A'),
                    'package_name': vuln.get('PkgName', 'N/A'),
                    'installed_version': vuln.get('InstalledVersion', 'N/A'),
                    'fixed_version': vuln.get('FixedVersion', 'N/A'),
                    'severity': severity,
                    'cvss_score': self._extract_cvss_score(vuln),
                    'description': vuln.get('Description', '')[:1000],
                    'reference_urls': vuln.get('References', []) or [],
                    'published_date': vuln.get('PublishedDate'),
                    'last_modified_date': vuln.get('LastModifiedDate'),
                    'exploit_available': vuln.get('Exploit', False),
                    'epss_score': vuln.get('EPSS', 0.0)
                })
        
        if self.conn:
            self._store_results(image_name, image_tag, vulnerabilities, severity_counts, scan_duration)
        
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

    def _extract_cvss_score(self, vuln):
        """Extract CVSS score"""
        cvss = vuln.get('CVSS', {})
        if isinstance(cvss, dict):
            for vendor in ['nvd', 'redhat', 'ghsa']:
                if vendor in cvss:
                    v3 = cvss[vendor].get('V3Score')
                    if v3:
                        return float(v3)
        return None
    
    def _store_results(self, image_name, image_tag, vulnerabilities, severity_counts, scan_duration):
        """Store scan + vulnerability details in PostgreSQL"""
        try:
            cursor = self.conn.cursor()
            
            cursor.execute("""
                INSERT INTO scan_results (
                    scan_id, image_name, image_tag, total_vulnerabilities,
                    critical_count, high_count, medium_count, low_count,
                    unknown_count, scan_duration_seconds
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                self.scan_id, image_name, image_tag, len(vulnerabilities),
                severity_counts['CRITICAL'],
                severity_counts['HIGH'],
                severity_counts['MEDIUM'],
                severity_counts['LOW'],
                severity_counts['UNKNOWN'],
                scan_duration
            ))
            
            for vuln in vulnerabilities:
                cursor.execute("""
                    INSERT INTO vulnerabilities (
                        scan_id, cve_id, package_name, installed_version,
                        fixed_version, severity, cvss_score, description,
                        reference_urls, published_date, last_modified_date,
                        exploit_available, epss_score
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    self.scan_id,
                    vuln['cve_id'],
                    vuln['package_name'],
                    vuln['installed_version'],
                    vuln['fixed_version'],
                    vuln['severity'],
                    vuln['cvss_score'],
                    vuln['description'],
                    vuln['reference_urls'],
                    vuln['published_date'],
                    vuln['last_modified_date'],
                    vuln['exploit_available'],
                    vuln['epss_score']
                ))
            
            self.conn.commit()
            logger.info(f"Stored {len(vulnerabilities)} vulnerabilities")
        
        except Exception as e:
            logger.error(f"Database error: {e}")
            self.conn.rollback()
            raise
        finally:
            cursor.close()

    def _create_error_result(self, image_name, image_tag, error):
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
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")


def main():
    import os
    
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

        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Image: {results['image_name']}:{results['image_tag']}")
        print(f"Scan ID: {results['scan_id']}")
        print(f"Total Vulnerabilities: {results['total_vulnerabilities']}")
        print("\nSeverity Breakdown:")
        for sev, count in results['severity_counts'].items():
            print(f"  {sev}: {count}")
        print(f"\nScan Duration: {results['scan_duration']:.2f} seconds")
        print("="*60)

        output_file = f"scan_results_{results['scan_id']}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nSaved: {output_file}")

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)
    finally:
        scanner.close()


if __name__ == "__main__":
    main()
