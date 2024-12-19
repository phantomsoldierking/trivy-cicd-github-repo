import json
import boto3
import datetime
import os

# import Security Hub and STS boto3 clients
securityhub = boto3.client('securityhub')
sts = boto3.client('sts')

# retrieve account ID from STS GetCallerID
getAccount = sts.get_caller_identity()
awsAccount = str(getAccount['Account'])

# retrieve environment variables from CodeBuild
awsRegion = os.environ['AWS_REGION']
codebuildBuildArn = os.environ['CODEBUILD_BUILD_ARN']
containerName = os.environ['docker_img_name']
containerTag = os.environ['docker_tag']

# open Trivy vuln report & parse out vulnerability info
with open('results.json') as json_file:
    data = json.load(json_file)

    for result in data:
            # Navigate through the updated structure for vulnerabilities
            vulnerabilities = result.get('Vulnerabilities', [])

            if not vulnerabilities:
                print(f"No vulnerabilities found for {result.get('Target', 'Unknown Target')}.")
            else:
                for vuln in vulnerabilities:
                    # Extract relevant information with fallback for missing fields
                    cveId = vuln.get('VulnerabilityID', 'N/A')
                    cveTitle = vuln.get('Title', 'N/A')
                    cveDescription = vuln.get('Description', 'No description available.')
                    cveDescription = (cveDescription[:1021] + '..') if len(cveDescription) > 1021 else cveDescription
                    packageName = vuln.get('PkgName', 'Unknown Package')
                    installedVersion = vuln.get('InstalledVersion', 'N/A')
                    fixedVersion = vuln.get('FixedVersion', 'N/A')
                    trivySeverity = vuln.get('Severity', 'UNKNOWN')
                    references = vuln.get('References', [])
                    cveReference = references[0] if references else 'No reference available.'

                    # Create ISO 8601 timestamp
                    iso8601Time = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()

                    # Map Trivy severity to Security Hub severity levels
                    severity_mapping = {
                        'LOW': 1,
                        'MEDIUM': 4,
                        'HIGH': 7,
                        'CRITICAL': 9
                    }
                    trivyProductSev = severity_mapping.get(trivySeverity.upper(), 1)
                    trivyNormalizedSev = trivyProductSev * 10

                    # Prepare Security Hub finding
                    finding = {
                        'SchemaVersion': '2018-10-08',
                        'Id': f"{containerName}:{containerTag}/{cveId}",
                        'ProductArn': f"arn:aws:securityhub:{awsRegion}:{awsAccount}:product/aquasecurity/aquasecurity",
                        'GeneratorId': codebuildBuildArn,
                        'AwsAccountId': awsAccount,
                        'Types': ['Software and Configuration Checks/Vulnerabilities/CVE'],
                        'CreatedAt': iso8601Time,
                        'UpdatedAt': iso8601Time,
                        'Severity': {
                            'Product': trivyProductSev,
                            'Normalized': trivyNormalizedSev
                        },
                        'Title': f"Trivy found a vulnerability {cveId} in container {containerName}",
                        'Description': cveDescription,
                        'Remediation': {
                            'Recommendation': {
                                'Text': 'More information on this vulnerability is provided in the hyperlink',
                                'Url': cveReference
                            }
                        },
                        'ProductFields': {'Product Name': 'Trivy'},
                        'Resources': [
                            {
                                'Type': 'Container',
                                'Id': f"{containerName}:{containerTag}",
                                'Partition': 'aws',
                                'Region': awsRegion,
                                'Details': {
                                    'Container': {
                                        'ImageName': f"{containerName}:{containerTag}"
                                    },
                                    'Other': {
                                        'CVE ID': cveId,
                                        'CVE Title': cveTitle,
                                        'Installed Package': f"{packageName} {installedVersion}",
                                        'Patched Package': f"{packageName} {fixedVersion}"
                                    }
                                }
                            }
                        ],
                        'RecordState': 'ACTIVE'
                    }

                    # Send finding to Security Hub
                    try:
                        response = securityhub.batch_import_findings(Findings=[finding])
                        print(response)
                    except Exception as e:
                        print(f"Error importing finding for {cveId}: {e}")
                        raise
