#!/usr/bin/env python3
"""
Docker Base Image Threat Analysis Tool
Scans all Dockerfiles in a repository and performs security analysis on base images
"""

import os
import re
import json
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Any
import click
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DockerfileThreatAnalyzer:
    def __init__(self, repo_path: str, output_dir: str = "/app/reports"):
        self.repo_path = Path(repo_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.base_images = set()
        self.dockerfiles = []
        
    def find_dockerfiles(self) -> List[Path]:
        """Find all Dockerfiles in the repository"""
        dockerfiles = []
        patterns = ['Dockerfile', 'Dockerfile.*', '*.dockerfile']
        
        for pattern in patterns:
            dockerfiles.extend(self.repo_path.rglob(pattern))
        
        # Filter out hidden directories and common ignore patterns
        filtered_dockerfiles = []
        ignore_patterns = {'.git', 'node_modules', '.venv', '__pycache__', '.pytest_cache'}
        
        for df in dockerfiles:
            if not any(ignore_dir in df.parts for ignore_dir in ignore_patterns):
                filtered_dockerfiles.append(df)
        
        logger.info(f"Found {len(filtered_dockerfiles)} Dockerfiles")
        return filtered_dockerfiles
    
    def extract_base_images(self, dockerfile_path: Path) -> List[str]:
        """Extract base images from a Dockerfile"""
        base_images = []
        
        try:
            with open(dockerfile_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Find FROM statements
            from_pattern = r'^FROM\s+([^\s]+)'
            matches = re.findall(from_pattern, content, re.MULTILINE | re.IGNORECASE)
            
            for match in matches:
                # Skip scratch and build stage references
                if match.lower() not in ['scratch'] and not match.startswith('--'):
                    # Handle AS statements
                    image = match.split(' AS ')[0].strip()
                    if image and not image.startswith('$'):  # Skip build args for now
                        base_images.append(image)
                        
        except Exception as e:
            logger.error(f"Error parsing {dockerfile_path}: {e}")
            
        return base_images
    
    def run_trivy_scan(self, image: str) -> Dict[str, Any]:
        """Run Trivy vulnerability scan on an image"""
        logger.info(f"Running Trivy scan on {image}")
        
        try:
            cmd = [
                'trivy', 'image', 
                '--format', 'json',
                '--severity', 'HIGH,CRITICAL',
                '--no-progress',
                image
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                logger.error(f"Trivy scan failed for {image}: {result.stderr}")
                return {"error": result.stderr}
                
        except subprocess.TimeoutExpired:
            logger.error(f"Trivy scan timed out for {image}")
            return {"error": "Scan timeout"}
        except Exception as e:
            logger.error(f"Error running Trivy scan for {image}: {e}")
            return {"error": str(e)}
    
    def run_grype_scan(self, image: str) -> Dict[str, Any]:
        """Run Grype vulnerability scan on an image"""
        logger.info(f"Running Grype scan on {image}")
        
        try:
            cmd = [
                'grype', 
                '--output', 'json',
                '--only-fixed',
                image
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                logger.error(f"Grype scan failed for {image}: {result.stderr}")
                return {"error": result.stderr}
                
        except subprocess.TimeoutExpired:
            logger.error(f"Grype scan timed out for {image}")
            return {"error": "Scan timeout"}
        except Exception as e:
            logger.error(f"Error running Grype scan for {image}: {e}")
            return {"error": str(e)}
    
    def analyze_image_metadata(self, image: str) -> Dict[str, Any]:
        """Analyze image metadata for security concerns"""
        logger.info(f"Analyzing metadata for {image}")
        
        try:
            # Get image history
            cmd = ['docker', 'history', '--format', 'json', '--no-trunc', image]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            metadata = {
                "image": image,
                "analysis_date": datetime.now().isoformat(),
                "size_analysis": {},
                "layer_analysis": {},
                "security_recommendations": []
            }
            
            if result.returncode == 0:
                # Parse history
                history_lines = result.stdout.strip().split('\n')
                layers = []
                for line in history_lines:
                    try:
                        layer = json.loads(line)
                        layers.append(layer)
                    except:
                        continue
                
                metadata["layer_analysis"] = {
                    "total_layers": len(layers),
                    "layers": layers[:5]  # Top 5 layers only
                }
            
            # Check for common security issues
            security_issues = []
            
            # Check if running as root
            inspect_cmd = ['docker', 'inspect', image]
            inspect_result = subprocess.run(inspect_cmd, capture_output=True, text=True)
            
            if inspect_result.returncode == 0:
                try:
                    inspect_data = json.loads(inspect_result.stdout)[0]
                    config = inspect_data.get('Config', {})
                    
                    # Check user
                    user = config.get('User', '')
                    if not user or user == 'root' or user == '0':
                        security_issues.append("Image runs as root user")
                    
                    # Check exposed ports
                    exposed_ports = config.get('ExposedPorts', {})
                    if exposed_ports:
                        metadata["exposed_ports"] = list(exposed_ports.keys())
                    
                    # Check environment variables for secrets
                    env_vars = config.get('Env', [])
                    for env_var in env_vars:
                        if any(keyword in env_var.upper() for keyword in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN']):
                            security_issues.append(f"Potential secret in environment variable: {env_var.split('=')[0]}")
                    
                except Exception as e:
                    logger.error(f"Error parsing inspect data: {e}")
            
            metadata["security_issues"] = security_issues
            return metadata
            
        except Exception as e:
            logger.error(f"Error analyzing metadata for {image}: {e}")
            return {"error": str(e)}
    
    def generate_report(self, analysis_results: Dict[str, Any]) -> None:
        """Generate comprehensive threat analysis report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"threat_analysis_report_{timestamp}.json"
        
        # Create summary
        summary = {
            "scan_date": datetime.now().isoformat(),
            "repository_path": str(self.repo_path),
            "total_dockerfiles": len(self.dockerfiles),
            "total_base_images": len(self.base_images),
            "high_risk_images": [],
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 0,
            "recommendations": []
        }
        
        # Analyze results for summary
        for image, results in analysis_results.items():
            trivy_results = results.get('trivy', {})
            if 'Results' in trivy_results:
                for result in trivy_results['Results']:
                    vulns = result.get('Vulnerabilities', [])
                    critical_count = sum(1 for v in vulns if v.get('Severity') == 'CRITICAL')
                    high_count = sum(1 for v in vulns if v.get('Severity') == 'HIGH')
                    
                    summary['critical_vulnerabilities'] += critical_count
                    summary['high_vulnerabilities'] += high_count
                    
                    if critical_count > 0 or high_count >= 5:
                        summary['high_risk_images'].append({
                            'image': image,
                            'critical': critical_count,
                            'high': high_count
                        })
        
        # Generate recommendations
        if summary['critical_vulnerabilities'] > 0:
            summary['recommendations'].append("Immediately update images with critical vulnerabilities")
        if summary['high_vulnerabilities'] > 10:
            summary['recommendations'].append("Consider using more recent base image versions")
        
        full_report = {
            "summary": summary,
            "detailed_results": analysis_results
        }
        
        # Save report
        with open(report_file, 'w') as f:
            json.dump(full_report, f, indent=2)
        
        # Generate human-readable report
        self.generate_human_readable_report(full_report, timestamp)
        
        logger.info(f"Reports generated: {report_file}")
    
    def generate_human_readable_report(self, data: Dict[str, Any], timestamp: str) -> None:
        """Generate a human-readable HTML report"""
        html_report = self.output_dir / f"threat_analysis_report_{timestamp}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Docker Base Image Threat Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .summary {{ background: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .critical {{ color: red; font-weight: bold; }}
                .high {{ color: orange; font-weight: bold; }}
                .medium {{ color: yellow; }}
                .low {{ color: green; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .image-section {{ margin: 20px 0; padding: 15px; border: 1px solid #ccc; }}
            </style>
        </head>
        <body>
            <h1>Docker Base Image Threat Analysis Report</h1>
            <div class="summary">
                <h2>Summary</h2>
                <p><strong>Scan Date:</strong> {data['summary']['scan_date']}</p>
                <p><strong>Repository:</strong> {data['summary']['repository_path']}</p>
                <p><strong>Dockerfiles Analyzed:</strong> {data['summary']['total_dockerfiles']}</p>
                <p><strong>Base Images Found:</strong> {data['summary']['total_base_images']}</p>
                <p><strong>Critical Vulnerabilities:</strong> <span class="critical">{data['summary']['critical_vulnerabilities']}</span></p>
                <p><strong>High Vulnerabilities:</strong> <span class="high">{data['summary']['high_vulnerabilities']}</span></p>
            </div>
        """
        
        if data['summary']['high_risk_images']:
            html_content += "<h2>High Risk Images</h2><table><tr><th>Image</th><th>Critical</th><th>High</th></tr>"
            for img in data['summary']['high_risk_images']:
                html_content += f"<tr><td>{img['image']}</td><td class='critical'>{img['critical']}</td><td class='high'>{img['high']}</td></tr>"
            html_content += "</table>"
        
        if data['summary']['recommendations']:
            html_content += "<h2>Recommendations</h2><ul>"
            for rec in data['summary']['recommendations']:
                html_content += f"<li>{rec}</li>"
            html_content += "</ul>"
        
        html_content += "</body></html>"
        
        with open(html_report, 'w') as f:
            f.write(html_content)
    
    def run_analysis(self) -> None:
        """Run the complete threat analysis"""
        logger.info("Starting Docker base image threat analysis")
        
        # Find all Dockerfiles
        self.dockerfiles = self.find_dockerfiles()
        
        if not self.dockerfiles:
            logger.warning("No Dockerfiles found in the repository")
            return
        
        # Extract base images
        dockerfile_images = {}
        for dockerfile in self.dockerfiles:
            images = self.extract_base_images(dockerfile)
            dockerfile_images[str(dockerfile)] = images
            self.base_images.update(images)
        
        logger.info(f"Found {len(self.base_images)} unique base images: {list(self.base_images)}")
        
        # Analyze each base image
        analysis_results = {}
        
        for image in self.base_images:
            logger.info(f"Analyzing image: {image}")
            
            image_analysis = {
                "image": image,
                "dockerfiles": [df for df, imgs in dockerfile_images.items() if image in imgs],
                "trivy": self.run_trivy_scan(image),
                "grype": self.run_grype_scan(image),
                "metadata": self.analyze_image_metadata(image)
            }
            
            analysis_results[image] = image_analysis
        
        # Generate reports
        self.generate_report(analysis_results)
        logger.info("Threat analysis completed")

@click.command()
@click.option('--repo-path', default='/repo', help='Path to the repository to analyze')
@click.option('--output-dir', default='/app/reports', help='Output directory for reports')
def main(repo_path: str, output_dir: str):
    """Run Docker base image threat analysis"""
    analyzer = DockerfileThreatAnalyzer(repo_path, output_dir)
    analyzer.run_analysis()

if __name__ == '__main__':
    main()
