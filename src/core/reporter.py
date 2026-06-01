import json
import csv
import logging
from typing import List, Dict, Any
from datetime import datetime
import os

from .engine import Vulnerability, Severity


class ReportGenerator:
    def __init__(self, vulnerabilities: List[Vulnerability], scan_info: Dict[str, Any], output_dir: str = "reports"):
        self.vulnerabilities = vulnerabilities
        self.scan_info = scan_info
        self.output_dir = output_dir
        self.logger = logging.getLogger(__name__)
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_all(self) -> Dict[str, str]:
        report_paths = {}
        report_paths['json'] = self.generate_json()
        report_paths['html'] = self.generate_html()
        report_paths['csv'] = self.generate_csv()
        report_paths['markdown'] = self.generate_markdown()
        return report_paths

    def generate_json(self) -> str:
        report = {
            'scan_info': self.scan_info,
            'summary': self._generate_summary(),
            'vulnerabilities': [v.__dict__ for v in self.vulnerabilities],
            'statistics': self._generate_statistics(),
            'generated_at': datetime.utcnow().isoformat()
        }
        filename = os.path.join(self.output_dir, f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        self.logger.info(f"JSON report generated: {filename}")
        return filename

    def generate_html(self) -> str:
        summary = self._generate_summary()
        stats = self._generate_statistics()
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        .content {{
            padding: 40px;
        }}
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .card.critical {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; }}
        .card.high {{ background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }}
        .card.medium {{ background: linear-gradient(135deg, #f6d365 0%, #fda085 100%); }}
        .card.low {{ background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%); }}
        .card h3 {{
            font-size: 2.5em;
            margin-bottom: 5px;
        }}
        .card p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        h2 {{
            margin: 30px 0 20px;
            color: #333;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }}
        .vuln-table th,
        .vuln-table td {{
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        .vuln-table th {{
            background: #667eea;
            color: white;
        }}
        .vuln-table tr:hover {{
            background: #f5f7fa;
        }}
        .severity-badge {{
            padding: 5px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .critical-badge {{ background: #f5576c; color: white; }}
        .high-badge {{ background: #fa709a; color: white; }}
        .medium-badge {{ background: #f6d365; color: #333; }}
        .low-badge {{ background: #a8edea; color: #333; }}
        .info-badge {{ background: #c3cfe2; color: #333; }}
        .code-block {{
            background: #f4f4f4;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 10px 0;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            background: #f5f7fa;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Vulnerability Scan Report</h1>
            <p>Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p>Target: {self.scan_info.get('target_url', 'N/A')}</p>
        </div>
        <div class="content">
            <h2>📊 Summary</h2>
            <div class="summary-cards">
                <div class="card critical">
                    <h3>{summary.get('critical')}</h3>
                    <p>Critical</p>
                </div>
                <div class="card high">
                    <h3>{summary.get('high')}</h3>
                    <p>High</p>
                </div>
                <div class="card medium">
                    <h3>{summary.get('medium')}</h3>
                    <p>Medium</p>
                </div>
                <div class="card low">
                    <h3>{summary.get('low')}</h3>
                    <p>Low</p>
                </div>
                <div class="card">
                    <h3>{summary.get('total')}</h3>
                    <p>Total</p>
                </div>
            </div>
            
            <h2>🔍 Vulnerabilities</h2>
            <table class="vuln-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>URL</th>
                        <th>CVSS</th>
                        <th>CWE</th>
                    </tr>
                </thead>
                <tbody>
"""
        for vuln in self.vulnerabilities:
            badge_class = f"{vuln.severity.value.lower()}-badge"
            html_content += f"""
                    <tr>
                        <td>{vuln.id}</td>
                        <td>{vuln.type.value}</td>
                        <td><span class="severity-badge {badge_class}">{vuln.severity.value}</span></td>
                        <td><a href="{vuln.url}" target="_blank">{vuln.url[:50]}...</a></td>
                        <td>{vuln.cvss_score}</td>
                        <td>{vuln.cwe_id or 'N/A'}</td>
                    </tr>
"""
        html_content += f"""
                </tbody>
            </table>
            
            <h2>📋 Details</h2>
"""
        for vuln in self.vulnerabilities:
            badge_class = f"{vuln.severity.value.lower()}-badge"
            html_content += f"""
            <div style="margin: 20px 0; padding: 20px; background: #f9f9f9; border-radius: 12px;">
                <h3><span class="severity-badge {badge_class}">{vuln.severity.value}</span> {vuln.type.value} - {vuln.id}</h3>
                <p><strong>URL:</strong> {vuln.url}</p>
                <p><strong>Description:</strong> {vuln.description}</p>
                {f'<p><strong>Parameter:</strong> {vuln.parameter}</p>' if vuln.parameter else ''}
                {f'<p><strong>Payload:</strong><div class="code-block">{vuln.payload}</div></p>' if vuln.payload else ''}
                <p><strong>Remediation:</strong> {vuln.remediation}</p>
            </div>
"""
        html_content += """
        </div>
        <div class="footer">
            <p>🔒 This report is confidential. Use only for authorized security purposes.</p>
        </div>
    </div>
</body>
</html>
"""
        filename = os.path.join(self.output_dir, f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.html")
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        self.logger.info(f"HTML report generated: {filename}")
        return filename

    def generate_csv(self) -> str:
        filename = os.path.join(self.output_dir, f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv")
        fieldnames = ['id', 'type', 'severity', 'url', 'parameter', 'payload', 'cvss_score', 'cwe_id']
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for vuln in self.vulnerabilities:
                writer.writerow({
                    'id': vuln.id,
                    'type': vuln.type.value,
                    'severity': vuln.severity.value,
                    'url': vuln.url,
                    'parameter': vuln.parameter,
                    'payload': vuln.payload,
                    'cvss_score': vuln.cvss_score,
                    'cwe_id': vuln.cwe_id
                })
        self.logger.info(f"CSV report generated: {filename}")
        return filename

    def generate_markdown(self) -> str:
        summary = self._generate_summary()
        md_content = f"# Vulnerability Scan Report\n\n"
        md_content += f"**Generated on:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        md_content += f"**Target:** {self.scan_info.get('target_url', 'N/A')}\n\n"
        md_content += "## Summary\n\n"
        md_content += f"- Critical: {summary.get('critical', 0)}\n"
        md_content += f"- High: {summary.get('high', 0)}\n"
        md_content += f"- Medium: {summary.get('medium', 0)}\n"
        md_content += f"- Low: {summary.get('low', 0)}\n"
        md_content += f"- Total: {summary.get('total', 0)}\n\n"
        md_content += "## Vulnerabilities\n\n"
        for vuln in self.vulnerabilities:
            md_content += f"### {vuln.type.value} - {vuln.severity.value}\n\n"
            md_content += f"- **ID:** {vuln.id}\n"
            md_content += f"- **URL:** {vuln.url}\n"
            md_content += f"- **Description:** {vuln.description}\n"
            if vuln.parameter:
                md_content += f"- **Parameter:** {vuln.parameter}\n"
            if vuln.payload:
                md_content += f"- **Payload:** `{vuln.payload}`\n"
            md_content += f"- **Remediation:** {vuln.remediation}\n"
            md_content += f"- **CVSS:** {vuln.cvss_score}\n"
            if vuln.cwe_id:
                md_content += f"- **CWE:** {vuln.cwe_id}\n"
            md_content += "\n---\n\n"
        filename = os.path.join(self.output_dir, f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md")
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(md_content)
        self.logger.info(f"Markdown report generated: {filename}")
        return filename

    def _generate_summary(self) -> Dict[str, int]:
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.severity.value.lower()
            summary[severity] = summary.get(severity, 0) + 1
            summary['total'] += 1
        return summary

    def _generate_statistics(self) -> Dict[str, Any]:
        return {
            'by_type': self._group_by_type(),
            'top_endpoints': self._get_top_endpoints(10)
        }

    def _group_by_type(self) -> Dict[str, int]:
        groups = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.type.value
            groups[vuln_type] = groups.get(vuln_type, 0) + 1
        return groups

    def _get_top_endpoints(self, limit: int = 10) -> List[Dict[str, Any]]:
        endpoint_counts = {}
        for vuln in self.vulnerabilities:
            url = vuln.url
            endpoint_counts[url] = endpoint_counts.get(url, 0) + 1
        sorted_endpoints = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)
        return [{'url': url, 'count': count} for url, count in sorted_endpoints[:limit]]
