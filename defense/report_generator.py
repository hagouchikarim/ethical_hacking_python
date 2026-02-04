"""
SOC Audit Report Generator
Creates comprehensive PDF reports for Blue Team security operations
"""

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import io


class SOCReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()
    
    def _create_custom_styles(self):
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#16213e'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#007bff'),
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold'
        ))
        
        # Body
        self.styles.add(ParagraphStyle(
            name='BodyText',
            parent=self.styles['Normal'],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#333333')
        ))
        
        # Alert text
        self.styles.add(ParagraphStyle(
            name='AlertText',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor('#dc3545'),
            fontName='Helvetica-Bold'
        ))
    
    def generate_report(self, dashboard_data, alerts, logs, firewall_rules, blocked_ips, snort_stats=None):
        """Generate comprehensive SOC audit report"""
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        story = []
        
        # Title page
        story.extend(self._build_title_page(dashboard_data))
        
        # Executive summary
        story.extend(self._build_executive_summary(dashboard_data, alerts, snort_stats))
        
        # Snort detections
        if snort_stats and snort_stats.get('total_alerts', 0) > 0:
            story.append(PageBreak())
            story.extend(self._build_snort_section(alerts, snort_stats))
        
        # IDS alerts
        story.append(PageBreak())
        story.extend(self._build_ids_section(alerts))
        
        # Firewall actions
        story.extend(self._build_firewall_section(firewall_rules, blocked_ips))
        
        # Prevention recommendations
        story.append(PageBreak())
        story.extend(self._build_prevention_recommendations(alerts))
        
        # System logs summary
        story.extend(self._build_logs_summary(logs))
        
        # Build PDF
        doc.build(story)
        
        buffer.seek(0)
        return buffer
    
    def _build_title_page(self, dashboard_data):
        """Create title page"""
        elements = []
        
        elements.append(Spacer(1, 1.5*inch))
        
        title = Paragraph("SOC Audit Report", self.styles['CustomTitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.3*inch))
        
        subtitle = Paragraph(
            f"Security Operations Center<br/>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            self.styles['BodyText']
        )
        subtitle.alignment = TA_CENTER
        elements.append(subtitle)
        
        elements.append(Spacer(1, 0.5*inch))
        
        # Summary box
        status_color = colors.HexColor('#28a745') if dashboard_data.get('security_score', 100) > 70 else colors.HexColor('#dc3545')
        
        summary_data = [
            ['Security Score', str(dashboard_data.get('security_score', 100))],
            ['System Status', dashboard_data.get('system_status', 'operational').upper()],
            ['Active Threats', str(dashboard_data.get('active_threats', 0))],
            ['Total Alerts', str(dashboard_data.get('total_alerts', 0))],
            ['Snort Detections', str(dashboard_data.get('snort_alerts', 0))],
            ['Blocked IPs', str(dashboard_data.get('blocked_attacks', 0))]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#495057')),
            ('TEXTCOLOR', (1, 0), (1, -1), status_color),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12)
        ]))
        
        elements.append(summary_table)
        elements.append(PageBreak())
        
        return elements
    
    def _build_executive_summary(self, dashboard_data, alerts, snort_stats):
        """Executive summary section"""
        elements = []
        
        elements.append(Paragraph("1. Executive Summary", self.styles['SectionHeader']))
        
        snort_alerts = [a for a in alerts if a.get('source') == 'snort']
        ids_alerts = [a for a in alerts if a.get('source') == 'ids']
        
        critical_count = len([a for a in alerts if a.get('severity') == 'Critical'])
        high_count = len([a for a in alerts if a.get('severity') == 'High'])
        
        summary_text = f"""
        This report provides a comprehensive overview of security operations during the monitoring period.
        The security operations center detected {len(alerts)} total security events, including {len(snort_alerts)} 
        Snort IDS detections and {len(ids_alerts)} pattern-based IDS alerts.
        <br/><br/>
        <b>Critical Findings:</b> {critical_count} critical and {high_count} high-severity threats were identified.
        All threats have been logged and correlated with attack patterns for further analysis.
        <br/><br/>
        <b>Response Actions:</b> {dashboard_data.get('blocked_attacks', 0)} IP addresses were blocked at the 
        firewall level to prevent future attacks from the same sources.
        """
        
        elements.append(Paragraph(summary_text, self.styles['BodyText']))
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _build_snort_section(self, alerts, snort_stats):
        """Snort detection details"""
        elements = []
        
        elements.append(Paragraph("2. Snort IDS Detections", self.styles['SectionHeader']))
        
        snort_alerts = [a for a in alerts if a.get('source') == 'snort']
        
        if not snort_alerts:
            elements.append(Paragraph("No Snort detections during this period.", self.styles['BodyText']))
            return elements
        
        # Snort stats
        stats_text = f"""
        <b>Total Snort Alerts:</b> {len(snort_alerts)}<br/>
        <b>Detection Rate:</b> Real-time network traffic analysis<br/>
        <b>Alert File:</b> /var/log/snort/alert_fast.txt
        """
        elements.append(Paragraph(stats_text, self.styles['BodyText']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Snort alerts table
        table_data = [['Time', 'Rule', 'Source IP', 'Dest IP', 'Severity']]
        
        for alert in snort_alerts[:20]:  # Limit to 20 most recent
            table_data.append([
                self._format_timestamp(alert.get('timestamp')),
                alert.get('rule_name', 'Unknown')[:30],
                alert.get('source_ip', 'N/A'),
                alert.get('dest_ip', 'N/A'),
                alert.get('severity', 'Medium')
            ])
        
        snort_table = Table(table_data, colWidths=[1.2*inch, 2.2*inch, 1.3*inch, 1.3*inch, 0.8*inch])
        snort_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#007bff')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
        ]))
        
        elements.append(snort_table)
        elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _build_ids_section(self, alerts):
        """IDS alerts section"""
        elements = []
        
        elements.append(Paragraph("3. Pattern-Based IDS Alerts", self.styles['SectionHeader']))
        
        ids_alerts = [a for a in alerts if a.get('source') == 'ids']
        
        if not ids_alerts:
            elements.append(Paragraph("No IDS pattern matches during this period.", self.styles['BodyText']))
            return elements
        
        # IDS table
        table_data = [['Time', 'Rule Name', 'Description', 'Severity']]
        
        for alert in ids_alerts[:15]:
            table_data.append([
                self._format_timestamp(alert.get('timestamp')),
                alert.get('rule_name', 'Unknown')[:25],
                (alert.get('description') or '')[:40],
                alert.get('severity', 'Medium')
            ])
        
        ids_table = Table(table_data, colWidths=[1.2*inch, 2*inch, 2.5*inch, 1*inch])
        ids_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ffc107')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#333333')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fffbf0')])
        ]))
        
        elements.append(ids_table)
        elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _build_firewall_section(self, firewall_rules, blocked_ips):
        """Firewall actions section"""
        elements = []
        
        elements.append(Paragraph("4. Firewall Actions", self.styles['SectionHeader']))
        
        # Blocked IPs
        if blocked_ips:
            elements.append(Paragraph(f"<b>Blocked IP Addresses ({len(blocked_ips)}):</b>", self.styles['BodyText']))
            elements.append(Spacer(1, 0.1*inch))
            
            blocked_data = [['IP Address', 'Timestamp', 'Reason']]
            for entry in blocked_ips[:15]:
                blocked_data.append([
                    entry.get('ip', 'N/A'),
                    self._format_timestamp(entry.get('timestamp')),
                    entry.get('reason', 'Security threat')
                ])
            
            blocked_table = Table(blocked_data, colWidths=[2*inch, 2*inch, 2.5*inch])
            blocked_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dc3545')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8d7da')])
            ]))
            
            elements.append(blocked_table)
        else:
            elements.append(Paragraph("No IP addresses have been blocked during this period.", self.styles['BodyText']))
        
        elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _build_prevention_recommendations(self, alerts):
        """Prevention and mitigation recommendations"""
        elements = []
        
        elements.append(Paragraph("5. Prevention Recommendations", self.styles['SectionHeader']))
        
        # Categorize alerts by attack type
        attack_types = {}
        for alert in alerts:
            attack_type = alert.get('attack_type', 'unknown')
            if attack_type not in attack_types:
                attack_types[attack_type] = []
            attack_types[attack_type].append(alert)
        
        # Recommendations per attack type
        recommendations = {
            'sql_injection': {
                'title': 'SQL Injection',
                'blocked_ips': [],
                'recommendations': [
                    'Implement parameterized queries in all database interactions',
                    'Deploy Web Application Firewall (WAF) with SQL injection rules',
                    'Enable strict input validation on all web forms',
                    'Apply principle of least privilege to database accounts',
                    'Regular security audits of application code'
                ]
            },
            'brute_force': {
                'title': 'Brute Force Attacks',
                'blocked_ips': [],
                'recommendations': [
                    'Implement account lockout policies after N failed attempts',
                    'Deploy multi-factor authentication (MFA)',
                    'Enable rate limiting on authentication endpoints',
                    'Use CAPTCHA for repeated login failures',
                    'Monitor and alert on unusual authentication patterns'
                ]
            },
            'port_scanner': {
                'title': 'Port Scanning',
                'blocked_ips': [],
                'recommendations': [
                    'Enable stealth mode on firewall to hide open ports',
                    'Implement port knocking for sensitive services',
                    'Close unnecessary ports and services',
                    'Deploy IPS rules to automatically block port scanners',
                    'Monitor and log all port scan attempts'
                ]
            },
            'ddos': {
                'title': 'DDoS Attacks',
                'blocked_ips': [],
                'recommendations': [
                    'Deploy DDoS mitigation service or CDN',
                    'Implement rate limiting at application layer',
                    'Configure traffic filtering rules',
                    'Enable SYN flood protection',
                    'Maintain scalable infrastructure for traffic absorption'
                ]
            }
        }
        
        # Collect blocked IPs per attack type
        for attack_type, type_alerts in attack_types.items():
            if attack_type in recommendations:
                blocked = set([a.get('source_ip') for a in type_alerts if a.get('source_ip') and a.get('blocked')])
                recommendations[attack_type]['blocked_ips'] = list(blocked)
        
        # Generate recommendation sections
        for attack_type, rec in recommendations.items():
            if attack_type in attack_types:
                elements.append(Paragraph(f"<b>{rec['title']}</b>", self.styles['BodyText']))
                
                if rec['blocked_ips']:
                    elements.append(Paragraph(
                        f"Blocked {len(rec['blocked_ips'])} source IP(s): {', '.join(rec['blocked_ips'][:5])}",
                        self.styles['AlertText']
                    ))
                
                elements.append(Spacer(1, 0.1*inch))
                
                for i, recommendation in enumerate(rec['recommendations'], 1):
                    elements.append(Paragraph(f"{i}. {recommendation}", self.styles['BodyText']))
                
                elements.append(Spacer(1, 0.15*inch))
        
        return elements
    
    def _build_logs_summary(self, logs):
        """System logs summary"""
        elements = []
        
        elements.append(Paragraph("6. System Logs Summary", self.styles['SectionHeader']))
        
        if not logs:
            elements.append(Paragraph("No system logs available.", self.styles['BodyText']))
            return elements
        
        # Log statistics
        attack_logs = [l for l in logs if l.get('type') == 'attack']
        system_logs = [l for l in logs if l.get('type') == 'system']
        
        stats_text = f"""
        <b>Total Log Entries:</b> {len(logs)}<br/>
        <b>Attack Logs:</b> {len(attack_logs)}<br/>
        <b>System Logs:</b> {len(system_logs)}
        """
        
        elements.append(Paragraph(stats_text, self.styles['BodyText']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Recent critical logs
        critical_logs = [l for l in logs if 'error' in l.get('message', '').lower() or 'critical' in l.get('message', '').lower()]
        
        if critical_logs:
            elements.append(Paragraph("<b>Recent Critical Events:</b>", self.styles['BodyText']))
            elements.append(Spacer(1, 0.1*inch))
            
            for log in critical_logs[:5]:
                elements.append(Paragraph(
                    f"{self._format_timestamp(log.get('timestamp'))} - {log.get('message', 'No message')[:80]}",
                    self.styles['BodyText']
                ))
        
        return elements
    
    def _format_timestamp(self, timestamp):
        """Format timestamp for display"""
        if not timestamp:
            return 'N/A'
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime('%H:%M:%S')
        except:
            return str(timestamp)[:19]


# Helper function for Flask route
def generate_soc_report(dashboard_data, alerts, logs, firewall_rules, blocked_ips, snort_stats=None):
    """Generate and return PDF report"""
    generator = SOCReportGenerator()
    return generator.generate_report(dashboard_data, alerts, logs, firewall_rules, blocked_ips, snort_stats)