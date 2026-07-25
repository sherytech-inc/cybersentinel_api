import logging
import io
import json
from datetime import datetime, timezone
from typing import Dict, Any, List
from supabase import AsyncClient
import csv
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

logger = logging.getLogger(__name__)

class ExportService:
    def __init__(self, db: AsyncClient, analytics_service):
        self._db = db
        self.analytics_service = analytics_service

    async def generate_json(self, time_range: str) -> dict:
        kpis = await self.analytics_service.get_kpis(time_range)
        threat_trends = await self.analytics_service.get_threat_trends(time_range)
        severity = await self.analytics_service.get_severity_distribution(time_range)
        top_attackers = await self.analytics_service.get_top_attackers(time_range)
        threat_types = await self.analytics_service.get_top_threat_types(time_range)
        intel = await self.analytics_service.get_intelligence_overview(time_range)
        response = await self.analytics_service.get_response_analytics(time_range)
        
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "time_range": time_range,
            "kpis": kpis,
            "threat_trends": threat_trends,
            "severity_distribution": severity,
            "top_attackers": top_attackers,
            "top_threat_types": threat_types,
            "intelligence_overview": intel,
            "response_analytics": response
        }

    async def generate_csv(self, data_type: str, time_range: str) -> str:
        cutoff = self.analytics_service._get_time_cutoff(time_range)
        output = io.StringIO()
        writer = csv.writer(output)
        
        if data_type == "alerts":
            query = self._db.table("threat_alerts").select("*").gte("created_at", cutoff).order("created_at", desc=True)
            from app.database.client import db_has_demo_columns
            if db_has_demo_columns(): query = query.neq("is_demo", True)
            res = await query.execute()
            
            if not res.data:
                return "No data found."
            keys = res.data[0].keys()
            writer.writerow(keys)
            for row in res.data:
                writer.writerow([row.get(k) for k in keys])
        elif data_type == "actions":
            query = self._db.table("firewall_actions").select("*").gte("created_at", cutoff).order("created_at", desc=True)
            from app.database.client import db_has_demo_columns
            if db_has_demo_columns(): query = query.neq("is_demo", True)
            res = await query.execute()
            
            if not res.data:
                return "No data found."
            keys = res.data[0].keys()
            writer.writerow(keys)
            for row in res.data:
                writer.writerow([row.get(k) for k in keys])
        else:
            writer.writerow(["Error", "Invalid data type"])
            
        return output.getvalue()

    def _generate_recommendations(self, top_attackers: List[Dict], threat_types: List[Dict]) -> List[str]:
        recs = []
        if top_attackers:
            top_ip = top_attackers[0]['ip']
            recs.append(f"Block recurring highly active IP: {top_ip}")
            countries = set(a['country'] for a in top_attackers if a['country'] != 'Unknown')
            if countries:
                recs.append(f"Monitor outbound traffic to high-risk countries: {', '.join(countries)}")
                
        if threat_types:
            top_type = threat_types[0]['type']
            recs.append(f"Investigate elevated {top_type} activity")
            
        recs.append("Review firewall policies for repeated alerts")
        return recs

    async def generate_pdf_report(self, time_range: str) -> bytes:
        data = await self.generate_json(time_range)
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        title_style = styles['Title']
        heading_style = styles['Heading2']
        normal_style = styles['Normal']
        
        story = []
        
        # Title
        story.append(Paragraph(f"CyberSentinel Executive Security Report", title_style))
        story.append(Paragraph(f"Generated: {data['generated_at']} | Time Range: {time_range}", normal_style))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        kpis = data["kpis"]
        summary_text = (f"During the last {time_range}, CyberSentinel detected {kpis['total_threats']} threats, "
                        f"including {kpis['critical_threats']} critical incidents. "
                        f"The SOC responded to {kpis['response_actions']} events and executed {kpis['recorded_blocks']} block actions.")
        story.append(Paragraph(summary_text, normal_style))
        story.append(Spacer(1, 20))
        
        # Top Attackers Table
        story.append(Paragraph("Top Threat Sources", heading_style))
        table_data = [["IP Address", "Country", "Threats", "Severity"]]
        for a in data["top_attackers"]:
            table_data.append([a["ip"], a["country"], str(a["count"]), a["highest_severity"]])
            
        if len(table_data) > 1:
            t = Table(table_data, colWidths=[150, 100, 80, 100])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.grey),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0,0), (-1,0), 12),
                ('BACKGROUND', (0,1), (-1,-1), colors.beige),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("No significant attackers detected.", normal_style))
            
        story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("Security Recommendations", heading_style))
        recs = self._generate_recommendations(data["top_attackers"], data["top_threat_types"])
        for i, rec in enumerate(recs, 1):
            story.append(Paragraph(f"{i}. {rec}", normal_style))
            
        doc.build(story)
        return buffer.getvalue()
