"""Byte-oriented PDF, JSON, and CSV exports for normalized reports."""

import csv
import io
import json
from typing import Iterable

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.schemas.reporting import ReportSummary
from .analytics_service import AnalyticsService


ALERT_CSV_HEADERS = [
    "alert_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "threat_type",
    "severity",
    "score",
    "status",
    "action",
    "analysis_status",
]

ACTION_CSV_HEADERS = [
    "action_id",
    "timestamp",
    "target",
    "action",
    "status",
    "analyst",
    "related_alert",
    "result",
    "platform",
]


class ExportService:
    def __init__(self, analytics_service: AnalyticsService):
        self.analytics_service = analytics_service

    @staticmethod
    def generate_json(summary: ReportSummary) -> bytes:
        return json.dumps(
            summary.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")

    @staticmethod
    def _csv_bytes(headers: list[str], rows: Iterable[dict]) -> bytes:
        output = io.StringIO(newline="")
        writer = csv.DictWriter(
            output,
            fieldnames=headers,
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") or "" for key in headers})
        return output.getvalue().encode("utf-8")

    async def generate_alerts_csv(self) -> tuple[bytes, bool]:
        result = await self.analytics_service.get_report_alerts()
        rows = [
            {
                "alert_id": row.get("alert_id"),
                "timestamp": row.get("created_at"),
                "source_ip": row.get("source_ip"),
                "destination_ip": "",
                "threat_type": row.get("model1_classification"),
                "severity": row.get("severity"),
                "score": row.get("threat_score"),
                "status": row.get("status"),
                "action": row.get("action"),
                "analysis_status": "",
            }
            for row in result.rows
        ]
        return self._csv_bytes(ALERT_CSV_HEADERS, rows), result.available

    async def generate_actions_csv(self) -> tuple[bytes, bool]:
        result = await self.analytics_service.get_report_actions()
        return (
            self._csv_bytes(ACTION_CSV_HEADERS, result.rows),
            result.available,
        )

    @staticmethod
    def generate_pdf_report(summary: ReportSummary) -> bytes:
        buffer = io.BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            title="CyberSentinel Security Report",
            author="CyberSentinel",
        )
        styles = getSampleStyleSheet()
        story = [
            Paragraph("CyberSentinel Security Report", styles["Title"]),
            Paragraph(
                f"Generated: {summary.generated_at.isoformat()}",
                styles["Normal"],
            ),
            Paragraph(
                f"Timeframe: {summary.timeframe.replace('_', ' ').title()} | "
                f"Monitoring: {summary.monitoring_state.title()}",
                styles["Normal"],
            ),
            Paragraph(
                f"Interface: {summary.interface or 'Unavailable'}",
                styles["Normal"],
            ),
            Spacer(1, 16),
            Paragraph("Session Summary", styles["Heading2"]),
        ]
        session = summary.session
        session_rows = [
            ["Captured", str(session.captured)],
            ["Analyzed", str(session.analyzed)],
            ["Pending", str(session.pending)],
            ["Complete", str(session.complete)],
            ["Partial", str(session.partial)],
            ["Failed", str(session.failed)],
            ["Deferred", str(session.deferred)],
            ["Not analyzed", str(session.not_analyzed)],
            ["Analysis completion", f"{session.completion_percentage:.1f}%"],
            [
                "Threat score",
                (
                    f"{session.threat_score:.1f} / 100"
                    if session.threat_score is not None
                    else "N/A"
                ),
            ],
            ["Highest severity", session.highest_severity or "N/A"],
        ]
        story.append(ExportService._styled_table(session_rows))
        story.extend(
            [
                Spacer(1, 16),
                Paragraph("Classification Distribution", styles["Heading2"]),
                ExportService._styled_table(
                    [
                        ["Normal", str(summary.classification_distribution.normal)],
                        [
                            "Suspicious",
                            str(summary.classification_distribution.suspicious),
                        ],
                        [
                            "Malicious",
                            str(summary.classification_distribution.malicious),
                        ],
                        ["Unknown", str(summary.classification_distribution.unknown)],
                    ]
                ),
                Spacer(1, 16),
                Paragraph("Severity Distribution", styles["Heading2"]),
                ExportService._styled_table(
                    [
                        ["Low", str(summary.severity_distribution.low)],
                        ["Medium", str(summary.severity_distribution.medium)],
                        ["High", str(summary.severity_distribution.high)],
                        ["Critical", str(summary.severity_distribution.critical)],
                        ["Unknown", str(summary.severity_distribution.unknown)],
                    ]
                ),
            ]
        )

        story.extend(
            ExportService._list_section(
                "Top Threat Types",
                [
                    f"{item.threat_type}: {item.count}"
                    for item in summary.top_threat_types
                ],
                "No analyzed threat-type evidence is available.",
                styles,
            )
        )
        story.extend(
            ExportService._list_section(
                "Top Attackers",
                [
                    f"{item.source_ip}: {item.count} alert(s), "
                    f"severity {item.highest_severity or 'unknown'}, "
                    f"country {item.country or 'unavailable'}"
                    for item in summary.top_attackers
                ],
                "No attacker evidence is available.",
                styles,
            )
        )
        story.extend(
            ExportService._list_section(
                "Recent Alerts",
                [
                    f"{item.timestamp or 'Unknown time'} — "
                    f"{item.source_ip or 'Unknown source'} — "
                    f"{item.threat_type or 'Unclassified'} — "
                    f"{item.severity or 'Unknown severity'}"
                    for item in summary.recent_alerts
                ],
                "No recent alerts are available.",
                styles,
            )
        )
        story.extend(
            ExportService._list_section(
                "Response Timeline",
                [
                    f"{item.timestamp or 'Unknown time'} — {item.action} — "
                    f"{item.target or 'Unknown target'} — "
                    f"{item.status or 'Unknown status'}"
                    for item in summary.response_timeline
                ],
                "No response actions are available.",
                styles,
            )
        )
        model = summary.model_availability
        story.extend(
            [
                Spacer(1, 16),
                Paragraph("Model Availability", styles["Heading2"]),
                ExportService._styled_table(
                    [
                        ["Model 1 evaluated", str(model.model1_evaluated)],
                        ["Model 2 evaluated", str(model.model2_evaluated)],
                        [
                            "Model 3 available",
                            (
                                str(model.model3_available)
                                if model.model3_available is not None
                                else "Unavailable"
                            ),
                        ],
                        ["Partial analysis", str(model.partial_analysis)],
                        ["Failed analysis", str(model.failed_analysis)],
                    ]
                ),
                Spacer(1, 16),
                Paragraph("Source Availability", styles["Heading2"]),
                ExportService._styled_table(
                    [
                        ["Capture", summary.source_status.capture],
                        ["Alerts", summary.source_status.alerts],
                        ["Actions", summary.source_status.actions],
                        ["Intelligence", summary.source_status.intelligence],
                    ]
                ),
            ]
        )
        if summary.messages:
            story.extend(
                ExportService._list_section(
                    "Notes",
                    summary.messages,
                    "No additional notes.",
                    styles,
                )
            )

        document.build(story)
        return buffer.getvalue()

    @staticmethod
    def _styled_table(rows: list[list[str]]) -> Table:
        table = Table(rows, colWidths=[180, 280], hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8F3F8")),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        return table

    @staticmethod
    def _list_section(
        title: str,
        values: list[str],
        empty_message: str,
        styles,
    ) -> list:
        content = [Spacer(1, 16), Paragraph(title, styles["Heading2"])]
        if not values:
            content.append(Paragraph(empty_message, styles["Normal"]))
            return content
        for value in values:
            content.append(Paragraph(f"• {value}", styles["Normal"]))
        return content
