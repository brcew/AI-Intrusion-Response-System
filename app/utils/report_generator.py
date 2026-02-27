"""
Report Generator.
Produces a professional Excel security incident report from session data.
"""

import io
from datetime import datetime
from typing import List, Dict

import pandas as pd


def generate_excel_report(
    results: List[Dict],
    blocked_ips: List[Dict],
    threat_records: List[Dict],
    intel_records: List[Dict],
    model_metrics: pd.DataFrame,
    best_model: str,
) -> bytes:
    output = io.BytesIO()

    with pd.ExcelWriter(output, engine="openpyxl") as writer:

        # Sheet 1: Executive Summary
        summary_data = {
            "Metric": [
                "Report Generated",
                "Best ML Model",
                "Total Logs Analyzed",
                "Total Anomalies Detected",
                "Total IPs Blocked",
                "Detection Rate (%)",
            ],
            "Value": [
                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                best_model,
                len(results),
                sum(1 for r in results if r.get("status") in ("ANOMALY", "BLOCKED")),
                len(blocked_ips),
                f"{(sum(1 for r in results if r.get('status') in ('ANOMALY','BLOCKED')) / max(len(results),1) * 100):.1f}%",
            ]
        }
        pd.DataFrame(summary_data).to_excel(writer, sheet_name="Executive Summary", index=False)

        # Sheet 2: All Log Results
        if results:
            pd.DataFrame(results).to_excel(writer, sheet_name="Log Analysis", index=False)

        # Sheet 3: Blocked IPs
        if blocked_ips:
            pd.DataFrame(blocked_ips).to_excel(writer, sheet_name="Blocked IPs", index=False)
        else:
            pd.DataFrame({"message": ["No IPs blocked in this session"]}).to_excel(
                writer, sheet_name="Blocked IPs", index=False)

        # Sheet 4: Threat Scores
        if threat_records:
            df_threats = pd.DataFrame(threat_records).sort_values("score", ascending=False)
            df_threats.to_excel(writer, sheet_name="Threat Scores", index=False)

        # Sheet 5: IP Intelligence
        if intel_records:
            pd.DataFrame(intel_records).to_excel(writer, sheet_name="IP Intelligence", index=False)

        # Sheet 6: Model Benchmark
        if model_metrics is not None:
            model_metrics.reset_index().to_excel(writer, sheet_name="Model Benchmark", index=False)

    output.seek(0)
    return output.getvalue()
