"""
Shared utility functions.
"""

from datetime import datetime
from typing import List, Dict, Any
import pandas as pd


def now_iso() -> str:
    return datetime.utcnow().isoformat()


def results_to_dataframe(results: List[Dict[str, Any]]) -> pd.DataFrame:
    if not results:
        return pd.DataFrame()
    return pd.DataFrame(results)


def status_color(status: str) -> str:
    return {
        "NORMAL": "#2ecc71",
        "ANOMALY": "#e67e22",
        "BLOCKED": "#e74c3c",
    }.get(status, "#95a5a6")


def truncate_ip_table(records: List[Dict], max_rows: int = 100) -> List[Dict]:
    return records[-max_rows:]