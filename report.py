from datetime import datetime


def generate_json_report(analysis_results):
    risk_info = analysis_results.get("risk_score", {})

    results = {
        "metadata": {
            "tool": "Phishing Analyzer",
            "version": "1.0",
            "analysis_time": datetime.utcnow().isoformat() + "Z"
        },
        "summary": {
            "risk_level": risk_info.get("risk_level"),
            "total_score": risk_info.get("total_score")
        },
        "analysis": {
            "headers": analysis_results.get("headers", {}),
            "content": analysis_results.get("content", {}),
            "attachments": analysis_results.get("attachments", []),
            "risk_score": risk_info
        }

    }
    return results
