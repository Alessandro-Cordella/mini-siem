from fastapi import FastAPI
from datetime import datetime, timedelta
from tinydb import TinyDB
import ipaddress
import math

app = FastAPI(
    title="Mini SIEM",
    description="Security Information and Event Management system",
    version="1.0.0"
)

db = TinyDB("siem_logs.json")
events_table = db.table("events")
alerts_table = db.table("alerts")

VALID_SOURCES = ["brute_force_detector", "password_analyzer", "manual"]
VALID_EVENT_TYPES = ["brute_force", "weak_password", "breached_password", "login_failed", "login_success"]
SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def validate_ip(ip: str):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def correlate_events(ip: str):
    alerts = []
    
    time_window = datetime.now() - timedelta(minutes=5)

    ip_events = [
       e for e in events_table.all()
       if e.get("ip") == ip
       and datetime.strptime(e.get("timestamp"), "%Y-%m-%d %H:%M:%S") >= time_window
]
    
    brute_force_events = [e for e in ip_events if e.get("event_type") == "brute_force"]
    login_success_events = [e for e in ip_events if e.get("event_type") == "login_success"]
    weak_password_events = [e for e in ip_events if e.get("event_type") == "weak_password"]
    breached_password_events = [e for e in ip_events if e.get("event_type") == "breached_password"]
    
    if len(brute_force_events) >= 3 and login_success_events:
     alerts.append({
        "ip": ip,
        "alert_type": "ACCOUNT_COMPROMISED",
        "severity": "CRITICAL",
        "description": "Brute force attack followed by successful login — account likely compromised!",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

    if len(brute_force_events) >= 3 and weak_password_events:
     alerts.append({
        "ip": ip,
        "alert_type": "TARGETED_ATTACK",
        "severity": "HIGH",
        "description": "Brute force attack combined with weak password detected — targeted attack!",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    
    if breached_password_events:
        alerts.append({
            "ip": ip,
            "alert_type": "BREACHED_CREDENTIALS",
            "severity": "HIGH",
            "description": "Breached password detected — credentials may be compromised!",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    
    if len(ip_events) >= 10:
        alerts.append({
            "ip": ip,
            "alert_type": "SUSPICIOUS_ACTIVITY",
            "severity": "MEDIUM",
            "description": "High volume of events from same IP — suspicious activity detected!",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    
    return alerts

@app.post("/event")
def receive_event(
    source: str,
    event_type: str,
    ip: str,
    severity: str,
    description: str = ""
):
    if source not in VALID_SOURCES:
        return {"error": f"Invalid source — valid sources: {VALID_SOURCES}"}
    if event_type not in VALID_EVENT_TYPES:
        return {"error": f"Invalid event type — valid types: {VALID_EVENT_TYPES}"}
    if severity not in SEVERITY_LEVELS:
        return {"error": f"Invalid severity — valid levels: {SEVERITY_LEVELS}"}
    if not validate_ip(ip):
        return {"error": "Invalid IP address format"}
    event = {
        "source": source,
        "event_type": event_type,
        "ip": ip,
        "severity": severity,
        "description": description,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    events_table.insert(event)
    
    new_alerts = correlate_events(ip)
    for alert in new_alerts:
        existing_alerts = [a for a in alerts_table.all() 
                if a.get("ip") == alert["ip"] 
                and a.get("alert_type") == alert["alert_type"]]
        if not existing_alerts:
            alerts_table.insert(alert)
    
    return {
        "message": "Event received successfully",
        "event": event,
        "new_alerts": len(new_alerts)
    }

@app.get("/alerts")
def get_alerts(severity: str = None):
    all_alerts = alerts_table.all()
    
    if severity:
        if severity not in SEVERITY_LEVELS:
            return {"error": f"Invalid severity — valid levels: {SEVERITY_LEVELS}"}
        all_alerts = [a for a in all_alerts if a.get("severity") == severity]
    
    return {
        "total": len(all_alerts),
        "alerts": all_alerts
    }

@app.get("/dashboard")
def get_dashboard():
    all_events = events_table.all()
    all_alerts = alerts_table.all()
    
    events_by_type = {}
    for event in all_events:
        event_type = event.get("event_type")
        if event_type in events_by_type:
            events_by_type[event_type] += 1
        else:
            events_by_type[event_type] = 1
    
    alerts_by_severity = {}
    for alert in all_alerts:
        severity = alert.get("severity")
        if severity in alerts_by_severity:
            alerts_by_severity[severity] += 1
        else:
            alerts_by_severity[severity] = 1
    
    unique_ips = list(set(e.get("ip") for e in all_events))
    
    critical_alerts = [a for a in all_alerts if a.get("severity") == "CRITICAL"]
    
    return {
        "total_events": len(all_events),
        "total_alerts": len(all_alerts),
        "unique_ips": len(unique_ips),
        "events_by_type": events_by_type,
        "alerts_by_severity": alerts_by_severity,
        "critical_alerts": critical_alerts
    }

@app.get("/report")
def get_report():
    all_events = events_table.all()
    all_alerts = alerts_table.all()
    
    critical_alerts = [a for a in all_alerts if a.get("severity") == "CRITICAL"]
    high_alerts = [a for a in all_alerts if a.get("severity") == "HIGH"]
    
    unique_ips = list(set(e.get("ip") for e in all_events))
    
    most_active_ip = None
    max_events = 0
    for ip in unique_ips:
        ip_count = len([e for e in all_events if e.get("ip") == ip])
        if ip_count > max_events:
            max_events = ip_count
            most_active_ip = ip
    
    return {
        "report_generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "total_events": len(all_events),
            "total_alerts": len(all_alerts),
            "critical_alerts": len(critical_alerts),
            "high_alerts": len(high_alerts),
            "unique_ips_monitored": len(unique_ips),
            "most_active_ip": most_active_ip,
            "most_active_ip_events": max_events
        },
        "critical_alerts_detail": critical_alerts,
        "high_alerts_detail": high_alerts,
        "recommendations": [
            "Investigate all CRITICAL alerts immediately",
            "Block IPs with brute force activity",
            "Reset credentials for compromised accounts",
            "Review weak password policies"
        ]
    }