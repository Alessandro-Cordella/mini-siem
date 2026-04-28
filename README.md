#Mini SIEM — Security Information and Event Management

A lightweight SIEM API built with Python and FastAPI that correlates security events in real time and generates alerts.

## Features
- Event ingestion from multiple sources
- Real-time event correlation
- Automated alert generation with severity levels
- Security dashboard with statistics
- Security report generation
- Time-window based correlation (5 minutes)
- Duplicate alert prevention
- IP address validation
- Fully containerized with Docker

## Alert Types
| Alert | Severity | Trigger |
|---|---|---|
| ACCOUNT_COMPROMISED | CRITICAL | 3+ brute force + login success |
| TARGETED_ATTACK | HIGH | 3+ brute force + weak password |
| BREACHED_CREDENTIALS | HIGH | Breached password detected |
| SUSPICIOUS_ACTIVITY | MEDIUM | 10+ events from same IP in 5 min |

## Endpoints
| Method | Endpoint | Description |
|---|---|---|
| POST | /event | Ingest a security event |
| GET | /alerts | Get all alerts with optional severity filter |
| GET | /dashboard | Get security statistics |
| GET | /report | Get full security report |

## Event Sources
- `brute_force_detector`
- `password_analyzer`
- `manual`

## Tech Stack
- Python 3.11
- FastAPI
- TinyDB
- Docker

## How to run
```bash
docker build -t mini-siem .
docker run -p 8000:8000 mini-siem
```

## Known Limitations
- TinyDB not suitable for high event volumes
- No authentication — add JWT for production use
- Breach database is local and simulated
- No real log ingestion pipeline
