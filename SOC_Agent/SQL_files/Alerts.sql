DROP TABLE IF EXISTS public.alerts;

CREATE TABLE alerts (

    alert_id TEXT PRIMARY KEY,

    alert_name TEXT NOT NULL,

    rule_name TEXT NOT NULL,

    severity VARCHAR(20) NOT NULL,

    alert_time TIMESTAMP NOT NULL,

    log_source VARCHAR(50) NOT NULL,

    src_ip INET,

    dest_ip INET,

    protocol VARCHAR(20),

    destination_ports INTEGER[],

    event_count INTEGER,

    time_window VARCHAR(20),

    sample_logs JSONB,

    asset JSONB,

    threat_intelligence JSONB,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE alerts
ADD COLUMN llm_classification VARCHAR(10),
ADD COLUMN llm_confidence NUMERIC(5,2),
ADD COLUMN llm_reason TEXT,
ADD COLUMN llm_recommendation TEXT,
ADD COLUMN analyzed_at TIMESTAMP,
ADD COLUMN analysis_status VARCHAR(20) DEFAULT 'Pending';

ALTER TABLE alerts
ALTER COLUMN llm_classification TYPE VARCHAR(30);
ALTER TABLE public.alerts
ADD COLUMN triage_status VARCHAR(20);

INSERT INTO public.alerts
(
    alert_id,
    alert_name,
    rule_name,
    severity,
    alert_time,
    log_source,
    src_ip,
    dest_ip,
    protocol,
    destination_ports,
    event_count,
    time_window,
    sample_logs,
    asset,
    threat_intelligence
)
VALUES

(
    'ALT-100001',
    'Possible Port Scan',
    'Port Scan Detection Rule',
    'Medium',
    '2026-08-07 10:05:00',
    'Firewall',
    '45.33.32.9',
    '192.168.1.10',
    'TCP',
    ARRAY[22,23,80,443],
    420,
    '5m',
    '[
        {"port":22,"action":"ALLOW"},
        {"port":23,"action":"ALLOW"},
        {"port":80,"action":"ALLOW"}
    ]'::jsonb,
    '{
        "hostname":"WebServer01",
        "criticality":"High"
    }'::jsonb,
    NULL
),

(
    'ALT-100002',
    'Multiple Failed Logins',
    'Brute Force Detection Rule',
    'Low',
    '2026-08-07 10:12:00',
    'Firewall',
    '103.21.244.5',
    '192.168.1.20',
    'TCP',
    ARRAY[22],
    18,
    '10m',
    '[
        {"user":"admin","status":"failed"},
        {"user":"admin","status":"failed"},
        {"user":"admin","status":"failed"}
    ]'::jsonb,
    '{
        "hostname":"LinuxServer01",
        "criticality":"Medium"
    }'::jsonb,
    NULL
),

(
    'ALT-100003',
    'Possible Data Exfiltration',
    'Large Outbound Transfer Rule',
    'High',
    '2026-08-07 10:25:00',
    'Firewall',
    '185.220.101.55',
    '185.199.108.153',
    'HTTPS',
    ARRAY[443],
    1750,
    '15m',
    '[
        {"bytes":450000000},
        {"bytes":380000000},
        {"bytes":520000000}
    ]'::jsonb,
    '{
        "hostname":"FinanceServer01",
        "criticality":"Critical"
    }'::jsonb,
    NULL
);

INSERT INTO public.alerts
(
    alert_id,
    alert_name,
    rule_name,
    severity,
    alert_time,
    log_source,
    src_ip,
    dest_ip,
    protocol,
    destination_ports,
    event_count,
    time_window,
    sample_logs,
    asset,
    threat_intelligence,
    llm_classification,
    llm_confidence,
    llm_reason,
    llm_recommendation,
    analyzed_at,
    analysis_status,
	triage_status
)
VALUES
(
    'ALT-100004',

    'SQL Injection Attempt',

    'SQL Injection Detection Rule',

    'High',

    '2026-08-05 11:05:00',

    'WebServer',

    '185.220.101.55',

    '192.168.1.50',

    'HTTP',

    ARRAY[80],

    67,

    '2m',

    $$[
        {
            "method":"GET",
            "url":"/login.php?id=1' OR '1'='1",
            "status":403
        },
        {
            "method":"GET",
            "url":"/login.php?id=1 UNION SELECT password FROM users",
            "status":403
        }
    ]$$::jsonb,

    $${
        "hostname":"CustomerPortal",
        "criticality":"Critical"
    }$$::jsonb,

    $${
        "abuseipdb": {
            "score": 98,
            "confidence": 95
        },
        "virustotal": {
            "malicious": 15,
            "suspicious": 2
        },
        "greynoise": {
            "classification": "malicious"
        },
        "otx": {
            "pulse_count": 8
        }
    }$$::jsonb,

    'True Positive',

    98.70,

    'The alert is a True Positive. Multiple SQL Injection payloads were detected targeting a critical web application. Threat intelligence also identifies the source IP as malicious.',

    'Immediately block the source IP, inspect web server logs, review database access, and verify whether any SQL queries were successfully executed.',

    CURRENT_TIMESTAMP,

    'Processed', 
	'Succeeded'
);
SELECT * FROM public.alerts;