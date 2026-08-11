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
    analysis_status
)
SELECT 
    'ALT-' || (100005 + i)::text AS alert_id,
    
    (ARRAY[
        'SQL Injection Attempt', 
        'Possible Port Scan', 
        'Multiple Failed Logins', 
        'Possible Data Exfiltration', 
        'DDoS Attack Volumetric', 
        'Malicious File Download', 
        'Command & Control Communication', 
        'SSH Brute Force Attack', 
        'Cross-Site Scripting (XSS)', 
        'Unusual Outbound Data Flow'
    ])[floor(random() * 10 + 1)] AS alert_name,
    
    (ARRAY[
        'SQLi Detection Rule', 
        'Port Scan Threshold Rule', 
        'Auth Failure Limit Rule', 
        'Data Exfiltration Rule', 
        'Rate Limiting Rule', 
        'Malware Signature Match', 
        'C2 Beaconing Detection', 
        'SSH Anomaly Rule', 
        'WAF Web Attack Rule', 
        'Outbound Traffic Spike Rule'
    ])[floor(random() * 10 + 1)] AS rule_name,
    
    (ARRAY['Low', 'Medium', 'High', 'Critical'])[floor(random() * 4 + 1)] AS severity,
    
    NOW() - (random() * interval '24 hours') AS alert_time,
    
    (ARRAY['Firewall', 'WebServer', 'WAF', 'EDR', 'VPN Gateway', 'IDS/IPS'])[floor(random() * 6 + 1)] AS log_source,
    
    (
        (ARRAY['185.220.101.', '45.33.32.', '103.21.244.', '198.51.100.', '104.28.16.', '51.158.1.', '185.199.108.', '93.184.216.'])[floor(random() * 8 + 1)]
        || floor(random() * 254 + 1)::text
    )::inet AS src_ip,
    
    (
        (ARRAY['142.250.190.', '20.112.52.', '13.107.21.', '52.84.125.', '104.16.123.', '172.67.182.'])[floor(random() * 6 + 1)]
        || floor(random() * 254 + 1)::text
    )::inet AS dest_ip,
    
    (ARRAY['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'TLS'])[floor(random() * 6 + 1)] AS protocol,
    
    (ARRAY['{80}', '{443}', '{22}', '{53}', '{80,443}', '{22,23,80,443}'])[floor(random() * 6 + 1)]::integer[] AS destination_ports,
    
    floor(random() * 1500 + 10)::int AS event_count,
    
    (ARRAY['1m', '5m', '10m', '15m', '30m'])[floor(random() * 5 + 1)] AS time_window,
    
    jsonb_build_array(
        jsonb_build_object(
            'event_type', 'security_event',
            'action', (ARRAY['ALLOW', 'DENY', 'BLOCK', '403', '200'])[floor(random() * 5 + 1)],
            'payload_size', floor(random() * 5000000 + 500)
        )
    ) AS sample_logs,
    
    jsonb_build_object(
        'hostname', (ARRAY['WebServer01', 'LinuxServer01', 'FinanceServer01', 'CustomerPortal', 'DB-Cluster-01', 'AuthServer'])[floor(random() * 6 + 1)],
        'criticality', (ARRAY['Low', 'Medium', 'High', 'Critical'])[floor(random() * 4 + 1)]
    ) AS asset,
    
    CASE 
        WHEN status_calc.status = 'Processed' THEN 
            jsonb_build_object(
                'abuseipdb', jsonb_build_object('score', floor(random() * 100), 'confidence', floor(random() * 100)),
                'virustotal', jsonb_build_object('malicious', floor(random() * 30), 'suspicious', floor(random() * 5)),
                'otx', jsonb_build_object('pulse_count', floor(random() * 20))
            )
        ELSE NULL 
    END AS threat_intelligence,
    
    -- التعديل هنا: إضافة تصنيفات متعددة (True Positive, False Positive, Suspicious, Benign)
    CASE 
        WHEN status_calc.status = 'Processed' THEN 
            (ARRAY['True Positive', 'False Positive'])[floor(random() * 4 + 1)]
        ELSE NULL 
    END AS llm_classification,
    
    CASE 
        WHEN status_calc.status = 'Processed' THEN 
            round((random() * 20 + 80)::numeric, 2)
        ELSE NULL 
    END AS llm_confidence,
    
    CASE 
        WHEN status_calc.status = 'Processed' THEN 
            'Automated LLM security analysis completed. Source IP flagged based on behavior anomalies and Threat Intel databases.'
        ELSE NULL 
    END AS llm_reason,
    
    CASE 
        WHEN status_calc.status = 'Processed' THEN 
            'Block incoming traffic from source IP, initiate threat hunting across connected endpoints, and retain logs for auditing.'
        ELSE NULL 
    END AS llm_recommendation,
    
    CASE 
        WHEN status_calc.status = 'Processed' THEN 
            NOW() - (random() * interval '12 hours')
        ELSE NULL 
    END AS analyzed_at,
    
    status_calc.status AS analysis_status

FROM generate_series(1, 10) AS i
CROSS JOIN LATERAL (
    SELECT (ARRAY['Processed', 'Pending'])[floor(random() * 2 + 1)] AS status
) AS status_calc;

SELECT * FROM public.alerts;
SELECT * FROM public.alerts