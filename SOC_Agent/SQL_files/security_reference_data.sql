DROP TABLE IF EXISTS public.security_reference_data;

CREATE TABLE public.security_reference_data (
    id BIGSERIAL PRIMARY KEY,

    reference_type TEXT NOT NULL UNIQUE
    CHECK (
        reference_type IN (
            'playbooks',
            'network_info'
        )
    ),

    data JSONB NOT NULL DEFAULT '{}'::jsonb,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


INSERT INTO public.security_reference_data (
    reference_type,
    data
)
VALUES

-- ============================================================
-- PLAYBOOKS (تتضمن شروط الاكتشاف Detection/Match والإجراءات Actions)
-- ============================================================

(
    'playbooks',

    '{
        "brute_force": {
            "severity": "High",
            "match": {
                "src": "external",
                "failed_logins": ">20",
                "window": "60s",
                "ports": [22, 3389]
            },
            "actions": [
                "Block source IP at Edge Firewall",
                "Reset credentials for targeted accounts",
                "Check authentication logs for successful logins post-failure",
                "Enforce MFA"
            ]
        },

        "sqli": {
            "severity": "Critical",
            "match": {
                "patterns": [
                    "UNION SELECT",
                    "OR 1=1",
                    "SQL comment",
                    "INFORMATION_SCHEMA"
                ]
            },
            "actions": [
                "Drop request & Block IP at WAF",
                "Terminate active database connections from affected app worker",
                "Perform differential vulnerability scan on application endpoint",
                "Flag target web server",
                "Escalate to Senior SOC Analyst"
            ]
        },

        "xss": {
            "severity": "Medium",
            "match": {
                "input": "malicious script payload"
            },
            "actions": [
                "Sanitize parameter inputs at WAF level",
                "Validate Content-Security-Policy (CSP) headers",
                "Review HTTP request payload logs"
            ]
        },

        "data_exfiltration": {
            "severity": "Critical",
            "match": {
                "volume": ">1GB",
                "protocol": "HTTPS",
                "destination": "unapproved_external_cloud"
            },
            "actions": [
                "Isolate the originating endpoint via EDR",
                "Block destination IP/Domain on Proxy & Firewall",
                "Identify leaked files via DLP agent logs",
                "Initiate Incident Response (IR) protocol"
            ]
        },

        "port_scan": {
            "severity": "Medium",
            "match": {
                "probed_ports": ">10",
                "window": "30s"
            },
            "actions": [
                "Verify if source IP belongs to approved internal/external scanner",
                "If unauthorized, block source IP on Edge Perimeter",
                "Audit target ports for unpatched exposed services"
            ]
        }
    }'::jsonb
),


-- ============================================================
-- NETWORK INFORMATION (تم اختصار أسماء الأصول Assets)
-- ============================================================

(
    'network_info',

    '{
        "assets": {
            "10.0.0.5": {
                "name": "Prod DB",
                "type": "database",
                "criticality": "Critical",
                "external_ingress": false,
                "owner": "Database Engineering Team"
            },

            "10.0.0.2": {
                "name": "Domain Controller",
                "type": "domain_controller",
                "criticality": "Critical",
                "zone": "management",
                "owner": "Identity & Access Team"
            },

            "10.0.0.10": {
                "name": "Web Gateway",
                "type": "web_server",
                "criticality": "High",
                "external_ingress": true,
                "zone": "DMZ"
            },

            "172.16.10.50": {
                "name": "Finance PC",
                "type": "workstation",
                "criticality": "Medium",
                "zone": "internal_user_lan"
            }
        },

        "segmentation": [
            {
                "src": "172.16.x.x",
                "dst": "10.0.0.2",
                "protocols": ["RPC", "SMB"],
                "allowed": false,
                "exception": "Verified IT Admin Jump Box (172.16.1.100)"
            },
            {
                "src": "DMZ (10.0.0.10)",
                "dst": "10.0.0.5",
                "protocols": ["PostgreSQL (5432)", "MySQL (3306)"],
                "allowed": true,
                "exception": "Database queries from app server only"
            }
        ],

        "approved_destinations": {
            "FinanceServer01": {
                "185.199.108.153": {
                    "approved": true,
                    "purpose": "Scheduled Finance backup to AWS S3 bucket",
                    "allowed_protocols": ["HTTPS"],
                    "allowed_ports": [443],
                    "owner": "Infrastructure Team"
                }
            },
            "VulnerabilityScanner": {
                "192.168.1.50": {
                    "approved": true,
                    "purpose": "Authorized Tenable Vulnerability Scan Node",
                    "allowed_protocols": ["TCP", "UDP"],
                    "allowed_ports": ["ANY"],
                    "owner": "Security Compliance Team"
                }
            }
        }
    }'::jsonb
);


SELECT * FROM public.security_reference_data;