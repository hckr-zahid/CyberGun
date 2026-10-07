ATTACK_MATRIX_DATA = {
    "Reconnaissance": {
        "T1595": "Active Scanning"
    },
    "Resource Development": {
        "T1588": "Obtain Capabilities"
    },
    "Initial Access": {
        "T1078": "Valid Accounts",
        "T1190": "Exploit Public-Facing Application",
        "T1200": "Hardware Additions",
        "T1566": "Phishing"
    },
    "Execution": {
        "T1053": "Scheduled Task/Job",
        "T1059": "Command and Scripting Interpreter",
        "T1204": "User Execution"
    },
    "Persistence": {
        "T1053": "Scheduled Task/Job",
        "T1136": "Create Account",
        "T1543": "Create or Modify System Process",
        "T1547": "Boot or Logon Autostart Execution"
    },
    "Privilege Escalation": {
        "T1068": "Exploitation for Privilege Escalation",
        "T1547": "Boot or Logon Autostart Execution",
        "T1548": "Abuse Elevation Control Mechanism"
    },
    "Defense Evasion": {
        "T1027": "Obfuscated Files or Information",
        "T1036": "Masquerading",
        "T1070": "Indicator Removal",
        "T1140": "Deobfuscate/Decode Files or Information",
        "T1222": "File and Directory Permissions Modification",
        "T1562": "Impair Defenses"
    },
    "Credential Access": {
        "T1003": "OS Credential Dumping",
        "T1110": "Brute Force",
        "T1555": "Credentials from Password Stores"
    },
    "Discovery": {
        "T1012": "Query Registry",
        "T1057": "Process Discovery",
        "T1082": "System Information Discovery",
        "T1083": "File and Directory Discovery"
    },
    "Lateral Movement": {
        "T1021": "Remote Services",
        "T1570": "Lateral Tool Transfer"
    },
    "Collection": {
        "T1005": "Data from Local System",
        "T1119": "Automated Collection",
        "T1560": "Archive Collected Data"
    },
    "Command and Control": {
        "T1071": "Application Layer Protocol",
        "T1090": "Proxy",
        "T1095": "Non-Application Layer Protocol",
        "T1105": "Ingress Tool Transfer"
    },
    "Exfiltration": {
        "T1041": "Exfiltration Over C2 Channel",
        "T1048": "Exfiltration Over Alternative Protocol"
    },
    "Impact": {
        "T1486": "Data Encrypted for Impact",
        "T1489": "Service Stop",
        "T1490": "Inhibit System Recovery"
    }
}