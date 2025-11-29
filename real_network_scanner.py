import socket
import threading
from datetime import datetime


print("WARNING: This is a real network scanner. Unethical use will have consequences.")

print("Network Scanner Initialized.")

targets = []
vulnerabilities = []
common_ports = [22, 80, 443, 21, 23, 25, 53, 3389, 587]
scan_data = []
critical_ports = [21, 23]  # FTP, Telnet
high_risk_ports = [22, 25, 3389]  # SSH, SMTP, RDP
medium_risk_ports = [80, 587]  # HTTP, SMTP Submission
low_risk_ports = [443, 53]  # HTTPS, DNS

critical_issues = 0
high_risk_issues = 0
medium_risk_issues = 0
vulnerability_database = {
    21: {
        "Service": "FTP",
        "Risk": "Critical",
        "Description": "Unencrypted file transfer",
        "summary": "FTP transmits data in plaintext, making it vulnerable to interception and eavesdropping.",
        "Recommendation": "Use SFTP or FTPS for secure file transfer."
    },
    22: {
        "Service": "SSH",
        "Risk": "High",
        "Description": "Remote access service",
        "summary": "SSH provides secure remote access, but weak configurations can lead to unauthorized access.",
        "Recommendation": "Use strong authentication methods and keep software updated."
    },
    25: {
        "Service": "SMTP",
        "Risk": "High",
        "Description": "Email transmission service",
        "summary": "SMTP servers can be exploited for email spoofing and spam relay if not properly secured.",
        "Recommendation": "Ensure proper authentication and encryption mechanisms are in place."
    },
    53: {
        "Service": "DNS",
        "Risk": "Low",
        "Description": "Domain Name System",
        "summary": "DNS servers can be targeted for cache poisoning attacks if not properly secured.",
        "Recommendation": "Implement DNSSEC and regular monitoring."
    },
    80: {
        "Service": "HTTP",
        "Risk": "Medium",
        "Description": "Unencrypted web traffic",
        "summary": "HTTP transmits data in plaintext, making it vulnerable to interception and eavesdropping.",
        "Recommendation": "Use HTTPS to encrypt web traffic."
    },
    443: {
        "Service": "HTTPS",
        "Risk": "Low",
        "Description": "Encrypted web traffic",
        "summary": "HTTPS provides a secure communication channel, but misconfigurations can still lead to vulnerabilities.",
        "Recommendation": "Regularly update and patch web servers."
    },
    587: {
        "Service": "SMTP Submission",
        "Risk": "Medium",
        "Description": "Email submission service",
        "summary": "SMTP servers can be exploited for email spoofing and spam relay if not properly secured.",  
        "Recommendation": "Ensure proper authentication and encryption mechanisms are in place."

    },
    3389: {
        "Service": "RDP",
        "Risk": "High",
        "Description": "Remote Desktop access",
        "summary": "RDP can be exploited for unauthorized remote access if not properly secured.",
        "Recommendation": "Use strong passwords, enable Network Level Authentication, and restrict access via firewalls."
    }
}

service_categories = {
    "Web Services": {
        "ports": [80, 443],
        "risk_level": "Medium",
        "description": "Services related to web hosting and browsing."
    },
    "Remote Access Services": {
        "ports": [22, 3389],
        "risk_level": "High",
        "description": "Services that allow remote access to systems."
    },
    "SMTP Services": {
        "ports": [25, 587],
        "risk_level": "High",
        "description": "Services used for sending and receiving emails."
    },
    "File Transfer Services": {
        "ports": [21],
        "risk_level": "Critical",
        "description": "Services used for transferring files over the network."
    },
    "DNS Services": {
        "ports": [53],
        "risk_level": "Low",
        "description": "Services that translate domain names to IP addresses."
    }
}

while True:
    print("\n=== Network Vulnerability Scanner ===")
    print("1. Add Target IP/Domain")
    print("2. View All Targets")
    print("3. Scan Single Target")
    print("4. Scan All Targets")
    print("5. View Scan Results")
    print("6. Generate Security Report")
    print("7. View Vulnerability Database")
    print("8. Exit")

    choice = input("Enter your choice: ")

    if choice == "1":
        ip_domain = input("Enter your IP address or domain to add: ")
        parts = ip_domain.split(".")
        if len(parts) == 4:
            valid = True
            for part in parts:
                if not part.isdigit() or not (0 <= int(part) <= 255):
                    valid = False
                    break
            if valid:
                targets.append(ip_domain)
                print(f"Target {ip_domain} successfully added.")
            else:
                print("Invalid IP address or domain format.")
        
    elif choice == "2":
        print("\n--- All Targets ---")
        if targets:
            for target in targets:
                print(f"- {target}")
        else:
            print("No targets added yet.")

    elif choice == "3":
        if not targets:
            print("No targets to scan. Please add targets first.")
            continue
        target = input("Enter target IP/Domain to scan: ")
        if target in targets:
            print(f"Scanning {target}...")
        else:
            print("Target not found in the list. Please add it first.")
            continue

        start_scan_time = datetime.now()

        current_scan = {
                'target': target,
                'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'open_ports': [],
                'closed_ports': [],
                'total_ports': len(common_ports)
            }

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)

                result = sock.connect_ex((target, port))

                   

                if result == 0:
                    print(f"Port {port}: Open")
                    current_scan['open_ports'].append(port)
                else:
                    print(f"Port {port}: Closed")
                    current_scan['closed_ports'].append(port)
                
            except Exception as e:
                print(f"Port {port}: Error - {e}")
            finally:
                sock.close()
        scan_end_time = datetime.now()
        scan_duration = scan_end_time - start_scan_time
        current_scan['scan_duration'] = scan_duration.total_seconds()

        scan_data.append(current_scan)

    elif choice == "4":
        if not targets:
            print("No targets to scan. Please add targets first.")
            continue

        for target in targets:
            print(f"Scanning {target}...")

            start_scan_time = datetime.now()


            current_scan = {
                    'target': target,
                    'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'open_ports': [],
                    'closed_ports': [],
                    'total_ports': len(common_ports)
                }
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)

                    result = sock.connect_ex((target, port))

                    
                   
                    if result == 0:
                        print(f"Port {port}: Open")
                        current_scan['open_ports'].append(port)
                    else:
                        print(f"Port {port}: Closed")
                        current_scan['closed_ports'].append(port)
                except Exception as e:
                    print(f"Port {port}: Error - {e}")
                finally:
                    sock.close()

            scan_end_time = datetime.now()
            scan_duration = scan_end_time - start_scan_time
            current_scan['scan_duration'] = scan_duration.total_seconds()

            scan_data.append(current_scan)


    elif choice == "5":
        print("\n---Scan Results---")
        if scan_data:
            for scan in scan_data:
                print(f"Target: {scan['target']}")
                print(f"Scan Time: {scan['scan_time']}")
                print(f"Open Ports: {scan['open_ports']}")
                print(f"Closed Ports: {scan['closed_ports']}")
                print(f"Total Ports Scanned: {scan['total_ports']}")
                print("-" * 40)
        else:
            print("No scan results available.")


    elif choice == "6":
        critical_issues = 0
        high_risk_issues = 0        
        medium_risk_issues = 0

        print("\n=== Network Security Report ===")
        print(f"Report Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("Analyst: Cyber Security Scanner v2.0")

        print("Executive Summary:")
        total_scans = len(scan_data)
        print(f"Total Scans Conducted: {total_scans}")
        total_open_ports = sum(len(scan['open_ports']) for scan in scan_data)
        print(f"Total Open Ports Found: {total_open_ports}")
        if 0 < total_open_ports <= 1:
            print("Overall Security Status: ✅ Secure - Minimal open ports detected.")
        elif 2 <= total_open_ports < 5:
            print("Overall Security Status: ⚠️ Moderate Risk - Some open ports detected.")
        elif total_open_ports >= 5:
            print("Overall Security Status: ❌ High Risk - Multiple open ports detected.")
        
        for scan in scan_data:
            for port in scan['open_ports']:
                if port in critical_ports:
                    critical_issues += 1
                elif port in high_risk_ports:
                    high_risk_issues += 1
                elif port in medium_risk_ports:
                    medium_risk_issues += 1
        print(f"Critical Issues Found: {critical_issues}")
        print(f"High-Risk Issues Found: {high_risk_issues}")
        print(f"Medium-Risk Issues Found: {medium_risk_issues}")

        print("Target Analysis:")
        print("-" * 40)
        for scan in scan_data:
            print(f"Target: {scan['target']}")
            if critical_issues > 0:
                print("Security Status: ❌ High Risk - Critical vulnerabilities detected.")
            elif high_risk_issues > 0:
                print("Security Status: ⚠️ Moderate Risk - High-risk vulnerabilities detected.")
            elif medium_risk_issues > 0:
                print("Security Status: 🔵 Low Risk - Medium-risk vulnerabilities detected.")
            else:
                print("Security Status: ✅ Secure - No vulnerabilities detected.")
            print(f"Open Ports: {scan['open_ports']}")
            print()
            if scan['open_ports']:
                print("Vulnerabilities Detected:")
                for port in scan['open_ports']:
                    if port in vulnerability_database:
                        vuln = vulnerability_database[port]
                        print(f" Port {port} ({vuln['Service']}): {vuln['Description']}")
                    else:
                        print(f" Port {port}: Unknown service detected")
            print()
            print("Last Scanned:", scan["scan_time"])
        print()
        print("Vulnerability Summary:")
        all_port_counts = {}
        for scan in scan_data:
            for port in scan['open_ports']:
                all_port_counts[port] = all_port_counts.get(port, 0) + 1

        for category, info in service_categories.items():
            category_ports = [p for p in all_port_counts.keys() if p in info["ports"]]
            if category_ports:
                total_found = sum(all_port_counts[p] for p in category_ports)
                print(f"📊 {category}: {total_found} instances found - Risk Level: {info['risk_level']} - Description: {info['description']}")
            else:
                print(f"📊 {category}: No instances found")
        print()

        print("Recommendations:")
        recommendations_dic= {}

        for scan in scan_data:
            for port in scan['open_ports']:
                if port in vulnerability_database:
                    vuln = vulnerability_database[port]
                    recommendation = vuln['Recommendation']

                    if recommendation not in recommendations_dic:
                        recommendations_dic[recommendation] = []
                    recommendations_dic[recommendation].append(f"{vuln['Service']} (Port {port})")
        for recommendation, services in recommendations_dic.items():
            services_str = ", ".join(set(services))
            print(f" {recommendation}")
            print(f"   Affected Services: {services_str}")
            print()

        print("Scan Statistics:")
        if scan_data:
            total_duration = sum(scan.get('scan_duration',0) for scan in scan_data)
            total_target_scanned = len(scan_data)
            ports_per_target = len(common_ports)
            total_ports_tested = total_target_scanned * ports_per_target

            print(f"- Scan Duration: {total_duration:.2f} seconds")
            print(f"- Ports Tested: {total_ports_tested}")
            print(f"- Success Rate: {((total_ports_tested - (critical_issues + high_risk_issues + medium_risk_issues)) / total_ports_tested) * 100:.2f}%")
            print(f"- Network Timeouts: {critical_issues + high_risk_issues + medium_risk_issues}")

    elif choice == "7":
        print("\n--- Vulnerability Database ---")
        for port, details in vulnerability_database.items():
            print("-" * 40)
            print(f"Port: {port} - {details['Service']}")
            print("-" * 40)
            if details['Risk'] == "High":
                print(f"🔴 Risk level: {details['Risk']}")
            elif details['Risk'] == "Medium":
                print(f"🟠 Risk level: {details['Risk']}")
            elif details['Risk'] == "Low":
                print(f"🟢 Risk level: {details['Risk']}")
            print(f"Description: {details['Description']}")
            print(f"Security Summary: {details['summary']}")
            print(f"Recommendation: {details['Recommendation']}")
            print()
            print()
        print("-" * 40)
        print("Database Summary")
        print("-" * 40)
        print(f"Total Services: {len(vulnerability_database)}")
        print(f"Critical Risk Services: {sum(1 for v in vulnerability_database.values() if v['Risk'] == 'Critical')}")
        print(f"High Risk Services: {sum(1 for v in vulnerability_database.values() if v['Risk'] == 'High')}")
        print(f"Medium Risk Services: {sum(1 for v in vulnerability_database.values() if v['Risk'] == 'Medium')}")
        print(f"Low Risk Services: {sum(1 for v in vulnerability_database.values() if v['Risk'] == 'Low')}")
        print()
        print(f"Last Updated: {datetime.now().strftime('%Y-%m-%d')}")

    elif choice == "8":
        print("Exiting Network Vulnerability Scanner. Stay Secure!")
        break