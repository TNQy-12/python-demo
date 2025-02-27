from collections import defaultdict
import time
import re

def detect_brute_force(log_entries, threshold=5, time_window=300):
    # Phát hiện Brute Force dựa trên số lần đăng nhập thất bại
    ip_attempts = defaultdict(list)
    alerts = []
    current_time = time.time()

    for entry in log_entries:
        if entry['type'] == 'apache' and entry['status'] == 401:
            ip = entry['ip']
            timestamp = time.mktime(time.strptime(entry['timestamp'], '%d/%b/%Y:%H:%M:%S %z'))
            ip_attempts[ip].append(timestamp)

    for ip, timestamps in ip_attempts.items():
        recent_attempts = [t for t in timestamps if current_time - t <= time_window]
        if len(recent_attempts) >= threshold:
            alerts.append(f"Phát hiện Brute Force từ IP: {ip} - {len(recent_attempts)} lần thất bại")
    return alerts

def detect_port_scanning(log_entries, threshold=5, time_window=60):
    # Phát hiện Port Scanning dựa trên số cổng truy cập từ một IP
    ip_ports = defaultdict(set)
    alerts = []
    current_time = time.time()

    for entry in log_entries:
        if entry['type'] == 'firewall':
            src_ip = entry['src_ip']
            dpt = entry['dpt']
            timestamp = time.mktime(time.strptime(entry['timestamp'], '%b %d %H:%M:%S'))
            if current_time - timestamp <= time_window:
                ip_ports[src_ip].add(dpt)

    for ip, ports in ip_ports.items():
        if len(ports) >= threshold:
            alerts.append(f"Phát hiện Port Scanning từ IP: {ip} - {len(ports)} cổng khác nhau")
    return alerts

def detect_sql_injection(log_entries):
    # Phát hiện SQL Injection dựa trên các chuỗi đặc trưng
    alerts = []
    sql_patterns = [r"'.*OR.*='", r"UNION\s+SELECT", r"SELECT.*FROM"]
    for entry in log_entries:
        if entry['type'] == 'apache':
            request = entry['request']
            for pattern in sql_patterns:
                if re.search(pattern, request, re.IGNORECASE):
                    alerts.append(f"Phát hiện SQL Injection từ IP: {entry['ip']} - Yêu cầu: {request}")
                    break
    return alerts

def detect_xss(log_entries):
    # Phát hiện XSS dựa trên mã JavaScript trong yêu cầu
    alerts = []
    xss_patterns = [r"<script>", r"javascript:", r"on\w+="]
    for entry in log_entries:
        if entry['type'] == 'apache':
            request = entry['request']
            for pattern in xss_patterns:
                if re.search(pattern, request, re.IGNORECASE):
                    alerts.append(f"Phát hiện XSS từ IP: {entry['ip']} - Yêu cầu: {request}")
                    break
    return alerts

def detect_attacks(log_entries):
    # Tổng hợp tất cả các loại tấn công
    alerts = []
    alerts.extend(detect_brute_force(log_entries))
    alerts.extend(detect_port_scanning(log_entries))
    alerts.extend(detect_sql_injection(log_entries))
    alerts.extend(detect_xss(log_entries))
    return alerts