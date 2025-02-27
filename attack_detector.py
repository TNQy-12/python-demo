from collections import defaultdict
import time
import re
import statistics

# Thêm thư viện để hỗ trợ tính năng nâng cao
from datetime import datetime

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
            timestamp = time.mktime(time.strptime(entry['timestamp'], '%b %d %H:%M:%S %Y'))
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

def detect_behavior_anomaly(log_entries, time_window=3600, anomaly_threshold=3):
    # Phát hiện bất thường dựa trên số lượng yêu cầu từ một IP
    alerts = []
    ip_requests = defaultdict(list)
    current_time = time.time()

    for entry in log_entries:
        if entry['type'] == 'apache':
            ip = entry['ip']
            timestamp = time.mktime(time.strptime(entry['timestamp'], '%d/%b/%Y:%H:%M:%S %z'))
            if current_time - timestamp <= time_window:
                ip_requests[ip].append(timestamp)

    request_counts = [len(timestamps) for timestamps in ip_requests.values()]
    if not request_counts:
        return alerts
    
    mean_requests = statistics.mean(request_counts)
    std_requests = statistics.stdev(request_counts) if len(request_counts) > 1 else 0

    for ip, timestamps in ip_requests.items():
        req_count = len(timestamps)
        if std_requests > 0 and (req_count - mean_requests) / std_requests > anomaly_threshold:
            alerts.append(f"Phát hiện truy cập bất thường từ IP: {ip} - {req_count} yêu cầu (trung bình: {mean_requests:.1f})")
    return alerts

def detect_command_injection(log_entries):
    # Phát hiện Command Injection dựa trên các chuỗi lệnh hệ điều hành
    alerts = []
    cmd_patterns = [
        r';.*(rm|del|dir|whoami|cat|ls|echo).*',
        r'\|.*(sh|bash|cmd|powershell).*',
        r'&&.*'
    ]
    for entry in log_entries:
        if entry['type'] == 'apache':
            request = entry['request']
            for pattern in cmd_patterns:
                if re.search(pattern, request, re.IGNORECASE):
                    alerts.append(f"Phát hiện Command Injection từ IP: {entry['ip']} - Yêu cầu: {request}")
                    break
    return alerts

def detect_lateral_movement(log_entries, threshold=5, time_window=300):
    # Phát hiện Lateral Movement dựa trên số lượng IP đích truy cập từ một IP nguồn
    src_ip_dsts = defaultdict(set)
    alerts = []
    current_time = time.time()

    for entry in log_entries:
        if entry['type'] == 'firewall':
            src_ip = entry['src_ip']
            dst_ip = entry['dst_ip']
            timestamp = time.mktime(time.strptime(entry['timestamp'], '%b %d %H:%M:%S %Y'))
            if current_time - timestamp <= time_window:
                src_ip_dsts[src_ip].add(dst_ip)

    for src_ip, dst_ips in src_ip_dsts.items():
        if len(dst_ips) >= threshold:
            alerts.append(f"Phát hiện Lateral Movement từ IP: {src_ip} - Truy cập {len(dst_ips)} IP đích")
    return alerts

# Tính năng nâng cao mới
def detect_slow_rate_attack(log_entries, threshold=5, time_window=86400):
    # Phát hiện Slow Rate Attack (tấn công từ từ) dựa trên số lần thất bại trong thời gian dài
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
        if len(recent_attempts) >= threshold and max(timestamps) - min(timestamps) > time_window / 2:
            alerts.append(f"Phát hiện Slow Rate Attack từ IP: {ip} - {len(recent_attempts)} lần thất bại trong thời gian dài")
    return alerts

def detect_data_exfiltration(log_entries, byte_threshold=10000, time_window=300):
    # Phát hiện Data Exfiltration dựa trên lượng byte gửi đi bất thường
    ip_bytes = defaultdict(int)
    alerts = []
    current_time = time.time()

    for entry in log_entries:
        if entry['type'] == 'apache' and entry['status'] == 200:
            ip = entry['ip']
            timestamp = time.mktime(time.strptime(entry['timestamp'], '%d/%b/%Y:%H:%M:%S %z'))
            bytes_sent = entry.get('bytes', 0)  # Giả định log có trường bytes, nếu không thì cần thêm vào parser
            if current_time - timestamp <= time_window:
                ip_bytes[ip] += bytes_sent

    for ip, total_bytes in ip_bytes.items():
        if total_bytes >= byte_threshold:
            alerts.append(f"Phát hiện Data Exfiltration từ IP: {ip} - {total_bytes} bytes gửi đi")
    return alerts

def detect_advanced_anomaly(log_entries, time_window=3600, anomaly_threshold=2.5):
    # Phát hiện bất thường nâng cao dựa trên tốc độ yêu cầu và khoảng cách thời gian
    alerts = []
    ip_requests = defaultdict(list)
    current_time = time.time()

    for entry in log_entries:
        if entry['type'] == 'apache':
            ip = entry['ip']
            timestamp = time.mktime(time.strptime(entry['timestamp'], '%d/%b/%Y:%H:%M:%S %z'))
            if current_time - timestamp <= time_window:
                ip_requests[ip].append(timestamp)

    for ip, timestamps in ip_requests.items():
        if len(timestamps) < 2:
            continue
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        # Tính tốc độ yêu cầu (requests per second)
        request_rate = len(timestamps) / (max(timestamps) - min(timestamps)) if max(timestamps) != min(timestamps) else 0
        
        # Phát hiện nếu tốc độ hoặc khoảng cách thời gian bất thường
        if std_interval > 0 and any((interval - mean_interval) / std_interval > anomaly_threshold for interval in intervals):
            alerts.append(f"Phát hiện bất thường nâng cao từ IP: {ip} - Khoảng cách thời gian bất thường")
        elif request_rate > 1:  # Ngưỡng tốc độ có thể điều chỉnh
            alerts.append(f"Phát hiện bất thường nâng cao từ IP: {ip} - Tốc độ yêu cầu cao: {request_rate:.2f} req/s")

    return alerts

def detect_attacks(log_entries):
    # Tổng hợp tất cả các loại tấn công
    alerts = []
    alerts.extend(detect_brute_force(log_entries))
    alerts.extend(detect_port_scanning(log_entries))
    alerts.extend(detect_sql_injection(log_entries))
    alerts.extend(detect_xss(log_entries))
    alerts.extend(detect_behavior_anomaly(log_entries))
    alerts.extend(detect_command_injection(log_entries))
    alerts.extend(detect_lateral_movement(log_entries))
    # Thêm các tính năng nâng cao
    alerts.extend(detect_slow_rate_attack(log_entries))
    alerts.extend(detect_data_exfiltration(log_entries))
    alerts.extend(detect_advanced_anomaly(log_entries))
    return alerts