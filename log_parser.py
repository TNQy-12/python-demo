import re

def parse_apache_log(line):
    # Phân tích log Apache với cú pháp cơ bản
    pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.+?)\] "(\w+ .*?)" (\d+)'
    match = re.match(pattern, line)
    if match:
        ip, timestamp, request, status = match.groups()
        return {'type': 'apache', 'ip': ip, 'timestamp': timestamp, 'request': request, 'status': int(status)}
    return None

def parse_firewall_log(line):
    # Phân tích log firewall cho port scanning
    pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+) firewall-1 kernel: \[BLOCK\] IN=eth0 SRC=(\d+\.\d+\.\d+\.\d+) DST=(\d+\.\d+\.\d+\.\d+) PROTO=TCP DPT=(\d+)'
    match = re.match(pattern, line)
    if match:
        timestamp, src_ip, dst_ip, dpt = match.groups()
        return {'type': 'firewall', 'src_ip': src_ip, 'dst_ip': dst_ip, 'dpt': int(dpt), 'timestamp': timestamp}
    return None

def parse_log_line(line):
    # Kiểm tra từng loại log
    apache_entry = parse_apache_log(line)
    if apache_entry:
        return apache_entry
    firewall_entry = parse_firewall_log(line)
    if firewall_entry:
        return firewall_entry
    return None

def read_log_file(file_path):
    # Đọc file log và phân tích từng dòng, sử dụng mã hóa UTF-8
    with open(file_path, 'r', encoding='utf-8') as file:
        return [parse_log_line(line) for line in file.readlines() if parse_log_line(line)]