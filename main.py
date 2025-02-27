from flask import Flask, render_template
from log_parser import read_log_file
from attack_detector import detect_attacks

app = Flask(__name__)

def process_log(file_path):
    # Đọc log và phát hiện tấn công
    log_entries = read_log_file(file_path)
    alerts = detect_attacks(log_entries)
    return alerts

@app.route('/')
def dashboard():
    log_file = "logs/sample_attack.log"
    alerts = process_log(log_file)
    
    if not alerts:
        alerts = ["Không phát hiện tấn công nào."]
    
    return render_template('dashboard.html', alerts=alerts)

if __name__ == "__main__":
    app.run(debug=True)