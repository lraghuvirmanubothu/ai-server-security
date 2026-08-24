import os
import re
from flask import Flask, render_template_string

app = Flask(__name__)

APACHE_LOG = "/var/log/apache2/access.log"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>AI Security Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f9; }
        h2 { color: #333; }
        table { width: 100%; border-collapse: collapse; background: #fff; }
        th, td { padding: 10px; border: 1px solid #ddd; text-align: left; }
        th { background: #333; color: #fff; }
        .status-200 { color: green; font-weight: bold; }
        .status-429 { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h2>Live Traffic Monitoring & Security Log</h2>
    <table>
        <tr>
            <th>#</th>
            <th>Client IP</th>
            <th>Endpoint</th>
            <th>HTTP Status</th>
            <th>Raw Log</th>
        </tr>
        {% for log in logs %}
        <tr>
            <td>{{ loop.index }}</td>
            <td>{{ log.ip }}</td>
            <td>{{ log.endpoint }}</td>
            <td class="status-{{ log.status }}">{{ log.status }}</td>
            <td>{{ log.raw }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

def parse_logs():
    parsed_logs = []

    if os.path.exists(APACHE_LOG):
        with open(APACHE_LOG, "r") as f:
            lines = f.readlines()

        log_pattern = re.compile(r'(\S+) - - \[.*?\] "GET (\S+) HTTP/\d\.\d" (\d{3})')

        for line in lines[-100:]:
            match = log_pattern.search(line)
            if match:
                ip, endpoint, status = match.groups()
                parsed_logs.append({
                    "ip": ip,
                    "endpoint": endpoint,
                    "status": status,
                    "raw": line.strip()
                })
    return parsed_logs

@app.route('/')
def index():
    logs = parse_logs()
    return render_template_string(HTML_TEMPLATE, logs=logs)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000)
