import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from flask import Flask, render_template, request
from fingerprint.nmap_scan import NetworkScanner
from analysis.port_explainer import explain_ports

app = Flask(__name__)

@app.route('/')
def index(): 
    return render_template('index.html')

@app.route('/scanner')
def scanner_page(): 
    return render_template('scanner.html')

@app.route('/discover', methods=['POST'])
def discover():
    target_range = request.form.get('target')
    scanner = NetworkScanner()
    active_hosts = scanner.discover_hosts(target_range)
    return render_template('select_host.html', hosts=active_hosts, range=target_range)

@app.route('/deep_scan', methods=['POST'])
def deep_scan():
    target_ip = request.form.get('target_ip')
    mode = request.form.get('mode')
    scanner = NetworkScanner()
    raw_data = scanner.run_deep_scan(target_ip, mode)
    
    # FIX: Initialize the list name correctly to match the return statement
    processed_output = [] 
    
    for host in raw_data:
        ports = []
        for proto in host.all_protocols():
            for port in host[proto].keys():
                s = host[proto][port]
                ports.append({
                    'port': port, 
                    'name': s['name'], 
                    'product': s['product'], 
                    'version': s['version']
                })
        
        analysis, summary = explain_ports(ports)
        processed_output.append({"ip": target_ip, "analysis": analysis, "summary": summary})
    
    # DEBUG: Check your terminal to see if data is actually being found
    print(f"DEBUG: Processed Output = {processed_output}")
    
    return render_template('results.html', results=processed_output)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
