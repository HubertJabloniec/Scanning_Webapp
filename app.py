#Hubert Jabloniec
#14/04/25
#
#This webapp combines few scanning tools into one application that can be hosted on a webserver

#Import Statements
from flask import Flask, render_template, request
import subprocess
import requests

#App name
app = Flask(__name__)

#Create Route
@app.route('/', methods=['GET', 'POST'])

#Index function
def index():

#Default Values
    scan_result = ''
    whois_result = ''
    dig_result = ''
    traceroute_result = ''
    geolocation_result = ''
    vuln_result = ''
    error_message = ''

#Redirect form requests to functions
    if request.method == 'POST':
        target = request.form['target']
        selected_tools = request.form.getlist('tools')
        nmap_scan_type = request.form.get('nmap_scan_type', 'fast')
        custom_scan_args = request.form.getlist('custom_scan_args')
        port_range = request.form.get('port_range', '')

        # Set dynamic timeout value based on scan type -- can edit if takes too long
        if nmap_scan_type == 'fast':
            timeout_value = 20
        elif nmap_scan_type == 'os':
            timeout_value = 60
        elif nmap_scan_type == 'full':
            timeout_value = 90
        elif nmap_scan_type == 'custom':
            timeout_value = 120
        else:
            timeout_value = 30

        try:
            # Nmap Scan
            if 'nmap' in selected_tools:
                nmap_args = ['nmap']
                if nmap_scan_type == 'fast':
                    nmap_args += ['-T4', '-F', target]
                elif nmap_scan_type == 'os':
                    nmap_args += ['-A', target]
                elif nmap_scan_type == 'full':
                    nmap_args += ['-p-', target]
		#Can add extra prompts later
                elif nmap_scan_type == 'custom':
                    nmap_args += custom_scan_args
                    if port_range:
                        nmap_args += ['-p', port_range]
                    nmap_args.append(target)

                if '-sU' in custom_scan_args:
                    nmap_args.append('-sU')
                scan_result = subprocess.check_output(
                    nmap_args,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    timeout=timeout_value
                )

            # Whois Scan
            if 'whois' in selected_tools:
                whois_result = subprocess.check_output(
                    ['whois', target],
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    timeout=10
                )

            # Dig Scan
            if 'dig' in selected_tools:
                dig_result = subprocess.check_output(
                    ['dig', target],
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    timeout=10
                )

            # Traceroute Scan
            if 'traceroute' in selected_tools:
                traceroute_result = subprocess.check_output(
                    ['traceroute', target],
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    timeout=20
                )

            # Geolocation Lookup --requires ipinfo.io account and API token
            if 'geolocation' in selected_tools:
                try:
                    geo_response = requests.get(f'https://ipinfo.io/{target}/json', timeout=10)
                    if geo_response.status_code == 200:
                        geolocation_result = geo_response.json()
                    else:
                        geolocation_result = {'status': geo_response.status_code, 'error': geo_response.json()}
                except Exception as e:
                    geolocation_result = {'error': str(e)}

            # Vulnerability Scan
            if 'vulnscan' in selected_tools:
                try:
                    vuln_cmd = ['nmap', '-sV', '--script', 'vulners', target]
                    vuln_result_raw = subprocess.check_output(vuln_cmd, stderr=subprocess.STDOUT, text=True, timeout=60)

                    # Extract CVE details from the raw output
                    vulnerabilities = []
                    for line in vuln_result_raw.splitlines():
                        if line.startswith("|     CVE-"):
                            # Extracting CVE ID, CVSS score, and link
                            cve_details = line.strip().split()
                            cve_id = cve_details[0]
                            cvss_score = cve_details[1]
                            cve_link = cve_details[2]
                            vulnerabilities.append({'cve_id': cve_id, 'cvss_score': cvss_score, 'link': cve_link})

                    # Format the vulnerabilities for display
                    if vulnerabilities:
                        vuln_result = "\n".join([f"{vuln['cve_id']} (CVSS: {vuln['cvss_score']}) - {vuln['link']}" for vuln in vulnerabilities])
                    else:
                        vuln_result = "No vulnerabilities found."
                except subprocess.CalledProcessError as e:
                    vuln_result = f"Error running vulnerability scan: {e.output}"
                except subprocess.TimeoutExpired:
                    vuln_result = "Vulnerability scan timed out."

        except subprocess.CalledProcessError as e:
            error_message = f"Command failed: {e.output}"
        except subprocess.TimeoutExpired:
            error_message = "Command timed out. Try a simpler scan or check the target."

    return render_template('index.html', scan_result=scan_result, whois_result=whois_result,
                           dig_result=dig_result, traceroute_result=traceroute_result,
                           geolocation_result=geolocation_result, vuln_result=vuln_result,
                           error_message=error_message, request=request)

if __name__ == '__main__':
    app.run(debug=True)
