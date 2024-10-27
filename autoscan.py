import requests
import argparse
import json
import csv
from datetime import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

headers = {"Content-Type": "application/json"}

# Mengambil data json pada saat mengakses endpoint openapi.json
def fetch_openapi_spec(url, proxies=None):
    try:
        response = requests.get(url, proxies=proxies)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Failed to fetch OpenAPI spec: {e}")
        return None

# Membuat payload schema sesuai struktur API pada target aplikasi
def generate_payload_data(schema, payload):
    data = {}
    for prop in schema.get("properties", {}).keys():
        data[prop] = payload
    return data

# Membaca data payload yang akan digunakan untuk pengujian
def load_wordlist(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]

# Menyimpan hasil ke dalam csv file
def save_to_csv(results):
    # Membuat nama file csv berdasarkan tanggal bulan tahun
    filename = f"{datetime.now().strftime('%Y%m%d')}_autoscan.csv"
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ["Vulnerability", "URL", "Method", "Payload", "Response"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)
    print(f"\nResults saved to {filename}")
    return filename

# Mengirim hasil Vulnerability Scanner melalui email
def send_email(to_email, filename):
    from_email = "youremail@yourdomain"
    email_password = "yourpass"

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = "Vulnerability Scan Report"

    body = "Dear Muzakir, \r\r\nPlease find attached the vulnerability scan report. \r\r\nBest Regards, \r\nMuzakir"
    msg.attach(MIMEText(body, 'plain'))

    # Melampirkan dokumen csv
    with open(filename, "rb") as attachment:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f"attachment; filename= {filename}")
        msg.attach(part)

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, email_password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print(f"Email sent successfully to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Membuat fungsi validasi sesuai kerentanan yang ditemukan ketika mendapatkan respon dari aplikasi
def autoscan(url, method, schema, wordlist, proxies=None, results=[]):
    vulnerabilities = {
        "Host Header Injection": {"payload": "openapi", "header": {"Host": "http://localhost"}},
        "Local File Inclusion": {"keyword": "root:"},
        "Remote File Inclusion": {"keyword": "<!DOCTYPE html>"},
        "SQL Injection": {"payloads": ["'testingsqli", "''testingsqli"]},
        "Server Side Template Injection": {"keyword": "1001"},
        "XSS": {"keyword": "('muzaxss{{30-5}}')"}
    }

    # hanya mengirimkan 1 data dari serangan Host Header Injection yang paling relevan
    for vuln_name, vuln_data in vulnerabilities.items():
        if vuln_name == "Host Header Injection":
            data = generate_payload_data(schema, vuln_data["payload"])
            custom_headers = headers.copy()
            custom_headers.update(vuln_data["header"])
            if method == "post":
                response = requests.post(url, headers=custom_headers, json=data, proxies=proxies)
                if "localhost" in response.text:
                    tampilkan_data(vuln_name, url, method, data, response, results)
                    break

    for vuln_name, vuln_data in vulnerabilities.items():
        # Laporan Serangan SQL Injection hanya menampilkan endpoint yang rentan berdasarkan serangan error-based SQL Injection
        if vuln_name == "SQL Injection":
            for payload in vuln_data["payloads"]:
                data = generate_payload_data(schema, payload)
                response = requests.post(url, headers=headers, json=data, proxies=proxies)
                if payload == "'testingsqli" and "syntax error" in response.text:
                    normal_payload = "''testingsqli"
                    normal_data = generate_payload_data(schema, normal_payload)
                    response = requests.post(url, headers=headers, json=normal_data, proxies=proxies)
                    if "syntax error" not in response.text:
                        tampilkan_data(vuln_name, url, method, data, response, results)
        else:
            for payload in wordlist:
                data = generate_payload_data(schema, payload)
                custom_headers = headers.copy()

                if "header" in vuln_data:
                    custom_headers.update(vuln_data["header"])

                if method == "get":
                    response = requests.get(url, headers=custom_headers, params=data, proxies=proxies)
                elif method == "post":
                    response = requests.post(url, headers=custom_headers, json=data, proxies=proxies)
                else:
                    continue

                if "keyword" in vuln_data and vuln_data["keyword"] in response.text:
                    tampilkan_data(vuln_name, url, method, data, response, results)

# Menampilkan informasi datail mengenai kerentanan yang ditemukan di dalam aplikasi 
def tampilkan_data(vuln_name, url, method, data, response, results):
    print(f"\n{vuln_name} detected at {url} using {method.upper()} method")
    print("Request:")
    print(f"{method.upper()} {url}")
    print("Payload:", data)
    print("\nResponse:")
    print(response.text)
    results.append({
        "Vulnerability": vuln_name,
        "URL": url,
        "Method": method.upper(),
        "Payload": json.dumps(data),
        "Response": response.text[:200]
    })

# Melakukan proses pengujian terhadap aplikasi dengan memanggil fungsi autoscan berdasarkan path API
def process_paths(base_url, paths, components, wordlist, proxies=None):
    results = []
    for path, methods in paths.items():
        for method, details in methods.items():
            if method in ["get", "post"]:
                schema_ref = details.get("requestBody", {}).get("content", {}).get("application/json", {}).get("schema", {}).get("$ref")
                schema = components.get("schemas", {}).get(schema_ref.split("/")[-1]) if schema_ref else {}
                autoscan(f"{base_url}{path}", method, schema, wordlist, proxies, results)
    report_file = save_to_csv(results)
    return report_file

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Auto scanner for vulnerabilities on Swagger API')
    parser.add_argument('-u', '--url', required=True, help='The OpenAPI URL (e.g., http://127.0.0.1:8000/api/openapi.json)')
    parser.add_argument('-p', '--proxy', help='The proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('-w', '--wordlist', required=True, help='File containing payloads (e.g., wordlists.txt)')
    parser.add_argument('-e', '--email', required=True, help='Email address to send the report to (e.g., yourmail@yourdomain.com)')
    args = parser.parse_args()
    base_url = args.url.rsplit('/', 1)[0]
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    wordlist = load_wordlist(args.wordlist)

    openapi_spec = fetch_openapi_spec(args.url, proxies=proxies)
    if openapi_spec:
        components = openapi_spec.get("components", {})
        report_file = process_paths(base_url, openapi_spec.get("paths", {}), components, wordlist, proxies=proxies)
        send_email(args.email, report_file)
