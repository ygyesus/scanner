import requests
from bs4 import BeautifulSoup
import re
import urllib.parse
import time
import json
from collections import defaultdict

class WebVulnerabilityScanner:
    def __init__(self, target_url):

        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.visited_urls = set()
        self.vulnerabilities = defaultdict(list)

    def crawl(self, url):

        if url in self.visited_urls:
            return
        self.visited_urls.add(url)

        try:
            response = self.session.get(url)

            soup = BeautifulSoup(response.text, 'html.parser')


            self.check_xss(url, response.text)
            print("FINISHED XSS")

            self.check_sql_injection(url)
            print("FINISHED SQL INJECTION")

            self.check_open_redirects(url)
            print("FINISHED OPEN REDIRECTS")

            self.check_csrf(url, soup)
            print("FINISHED CSRF")

            self.check_clickjacking(url, response.headers)
            print("FINISHED CLICKJACKING")

            self.check_sensitive_data_exposure(url, response.text)
            print("FINISHED EXPOSURE")

            for link in soup.find_all('a', href=True):
                next_url = urllib.parse.urljoin(url, link['href'])
                if self.target_url in next_url and next_url not in self.visited_urls:
                    self.crawl(next_url)

        except Exception as e:
            print(f"Error crawling {url}: {str(e)}")

    def check_xss(self, url, content):

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>"
        ]


        for payload in xss_payloads:
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{url}?q={encoded_payload}"
            response = self.session.get(test_url)
            if payload in response.text:
                self.vulnerabilities['XSS'].append(f"Potential XSS vulnerability found at {test_url}")

    def check_sql_injection(self, url):

        sql_payloads = ["' OR '1'='1", "1 UNION SELECT null, username, password FROM users--"]

        for payload in sql_payloads:
            encoded_payload = urllib.parse.quote(payload)

            test_url = f"{url}?id={encoded_payload}"

            response = self.session.get(test_url)
            if "error in your SQL syntax" in response.text.lower():
                self.vulnerabilities['SQL Injection'].append(f"Potential SQL Injection vulnerability found at {test_url}")

    def check_open_redirects(self, url):
        redirect_payloads = ["https://example.com", "//google.com"]

        for payload in redirect_payloads:
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{url}?redirect={encoded_payload}"
            response = self.session.get(test_url, allow_redirects=False)

            if response.status_code in (301, 302) and payload in response.headers.get('Location', ''):
                self.vulnerabilities['Open Redirect'].append(f"Potential Open Redirect vulnerability found at {test_url}")

    def check_csrf(self, url, soup):

        forms = soup.find_all('form')
        for form in forms:

            if not form.find('input', {'name': 'csrf_token'}):
                self.vulnerabilities['CSRF'].append(f"Potential CSRF vulnerability found in form at {url}")

    def check_clickjacking(self, url, headers):

        if 'X-Frame-Options' not in headers:
            '''
            X-Frame-Options allows content publishers to prevent their own content
            from being used in an invisible frame by attackers.
            '''
            self.vulnerabilities['Clickjacking'].append(f"Potential Clickjacking vulnerability found at {url} (X-Frame-Options header missing)")

    def check_sensitive_data_exposure(self, url, content):

        patterns = {
            'Credit Card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'Social Security Number': r'\b\d{3}-\d{2}-\d{4}\b',
            'API Key': r'\b[A-Za-z0-9]{32,}\b'
        }


        for name, pattern in patterns.items():
            if re.search(pattern, content):  # If a match is found
                self.vulnerabilities['Sensitive Data Exposure'].append(f"Potential {name} exposure found at {url}")

    def run_scan(self):

        start_time = time.time()
        print(f"Starting vulnerability scan on {self.target_url}")

        self.crawl(self.target_url)
        end_time = time.time()
        print(f"\nScan completed in {end_time - start_time:.2f} seconds")
        self.generate_report()

    def generate_report(self):

        report = {
            "target_url": self.target_url,
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": dict(self.vulnerabilities),
            "urls_scanned": list(self.visited_urls)
        }

        with open("vulnerability_report.json", "w") as f:
            json.dump(report, f, indent=2)

        print("\nVulnerability Report:")
        for vuln_type, instances in self.vulnerabilities.items():
            print(f"\n{vuln_type}:")
            for instance in instances:
                print(f"  - {instance}")

        print(f"\nDetailed report saved to vulnerability_report.json")
        print(f"Total URLs scanned: {len(self.visited_urls)}")

def main():
    print("Web Application Vulnerability Scanner")
    target_url = input("Enter the target URL to scan: ")
    scanner = WebVulnerabilityScanner(target_url)
    scanner.run_scan()

if __name__ == "__main__":
    main()