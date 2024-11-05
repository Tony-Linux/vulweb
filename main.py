import requests
import myinfo
import argparse

def check_security_headers(url):
    security_headers = {
        'Strict-Transport-Security': "This header enforces HTTPS, protecting against man-in-the-middle attacks.",
        'Content-Security-Policy': "Helps prevent XSS attacks by controlling the sources from which content can be loaded.",
        'X-Content-Type-Options': "Prevents browsers from interpreting files as a different MIME type, mitigating content type sniffing.",
        'X-Frame-Options': "Stops clickjacking by preventing the site from being embedded in frames.",
        'X-XSS-Protection': "Provides basic protection against reflected XSS attacks in some browsers.",
        'Referrer-Policy': "Controls how much referrer information is passed when navigating to other pages.",
        'Permissions-Policy': "Controls access to features like camera or microphone, limiting them to specific origins."
    }
    
    try:
        response = requests.get(url)
        missing_headers = {header: desc for header, desc in security_headers.items() if header not in response.headers}
        return missing_headers
    except requests.RequestException as e:
        return {str(e): "An error occurred while checking security headers."}

def main():
    parser = argparse.ArgumentParser(description="Scan a website for security vulnerabilities and information.")
    parser.add_argument('--url', required=True, help='The URL of the domain to scan (e.g., http://example.com or https://example.com)')
    args = parser.parse_args()

    domain = args.url
    
    whois_info = myinfo.get_whois_info(domain)
    if 'error' not in whois_info:
        formatted_whois = myinfo.format_whois_info(whois_info)
        print(f"Domain Name : {formatted_whois['domain_name']}")
        print(f"Registry Expiry Date : {formatted_whois['registry_expiry_date']}")
    else:
        print(whois_info['error'])

    ip_address = myinfo.resolve_domain_to_ip(domain)
    if isinstance(ip_address, dict) and 'error' in ip_address:
        print(ip_address['error'])
    else:
        ip_info = myinfo.get_ip_geolocation(ip_address)
        if 'error' not in ip_info:
            formatted_ip_info = myinfo.format_ip_info(ip_address, ip_info)
            print(f"IP Address : {formatted_ip_info['ip_address']}")
            print(f"City: {formatted_ip_info['city']}")
            print(f"Country : {formatted_ip_info['country']}")
        else:
            print(ip_info['error'])

    missing_headers = check_security_headers(domain)
    if missing_headers:
        print("Missing Security Headers and their implications:")
        for header, description in missing_headers.items():
            print(f"- {header}: {description}")
    else:
        print("All security headers are present.")

if __name__ == "__main__":
    main()
