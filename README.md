# VulWeb

VulWeb is a command-line tool designed to scan websites for security vulnerabilities, including missing security headers, WHOIS information, and IP geolocation data.

## Features

- Checks for common missing security headers and provides explanations for their importance.
- Retrieves WHOIS information for a specified domain.
- Resolves a domain to its IP address and retrieves geolocation information.

## Installation

You can install VulWeb using the following command:

```bash
sudo apt install vulweb
```

Make sure you have the required dependencies installed on your system. This typically includes Python and the `requests` library.

## Usage

Run the script from the command line using the following syntax:

```bash
vulweb --url <domain>
```

### Examples

To scan a website, you can use:

```bash
vulweb --url http://example.com
```

or

```bash
vulweb --url https://example.com
```

### Output

The script will output the following information:

- **Domain Name**: The domain name being scanned.
- **Registry Expiry Date**: The expiration date of the domain registration.
- **IP Address**: The resolved IP address of the domain.
- **City**: The city associated with the IP address.
- **Country**: The country associated with the IP address.
- **Missing Security Headers**: A list of any missing security headers along with their implications.

### Example Output

```bash
Domain Name: example.com
Registry Expiry Date: 2024-12-31
IP Address: 93.184.216.34
City: Los Angeles
Country: United States
Missing Security Headers and their implications:
- Strict-Transport-Security: This header enforces HTTPS, protecting against man-in-the-middle attacks.
- Content-Security-Policy: Helps prevent XSS attacks by controlling the sources from which content can be loaded.
```
### License

This project is licensed under the MIT License. See the LICENSE file for details.

### Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

### Contact

For any questions or feedback, please reach out at mrfidal@proton.me.
