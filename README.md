# Apache to Nginx Configuration Conversion Script

This bash script automates the conversion of Apache configuration files to Nginx configuration files. It supports additional features like rate limiting, untrusted content handling, and directory traversal protection.


##### I developed this script to streamline the conversion of over 200+ virtual hosts from Apache to Nginx, tailored precisely to meet our infrastructure's requirements. Sensitive data and configurations have been sanitized for this public release. The script significantly reduced the time and effort required for our migration, enabling us to transition numerous vHosts efficiently.

This tool served as an invaluable resource during our migration process, but please note that it was designed with specific use cases in mind. As such, while it has proven reliable in our environment, I strongly recommend that you thoroughly review and test it within your own setup before deploying it to production.

Use at your own risk.

## Features

- **Automatic Conversion**: Converts Apache virtual host configurations to Nginx.
- **Rate Limiting**: Option to enable request rate limiting and connection limits.
- **Untrusted Content Handling**: Configurable restriction on PHP execution in specific directories.
- **Directory Traversal Protection**: Adds protection against directory traversal attacks.
- **SSL/TLS Support**: Automatically configures SSL/TLS if valid certificates are detected.
- **Dry Run Mode**: Preview Nginx configurations before applying changes.
- **Logging**: Logs all actions and outputs to a secure log file.

## Prerequisites

- **Apache**: Ensure Apache is installed and your configuration files are in the default `/etc/apache2/sites-available` directory.
- **Nginx**: Ensure Nginx is installed and properly configured.
- **PHP-FPM**: PHP-FPM must be installed and running for PHP sites.
- **OpenSSL**: Used for verifying SSL certificates.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/apache-to-nginx-conversion.git
    cd apache-to-nginx-conversion
    ```

2. Make the script executable:
    ```bash
    chmod +x convert_apache_to_nginx.sh
    ```

3. Run the script with your desired options.

## Usage


```bash
./convert_apache_to_nginx.sh [options]
```
## Options
--dry-run: Enables dry run mode to preview configurations without applying changes.
--enable-rate-limiting: Enables rate limiting for requests and connections.
--enable-untrusted-content-handling: Restricts PHP execution in certain directories.
--enable-directory-traversal-protection: Protects against directory traversal attacks.


## Example command
```bash
./convert_apache_to_nginx.sh --enable-rate-limiting --enable-directory-traversal-protection
```
## Logs
  The script logs its actions to /var/log/nginx_conversion.log. Check this file for detailed output and any errors encountered during the conversion process.

## Backup
 The script automatically backs up any existing Nginx configurations before generating new ones. Backup files are saved with a .bak extension.

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer
This script is provided as-is. Use it at your own risk. Always verify the generated configurations before deploying them to a production environment.

## Authors

- [@razamoh](https://www.github.com/razamoh)
