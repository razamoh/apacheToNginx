#!/bin/bash

# Apache to Nginx Configuration Conversion Script
# Developed by razamoh - https://github.com/razamoh
# This script automates the migration of Apache virtual host configurations to Nginx.
# Use this script at your own risk. Always review the generated configurations before deploying to production.


# Default paths for Apache and Nginx configurations
APACHE_SITES_AVAILABLE="/etc/apache2/sites-available"
NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"

# Default SSL certificate paths (can be overridden)
DEFAULT_SSL_CERT_PATH="/etc/letsencrypt/live"
DEFAULT_SSL_KEY_PATH="/etc/letsencrypt/live
# Default dry run mode (false)
DRY_RUN=false

# Feature toggles
HANDLE_UNTRUSTED_CONTENT=false
RATE_LIMITING=false
DIRECTORY_TRAVERSAL_PROTECTION=false

# Rate limiting default values
RATE_LIMIT_ZONE="one:10m"
RATE_LIMIT="30r/m"
BURST_LIMIT="10"
CONNECTION_LIMIT="10"

# Secure log location
LOG_FILE="/var/log/nginx_conversion.log"

# Function to log messages with a timestamp
log() {
    local message="$1"
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $message" | tee -a "$LOG_FILE"
}

# Function to extract a specified directive from an Apache configuration file
extract_apache_directive() {
    local directive="$1"
    local apache_conf_file="$2"
    grep -i "^[^#]*${directive}" "$apache_conf_file" | awk '{$1=""; gsub(/^[ \t]+|[ \t]+$/, "", $0); print $0; exit}' 2>/dev/null
}

# Function to detect the PHP-FPM socket
detect_php_fpm_socket() {
    local socket_path=$(find /var/run/php/ -name "php*-fpm.sock" | head -n 1)
    if [ -z "$socket_path" ]; then
        log "Error: PHP-FPM socket not found. Please ensure PHP-FPM is installed and running."
        return 1
    fi
    echo "$socket_path"
}

# Function to verify SSL certificates
verify_ssl_certificates() {
    local server_name="$1"
    local cert_path="${2:-$DEFAULT_SSL_CERT_PATH}/${server_name}/fullchain.pem"
    local key_path="${3:-$DEFAULT_SSL_KEY_PATH}/${server_name}/privkey.pem"

    # Verify that certificates exist and are valid
    if [[ -f "$cert_path" && -f "$key_path" ]]; then
        if openssl x509 -checkend 86400 -noout -in "$cert_path" > /dev/null; then
            echo "$cert_path $key_path"
        else
            log "Warning: SSL certificates for $server_name are either expired or invalid. Skipping HTTPS configuration."
            echo ""
        fi
    else
        log "Warning: SSL certificates not found for $server_name. Skipping HTTPS configuration."
        echo ""
    fi
}


# Function to generate Nginx configuration based on extracted directives
generate_nginx_config() {
    local server_name="$1"
    local nginx_conf_file="$2"
    local php_fpm_socket="$3"
    local ssl_certificates="$4"

    # Directory traversal protection pattern
    local directory_traversal_pattern='(\.\./|\.\.\\)'

    cat <<EOF >"$nginx_conf_file"
server {
    listen 80;
    listen [::]:80;
    server_name ${server_name};
    root /var/www/html/${server_name}/;
    index index.php index.html index.htm;

    # Logging
    access_log /var/log/nginx/${server_name}_access.log;
    error_log /var/log/nginx/${server_name}_error.log;

    # Rate limiting (if enabled)
    $(if [ "$RATE_LIMITING" = true ]; then
    cat <<RATE_LIMIT
    limit_req_zone \$binary_remote_addr zone=${RATE_LIMIT_ZONE} rate=${RATE_LIMIT};
    limit_conn_zone \$binary_remote_addr zone=addr:10m;

    location / {
        limit_req zone=one burst=${BURST_LIMIT} nodelay;
        limit_conn addr ${CONNECTION_LIMIT};
        try_files \$uri \$uri/ =404;
    }
RATE_LIMIT
    else
        echo "location / { try_files \$uri \$uri/ =404; }"
    fi)

    # PHP configurations (restrict execution if enabled)
    $(if [ "$HANDLE_UNTRUSTED_CONTENT" = true ]; then
    cat <<UNTRUSTED_CONTENT
    location ~ ^/some-restricted-directory/.*\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${php_fpm_socket}; 
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
        deny all;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${php_fpm_socket};
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
        allow all;
    }
UNTRUSTED_CONTENT
    else
        echo "location ~ \.php$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:${php_fpm_socket};
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    include fastcgi_params;
}"
    fi)

    # Directory traversal protection (if enabled)
    $(if [ "$DIRECTORY_TRAVERSAL_PROTECTION" = true ]; then
    cat <<TRAVERSAL_PROTECTION
    location ~* ${directory_traversal_pattern} {
        return 403;
    }
TRAVERSAL_PROTECTION
    fi)

    # SSL configurations (if available)
    $(if [[ -n "$ssl_certificates" ]]; then
    cat <<SSL
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    ssl_certificate $(echo "$ssl_certificates" | awk '{print $1}');
    ssl_certificate_key $(echo "$ssl_certificates" | awk '{print $2}');
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1h;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
SSL
    fi)
}

server {
    if (\$host = www.${server_name}) {
        return 301 https://\$host\$request_uri;
    }

    if (\$host = ${server_name}) {
        return 301 https://\$host\$request_uri;
    }

    listen 80;
    listen [::]:80;

    server_name www.${server_name} ${server_name};
    return 404;
}
EOF

    if [ "$DRY_RUN" = true ]; then
        log "Dry run mode: The following Nginx configuration would be created for ${server_name}:"
        cat "$nginx_conf_file"
        rm "$nginx_conf_file"
    else
        log "Nginx configuration generated for ${server_name} at ${nginx_conf_file}"
    fi
}

# Function to convert Apache configurations to Nginx
convert_apache_to_nginx() {
    for apache_conf_file in "$APACHE_SITES_AVAILABLE"/*.conf; do
        # Skip excluded configurations
        case "$(basename "$apache_conf_file")" in
            000-default.conf | default.conf | default-ssl.conf)
                log "Skipping $(basename "$apache_conf_file")"
                continue ;;
        esac

        # Check if the Apache config file is non-empty
        if [ ! -s "$apache_conf_file" ]; then
            log "Skipping empty configuration file: $(basename "$apache_conf_file")"
            continue
        fi

        # Extract ServerName from Apache configuration
        local server_name
        server_name=$(extract_apache_directive "ServerName" "$apache_conf_file")
        if [ -z "$server_name" ]; then
            log "Error: Missing or invalid ServerName in $(basename "$apache_conf_file"). Skipping."
            continue
        fi

        # Validate ServerName format to avoid injection or other issues
        if [[ ! "$server_name" =~ ^[a-zA-Z0-9.-]+$ ]]; then
            log "Error: Invalid ServerName format in $(basename "$apache_conf_file"). Skipping."
            continue
        fi

        # Set the Nginx configuration file path
        local nginx_conf_file="$NGINX_SITES_AVAILABLE/${server_name}.conf"

        # Backup existing Nginx configuration if it exists
        if [ -f "$nginx_conf_file" ]; then
            mv "$nginx_conf_file" "$nginx_conf_file.bak"
            log "Backup existing Nginx configuration for ${server_name} to ${nginx_conf_file}.bak"
        fi

        # Detect PHP-FPM socket
        local php_fpm_socket
        php_fpm_socket=$(detect_php_fpm_socket)
        if [ -z "$php_fpm_socket" ]; then
            log "Skipping ${server_name} due to missing PHP-FPM socket."
            continue
        fi

        # Verify SSL certificates
        local ssl_certificates
        ssl_certificates=$(verify_ssl_certificates "$server_name")

        # Generate Nginx configuration
        generate_nginx_config "$server_name" "$nginx_conf_file" "$php_fpm_socket" "$ssl_certificates"

        # Enable the site if not in dry run mode
        if [ "$DRY_RUN" = false ]; then
            ln -sf "$nginx_conf_file" "$NGINX_SITES_ENABLED/"
            log "Site enabled: ${server_name}"
        fi
    done
}

# Main execution
log "Starting Apache to Nginx configuration conversion..."

convert_apache_to_nginx

log "Conversion completed."

