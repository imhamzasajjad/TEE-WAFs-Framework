#!/bin/bash

set -e

apt-get update -y

# Install necessary packages
apt-get install gnupg2 software-properties-common curl wget git unzip -y

# Add repository for Apache2
add-apt-repository ppa:ondrej/apache2 -y
apt-get update -y

# Install Apache2 and ModSecurity
apt-get install apache2 -y
apt-get install libapache2-mod-security2 -y

# Enable security module
a2enmod security2

# Move and edit modsecurity.conf
mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

# Enable ModSecurity in the Apache configuration
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# Restart Apache service
service apache2 restart

# Use distro-provided CRS configuration from libapache2-mod-security2.
# Avoiding manual CRS download prevents duplicate rule-id loading errors.

# Test Apache configuration
apache2ctl -t

# Install curl
apt-get install curl -y

# Test ModSecurity installation
#curl http://localhost/index.html?exec=/bin/bash

# Check ModSecurity audit log
#tail /var/log/apache2/modsec_audit.log
