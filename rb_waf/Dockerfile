# Use the official Ubuntu image as a base
# Pin the base image to an LTS release. Third-party PPAs often lag behind
# Ubuntu development releases (for example, "resolute").
FROM ubuntu:24.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Copy the install script into the container
COPY install_modsecurity.sh /install_modsecurity.sh

# Normalize line endings and make script executable
RUN sed -i 's/\r$//' /install_modsecurity.sh && chmod +x /install_modsecurity.sh

# Run the install script
RUN bash /install_modsecurity.sh

# Expose the default Apache port
EXPOSE 80

# Start Apache in the foreground
CMD ["apache2ctl", "-D", "FOREGROUND"]
