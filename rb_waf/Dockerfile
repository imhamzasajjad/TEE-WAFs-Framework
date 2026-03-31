# Use the official Ubuntu image as a base
FROM ubuntu:latest

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
