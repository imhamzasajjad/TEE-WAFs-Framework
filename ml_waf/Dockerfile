# Use an official Python runtime as a parent image
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Copy dependency metadata and the WAF-Brain package first so dependency
# installation remains cached when a provider adapter changes.
COPY requirements.txt setup.py VERSION MANIFEST.in README.rst /app/
COPY waf_brain /app/waf_brain

# Create a virtual environment and install dependencies
RUN python -m venv myenv && \
    /app/myenv/bin/pip install --upgrade pip && \
    /app/myenv/bin/pip install -r requirements.txt && \
    /app/myenv/bin/pip install .

# Copy provider adapters and the remaining project files after dependencies.
COPY . /app

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Select the provider at runtime through ML_WAF_PROVIDER. WAF-Brain remains
# the default; external providers will use the same adapter entrypoint.
RUN chmod +x /app/entrypoint.sh
CMD ["/app/entrypoint.sh"]
