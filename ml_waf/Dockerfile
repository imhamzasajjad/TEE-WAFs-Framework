# Use an official Python runtime as a parent image
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Create a virtual environment and install dependencies
RUN python -m venv myenv && \
    /app/myenv/bin/pip install --upgrade pip && \
    /app/myenv/bin/pip install -r requirements.txt && \
    /app/myenv/bin/pip install .

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Run the application using the virtual environment's Python
CMD ["/app/myenv/bin/python", "-m", "waf_brain", "-T", "--dump-file", "logs.txt", "-l", "0.0.0.0", "-A", "0.0.0.0:8000"]
