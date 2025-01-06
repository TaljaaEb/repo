# Use a Python base image
FROM python:3.9-slim

#RUN pip install -r requirements.txt

# Update and install OpenSSL and other dependencies
RUN apt-get update && apt-get install -y \
    openssl \
    && apt-get clean

# Set the working directory inside the container
WORKDIR /auth

#RUN openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt -subj "/CN=localhost"

# Copy the necessary files into the container
COPY auth.py /auth/
COPY server.crt /auth/
COPY server.key /auth/

# Expose the HTTPS port
EXPOSE 8443

# Run the Python HTTPS server
CMD ["python3", "auth.py"]
