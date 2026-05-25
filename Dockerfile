FROM nginx:alpine

# Install python3, gdu, bash, and curl
RUN apk add --no-cache python3 gdu bash curl

# Remove default nginx welcome page
RUN rm -rf /usr/share/nginx/html/*

# Copy the local webdiskstat.py into the image
COPY webdiskstat.py /usr/local/bin/webdiskstat.py
RUN chmod +x /usr/local/bin/webdiskstat.py

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set working directory
WORKDIR /usr/share/nginx/html

# Expose port 80
EXPOSE 80

# Run entrypoint
ENTRYPOINT ["/entrypoint.sh"]
