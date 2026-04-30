FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Directory for the SQLite database volume mount
RUN mkdir -p /app/data

EXPOSE 5000

# Convert Windows CRLF → LF so the script runs correctly inside Linux container
RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh

ENTRYPOINT ["sh", "entrypoint.sh"]
