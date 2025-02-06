# Use Python slim image to reduce size
FROM python:3.12-slim

WORKDIR /app

# Copy only the requirements file initially
COPY . .

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install dependencies
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# Expose the port that the app runs on
EXPOSE 4348/tcp 53/udp

# Command to run the application
CMD ["python", "main.py"]