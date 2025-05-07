# Use the official Python 3.11 image (since your project requires >=3.11)
FROM python:3.11-slim

# Set environment variables to prevent Python from writing .pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies (for packages like psycopg2, pdfplumber, pypandoc, etc.)
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    poppler-utils \
    pandoc \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Expose the Flask app's port (change if you're using a different one)
EXPOSE 8000

# Command to run the Flask app
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "main:app"]