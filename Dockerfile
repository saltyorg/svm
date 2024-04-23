FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /app

# Install dependencies
COPY /app/ /app/
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Expose the Flask run port
EXPOSE 8000

# Start gunicorn
CMD ["uvicorn", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "app:app"]
