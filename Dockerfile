FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y libpq-dev curl gnupg \
    && apt-get clean

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Copy and install Python dependencies
COPY pyproject.toml poetry.lock config.json ./
RUN pip install poetry
RUN poetry install --no-root

COPY app ./app
COPY .env .

CMD ["poetry", "run", "python", "src/main.py"]