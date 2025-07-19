FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
COPY src ./src

RUN pip install --no-cache-dir .

ENV PYTHONPATH=/app/src

ENTRYPOINT ["python", "-m", "aws_scanner.cli.main"]
CMD ["--all"]