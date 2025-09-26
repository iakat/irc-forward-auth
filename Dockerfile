FROM python:3.13-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
WORKDIR /app
COPY requirements.lock /app
# Install dependencies
RUN uv pip install --system -r requirements.lock

COPY . /app
EXPOSE 8000
CMD ["python3", "app.py"]
ENV PYTHONUNBUFFERED=1
