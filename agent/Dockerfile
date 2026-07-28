FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY run.py .
RUN useradd --create-home --uid 10001 agent \
    && mkdir -p /artifacts \
    && chown -R agent:agent /app /artifacts
USER agent
CMD ["python", "/app/run.py"]
