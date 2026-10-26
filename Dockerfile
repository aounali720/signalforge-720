FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SF720_DB_PATH=/app/data/signalforge.sqlite
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock && useradd --create-home appuser
COPY . .
RUN mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
