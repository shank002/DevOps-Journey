FROM python:3.12-slim
WORKDIR /app
RUN groupadd -r api && useradd -r -g api apiuser
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api/app.py .
USER apiuser
CMD ["python", "app.py"]

