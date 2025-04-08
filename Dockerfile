# Container definition

FROM python:3.10-slim
WORKDIR /app
COPY . /app
RUN pip install fastapi uvicorn python-jose requests
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80"]

# nawabkhan5016