FROM python:3.11-slim

WORKDIR /app
COPY . .

RUN pip install -r requirements.txt

CMD ["gunicorn", "server:app", "--bind", "0.0.0.0:10000"]
