FROM python:3.10-slim

WORKDIR /app
COPY ./src .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5005
CMD ["python", "policy-translator.py"]