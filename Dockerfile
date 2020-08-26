FROM python:3.8-alpine

RUN pip install pipenv
RUN apk add build-base

RUN adduser -D app
USER app

WORKDIR /app
COPY . /app

RUN pipenv install --system
ENTRYPOINT ["python3", "main.py"]
