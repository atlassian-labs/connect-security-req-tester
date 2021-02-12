FROM python:3.9-slim

RUN pip install pipenv
RUN apt update && apt install build-essential -y

RUN useradd -m app
USER app

WORKDIR /app
COPY . /app

RUN pipenv install --system
ENTRYPOINT ["python3", "main.py"]
