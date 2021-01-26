FROM python:3.8 AS builder

WORKDIR /usr/src/app

COPY Pipfile Pipfile.lock ./

RUN pip install pipenv \
    && pipenv install --system


FROM python:3.8-slim

ENV PYTHONUNBUFFERED=1

ENV TZ=Asia/Tokyo

COPY --from=builder /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages

WORKDIR /app

COPY . ./

RUN apt update

RUN apt-get install -y cron

RUN /etc/init.d/cron restart

RUN python manage.py crontab add

RUN python manage.py migrate

RUN chmod +x docker_start.sh

CMD ["./docker_start.sh"]