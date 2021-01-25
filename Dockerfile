FROM python:3.8 AS builder

WORKDIR /usr/src/app

COPY Pipfile Pipfile.lock ./

RUN pip install pipenv \
    && pipenv install --system


FROM python:3.8-slim

ENV PYTHONUNBUFFERED=1

COPY --from=builder /usr/local/lib/python3.8/site-packages /usr/local/lib/python3.8/site-packages

COPY . ./

RUN python manage.py crontab add

RUN python manage.py migrate

CMD ["python","manage.py","runserver","0.0.0.0:8000"]