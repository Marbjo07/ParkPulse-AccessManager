# syntax=docker/dockerfile:1

ARG PYTHON_VERSION=3.12.2
FROM python:${PYTHON_VERSION}-slim as base

# Prevents Python from writing pyc files.
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /usr/src/app

ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser

RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=bind,source=requirements.txt,target=requirements.txt \
    python -m pip install -r requirements.txt
    
COPY . .
    
RUN [ ! -f log.txt ] && touch log.txt
RUN [ ! -f access_manager.state  ] && touch access_manager.state 

RUN chown appuser:appuser log.txt
RUN chmod 664 log.txt

RUN chown appuser:appuser access_manager.state 
RUN chmod 664 access_manager.state 

# Switch to the non-privileged user to run the application.
USER appuser

# Copy the source code into the container.
COPY gunicorn_config.py /app/gunicorn_config.py

# Expose the port that the application listens on.
EXPOSE 5000
ENV PYTHONPATH=/usr/src/app/app
# Run the application.
CMD ["gunicorn", "-w", "1", "-c", "gunicorn_config.py", "app:app", "-b", ":5000"]