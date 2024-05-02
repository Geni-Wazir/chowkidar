#!/bin/sh

echo "Starting Chowkidar"

# Start Gunicorn
# gunicorn -w 3 --timeout 200 --bind=0.0.0.0:5000 --log-level debug --error-logfile - --access-logfile - app:app &

flask run --host=0.0.0.0 &

# Start RQ Worker
rq worker --url redis://scheduler:6379/ task_queue