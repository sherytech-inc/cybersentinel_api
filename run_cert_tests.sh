#!/bin/bash
source venv/bin/activate
uvicorn app.main:app --port 8000 &
PID=$!
echo "Waiting for server to start..."
sleep 4
pytest tests/certification/
EXIT_CODE=$?
kill $PID
exit $EXIT_CODE
