# Minimal Dockerfile — deliberately kept simple/clean so it does NOT contain
# the ".get(" / ".post(" token that would false-trigger the Go-Gin route regex
# bug documented separately. This lets you verify the exposure classifier's
# actual EXPOSE-based signal path in isolation.
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 443
CMD ["python", "src/prod/payment/checkout_controller.py"]
