FROM otel/opentelemetry-collector-contrib
ADD collector-config.yaml /etc/otelcol-contrib/config.yaml
EXPOSE 4317
EXPOSE 4318
ENV AWS_ACCESS_KEY_ID="PUT_ACCESS_KEY_ID_HERE"
ENV AWS_SECRET_ACCESS_KEY="PUT_SECRET_ACCESS_KEY_HERE"