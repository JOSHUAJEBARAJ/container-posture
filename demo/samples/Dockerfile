FROM ubuntu:latest

ENV DB_PASSWORD=supersecret123
ENV API_KEY=sk-prod-abcdef1234567890

COPY .env /app/.env

RUN apt-get update && apt-get install -y sudo curl
RUN chmod 777 /app

VOLUME /var/run/docker.sock

CMD ["/app/start.sh"]
