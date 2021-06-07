FROM golang:1.15.7-buster
RUN mkdir -p /app
COPY . /app
WORKDIR /app/server
EXPOSE 80
CMD ["go", "run", "."]