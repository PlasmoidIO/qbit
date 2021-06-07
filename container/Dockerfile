FROM golang:1.15.7-buster
RUN git clone https://github.com/plasmoidio/qbit
COPY qbit/server /app
WORKDIR /app
EXPOSE 4201
CMD ["go", "run", "."]