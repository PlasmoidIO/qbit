FROM golang:1.15.7-buster
RUN git clone https://github.com/plasmoidio/qbit
RUN cp -r qbit /app
WORKDIR /app/server
EXPOSE 4201
CMD ["go", "run", "."]