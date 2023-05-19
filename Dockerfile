FROM golang:1.20.4-alpine3.18

WORKDIR /app

COPY . .

RUN go build -o backend ./cmd

EXPOSE 8000

CMD ["./backend"]