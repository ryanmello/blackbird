FROM golang:1.24

WORKDIR /app

COPY go.mod ./
COPY main.go ./

RUN go build -o /blackbird

ENTRYPOINT ["/blackbird"]
