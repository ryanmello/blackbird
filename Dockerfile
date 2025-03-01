FROM golang:1.24

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
COPY main.go ./

RUN go mod tidy

RUN go install golang.org/x/vuln/cmd/govulncheck@latest
ENV PATH="/go/bin:${PATH}"

RUN go build -o /blackbird

ENTRYPOINT ["/blackbird"]
