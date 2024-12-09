FROM golang:1.24

RUN go install golang.org/x/vuln/cmd/govulncheck@latest
ENV PATH="/go/bin:${PATH}"

WORKDIR /app

COPY go.mod ./
COPY main.go ./

RUN go build -o /blackbird

WORKDIR /github/workspace

ENTRYPOINT ["/blackbird"]
