FROM golang:1.24

# Create a directory for the blackbird binary
WORKDIR /app

# Copy the blackbird code
COPY go.mod ./
COPY main.go ./

# Build the blackbird binary
RUN go build -o /blackbird

# Set the working directory to the mounted workspace
WORKDIR /github/workspace

# Install govulncheck in the workspace context
RUN go install golang.org/x/vuln/cmd/govulncheck@latest
ENV PATH="/go/bin:${PATH}"

# The entrypoint will run in the mounted workspace
ENTRYPOINT ["/blackbird"]
