# Stage 1: Build Stage
FROM public.ecr.aws/docker/library/golang:alpine AS builder

LABEL org.opencontainers.image.source=https://github.com/chris-short/chkcerts
LABEL org.opencontainers.image.description="certcheck: A Go program to display certificate chains simply and quickly with an easy to remember syntax"
LABEL org.opencontainers.image.licenses="Apache-2.0 license"

WORKDIR /chkcerts

# Copy the source code into the container
COPY . .

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o chkcerts .

# Stage 2: Final Stage
FROM public.ecr.aws/docker/library/alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the built executable from the previous stage
COPY --from=builder /chkcerts .

# Set the entry point for the container
ENTRYPOINT ["./chkcerts"]
