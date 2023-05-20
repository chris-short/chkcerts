# Stage 1: Build Stage
FROM public.ecr.aws/docker/library/golang:alpine AS builder

WORKDIR /certcheck

# Copy the source code into the container
COPY . .

# Build the Go application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o certcheck .

# Stage 2: Final Stage
FROM public.ecr.aws/docker/library/alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the built executable from the previous stage
COPY --from=builder /certcheck .

# Set the entry point for the container
ENTRYPOINT ["./certcheck"]
