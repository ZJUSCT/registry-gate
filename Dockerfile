FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/registry-gate ./cmd/registry-gate

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/registry-gate /registry-gate
USER nonroot:nonroot
ENTRYPOINT ["/registry-gate"]
