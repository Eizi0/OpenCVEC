# Étape 1 : application web
FROM node:25-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Étape 2 : binaire Go (le front est embarqué)
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/opencvec ./cmd/opencvec

# Étape 3 : image finale minimale, utilisateur non root
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/opencvec /opencvec
# 8080 : interface et API · 53 : DNS autoritaire de la zone canari · 80 : récepteur HTTP
EXPOSE 8080 53/udp 53/tcp 80
HEALTHCHECK --interval=10s --timeout=4s --start-period=10s --retries=5 CMD ["/opencvec", "healthcheck"]
ENTRYPOINT ["/opencvec"]
CMD ["serve"]
