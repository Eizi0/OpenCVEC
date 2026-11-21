# Étape 1 : application web
# Les étapes de compilation tournent sur l'architecture de la machine de build (pas d'émulation) ;
# seul le binaire Go est compilé pour la cible (amd64, arm64…).
FROM --platform=$BUILDPLATFORM node:26-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Étape 2 : binaire Go (le front est embarqué)
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /out/opencvec ./cmd/opencvec

# Étape 3 : image finale minimale, utilisateur non root
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/opencvec /opencvec
# 8080 : interface et API · 53 : DNS autoritaire de la zone canari · 80 : récepteur HTTP
EXPOSE 8080 53/udp 53/tcp 80
HEALTHCHECK --interval=10s --timeout=4s --start-period=10s --retries=5 CMD ["/opencvec", "healthcheck"]
ENTRYPOINT ["/opencvec"]
CMD ["serve"]
