FROM node:22 AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# pdqhash has no Linux wheel, so pip compiles it: the compiler stays in this stage.
FROM python:3.11-slim AS deps
RUN apt-get update && apt-get install -y --no-install-recommends build-essential curl ca-certificates
WORKDIR /build
COPY requirements.txt ./
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt
COPY scripts/get_models.sh scripts/
RUN bash scripts/get_models.sh

FROM python:3.11-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr poppler-utils libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=deps /install /usr/local
WORKDIR /app
# Named paths only, never `COPY .`: .env cannot enter the image even if .dockerignore is lost.
COPY shield/ shield/
COPY registry/ registry/
COPY --from=deps /build/models models/
COPY --from=web /web/dist web/dist/
RUN useradd --uid 10001 --create-home shield
USER shield
# main() refuses this bind unless SHIELD_API_TOKEN or SHIELD_PUBLIC_DEMO is set. The port comes from PORT (default 8000).
ENV SHIELD_HOST=0.0.0.0
CMD ["python", "-m", "shield.api"]
