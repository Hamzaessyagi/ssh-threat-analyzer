# ─── SSH Threat Analyzer - Dockerfile ─────────────────────────
FROM ubuntu:22.04

LABEL maintainer="ES-SYAGI HAMZA"
LABEL description="SSH Auth Log Threat Analyzer"

# Pas de prompt interactif pendant l'install
ENV DEBIAN_FRONTEND=noninteractive

# ─── Dépendances système ────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    bash \
    && rm -rf /var/lib/apt/lists/*

# ─── Dépendances Python ─────────────────────────────────────────
RUN pip3 install --no-cache-dir \
    matplotlib \
    numpy \
    requests

# ─── Copier les scripts ─────────────────────────────────────────
WORKDIR /app
COPY scripts/ ./scripts/
COPY run.sh .
RUN chmod +x run.sh

# ─── Le fichier log sera monté via volume ───────────────────────
# Les fichiers auth.log ne sont JAMAIS dans l'image
VOLUME ["/data"]

# ─── Entrée par défaut ──────────────────────────────────────────
ENTRYPOINT ["python3", "scripts/analyze.py"]
CMD ["--help"]
