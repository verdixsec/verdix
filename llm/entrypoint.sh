#!/bin/sh
# Verdix lean-llm first-run entrypoint.
# Idempotent: if the model is already imported into Ollama, skips everything.
# Fresh install: pulls the model natively from ghcr.io (Ollama-native OCI
# manifest, published separately by maintainer tooling) via `ollama pull`, then
# aliases it to the local tag the app expects via `ollama cp`. No oras, no
# GGUF cache dir, no sha256 verification, no `ollama create` — the pulled
# blobs land directly in Ollama's own store at their final size (peak disk
# == model size, ~11 GB, vs. the old two-copy ~23GB peak from staging a raw
# GGUF and then `ollama create`-importing it).
set -eu

MODEL_TAG="gemma4:e4b-it-q8_0"
ARTIFACT_REF="ghcr.io/verdixsec/gemma4:e4b-it-q8_0"

# Start ollama serve in the background; we will wait on its PID at the end
# so the container's main process remains ollama serve.
ollama serve &
OLLAMA_PID=$!

echo "[vx-entrypoint] Waiting for Ollama API..."
until ollama list >/dev/null 2>&1; do
    # Exit immediately if ollama serve died during startup
    if ! kill -0 "$OLLAMA_PID" 2>/dev/null; then
        echo "[vx-entrypoint] ERROR: ollama serve exited unexpectedly." >&2
        exit 1
    fi
    sleep 1
done
echo "[vx-entrypoint] Ollama API ready."

# Fast path: model already imported (all restarts after a successful first boot).
if ollama show "$MODEL_TAG" >/dev/null 2>&1; then
    echo "[vx-entrypoint] Model $MODEL_TAG present — skipping fetch."
else
    echo "[vx-entrypoint] Model not present."
    echo "[vx-entrypoint] Pulling ~11 GB from ghcr.io — this runs ONCE."
    echo "[vx-entrypoint] The model lands directly in the verdix_models volume, so"
    echo "[vx-entrypoint] restarts after this skip straight to serving in seconds."

    # OLLAMA_NO_CLOUD (set at image level) ensures no fallback to ollama.com.
    # A partial/failed pull leaves no partial model tag behind — `ollama show`
    # above will correctly report absent and this block retries on next boot.
    if ! ollama pull "$ARTIFACT_REF"; then
        echo "[vx-entrypoint] ERROR: ollama pull failed for $ARTIFACT_REF." >&2
        kill "$OLLAMA_PID" 2>/dev/null || true
        exit 1
    fi

    # The pulled model is tagged with its full ghcr reference, not the short
    # tag the app requests (VX_OLLAMA_MODEL / the healthcheck both expect
    # "gemma4:e4b-it-q8_0"). `ollama cp` aliases it to that tag without
    # copying any bytes — it just writes a second manifest pointing at the
    # same blobs. Then drop the ghcr-named reference so `ollama list` only
    # shows the canonical tag; the blobs stay because the aliased tag still
    # references them.
    echo "[vx-entrypoint] Aliasing $ARTIFACT_REF -> $MODEL_TAG..."
    if ! ollama cp "$ARTIFACT_REF" "$MODEL_TAG"; then
        echo "[vx-entrypoint] ERROR: ollama cp failed to alias $ARTIFACT_REF." >&2
        kill "$OLLAMA_PID" 2>/dev/null || true
        exit 1
    fi
    ollama rm "$ARTIFACT_REF" >/dev/null 2>&1 || true

    echo "[vx-entrypoint] Import complete."
fi

echo "[vx-entrypoint] Serving $MODEL_TAG."
# Bring ollama serve back to the foreground as PID 1's child.
wait "$OLLAMA_PID"
