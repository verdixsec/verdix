#!/bin/sh
# Verdix lean-llm first-run entrypoint.
# Idempotent: if the model is already imported into Ollama, skips everything.
# Fresh install: pulls the GGUF from ghcr.io into the persisted verdix_models
# volume, verifies its sha256, stages a Modelfile with an absolute FROM path,
# and imports it via `ollama create`.
set -eu

MODEL_TAG="gemma4:e4b-it-q8_0"
ARTIFACT_REF="ghcr.io/verdixsec/verdix/gemma4:e4b-it-q8_0"
GGUF_FILENAME="gemma4-e4b-it-q8_0.gguf"
MODELFILE_SRC="/opt/verdix/Modelfile"
# CACHE_DIR lives inside the verdix_models volume (mounted at /root/.ollama)
# so the pulled GGUF survives restarts even if `ollama create` hasn't
# succeeded yet — a failed create must never trigger a re-download.
CACHE_DIR="/root/.ollama/vx-model-cache"
GGUF_PATH="$CACHE_DIR/$GGUF_FILENAME"
STAGED_MODELFILE="$CACHE_DIR/Modelfile"

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
    echo "[vx-entrypoint] Model $MODEL_TAG present — skipping fetch and import."
else
    mkdir -p "$CACHE_DIR"

    # Skip the pull if a verified GGUF is already cached in the volume. This
    # covers the retry-after-failed-create path and a restart mid-import.
    # A failed `ollama create` must never trigger a re-pull — only a
    # missing or corrupt cached GGUF does.
    NEED_PULL=1
    if [ -f "$GGUF_PATH" ]; then
        echo "[vx-entrypoint] Found cached GGUF at $GGUF_PATH — verifying checksum..."
        CACHED_SHA=$(sha256sum "$GGUF_PATH" | awk '{print $1}')
        if [ "$CACHED_SHA" = "$GEMMA4_GGUF_SHA256" ]; then
            echo "[vx-entrypoint] Cached GGUF checksum OK — skipping oras pull."
            NEED_PULL=0
        else
            echo "[vx-entrypoint] Cached GGUF checksum mismatch — will re-fetch." >&2
        fi
    fi

    if [ "$NEED_PULL" -eq 1 ]; then
        echo "[vx-entrypoint] Model not cached."
        echo "[vx-entrypoint] Downloading ~11 GB from ghcr.io — this runs ONCE."
        echo "[vx-entrypoint] The GGUF is saved to the verdix_models volume, so"
        echo "[vx-entrypoint] restarts after this skip straight to serving in seconds."

        rm -rf "$CACHE_DIR"
        mkdir -p "$CACHE_DIR"

        # Pull the OCI artifact (GGUF + Modelfile + LICENSE) from our ghcr.
        # OLLAMA_NO_CLOUD ensures no fallback to ollama.com.
        oras pull "$ARTIFACT_REF" --output "$CACHE_DIR"

        echo "[vx-entrypoint] Verifying GGUF checksum..."
        ACTUAL=$(sha256sum "$GGUF_PATH" | awk '{print $1}')
        if [ "$ACTUAL" != "$GEMMA4_GGUF_SHA256" ]; then
            echo "[vx-entrypoint] ERROR: GGUF checksum mismatch." >&2
            echo "  Expected: $GEMMA4_GGUF_SHA256" >&2
            echo "  Got:      $ACTUAL" >&2
            rm -f "$GGUF_PATH"
            kill "$OLLAMA_PID" 2>/dev/null || true
            exit 1
        fi
        echo "[vx-entrypoint] Checksum OK."
    fi

    # Stage a Modelfile with an ABSOLUTE FROM path. Ollama resolves a
    # Modelfile's relative FROM against the Modelfile's own directory, not
    # the process cwd, so `cd`-ing before `ollama create` does not help —
    # the FROM line itself must point at an absolute path. Every other
    # directive (TEMPLATE, RENDERER, PARSER, PARAMETER, stop tokens, LICENSE)
    # is carried through verbatim from the image's canonical Modelfile;
    # template fidelity is load-bearing for structured-JSON compliance.
    # This also overwrites the reference Modelfile that `oras pull` wrote
    # into CACHE_DIR (from the ghcr artifact), which still has the same
    # unresolved relative FROM — the image's baked-in Modelfile is the one
    # source of truth for import.
    sed "s|^FROM .*|FROM $GGUF_PATH|" "$MODELFILE_SRC" > "$STAGED_MODELFILE"
    echo "[vx-entrypoint] Staged Modelfile at $STAGED_MODELFILE"
    echo "[vx-entrypoint] Resolved FROM: $GGUF_PATH"

    echo "[vx-entrypoint] Importing model (ollama create)..."
    if ! ollama create "$MODEL_TAG" -f "$STAGED_MODELFILE"; then
        echo "[vx-entrypoint] ERROR: ollama create failed." >&2
        echo "  Modelfile used: $STAGED_MODELFILE" >&2
        echo "  Resolved FROM:  $GGUF_PATH" >&2
        echo "  The GGUF is cached in the verdix_models volume and will NOT be" >&2
        echo "  re-downloaded on the next restart — only 'ollama create' will retry." >&2
        kill "$OLLAMA_PID" 2>/dev/null || true
        exit 1
    fi
    echo "[vx-entrypoint] Import complete."
fi

echo "[vx-entrypoint] Serving $MODEL_TAG."
# Bring ollama serve back to the foreground as PID 1's child.
wait "$OLLAMA_PID"
