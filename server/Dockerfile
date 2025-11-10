# ======================================================================
# BCord Backend Dockerfile — Full WebSocket + Redis + Postgres Support
# ======================================================================

# ------------------------
# Stage 1 — Build
# ------------------------
FROM ubuntu:24.04 AS build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git pkg-config ninja-build wget curl ca-certificates \
    libssl-dev libpqxx-dev libboost-system-dev libhiredis-dev \
    libcurl4-openssl-dev nlohmann-json3-dev libargon2-dev && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev libpqxx-dev libboost-system-dev libhiredis-dev \
    libcurl4 wget libargon2-dev \
    nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

# ----------------------------------------------------------
# 🧰 Add diagnostic tools (curl, wget, ping)
# ----------------------------------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl wget iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# ----------------------------------------------------------------------
# Build Redis++ (C++ Redis client)
# ----------------------------------------------------------------------
COPY third_party/redis-plus-plus /tmp/redis-plus-plus
RUN cd /tmp/redis-plus-plus && \
    mkdir -p build && cd build && \
    cmake -DREDIS_PLUS_PLUS_CXX_STANDARD=23 .. && \
    make -j$(nproc) && make install

# ----------------------------------------------------------------------
# Build BCord Backend Application
# ----------------------------------------------------------------------
WORKDIR /app
COPY ./ /app

RUN echo "📁 Listing /app contents:" && find /app -maxdepth 2 -type f

# Compile
RUN cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j$(nproc)

# ------------------------
# Stage 2 — Runtime
# ------------------------
FROM ubuntu:24.04 AS runtime

# Install runtime libraries + permanent debug tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev libpqxx-dev libboost-system-dev libhiredis-dev \
    libcurl4 libargon2-1 \
    curl wget iputils-ping \
    && rm -rf /var/lib/apt/lists/*


# Copy Redis++ shared libraries and BCord binary
COPY --from=build /usr/local/lib/libredis++.so* /usr/local/lib/
COPY --from=build /app/build/BCordServer /usr/local/bin/bcord

EXPOSE 9000
CMD ["bcord"]

# 🩺 Final Healthcheck — simple and reliable
HEALTHCHECK --interval=15s --timeout=5s --start-period=45s --retries=8 \
  CMD wget -qO- http://localhost:9000/api/health | grep -q "healthy" || exit 1

