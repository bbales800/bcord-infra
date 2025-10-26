# ======================================================================
# BCord Backend Dockerfile — Full WebSocket + Redis + Postgres Support
# ======================================================================
FROM ubuntu:24.04 AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git pkg-config ninja-build \
    ca-certificates libssl-dev libpqxx-dev libboost-system-dev \
    libhiredis-dev wget curl && \
    rm -rf /var/lib/apt/lists/*

# ----------------------------------------------------------------------
# Build Redis++ from local folder (pinned to 1.3.9)
# ----------------------------------------------------------------------
COPY third_party/redis-plus-plus /tmp/redis-plus-plus
RUN cd /tmp/redis-plus-plus && \
    mkdir -p build && cd build && \
    cmake -DREDIS_PLUS_PLUS_CXX_STANDARD=23 .. && \
    make -j$(nproc) && make install
WORKDIR /app
COPY ./ /app

RUN echo "CONTENTS OF /app:" && find /app -maxdepth 2 -type f

RUN cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j$(nproc)
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev libpqxx-dev libboost-system-dev libhiredis-dev && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/lib/libredis++.so* /usr/local/lib/
# Redis++ has no binary, only libraries — skip this copy
# COPY --from=build /usr/local/bin/redis-plus-plus /usr/local/bin/
COPY --from=build /app/build/BCordServer /usr/local/bin/bcord

EXPOSE 9000
CMD ["bcord"]

