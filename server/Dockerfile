# ======================== Build stage ========================
FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates build-essential cmake ninja-build libssl-dev libpqxx-dev libboost-all-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j

# ======================== Runtime stage ======================
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev libpqxx-dev libboost-system-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /app/build/BCordServer /usr/local/bin/bcord
EXPOSE 9000
ENTRYPOINT ["/usr/local/bin/bcord"]

