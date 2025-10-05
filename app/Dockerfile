FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates build-essential cmake ninja-build pkg-config \
    libboost-system-dev libpq-dev libpqxx-dev libssl-dev curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j

CMD ["/app/build/BCordServer"]

