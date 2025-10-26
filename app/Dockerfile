FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates build-essential cmake ninja-build pkg-config \
    libboost-system-dev libpq-dev libpqxx-dev libssl-dev curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

ARG CMAKE_BUILD_TYPE=Release
RUN cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} && \
    cmake --build build -j

CMD ["/app/build/BCordServer"]

