FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash","-o","pipefail","-c"]

# add pkg-config so CMake can fall back if pqxx's CMake config isn't found
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates build-essential cmake ninja-build pkg-config \
      libboost-system-dev \
      libpq-dev libpqxx-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

RUN cmake -G Ninja -S . -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j

ENV PORT=9000
ENV BIND_ADDR=0.0.0.0
CMD ["/app/build/BCordServer"]

