# Obelisk — лёгкий TCP-релей (шлюз для «Играть с друзьями»)
# Сборка: docker build -t obelisk .
# Запуск см. docker-compose.yml
FROM ubuntu:22.04 AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake ninja-build g++ pkg-config \
    libssl-dev libasio-dev libspdlog-dev nlohmann-json3-dev libcpp-httplib-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -G Ninja \
    && cmake --build build --config Release

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/build/Obelisk /usr/local/bin/obelisk
COPY packaging/obelisk.service /etc/obelisk/obelisk.service

# Папки данных/логов
RUN mkdir -p /etc/obelisk && chmod 600 /etc/obelisk

# Порты: control, data, web + пул сессий
EXPOSE 4455 50021 8000 30000-39999

# Пул данных/логов внутри контейнера
VOLUME ["/etc/obelisk"]

ENTRYPOINT ["/usr/local/bin/obelisk"]
