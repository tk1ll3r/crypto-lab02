# Dockerfile - Containerize UIT NT219 AES Lab (Task 2)
# Usage:
#   docker build -t uit-nt219-aes-lab .
#   docker run --rm uit-nt219-aes-lab

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY AES.h AES.cpp modes.h \
     sp800_38a.cpp sp800_38c.cpp sp800_38d.cpp sp800_38e.cpp sp800_38f.cpp \
     c_api.h c_api.cpp main.cpp test_c.c test_import.py CMakeLists.txt Makefile ./

# Build static library (libaes_crypto.a), shared library (libaes_crypto.so), and executables (main, test_c)
RUN make -f Makefile all

# Run C++, C, and Python verification suites on container startup
CMD ["make", "-f", "Makefile", "test"]
