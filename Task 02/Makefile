# Makefile for UIT NT219 AES Lab (Task 1 & Task 2)
# 7 Core C++ Code Files:
#   1. AES.cpp       (NIST FIPS 197: AES-128, AES-192, AES-256)
#   2. sp800_38a.cpp (NIST SP 800-38A: ECB, CBC, CFB, OFB, CTR + PKCS#7)
#   3. sp800_38c.cpp (NIST SP 800-38C: AES-CCM) [Standard B 800-38B CMAC excluded]
#   4. sp800_38d.cpp (NIST SP 800-38D: AES-GCM & GMAC)
#   5. sp800_38e.cpp (NIST SP 800-38E: AES-XTS)
#   6. sp800_38f.cpp (NIST SP 800-38F: AES-KW & AES-KWP + RFC 8452 GCM-SIV)
#   7. main.cpp      (Known-Answer Tests & Block-by-block CLI)
# Plus C ABI Wrapper (c_api.cpp) for importing into C (test_c.c) and Python (test_import.py).

CXX        := g++
CC         := gcc
AR         := ar
CXXFLAGS   := -std=c++17 -O2 -Wall -Wextra -fPIC
CFLAGS     := -std=c11 -O2 -Wall -Wextra -fPIC

LIB_OBJS   := AES.o sp800_38a.o sp800_38c.o sp800_38d.o sp800_38e.o sp800_38f.o c_api.o
STATIC_LIB := libaes_crypto.a
SHARED_LIB := libaes_crypto.so

.PHONY: all clean test

all: $(STATIC_LIB) $(SHARED_LIB) main test_c

AES.o: AES.cpp AES.h
	$(CXX) $(CXXFLAGS) -c AES.cpp -o AES.o

sp800_38a.o: sp800_38a.cpp modes.h AES.h
	$(CXX) $(CXXFLAGS) -c sp800_38a.cpp -o sp800_38a.o

sp800_38c.o: sp800_38c.cpp modes.h AES.h
	$(CXX) $(CXXFLAGS) -c sp800_38c.cpp -o sp800_38c.o

sp800_38d.o: sp800_38d.cpp modes.h AES.h
	$(CXX) $(CXXFLAGS) -c sp800_38d.cpp -o sp800_38d.o

sp800_38e.o: sp800_38e.cpp modes.h AES.h
	$(CXX) $(CXXFLAGS) -c sp800_38e.cpp -o sp800_38e.o

sp800_38f.o: sp800_38f.cpp modes.h AES.h
	$(CXX) $(CXXFLAGS) -c sp800_38f.cpp -o sp800_38f.o

c_api.o: c_api.cpp c_api.h modes.h AES.h
	$(CXX) $(CXXFLAGS) -DAES_CRYPTO_EXPORTS -c c_api.cpp -o c_api.o

# 1. Build Static Library (.a)
$(STATIC_LIB): $(LIB_OBJS)
	$(AR) rcs $(STATIC_LIB) $(LIB_OBJS)

# 2. Build Shared Library (.so)
$(SHARED_LIB): $(LIB_OBJS)
	$(CXX) -shared -o $(SHARED_LIB) $(LIB_OBJS)

# 3. Build C++ main executable linked against libaes_crypto.a
main: main.cpp $(STATIC_LIB)
	$(CXX) $(CXXFLAGS) main.cpp $(STATIC_LIB) -o main

# 4. Build C language test executable linked against libaes_crypto.a
test_c: test_c.c $(STATIC_LIB)
	$(CC) $(CFLAGS) test_c.c $(STATIC_LIB) -lstdc++ -lm -o test_c

test: all
	@echo "--- [1/4] Running C++ AES Known-Answer Tests (./main) ---"
	./main
	@echo ""
	@echo "--- [2/4] Running All 5 NIST Standards (A, C, D, E, F) Tests (./main --all) ---"
	./main --all
	@echo ""
	@echo "--- [3/4] Running C Library Import Test (./test_c) ---"
	./test_c
	@echo ""
	@echo "--- [4/4] Running Python Shared Library (.so) Import Test (python3 test_import.py) ---"
	python3 test_import.py

clean:
	rm -f *.o $(STATIC_LIB) $(SHARED_LIB) main test_c
