CPP= $(CXX) -std=c++20 -O2 -I ./deps
LDFLAGS = -lssl -lcrypto -pthread -lm
ifneq (,$(findstring clang,$(CXX)))
CPP := $(CPP) -stdlib=libc++
LDFLAGS := $(LDFLAGS) -lc++ -lc++abi -lm -lc -lgcc_s -lgcc
endif

bin/aesgcm:
	$(CPP) aesgcm.cpp -o bin/aesgcm $(LDFLAGS)
bin/aesgcm_san:
	$(CPP) aesgcm.cpp -fsanitize=address -o bin/aesgcm_san $(LDFLAGS)
test:bin/aesgcm_san
	bin/aesgcm_san test

env_install:
	python3 -m pip install tclib
	mkdir -p bin
	mkdir -p deps && cd deps
	python3 -m tclib download https://github.com/CLIUtils/CLI11/releases/download/v2.3.2/CLI11.hpp deps/CLI11.hpp ba83806399a66634ca8f8d292df031e5ed651315ceb9a6a09ba56f88d75f1797
