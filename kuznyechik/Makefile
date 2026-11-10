CXX ?= c++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wpedantic -g

.PHONY: all check clean

all: main test

main: main.cpp cipher.cpp cipher.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) main.cpp cipher.cpp $(LDFLAGS) $(LDLIBS) -o $@

test: test.cpp cipher.cpp cipher.hpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) test.cpp cipher.cpp $(LDFLAGS) $(LDLIBS) -o $@

check: test main
	./test
	../data/test-data/test.sh

clean:
	rm -f main test
