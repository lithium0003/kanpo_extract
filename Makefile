all: kanpo_extract

kanpo_extract: main.cpp
	c++ -O2 main.cpp -o kanpo_extract -std=c++17 `pkg-config --cflags --libs openssl` `pkg-config --cflags --libs zlib` `pkg-config --cflags --libs libpng`

.PHONY : clean
clean: 
	@rm -rf kanpo_extract
