.DEFAULT_GOAL := build

build:
	go build -o bin/dencrypt ./main.go

clean:
	rm bin/dencrypt

install:
	if [ ! -e "bin/dencrypt" ]; then \
	    echo "bin/dencrypt not found. Make sure to run 'make' first."; \
	    exit 1; \
	fi

	if [ $(shell id -u) -eq 0 ]; then \
	    cp bin/dencrypt /bin/; \
	else \
		if [ ! -d "$$HOME/.local/bin" ]; then \
		    mkdir -p $$HOME/.local/bin; \
		fi; \
		cp bin/dencrypt $$HOME/.local/bin/; \
	fi

uninstall:
	if [ $(shell id -u) -eq 0 ]; then \
	    rm /bin/dencrypt; \
	else \
		if [ -e "$$HOME/.local/bin/dencrypt" ]; then \
			rm $$HOME/.local/bin/dencrypt; \
		fi; \
	fi

install_termux:
	if [ ! -e "bin/dencrypt" ]; then \
		echo "bin/dencrypt not found. Make sure to run 'make' first."; \
		exit 1; \
	fi

	cp bin/dencrypt "$$PREFIX/bin/";

uninstall_termux:
	if [ -e "$$PREFIX/bin/dencrypt" ]; then \
		rm "$$PREFIX/bin/dencrypt"; \
	fi

windows:
	GOOS=windows GOARCH=amd64 go build -o bin/dencrypt.exe ./main.go
