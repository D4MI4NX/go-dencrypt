.DEFAULT_GOAL := build

build:
	go build -ldflags "-s -w" -buildmode pie -o bin/dencrypt ./main.go ./dencrypt.go ./magic.go

clean:
	rm -r bin

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
	GOOS=windows GOARCH=amd64 go build -o bin/dencrypt.exe ./main.go ./dencrypt.go ./magic.go

all:
	# Linux
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o bin/dencrypt_linux_amd64 ./main.go ./dencrypt.go ./magic.go
	GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o bin/dencrypt_linux_arm64 ./main.go ./dencrypt.go ./magic.go
	# Windows
	GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o bin/dencrypt_windows_amd64.exe ./main.go ./dencrypt.go ./magic.go
	GOOS=windows GOARCH=arm64 go build -ldflags "-s -w" -o bin/dencrypt_windows_arm64.exe ./main.go ./dencrypt.go ./magic.go

small:
	go build -o bin/dencrypt -ldflags "-s -w" && upx bin/dencrypt

dynamic:
	sudo go install -buildmode=shared -linkshared std
	sudo go build -linkshared -o dencrypt ./main.go ./dencrypt.go ./magic.go
