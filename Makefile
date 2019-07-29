dep:
	dep ensure -v

test: dep
	go test -v

build: dep
	go build -o bin/envvault

clean:
	rm -r bin/
