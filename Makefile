
goFiles=$(shell ls *.go)

all: data $(goFiles)
	go build

data:
	go-bindata data/...

.PHONY: data