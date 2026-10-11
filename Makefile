BINARY := gauth-decoder

.PHONY: build clean

build:
	go build -o $(BINARY) .

clean:
	$(RM) $(BINARY)
