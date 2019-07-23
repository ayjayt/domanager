
all:
	go build

install:
	go install

test:
	go test -test.v -cover -race 
	go test -run=xxx -test.bench=. -test.benchmem 
	@# Recreate a profile_cpu.out without race cover and bench, which skew results
	go test -cpuprofile profile_cpu.out 

# The following requires graphviz
viz:
	go tool pprof -svg profile_cpu.out > profile_cpu.svg

# The following requires github.com/uber/go-torch and github.com/brendangregg/FlameGraph
# Here it is installed to $(HOME)/software/FlameGraph
# NOTE: go tool now supports this directly so use that instead! Uninstall the software: learn how to use pprof
torch:
	PATH=$(PATH):$(HOME)/software/FlameGraph go-torch -b profile_cpu.out -f profile_cpu.torch.svg

heap:
	go build -gcflags '-m -m -l -e'
	@# two more m's are possible but its too verbose
	@# -race is better for load and integration tests

lint:
	golangci-lint run --skip-dirs 'scrap'
