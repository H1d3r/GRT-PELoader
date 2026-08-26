export GOOS=windows
go build -v -trimpath -ldflags "-s -w" -o pe_loader.exe main.go