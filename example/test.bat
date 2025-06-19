go build -v -trimpath -o GRT-PELoader.exe ../tool/pe_loader/main.go

go build -v -trimpath -ldflags "-s -w" -o argument.exe argument/main.go
go build -v -trimpath -ldflags "-s -w" -o im_storage.exe im_storage/main.go

GRT-PELoader.exe -pe argument.exe
GRT-PELoader.exe -pe im_storage.exe