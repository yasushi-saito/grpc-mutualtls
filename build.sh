set -ex

go get -u github.com/golang/protobuf/protoc-gen-go
protoc example.proto --go_out=plugins=grpc:.
go test -v .
