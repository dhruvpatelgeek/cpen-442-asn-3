sudo rm -rf protogen_out
mkdir protogen_out
protoc --python_out=./protogen_out *.proto --experimental_allow_proto3_optional