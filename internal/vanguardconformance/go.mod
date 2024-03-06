module connectrpc.com/vanguard/internal/vanguardconformance

go 1.23.3

require (
	buf.build/gen/go/connectrpc/conformance/connectrpc/go v1.17.0-20241008212309-5939a22621c8.1
	buf.build/gen/go/connectrpc/conformance/protocolbuffers/go v1.35.1-20241008212309-5939a22621c8.1
	connectrpc.com/vanguard v0.3.0
	google.golang.org/protobuf v1.35.1
)

require (
	connectrpc.com/connect v1.17.0 // indirect
	golang.org/x/net v0.30.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20241104194629-dd2ea8efbc28 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241104194629-dd2ea8efbc28 // indirect
)

replace connectrpc.com/vanguard => ../../
