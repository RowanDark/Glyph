// module name: 0xgen
module github.com/RowanDark/0xgen

go 1.24.3

require (
	github.com/google/uuid v1.6.0
	github.com/inconshreveable/go-update v0.0.0-20160112193335-8152e7eb6ccf
	github.com/kr/binarydist v0.1.0
	go.opentelemetry.io/otel v1.37.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.37.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.37.0
	go.opentelemetry.io/otel/sdk v1.37.0
	go.opentelemetry.io/otel/trace v1.37.0
	golang.org/x/mod v0.25.0
	golang.org/x/net v0.42.0
	golang.org/x/sys v0.34.0
	google.golang.org/grpc v1.76.0
	google.golang.org/protobuf v1.36.9
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/cenkalti/backoff/v5 v5.0.2 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.1 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel/metric v1.37.0 // indirect
	go.opentelemetry.io/proto/otlp v1.7.0 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250804133106-a7a43d27e69b // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250804133106-a7a43d27e69b // indirect
)

replace golang.org/x/crypto => ./third_party/golang.org/x/crypto
