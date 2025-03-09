package authorization

import (
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
)

var (
	logger = otelslog.NewLogger(ServiceName)
	tracer = otel.Tracer(ServiceName)
)
