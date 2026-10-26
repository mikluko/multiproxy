package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"runtime/debug"
	"strings"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"

	"sarak.sh/mikluko/multiproxy/pkg/middleware/log"
)

// scope is the instrumentation scope of the command's own telemetry.
const scope = "sarak.sh/mikluko/multiproxy"

// setupTelemetry installs global tracer, meter and logger providers, the W3C propagators, and returns the access and
// server loggers, writing locally as newLogHandlers does and to the logger provider. Exporters follow the standard
// OTEL_* environment variables, and so export over OTLP to localhost by default. With OTEL_SDK_DISABLED=true it
// installs nothing and the loggers write locally only; the Go SDK does not implement that variable itself.
//
// The returned function flushes and shuts down the providers.
func setupTelemetry(ctx context.Context, stdout, stderr io.Writer) (access, server *slog.Logger, shutdown func(context.Context) error, err error) {
	localAccess, localServer := newLogHandlers(stdout, stderr)
	if sdkDisabled() {
		return slog.New(localAccess), slog.New(localServer), func(context.Context) error { return nil }, nil
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName("multiproxy"), semconv.ServiceVersion(version())),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithProcessRuntimeName(),
		resource.WithProcessRuntimeVersion(),
		resource.WithFromEnv(),
	)
	if err != nil {
		return nil, nil, nil, err
	}

	var shutdowns []func(context.Context) error
	shutdown = func(ctx context.Context) error {
		var errs []error
		for i := len(shutdowns) - 1; i >= 0; i-- {
			errs = append(errs, shutdowns[i](ctx))
		}
		return errors.Join(errs...)
	}
	fail := func(err error) (*slog.Logger, *slog.Logger, func(context.Context) error, error) {
		return nil, nil, nil, errors.Join(err, shutdown(ctx))
	}

	spanExp, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		return fail(err)
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(spanExp))
	shutdowns = append(shutdowns, tp.Shutdown)

	reader, err := autoexport.NewMetricReader(ctx)
	if err != nil {
		return fail(err)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(reader))
	shutdowns = append(shutdowns, mp.Shutdown)

	logExp, err := autoexport.NewLogExporter(ctx)
	if err != nil {
		return fail(err)
	}
	lp := sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)))
	shutdowns = append(shutdowns, lp.Shutdown)

	if err := runtime.Start(runtime.WithMeterProvider(mp)); err != nil {
		return fail(err)
	}

	otel.SetTracerProvider(tp)
	otel.SetMeterProvider(mp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	// SDK errors are logged locally only: routed through the logger provider, a failing log export would feed itself.
	errLogger, errLevel := slog.New(localServer).With("logger", "opentelemetry"), exportErrorLevel()
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		errLogger.Log(context.Background(), errLevel, "opentelemetry", "error", err)
	}))

	bridge := otelslog.NewHandler(scope, otelslog.WithLoggerProvider(lp), otelslog.WithVersion(version()))
	access = slog.New(slog.NewMultiHandler(localAccess, bridge))
	server = slog.New(slog.NewMultiHandler(localServer, bridge))
	return access, server, shutdown, nil
}

// newLogHandlers returns the local access handler, writing JSON records without level or message to stdout, and the
// local server handler, writing JSON records to stderr. Both add trace_id and span_id where the context carries a
// span.
func newLogHandlers(stdout, stderr io.Writer) (access, server slog.Handler) {
	dropLevelAndMessage := func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 && (a.Key == slog.LevelKey || a.Key == slog.MessageKey) {
			return slog.Attr{}
		}
		return a
	}
	access = log.TraceHandler(slog.NewJSONHandler(stdout, &slog.HandlerOptions{ReplaceAttr: dropLevelAndMessage}))
	server = log.TraceHandler(slog.NewJSONHandler(stderr, nil))
	return access, server
}

// exportErrorLevel is the level SDK errors are logged at: debug where no OTLP endpoint is configured, so that the
// default export to an absent local collector stays quiet, and warn otherwise.
func exportErrorLevel() slog.Level {
	for _, name := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
	} {
		if os.Getenv(name) != "" {
			return slog.LevelWarn
		}
	}
	return slog.LevelDebug
}

// sdkDisabled reports whether OTEL_SDK_DISABLED is "true", case-insensitively, as the OpenTelemetry specification
// defines it.
func sdkDisabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("OTEL_SDK_DISABLED")), "true")
}

// version is the module version the binary was built from, "(devel)" for a build from a working tree.
func version() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		return bi.Main.Version
	}
	return "(devel)"
}
