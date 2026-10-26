# How to send telemetry to a collector

This guide shows you how to send multiproxy's traces, metrics and logs to an OpenTelemetry collector, and how to
turn them off.

multiproxy reads the standard OpenTelemetry environment variables. With none set, it exports over OTLP to a
collector on localhost.

## Send to a collector elsewhere

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to the collector's OTLP/HTTP address:

```
OTEL_EXPORTER_OTLP_ENDPOINT=http://<collector-host>:4318 multiproxy
```

`<collector-host>` is the collector's host name. With an endpoint set, failed exports are logged to stderr at
warn level; without one, at debug level, so a run without a collector stays quiet.

## Turn telemetry off

- To turn all of it off, set `OTEL_SDK_DISABLED=true`.
- To turn off one signal, set `OTEL_TRACES_EXPORTER`, `OTEL_METRICS_EXPORTER` or `OTEL_LOGS_EXPORTER` to `none`.

## What's next

- [Command-line reference](../reference/command-line.md#logs) lists the log fields, including `trace_id`.
- The [OpenTelemetry SDK environment variables](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/)
  cover everything else the SDK reads.
