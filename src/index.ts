import * as k8s from "@kubernetes/client-node";
import { PodWatcher } from "./pod-watcher.js";
import { LogStreamer, type EnrichedWafEvent } from "./log-streamer.js";

const useSentry = !!process.env.SENTRY_DSN;

function parseHostnameMap(): Record<string, string> {
  const raw = process.env.HOSTNAME_ENVIRONMENT_MAP;
  if (!raw) return {};

  try {
    const parsed = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      console.error(
        "HOSTNAME_ENVIRONMENT_MAP must be a JSON object (e.g. '{\"app.example.com\":\"production\"}')",
      );
      return {};
    }
    for (const [key, value] of Object.entries(parsed)) {
      if (typeof value !== "string") {
        console.error(
          `HOSTNAME_ENVIRONMENT_MAP: value for "${key}" must be a string, got ${typeof value}`,
        );
        return {};
      }
    }
    return parsed as Record<string, string>;
  } catch (err) {
    console.error("Failed to parse HOSTNAME_ENVIRONMENT_MAP:", (err as Error).message);
    return {};
  }
}

let Sentry: typeof import("@sentry/node") | null = null;

if (useSentry) {
  // Dynamic import so the module loads even if @sentry/node is not installed
  Sentry = await import("@sentry/node");

  const hostnameMap = parseHostnameMap();
  const sentryEnvironmentFallback = process.env.SENTRY_ENVIRONMENT;

  Sentry.init({
    dsn: process.env.SENTRY_DSN,
    release: process.env.BUILD_ID ?? "development",
    ...(sentryEnvironmentFallback && { environment: sentryEnvironmentFallback }),
    enableLogs: true,
    beforeSendLog: (log) => {
      // Promote target_environment to sentry.environment so each WAF log
      // is attributed to the correct environment (staging vs production)
      // based on which hostname was attacked.
      const attrs = log.attributes as Record<string, unknown> | undefined;
      if (attrs?.["target_environment"]) {
        attrs["sentry.environment"] = attrs["target_environment"];
        delete attrs["target_environment"];
      } else if (sentryEnvironmentFallback && attrs) {
        // Fall back to SENTRY_ENVIRONMENT when hostname map didn't match
        attrs["sentry.environment"] = sentryEnvironmentFallback;
      }
      return log;
    },
  });
} else {
  console.warn(
    "SENTRY_DSN not set — WAF events will be logged to stdout as JSON instead of Sentry",
  );
}

const NAMESPACE = process.env.POD_NAMESPACE ?? "envoy-gateway-system";
const LABEL_SELECTOR =
  process.env.POD_LABEL_SELECTOR ??
  "gateway.envoyproxy.io/owning-gateway-name";
const CONTAINER_NAME = process.env.CONTAINER_NAME ?? "envoy";
const HOSTNAME_TO_ENVIRONMENT = parseHostnameMap();

function handleWafEvent(event: EnrichedWafEvent, podName: string): void {
  const attrs: Record<string, unknown> = {
    rule_id: event.ruleId,
    rule_msg: event.message,
    client_ip: event.clientIp,
    action: event.action,
    pod: podName,
    ...(event.uri && { uri: event.uri }),
    ...(event.hostname && { hostname: event.hostname }),
    ...(event.severity && { severity: event.severity }),
    ...(event.matchedData && { matched_data: event.matchedData }),
    ...(event.crsVersion && { crs_version: event.crsVersion }),
    ...(event.authority && { authority: event.authority }),
    ...(event.environment && { target_environment: event.environment }),
  };

  if (Sentry) {
    if (event.action === "block") {
      Sentry.logger.error(
        `WAF blocked request from ${event.clientIp} to ${event.uri ?? "unknown"} - rule ${event.ruleId}: ${event.message}`,
        attrs,
      );
    } else {
      Sentry.logger.warn(
        `WAF detected ${event.message} from ${event.clientIp} to ${event.uri ?? "unknown"} - rule ${event.ruleId}`,
        attrs,
      );
    }
  } else {
    // No Sentry — emit structured JSON to stdout
    const level = event.action === "block" ? "error" : "warn";
    console.log(
      JSON.stringify({
        level,
        message:
          event.action === "block"
            ? `WAF blocked request from ${event.clientIp} to ${event.uri ?? "unknown"} - rule ${event.ruleId}: ${event.message}`
            : `WAF detected ${event.message} from ${event.clientIp} to ${event.uri ?? "unknown"} - rule ${event.ruleId}`,
        ...attrs,
      }),
    );
  }
}

async function main(): Promise<void> {
  console.log(
    `Starting WAF log tailer: namespace=${NAMESPACE} selector=${LABEL_SELECTOR} container=${CONTAINER_NAME}`,
  );

  if (Object.keys(HOSTNAME_TO_ENVIRONMENT).length > 0) {
    console.log(
      `Hostname-to-environment map: ${JSON.stringify(HOSTNAME_TO_ENVIRONMENT)}`,
    );
  }

  const kc = new k8s.KubeConfig();
  kc.loadFromDefault();

  const streamer = new LogStreamer(kc, {
    namespace: NAMESPACE,
    containerName: CONTAINER_NAME,
    onEvent: handleWafEvent,
    onError: (err, pod) =>
      console.error(`Stream error for pod ${pod}:`, err.message),
    hostnameToEnvironment: HOSTNAME_TO_ENVIRONMENT,
  });

  const watcher = new PodWatcher(kc, {
    namespace: NAMESPACE,
    labelSelector: LABEL_SELECTOR,
  });

  watcher.on("added", (podName: string) => {
    console.log(`Pod added: ${podName}, starting log stream`);
    streamer.startStream(podName);
  });

  watcher.on("removed", (podName: string) => {
    console.log(`Pod removed: ${podName}, stopping log stream`);
    streamer.stopStream(podName);
  });

  watcher.on("error", (err: Error) => {
    console.error("Pod watcher error:", err.message);
  });

  const shutdown = async () => {
    console.log("Shutting down...");
    watcher.stop();
    streamer.stopAll();
    if (Sentry) await Sentry.flush(5000);
    process.exit(0);
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);

  await watcher.start();
  console.log(
    `Watching ${watcher.getPods().length} Envoy pods for WAF events`,
  );
}

main().catch((err) => {
  console.error("Fatal error:", err);
  if (Sentry) {
    Sentry.captureException(err);
    Sentry.flush(5000).then(() => process.exit(1));
  } else {
    process.exit(1);
  }
});
