import * as k8s from "@kubernetes/client-node";
import { PassThrough } from "node:stream";
import {
  parseCorazaLog,
  parseAccessLog,
  type WafEvent,
  type AccessLogEntry,
} from "./parser.js";

export interface EnrichedWafEvent extends WafEvent {
  authority?: string;
  environment?: string;
}

export interface LogStreamerOptions {
  namespace: string;
  containerName: string;
  onEvent: (event: EnrichedWafEvent, podName: string) => void;
  onError?: (err: Error, podName: string) => void;
  hostnameToEnvironment?: Record<string, string>;
}

const BUFFER_TIMEOUT_MS = 10000;

export class LogStreamer {
  private kc: k8s.KubeConfig;
  private options: LogStreamerOptions;
  private activeStreams = new Map<string, AbortController>();
  private backoff = new Map<string, number>();
  private pendingEvents = new Map<string, { event: WafEvent; timer: ReturnType<typeof setTimeout> }[]>();

  constructor(kc: k8s.KubeConfig, options: LogStreamerOptions) {
    this.kc = kc;
    this.options = options;
  }

  async startStream(podName: string): Promise<void> {
    if (this.activeStreams.has(podName)) return;

    const controller = new AbortController();
    this.activeStreams.set(podName, controller);
    this.backoff.set(podName, 1000);
    this.pendingEvents.set(podName, []);

    this.connectStream(podName, controller);
  }

  private async connectStream(
    podName: string,
    controller: AbortController,
  ): Promise<void> {
    if (controller.signal.aborted) return;

    try {
      const log = new k8s.Log(this.kc);
      const stream = new PassThrough();

      // Reset backoff on successful connection
      this.backoff.set(podName, 1000);

      let buffer = "";
      stream.on("data", (chunk: Buffer) => {
        if (controller.signal.aborted) {
          stream.destroy();
          return;
        }

        buffer += chunk.toString();
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (!line.trim()) continue;
          this.processLine(line, podName);
        }
      });

      stream.on("error", (err) => {
        this.handleStreamError(podName, err, controller);
      });

      stream.on("end", () => {
        if (!controller.signal.aborted) {
          this.handleStreamError(
            podName,
            new Error("Stream ended unexpectedly"),
            controller,
          );
        }
      });

      await log.log(this.options.namespace, podName, this.options.containerName, stream, {
        follow: true,
        sinceSeconds: 1,
      });
    } catch (err) {
      this.handleStreamError(podName, err as Error, controller);
    }
  }

  private processLine(line: string, podName: string): void {
    // Try parsing as WAF event first
    const wafEvent = parseCorazaLog(line);
    if (wafEvent) {
      // Buffer the event and wait for a matching access log line
      const timer = setTimeout(() => {
        this.flushEvent(podName, wafEvent);
      }, BUFFER_TIMEOUT_MS);

      const pending = this.pendingEvents.get(podName);
      if (pending) {
        pending.push({ event: wafEvent, timer });
      } else {
        this.emitEnriched(wafEvent, podName);
      }
      return;
    }

    // Try parsing as access log
    const accessLog = parseAccessLog(line);
    if (accessLog) {
      this.correlateAccessLog(accessLog, podName);
    }
  }

  private correlateAccessLog(accessLog: AccessLogEntry, podName: string): void {
    const pending = this.pendingEvents.get(podName);
    if (!pending || pending.length === 0) return;

    // Match pending WAF events whose URI matches the access log path
    const matched: number[] = [];
    for (let i = 0; i < pending.length; i++) {
      const { event, timer } = pending[i];
      if (event.uri && accessLog.path && accessLog.path.includes(event.uri)) {
        clearTimeout(timer);
        matched.push(i);
        this.emitEnriched(event, podName, accessLog.authority);
      }
    }

    // Remove matched events in reverse order to preserve indices
    for (let i = matched.length - 1; i >= 0; i--) {
      pending.splice(matched[i], 1);
    }
  }

  private flushEvent(podName: string, event: WafEvent): void {
    // Timer expired without a matching access log — emit without authority
    const pending = this.pendingEvents.get(podName);
    if (pending) {
      const idx = pending.findIndex((p) => p.event === event);
      if (idx !== -1) {
        pending.splice(idx, 1);
      }
    }
    this.emitEnriched(event, podName);
  }

  private emitEnriched(event: WafEvent, podName: string, authority?: string): void {
    const enriched: EnrichedWafEvent = { ...event };

    if (authority) {
      enriched.authority = authority;
      const envMap = this.options.hostnameToEnvironment;
      if (envMap && envMap[authority]) {
        enriched.environment = envMap[authority];
      }
    }

    this.options.onEvent(enriched, podName);
  }

  private handleStreamError(
    podName: string,
    err: Error,
    controller: AbortController,
  ): void {
    if (controller.signal.aborted) return;

    this.options.onError?.(err, podName);

    const delay = Math.min(this.backoff.get(podName) ?? 1000, 30000);
    this.backoff.set(podName, delay * 2);

    setTimeout(() => {
      if (!controller.signal.aborted) {
        this.connectStream(podName, controller);
      }
    }, delay);
  }

  stopStream(podName: string): void {
    const controller = this.activeStreams.get(podName);
    if (controller) {
      controller.abort();
      this.activeStreams.delete(podName);
      this.backoff.delete(podName);
    }

    // Clear pending timers
    const pending = this.pendingEvents.get(podName);
    if (pending) {
      for (const { timer } of pending) {
        clearTimeout(timer);
      }
      this.pendingEvents.delete(podName);
    }
  }

  stopAll(): void {
    for (const [podName] of this.activeStreams) {
      this.stopStream(podName);
    }
  }
}
