import * as k8s from "@kubernetes/client-node";
import { EventEmitter } from "node:events";

export interface PodWatcherOptions {
  namespace: string;
  labelSelector: string;
}

export class PodWatcher extends EventEmitter {
  private coreApi: k8s.CoreV1Api;
  private watch: k8s.Watch;
  private options: PodWatcherOptions;
  private activePods = new Set<string>();
  private abortController: AbortController | null = null;

  constructor(kc: k8s.KubeConfig, options: PodWatcherOptions) {
    super();
    this.coreApi = kc.makeApiClient(k8s.CoreV1Api);
    this.watch = new k8s.Watch(kc);
    this.options = options;
  }

  async start(): Promise<void> {
    const { items } = await this.coreApi.listNamespacedPod({
      namespace: this.options.namespace,
      labelSelector: this.options.labelSelector,
    });

    for (const pod of items) {
      const name = pod.metadata?.name;
      if (name && pod.status?.phase === "Running") {
        this.activePods.add(name);
        this.emit("added", name);
      }
    }

    this.watchPods();
  }

  private async watchPods(): Promise<void> {
    const path = `/api/v1/namespaces/${this.options.namespace}/pods`;
    try {
      this.abortController = await this.watch.watch(
        path,
        { labelSelector: this.options.labelSelector },
        (type: string, pod: k8s.V1Pod) => {
          const name = pod.metadata?.name;
          if (!name) return;

          if (
            type === "ADDED" ||
            (type === "MODIFIED" && pod.status?.phase === "Running")
          ) {
            if (!this.activePods.has(name)) {
              this.activePods.add(name);
              this.emit("added", name);
            }
          } else if (type === "DELETED") {
            if (this.activePods.delete(name)) {
              this.emit("removed", name);
            }
          }
        },
        (err: unknown) => {
          if (err) this.emit("error", err);
          setTimeout(() => this.watchPods(), 5000);
        },
      );
    } catch (err) {
      this.emit("error", err);
      setTimeout(() => this.watchPods(), 5000);
    }
  }

  stop(): void {
    this.abortController?.abort();
  }

  getPods(): string[] {
    return Array.from(this.activePods);
  }
}
