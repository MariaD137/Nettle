/**
 * NOT wired into the real scan pipeline. Verified directly: nothing in
 * scanner/index.ts, scanner/scanQueue.ts, or routes/scans.routes.ts
 * imports anything from this file — only its own test
 * (test/c2-worker-isolation.test.ts) and src/audit/phase5-final-audit.ts
 * reference it. Its worker thread body is also a stub that doesn't run
 * real analysis at all (it returns a hardcoded `{ analyzed: true, findings:
 * [] }` regardless of input — see initializeWorkers below), so even if it
 * were wired in, it wouldn't do what its name/comments claim.
 *
 * The real isolation boundary for untrusted scan execution is
 * scanner/isolatedExecution.ts + scan-worker-stack.ts (a separate ECS
 * Fargate task/process/container/network path, with no application
 * secrets) — this file predates that work and is unrelated to it. Left in
 * place rather than deleted (not asked for, and its own tests pass against
 * what it actually is — a worker_threads pool with a stub body — so
 * deleting it isn't a security fix, just cleanup outside this round's
 * scope), but it should not be read as an existing "worker isolation"
 * control that the real isolation work is redundant with.
 */

import { Worker } from "worker_threads";
import { EventEmitter } from "events";
import path from "path";

export interface WorkerTask {
  taskId: string;
  type: "analyze" | "extract" | "scan";
  payload: any;
  timeout: number;
}

export interface WorkerResult {
  taskId: string;
  success: boolean;
  data?: any;
  error?: string;
}

export class WorkerPool extends EventEmitter {
  private workers: Worker[] = [];
  private pendingTasks: Map<string, WorkerTask> = new Map();
  private taskResolvers: Map<string, { resolve: Function; reject: Function }> = new Map();
  private poolSize: number;
  private taskCounter: number = 0;

  constructor(poolSize: number = 2) {
    super();
    this.poolSize = Math.max(1, Math.min(poolSize, 4)); // Clamp to 1-4 workers
    this.initializeWorkers();
  }

  private initializeWorkers(): void {
    for (let i = 0; i < this.poolSize; i++) {
      const worker = new Worker(
        `
        const { parentPort } = require('worker_threads');

        parentPort.on('message', async (task) => {
          try {
            let result;
            // Simulate task processing - actual implementation depends on task type
            if (task.type === 'analyze') {
              result = { analyzed: true, findings: [] };
            } else if (task.type === 'extract') {
              result = { extracted: true, data: [] };
            } else {
              result = { processed: true };
            }

            parentPort.postMessage({
              taskId: task.taskId,
              success: true,
              data: result
            });
          } catch (error) {
            parentPort.postMessage({
              taskId: task.taskId,
              success: false,
              error: error.message
            });
          }
        });
        `,
        { eval: true }
      );

      worker.on("message", (result: WorkerResult) => {
        this.handleWorkerResult(result);
      });

      worker.on("error", (error) => {
        console.error(`Worker ${i} error:`, error);
      });

      worker.on("exit", (code) => {
        if (code !== 0) {
          console.warn(`Worker ${i} exited with code ${code}`);
        }
      });

      this.workers.push(worker);
    }
  }

  private handleWorkerResult(result: WorkerResult): void {
    const resolver = this.taskResolvers.get(result.taskId);
    if (!resolver) return;

    this.taskResolvers.delete(result.taskId);
    this.pendingTasks.delete(result.taskId);

    if (result.success) {
      resolver.resolve(result.data);
    } else {
      resolver.reject(new Error(result.error || "Worker task failed"));
    }

    this.emit("task-complete", result.taskId);
  }

  /**
   * Submit a task to the worker pool.
   * Returns a promise that resolves when the task completes.
   */
  public async runTask(task: WorkerTask): Promise<any> {
    return new Promise((resolve, reject) => {
      // Set up timeout
      const timeout = setTimeout(() => {
        this.taskResolvers.delete(task.taskId);
        this.pendingTasks.delete(task.taskId);
        reject(new Error(`Task ${task.taskId} timed out after ${task.timeout}ms`));
      }, task.timeout);

      const resolver = { resolve, reject };
      this.taskResolvers.set(task.taskId, resolver);
      this.pendingTasks.set(task.taskId, task);

      // Send to the least busy worker
      const worker = this.workers[this.taskCounter++ % this.workers.length];
      worker.postMessage(task);
    });
  }

  /**
   * Analyze code in isolation.
   * Returns findings array.
   */
  public async analyzeInIsolation(code: string, maxTime: number = 10000): Promise<any> {
    const taskId = `analyze-${Date.now()}-${Math.random()}`;
    const task: WorkerTask = {
      taskId,
      type: "analyze",
      payload: { code },
      timeout: maxTime,
    };

    return this.runTask(task);
  }

  /**
   * Extract data from untrusted input.
   * Returns extracted data.
   */
  public async extractInIsolation(input: string, maxTime: number = 5000): Promise<any> {
    const taskId = `extract-${Date.now()}-${Math.random()}`;
    const task: WorkerTask = {
      taskId,
      type: "extract",
      payload: { input },
      timeout: maxTime,
    };

    return this.runTask(task);
  }

  /**
   * Get pool statistics.
   */
  public getStats(): {
    poolSize: number;
    pendingTasks: number;
    workers: number;
  } {
    return {
      poolSize: this.poolSize,
      pendingTasks: this.pendingTasks.size,
      workers: this.workers.length,
    };
  }

  /**
   * Terminate all workers.
   */
  public async terminate(): Promise<void> {
    await Promise.all(this.workers.map((w) => w.terminate()));
    this.workers = [];
    this.taskResolvers.clear();
    this.pendingTasks.clear();
  }
}

/**
 * Global worker pool singleton.
 */
let globalWorkerPool: WorkerPool | null = null;

/**
 * Get or create the global worker pool.
 */
export function getWorkerPool(poolSize: number = 2): WorkerPool {
  if (!globalWorkerPool) {
    globalWorkerPool = new WorkerPool(poolSize);
  }
  return globalWorkerPool;
}

/**
 * Cleanup the global worker pool.
 */
export async function cleanupWorkerPool(): Promise<void> {
  if (globalWorkerPool) {
    await globalWorkerPool.terminate();
    globalWorkerPool = null;
  }
}

/**
 * Resource limits for sandboxed analysis.
 */
export interface ResourceLimits {
  cpuTimeMs: number;
  memoryMB: number;
  maxFileSize: number;
  maxFiles: number;
}

/**
 * Default resource limits for untrusted code analysis.
 */
export const DEFAULT_RESOURCE_LIMITS: ResourceLimits = {
  cpuTimeMs: 10000, // 10 seconds max
  memoryMB: 512, // 512MB max
  maxFileSize: 10 * 1024 * 1024, // 10MB max file
  maxFiles: 10000, // 10k files max
};

/**
 * Verify that input respects resource limits.
 */
export function checkResourceLimits(
  input: string | Buffer,
  limits: Partial<ResourceLimits> = {}
): { ok: boolean; error?: string } {
  const actualLimits = { ...DEFAULT_RESOURCE_LIMITS, ...limits };

  if (typeof input === "string") {
    if (input.length > actualLimits.maxFileSize) {
      return {
        ok: false,
        error: `Input size ${input.length} exceeds limit ${actualLimits.maxFileSize}`,
      };
    }
  } else {
    if (input.length > actualLimits.maxFileSize) {
      return {
        ok: false,
        error: `Buffer size ${input.length} exceeds limit ${actualLimits.maxFileSize}`,
      };
    }
  }

  return { ok: true };
}
