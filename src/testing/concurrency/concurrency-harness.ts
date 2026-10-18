import { HttpException } from "@nestjs/common";

/**
 * Multi-actor concurrency harness for race-prone mutations (#218).
 *
 * JavaScript is single-threaded, so "concurrent" in a test means N async
 * flows interleaved at `await` points. Tests that hand-roll `Promise.all`
 * get three things wrong in practice:
 *
 *  - **Races that never race.** Actors that start staggered (one after
 *    another via `await`) never overlap, so a broken claim path passes.
 *    The start barrier releases every actor together; each operation's
 *    synchronous prefix runs before any of them can complete, which is
 *    as close to simultaneous entry as a single event loop offers.
 *  - **Assertions on ordering.** `expect(results[0]).toBe(...)` encodes
 *    an accidental scheduling order. The report classifies outcomes
 *    (success / rejection with status and message) so tests assert
 *    *invariants*: "exactly one winner", "everyone else saw 409".
 *  - **Unobserved failures.** `Promise.all` rejects on the first error
 *    and hides the rest. Every actor's outcome is captured; rejections
 *    are data, never thrown out of the harness.
 *
 * Everything is deterministic: no wall clock sleeps, no random jitter,
 * no real threads. The primitives map onto the failure shapes production
 * actually sees:
 *
 *  - `runConcurrently`  — N actors submit the same critical write at once
 *  - `duplicateSubmissions` — an identical payload arrives k times (client
 *    retries, proxy replays, double-clicks)
 *  - `retryStorm`       — one client hammers an operation while the first
 *    attempt is still in flight or after it finished
 *
 * Combined with a state-capturing fake repository, tests also reproduce
 * the **stale version** shape: an actor that read state before a peer's
 * write then attempts its own write against the (now outdated) view.
 */

/** A rejection, reduced to what an assertion needs. */
export interface ClassifiedError {
  /** Exception class name, e.g. `ConflictException`. */
  name: string;
  /** HTTP status when the rejection carries one, else `null`. */
  status: number | null;
  /** Message a client would see (exception response message, or `Error.message`). */
  message: string;
}

/** What one actor observed. Exactly one of `value` / `error` is set. */
export interface ActorOutcome<T> {
  /** Actor name (from the input list, or generated for the numeric form). */
  actor: string;
  ok: boolean;
  value?: T;
  error?: ClassifiedError;
}

/** Aggregated results of one concurrent run. Never rejects. */
export interface ConcurrencyReport<T> {
  outcomes: ActorOutcome<T>[];
  successes: ActorOutcome<T>[];
  rejections: ActorOutcome<T>[];
}

/** One distinct rejection reason with the actors that produced it. */
export interface RejectionKind {
  status: number | null;
  name: string;
  message: string;
  count: number;
  actors: string[];
}

/** Reduces any thrown value to a comparable shape. */
export function classifyError(error: unknown): ClassifiedError {
  if (error instanceof HttpException) {
    const status = error.getStatus();
    const response = error.getResponse();
    let message = error.message;
    if (typeof response === "string") {
      message = response;
    } else if (response && typeof response === "object") {
      const body = response as { message?: unknown };
      if (typeof body.message === "string") {
        message = body.message;
      } else if (Array.isArray(body.message)) {
        message = body.message.join("; ");
      }
    }
    return { name: error.constructor.name, status, message };
  }
  if (error instanceof Error) {
    return { name: error.name, status: null, message: error.message };
  }
  return {
    name: typeof error,
    status: null,
    message: error === undefined ? "undefined" : String(error),
  };
}

function actorNames(actors: number | readonly string[]): string[] {
  if (typeof actors === "number") {
    return Array.from({ length: actors }, (_, index) => `actor-${index + 1}`);
  }
  return [...actors];
}

/**
 * Runs `operation` for every actor against a shared start barrier: all
 * actors begin together (each synchronous prefix runs before any actor can
 * complete), and every outcome — success or rejection — is captured.
 *
 * @param actors either a count (named `actor-1..n`) or explicit names.
 * @param operation the critical write under test, per actor.
 */
export async function runConcurrently<T>(
  actors: number | readonly string[],
  operation: (actor: string, index: number) => Promise<T>
): Promise<ConcurrencyReport<T>> {
  const names = actorNames(actors);

  let release: () => void = () => undefined;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });

  const pending = names.map(async (name, index) => {
    await gate;
    return operation(name, index);
  });

  // Release only after every actor is queued on the gate, so the first
  // await inside `operation` cannot resolve before all actors have started.
  release();

  const settled = await Promise.allSettled(pending);
  const outcomes: ActorOutcome<T>[] = settled.map((result, index) =>
    result.status === "fulfilled"
      ? { actor: names[index], ok: true, value: result.value }
      : { actor: names[index], ok: false, error: classifyError(result.reason) }
  );

  return {
    outcomes,
    successes: outcomes.filter((outcome) => outcome.ok),
    rejections: outcomes.filter((outcome) => !outcome.ok),
  };
}

/**
 * An identical payload submitted `copies` times in parallel — double-clicks,
 * proxy replays and client retries with a reused Idempotency-Key. The
 * operation closes over the shared payload; the actor name is decorative.
 */
export async function duplicateSubmissions<T>(
  copies: number,
  operation: () => Promise<T>
): Promise<ConcurrencyReport<T>> {
  return runConcurrently(
    Array.from({ length: copies }, (_, index) => `submission-${index + 1}`),
    () => operation()
  );
}

/**
 * One logical client hammering an operation `attempts` times concurrently —
 * a retry storm where attempts overlap the in-flight original rather than
 * waiting for it. `operation` receives the 1-based attempt number.
 */
export async function retryStorm<T>(
  attempts: number,
  operation: (attempt: number) => Promise<T>
): Promise<ConcurrencyReport<T>> {
  return runConcurrently(
    Array.from({ length: attempts }, (_, index) => `attempt-${index + 1}`),
    (_actor, index) => operation(index + 1)
  );
}

/** Throws unless exactly `expected` actors resolved successfully. */
export function expectSuccessCount<T>(
  report: ConcurrencyReport<T>,
  expected: number
): void {
  if (report.successes.length === expected) return;
  const detail = report.outcomes
    .map((outcome) =>
      outcome.ok
        ? `${outcome.actor}=ok`
        : `${outcome.actor}=${outcome.error?.status ?? "err"}(${outcome.error?.name}: ${outcome.error?.message})`
    )
    .join(", ");
  throw new Error(
    `Expected ${expected} successful actor(s), got ${report.successes.length}: ${detail}`
  );
}

/** Distinct rejection reasons (`status + name + message`) with counts. */
export function rejectionSummary<T>(
  report: ConcurrencyReport<T>
): RejectionKind[] {
  const kinds = new Map<string, RejectionKind>();
  for (const outcome of report.rejections) {
    const error = outcome.error!;
    const key = `${error.status ?? "non-http"}|${error.name}|${error.message}`;
    const kind = kinds.get(key);
    if (kind) {
      kind.count += 1;
      kind.actors.push(outcome.actor);
    } else {
      kinds.set(key, {
        status: error.status,
        name: error.name,
        message: error.message,
        count: 1,
        actors: [outcome.actor],
      });
    }
  }
  return [...kinds.values()];
}
