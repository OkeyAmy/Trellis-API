import {
  duplicateSubmissions,
  expectSuccessCount,
  rejectionSummary,
  retryStorm,
  runConcurrently,
} from "src/testing/concurrency/concurrency-harness";
import { IdempotencyService, isUniqueViolation } from "./idempotency.service";
import {
  IdempotencyRecord,
  IdempotencyRecordStatus,
} from "./entities/idempotency-record.entity";

/*
 * Concurrency harness against the idempotency layer (#218): duplicate
 * submissions, in-flight retry storms, stale views and key-reuse races
 * around the `(scope, key)` claim that guards every idempotent write.
 *
 * The repository fake models the production contract the entity documents:
 * `(scope, idempotencyKey)` is unique (the second INSERT raises SQLSTATE
 * 23505), and every method crosses a real async boundary — the round trip
 * where concurrent flows interleave.
 */

const SCOPE = "POST:/payments:user-1";
const KEY = "payment-key-0001";

const tick = () => new Promise<void>((resolve) => setImmediate(resolve));

class RacingIdempotencyRepository {
  rows: IdempotencyRecord[] = [];

  create(partial: Partial<IdempotencyRecord>): IdempotencyRecord {
    return { ...partial } as IdempotencyRecord;
  }

  async save(record: IdempotencyRecord): Promise<IdempotencyRecord> {
    await tick();
    const index = this.rows.findIndex(
      (row) =>
        row.scope === record.scope && row.idempotencyKey === record.idempotencyKey
    );
    if (index >= 0 && this.rows[index] !== record) {
      // A different row already owns the key: the unique index rejects the
      // INSERT, exactly as `UQ_idempotency_scope_key` does in production.
      const error = new Error(
        'duplicate key value violates unique constraint "UQ_idempotency_scope_key"'
      ) as Error & { code: string };
      error.code = "23505";
      throw error;
    }
    if (index >= 0) this.rows[index] = record;
    else this.rows.push(record);
    return record;
  }

  async findOne(options: {
    where: { scope: string; idempotencyKey: string };
  }): Promise<IdempotencyRecord | null> {
    await tick();
    const { scope, idempotencyKey } = options.where;
    return (
      this.rows.find(
        (row) => row.scope === scope && row.idempotencyKey === idempotencyKey
      ) ?? null
    );
  }

  async remove(
    record: IdempotencyRecord | IdempotencyRecord[]
  ): Promise<IdempotencyRecord | IdempotencyRecord[]> {
    await tick();
    const targets = Array.isArray(record) ? record : [record];
    this.rows = this.rows.filter((row) => !targets.includes(row));
    return record;
  }
}

function buildService() {
  const repo = new RacingIdempotencyRepository();
  const service = new IdempotencyService(repo as never);
  return { repo, service };
}

async function waitFor(condition: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (condition()) return;
    await tick();
  }
  throw new Error("condition never became true");
}

const successfulHandler = () => ({
  statusCode: 201,
  body: { id: "payment-1" },
});

describe("IdempotencyService concurrency (harness)", () => {
  it("executes the handler exactly once for concurrent duplicate submissions", async () => {
    const { repo, service } = buildService();
    let handlerCalls = 0;
    const handler = async () => {
      handlerCalls += 1;
      return successfulHandler();
    };

    const report = await duplicateSubmissions(5, () =>
      service.execute({ key: KEY, scope: SCOPE, requestHash: "hash-v1", handler })
    );

    expect(handlerCalls).toBe(1);
    expect(report.outcomes).toHaveLength(5);
    expect(repo.rows).toHaveLength(1);

    // Every loser sees the documented 409 — a raw unique-index 500 here is
    // the regression this suite exists to catch.
    for (const kind of rejectionSummary(report)) {
      expect(kind.status).toBe(409);
    }

    // Exactly one actor ran the handler; the rest are replays of its stored
    // response (or 409s, depending on when each loser re-read the row).
    const originals = report.successes.filter(
      (outcome) => outcome.value?.replayed === false
    );
    expect(originals).toHaveLength(1);
    for (const success of report.successes) {
      expect(success.value?.body).toEqual({ id: "payment-1" });
      expect(success.value?.statusCode).toBe(201);
    }
  });

  it("rejects a retry storm overlapping an in-flight request with 409s", async () => {
    const { repo, service } = buildService();
    let handlerCalls = 0;
    let releaseHandler: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      releaseHandler = resolve;
    });

    const inFlight = service.execute({
      key: KEY,
      scope: SCOPE,
      requestHash: "hash-v1",
      handler: async () => {
        handlerCalls += 1;
        await gate;
        return successfulHandler();
      },
    });
    await waitFor(
      () => repo.rows[0]?.status === IdempotencyRecordStatus.IN_PROGRESS
    );

    const storm = await retryStorm(4, () =>
      service.execute({ key: KEY, scope: SCOPE, requestHash: "hash-v1", handler: async () => successfulHandler() })
    );

    expect(handlerCalls).toBe(1);
    expect(storm.successes).toHaveLength(0);
    expect(storm.rejections).toHaveLength(4);
    for (const kind of rejectionSummary(storm)) {
      expect(kind.status).toBe(409);
      expect(kind.message).toContain("already in progress");
    }

    releaseHandler();
    const first = await inFlight;
    expect(first.replayed).toBe(false);
    expect(first.body).toEqual({ id: "payment-1" });
    expect(handlerCalls).toBe(1);
  });

  it("corrects a stale in-progress view: the next retry replays instead of re-running", async () => {
    const { repo, service } = buildService();
    let handlerCalls = 0;
    let releaseHandler: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      releaseHandler = resolve;
    });

    const inFlight = service.execute({
      key: KEY,
      scope: SCOPE,
      requestHash: "hash-v1",
      handler: async () => {
        handlerCalls += 1;
        await gate;
        return successfulHandler();
      },
    });
    await waitFor(
      () => repo.rows[0]?.status === IdempotencyRecordStatus.IN_PROGRESS
    );
    // The client's snapshot: taken while the request was still running.
    const staleSnapshot = { ...repo.rows[0] };

    releaseHandler();
    await inFlight;
    expect(staleSnapshot.status).toBe(IdempotencyRecordStatus.IN_PROGRESS);

    // Acting on the stale belief would double-charge; the service re-reads
    // current state and replays the stored response instead.
    const retry = await service.execute({
      key: KEY,
      scope: SCOPE,
      requestHash: "hash-v1",
      handler: async () => {
        handlerCalls += 1;
        return successfulHandler();
      },
    });

    expect(retry.replayed).toBe(true);
    expect(retry.body).toEqual({ id: "payment-1" });
    expect(handlerCalls).toBe(1);
  });

  it("rejects a concurrent key reuse with a different payload while the winner completes once", async () => {
    const { service } = buildService();
    let handlerCalls = 0;
    const handler = async () => {
      handlerCalls += 1;
      return successfulHandler();
    };

    const report = await runConcurrently(["payload-a", "payload-b"], (_actor, index) =>
      service.execute({
        key: KEY,
        scope: SCOPE,
        requestHash: index === 0 ? "hash-v1" : "hash-v2",
        handler,
      })
    );

    expect(handlerCalls).toBe(1);
    expectSuccessCount(report, 1);
    const kinds = rejectionSummary(report);
    expect(kinds).toHaveLength(1);
    expect(kinds[0]).toMatchObject({
      status: 409,
      message: "Idempotency-Key was already used for a different request payload",
    });
  });

  it("treats only SQLSTATE 23505-shaped failures as unique violations", () => {
    const codeError = Object.assign(new Error("insert failed"), {
      code: "23505",
    });
    expect(isUniqueViolation(codeError)).toBe(true);
    expect(isUniqueViolation({ driverError: { code: "23505" } })).toBe(true);
    expect(
      isUniqueViolation(
        new Error('duplicate key value violates unique constraint "uq"')
      )
    ).toBe(true);
    expect(isUniqueViolation(new Error("connection reset"))).toBe(false);
    expect(isUniqueViolation(null)).toBe(false);
    expect(isUniqueViolation("23505")).toBe(false);
  });
});
