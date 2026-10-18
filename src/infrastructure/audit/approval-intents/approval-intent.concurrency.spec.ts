import { ConflictException } from "@nestjs/common";
import {
  expectSuccessCount,
  rejectionSummary,
  retryStorm,
  runConcurrently,
} from "src/testing/concurrency/concurrency-harness";
import { ApprovalIntentStatus } from "./approval-intent.types";
import { createService, proposedIntent } from "./testing/approval-intent.testkit";

/*
 * Concurrency harness against the approval-intent claim (#218): concurrent
 * actors racing one intent, duplicate submissions of the same intent id,
 * stale reads acted upon after a peer finished, and retry storms against a
 * terminal row — plus the cancel-vs-execute mutual exclusion that keeps a
 * withdrawal from ever clobbering a live execution.
 *
 * The shared fake repository models a conditional SQL UPDATE
 * (`... WHERE status = 'proposed'`) as one synchronous pass over the rows,
 * which is the guarantee the production claim relies on.
 */

describe("ApprovalIntentService concurrency (harness)", () => {
  it("lets exactly one concurrent actor claim a proposed intent", async () => {
    const { service, repo } = createService();
    const intent = await proposedIntent(service);
    let runs = 0;

    const report = await runConcurrently(5, (name) =>
      service.execute(intent.id, { id: name, role: "ADMIN" }, async () => {
        runs += 1;
        return `done:${name}`;
      })
    );

    expectSuccessCount(report, 1);
    expect(runs).toBe(1);
    expect(report.rejections).toHaveLength(4);
    for (const kind of rejectionSummary(report)) {
      expect(kind.status).toBe(409);
      expect(kind.message).toMatch(
        /claimed by another execution|can no longer execute/
      );
    }

    const row = repo.rows.get(intent.id)!;
    expect(row.status).toBe(ApprovalIntentStatus.COMPLETED);
    expect(row.receipt).toBeDefined();
    expect(report.successes[0].value?.result).toBe(
      `done:${report.successes[0].actor}`
    );
  });

  it("rejects a retry storm against a completed intent without re-running the work", async () => {
    const { service } = createService();
    const intent = await proposedIntent(service);
    let runs = 0;
    const operation = async () => {
      runs += 1;
      return "executed";
    };

    await service.execute(intent.id, { id: "admin-2", role: "ADMIN" }, operation);
    expect(runs).toBe(1);

    const storm = await retryStorm(4, () =>
      service.execute(intent.id, { id: "admin-2", role: "ADMIN" }, operation)
    );

    expect(storm.successes).toHaveLength(0);
    expect(storm.rejections).toHaveLength(4);
    for (const kind of rejectionSummary(storm)) {
      expect(kind.status).toBe(409);
      expect(kind.message).toContain("can no longer execute");
    }
    expect(runs).toBe(1);
  });

  it("discards a stale proposed-state view: later claims re-read current state", async () => {
    const { service } = createService();
    const intent = await proposedIntent(service);
    let runs = 0;
    const operation = async () => {
      runs += 1;
      return "executed";
    };

    // Actor A reads the intent while it is still proposed...
    const staleSnapshot = await service.get(intent.id);
    // ...actor B completes it in the meantime...
    await service.execute(intent.id, { id: "admin-2", role: "ADMIN" }, operation);
    expect(staleSnapshot.status).toBe(ApprovalIntentStatus.PROPOSED);

    // ...so A's write, computed from its stale view, must lose cleanly.
    await expect(
      service.execute(intent.id, { id: "admin-3", role: "ADMIN" }, operation),
    ).rejects.toBeInstanceOf(ConflictException);
    await expect(
      service.cancel(intent.id, { id: "admin-3" }, "stale withdrawal"),
    ).rejects.toBeInstanceOf(ConflictException);

    expect(runs).toBe(1);
    expect((await service.get(intent.id)).status).toBe(
      ApprovalIntentStatus.COMPLETED,
    );
  });

  it("keeps cancellation and execution mutually exclusive under a race", async () => {
    const { service, repo } = createService();
    const intent = await proposedIntent(service);
    let runs = 0;

    const [cancelResult, executeResult] = await Promise.allSettled([
      service.cancel(intent.id, { id: "admin-c" }, "withdrawn concurrently"),
      service.execute(intent.id, { id: "admin-x", role: "ADMIN" }, async () => {
        runs += 1;
        return "executed";
      }),
    ]);

    // Exactly one side effect ever lands; the row agrees with which one.
    const fulfilled = [cancelResult, executeResult].filter(
      (result) => result.status === "fulfilled"
    );
    expect(fulfilled).toHaveLength(1);

    const row = repo.rows.get(intent.id)!;
    if (row.status === ApprovalIntentStatus.CANCELLED) {
      expect(cancelResult.status).toBe("fulfilled");
      expect(executeResult.status).toBe("rejected");
      expect(runs).toBe(0);
      expect(
        (executeResult as PromiseRejectedResult).reason,
      ).toBeInstanceOf(ConflictException);
    } else {
      expect(row.status).toBe(ApprovalIntentStatus.COMPLETED);
      expect(executeResult.status).toBe("fulfilled");
      expect(cancelResult.status).toBe("rejected");
      expect(runs).toBe(1);
      expect(
        (cancelResult as PromiseRejectedResult).reason,
      ).toBeInstanceOf(ConflictException);
    }
  });
});
