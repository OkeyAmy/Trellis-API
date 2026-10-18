import {
  BadRequestException,
  ConflictException,
  HttpException,
  NotFoundException,
} from "@nestjs/common";
import {
  classifyError,
  duplicateSubmissions,
  expectSuccessCount,
  rejectionSummary,
  retryStorm,
  runConcurrently,
} from "./concurrency-harness";

/*
 * Self-tests for the concurrency harness (#218): the barrier guarantee,
 * outcome classification, invariant assertions, and the duplicate/retry
 * primitives. If the barrier ever degrades, races elsewhere silently stop
 * racing — that assertion is the harness's load-bearing wall.
 */
describe("concurrency harness", () => {
  describe("runConcurrently", () => {
    it("starts every actor before any actor can complete (start barrier)", async () => {
      const started: string[] = [];
      const startedAtCompletion: number[] = [];

      const report = await runConcurrently(4, async (actor) => {
        started.push(actor);
        await Promise.resolve();
        startedAtCompletion.push(started.length);
        return actor;
      });

      expect(started).toEqual(["actor-1", "actor-2", "actor-3", "actor-4"]);
      // Without the barrier the first completion would observe 1.
      expect(startedAtCompletion).toEqual([4, 4, 4, 4]);
      expectSuccessCount(report, 4);
    });

    it("accepts explicit actor names", async () => {
      const report = await runConcurrently(["alice", "bob"], async (actor) => `${actor}!`);
      expect(report.successes.map((outcome) => outcome.value)).toEqual([
        "alice!",
        "bob!",
      ]);
    });

    it("captures rejections as data instead of failing the whole run", async () => {
      const report = await runConcurrently(3, async (actor, index) => {
        if (index % 2 === 1) throw new ConflictException("claimed already");
        return actor;
      });

      expect(report.successes).toHaveLength(2);
      expect(report.rejections).toHaveLength(1);
      expect(report.rejections[0].actor).toBe("actor-2");
      expect(report.rejections[0].error).toEqual({
        name: "ConflictException",
        status: 409,
        message: "claimed already",
      });
    });
  });

  describe("classifyError", () => {
    it("extracts status and message from Nest exceptions", () => {
      expect(classifyError(new BadRequestException("bad key"))).toEqual({
        name: "BadRequestException",
        status: 400,
        message: "bad key",
      });
      expect(classifyError(new NotFoundException("gone"))).toMatchObject({
        status: 404,
        message: "gone",
      });
      expect(
        classifyError(
          new HttpException({ statusCode: 428, message: "need intent" }, 428)
        )
      ).toMatchObject({ status: 428, message: "need intent" });
    });

    it("falls back for plain errors and non-errors", () => {
      expect(classifyError(new Error("boom"))).toEqual({
        name: "Error",
        status: null,
        message: "boom",
      });
      expect(classifyError("raw string")).toMatchObject({
        status: null,
        message: "raw string",
      });
    });
  });

  describe("expectSuccessCount", () => {
    it("throws a diagnostic listing every actor's outcome", async () => {
      const report = await runConcurrently(2, async (_actor, index) => {
        if (index === 0) return "ok";
        throw new ConflictException("loser");
      });

      expect(() => expectSuccessCount(report, 2)).toThrow(
        /Expected 2 successful actor\(s\), got 1: actor-1=ok, actor-2=409\(ConflictException: loser\)/
      );
      expect(() => expectSuccessCount(report, 1)).not.toThrow();
    });
  });

  describe("rejectionSummary", () => {
    it("groups identical reasons and keeps distinct ones apart", async () => {
      const report = await runConcurrently(4, async (_actor, index) => {
        if (index < 2) throw new ConflictException("in progress");
        if (index === 2) throw new ConflictException("different payload");
        return "fine";
      });

      const summary = rejectionSummary(report);
      expect(summary).toHaveLength(2);
      expect(summary[0]).toMatchObject({
        status: 409,
        message: "in progress",
        count: 2,
        actors: ["actor-1", "actor-2"],
      });
      expect(summary[1]).toMatchObject({
        status: 409,
        message: "different payload",
        count: 1,
      });
    });
  });

  describe("duplicateSubmissions", () => {
    it("submits one payload from every copy in a single burst", async () => {
      const observed: string[] = [];
      const report = await duplicateSubmissions(5, async () => {
        observed.push("payload-v1");
        return "stored";
      });

      expect(report.outcomes.map((outcome) => outcome.actor)).toEqual([
        "submission-1",
        "submission-2",
        "submission-3",
        "submission-4",
        "submission-5",
      ]);
      expect(observed).toHaveLength(5);
      expectSuccessCount(report, 5);
    });
  });

  describe("retryStorm", () => {
    it("delivers 1-based attempt numbers to each concurrent retry", async () => {
      const attempts: number[] = [];
      const report = await retryStorm(3, async (attempt) => {
        attempts.push(attempt);
        return attempt;
      });

      expect(attempts.sort()).toEqual([1, 2, 3]);
      expectSuccessCount(report, 3);
    });
  });
});
