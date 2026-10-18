import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  ServiceUnavailableException,
} from "@nestjs/common";
import {
  ApprovalIntentService,
  isMaintainerApprovalEnforced,
} from "./approval-intent.service";
import { SensitiveAction } from "../sensitive-actions/sensitive-action.enum";
import { ApprovalIntentStatus } from "./approval-intent.types";
import { hashReceipt, verifyReceipt } from "./approval-intent.receipt";
import { approvalIntentFingerprint } from "./approval-intent.fingerprint";
import { createService, proposedIntent } from "./testing/approval-intent.testkit";

/*
 * Unit tests for the approval intent service (#220): proposal, single-use
 * execution with signed receipts, cancellation, expiry and verification.
 *
 * Fixtures — the in-memory repository whose conditional `update` mirrors a
 * guarded SQL UPDATE, the signer and the builders — come from
 * ./testing/approval-intent.testkit, shared with the concurrency suite so
 * both observe identical claim semantics.
 */

describe("ApprovalIntentService", () => {
  describe("propose", () => {
    it("persists a proposed intent with a signed fingerprint and TTL", async () => {
      const { service, signer, audit } = createService();
      const before = Date.now();

      const intent = await proposedIntent(service);

      expect(intent.status).toBe(ApprovalIntentStatus.PROPOSED);
      expect(intent.id).toBeDefined();
      expect(intent.actorId).toBe("admin-1");
      expect(intent.payloadHash).toHaveLength(64);
      expect(intent.fingerprint).toBe(
        approvalIntentFingerprint({
          action: SensitiveAction.ROLE_ASSIGNED,
          actorId: "admin-1",
          resourceType: "user",
          resourceId: "user-7",
          reason: "Promotion approved in ticket OPS-142",
          payload: { role: "MAINTAINER" },
        }),
      );
      expect(intent.intentSignature).toBe(signer.sign(intent.fingerprint));
      expect(intent.expiresAt.getTime()).toBeGreaterThanOrEqual(
        before + 900 * 1000,
      );
      expect(intent.expiresAt.getTime()).toBeLessThanOrEqual(
        Date.now() + 900 * 1000,
      );

      expect(audit.recordSensitiveAction).toHaveBeenCalledWith(
        expect.objectContaining({
          action: SensitiveAction.MAINTAINER_ACTION_PROPOSED,
          actorId: "admin-1",
          resourceId: "user-7",
          metadata: expect.objectContaining({ intentId: intent.id }),
        }),
      );
    });

    it("rejects an unknown action, a missing reason, or a missing actor", async () => {
      const { service } = createService();

      await expect(
        proposedIntent(service, { action: "not.a.real.action" }),
      ).rejects.toBeInstanceOf(BadRequestException);
      await expect(proposedIntent(service, { reason: "   " })).rejects.toBeInstanceOf(
        BadRequestException,
      );
      await expect(
        proposedIntent(service, { actor: { id: "" } }),
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    it("rejects self-approval: the approver must differ from the actor", async () => {
      const { service } = createService();

      await expect(
        proposedIntent(service, { approverId: "admin-1" }),
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    it("rejects a TTL below the floor", async () => {
      const { service } = createService();

      await expect(
        proposedIntent(service, { ttlSeconds: 5 }),
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    it("treats an identical still-proposed commitment as a conflict", async () => {
      const { service } = createService();
      const first = await proposedIntent(service);

      await expect(proposedIntent(service)).rejects.toThrow(
        new ConflictException(
          `An identical intent is already proposed as ${first.id}; ` +
            "execute or cancel it before proposing another",
        ),
      );
    });

    it("cancels the intent when proposal evidence fails (fail closed)", async () => {
      const audit = {
        recordSensitiveAction: jest
          .fn()
          .mockRejectedValueOnce(new Error("chain head mismatch")),
      };
      const { service, repo } = createService({ audit });

      await expect(proposedIntent(service)).rejects.toBeInstanceOf(
        ServiceUnavailableException,
      );

      const [row] = [...repo.rows.values()];
      expect(row?.status).toBe(ApprovalIntentStatus.CANCELLED);
    });
  });

  describe("cancel", () => {
    it("withdraws a proposed intent and records the cancellation under the canceller", async () => {
      const { service, audit } = createService();
      const intent = await proposedIntent(service);

      const cancelled = await service.cancel(
        intent.id,
        { id: "admin-2", role: "ADMIN" },
        "Superseded by a corrected request",
      );

      expect(cancelled.status).toBe(ApprovalIntentStatus.CANCELLED);
      // The signed commitment keeps the proposal's reason verbatim.
      expect(cancelled.reason).toBe(
        "Promotion approved in ticket OPS-142",
      );
      expect(audit.recordSensitiveAction).toHaveBeenLastCalledWith(
        expect.objectContaining({
          action: SensitiveAction.MAINTAINER_ACTION_CANCELLED,
          actorId: "admin-2",
          reason: "Superseded by a corrected request",
        }),
      );
    });

    it("refuses to cancel anything that is not proposed", async () => {
      const { service } = createService();
      const intent = await proposedIntent(service);
      await service.expireIntent(intent.id);

      await expect(
        service.cancel(intent.id, { id: "admin-2" }, "changed my mind"),
      ).rejects.toBeInstanceOf(ConflictException);
    });

    it("requires a cancellation reason", async () => {
      const { service } = createService();
      const intent = await proposedIntent(service);

      await expect(
        service.cancel(intent.id, { id: "admin-2" }, "  "),
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    it("still cancels when the evidence append fails (best effort)", async () => {
      const audit = {
        recordSensitiveAction: jest
          .fn()
          // Proposal evidence succeeds; only the cancellation's append fails.
          .mockResolvedValueOnce({})
          .mockRejectedValueOnce(new Error("db blip")),
      };
      const { service } = createService({ audit });
      const intent = await proposedIntent(service);

      const cancelled = await service.cancel(intent.id, { id: "admin-2" }, "nope");
      expect(cancelled.status).toBe(ApprovalIntentStatus.CANCELLED);
    });
  });

  describe("expiry", () => {
    it("ages out one proposed intent on demand", async () => {
      const { service } = createService();
      const intent = await proposedIntent(service);

      const expired = await service.expireIntent(intent.id);
      expect(expired.status).toBe(ApprovalIntentStatus.EXPIRED);

      await expect(
        service.expireIntent(intent.id),
      ).rejects.toBeInstanceOf(ConflictException);
    });

    it("bulk-expires only due proposed intents and reports the count", async () => {
      const { service, repo } = createService();
      const due = await proposedIntent(service, { resourceId: "user-a" });
      await proposedIntent(service, { resourceId: "user-b" });
      const future = new Date(Date.now() + 3_600_000);
      repo.rows.get(due.id)!.expiresAt = future;

      await expect(service.expireDueIntents()).resolves.toBe(0);

      repo.rows.get(due.id)!.expiresAt = new Date(Date.now() - 1000);
      await expect(service.expireDueIntents()).resolves.toBe(1);
    });
  });

  describe("execute", () => {
    it("claims the intent once, runs the operation and stores a verifiable receipt", async () => {
      const { service, signer, audit } = createService();
      const intent = await proposedIntent(service);
      const operation = jest.fn().mockResolvedValue({ ok: true });

      const { intent: finished, result } = await service.execute(
        intent.id,
        { id: "admin-2", role: "ADMIN" },
        operation,
      );

      expect(result).toEqual({ ok: true });
      expect(operation).toHaveBeenCalledTimes(1);
      expect(finished.status).toBe(ApprovalIntentStatus.COMPLETED);
      expect(finished.startedAt).toBeInstanceOf(Date);
      expect(finished.completedAt).toBeInstanceOf(Date);
      expect(finished.receiptHash).toBe(hashReceipt(finished.receipt!));
      expect(
        verifyReceipt(finished.receipt!, {
          receiptHash: finished.receiptHash!,
          signature: finished.receiptSignature!,
          signingAlgorithm: finished.signatureAlgorithm,
        }, signer).valid,
      ).toBe(true);

      await expect(service.verify(intent.id)).resolves.toMatchObject({
        intentId: intent.id,
        status: ApprovalIntentStatus.COMPLETED,
        valid: true,
        errors: [],
      });

      expect(audit.recordSensitiveAction).toHaveBeenLastCalledWith(
        expect.objectContaining({
          action: SensitiveAction.MAINTAINER_ACTION_EXECUTED,
          actorId: "admin-2",
          metadata: expect.objectContaining({
            intentId: intent.id,
            receiptHash: finished.receiptHash,
          }),
        }),
      );
    });

    it("records a signed failure receipt and rethrows when the operation throws", async () => {
      const { service } = createService();
      const intent = await proposedIntent(service);
      const boom = new Error("assignRole exploded");

      await expect(
        service.execute(intent.id, { id: "admin-2", role: "ADMIN" }, async () => {
          throw boom;
        }),
      ).rejects.toBe(boom);

      const row = await service.get(intent.id);
      expect(row.status).toBe(ApprovalIntentStatus.FAILED);
      expect(row.failureReason).toBe("assignRole exploded");
      expect(row.receipt?.status).toBe(ApprovalIntentStatus.FAILED);
      expect(row.receipt?.failureReason).toBe("assignRole exploded");
      expect(row.receiptHash).toHaveLength(64);
    });

    it("refuses to execute a terminal intent", async () => {
      const { service } = createService();
      const intent = await proposedIntent(service);
      await service.cancel(intent.id, { id: "admin-2" }, "not needed");

      await expect(
        service.execute(intent.id, { id: "admin-2", role: "ADMIN" }, async () => "x"),
      ).rejects.toBeInstanceOf(ConflictException);
    });

    it("expires an intent that outlived its TTL instead of executing it", async () => {
      const { service, repo } = createService();
      const intent = await proposedIntent(service);
      repo.rows.get(intent.id)!.expiresAt = new Date(Date.now() - 1000);

      await expect(
        service.execute(intent.id, { id: "admin-2", role: "ADMIN" }, async () => "x"),
      ).rejects.toBeInstanceOf(ConflictException);
      expect((await service.get(intent.id)).status).toBe(
        ApprovalIntentStatus.EXPIRED,
      );
    });

    it("loses the atomic claim cleanly when another execution got there first", async () => {
      const { service, repo } = createService();
      const intent = await proposedIntent(service);

      // Simulate the racing execution by flipping the row after load checks
      // but before the conditional update is applied.
      (repo.update as jest.Mock).mockImplementationOnce(async () => ({
        affected: 0,
      }));

      await expect(
        service.execute(intent.id, { id: "admin-2", role: "ADMIN" }, async () => "x"),
      ).rejects.toThrow("claimed by another execution");
    });

    it("lets only the designated approver execute when one is set", async () => {
      const { service } = createService();
      const intent = await proposedIntent(service, { approverId: "admin-7" });

      await expect(
        service.execute(intent.id, { id: "admin-2", role: "ADMIN" }, async () => "x"),
      ).rejects.toBeInstanceOf(ForbiddenException);

      const { intent: finished } = await service.execute(
        intent.id,
        { id: "admin-7", role: "MAINTAINER" },
        async () => "x",
      );
      expect(finished.status).toBe(ApprovalIntentStatus.COMPLETED);
    });

    it("re-checks the executor role when no approver is designated", async () => {
      const { service } = createService();
      const intent = await proposedIntent(service);

      await expect(
        service.execute(intent.id, { id: "operator-1", role: "OPERATOR" }, async () => "x"),
      ).rejects.toBeInstanceOf(ForbiddenException);
      await expect(
        service.execute(intent.id, { id: "operator-1" }, async () => "x"),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });
  });

  describe("verify", () => {
    it("detects a tampered receipt document after the fact", async () => {
      const { service, repo } = createService();
      const intent = await proposedIntent(service);
      await service.execute(intent.id, { id: "admin-2", role: "ADMIN" }, async () => "x");

      // Poke the stored row directly, bypassing the service's storage path.
      const stored = repo.rows.get(intent.id)!;
      stored.receipt = { ...stored.receipt!, reason: "edited by an insider" } as never;

      const verification = await service.verify(intent.id);
      expect(verification.valid).toBe(false);
      expect(verification.errors.join(" ")).toContain("Receipt hash mismatch");
    });

    it("reports an intent without a receipt instead of throwing", async () => {
      const { service } = createService();
      const intent = await proposedIntent(service);

      await expect(service.verify(intent.id)).resolves.toMatchObject({
        valid: false,
        errors: [expect.stringContaining("no signed receipt")],
      });
    });
  });

  describe("isMaintainerApprovalEnforced", () => {
    it("accepts true/1/yes case-insensitively and rejects everything else", () => {
      expect(isMaintainerApprovalEnforced({ MAINTAINER_APPROVAL_INTENTS_ENFORCED: "true" })).toBe(true);
      expect(isMaintainerApprovalEnforced({ MAINTAINER_APPROVAL_INTENTS_ENFORCED: "TRUE" })).toBe(true);
      expect(isMaintainerApprovalEnforced({ MAINTAINER_APPROVAL_INTENTS_ENFORCED: "1" })).toBe(true);
      expect(isMaintainerApprovalEnforced({ MAINTAINER_APPROVAL_INTENTS_ENFORCED: "yes" })).toBe(true);
      expect(isMaintainerApprovalEnforced({ MAINTAINER_APPROVAL_INTENTS_ENFORCED: "false" })).toBe(false);
      expect(isMaintainerApprovalEnforced({ MAINTAINER_APPROVAL_INTENTS_ENFORCED: "" })).toBe(false);
      expect(isMaintainerApprovalEnforced({})).toBe(false);
    });
  });
});
