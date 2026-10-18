import {
  APPROVAL_INTENT_SCHEMA,
  APPROVAL_INTENT_SIGNATURE_ALGORITHM,
  ApprovalIntentStatus,
  isTerminalIntentStatus,
  transitionIntentStatus,
} from "./approval-intent.types";

describe("ApprovalIntentStatus state machine (#220)", () => {
  it("walks the happy path proposed -> executing -> completed", () => {
    let status = ApprovalIntentStatus.PROPOSED;
    status = transitionIntentStatus(status, ApprovalIntentStatus.EXECUTING);
    status = transitionIntentStatus(status, ApprovalIntentStatus.COMPLETED);
    expect(status).toBe(ApprovalIntentStatus.COMPLETED);
  });

  it("walks the failure path proposed -> executing -> failed", () => {
    let status = transitionIntentStatus(
      ApprovalIntentStatus.PROPOSED,
      ApprovalIntentStatus.EXECUTING,
    );
    status = transitionIntentStatus(status, ApprovalIntentStatus.FAILED);
    expect(status).toBe(ApprovalIntentStatus.FAILED);
  });

  it("allows a proposal to expire or be cancelled without executing", () => {
    expect(
      transitionIntentStatus(
        ApprovalIntentStatus.PROPOSED,
        ApprovalIntentStatus.EXPIRED,
      ),
    ).toBe(ApprovalIntentStatus.EXPIRED);
    expect(
      transitionIntentStatus(
        ApprovalIntentStatus.PROPOSED,
        ApprovalIntentStatus.CANCELLED,
      ),
    ).toBe(ApprovalIntentStatus.CANCELLED);
  });

  it("treats self-transitions as no-ops so a retried save cannot fail", () => {
    expect(
      transitionIntentStatus(
        ApprovalIntentStatus.EXECUTING,
        ApprovalIntentStatus.EXECUTING,
      ),
    ).toBe(ApprovalIntentStatus.EXECUTING);
  });

  it("refuses to skip straight to a receipt-bearing terminal state", () => {
    expect(() =>
      transitionIntentStatus(
        ApprovalIntentStatus.PROPOSED,
        ApprovalIntentStatus.COMPLETED,
      ),
    ).toThrow("Invalid approval intent transition: proposed -> completed");
  });

  it("never lets an execution be claimed twice", () => {
    expect(() =>
      transitionIntentStatus(
        ApprovalIntentStatus.EXECUTING,
        ApprovalIntentStatus.PROPOSED,
      ),
    ).toThrow("executing -> proposed");
    expect(() =>
      transitionIntentStatus(
        ApprovalIntentStatus.COMPLETED,
        ApprovalIntentStatus.EXECUTING,
      ),
    ).toThrow("completed -> executing");
  });

  it("refuses to resurrect, expire, or cancel terminal states", () => {
    for (const terminal of [
      ApprovalIntentStatus.COMPLETED,
      ApprovalIntentStatus.FAILED,
      ApprovalIntentStatus.EXPIRED,
      ApprovalIntentStatus.CANCELLED,
    ]) {
      expect(() =>
        transitionIntentStatus(terminal, ApprovalIntentStatus.EXECUTING),
      ).toThrow(`Invalid approval intent transition: ${terminal} -> executing`);
      expect(() =>
        transitionIntentStatus(terminal, ApprovalIntentStatus.PROPOSED),
      ).toThrow();
    }
  });

  it("keeps an in-flight execution from being expired or cancelled", () => {
    expect(() =>
      transitionIntentStatus(
        ApprovalIntentStatus.EXECUTING,
        ApprovalIntentStatus.EXPIRED,
      ),
    ).toThrow("executing -> expired");
    expect(() =>
      transitionIntentStatus(
        ApprovalIntentStatus.EXECUTING,
        ApprovalIntentStatus.CANCELLED,
      ),
    ).toThrow("executing -> cancelled");
  });

  it("classifies terminal statuses exactly once", () => {
    expect(isTerminalIntentStatus(ApprovalIntentStatus.COMPLETED)).toBe(true);
    expect(isTerminalIntentStatus(ApprovalIntentStatus.FAILED)).toBe(true);
    expect(isTerminalIntentStatus(ApprovalIntentStatus.EXPIRED)).toBe(true);
    expect(isTerminalIntentStatus(ApprovalIntentStatus.CANCELLED)).toBe(true);
    expect(isTerminalIntentStatus(ApprovalIntentStatus.PROPOSED)).toBe(false);
    expect(isTerminalIntentStatus(ApprovalIntentStatus.EXECUTING)).toBe(false);
  });
});

describe("approval intent schema constants (#220)", () => {
  it("pins the schema id and algorithm so receipts stay verifiable", () => {
    expect(APPROVAL_INTENT_SCHEMA).toBe("trellis.audit.approval-intent.v1");
    expect(APPROVAL_INTENT_SIGNATURE_ALGORITHM).toBe("HMAC-SHA256");
  });
});
