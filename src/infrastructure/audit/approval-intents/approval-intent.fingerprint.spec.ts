import {
  approvalIntentFingerprint,
  intentCommitmentDocument,
  intentPayloadHash,
} from "./approval-intent.fingerprint";
import { IntentCommitment } from "./approval-intent.types";

function commitment(
  overrides: Partial<IntentCommitment> = {},
): IntentCommitment {
  return {
    action: "user.role.assigned",
    actorId: "admin-1",
    resourceType: "user",
    resourceId: "user-9",
    reason: "Promote on-call operator for incident 412",
    payload: { role: "OPERATOR", expectedVersion: 7 },
    ...overrides,
  };
}

describe("approval intent fingerprint (#220)", () => {
  it("is deterministic across processes regardless of key order", () => {
    const a = approvalIntentFingerprint(commitment());
    const b = approvalIntentFingerprint(
      commitment({
        payload: { expectedVersion: 7, role: "OPERATOR" },
      }),
    );
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("commits to the schema so a future format cannot collide with v1", () => {
    const document = intentCommitmentDocument(commitment());
    expect(document).toContain('"schema":"trellis.audit.approval-intent.v1"');
    // Canonical form: sorted keys, no structural whitespace between tokens.
    expect(document.indexOf('"action"')).toBeLessThan(
      document.indexOf('"schema"'),
    );
    expect(document).toBe(
      '{"action":"user.role.assigned","actorId":"admin-1",' +
        '"payload":{"expectedVersion":7,"role":"OPERATOR"},' +
        '"reason":"Promote on-call operator for incident 412",' +
        '"resourceId":"user-9","resourceType":"user",' +
        '"schema":"trellis.audit.approval-intent.v1"}',
    );
  });

  it("changes when any part of the intended action changes", () => {
    const base = approvalIntentFingerprint(commitment());
    const variants: Array<Partial<IntentCommitment>> = [
      { action: "user.role.reset" },
      { actorId: "admin-2" },
      { resourceType: "agent" },
      { resourceId: "user-10" },
      { reason: "Different justification" },
      { payload: { role: "ADMIN", expectedVersion: 7 } },
      { payload: { role: "OPERATOR", expectedVersion: 8 } },
    ];
    for (const variant of variants) {
      expect(approvalIntentFingerprint(commitment(variant))).not.toBe(base);
    }
  });

  it("binds the actor so a stolen payload cannot be replayed by another maintainer", () => {
    const theirs = approvalIntentFingerprint(commitment({ actorId: "admin-1" }));
    const mine = approvalIntentFingerprint(commitment({ actorId: "admin-2" }));
    expect(theirs).not.toBe(mine);
  });

  it("rejects payloads canonical JSON cannot represent", () => {
    expect(() =>
      approvalIntentFingerprint(
        commitment({
          payload: { role: "OPERATOR", nested: { bad: undefined } },
        }),
      ),
    ).toThrow("undefined");
    expect(() =>
      approvalIntentFingerprint(
        commitment({ payload: { role: "OPERATOR", bad: () => 1 } }),
      ),
    ).toThrow();
    const circular: Record<string, unknown> = { role: "OPERATOR" };
    circular.self = circular;
    expect(() =>
      approvalIntentFingerprint(commitment({ payload: circular })),
    ).toThrow("circular");
  });

  it("hashes payloads independently for reviewer diffs", () => {
    expect(intentPayloadHash({ a: 1, b: 2 })).toBe(
      intentPayloadHash({ b: 2, a: 1 }),
    );
    expect(intentPayloadHash({ a: 1 })).not.toBe(intentPayloadHash({ a: 2 }));
    expect(intentPayloadHash({ a: 1 })).toMatch(/^[0-9a-f]{64}$/);
  });
});
