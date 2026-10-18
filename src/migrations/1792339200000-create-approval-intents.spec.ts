import { QueryRunner } from "typeorm";
import { CreateApprovalIntents1792339200000 } from "src/migrations/1792339200000-create-approval-intents";

describe("CreateApprovalIntents1792339200000", () => {
  let queryRunner: QueryRunner;
  let migration: CreateApprovalIntents1792339200000;

  beforeEach(() => {
    queryRunner = {
      query: jest.fn().mockResolvedValue(undefined),
    } as unknown as QueryRunner;
    migration = new CreateApprovalIntents1792339200000();
  });

  function statements(): string {
    return (queryRunner.query as jest.Mock).mock.calls
      .map(([sql]) => String(sql))
      .join("\n");
  }

  it("creates the approval_intents table idempotently", async () => {
    await migration.up(queryRunner);

    const sql = statements();
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS "approval_intents"');
    expect(sql).toContain('"fingerprint" varchar(64) NOT NULL');
    expect(sql).toContain('"payload" jsonb NOT NULL');
    expect(sql).toContain('"intentSignature" varchar(64) NOT NULL');
    expect(sql).toContain('"receiptSignature" varchar(64)');
    expect(sql).toContain('"expiresAt" timestamptz NOT NULL');
  });

  // Without this the uuid default would need the uuid-ossp extension, which
  // this migration does not create (same rule as the billing migration).
  it("defaults the primary key to gen_random_uuid", async () => {
    await migration.up(queryRunner);

    const sql = statements();
    expect(sql).toContain('CREATE EXTENSION IF NOT EXISTS "pgcrypto"');
    expect(sql).toContain("DEFAULT gen_random_uuid()");
    expect(sql).not.toContain("uuid_generate_v4()");
  });

  // A receipt-bearing status without a signed receipt would break the
  // "reviewable after completion or failure" guarantee — the database is the
  // last line of defence beneath the service.
  it("rejects terminal rows that lack a signed receipt", async () => {
    await migration.up(queryRunner);

    const sql = statements();
    expect(sql).toContain('"CK_approval_intents_receipt"');
    expect(sql).toMatch(/"status" NOT IN \('completed','failed'\)\s*\n?\s*OR/);
    expect(sql).toMatch(/"receiptHash" IS NOT NULL/);
    expect(sql).toMatch(/"receiptSignature" IS NOT NULL/);
  });

  it("constrains status values and requires a failure reason on failure", async () => {
    await migration.up(queryRunner);

    const sql = statements();
    expect(sql).toContain("'proposed','executing','completed','failed','expired','cancelled'");
    expect(sql).toContain('"CK_approval_intents_failure_reason"');
    expect(sql).toMatch(/"status" <> 'failed' OR "failureReason" IS NOT NULL/);
  });

  it("indexes the lookup paths used by the execution and review queries", async () => {
    await migration.up(queryRunner);

    const sql = statements();
    expect(sql).toContain('"IDX_approval_intents_fingerprint_status"');
    expect(sql).toContain('"IDX_approval_intents_status_expires"');
    expect(sql).toContain('"IDX_approval_intents_actor_created"');
    expect(sql).toContain('"IDX_approval_intents_action_created"');
  });

  it("drops the table on revert", async () => {
    await migration.down(queryRunner);

    expect(statements()).toContain('DROP TABLE IF EXISTS "approval_intents"');
  });
});
