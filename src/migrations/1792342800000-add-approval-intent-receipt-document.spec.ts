import { AddApprovalIntentReceiptDocument1792342800000 } from "./1792342800000-add-approval-intent-receipt-document";

/*
 * Second schema slice of the maintainer approval flow (#220): the signed
 * receipt document is stored next to its hash so verification can be
 * re-run after the fact.
 */
describe("AddApprovalIntentReceiptDocument1792342800000", () => {
  const migration = new AddApprovalIntentReceiptDocument1792342800000();
  let queryRunner: { query: jest.Mock };

  beforeEach(() => {
    queryRunner = { query: jest.fn().mockResolvedValue(undefined) };
  });

  it("has a stable name so TypeORM orders it after the table migration", () => {
    expect(migration.name).toBe("AddApprovalIntentReceiptDocument1792342800000");
  });

  it("up() adds the receipt column idempotently", async () => {
    await migration.up(queryRunner as never);

    expect(queryRunner.query).toHaveBeenCalledTimes(1);
    const sql = queryRunner.query.mock.calls[0][0] as string;
    expect(sql).toContain('ALTER TABLE "approval_intents"');
    expect(sql).toContain('ADD COLUMN IF NOT EXISTS "receipt" jsonb');
  });

  it("down() drops the receipt column idempotently", async () => {
    await migration.down(queryRunner as never);

    const sql = queryRunner.query.mock.calls[0][0] as string;
    expect(sql).toContain('DROP COLUMN IF EXISTS "receipt"');
  });
});
