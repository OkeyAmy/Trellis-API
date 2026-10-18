import { MigrationInterface, QueryRunner } from "typeorm";

/**
 * Stores the exact signed receipt document next to its hash and signature
 * (#220, second slice).
 *
 * The first migration kept only `receiptHash` / `receiptSignature`, which
 * proves a receipt was signed but cannot re-derive the document that was
 * signed — a reviewer could not re-run verification after the fact. Storing
 * the document (jsonb) closes that gap: verification re-canonicalizes the
 * stored document (sorted keys, no whitespace) before hashing, so the key
 * order jsonb does not preserve is irrelevant.
 *
 * Idempotent: `ADD COLUMN IF NOT EXISTS` makes re-running harmless, matching
 * the convention of the rest of the migration set.
 */
export class AddApprovalIntentReceiptDocument1792342800000
  implements MigrationInterface
{
  name = "AddApprovalIntentReceiptDocument1792342800000";

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "approval_intents"
        ADD COLUMN IF NOT EXISTS "receipt" jsonb
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      ALTER TABLE "approval_intents"
        DROP COLUMN IF EXISTS "receipt"
    `);
  }
}
