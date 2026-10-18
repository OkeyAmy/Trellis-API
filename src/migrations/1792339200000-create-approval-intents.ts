import { MigrationInterface, QueryRunner } from "typeorm";

export class CreateApprovalIntents1792339200000 implements MigrationInterface {
  name = "CreateApprovalIntents1792339200000";

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`);
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "approval_intents" (
        "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        "action" varchar(100) NOT NULL,
        "actorId" varchar(64) NOT NULL,
        "actorRole" varchar(64),
        "actorType" varchar(16) NOT NULL DEFAULT 'maintainer',
        "approverId" varchar(64),
        "resourceType" varchar(100) NOT NULL,
        "resourceId" varchar(255) NOT NULL,
        "reason" text NOT NULL,
        "payload" jsonb NOT NULL,
        "payloadHash" varchar(64) NOT NULL,
        "fingerprint" varchar(64) NOT NULL,
        "status" varchar(16) NOT NULL DEFAULT 'proposed',
        "expiresAt" timestamptz NOT NULL,
        "requestedAt" timestamptz NOT NULL DEFAULT now(),
        "startedAt" timestamptz,
        "completedAt" timestamptz,
        "intentSignature" varchar(64) NOT NULL,
        "receiptHash" varchar(64),
        "receiptSignature" varchar(64),
        "signedAt" timestamptz,
        "signatureAlgorithm" varchar(32) NOT NULL DEFAULT 'HMAC-SHA256',
        "failureReason" text,
        "metadata" jsonb,
        "ipAddress" varchar(45),
        "userAgent" varchar(512),
        "createdAt" timestamptz NOT NULL DEFAULT now(),
        "updatedAt" timestamptz NOT NULL DEFAULT now(),
        "deletedAt" timestamptz,
        CONSTRAINT "CK_approval_intents_status" CHECK (
          "status" IN ('proposed','executing','completed','failed','expired','cancelled')
        ),
        CONSTRAINT "CK_approval_intents_executing_started" CHECK (
          "status" <> 'executing' OR "startedAt" IS NOT NULL
        ),
        CONSTRAINT "CK_approval_intents_receipt" CHECK (
          "status" NOT IN ('completed','failed')
          OR (
            "receiptHash" IS NOT NULL
            AND "receiptSignature" IS NOT NULL
            AND "signedAt" IS NOT NULL
            AND "completedAt" IS NOT NULL
          )
        ),
        CONSTRAINT "CK_approval_intents_failure_reason" CHECK (
          "status" <> 'failed' OR "failureReason" IS NOT NULL
        )
      )
    `);
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_approval_intents_fingerprint_status"
      ON "approval_intents" ("fingerprint", "status")
    `);
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_approval_intents_status_expires"
      ON "approval_intents" ("status", "expiresAt")
    `);
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_approval_intents_actor_created"
      ON "approval_intents" ("actorId", "createdAt")
    `);
    await queryRunner.query(`
      CREATE INDEX IF NOT EXISTS "IDX_approval_intents_action_created"
      ON "approval_intents" ("action", "createdAt")
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "approval_intents"`);
  }
}
