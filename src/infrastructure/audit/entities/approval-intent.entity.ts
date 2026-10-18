import { Column, Entity, Index } from "typeorm";
import { BaseEntity } from "../../../common/database/entities/base.entity";
import {
  ApprovalIntentStatus,
  SignedIntentReceipt,
} from "../approval-intents/approval-intent.types";

/**
 * One maintainer approval intent (#220).
 *
 * Rows are append-only in practice: only `status` and the terminal receipt
 * columns are updated, and only through the legal transitions defined in
 * `approval-intent.types.ts`. The `fingerprint` commits to (action, actor,
 * resource, reason, payload) over canonical JSON under a versioned schema,
 * and `intentSignature` signs that fingerprint at rest — so an intent cannot
 * be edited in place without breaking both the signature and the audit trail.
 *
 * Terminal rows always carry a signed receipt (`receiptHash` +
 * `receiptSignature`), enforced by a CHECK constraint in the migration as a
 * last line of defence beneath the service.
 */
@Entity("approval_intents")
@Index(["fingerprint", "status"])
@Index(["status", "expiresAt"])
@Index(["actorId", "createdAt"])
@Index(["action", "createdAt"])
export class ApprovalIntent extends BaseEntity {
  /** Catalogued sensitive action this intent authorizes, e.g. `user.role.assigned`. */
  @Column({ type: "varchar", length: 100 })
  action: string;

  /** The maintainer who declared the intent. */
  @Column({ type: "varchar", length: 64 })
  actorId: string;

  /** Role held at proposal time; re-checked at execution. */
  @Column({ type: "varchar", length: 64, nullable: true })
  actorRole: string | null;

  /** Maps to `SensitiveActionEvent.actorType`. */
  @Column({ type: "varchar", length: 16, default: "maintainer" })
  actorType: string;

  /** Second approver when the action requires dual control; must differ from `actorId`. */
  @Column({ type: "varchar", length: 64, nullable: true })
  approverId: string | null;

  @Column({ type: "varchar", length: 100 })
  resourceType: string;

  @Column({ type: "varchar", length: 255 })
  resourceId: string;

  /** Mandatory justification; also mandatory in the sensitive-action catalogue. */
  @Column({ type: "text" })
  reason: string;

  /** Exact input the action will be executed with (sanitized before persisting). */
  @Column({ type: "jsonb" })
  payload: Record<string, unknown>;

  @Column({ type: "varchar", length: 64 })
  payloadHash: string;

  /** sha256 of the canonical commitment document; replay/dedupe key. */
  @Column({ type: "varchar", length: 64 })
  fingerprint: string;

  @Column({ type: "varchar", length: 16, default: ApprovalIntentStatus.PROPOSED })
  status: ApprovalIntentStatus;

  /** After this instant the intent can only transition to `expired`. */
  @Column({ type: "timestamptz" })
  expiresAt: Date;

  @Column({ type: "timestamptz" })
  requestedAt: Date;

  /** Set when an execution claims the intent (`proposed -> executing`). */
  @Column({ type: "timestamptz", nullable: true })
  startedAt: Date | null;

  /** Set when the execution reaches `completed` or `failed`. */
  @Column({ type: "timestamptz", nullable: true })
  completedAt: Date | null;

  /** HMAC-SHA256 over `fingerprint`, signed when the intent is persisted. */
  @Column({ type: "varchar", length: 64 })
  intentSignature: string;

  /** sha256 of the canonical receipt document; set at terminal status only. */
  @Column({ type: "varchar", length: 64, nullable: true })
  receiptHash: string | null;

  /** HMAC-SHA256 over `receiptHash`. */
  @Column({ type: "varchar", length: 64, nullable: true })
  receiptSignature: string | null;

  /**
   * The exact signed receipt document. Verification re-canonicalizes this
   * document (sorted keys) before hashing, so a jsonb round-trip — which
   * does not preserve key order — cannot invalidate a receipt.
   */
  @Column({ type: "jsonb", nullable: true })
  receipt: SignedIntentReceipt | null;

  @Column({ type: "timestamptz", nullable: true })
  signedAt: Date | null;

  @Column({ type: "varchar", length: 32, default: "HMAC-SHA256" })
  signatureAlgorithm: string;

  /** Why the execution failed, when `status = failed`. */
  @Column({ type: "text", nullable: true })
  failureReason: string | null;

  /** Non-secret context (request id, ticket reference, operation name). */
  @Column({ type: "jsonb", nullable: true })
  metadata: Record<string, unknown> | null;

  @Column({ type: "varchar", length: 45, nullable: true })
  ipAddress: string | null;

  @Column({ type: "varchar", length: 512, nullable: true })
  userAgent: string | null;
}
