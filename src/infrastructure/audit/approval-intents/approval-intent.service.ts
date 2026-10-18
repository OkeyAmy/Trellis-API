import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  Optional,
  ServiceUnavailableException,
} from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { FindOptionsWhere, LessThan, Repository } from "typeorm";
import { SensitiveActionAuditService } from "../sensitive-actions/sensitive-action-audit.service";
import {
  RecordSensitiveActionInput,
} from "../sensitive-actions/sensitive-action-audit.service";
import {
  isSensitiveAction,
  SensitiveAction,
} from "../sensitive-actions/sensitive-action.enum";
import {
  AuditActorType,
  SensitiveActionStatus,
} from "../entities/sensitive-action-event.entity";
import { ApprovalIntent } from "../entities/approval-intent.entity";
import { ExportSigningService } from "../algorithms/export-signing.service";
import {
  ApprovalIntentRequest,
  ApprovalIntentStatus,
  ReceiptIntegrity,
  SignedIntentReceipt,
  transitionIntentStatus,
} from "./approval-intent.types";
import {
  approvalIntentFingerprint,
  intentPayloadHash,
} from "./approval-intent.fingerprint";
import {
  receiptDocument,
  signReceipt,
  verifyReceipt,
  ReceiptVerification,
} from "./approval-intent.receipt";

/** Optional provider token for {@link ApprovalIntentOptions}. */
export const APPROVAL_INTENT_OPTIONS = "APPROVAL_INTENT_OPTIONS";

export interface ApprovalIntentOptions {
  /** Lifetime given to an intent when the caller does not pick one. */
  defaultTtlSeconds?: number;
  /** Upper bound for a caller-chosen lifetime. */
  maxTtlSeconds?: number;
}

/** Roles that may execute an intent that does not designate an approver. */
export const APPROVAL_INTENT_EXECUTOR_ROLES = ["ADMIN", "MAINTAINER"] as const;

/** Who executes an intent; re-checked against the row at claim time. */
export interface IntentExecutor {
  id: string;
  role?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
}

/** Filters accepted by {@link ApprovalIntentService.list}. */
export interface IntentListFilter {
  status?: ApprovalIntentStatus;
  action?: string;
  actorId?: string;
  resourceId?: string;
  limit?: number;
}

/**
 * Input accepted by {@link ApprovalIntentService.propose}: the commitment's
 * `actorId` is derived from `actor.id` rather than passed twice, so the two
 * can never diverge.
 */
export type ProposeIntentInput = Omit<ApprovalIntentRequest, "actorId">;

export interface StoredReceiptVerification extends ReceiptVerification {
  intentId: string;
  status: ApprovalIntentStatus;
}

/** Environment flag that turns on the approval requirement (#220). */
export function isMaintainerApprovalEnforced(
  env: Record<string, string | undefined> = process.env,
): boolean {
  const raw = env.MAINTAINER_APPROVAL_INTENTS_ENFORCED?.trim().toLowerCase();
  return raw === "true" || raw === "1" || raw === "yes";
}

/**
 * Maintainer approval intents (#220).
 *
 * A high-impact action is split into a signed *intent* and a single-use
 * *execution* that ends in a signed receipt:
 *
 *   propose  -> proposed    (fingerprint + HMAC at rest, evidence event)
 *   execute  -> executing   (atomic claim; exactly one execution may win)
 *            -> completed | failed  (signed receipt stored on the row)
 *   cancel   -> cancelled   (withdrawn before execution)
 *   expiry   -> expired     (aged out; can never execute)
 *
 * Failure posture:
 *   - proposal evidence that cannot be written cancels the intent (fail
 *     closed: nothing stays executable that cannot be evidenced);
 *   - an execution that throws still receives a signed *failure* receipt
 *     before the original error is rethrown;
 *   - the signed receipt is the authoritative execution record; the
 *     surrounding audit event is a best-effort index into it.
 */
@Injectable()
export class ApprovalIntentService {
  private readonly logger = new Logger(ApprovalIntentService.name);
  private readonly defaultTtlSeconds: number;
  private readonly maxTtlSeconds: number;

  constructor(
    @InjectRepository(ApprovalIntent)
    private readonly repo: Repository<ApprovalIntent>,
    private readonly signing: ExportSigningService,
    private readonly audit: SensitiveActionAuditService,
    @Optional()
    @Inject(APPROVAL_INTENT_OPTIONS)
    options: ApprovalIntentOptions | null = null,
  ) {
    this.defaultTtlSeconds = Math.max(60, options?.defaultTtlSeconds ?? 900);
    this.maxTtlSeconds = Math.max(
      this.defaultTtlSeconds,
      options?.maxTtlSeconds ?? 604_800,
    );
  }

  /**
   * Persists and signs a new intent. An identical commitment (same
   * fingerprint) that is still proposed is rejected as a conflict instead of
   * silently creating a second copy a reviewer would have to disentangle.
   */
  async propose(request: ProposeIntentInput): Promise<ApprovalIntent> {
    if (!request.actor?.id) {
      throw new BadRequestException("An intent requires an actor id");
    }
    if (!isSensitiveAction(request.action)) {
      throw new BadRequestException(
        `Unknown sensitive action: ${String(request.action)}`,
      );
    }
    const reason = request.reason?.trim();
    if (!reason) {
      throw new BadRequestException(
        `A reason is required to propose ${request.action}`,
      );
    }
    if (request.approverId && request.approverId === request.actor.id) {
      throw new BadRequestException(
        "An approver must differ from the actor proposing the intent",
      );
    }

    const commitment = {
      action: request.action,
      actorId: request.actor.id,
      resourceType: request.resourceType,
      resourceId: String(request.resourceId),
      reason,
      payload: request.payload ?? {},
    };
    const fingerprint = approvalIntentFingerprint(commitment);

    const existing = await this.repo.findOne({
      where: { fingerprint, status: ApprovalIntentStatus.PROPOSED },
    });
    if (existing) {
      throw new ConflictException(
        `An identical intent is already proposed as ${existing.id}; ` +
          "execute or cancel it before proposing another",
      );
    }

    const now = new Date();
    const ttlSeconds = this.resolveTtl(request.ttlSeconds);
    const intent = this.repo.create({
      ...commitment,
      actorRole: request.actor.role ?? null,
      actorType: request.actor.type ?? AuditActorType.MAINTAINER,
      approverId: request.approverId ?? null,
      payloadHash: intentPayloadHash(commitment.payload),
      fingerprint,
      status: ApprovalIntentStatus.PROPOSED,
      requestedAt: now,
      expiresAt: new Date(now.getTime() + ttlSeconds * 1000),
      intentSignature: this.signing.sign(fingerprint),
      metadata: request.metadata ?? null,
      ipAddress: request.actor.ipAddress ?? null,
      userAgent: request.actor.userAgent ?? null,
    });
    const saved = await this.repo.save(intent);

    try {
      await this.recordEvidence(saved, SensitiveAction.MAINTAINER_ACTION_PROPOSED, {
        actor: { id: saved.actorId, role: saved.actorRole },
        status: SensitiveActionStatus.SUCCEEDED,
        reason,
        after: this.evidenceState(saved),
        ipAddress: request.actor.ipAddress,
        userAgent: request.actor.userAgent,
      });
    } catch (error) {
      // Fail closed: an intent whose proposal cannot be evidenced must not
      // remain executable. Cancelling is the only safe transition left.
      this.logger.error(
        `proposal evidence for intent ${saved.id} failed; cancelling: ` +
          `${(error as Error)?.message ?? error}`,
      );
      try {
        saved.status = transitionIntentStatus(
          saved.status,
          ApprovalIntentStatus.CANCELLED,
        );
        await this.repo.save(saved);
      } catch (cancelError) {
        this.logger.error(
          `CRITICAL: intent ${saved.id} could not be cancelled after its ` +
            `evidence failed: ${(cancelError as Error)?.message ?? cancelError}`,
        );
      }
      throw new ServiceUnavailableException(
        "The approval intent was not proposed because its evidence record " +
          "could not be written",
      );
    }

    return saved;
  }

  async get(intentId: string): Promise<ApprovalIntent> {
    const intent = await this.repo.findOne({ where: { id: intentId } });
    if (!intent) {
      throw new NotFoundException(`Approval intent ${intentId} was not found`);
    }
    return intent;
  }

  async list(filter: IntentListFilter = {}): Promise<ApprovalIntent[]> {
    const where: FindOptionsWhere<ApprovalIntent> = {};
    if (filter.status) where.status = filter.status;
    if (filter.action) where.action = filter.action;
    if (filter.actorId) where.actorId = filter.actorId;
    if (filter.resourceId) where.resourceId = filter.resourceId;

    const take = Math.min(Math.max(filter.limit ?? 20, 1), 100);
    return this.repo.find({ where, order: { createdAt: "DESC" }, take });
  }

  /**
   * Withdraws a proposed intent. The row keeps the *proposal's* reason — it
   * is part of the signed commitment — so the cancellation reason travels in
   * the evidence event, recorded under the canceller, not the proposer.
   */
  async cancel(
    intentId: string,
    actor: IntentExecutor,
    reason: string,
  ): Promise<ApprovalIntent> {
    const intent = await this.get(intentId);
    const trimmed = reason?.trim();
    if (!trimmed) {
      throw new BadRequestException("A cancellation reason is required");
    }
    if (intent.status !== ApprovalIntentStatus.PROPOSED) {
      throw new ConflictException(
        `Only proposed intents can be cancelled; ${intentId} is ` +
          `${intent.status}`,
      );
    }

    intent.status = transitionIntentStatus(
      intent.status,
      ApprovalIntentStatus.CANCELLED,
    );
    intent.completedAt = new Date();
    // Atomic claim: only a row still `proposed` may be withdrawn, so a
    // cancellation can never clobber an execution that started between our
    // read and this write (and two racing cancellations cannot both win).
    const claimed = await this.repo.update(
      { id: intent.id, status: ApprovalIntentStatus.PROPOSED },
      { status: intent.status, completedAt: intent.completedAt },
    );
    if (!claimed.affected) {
      const current = await this.get(intentId);
      throw new ConflictException(
        `Only proposed intents can be cancelled; ${intentId} is ` +
          `${current.status}`,
      );
    }
    const saved = intent;

    // Best-effort: the direction of travel is already safe (the action can
    // no longer run) and the row itself records who and when; a failed
    // evidence append must not resurrect a cancelled intent.
    await this.recordEvidence(saved, SensitiveAction.MAINTAINER_ACTION_CANCELLED, {
      actor: { id: actor?.id ?? saved.actorId, role: actor?.role ?? null },
      status: SensitiveActionStatus.SUCCEEDED,
      reason: trimmed,
      after: this.evidenceState(saved),
      ipAddress: actor?.ipAddress,
      userAgent: actor?.userAgent,
    }).catch((error) =>
      this.logger.error(
        `cancellation evidence for intent ${intentId} failed: ` +
          `${(error as Error)?.message ?? error}`,
      ),
    );

    return saved;
  }

  /** Ages out every proposed intent past its expiry. Returns the count. */
  async expireDueIntents(now: Date = new Date()): Promise<number> {
    const result = await this.repo.update(
      { status: ApprovalIntentStatus.PROPOSED, expiresAt: LessThan(now) },
      { status: ApprovalIntentStatus.EXPIRED },
    );
    return result.affected ?? 0;
  }

  /**
   * Administrative early expiry: forces one proposed intent to `expired`
   * before its TTL so it can never execute. Intents that already started
   * or ended are left alone (409), because rewriting them would either
   * erase an execution record or resurrect a terminal row.
   */
  async expireIntent(intentId: string): Promise<ApprovalIntent> {
    const intent = await this.get(intentId);
    if (intent.status !== ApprovalIntentStatus.PROPOSED) {
      throw new ConflictException(
        `Only proposed intents can be expired; ${intentId} is ` +
          `${intent.status}`,
      );
    }

    intent.status = transitionIntentStatus(
      intent.status,
      ApprovalIntentStatus.EXPIRED,
    );
    intent.completedAt = new Date();
    // Same atomic claim as cancellation: never rewrite a row that an
    // execution (or another expiry) has already moved on from.
    const claimed = await this.repo.update(
      { id: intent.id, status: ApprovalIntentStatus.PROPOSED },
      { status: intent.status, completedAt: intent.completedAt },
    );
    if (!claimed.affected) {
      const current = await this.get(intentId);
      throw new ConflictException(
        `Only proposed intents can be expired; ${intentId} is ` +
          `${current.status}`,
      );
    }
    return intent;
  }

  /**
   * Consumes an intent exactly once and returns the operation's result.
   *
   * Ordering is deliberate: expiry is settled before the claim, the claim
   * itself is an atomic conditional update (two concurrent executions
   * cannot both win), and the executor is re-checked against the row —
   * the fingerprint binds *what*, this check binds *who*.
   */
  async execute<TResult>(
    intentId: string,
    executor: IntentExecutor,
    operation: () => Promise<TResult>,
  ): Promise<{ intent: ApprovalIntent; result: TResult }> {
    const intent = await this.get(intentId);

    if (intent.status !== ApprovalIntentStatus.PROPOSED) {
      throw new ConflictException(
        `Intent ${intentId} is ${intent.status} and can no longer execute`,
      );
    }
    if (intent.expiresAt.getTime() <= Date.now()) {
      await this.markExpired(intent);
      throw new ConflictException(
        `Intent ${intentId} expired at ${intent.expiresAt.toISOString()}`,
      );
    }
    this.assertExecutorAllowed(intent, executor);

    const startedAt = new Date();
    const claimed = await this.repo.update(
      { id: intent.id, status: ApprovalIntentStatus.PROPOSED },
      { status: ApprovalIntentStatus.EXECUTING, startedAt },
    );
    if (!claimed.affected) {
      // Whoever won the claim either claimed it (executing) or already
      // finished/cancelled it; report the observed state honestly.
      const current = await this.get(intentId);
      const terminal =
        current.status === ApprovalIntentStatus.COMPLETED ||
        current.status === ApprovalIntentStatus.FAILED ||
        current.status === ApprovalIntentStatus.CANCELLED ||
        current.status === ApprovalIntentStatus.EXPIRED;
      if (terminal) {
        throw new ConflictException(
          `Intent ${intentId} is ${current.status} and can no longer execute`,
        );
      }
      throw new ConflictException(
        `Intent ${intentId} was claimed by another execution`,
      );
    }
    intent.status = ApprovalIntentStatus.EXECUTING;
    // Keep the in-memory row consistent with the claim: `save()` below
    // would otherwise write the stale (null) startedAt back over it.
    intent.startedAt = startedAt;

    let result: TResult;
    try {
      result = await operation();
    } catch (error) {
      await this.finish(
        intent,
        executor,
        ApprovalIntentStatus.FAILED,
        error instanceof Error ? error.message : String(error),
      );
      throw error;
    }

    const finished = await this.finish(
      intent,
      executor,
      ApprovalIntentStatus.COMPLETED,
      null,
    );
    return { intent: finished, result };
  }

  /**
   * Re-runs receipt verification for a stored intent. A row without a
   * receipt (never executed, or predating the receipt column) reports
   * `valid: false` with the reason instead of throwing.
   */
  async verify(intentId: string): Promise<StoredReceiptVerification> {
    const intent = await this.get(intentId);
    if (!intent.receipt) {
      return {
        intentId,
        status: intent.status,
        valid: false,
        recomputedHash: "",
        errors: [
          `Intent ${intentId} has no signed receipt (status: ${intent.status})`,
        ],
      };
    }

    const integrity: ReceiptIntegrity = {
      receiptHash: intent.receiptHash ?? "",
      signature: intent.receiptSignature ?? "",
      signingAlgorithm: intent.signatureAlgorithm,
    };
    return {
      intentId,
      status: intent.status,
      ...verifyReceipt(intent.receipt, integrity, this.signing),
    };
  }

  /** Rebuilds the receipt document a terminal row commits to. */
  receiptFor(intent: ApprovalIntent): SignedIntentReceipt | null {
    return intent.receipt ?? null;
  }

  private resolveTtl(ttlSeconds?: number | null): number {
    if (ttlSeconds === undefined || ttlSeconds === null) {
      return this.defaultTtlSeconds;
    }
    if (!Number.isFinite(ttlSeconds) || ttlSeconds < 60) {
      throw new BadRequestException("ttlSeconds must be at least 60");
    }
    return Math.min(Math.floor(ttlSeconds), this.maxTtlSeconds);
  }

  private assertExecutorAllowed(
    intent: ApprovalIntent,
    executor: IntentExecutor,
  ): void {
    if (!executor?.id) {
      throw new ForbiddenException("An executor id is required");
    }
    if (intent.approverId) {
      if (executor.id !== intent.approverId) {
        throw new ForbiddenException(
          `Intent ${intent.id} designates ${intent.approverId} as its ` +
            "only executor",
        );
      }
      return;
    }
    const role = executor.role?.toUpperCase() ?? null;
    if (
      !role ||
      !(APPROVAL_INTENT_EXECUTOR_ROLES as readonly string[]).includes(role)
    ) {
      throw new ForbiddenException(
        "Insufficient role to execute a maintainer approval intent",
      );
    }
  }

  private async markExpired(intent: ApprovalIntent): Promise<void> {
    const updated = await this.repo.update(
      { id: intent.id, status: ApprovalIntentStatus.PROPOSED },
      { status: ApprovalIntentStatus.EXPIRED },
    );
    if (updated.affected) {
      intent.status = ApprovalIntentStatus.EXPIRED;
    }
  }

  /**
   * Signs and stores the terminal receipt, then appends the execution
   * evidence event best-effort. The receipt itself already lives in the
   * row the moment `save` returns, so an audit-chain outage cannot undo
   * or unprove the execution — it only costs the index into it.
   */
  private async finish(
    intent: ApprovalIntent,
    executor: IntentExecutor,
    outcome: ApprovalIntentStatus.COMPLETED | ApprovalIntentStatus.FAILED,
    failureReason: string | null,
  ): Promise<ApprovalIntent> {
    const completedAt = new Date();
    const receipt = receiptDocument({
      intentId: intent.id,
      fingerprint: intent.fingerprint,
      action: intent.action,
      actorId: intent.actorId,
      actorRole: intent.actorRole,
      approverId: intent.approverId,
      resourceType: intent.resourceType,
      resourceId: intent.resourceId,
      reason: intent.reason,
      payloadHash: intent.payloadHash,
      status: outcome,
      failureReason,
      requestedAt: intent.requestedAt.toISOString(),
      completedAt: completedAt.toISOString(),
      signedAt: completedAt.toISOString(),
    });
    const integrity = signReceipt(receipt, this.signing);

    intent.status = outcome;
    intent.completedAt = completedAt;
    intent.signedAt = completedAt;
    intent.receiptHash = integrity.receiptHash;
    intent.receiptSignature = integrity.signature;
    intent.signatureAlgorithm = integrity.signingAlgorithm;
    intent.receipt = receipt;
    intent.failureReason = failureReason;
    const saved = await this.repo.save(intent);

    await this.recordEvidence(saved, SensitiveAction.MAINTAINER_ACTION_EXECUTED, {
      actor: { id: executor?.id ?? saved.actorId, role: executor?.role ?? null },
      status:
        outcome === ApprovalIntentStatus.COMPLETED
          ? SensitiveActionStatus.SUCCEEDED
          : SensitiveActionStatus.FAILED,
      reason: saved.reason,
      after: this.evidenceState(saved),
      metadata: {
        receiptHash: integrity.receiptHash,
        ...(failureReason ? { failureReason } : {}),
      },
      ipAddress: executor?.ipAddress,
      userAgent: executor?.userAgent,
    }).catch((error) =>
      this.logger.error(
        `execution evidence for intent ${saved.id} failed: ` +
          `${(error as Error)?.message ?? error}`,
      ),
    );

    return saved;
  }

  private recordEvidence(
    intent: ApprovalIntent,
    action: SensitiveAction,
    fields: {
      actor?: { id: string; role?: string | null };
      status: SensitiveActionStatus;
      reason: string;
      before?: Record<string, unknown> | null;
      after?: Record<string, unknown> | null;
      metadata?: Record<string, unknown>;
      ipAddress?: string | null;
      userAgent?: string | null;
    },
  ): Promise<unknown> {
    const input: RecordSensitiveActionInput = {
      action,
      actorId: fields.actor?.id ?? intent.actorId,
      actorType: AuditActorType.MAINTAINER,
      actorRole: fields.actor?.role ?? intent.actorRole ?? undefined,
      resourceType: intent.resourceType,
      resourceId: intent.resourceId,
      reason: fields.reason,
      beforeState: fields.before ?? undefined,
      afterState: fields.after ?? undefined,
      metadata: {
        intentId: intent.id,
        fingerprint: intent.fingerprint,
        ...fields.metadata,
      },
      status: fields.status,
      ipAddress: fields.ipAddress ?? intent.ipAddress ?? undefined,
      userAgent: fields.userAgent ?? intent.userAgent ?? undefined,
    };
    return this.audit.recordSensitiveAction(input);
  }

  /** Compact, non-secret state recorded next to every lifecycle event. */
  private evidenceState(intent: ApprovalIntent): Record<string, unknown> {
    return {
      intentId: intent.id,
      status: intent.status,
      action: intent.action,
      fingerprint: intent.fingerprint,
      resourceId: intent.resourceId,
      expiresAt: intent.expiresAt.toISOString(),
      ...(intent.receiptHash ? { receiptHash: intent.receiptHash } : {}),
      ...(intent.failureReason ? { failureReason: intent.failureReason } : {}),
    };
  }
}
