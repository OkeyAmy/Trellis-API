import { createHash } from "crypto";
import { FindOperator } from "typeorm";
import { ApprovalIntentService } from "../approval-intent.service";
import { ApprovalIntent } from "../../entities/approval-intent.entity";
import { ExportSigningService } from "../../algorithms/export-signing.service";
import { SensitiveActionAuditService } from "../../sensitive-actions/sensitive-action-audit.service";
import { SensitiveAction } from "../../sensitive-actions/sensitive-action.enum";
import { ApprovalIntentStatus } from "../approval-intent.types";
import { ReceiptSigner } from "../approval-intent.receipt";

/*
 * Shared in-memory fixtures for approval-intent specs (#218 extraction so the
 * lifecycle suite and the concurrency suite observe the SAME fake repository
 * semantics).
 *
 * The fake implements exactly the repository surface the service calls, with
 * one deliberate property: `update(criteria, patch)` is a single synchronous
 * pass over the rows, mirroring a conditional SQL UPDATE — concurrent callers
 * therefore contend over one winner, which is what the atomic-claim tests
 * need to observe.
 */

export interface FakeRow extends Partial<ApprovalIntent> {
  id: string;
}

export function createFakeRepo() {
  const rows = new Map<string, FakeRow>();
  let sequence = 0;

  const matches = (row: FakeRow, where: Record<string, unknown>): boolean =>
    Object.entries(where).every(([key, condition]) => {
      if (condition instanceof FindOperator) {
        const actual = (row as unknown as Record<string, unknown>)[key];
        if (condition.type === "lessThan") {
          return (
            actual instanceof Date &&
            condition.value instanceof Date &&
            actual.getTime() < condition.value.getTime()
          );
        }
        return false;
      }
      return (row as unknown as Record<string, unknown>)[key] === condition;
    });

  return {
    rows,
    create: jest.fn((partial: Partial<ApprovalIntent>) => ({ ...partial })),
    save: jest.fn(async (entity: ApprovalIntent) => {
      if (!entity.id) {
        sequence += 1;
        entity.id = `intent-${sequence}`;
      }
      rows.set(entity.id, { ...(entity as FakeRow) });
      return entity;
    }),
    findOne: jest.fn(async ({ where }: { where: Record<string, unknown> }) => {
      for (const row of rows.values()) {
        if (matches(row, where)) return { ...row };
      }
      return null;
    }),
    find: jest.fn(
      async ({
        where,
        take,
      }: {
        where: Record<string, unknown>;
        take?: number;
      }) => {
        const found = [...rows.values()].filter((row) => matches(row, where));
        return take ? found.slice(0, take) : found;
      },
    ),
    update: jest.fn(
      async (
        criteria: Record<string, unknown>,
        patch: Partial<ApprovalIntent>,
      ) => {
        let affected = 0;
        for (const row of rows.values()) {
          if (matches(row, criteria)) {
            Object.assign(row, patch);
            affected += 1;
          }
        }
        return { affected };
      },
    ),
  };
}

const TEST_KEY = "approval-intent-test-key";

export function createSigner(): ReceiptSigner & { sign: jest.Mock } {
  const sign = jest.fn((payload: string) =>
    createHash("sha256").update(`${TEST_KEY}:${payload}`).digest("hex"),
  );
  return {
    sign,
    verify: (payload: string, signature: string) => sign(payload) === signature,
  };
}

export function createService(overrides: {
  repo?: ReturnType<typeof createFakeRepo>;
  signer?: ReceiptSigner & { sign: jest.Mock };
  audit?: { recordSensitiveAction: jest.Mock };
} = {}) {
  const repo = overrides.repo ?? createFakeRepo();
  const signer = overrides.signer ?? createSigner();
  const audit =
    overrides.audit ?? { recordSensitiveAction: jest.fn().mockResolvedValue({}) };

  const service = new ApprovalIntentService(
    repo as never,
    signer as unknown as ExportSigningService,
    audit as unknown as SensitiveActionAuditService,
  );
  return { service, repo, signer, audit };
}

export const actor = { id: "admin-1", role: "ADMIN" };

export function proposeInput(over: Record<string, unknown> = {}) {
  return {
    action: SensitiveAction.ROLE_ASSIGNED,
    actor,
    resourceType: "user",
    resourceId: "user-7",
    reason: "Promotion approved in ticket OPS-142",
    payload: { role: "MAINTAINER" },
    ...over,
  };
}

export async function proposedIntent(
  service: ApprovalIntentService,
  over: Record<string, unknown> = {},
): Promise<ApprovalIntent> {
  return service.propose(proposeInput(over) as never);
}

export { ApprovalIntentStatus };
