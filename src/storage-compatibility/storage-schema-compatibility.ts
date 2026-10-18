import { Dirent, readdirSync } from "fs";
import { basename, join, relative, sep } from "path";
import { DataSource } from "typeorm";

export type StorageSchemaCompatibilityStatus =
  | "up-to-date"
  | "upgrade-ready"
  | "incompatible";

export interface MigrationVersion {
  timestamp: number;
  id: string;
}

export interface AppliedMigration {
  timestamp: number;
  name: string;
}

export interface StorageSchemaCompatibilityReport {
  status: StorageSchemaCompatibilityStatus;
  compatible: boolean;
  appliedMigrations: number;
  knownMigrations: number;
  currentVersion: string | null;
  nextVersion: string | null;
  pendingVersions: string[];
  reason: string;
  checkedAt: string;
}

export interface CompatibilityCheckOptions {
  knownMigrations?: MigrationVersion[];
  sourceRoot?: string;
  maxAttempts?: number;
  sleep?: (delayMs: number) => Promise<void>;
}

const TRANSIENT_DATABASE_CODES = new Set([
  "40001", // serialization_failure
  "40P01", // deadlock_detected
  "55P03", // lock_not_available
  "57P01", // admin_shutdown
  "08000",
  "08001",
  "08003",
  "08004",
  "08006",
  "08P01",
  "ECONNRESET",
  "ETIMEDOUT",
  "EPIPE",
]);

const MIGRATION_FILE_PATTERN = /^(\d{10,})-(.+)\.(?:ts|js)$/;

export class MigrationHistoryUnavailableError extends Error {
  constructor(
    public readonly attempts: number,
    public readonly errorCode?: string,
  ) {
    super("Unable to read TypeORM migration history");
    this.name = "MigrationHistoryUnavailableError";
  }
}

function errorCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object" || !("code" in error)) {
    return undefined;
  }

  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

export function isTransientDatabaseError(error: unknown): boolean {
  const code = errorCode(error);
  return code ? TRANSIENT_DATABASE_CODES.has(code) : false;
}

function migrationFileVersion(fileName: string): MigrationVersion | null {
  if (
    fileName.endsWith(".spec.ts") ||
    fileName.endsWith(".spec.js") ||
    fileName.endsWith(".d.ts")
  ) {
    return null;
  }

  const match = MIGRATION_FILE_PATTERN.exec(fileName);
  if (!match) return null;

  const timestamp = Number(match[1]);
  if (!Number.isSafeInteger(timestamp)) return null;

  return {
    timestamp,
    id: fileName.replace(/\.(?:ts|js)$/, ""),
  };
}

/**
 * Discover the same migration locations configured by src/config/typeorm.config.ts:
 * src/migrations/* and any nested **\/migration/* directory.
 *
 * Only timestamp-prefixed migration source/build files are considered. The
 * timestamp is TypeORM's durable migration identity and is also what is stored
 * in the migration history table.
 */
export function discoverKnownMigrationVersions(
  sourceRoot = join(__dirname, ".."),
): MigrationVersion[] {
  const versions = new Map<number, MigrationVersion>();

  const visit = (directory: string): void => {
    let entries: Dirent[];
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const absolutePath = join(directory, entry.name);

      if (entry.isDirectory()) {
        if (entry.name === "node_modules" || entry.name === "__tests__") {
          continue;
        }
        visit(absolutePath);
        continue;
      }

      const parentName = basename(directory);
      const relativePath = relative(sourceRoot, absolutePath).split(sep).join("/");
      const isRootMigration =
        parentName === "migrations" && relativePath.startsWith("migrations/");
      const isNestedMigration = parentName === "migration";

      if (!isRootMigration && !isNestedMigration) continue;

      const version = migrationFileVersion(entry.name);
      if (version) versions.set(version.timestamp, version);
    }
  };

  visit(sourceRoot);
  return [...versions.values()].sort((a, b) => a.timestamp - b.timestamp);
}

function incompatibleReport(
  known: MigrationVersion[],
  applied: AppliedMigration[],
  reason: string,
): StorageSchemaCompatibilityReport {
  const currentApplied = applied.length > 0 ? applied[applied.length - 1] : undefined;
  const currentVersion =
    known.find(
      (migration) => migration.timestamp === currentApplied?.timestamp,
    )?.id ??
    currentApplied?.name ??
    null;

  return {
    status: "incompatible",
    compatible: false,
    appliedMigrations: applied.length,
    knownMigrations: known.length,
    currentVersion,
    nextVersion: null,
    pendingVersions: [],
    reason,
    checkedAt: new Date().toISOString(),
  };
}

/**
 * Compare applied TypeORM history with the application-known migration chain.
 * A valid database must be an exact prefix of the known chain. Unknown,
 * duplicated, skipped or reordered migration timestamps fail closed.
 */
export function evaluateMigrationCompatibility(
  knownMigrations: MigrationVersion[],
  appliedMigrations: AppliedMigration[],
): StorageSchemaCompatibilityReport {
  const known = [...knownMigrations].sort((a, b) => a.timestamp - b.timestamp);
  const applied = [...appliedMigrations];

  if (known.length === 0) {
    return incompatibleReport(
      known,
      applied,
      "No application migrations were discovered; compatibility cannot be proven.",
    );
  }

  const knownTimestamps = new Set<number>();
  for (const migration of known) {
    if (knownTimestamps.has(migration.timestamp)) {
      return incompatibleReport(
        known,
        applied,
        `Duplicate application migration timestamp ${migration.timestamp}.`,
      );
    }
    knownTimestamps.add(migration.timestamp);
  }

  if (applied.length > known.length) {
    return incompatibleReport(
      known,
      applied,
      "Database migration history is ahead of this application build.",
    );
  }

  const seenApplied = new Set<number>();
  for (let index = 0; index < applied.length; index += 1) {
    const actual = applied[index];
    const expected = known[index];

    if (!Number.isSafeInteger(actual.timestamp)) {
      return incompatibleReport(
        known,
        applied,
        `Migration history contains an invalid timestamp at position ${index + 1}.`,
      );
    }

    if (seenApplied.has(actual.timestamp)) {
      return incompatibleReport(
        known,
        applied,
        `Migration history contains duplicate timestamp ${actual.timestamp}.`,
      );
    }
    seenApplied.add(actual.timestamp);

    if (!expected || actual.timestamp !== expected.timestamp) {
      return incompatibleReport(
        known,
        applied,
        `Migration history diverges at position ${index + 1}; expected ${expected?.id ?? "no migration"}.`,
      );
    }
  }

  const current = applied.length > 0 ? known[applied.length - 1] : null;
  const pending = known.slice(applied.length);

  if (pending.length === 0) {
    return {
      status: "up-to-date",
      compatible: true,
      appliedMigrations: applied.length,
      knownMigrations: known.length,
      currentVersion: current?.id ?? null,
      nextVersion: null,
      pendingVersions: [],
      reason: "Database migration history exactly matches this application build.",
      checkedAt: new Date().toISOString(),
    };
  }

  return {
    status: "upgrade-ready",
    compatible: true,
    appliedMigrations: applied.length,
    knownMigrations: known.length,
    currentVersion: current?.id ?? null,
    nextVersion: pending[0].id,
    pendingVersions: pending.map((migration) => migration.id),
    reason:
      "Database migration history is a valid prefix of this application build and can advance through the pending migrations in order.",
    checkedAt: new Date().toISOString(),
  };
}

function quoteQualifiedIdentifier(identifier: string): string {
  const parts = identifier.split(".");
  if (
    parts.length === 0 ||
    parts.some((part) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(part))
  ) {
    throw new Error("Invalid TypeORM migrations table name");
  }

  return parts.map((part) => `"${part}"`).join(".");
}

async function defaultSleep(delayMs: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, delayMs));
}

export async function readAppliedMigrations(
  dataSource: DataSource,
  maxAttempts = 3,
  sleep: (delayMs: number) => Promise<void> = defaultSleep,
): Promise<AppliedMigration[]> {
  const tableName = dataSource.options.migrationsTableName ?? "migrations";
  const quotedTable = quoteQualifiedIdentifier(tableName);
  let attempts = 0;

  while (attempts < maxAttempts) {
    attempts += 1;
    try {
      const rows = (await dataSource.query(
        `SELECT "timestamp", "name" FROM ${quotedTable} ORDER BY "id" ASC`,
      )) as Array<{ timestamp: string | number; name: string }>;

      return rows.map((row) => ({
        timestamp: Number(row.timestamp),
        name: String(row.name),
      }));
    } catch (error) {
      const transient = isTransientDatabaseError(error);
      if (!transient || attempts >= maxAttempts) {
        throw new MigrationHistoryUnavailableError(attempts, errorCode(error));
      }

      // Small bounded backoff keeps the operator endpoint responsive while
      // tolerating transient lock/connection failures.
      await sleep(25 * attempts);
    }
  }

  throw new MigrationHistoryUnavailableError(attempts);
}

export async function checkStorageSchemaCompatibility(
  dataSource: DataSource,
  options: CompatibilityCheckOptions = {},
): Promise<StorageSchemaCompatibilityReport> {
  const knownMigrations =
    options.knownMigrations ??
    discoverKnownMigrationVersions(options.sourceRoot ?? join(__dirname, ".."));
  const appliedMigrations = await readAppliedMigrations(
    dataSource,
    options.maxAttempts ?? 3,
    options.sleep,
  );

  return evaluateMigrationCompatibility(knownMigrations, appliedMigrations);
}
