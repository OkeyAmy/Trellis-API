import { ExecutionContext, HttpException, HttpStatus } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { QuotaGuard } from "./quota.guard";

// The guard builds its own client from REDIS_URL; tests replace the whole
// driver so the monthly counter is deterministic and no server is required.
const mockQuotaStore = new Map<string, number>();

jest.mock("redis", () => ({
  createClient: jest.fn(() => ({
    isOpen: true,
    on: jest.fn(),
    connect: jest.fn().mockResolvedValue(undefined),
    incr: jest.fn(async (key: string) => {
      const next = (mockQuotaStore.get(key) ?? 0) + 1;
      mockQuotaStore.set(key, next);
      return next;
    }),
    expire: jest.fn().mockResolvedValue(true),
  })),
}));

function createContext(options?: {
  user?: {
    id?: string;
    sub?: string;
    address?: string;
    role?: string;
    tier?: string;
    type?: string;
  };
  ip?: string;
  originalUrl?: string;
  headers?: Record<string, string>;
}): {
  context: ExecutionContext;
  response: { header: jest.Mock; setHeader: jest.Mock };
} {
  const request = {
    ip: options?.ip ?? "127.0.0.1",
    headers: options?.headers ?? {},
    originalUrl: options?.originalUrl ?? "/api/test",
    route: { path: "/api/test" },
    authType: options?.user?.type,
    user: options?.user,
  };

  const response = {
    header: jest.fn(),
    setHeader: jest.fn(),
  };

  const context = {
    getHandler: jest.fn(),
    getClass: jest.fn(),
    switchToHttp: () => ({
      getRequest: () => request,
      getResponse: () => response,
    }),
  } as unknown as ExecutionContext;

  return { context, response };
}

describe("QuotaGuard", () => {
  let guard: QuotaGuard;
  let reflector: Reflector;

  beforeEach(() => {
    reflector = new Reflector();
    guard = new QuotaGuard(reflector);
  });

  it("allows requests and emits rate-limit headers for the default tier", async () => {
    jest.spyOn(reflector, "getAllAndOverride").mockReturnValue(undefined);
    const { context, response } = createContext();

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(response.header).toHaveBeenCalledWith("X-RateLimit-Limit", 100);
    expect(response.header).toHaveBeenCalledWith("X-RateLimit-Remaining", 99);
    expect(response.header).toHaveBeenCalledWith("X-RateLimit-Tier", "free");
  });

  it("uses the authenticated user tier when one is available", async () => {
    jest.spyOn(reflector, "getAllAndOverride").mockReturnValue(undefined);
    const { context, response } = createContext({
      user: { id: "user-1", role: "admin" },
    });

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(response.header).toHaveBeenCalledWith(
      "X-RateLimit-Tier",
      "enterprise",
    );
  });

  it("rejects requests after the configured limit is reached", async () => {
    jest.spyOn(reflector, "getAllAndOverride").mockReturnValue({
      level: "auth",
      limit: 1,
      windowMs: 60_000,
    });

    const { context } = createContext({
      user: { id: "user-2", role: "user" },
    });

    await expect(guard.canActivate(context)).resolves.toBe(true);

    try {
      await guard.canActivate(context);
      throw new Error("Expected rate limit rejection");
    } catch (error) {
      expect(error).toBeInstanceOf(HttpException);
      expect((error as HttpException).getStatus()).toBe(
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  });

  describe("monthly API quota (redis-backed)", () => {
    const previousRedisUrl = process.env.REDIS_URL;

    function currentMonthKey(): string {
      const now = new Date();
      return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
    }

    beforeEach(() => {
      // Must be set before the guard is constructed: the client promise is
      // resolved once and cached per instance.
      process.env.REDIS_URL = "redis://localhost:6379";
      mockQuotaStore.clear();
      guard = new QuotaGuard(reflector);
    });

    afterEach(() => {
      if (previousRedisUrl === undefined) {
        delete process.env.REDIS_URL;
      } else {
        process.env.REDIS_URL = previousRedisUrl;
      }
    });

    it("increments the per-key monthly counter once per request", async () => {
      jest.spyOn(reflector, "getAllAndOverride").mockReturnValue(undefined);
      const { context } = createContext({
        user: { id: "user-7", tier: "free" },
        headers: { "x-api-key": "key-counter" },
      });

      await expect(guard.canActivate(context)).resolves.toBe(true);
      await expect(guard.canActivate(context)).resolves.toBe(true);

      expect(
        mockQuotaStore.get(`quota:key-counter:${currentMonthKey()}`),
      ).toBe(2);
    });

    it("emits the paid-tier monthly limit, not the free-tier fallback", async () => {
      jest.spyOn(reflector, "getAllAndOverride").mockReturnValue(undefined);
      const { context, response } = createContext({
        user: { id: "user-8", tier: "paid" },
        headers: { "x-api-key": "key-paid" },
      });

      await expect(guard.canActivate(context)).resolves.toBe(true);

      expect(response.header).toHaveBeenCalledWith("X-Quota-Limit", 1_000_000);
      expect(response.header).toHaveBeenCalledWith(
        "X-Quota-Remaining",
        999_999,
      );
    });

    it("returns 429 with QUOTA_EXCEEDED when the free quota is exhausted", async () => {
      jest.spyOn(reflector, "getAllAndOverride").mockReturnValue(undefined);
      mockQuotaStore.set(`quota:key-done:${currentMonthKey()}`, 10_000);

      const { context } = createContext({
        user: { id: "user-9", tier: "free" },
        headers: { "x-api-key": "key-done" },
      });

      try {
        await guard.canActivate(context);
        throw new Error("Expected monthly quota rejection");
      } catch (error) {
        expect(error).toBeInstanceOf(HttpException);
        expect((error as HttpException).getStatus()).toBe(
          HttpStatus.TOO_MANY_REQUESTS,
        );
        const body = (error as HttpException).getResponse() as {
          code?: string;
        };
        expect(body.code).toBe("QUOTA_EXCEEDED");
      }
    });

    it("reports enterprise usage as unlimited without touching redis", async () => {
      jest.spyOn(reflector, "getAllAndOverride").mockReturnValue(undefined);
      const { context, response } = createContext({
        user: { id: "user-10", role: "admin" },
        headers: { "x-api-key": "key-ent" },
      });

      await expect(guard.canActivate(context)).resolves.toBe(true);

      expect(response.header).toHaveBeenCalledWith(
        "X-Quota-Remaining",
        "unlimited",
      );
      expect(mockQuotaStore.size).toBe(0);
    });
  });
});
