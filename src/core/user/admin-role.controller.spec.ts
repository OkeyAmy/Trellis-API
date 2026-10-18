import { Test, TestingModule } from "@nestjs/testing";
import {
  BadRequestException,
  ConflictException,
  HttpException,
  NotFoundException,
} from "@nestjs/common";
import { AdminRoleController } from "./admin-role.controller";
import { UserService } from "./user.service";
import { User } from "./entities/user.entity";
import { Role } from "src/common/guard/roles.enum";
import { RolesGuard } from "src/common/guard/roles.guard";
import { JwtAuthGuard } from "src/core/auth/guards/jwt-auth.guard";
import { AdminTwoFactorGuard } from "src/core/auth/guards/admin-two-factor.guard";
import { ApprovalIntentService } from "src/infrastructure/audit/approval-intents/approval-intent.service";
import { ApprovalIntent } from "src/infrastructure/audit/entities/approval-intent.entity";
import { SensitiveAction } from "src/infrastructure/audit/sensitive-actions/sensitive-action.enum";

describe("AdminRoleController", () => {
  let controller: AdminRoleController;
  let userService: jest.Mocked<
    Pick<UserService, "assignRole" | "findOneOrFail">
  >;
  let approvalIntents: {
    get: jest.Mock;
    execute: jest.Mock;
  };

  const makeUser = (role: Role): User =>
    ({ id: "user-1", role }) as unknown as User;

  beforeEach(async () => {
    userService = {
      assignRole: jest.fn(),
      findOneOrFail: jest.fn(),
    };
    approvalIntents = {
      get: jest.fn(),
      execute: jest.fn(async (_id, _executor, operation) => ({
        intent: { id: _id, status: "completed" } as unknown as ApprovalIntent,
        result: await operation(),
      })),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AdminRoleController],
      providers: [
        { provide: UserService, useValue: userService },
        { provide: ApprovalIntentService, useValue: approvalIntents },
      ],
    })
      // These are unit tests for the controller's logic; the guard behaviour
      // is covered by their own specs, so override them with pass-throughs
      // to avoid resolving their (auth-module) dependencies here.
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(RolesGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(AdminTwoFactorGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get<AdminRoleController>(AdminRoleController);
  });

  describe("listRoles", () => {
    it("returns every canonical role", () => {
      expect(controller.listRoles()).toEqual({ roles: Object.values(Role) });
    });
  });

  describe("getUserRole", () => {
    it("returns the target user's current role", async () => {
      userService.findOneOrFail.mockResolvedValue(makeUser(Role.OPERATOR));
      await expect(controller.getUserRole("user-1")).resolves.toEqual({
        id: "user-1",
        role: Role.OPERATOR,
      });
    });

    it("propagates NotFoundException for an unknown user", async () => {
      userService.findOneOrFail.mockRejectedValue(new NotFoundException());
      await expect(controller.getUserRole("nope")).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe("assignRole", () => {
    it("assigns the requested role and echoes the result", async () => {
      userService.assignRole.mockResolvedValue(makeUser(Role.ADMIN));
      await expect(
        controller.assignRole("user-1", { role: Role.ADMIN }),
      ).resolves.toEqual({ id: "user-1", role: Role.ADMIN });
      expect(userService.assignRole).toHaveBeenCalledWith("user-1", Role.ADMIN, {
        actorId: "user-1",
        actorRole: Role.ADMIN,
        reason: undefined,
      });
    });

    it("propagates BadRequestException for a conflicting role", async () => {
      userService.assignRole.mockRejectedValue(new BadRequestException());
      await expect(
        controller.assignRole("user-1", { role: Role.KYC_OPERATOR }),
      ).rejects.toThrow(BadRequestException);
    });

    it("propagates NotFoundException for an unknown user", async () => {
      userService.assignRole.mockRejectedValue(new NotFoundException());
      await expect(
        controller.assignRole("nope", { role: Role.ADMIN }),
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe("resetRole", () => {
    it("resets the target user to the least-privileged USER role", async () => {
      userService.assignRole.mockResolvedValue(makeUser(Role.USER));
      await expect(controller.resetRole("user-1")).resolves.toEqual({
        id: "user-1",
        role: Role.USER,
      });
      expect(userService.assignRole).toHaveBeenCalledWith("user-1", Role.USER, {
        actorId: "user-1",
        actorRole: Role.ADMIN,
        reason: "Administrator reset the user to the least-privileged role",
      });
    });
  });

  describe("getRoleMatrix", () => {
    it("returns role hierarchy, permissions, and capabilities", () => {
      const matrix = controller.getRoleMatrix();
      expect(matrix.hierarchy).toContain(Role.MAINTAINER);
      expect(matrix.roles.length).toBe(Object.values(Role).length);
      const adminEntry = matrix.roles.find((r) => r.role === Role.ADMIN);
      expect(adminEntry?.capabilities.canManageUsers).toBe(true);
      expect(adminEntry?.capabilities.canTrade).toBe(true);
    });
  });

  describe("approval intent enforcement (#220)", () => {
    const makeIntent = (over: Partial<ApprovalIntent> = {}): ApprovalIntent =>
      ({
        id: "intent-1",
        status: "proposed",
        action: SensitiveAction.ROLE_ASSIGNED,
        resourceType: "user",
        resourceId: "user-1",
        payload: { role: Role.ADMIN },
        ...over,
      }) as unknown as ApprovalIntent;

    const request = {
      user: { sub: "admin-9", role: Role.ADMIN },
      ip: "10.0.0.9",
      headers: { "user-agent": "jest" },
    };

    const statusOf = (error: unknown): number =>
      (error as HttpException).getStatus();

    afterEach(() => {
      delete process.env.MAINTAINER_APPROVAL_INTENTS_ENFORCED;
    });

    it("ignores approvalIntentId while the flag is off (default unchanged)", async () => {
      userService.assignRole.mockResolvedValue(makeUser(Role.ADMIN));
      approvalIntents.get.mockResolvedValue(makeIntent());

      await expect(
        controller.assignRole(
          "user-1",
          { role: Role.ADMIN, approvalIntentId: "intent-1" },
          request,
        ),
      ).resolves.toEqual({ id: "user-1", role: Role.ADMIN });

      expect(approvalIntents.get).not.toHaveBeenCalled();
      expect(approvalIntents.execute).not.toHaveBeenCalled();
      expect(userService.assignRole).toHaveBeenCalledWith(
        "user-1",
        Role.ADMIN,
        expect.objectContaining({ actorId: "admin-9" }),
      );
    });

    it("rejects an assign without an intent with 428 when enforced", async () => {
      process.env.MAINTAINER_APPROVAL_INTENTS_ENFORCED = "true";

      try {
        await controller.assignRole("user-1", { role: Role.ADMIN }, request);
        throw new Error("expected a 428 rejection");
      } catch (error) {
        expect(statusOf(error)).toBe(428);
      }
      expect(userService.assignRole).not.toHaveBeenCalled();
    });

    it("refuses an intent that authorizes a different action (409)", async () => {
      process.env.MAINTAINER_APPROVAL_INTENTS_ENFORCED = "true";
      approvalIntents.get.mockResolvedValue(
        makeIntent({ action: SensitiveAction.ROLE_REVOKED }),
      );

      try {
        await controller.assignRole(
          "user-1",
          { role: Role.ADMIN, approvalIntentId: "intent-1" },
          request,
        );
        throw new Error("expected a conflict");
      } catch (error) {
        expect(statusOf(error)).toBe(409);
      }
      expect(approvalIntents.execute).not.toHaveBeenCalled();
    });

    it("refuses an intent that targets another user (409)", async () => {
      process.env.MAINTAINER_APPROVAL_INTENTS_ENFORCED = "true";
      approvalIntents.get.mockResolvedValue(
        makeIntent({ resourceId: "user-2" }),
      );

      try {
        await controller.assignRole(
          "user-1",
          { role: Role.ADMIN, approvalIntentId: "intent-1" },
          request,
        );
        throw new Error("expected a conflict");
      } catch (error) {
        expect(statusOf(error)).toBe(409);
      }
    });

    it("refuses an intent that commits to another role (409)", async () => {
      process.env.MAINTAINER_APPROVAL_INTENTS_ENFORCED = "true";
      approvalIntents.get.mockResolvedValue(
        makeIntent({ payload: { role: Role.MAINTAINER } }),
      );

      try {
        await controller.assignRole(
          "user-1",
          { role: Role.ADMIN, approvalIntentId: "intent-1" },
          request,
        );
        throw new Error("expected a conflict");
      } catch (error) {
        expect(statusOf(error)).toBe(409);
      }
    });

    it("runs a bound intent through execute() and returns the result", async () => {
      process.env.MAINTAINER_APPROVAL_INTENTS_ENFORCED = "true";
      approvalIntents.get.mockResolvedValue(makeIntent());
      userService.assignRole.mockResolvedValue(makeUser(Role.ADMIN));

      await expect(
        controller.assignRole(
          "user-1",
          { role: Role.ADMIN, approvalIntentId: "intent-1", reason: "promo" },
          request,
        ),
      ).resolves.toEqual({ id: "user-1", role: Role.ADMIN });

      expect(approvalIntents.execute).toHaveBeenCalledWith(
        "intent-1",
        {
          id: "admin-9",
          role: Role.ADMIN,
          ipAddress: "10.0.0.9",
          userAgent: "jest",
        },
        expect.any(Function),
      );
      expect(userService.assignRole).toHaveBeenCalledTimes(1);
    });

    it("propagates an execution conflict (double-claim, expiry) untouched", async () => {
      process.env.MAINTAINER_APPROVAL_INTENTS_ENFORCED = "true";
      approvalIntents.get.mockResolvedValue(makeIntent());
      approvalIntents.execute.mockRejectedValue(
        new ConflictException(
          "Intent intent-1 was claimed by another execution",
        ),
      );

      await expect(
        controller.assignRole(
          "user-1",
          { role: Role.ADMIN, approvalIntentId: "intent-1" },
          request,
        ),
      ).rejects.toThrow(ConflictException);
      expect(userService.assignRole).not.toHaveBeenCalled();
    });

    it("enforces a revoke intent on resetRole through the query parameter", async () => {
      process.env.MAINTAINER_APPROVAL_INTENTS_ENFORCED = "true";
      approvalIntents.get.mockResolvedValue(
        makeIntent({
          action: SensitiveAction.ROLE_REVOKED,
          payload: { role: Role.USER },
        }),
      );
      userService.assignRole.mockResolvedValue(makeUser(Role.USER));

      await expect(
        controller.resetRole("user-1", "intent-1", request),
      ).resolves.toEqual({ id: "user-1", role: Role.USER });

      expect(approvalIntents.execute).toHaveBeenCalledWith(
        "intent-1",
        expect.objectContaining({ id: "admin-9" }),
        expect.any(Function),
      );
      expect(userService.assignRole).toHaveBeenCalledWith(
        "user-1",
        Role.USER,
        expect.objectContaining({
          reason: "Administrator reset the user to the least-privileged role",
        }),
      );
    });

    it("rejects a reset without an intent with 428 when enforced", async () => {
      process.env.MAINTAINER_APPROVAL_INTENTS_ENFORCED = "true";

      try {
        await controller.resetRole("user-1", undefined, request);
        throw new Error("expected a 428 rejection");
      } catch (error) {
        expect(statusOf(error)).toBe(428);
      }
      expect(userService.assignRole).not.toHaveBeenCalled();
    });
  });
});

