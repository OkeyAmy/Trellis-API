import { Test, TestingModule } from "@nestjs/testing";
import { NotFoundException } from "@nestjs/common";
import { ApprovalIntentController } from "./approval-intent.controller";
import { ApprovalIntentService } from "./approval-intent.service";
import { ApprovalIntentStatus } from "./approval-intent.types";
import { JwtAuthGuard } from "src/core/auth/guards/jwt-auth.guard";
import { AdminTwoFactorGuard } from "src/core/auth/guards/admin-two-factor.guard";
import { RolesGuard } from "src/common/guard/roles.guard";
import {
  CancelApprovalIntentDto,
  ProposeApprovalIntentDto,
} from "./dto/propose-intent.dto";

/*
 * Route wiring for the approval intent API (#220): actor extraction from
 * the authenticated request, DTO mapping, and error passthrough. Guard
 * behaviour belongs to the guards' own specs.
 */
describe("ApprovalIntentController", () => {
  let controller: ApprovalIntentController;
  let intents: jest.Mocked<
    Pick<
      ApprovalIntentService,
      "propose" | "get" | "list" | "cancel" | "expireIntent" | "verify"
    >
  >;

  const request = {
    user: { sub: "admin-3", role: "ADMIN" },
    ip: "10.1.1.3",
    headers: { "user-agent": "curl/8" },
  };

  beforeEach(async () => {
    intents = {
      propose: jest.fn().mockResolvedValue({ id: "intent-1" }),
      get: jest.fn().mockResolvedValue({ id: "intent-1" }),
      list: jest.fn().mockResolvedValue([]),
      cancel: jest.fn().mockResolvedValue({ id: "intent-1" }),
      expireIntent: jest.fn().mockResolvedValue({ id: "intent-1" }),
      verify: jest.fn().mockResolvedValue({ valid: true, errors: [] }),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ApprovalIntentController],
      providers: [{ provide: ApprovalIntentService, useValue: intents }],
    })
      // The guard stack's dependencies (auth module, repositories) are not
      // resolvable in a unit context; guard behaviour has its own specs.
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(RolesGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(AdminTwoFactorGuard)
      .useValue({ canActivate: () => true })
      .compile();

    controller = module.get(ApprovalIntentController);
  });

  it("maps the propose DTO and derives the actor from the request", async () => {
    await controller.propose(
      {
        action: "access.role.assigned",
        resourceType: "user",
        resourceId: "user-5",
        reason: "approved in OPS-1",
        payload: { role: "MAINTAINER" },
        approverId: "admin-4",
        ttlSeconds: 600,
      } as ProposeApprovalIntentDto,
      request,
    );

    expect(intents.propose).toHaveBeenCalledWith({
      action: "access.role.assigned",
      actor: {
        id: "admin-3",
        role: "ADMIN",
        ipAddress: "10.1.1.3",
        userAgent: "curl/8",
      },
      resourceType: "user",
      resourceId: "user-5",
      reason: "approved in OPS-1",
      payload: { role: "MAINTAINER" },
      approverId: "admin-4",
      metadata: undefined,
      ttlSeconds: 600,
    });
  });

  it("passes list filters through untouched", async () => {
    await controller.list({
      status: ApprovalIntentStatus.PROPOSED,
      action: "access.role.assigned",
      actorId: "admin-3",
      resourceId: "user-5",
      limit: 5,
    });

    expect(intents.list).toHaveBeenCalledWith({
      status: ApprovalIntentStatus.PROPOSED,
      action: "access.role.assigned",
      actorId: "admin-3",
      resourceId: "user-5",
      limit: 5,
    });
  });

  it("cancels with the caller as executor and the supplied reason", async () => {
    await controller.cancel(
      "intent-1",
      { reason: "superseded" } as CancelApprovalIntentDto,
      request,
    );

    expect(intents.cancel).toHaveBeenCalledWith(
      "intent-1",
      expect.objectContaining({ id: "admin-3", ipAddress: "10.1.1.3" }),
      "superseded",
    );
  });

  it("routes expiry and verification by id", async () => {
    await controller.expire("intent-1");
    expect(intents.expireIntent).toHaveBeenCalledWith("intent-1");

    await controller.verify("intent-1");
    expect(intents.verify).toHaveBeenCalledWith("intent-1");
  });

  it("propagates a missing intent as 404", async () => {
    intents.get.mockRejectedValue(new NotFoundException("no such intent"));
    await expect(controller.get("missing")).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });
});
