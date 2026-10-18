import {
  ConflictException,
  Controller,
  Delete,
  Get,
  HttpException,
  HttpStatus,
  Param,
  Patch,
  Body,
  Query,
  Request,
  UseGuards,
} from "@nestjs/common";
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from "@nestjs/swagger";
import { UserService } from "./user.service";
import { AssignRoleDto } from "./dto/assign-role.dto";
import {
  Role,
  ROLE_HIERARCHY,
  getRolePermissions,
  getUiCapabilities,
} from "src/common/guard/roles.enum";
import { Roles } from "src/common/guard/roles.decorator";
import { RolesGuard } from "src/common/guard/roles.guard";
import { JwtAuthGuard } from "src/core/auth/guards/jwt-auth.guard";
import { AdminTwoFactorGuard } from "src/core/auth/guards/admin-two-factor.guard";
import {
  ApprovalIntentService,
  isMaintainerApprovalEnforced,
} from "src/infrastructure/audit/approval-intents/approval-intent.service";
import { ApprovalIntent } from "src/infrastructure/audit/entities/approval-intent.entity";
import { SensitiveAction } from "src/infrastructure/audit/sensitive-actions/sensitive-action.enum";

/**
 * AdminRoleController — admin-only role management.
 *
 * Every route requires an authenticated admin whose session is 2FA-verified:
 *  - {@link JwtAuthGuard} populates `request.user` from the bearer token.
 *  - {@link RolesGuard} enforces `@Roles(Role.ADMIN)`.
 *  - {@link AdminTwoFactorGuard} enforces mandatory 2FA for admins.
 *
 * Role assignment is delegated to {@link UserService.assignRole}, which
 * validates the target user exists and rejects conflicting role pairs.
 *
 * When `MAINTAINER_APPROVAL_INTENTS_ENFORCED` is on (#220), the two role
 * mutating routes additionally require a signed approval intent that commits
 * to this exact action, user and role; the change runs through
 * {@link ApprovalIntentService.execute}, which claims the intent once and
 * stores a signed receipt. With the flag off (the default) behaviour is
 * byte-identical to the pre-approval flow.
 */
@ApiTags("Admin — Role Management")
@ApiBearerAuth()
@UseGuards(JwtAuthGuard, RolesGuard, AdminTwoFactorGuard)
@Roles(Role.ADMIN)
@Controller("admin")
export class AdminRoleController {
  constructor(
    private readonly userService: UserService,
    private readonly approvalIntents: ApprovalIntentService,
  ) {}

  @Get("roles")
  @ApiOperation({
    summary: "List assignable roles",
    description: "Returns the canonical set of roles that can be assigned.",
  })
  @ApiResponse({ status: 200, description: "List of assignable roles" })
  listRoles(): { roles: Role[] } {
    return { roles: Object.values(Role) };
  }

  @Get("roles/matrix")
  @ApiOperation({
    summary: "Get roles and permissions matrix",
    description:
      "Returns the capabilities, permissions, and hierarchy for every canonical role.",
  })
  @ApiResponse({ status: 200, description: "Role matrix and capabilities" })
  getRoleMatrix() {
    return {
      hierarchy: ROLE_HIERARCHY,
      roles: Object.values(Role).map((role) => ({
        role,
        permissions: getRolePermissions(role),
        capabilities: getUiCapabilities(role),
      })),
    };
  }

  @Get("users/:id/role")
  @ApiOperation({ summary: "Get a user's current role" })
  @ApiResponse({ status: 200, description: "The user's current role" })
  @ApiResponse({ status: 404, description: "User not found" })
  async getUserRole(
    @Param("id") id: string,
  ): Promise<{ id: string; role: Role }> {
    const user = await this.userService.findOneOrFail(id);
    return { id: user.id, role: user.role };
  }

  @Patch("users/:id/role")
  @ApiOperation({
    summary: "Assign a role to a user",
    description:
      "Assigns the given canonical role. Rejects conflicting role pairs " +
      "(e.g. GOVERNANCE_OPERATOR + KYC_OPERATOR) with 400. When " +
      "MAINTAINER_APPROVAL_INTENTS_ENFORCED is on, an approval intent that " +
      "commits to this action, user and role is required (428 without one, " +
      "409 on a mismatched intent).",
  })
  @ApiResponse({ status: 200, description: "Role assigned" })
  @ApiResponse({ status: 400, description: "Invalid or conflicting role" })
  @ApiResponse({ status: 404, description: "User not found" })
  async assignRole(
    @Param("id") id: string,
    @Body() dto: AssignRoleDto,
    @Request() request?: any,
  ): Promise<{ id: string; role: Role }> {
    const auditContext = {
      actorId: request?.user?.sub ?? request?.user?.id ?? id,
      actorRole: request?.user?.role ?? Role.ADMIN,
      reason: dto.reason,
    };
    const operation = () =>
      this.userService.assignRole(id, dto.role, auditContext);

    if (!isMaintainerApprovalEnforced()) {
      return this.respond(await operation());
    }

    const intentId = dto.approvalIntentId?.trim();
    if (!intentId) {
      throw new HttpException(
        {
          statusCode: HttpStatus.PRECONDITION_REQUIRED,
          error: "Precondition Required",
          message:
            "MAINTAINER_APPROVAL_INTENTS_ENFORCED requires an " +
            "approvalIntentId: propose one at POST /admin/intents with " +
            `action ${SensitiveAction.ROLE_ASSIGNED} for this user and role`,
        },
        HttpStatus.PRECONDITION_REQUIRED,
      );
    }
    const intent = await this.approvalIntents.get(intentId);
    this.assertRoleIntentBinding(intent, id, {
      action: SensitiveAction.ROLE_ASSIGNED,
      role: dto.role,
    });

    const { result } = await this.approvalIntents.execute(
      intentId,
      {
        id: auditContext.actorId,
        role: auditContext.actorRole,
        ipAddress: request?.ip ?? null,
        userAgent: request?.headers?.["user-agent"] ?? null,
      },
      operation,
    );
    return this.respond(result);
  }

  @Delete("users/:id/role")
  @ApiOperation({
    summary: "Reset a user's role",
    description:
      "Resets the user to the least-privileged USER role. When " +
      "MAINTAINER_APPROVAL_INTENTS_ENFORCED is on, an approval intent that " +
      "commits to revoking this user's role is required.",
  })
  @ApiResponse({ status: 200, description: "Role reset to USER" })
  @ApiResponse({ status: 404, description: "User not found" })
  async resetRole(
    @Param("id") id: string,
    @Query("approvalIntentId") approvalIntentId?: string,
    @Request() request?: any,
  ): Promise<{ id: string; role: Role }> {
    const auditContext = {
      actorId: request?.user?.sub ?? request?.user?.id ?? id,
      actorRole: request?.user?.role ?? Role.ADMIN,
      reason: "Administrator reset the user to the least-privileged role",
    };
    const operation = () =>
      this.userService.assignRole(id, Role.USER, auditContext);

    if (!isMaintainerApprovalEnforced()) {
      return this.respond(await operation());
    }

    const intentId = approvalIntentId?.trim();
    if (!intentId) {
      throw new HttpException(
        {
          statusCode: HttpStatus.PRECONDITION_REQUIRED,
          error: "Precondition Required",
          message:
            "MAINTAINER_APPROVAL_INTENTS_ENFORCED requires an " +
            "approvalIntentId query parameter: propose one at " +
            `POST /admin/intents with action ${SensitiveAction.ROLE_REVOKED}`,
        },
        HttpStatus.PRECONDITION_REQUIRED,
      );
    }
    const intent = await this.approvalIntents.get(intentId);
    this.assertRoleIntentBinding(intent, id, {
      action: SensitiveAction.ROLE_REVOKED,
      role: Role.USER,
    });

    const { result } = await this.approvalIntents.execute(
      intentId,
      {
        id: auditContext.actorId,
        role: auditContext.actorRole,
        ipAddress: request?.ip ?? null,
        userAgent: request?.headers?.["user-agent"] ?? null,
      },
      operation,
    );
    return this.respond(result);
  }

  /**
   * Binds an execution to the exact work the intent signed for (#220). The
   * fingerprint already commits to these values; this check makes the
   * executing route refuse to consume an intent that signed for different
   * work (another user, another target role, another action).
   */
  private assertRoleIntentBinding(
    intent: ApprovalIntent,
    userId: string,
    expected: { action: SensitiveAction; role: Role },
  ): void {
    if (intent.action !== expected.action) {
      throw new ConflictException(
        `Intent ${intent.id} authorizes ${intent.action}, not ` +
          `${expected.action}`,
      );
    }
    if (intent.resourceType !== "user" || intent.resourceId !== userId) {
      throw new ConflictException(
        `Intent ${intent.id} targets ${intent.resourceType}/` +
          `${intent.resourceId}, not user/${userId}`,
      );
    }
    const intendedRole = intent.payload?.["role"];
    if (intendedRole !== expected.role) {
      throw new ConflictException(
        `Intent ${intent.id} commits to role ${JSON.stringify(intendedRole)}, ` +
          `not ${expected.role}`,
      );
    }
  }

  private respond(user: { id: string; role: Role }): { id: string; role: Role } {
    return { id: user.id, role: user.role };
  }
}
