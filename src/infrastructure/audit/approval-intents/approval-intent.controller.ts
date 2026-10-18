import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Post,
  Query,
  Request,
  UseGuards,
} from "@nestjs/common";
import {
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from "@nestjs/swagger";
import { JwtAuthGuard } from "src/core/auth/guards/jwt-auth.guard";
import { AdminTwoFactorGuard } from "src/core/auth/guards/admin-two-factor.guard";
import { RolesGuard } from "src/common/guard/roles.guard";
import { Roles } from "src/common/guard/roles.decorator";
import { Role } from "src/common/guard/roles.enum";
import { ApprovalIntentStatus } from "./approval-intent.types";
import {
  ApprovalIntentService,
  IntentExecutor,
} from "./approval-intent.service";
import {
  CancelApprovalIntentDto,
  ListApprovalIntentsQueryDto,
  ProposeApprovalIntentDto,
} from "./dto/propose-intent.dto";

/**
 * Admin API for the maintainer approval flow (#220).
 *
 * Same guard stack as {@link AdminRoleController}: bearer JWT, role check,
 * and a 2FA-verified admin session. Execution is deliberately *not* exposed
 * here — an intent is consumed by the route it authorizes (see
 * `PATCH /admin/users/:id/role`), so the executor never gets to pick an
 * arbitrary operation to attach to a signed intent.
 */
@ApiTags("admin-approval-intents")
@ApiBearerAuth("bearer")
@UseGuards(JwtAuthGuard, RolesGuard, AdminTwoFactorGuard)
@Roles(Role.ADMIN)
@Controller("admin/intents")
export class ApprovalIntentController {
  constructor(private readonly intents: ApprovalIntentService) {}

  @Post()
  @HttpCode(201)
  @ApiOperation({
    summary: "Propose a maintainer approval intent",
    description:
      "Persists and signs an intent to perform a high-impact action. The " +
      "intent binds action, actor, resource, reason and payload; executing " +
      "route consumes it exactly once.",
  })
  @ApiResponse({ status: 201, description: "Intent proposed and signed" })
  @ApiResponse({ status: 400, description: "Invalid action, reason or TTL" })
  @ApiResponse({
    status: 409,
    description: "An identical intent is already proposed",
  })
  async propose(@Body() dto: ProposeApprovalIntentDto, @Request() request: any) {
    return this.intents.propose({
      action: dto.action,
      actor: this.actorFrom(request),
      resourceType: dto.resourceType,
      resourceId: dto.resourceId,
      reason: dto.reason,
      payload: dto.payload ?? {},
      approverId: dto.approverId ?? null,
      metadata: dto.metadata,
      ttlSeconds: dto.ttlSeconds,
    });
  }

  @Get()
  @ApiOperation({ summary: "List approval intents, newest first" })
  @ApiQuery({ name: "status", required: false, enum: ApprovalIntentStatus })
  @ApiQuery({ name: "action", required: false })
  @ApiQuery({ name: "actorId", required: false })
  @ApiQuery({ name: "resourceId", required: false })
  @ApiQuery({ name: "limit", required: false, type: Number })
  async list(@Query() query: ListApprovalIntentsQueryDto) {
    return this.intents.list({
      status: query.status,
      action: query.action,
      actorId: query.actorId,
      resourceId: query.resourceId,
      limit: query.limit,
    });
  }

  @Get(":id")
  @ApiParam({ name: "id" })
  @ApiOperation({ summary: "Fetch one approval intent" })
  @ApiResponse({ status: 404, description: "No such intent" })
  get(@Param("id") id: string) {
    return this.intents.get(id);
  }

  @Get(":id/receipt/verify")
  @ApiParam({ name: "id" })
  @ApiOperation({
    summary: "Verify the signed receipt of a terminal intent",
    description:
      "Re-canonicalizes the stored receipt document, recomputes its hash " +
      "and checks the HMAC over it. An intent without a receipt reports " +
      "valid=false with the reason.",
  })
  verify(@Param("id") id: string) {
    return this.intents.verify(id);
  }

  @Post(":id/cancel")
  @HttpCode(200)
  @ApiParam({ name: "id" })
  @ApiOperation({ summary: "Withdraw a proposed intent" })
  @ApiResponse({ status: 409, description: "Intent is not proposed" })
  cancel(
    @Param("id") id: string,
    @Body() dto: CancelApprovalIntentDto,
    @Request() request: any,
  ) {
    return this.intents.cancel(id, this.executorFrom(request), dto.reason);
  }

  @Post(":id/expire")
  @HttpCode(200)
  @ApiParam({ name: "id" })
  @ApiOperation({
    summary: "Age out a proposed intent immediately",
    description:
      "Administrative cleanup: forces proposed -> expired so an intent " +
      "can never execute, without waiting for its TTL.",
  })
  @ApiResponse({ status: 409, description: "Intent is not proposed" })
  expire(@Param("id") id: string) {
    return this.intents.expireIntent(id);
  }

  private actorFrom(request: any) {
    return {
      id: request?.user?.sub ?? request?.user?.id ?? "",
      role: request?.user?.role ?? null,
      ipAddress: request?.ip ?? null,
      userAgent: request?.headers?.["user-agent"] ?? null,
    };
  }

  private executorFrom(request: any): IntentExecutor {
    return this.actorFrom(request);
  }
}
