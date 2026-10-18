import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { Type } from "class-transformer";
import {
  IsEnum,
  IsInt,
  IsObject,
  IsOptional,
  IsString,
  Max,
  MaxLength,
  Min,
} from "class-validator";
import { ApprovalIntentStatus } from "../approval-intent.types";

/**
 * Payload for proposing a maintainer approval intent (#220).
 *
 * `action` must be a catalogued sensitive action: an intent that could name
 * an undeclared action would let a caller invent an unauditable operation.
 * `reason` is always required — it is committed to by the fingerprint, so a
 * reviewer can prove what justification was signed.
 */
export class ProposeApprovalIntentDto {
  @ApiProperty({
    description: "Catalogued sensitive action this intent authorizes.",
    example: "access.role.assigned",
  })
  @IsString()
  @MaxLength(100)
  action: string;

  @ApiProperty({
    description: "Kind of resource the action will touch.",
    example: "user",
  })
  @IsString()
  @MaxLength(100)
  resourceType: string;

  @ApiProperty({
    description: "Identifier of the resource the action will touch.",
    example: "0d9a1f7c-8f2e-4b6a-9c3d-1a2b3c4d5e6f",
  })
  @IsString()
  @MaxLength(255)
  resourceId: string;

  @ApiProperty({
    description: "Mandatory justification; committed to by the fingerprint.",
    example: "Promotion approved in ticket OPS-142",
  })
  @IsString()
  @MaxLength(2000)
  reason: string;

  @ApiPropertyOptional({
    description:
      "Exact input the action will be executed with; also committed to.",
    type: "object",
    additionalProperties: true,
    example: { role: "MAINTAINER" },
  })
  @IsOptional()
  @IsObject()
  payload?: Record<string, unknown>;

  @ApiPropertyOptional({
    description:
      "Second pair of eyes. Must differ from the proposing actor; when set, " +
      "only the approver may execute the intent.",
  })
  @IsOptional()
  @IsString()
  @MaxLength(64)
  approverId?: string;

  @ApiPropertyOptional({
    description: "Non-secret context (request id, ticket reference).",
    type: "object",
    additionalProperties: true,
  })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, unknown>;

  @ApiPropertyOptional({
    description: "Lifetime of the intent in seconds.",
    minimum: 60,
    maximum: 604800,
    default: 900,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(60)
  @Max(604800)
  ttlSeconds?: number;
}

/** Body for withdrawing a proposed intent. */
export class CancelApprovalIntentDto {
  @ApiProperty({
    description: "Why the intent is being withdrawn; recorded as evidence.",
    example: "Superseded by a corrected request",
  })
  @IsString()
  @MaxLength(2000)
  reason: string;
}

/** Query filters for listing intents. */
export class ListApprovalIntentsQueryDto {
  @ApiPropertyOptional({ enum: ApprovalIntentStatus })
  @IsOptional()
  @IsEnum(ApprovalIntentStatus)
  status?: ApprovalIntentStatus;

  @ApiPropertyOptional({ description: "Filter by catalogued action." })
  @IsOptional()
  @IsString()
  @MaxLength(100)
  action?: string;

  @ApiPropertyOptional({ description: "Filter by proposing actor." })
  @IsOptional()
  @IsString()
  @MaxLength(64)
  actorId?: string;

  @ApiPropertyOptional({ description: "Filter by target resource." })
  @IsOptional()
  @IsString()
  @MaxLength(255)
  resourceId?: string;

  @ApiPropertyOptional({ minimum: 1, maximum: 100, default: 20 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number;
}
