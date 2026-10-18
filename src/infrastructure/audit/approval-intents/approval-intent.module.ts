import { Module } from "@nestjs/common";
import { TypeOrmModule } from "@nestjs/typeorm";
import { ApprovalIntent } from "../entities/approval-intent.entity";
import { SensitiveActionAuditModule } from "../sensitive-actions/sensitive-action-audit.module";
import { ExportSigningService } from "../algorithms/export-signing.service";
import { ApprovalIntentService } from "./approval-intent.service";
import { ApprovalIntentController } from "./approval-intent.controller";

/**
 * Maintainer approval flow (#220).
 *
 * Owns the `approval_intents` table, the propose/cancel/expiry REST surface,
 * and the `execute()` primitive consumed by the routes that a signed intent
 * authorizes (wired into the admin role routes behind
 * `MAINTAINER_APPROVAL_INTENTS_ENFORCED`).
 *
 * `ExportSigningService` is provided here rather than imported from
 * `AuditModule`, which does not export it — the same stateless-provide
 * convention `EvidenceBundleModule` follows.
 */
@Module({
  imports: [TypeOrmModule.forFeature([ApprovalIntent]), SensitiveActionAuditModule],
  controllers: [ApprovalIntentController],
  providers: [ApprovalIntentService, ExportSigningService],
  exports: [ApprovalIntentService],
})
export class ApprovalIntentModule {}
