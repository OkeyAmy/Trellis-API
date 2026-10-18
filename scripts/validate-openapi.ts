/**
 * OpenAPI Specification Validation Script
 *
 * Validates the generated OpenAPI specification for completeness and consistency,
 * and detects breaking REST API contract changes against a git baseline.
 *
 * Usage:
 *   npm run openapi:validate
 *   npm run openapi:validate -- --allow-breaking-changes
 *   npm run openapi:validate -- --baseline git:Origin/main
 */

import { NestFactory } from "@nestjs/core";
import { DocumentBuilder, SwaggerModule, OpenAPIObject } from "@nestjs/swagger";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { execFileSync } from "child_process";
import { AppModule } from "../src/app.module";

interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  breakingChanges: BreakingChange[];
  stats: {
    endpoints: number;
    schemas: number;
    tags: number;
    securitySchemes: number;
  };
}

export type BreakingChangeKind =
  | "removed-endpoint"
  | "removed-method"
  | "removed-response-status"
  | "removed-response-property"
  | "changed-property-type"
  | "added-required-request-parameter"
  | "added-required-request-body-property"
  | "removed-path-parameter"
  | "changed-parameter-type";

export interface BreakingChange {
  kind: BreakingChangeKind;
  location: string;
  message: string;
}

export interface CompareOptions {
  allowBreakingChanges?: boolean;
  baselineRef?: string;
}

const HTTP_METHODS = [
  "get",
  "post",
  "put",
  "delete",
  "patch",
  "options",
  "head",
] as const;

/**
 * Resolve the git baseline OpenAPI JSON document. Prefers an explicit ref
 * (usually from CI, e.g. git:ORIGIN_HEAD~1 or git:origin/main). Falls back
 * to a sensible default and returns null when no baseline is available.
 */
export function resolveBaselineSpec(baselineRef?: string): OpenAPIObject | null {
  const ref = baselineRef || process.env.OPENAPI_BASELINE_REF || "git:HEAD~1";
  const [source, refName] = ref.split(":", 2);

  if (source === "file") {
    if (!existsSync(refName)) {
      return null;
    }
    try {
      return JSON.parse(readFileSync(refName, "utf-8")) as OpenAPIObject;
    } catch {
      return null;
    }
  }

  if (source !== "git") {
    return null;
  }

  const gitRef = refName || "HEAD�1";
  try {
    const out = execFileSync(
      "git",
      ["show", `${gitRef}:docs/openapi.json`],
      { encoding: "utf-8", maxBuffer: 64 * 1024 * 1024 },
    );
    return JSON.parse(out) as OpenAPIObject;
  } catch {
    return null;
  }
}

function resolveRef(spec: any, ref: string): any {
  if (!ref || !ref.startsWith("#/")) {
    return undefined;
  }
  const parts = ref.substring(1).split("/");
  let cur = spec;
  for (const part of parts) {
    if (cur == null) {
      return undefined;
    }
    cur = cur[decodeURIComponent(part)];
  }
  return cur;
}

function normalizeType(type: any): string {
  if (type == null) {
    return "unknown";
  }
  if (Array.isArray(type)) {
    return type.map((t) => String(t)).sort().join("|");
  }
  return String(type);
}

function describeSchema(schema: any): string {
  if (!schema) {
    return "unknown";
  }
  if (schema.$ref) {
    return schema.$ref;
  }
  if (schema.allOf) {
    return schema.allOf.map(describeSchema).join(" & ");
  }
  if (schema.oneOf) {
    return schema.oneOf.map(describeSchema).join(" | ");
  }
  if (schema.anyOf) {
    return schema.anyOf.map(describeSchema).join(" | ");
  }
  if (schema.type === "array") {
    return `Array<${describeSchema(schema.items)}>`;
  }
  if (schema.type === "object" || schema.properties) {
    return "object";
  }
  return normalizeType(schema.type);
}

function getResolvedSchema(spec: any, schema: any): any {
  if (!schema) {
    return schema;
  }
  if (schema.$ref) {
    const resolved = resolveRef(spec, schema.$ref);
    return resolved || schema;
  }
  return schema;
}

function collectResponseProperties(
  spec: any,
  schema: any,
  prefix: string,
  out: Map<string, string>,
  visited: Set<string>,
): void {
  const resolved = getResolvedSchema(spec, schema);
  if (!resolved) {
    return;
  }

  if (resolved.$ref) {
    if (visited.has(resolved.$ref)) {
      return;
    }
    visited.add(resolved.$ref);
  }

  if (resolved.allOf) {
    for (const part of resolved.allOf) {
      collectResponseProperties(spec, part, prefix, out, visited);
    }
  }

  if (resolved.properties) {
    for (const [key, value] of Object.entries(resolved.properties as Record<string, any>)) {
      const path = prefix ? `${prefix}.${key}` : key;
      out.set(path, describeSchema(value));
      const nested = getResolvedSchema(spec, value);
      if (nested && (nested.properties || nested.allOf)) {
        collectResponseProperties(spec, nested, path, out, visited);
      }
    }
  }
}

function collectRequestBodyProperties(
  spec: any,
  schema: any,
  prefix: string,
  out: Map<string, string>,
  visited: Set<string>,
): void {
  const resolved = getResolvedSchema(spec, schema);
  if (!resolved) {
    return;
  }

  if (resolved.$ref) {
    if (visited.has(resolved.$ref)) {
      return;
    }
    visited.add(resolved.$ref);
  }

  if (resolved.allOf) {
    for (const part of resolved.allOf) {
      collectRequestBodyProperties(spec, part, prefix, out, visited);
    }
  }

  if (resolved.properties) {
    for (const [key, value] of Object.entries(resolved.properties as Record<string, any>)) {
      const path = prefix ? `${prefix}.${key}` : key;
      out.set(path, describeSchema(value));
      const nested = getResolvedSchema(spec, value);
      if (nested && (nested.properties || nested.allOf)) {
        collectRequestBodyProperties(spec, nested, path, out, visited);
      }
    }
  }
}

function collectRequestBodyRequired(
  spec: any,
  schema: any,
  prefix: string,
  out: Map<string, string>,
  visited: Set<string>,
): void {
  const resolved = getResolvedSchema(spec, schema);
  if (!resolved) {
    return;
  }

  if (resolved.$ref) {
    if (visited.has(resolved.$ref)) {
      return;
    }
    visited.add(resolved.$ref);
  }

  if (resolved.allOf) {
    for (const part of resolved.allOf) {
      collectRequestBodyRequired(spec, part, prefix, out, visited);
    }
  }

  if (resolved.properties) {
    const required: string[] = Array.isArray(resolved.required)
      ? resolved.required
      : [];
    for (const [key, value] of Object.entries(resolved.properties as Record<string, any>)) {
      const path = prefix ? `${prefix}.${key}` : key;
      if (required.includes(key)) {
        out.set(path, describeSchema(value));
      }
      const nested = getResolvedSchema(spec, value);
      if (nested && (nested.properties || nested.allOf)) {
        collectRequestBodyRequired(spec, nested, path, out, visited);
      }
    }
  }
}

function collectResponseStatuses(operation: any): Map<string, any> {
  const out = new Map<string, any>();
  for (const [status, response] of Object.entries(
    (operation.responses || {}) as Record<string, any>,
  )) {
    out.set(String(status), response);
  }
  return out;
}

function collectParameters(operation: any): Map<string, any> {
  const out = new Map<string, any>();
  const params = Array.isArray(operation.parameters)
    ? operation.parameters
    : [];
  for (const param of params) {
    if (!param || !param.name) {
      continue;
    }
    const key = `${param.in || "query"}:${param.name}`;
    out.set(key, param);
  }
  return out;
}

export function detectBreakingChanges(
  baseline: OpenAPIObject | null,
  current: OpenAPIObject,
): BreakingChange[] {
  const changes: BreakingChange[] = [];

  if (!baseline) {
    return changes;
  }

  const basePaths = (baseline.paths || {}) as Record<string, any>;
  const currPaths = (current.paths || {}) as Record<string, any>;

  for (const [path, baseItem] of Object.entries(basePaths)) {
    const currItem = currPaths[path];
    if (!currItem) {
      changes.push({
        kind: "removed-endpoint",
        location: path,
        message: `Endpoint ${path} was removed`,
      });
      continue;
    }

    for (const method of HTTP_METHODS) {
      const baseOp = baseItem[method];
      if (!baseOp) {
        continue;
      }
      const currOp = currItem[method];
      const location = `${method.toUpperCase()} ${path}`;
      if (!currOp) {
        changes.push({
          kind: "removed-method",
          location,
          message: `Method ${method.toUpperCase()} ${path} was removed`,
        });
        continue;
      }

      // Response status codes
      const baseResponses = collectResponseStatuses(baseOp);
      const currResponses = collectResponseStatuses(currOp);
      for (const [status, baseResponse] of baseResponses) {
        const currResponse = currResponses.get(status);
        if (!currResponse) {
          changes.push({
            kind: "removed-response-status",
            location: `${location} -> ${status}`,
            message: `Response status ${status} was removed from ${location}`,
          });
          continue;
        }

        const baseSchema = baseResponse.content?.["application/json"]?.schema;
        const currSchema = currResponse.content?.["application/json"]?.schema;
        if (!baseSchema) {
          continue;
        }
        if (!currSchema) {
          changes.push({
            kind: "removed-response-property",
            location: `${location} -> ${status} body`,
            message: `Response body schema was removed for ${location} (${status})`,
          });
          continue;
        }

        const baseProps = new Map<string, string>();
        collectResponseProperties(
          baseline as any,
          baseSchema,
          "",
          baseProps,
          new Set(),
        );
        const currProps = new Map<string, string>();
        collectResponseProperties(
          current as any,
          currSchema,
          "",
          currProps,
          new Set(),
        );

        for (const [prop, baseType] of baseProps) {
          const currType = currProps.get(prop);
          if (currType === undefined) {
            changes.push({
              kind: "removed-response-property",
              location: `${location} -> ${status} -> ${prop}`,
              message: `Response property ${prop} was removed from ${location} (${status})`,
            });
          } else if (currType !== baseType) {
            changes.push({
              kind: "changed-property-type",
              location: `${location} -> ${status} -> ${prop}`,
              message: `Response property ${prop} type changed from '${baseType}' to '${currType}' in ${location} (${status})`,
            });
          }
        }
      }

      // Parameters
      const baseParams = collectParameters(baseOp);
      const currParams = collectParameters(currOp);
      for (const [key, baseParam] of baseParams) {
        const currParam = currParams.get(key);
        if (!currParam) {
          if (baseParam.in === "path") {
            changes.push({
              kind: "removed-path-parameter",
              location: `${location} -> ${key}`,
              message: `Path parameter ${baseParam.name} was removed from ${location}`,
            });
          }
          continue;
        }
        const baseType = normalizeType(baseParam.schema?.type);
        const currType = normalizeType(currParam.schema?.type);
        if (baseType !== currType) {
          changes.push({
            kind: "changed-parameter-type",
            location: `${location} -> ${key}`,
            message: `Parameter ${baseParam.name} type changed from '${baseType}' to '${currType}' in ${location}`,
          });
        }
      }

      for (const [key, currParam] of currParams) {
        if (baseParams.has(key)) {
          continue;
        }
        if (currParam.required === true) {
          changes.push({
            kind: "added-required-request-parameter",
            location: `${location} -> ${key}`,
            message: `Required parameter ${currParam.name} (${currParam.in}) was added to ${location}`,
          });
        }
      }

      // Request body required properties
      const baseRequestSchema =
        baseOp.requestBody?.content?.["application/json"]?.schema;
      const currRequestSchema =
        currOp.requestBody?.content?.["application/json"]?.schema;
      if (currRequestSchema) {
        const baseRequired = new Map<string, string>();
        if (baseRequestSchema) {
          collectRequestBodyRequired(
            baseline as any,
            baseRequestSchema,
            "",
            baseRequired,
            new Set(),
          );
        }
        const currRequired = new Map<string, string>();
        collectRequestBodyRequired(
          current as any,
          currRequestSchema,
          "",
          currRequired,
          new Set(),
        );
        for (const [prop, type] of currRequired) {
          if (!baseRequired.has(prop)) {
            changes.push({
              kind: "added-required-request-body-property",
              location: `${location} -> requestBody -> ${prop}`,
              message: `Required request body property ${prop} (${type}) was added to ${location}`,
            });
          }
        }
      }
    }
  }

  return changes;
}

function parseArgs(): { allowBreakingChanges: boolean; baselineRef?: string } {
  const argv = process.argv.slice(2);
  const options = { allowBreakingChanges: false as boolean, baselineRef: undefined as string | undefined };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--allow-breaking-changes") {
      options.allowBreakingChanges = true;
    } else if (arg === "--baseline" && argv[i + 1]) {
      options.baselineRef = argv[++i];
    } else if (arg.startsWith("--baseline=")) {
      options.baselineRef = arg.substring("--baseline=".length);
    }
  }
  return options;
}

async function validateOpenAPI(
  options: CompareOptions = {},
): Promise<ValidationResult> {
  const result: ValidationResult = {
    valid: true,
    errors: [],
    warnings: [],
    breakingChanges: [],
    stats: {
      endpoints: 0,
      schemas: 0,
      tags: 0,
      securitySchemes: 0,
    },
  };

  try {
    const specPath = join(__dirname, "..", "docs", "openapi.json");

    if (!existsSync(specPath)) {
      console.log("📝 Generating OpenAPI spec first...");
      await generateOpenAPISpec();
    }

    const specContent = readFileSync(specPath, "utf-8");
    const spec: OpenAPIObject = JSON.parse(specContent);

    console.log("\n🔍 Validating OpenAPI Specification\n");

    if (!spec.openapi) {
      result.errors.push("Missing openapi version");
    }
    if (!spec.info) {
      result.errors.push("Missing info object");
    }
    if (!spec.paths) {
      result.errors.push("Missing paths object");
    }

    result.stats.endpoints = Object.keys(spec.paths || {}).length;
    result.stats.schemas = Object.keys(spec.components?.schemas || {}).length;
    result.stats.tags = spec.tags?.length || 0;
    result.stats.securitySchemes = Object.keys(
      spec.components?.securitySchemes || {},
    ).length;

    const requiredTags = ["Health", "Authentication", "Users", "Oracle"];
    const existingTags = (spec.tags || []).map((t: any) => t.name);

    for (const tag of requiredTags) {
      if (!existingTags.includes(tag)) {
        result.warnings.push(`Missing recommended tag: ${tag}`);
      }
    }

    const securitySchemes = spec.components?.securitySchemes || {};
    if (!securitySchemes["JWT-auth"]) {
      result.warnings.push("Missing JWT security scheme (JWT-auth)");
    }
    if (!securitySchemes["api-key"]) {
      result.warnings.push("Missing API key security scheme");
    }

    if (!spec.servers || spec.servers.length === 0) {
      result.warnings.push("No servers defined in spec");
    }

    let undocumentedEndpoints = 0;

    for (const [path, pathItem] of Object.entries(spec.paths || {})) {
      for (const [method, operation] of Object.entries(pathItem as any) as [string, any][]) {
        if (
          ["get", "post", "put", "delete", "patch", "options"].includes(method)
        ) {
          if (!operation.summary) {
            undocumentedEndpoints++;
          }

          if (!operation.responses) {
            result.warnings.push(
              `Missing responses for ${method.toUpperCase()} ${path}`,
            );
          }
        }
      }
    }

    if (undocumentedEndpoints > 0) {
      result.warnings.push(
        `${undocumentedEndpoints} endpoints missing summary documentation`,
      );
    }

    // Breaking change detection against the git baseline
    const baseline = resolveBaselineSpec(options.baselineRef);
    if (baseline) {
      const breakingChanges = detectBreakingChanges(baseline, spec);
      result.breakingChanges = breakingChanges;

      if (breakingChanges.length > 0) {
        console.log(
          `\n⚠ Detected ${breakingChanges.length} breaking API change(s) against baseline:`.replace("b ", "b"),
        );
        for (const change of breakingChanges) {
          console.log(`\n   [🔴] ${change.kind}`);
          console.log(`       📁 Location: ${change.location}`);
          console.log(`       ${change.message}`);
        }

        if (options.allowBreakingChanges) {
          console.log(
            "\n⚠️  --allow-breaking-changes was set; breaking changes will not fail CI.\n" +
              "   Use this only for intentional API major version upgrades.",
          );
        } else {
          result.errors.push(
            `Detected ${breakingChanges.length} breaking API change(s). Run with --allow-breaking-changes to override.`,
          );
          result.valid = false;
        }
      } else {
        console.log("\n✅ No breaking API changes detected against baseline.");
      }
    } else {
      console.log(
        "\nℹ️  No baseline OpenAPI spec found; skipping breaking change detection.",
      );
    }

    console.log("\n📊 Specification Statistics:");
    console.log(`   Endpoints:        ${result.stats.endpoints}`);
    console.log(`   Schemas:          ${result.stats.schemas}`);
    console.log(`   Tags:             ${result.stats.tags}`);
    console.log(`   Security Schemes: ${result.stats.securitySchemes}`);

    
    if (result.errors.length > 0) {
      console.log("\n❌ Validation Errors:");
      for (const message of result.errors) {
        console.log(`   ✖ ${message}`);
      }
      result.valid = false;
    }

    if (result.warnings.length > 0) {
      console.log(`\n⚠️  ${result.warnings.length} warning(s):`);
      for (const message of result.warnings) {
        console.log(`   • ${message}`);
      }
    }

    if (result.valid) {
      console.log(
        result.warnings.length > 0
          ? "\n✅ OpenAPI specification is valid (warnings are advisory)."
          : "\n✅ OpenAPI specification is valid.",
      );
    } else {
      console.log("\n❌ OpenAPI specification validation failed.");
    }
  } catch (error) {
    result.errors.push(`Validation error: ${(error as Error).message}`);
    result.valid = false;
  }

  return result;
}

async function generateOpenAPISpec(): Promise<void> {
  const app = await NestFactory.create(AppModule, {
    logger: false,
    abortOnError: false,
  });

  const config = new DocumentBuilder()
    .setTitle("Trellis Backend API")
    .setDescription(
      "Comprehensive API documentation for Trellis backend services",
    )
    .setVersion("1.0.0")
    .setContact("Trellis Team", "https://trellis.example", "support@trellis.example")
    .setLicense("MIT", "https://opensource.org/licenses/MIT")
    .addServer("http://localhost:3001", "Development Server")
    .addServer("https://api.trellis.example", "Production Server")
    .addBearerAuth(
      {
        type: "http",
        scheme: "bearer",
        bearerFormat: "JWT",
        description: "Enter JWT token",
        in: "header",
      },
      "JWT-auth",
    )
    .addApiKey(
      {
        type: "apiKey",
        name: "X-API-Key",
        in: "header",
        description: "API key for service-to-service communication",
      },
      "api-key",
    )
    .build();

  const document = SwaggerModule.createDocument(app, config, {
    deepScanRoutes: true,
  });

  const { writeFileSync, mkdirSync } = await import("fs");

  const outDir = join(__dirname, "..", "docs");
  mkdirSync(outDir, { recursive: true });

  writeFileSync(
    join(outDir, "openapi.json"),
    JSON.stringify(document, null, 2),
    "utf-8",
  );

  await app.close();
}

async function main(): Promise<void> {
  try {
    const options = parseArgs();
    const result = await validateOpenAPI(options);
    process.exit(result.valid ? 0 : 1);
  } catch (error) {
    console.error("Validation script error:", error);
    process.exit(1);
  }
}

main();

export { validateOpenAPI, generateOpenAPISpec };
export type { ValidationResult };
