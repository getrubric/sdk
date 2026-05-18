// RFC 9457 (Problem Details for HTTP APIs) types + SDK error classes.
//
// The Rubric API returns errors as `application/problem+json` per RFC
// 9457. The SDK parses those bodies into a typed `ProblemDetails` and
// throws `GovernanceProblemError` so callers can branch on
// `problem.type` instead of parsing strings.

import { z } from 'zod';

import { CONTENT_TYPE_PROBLEM_JSON, HTTP_HEADER_CONTENT_TYPE } from './constants.js';

// Standard RFC 9457 members are typed; extension members are
// preserved via `.passthrough()`.
export const ProblemDetailsSchema = z
  .object({
    type: z.string(),
    title: z.string(),
    status: z.number().int(),
    detail: z.string().nullable().optional(),
    instance: z.string().nullable().optional(),
  })
  .passthrough();
export type ProblemDetails = z.infer<typeof ProblemDetailsSchema>;

export class GovernanceError extends Error {
  // Keep `name` set to the actual class name in derived errors so
  // `instanceof` works after structured-clone / cross-realm boundaries
  // (rare for our case, but cheap insurance).
  override name = 'GovernanceError';
}

export class GovernanceProblemError extends GovernanceError {
  override name = 'GovernanceProblemError';
  readonly problem: ProblemDetails;

  constructor(problem: ProblemDetails) {
    super(`${problem.title} (${problem.status}): ${problem.detail ?? ''}`);
    this.problem = problem;
  }
}

export class IdentityRevokedError extends GovernanceError {
  override name = 'IdentityRevokedError';
}

export class IdentityNotInitializedError extends GovernanceError {
  override name = 'IdentityNotInitializedError';
}

/**
 * Best-effort parse of a `fetch` Response body as a ProblemDetails object.
 *
 * Returns null when the response isn't `application/problem+json` or the body
 * can't be parsed; the caller decides how to surface the underlying failure.
 *
 * Consumes the response body — call this only when you've decided you're done
 * with the original response. Callers that may want either path should
 * `response.clone()` first.
 */
export async function parseProblemDetails(response: Response): Promise<ProblemDetails | null> {
  const contentType = response.headers.get(HTTP_HEADER_CONTENT_TYPE) ?? '';
  if (!contentType.startsWith(CONTENT_TYPE_PROBLEM_JSON)) return null;
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return null;
  }
  const parsed = ProblemDetailsSchema.safeParse(payload);
  return parsed.success ? parsed.data : null;
}
