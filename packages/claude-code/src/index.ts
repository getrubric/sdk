// `@rubric/claude-code` — Claude Code hook adapter.
//
// Public library surface. The actual binary is `cli/index.ts` (see
// `bin` in package.json); this file is for programmatic consumers.
//
// Subpackages:
//   cli/       — commander entry, `rubric init/doctor/start/...`
//   daemon/    — node:http server, hook handlers, lifecycle
//   config/    — paths, settings.json patcher, launchd/systemd writers

export * from './daemon/index.js';
export { defaultPaths } from './config/paths.js';
export type { Paths } from './config/paths.js';
