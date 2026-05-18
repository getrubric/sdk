// Platform dispatcher for service installation.
//
// macOS → launchd LaunchAgent
// Linux → systemd --user unit
// other → null (caller falls back to detached spawn, which doesn't
//         survive reboot but does survive terminal close)

import * as os from 'node:os';

import type { Paths } from '../paths.js';

import {
  buildLaunchdService,
  installLaunchdService,
  uninstallLaunchdService,
  LAUNCHD_LABEL,
} from './launchd.js';
import {
  buildSystemdService,
  installSystemdService,
  uninstallSystemdService,
  SYSTEMD_UNIT_NAME,
} from './systemd.js';

export type ServicePlatform = 'launchd' | 'systemd' | 'unsupported';

export interface ServiceInstallOptions {
  paths: Paths;
  nodeBinary: string;
  cliEntry: string;
  /** Override platform — used by tests. */
  platform?: NodeJS.Platform;
  /** Override $HOME — used by tests. */
  home?: string;
}

export interface ServiceInstallResult {
  platform: ServicePlatform;
  loaded: boolean;
  message: string;
  /** Absolute path of the file that was written, if any. */
  filePath?: string;
}

export async function installService(
  options: ServiceInstallOptions,
): Promise<ServiceInstallResult> {
  const home = options.home ?? os.homedir();
  const platform = options.platform ?? process.platform;

  if (platform === 'darwin') {
    const spec = buildLaunchdService({
      paths: options.paths,
      nodeBinary: options.nodeBinary,
      cliEntry: options.cliEntry,
      home,
    });
    const result = await installLaunchdService(spec);
    return {
      platform: 'launchd',
      loaded: result.loaded,
      message: result.message,
      filePath: spec.plistPath,
    };
  }

  if (platform === 'linux') {
    const spec = buildSystemdService({
      paths: options.paths,
      nodeBinary: options.nodeBinary,
      cliEntry: options.cliEntry,
      home,
    });
    const result = await installSystemdService(spec);
    return {
      platform: 'systemd',
      loaded: result.loaded,
      message: result.message,
      filePath: spec.unitPath,
    };
  }

  return {
    platform: 'unsupported',
    loaded: false,
    message: `no service manager known for platform '${platform}' — daemon will run as a detached child`,
  };
}

export async function uninstallService(
  options: {
    paths: Paths;
    platform?: NodeJS.Platform;
    home?: string;
  },
): Promise<ServiceInstallResult> {
  const home = options.home ?? os.homedir();
  const platform = options.platform ?? process.platform;

  if (platform === 'darwin') {
    const { plistPath } = buildLaunchdService({
      paths: options.paths,
      // Build inputs that go into the file aren't needed for unload —
      // only the path. Empty strings here are fine.
      nodeBinary: '',
      cliEntry: '',
      home,
    });
    const result = await uninstallLaunchdService(plistPath, LAUNCHD_LABEL);
    return {
      platform: 'launchd',
      loaded: false,
      message: result.message,
      filePath: plistPath,
    };
  }

  if (platform === 'linux') {
    const { unitPath } = buildSystemdService({
      paths: options.paths,
      nodeBinary: '',
      cliEntry: '',
      home,
    });
    const result = await uninstallSystemdService(unitPath, SYSTEMD_UNIT_NAME);
    return {
      platform: 'systemd',
      loaded: false,
      message: result.message,
      filePath: unitPath,
    };
  }

  return {
    platform: 'unsupported',
    loaded: false,
    message: `no service manager known for platform '${platform}'`,
  };
}

export { buildLaunchdService, LAUNCHD_LABEL } from './launchd.js';
export { buildSystemdService, SYSTEMD_UNIT_NAME } from './systemd.js';
