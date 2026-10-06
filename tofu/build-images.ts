/** Build private-site images and attach their actual hashes to provider input files. */
export const roles = ["storage", "control", "compute", "ci", "arch-worker"] as const;
export function imageRoles(archFile: string): readonly (typeof roles)[number][] {
  return archFile === "-" ? roles.filter((role) => role !== "arch-worker") : roles;
}
export function validateBase(primary: unknown, arch: unknown, includeArch = true): {
  primary: Record<string, unknown> & { vms: Record<string, Record<string, unknown>> };
  arch: Record<string, unknown>;
} {
  if (
    !primary || typeof primary !== "object" ||
    (includeArch && (!arch || typeof arch !== "object"))
  ) {
    throw new Error("Site input files must contain JSON objects.");
  }
  const p = primary as Record<string, unknown>;
  if (
    !p.vms || typeof p.vms !== "object" ||
    Object.keys(p.vms).sort().join() !== ["ci", "compute", "control", "storage"].join()
  ) throw new Error("Proxmox inputs must contain the four VM role objects.");
  for (const vm of Object.values(p.vms)) {
    if (!vm || typeof vm !== "object" || Array.isArray(vm)) throw new Error("Invalid VM object.");
  }
  return {
    primary: p as Record<string, unknown> & { vms: Record<string, Record<string, unknown>> },
    arch: includeArch ? arch as Record<string, unknown> : {},
  };
}
type NixCommand = (args: string[]) => Promise<string>;
const derivation = /^\/nix\/store\/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._-]+[.]drv$/;
const nginxTarget = /^\/nix\/store\/[0-9abcdfghijklmnpqrsvwxyz]{32}-nginx[.]conf[.]drv\^out$/;
const nginxQuery = `c: let context = builtins.getContext (if c.services.nginx.enableReload
    then toString c.environment.etc."nginx/nginx.conf".source
    else c.systemd.services.nginx.serviceConfig.ExecStart);
  paths = builtins.filter (p: builtins.match ".*-nginx[.]conf[.]drv" p != null) (builtins.attrNames context);
  in { enabled = c.services.nginx.enable; validated = c.services.nginx.validateConfigFile;
    executable = "\${c.services.nginx.package}/bin/nginx";
    exec_start = c.systemd.services.nginx.serviceConfig.ExecStart;
    reload = c.services.nginx.enableReload;
    config_file = if c.services.nginx.enableReload then toString c.environment.etc."nginx/nginx.conf".source else null;
    targets = map (p: assert context.\${p}.outputs == [ "out" ]; p + "^out") paths; }`;

type NativePreflight = {
  schema: string;
  operation: string;
  status: string;
  configuration: {
    roles: Record<string, string>;
    nginx: {
      targets: string[];
      executable: string;
      exec_start: string;
      reload: boolean;
      config_file: string | null;
    };
  };
  nginx_build: { exit_code: number; failure: unknown; stdout: string };
  nginx_actual_config: {
    path: string;
    sha256: string;
    test_sha256: string;
    executable: string;
    exec_start: string;
  };
  nginx_test: { exit_code: number; failure: unknown; stdout: string; stderr: string };
  nginx_severity_counters: Record<string, number>;
};

function nativePreflight(value: unknown): NativePreflight {
  const receipt = value as NativePreflight;
  const test = receipt?.nginx_test;
  const counters = receipt?.nginx_severity_counters;
  const actual = receipt?.nginx_actual_config;
  const roles = receipt?.configuration?.roles;
  if (
    receipt?.schema !== "qcl.bootstrap-preflight.v1" || receipt.operation !== "preflight" ||
    receipt.status !== "pass" ||
    !roles || Object.keys(roles).sort().join() !== "ci,compute,control,storage" ||
    !Object.values(roles).every((path) => typeof path === "string" && derivation.test(path)) ||
    test?.exit_code !== 0 || test.failure !== null || typeof test.stdout !== "string" ||
    typeof test.stderr !== "string" ||
    !counters || Object.keys(counters).sort().join() !== "alert,crit,emerg,error,warn" ||
    !Object.values(counters).every((count) => count === 0) ||
    receipt.nginx_build?.exit_code !== 0 || receipt.nginx_build.failure !== null ||
    typeof receipt.nginx_build.stdout !== "string" ||
    !actual || !/^[0-9a-f]{64}$/.test(actual.sha256) || !/^[0-9a-f]{64}$/.test(actual.test_sha256)
  ) throw new Error("A passed actual nginx preflight receipt is required before images.");
  const output = test.stdout + test.stderr;
  if (
    !output.includes("syntax is ok") || !output.includes("test is successful") ||
    /\[(warn|error|crit|alert|emerg)\]/.test(output)
  ) {
    throw new Error("Preflight receipt lacks a strict successful native nginx test.");
  }
  return receipt;
}

/** All configuration gates finish before any image callback. Flake URIs remain supported. */
export async function imageStages(
  site: string,
  archFile: string,
  command: NixCommand,
  image: (role: (typeof roles)[number]) => Promise<void>,
  preflightReceipt?: unknown,
): Promise<void> {
  const receipt = nativePreflight(preflightReceipt);
  for (const role of imageRoles("-")) {
    const drv = await command([
      "eval",
      "--raw",
      "--no-write-lock-file",
      `${site}#nixosConfigurations.${role}.config.system.build.toplevel.drvPath`,
    ]);
    if (!derivation.test(drv)) throw new Error(`Invalid evaluated derivation for ${role}.`);
    if (receipt.configuration.roles[role] !== drv) {
      throw new Error(`Preflight receipt has a different derivation for ${role}.`);
    }
  }
  const config = JSON.parse(
    await command([
      "eval",
      "--json",
      "--no-write-lock-file",
      `${site}#nixosConfigurations.control.config`,
      "--apply",
      nginxQuery,
    ]),
  );
  if (
    config?.enabled !== true || config?.validated !== true ||
    !Array.isArray(config.targets) || config.targets.length !== 1 ||
    typeof config.targets[0] !== "string" || !nginxTarget.test(config.targets[0])
  ) {
    throw new Error("One strict validated nginx.conf writer required before images.");
  }
  const recorded = receipt.configuration.nginx;
  const actual = receipt.nginx_actual_config;
  const outputs = JSON.parse(receipt.nginx_build.stdout);
  const match = typeof config.exec_start === "string"
    ? config.exec_start.match(/^([^ ]+) -c '?([^' ]+)'?$/)
    : null;
  if (
    recorded?.targets?.length !== 1 || recorded.targets[0] !== config.targets[0] ||
    recorded.executable !== config.executable || recorded.exec_start !== config.exec_start ||
    recorded.reload !== config.reload || recorded.config_file !== config.config_file ||
    actual.executable !== config.executable || actual.exec_start !== config.exec_start ||
    !match || match[1] !== config.executable ||
    actual.path !== (config.reload === true ? config.config_file : match[2]) ||
    (config.reload === true && match[2] !== "/etc/nginx/nginx.conf") ||
    !/^\/nix\/store\/[0-9abcdfghijklmnpqrsvwxyz]{32}-nginx[.]conf$/.test(actual.path) ||
    !Array.isArray(outputs) || outputs.length !== 1 ||
    outputs[0]?.drvPath !== config.targets[0].replace(/\^out$/, "") ||
    Object.keys(outputs[0]?.outputs ?? {}).join() !== "out" ||
    outputs[0].outputs.out !== actual.path
  ) throw new Error("Actual evaluated nginx config differs from the native preflight receipt.");
  const digest = await command(["hash", "file", "--type", "sha256", "--base16", actual.path]);
  if (!/^[0-9a-f]{64}$/.test(digest) || digest !== actual.sha256) {
    throw new Error("Actual nginx config hash differs from its preflight receipt.");
  }
  for (const role of imageRoles(archFile)) await image(role);
}

async function nix(args: string[]): Promise<string> {
  const result = await new Deno.Command("nix", { args, stdout: "piped", stderr: "inherit" })
    .output();
  if (!result.success) throw new Error(`nix exited ${result.code}`);
  return new TextDecoder().decode(result.stdout).trim();
}
export async function main(args: string[]): Promise<void> {
  const [site, primaryFile, archFile, outputDirectory, receiptFlag, receiptFile] = args;
  if (
    !site || !primaryFile || !archFile || !outputDirectory || args.length !== 6 ||
    receiptFlag !== "--preflight-receipt" || !receiptFile ||
    site.startsWith("-") || site.includes("#")
  ) {
    throw new Error(
      "Usage: build-images.ts SITE_FLAKE PROXMOX_BASE.json ARCH_BASE.json|- OUTPUT_DIRECTORY --preflight-receipt ACTUAL_PREFLIGHT.json",
    );
  }
  const receiptInfo = await Deno.lstat(receiptFile);
  if (!receiptInfo.isFile || receiptInfo.size > 8 * 1024 * 1024) {
    throw new Error("Preflight receipt must be a bounded regular JSON file.");
  }
  const preflight = nativePreflight(JSON.parse(await Deno.readTextFile(receiptFile)));
  const base = validateBase(
    JSON.parse(await Deno.readTextFile(primaryFile)),
    archFile === "-" ? null : JSON.parse(await Deno.readTextFile(archFile)),
    archFile !== "-",
  );
  const artifacts: Record<
    string,
    { image_path: string; image_sha256: string; image_bytes: number }
  > = {};
  await imageStages(site, archFile, nix, async (role) => {
    const built = JSON.parse(
      await nix(["build", "--no-link", "--json", `${site}#${role}-image`]),
    ) as { outputs?: { out?: string } }[];
    const output = built[0]?.outputs?.out;
    if (built.length !== 1 || !output?.startsWith("/nix/store/")) {
      throw new Error("Unexpected image build result.");
    }
    const images = [];
    for await (const entry of Deno.readDir(output)) {
      if (entry.isFile && entry.name.endsWith(".qcow2")) images.push(`${output}/${entry.name}`);
    }
    if (images.length !== 1) throw new Error(`Expected one QCOW2 for ${role}.`);
    const image_path = images[0]!;
    const image_sha256 = await nix(["hash", "file", "--type", "sha256", "--base16", image_path]);
    if (!/^[0-9a-f]{64}$/.test(image_sha256)) throw new Error("Invalid image digest.");
    const image_bytes = (await Deno.stat(image_path)).size;
    if (!Number.isSafeInteger(image_bytes) || image_bytes < 72) {
      throw new Error("Invalid measured image byte count.");
    }
    artifacts[role] = { image_path, image_sha256, image_bytes };
    if (role === "arch-worker") Object.assign(base.arch, artifacts[role]);
    else Object.assign(base.primary.vms[role]!, artifacts[role]);
  }, preflight);
  await Deno.mkdir(outputDirectory, { recursive: true });
  const outputs: [string, unknown][] = [
    ["proxmox.tfvars.json", base.primary],
    ["images.json", artifacts],
  ];
  if (archFile !== "-") outputs.push(["arch-libvirt.tfvars.json", base.arch]);
  for (const [file, value] of outputs) {
    await Deno.writeTextFile(`${outputDirectory}/${file}`, `${JSON.stringify(value, null, 2)}\n`, {
      mode: 0o600,
    });
  }
}
if (import.meta.main) {
  try {
    await main(Deno.args);
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    Deno.exit(1);
  }
}
