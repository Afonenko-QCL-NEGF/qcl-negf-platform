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
async function nix(args: string[]): Promise<string> {
  const result = await new Deno.Command("nix", { args, stdout: "piped", stderr: "inherit" })
    .output();
  if (!result.success) throw new Error(`nix exited ${result.code}`);
  return new TextDecoder().decode(result.stdout).trim();
}
export async function main(args: string[]): Promise<void> {
  const [site, primaryFile, archFile, outputDirectory] = args;
  if (
    !site || !primaryFile || !archFile || !outputDirectory || args.length !== 4 ||
    site.startsWith("-") || site.includes("#")
  ) {
    throw new Error(
      "Usage: build-images.ts SITE_FLAKE PROXMOX_BASE.json ARCH_BASE.json|- OUTPUT_DIRECTORY",
    );
  }
  const base = validateBase(
    JSON.parse(await Deno.readTextFile(primaryFile)),
    archFile === "-" ? null : JSON.parse(await Deno.readTextFile(archFile)),
    archFile !== "-",
  );
  const artifacts: Record<string, { image_path: string; image_sha256: string }> = {};
  for (const role of imageRoles(archFile)) {
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
    artifacts[role] = { image_path, image_sha256 };
    if (role === "arch-worker") Object.assign(base.arch, artifacts[role]);
    else Object.assign(base.primary.vms[role]!, artifacts[role]);
  }
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
