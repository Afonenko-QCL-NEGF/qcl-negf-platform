/** Validated deployment intent. Command arguments are never passed through a shell. */
export interface Host {
  name: string;
  flake: string;
  target: string;
}
export interface Inventory {
  hosts: Host[];
}
export type Action = "build" | "test" | "switch";
export interface Command {
  executable: string;
  args: string[];
}
const identifier = /^[a-z][a-z0-9-]{0,62}$/;
const target = /^(?:[a-z_][a-z0-9_-]*@)?[a-zA-Z0-9][a-zA-Z0-9.-]*$/;

export function inventory(value: unknown): Inventory {
  if (!value || typeof value !== "object" || !("hosts" in value) || !Array.isArray(value.hosts)) {
    throw new Error("Inventory must contain a hosts array.");
  }
  const names = new Set<string>();
  const hosts: Host[] = value.hosts.map((item: unknown) => {
    if (!item || typeof item !== "object") throw new Error("Host must be an object.");
    const h = item as Record<string, unknown>;
    if (typeof h.name !== "string" || !identifier.test(h.name) || names.has(h.name)) {
      throw new Error("Host names must be unique DNS labels.");
    }
    if (
      typeof h.flake !== "string" || !h.flake || /\s/.test(h.flake) || h.flake.includes("\u0000") ||
      h.flake.startsWith("-")
    ) {
      throw new Error(
        "Host flake must be a nonempty reference without whitespace or option prefix.",
      );
    }
    if (h.flake.includes("#")) {
      throw new Error("Flake reference must not contain an output selector.");
    }
    if (typeof h.target !== "string" || !target.test(h.target)) {
      throw new Error("Target must be an SSH hostname, optionally prefixed by a user.");
    }
    names.add(h.name);
    return { name: h.name, flake: h.flake, target: h.target };
  });
  if (!hosts.length) throw new Error("Inventory must have at least one host.");
  return { hosts };
}

export function deployPlan(host: Host, action: Action): Command[] {
  const selector = `${host.flake}#${host.name}`;
  if (action === "build") {
    return [{
      executable: "nix",
      args: [
        "build",
        "--no-link",
        `${host.flake}#nixosConfigurations.${host.name}.config.system.build.toplevel`,
      ],
    }];
  }
  return [{
    executable: "nixos-rebuild",
    args: [action, "--flake", selector, "--target-host", host.target, "--sudo"],
  }];
}

export function installPlan(host: Host, root: string): Command[] {
  if (
    !root.startsWith("/") || root === "/" || root.includes("\u0000") ||
    root.split("/").some((part, index) => index > 0 && ["", ".", ".."].includes(part))
  ) {
    throw new Error("Install root must be an absolute mounted target directory other than /.");
  }
  return [{
    executable: "nixos-install",
    args: ["--flake", `${host.flake}#${host.name}`, "--root", root, "--no-root-password"],
  }];
}

export function commandDisplay(c: Command): string {
  return [c.executable, ...c.args].map((arg) => JSON.stringify(arg)).join(" ");
}
