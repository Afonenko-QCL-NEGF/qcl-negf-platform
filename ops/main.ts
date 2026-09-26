import { type Command, commandDisplay, deployPlan, installPlan, inventory } from "./plan.ts";

async function execute(plan: Command[], apply: boolean): Promise<void> {
  for (const command of plan) {
    console.log(commandDisplay(command));
    if (apply) {
      const result = await new Deno.Command(command.executable, {
        args: command.args,
        stdin: "inherit",
        stdout: "inherit",
        stderr: "inherit",
      }).spawn().status;
      if (!result.success) throw new Error(`${command.executable} exited ${result.code}`);
    }
  }
}

export async function main(args: string[]): Promise<void> {
  const [operation, file, name, ...flags] = args;
  if (!operation || !file || !name || !["build", "test", "switch", "install"].includes(operation)) {
    throw new Error(
      "Usage: deno task ops build|test|switch|install INVENTORY HOST [--apply] [--root /mnt]",
    );
  }
  let apply = false;
  let root: string | undefined;
  for (let i = 0; i < flags.length; i++) {
    const flag = flags[i];
    if (flag === "--apply") apply = true;
    else if (flag === "--root") root = flags[++i];
    else throw new Error(`Unknown argument: ${flag}`);
  }
  const configured = inventory(JSON.parse(await Deno.readTextFile(file)));
  const host = configured.hosts.find((h) => h.name === name);
  if (!host) throw new Error(`Unknown host: ${name}`);
  if (operation === "install") {
    if (!root) throw new Error("Install needs --root pointing to the mounted target root.");
    const plan = installPlan(host, root);
    if (apply) {
      const real = await Deno.realPath(root);
      if (real === "/") throw new Error("Refusing to install onto the running root filesystem.");
      const mountinfo = await Deno.readTextFile("/proc/self/mountinfo");
      const mounts = mountinfo.split("\n").map((line) => line.split(" ")[4]);
      const encoded = real.replaceAll("\\", "\\134").replaceAll(" ", "\\040").replaceAll(
        "\t",
        "\\011",
      ).replaceAll("\n", "\\012");
      if (!mounts.includes(encoded)) {
        throw new Error("Install root must be an existing mount point.");
      }
    }
    await execute(plan, apply);
  } else {
    if (root) throw new Error("--root is only valid for install.");
    await execute(deployPlan(host, operation as "build" | "test" | "switch"), apply);
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
