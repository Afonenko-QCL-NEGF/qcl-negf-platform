import { deployPlan, installPlan, inventory } from "../ops/plan.ts";
function assert(condition: boolean): asserts condition {
  if (!condition) throw new Error("Assertion failed");
}
function rejects(fn: () => unknown) {
  let failed = false;
  try {
    fn();
  } catch {
    failed = true;
  }
  assert(failed);
}
const host = { name: "control", target: "deploy@control", flake: "." };
Deno.test("target and output selectors cannot inject executable options", () => {
  for (
    const h of [{ ...host, target: "-oProxyCommand=bad" }, { ...host, name: "control;false" }, {
      ...host,
      flake: "--impure",
    }, { ...host, flake: ".#wrong" }]
  ) rejects(() => inventory({ hosts: [h] }));
});
Deno.test("duplicate names and invalid shapes fail closed", () => {
  for (const value of [null, {}, { hosts: [] }, { hosts: [host, host] }]) {
    rejects(() => inventory(value));
  }
});
Deno.test("build does not contact target or activate configuration", () => {
  const plan = deployPlan(inventory({ hosts: [host] }).hosts[0]!, "build");
  assert(plan.length === 1 && plan[0]!.executable === "nix");
  assert(plan[0]!.args.includes(".#nixosConfigurations.control.config.system.build.toplevel"));
  assert(!plan[0]!.args.includes(host.target));
});
Deno.test("activation uses upstream nixos-rebuild with argument vector", () => {
  const plan = deployPlan(host, "test");
  assert(plan[0]!.executable === "nixos-rebuild");
  assert(
    JSON.stringify(plan[0]!.args) ===
      JSON.stringify(["test", "--flake", ".#control", "--target-host", "deploy@control", "--sudo"]),
  );
});
Deno.test("clean installation requires a separate mounted root", () => {
  for (const root of ["/", "/.", "//", "/mnt/..", "/mnt/../."]) {
    rejects(() => installPlan(host, root));
  }
  rejects(() => installPlan(host, "mnt"));
  assert(installPlan(host, "/mnt")[0]!.args.includes("--no-root-password"));
});

Deno.test("bootstrap pins local Slurm and peer-authenticated PostgreSQL", async () => {
  const { bootstrapPlan } = await import("../ops/bootstrap.ts");
  rejects(() => bootstrapPlan("invalid"));
  const plan = bootstrapPlan("research@example.org");
  assert(plan.length === 3);
  assert(plan[0]!.args.includes("core.zeromq"));
  assert(plan[0]!.args.includes("/run/postgresql"));
  assert(plan[1]!.args.includes("core.slurm") && plan[1]!.args.includes("core.local"));
});
