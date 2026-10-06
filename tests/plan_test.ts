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

Deno.test("bootstrap registers the immutable installed code as part of recovery", async () => {
  const { bootstrapPlan } = await import("../ops/bootstrap.ts");
  rejects(() => bootstrapPlan("invalid"));
  const plan = bootstrapPlan("research@example.org", "/nix/store/example/bin/qcl-negf");
  assert(plan.length === 2);
  assert(plan[0]!.args[0]!.endsWith("/bootstrap_profile.py"));
  assert(plan[0]!.args.includes("research@example.org"));
  assert(plan[1]!.args.includes("run"));
  assert(plan[1]!.args.includes("/nix/store/example/bin/qcl-negf"));
  rejects(() => bootstrapPlan("research@example.org", "/run/current-system/sw/bin/qcl-negf"));
});

Deno.test("existing profile permits recovery only for the same local storage contract", async () => {
  const { profileSetupRequired } = await import("../ops/bootstrap.ts");
  assert(profileSetupRequired({ profiles: {} }));
  rejects(() => profileSetupRequired(null));
  const profile = {
    storage: {
      backend: "core.psql_dos",
      config: {
        database_hostname: "/run/postgresql",
        database_port: 5432,
        database_username: "qcl-negf",
        database_password: "",
        database_name: "qcl-negf",
        repository_uri: "file:///var/lib/qcl-negf/aiida/repository",
      },
    },
    process_control: { backend: "core.zeromq" },
  };
  assert(profileSetupRequired({ profiles: { "qcl-negf": profile } }));
  profile.storage.config.repository_uri = "file:///different/repository";
  rejects(() => profileSetupRequired({ profiles: { "qcl-negf": profile } }));
});
