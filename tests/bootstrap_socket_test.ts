import { bootstrapPlan, profileSetupRequired } from "../ops/bootstrap.ts";

Deno.test("cold bootstrap uses the declared Python before a database profile exists", () => {
  const plan = bootstrapPlan("research@example.org", "/nix/store/example/bin/qcl-negf");
  if (plan[0]?.executable !== "/nix/var/nix/profiles/qcl-negf-application/bin/python") {
    throw new Error("AiiDA's profile CLI loses the supported socket connect_args");
  }
  if (!plan[0].args[0]?.endsWith("/bootstrap_profile.py")) throw new Error("Missing helper");
});

Deno.test("warm bootstrap reconciles a legacy raw socket profile before registering Code", () => {
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
  if (!profileSetupRequired({ profiles: { "qcl-negf": profile } })) {
    throw new Error("Legacy socket profiles still need connection configuration reconciliation");
  }
});
