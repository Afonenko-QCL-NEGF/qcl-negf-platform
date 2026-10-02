/** Reconcile the local profile and installed solver without replacing provenance. */
import { type Command, commandDisplay } from "./plan.ts";

const storage = {
  database_hostname: "/run/postgresql",
  database_port: 5432,
  database_username: "qcl-negf",
  database_password: "",
  database_name: "qcl-negf",
  repository_uri: "file:///var/lib/qcl-negf/aiida/repository",
};

export function profileSetupRequired(value: unknown): boolean {
  if (!value || typeof value !== "object" || !("profiles" in value)) {
    throw new Error("Invalid existing AiiDA configuration; inspect it before bootstrap.");
  }
  const profiles = value.profiles as Record<string, unknown>;
  const profile = profiles["qcl-negf"] as {
    storage?: { backend?: string; config?: Record<string, unknown> };
    process_control?: { backend?: string };
  } | undefined;
  if (!profile) return true;
  if (
    profile.storage?.backend !== "core.psql_dos" ||
    profile.process_control?.backend !== "core.zeromq" ||
    Object.entries(storage).some(([key, expected]) => profile.storage?.config?.[key] !== expected)
  ) {
    throw new Error("Existing qcl-negf profile differs from the declared local storage/broker.");
  }
  return false;
}

export function bootstrapPlan(
  email: string,
  solverExecutable?: string,
  codeLabel = "qcl-negf",
): Command[] {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new Error("Provide an AiiDA service email address.");
  }
  if (!solverExecutable || !/^\/nix\/store\/[^\s/]+\/bin\/qcl-negf$/.test(solverExecutable)) {
    throw new Error("Provide the immutable /nix/store/.../bin/qcl-negf executable.");
  }
  if (!/^[a-z][a-z0-9._-]{0,127}$/.test(codeLabel)) {
    throw new Error("Provide a stable installed Code label; use a new label for a new solver.");
  }
  return [{
    executable: "verdi",
    args: [
      "profile",
      "setup",
      "core.psql_dos",
      "--non-interactive",
      "--profile-name",
      "qcl-negf",
      "--set-as-default",
      "--email",
      email,
      "--first-name",
      "Research",
      "--last-name",
      "Service",
      "--institution",
      "QCL-NEGF",
      "--broker",
      "core.zeromq",
      "--database-hostname",
      "/run/postgresql",
      "--database-port",
      "5432",
      "--database-username",
      "qcl-negf",
      "--database-password",
      "",
      "--database-name",
      "qcl-negf",
      "--repository-uri",
      "file:///var/lib/qcl-negf/aiida/repository",
    ],
  }, {
    executable: "verdi",
    args: [
      "-p",
      "qcl-negf",
      "run",
      decodeURIComponent(new URL("./register_aiida.py", import.meta.url).pathname),
      "--",
      email,
      solverExecutable,
      codeLabel,
    ],
  }];
}

if (import.meta.main) {
  try {
    const [email, solver, ...flags] = Deno.args;
    let apply = false;
    let label = "qcl-negf";
    for (let i = 0; i < flags.length; i++) {
      if (flags[i] === "--apply") apply = true;
      else if (flags[i] === "--label" && flags[i + 1]) label = flags[++i]!;
      else throw new Error(`Unknown bootstrap argument: ${flags[i]}`);
    }
    if (!email || !solver) {
      throw new Error(
        "Usage: bootstrap.ts EMAIL /nix/store/.../bin/qcl-negf [--label LABEL] [--apply]",
      );
    }
    let plan = bootstrapPlan(email, solver, label);
    if (apply) {
      const owner = (await Deno.stat("/var/lib/qcl-negf")).uid;
      if (Deno.uid() === 0 || Deno.uid() !== owner) {
        throw new Error("Run bootstrap as the qcl-negf service account, not root.");
      }
      try {
        const existing = JSON.parse(await Deno.readTextFile("/var/lib/qcl-negf/aiida/config.json"));
        if (!profileSetupRequired(existing)) plan = plan.slice(1);
      } catch (error) {
        if (!(error instanceof Deno.errors.NotFound)) throw error;
      }
    }
    for (const command of plan) {
      console.log(commandDisplay(command));
      if (apply) {
        const result = await new Deno.Command(command.executable, {
          args: command.args,
          env: { AIIDA_PATH: "/var/lib/qcl-negf/aiida" },
          stdout: "inherit",
          stderr: "inherit",
        }).spawn().status;
        if (!result.success) throw new Error(`verdi exited ${result.code}`);
      }
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    Deno.exit(1);
  }
}
