/** One-time AiiDA profile setup on the controller, as its service account. */
import { type Command, commandDisplay } from "./plan.ts";

export function bootstrapPlan(email: string): Command[] {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new Error("Provide an AiiDA service email address.");
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
      "computer",
      "setup",
      "--non-interactive",
      "--label",
      "slurm",
      "--hostname",
      "localhost",
      "--transport",
      "core.local",
      "--scheduler",
      "core.slurm",
      "--work-dir",
      "/srv/qcl-negf/jobs",
      "--mpiprocs-per-machine",
      "1",
    ],
  }, {
    executable: "verdi",
    args: ["-p", "qcl-negf", "computer", "configure", "core.local", "slurm", "--non-interactive"],
  }];
}

if (import.meta.main) {
  try {
    const [email, flag] = Deno.args;
    if (!email || (flag !== undefined && flag !== "--apply")) {
      throw new Error("Usage: bootstrap.ts EMAIL [--apply]");
    }
    const plan = bootstrapPlan(email);
    if (flag === "--apply") {
      const owner = (await Deno.stat("/var/lib/qcl-negf")).uid;
      if (Deno.uid() === 0 || Deno.uid() !== owner) {
        throw new Error("Run bootstrap as the qcl-negf service account, not root.");
      }
      try {
        await Deno.stat("/var/lib/qcl-negf/aiida/config.json");
        throw new Error("AiiDA is already configured; inspect it using verdi.");
      } catch (error) {
        if (!(error instanceof Deno.errors.NotFound)) throw error;
      }
    }
    for (const command of plan) {
      console.log(commandDisplay(command));
      if (flag === "--apply") {
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
