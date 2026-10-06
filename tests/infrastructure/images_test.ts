import { imageRoles, imageStages, main, roles, validateBase } from "../../tofu/build-images.ts";
const configPath = "/nix/store/cccccccccccccccccccccccccccccccc-nginx.conf";
const nginxExecutable = "/nix/store/dddddddddddddddddddddddddddddddd-nginx/bin/nginx";
const configHash = "1".repeat(64);
function nativeReceipt() {
  return {
    schema: "qcl.bootstrap-preflight.v1",
    operation: "preflight",
    status: "pass",
    configuration: {
      roles: Object.fromEntries(
        imageRoles("-").map((
          role,
        ) => [role, "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system.drv"]),
      ),
      nginx: {
        enabled: true,
        validated: true,
        targets: ["/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nginx.conf.drv^out"],
        executable: nginxExecutable,
        exec_start: `${nginxExecutable} -c '${configPath}'`,
        reload: false,
        config_file: null,
      },
    },
    nginx_build: {
      exit_code: 0,
      failure: null,
      stdout: JSON.stringify([{
        drvPath: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nginx.conf.drv",
        outputs: { out: configPath },
      }]),
    },
    nginx_actual_config: {
      path: configPath,
      sha256: configHash,
      test_sha256: "2".repeat(64),
      executable: nginxExecutable,
      exec_start: `${nginxExecutable} -c '${configPath}'`,
    },
    nginx_test: {
      exit_code: 0,
      failure: null,
      stdout: "",
      stderr:
        "nginx: configuration file syntax is ok\nnginx: configuration file test is successful\n",
    },
    nginx_severity_counters: { warn: 0, error: 0, crit: 0, alert: 0, emerg: 0 },
  };
}
function nativeCommand(args: string[]) {
  return Promise.resolve(
    args.includes("--raw")
      ? "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system.drv"
      : args[0] === "eval"
      ? JSON.stringify(nativeReceipt().configuration.nginx)
      : args[0] === "hash"
      ? configHash
      : "[]",
  );
}
function rejects(fn: () => unknown) {
  let failed = false;
  try {
    fn();
  } catch {
    failed = true;
  }
  if (!failed) throw new Error("Expected rejection");
}
Deno.test("image inputs require all four Proxmox role objects", () => {
  const vms = Object.fromEntries(
    roles.filter((name) => name !== "arch-worker").map((name) => [name, { vm_id: 1 }]),
  );
  if (!validateBase({ vms }, {}).primary.vms.storage) throw new Error("Missing storage");
  rejects(() => validateBase({ vms: { control: {} } }, {}));
  rejects(() => validateBase({ vms: { ...vms, storage: null } }, {}));
  rejects(() => validateBase(null, {}));
});
Deno.test("single-server image build excludes the optional Arch worker", () => {
  if (imageRoles("-").join() !== "storage,control,compute,ci") {
    throw new Error("Single-server builds must only build the four Proxmox roles");
  }
  if (imageRoles("arch.json").join() !== roles.join()) throw new Error("Default roles changed");
  const vms = Object.fromEntries(imageRoles("-").map((name) => [name, {}]));
  validateBase({ vms }, null, false);
  rejects(() => validateBase({ vms }, null));
});

Deno.test("all roles and strict nginx pass before the first image stage", async () => {
  const module = await import("../../tofu/build-images.ts");
  const stages: string[] = [];
  const images: string[] = [];
  const command = async (args: string[]) => {
    await Promise.resolve();
    stages.push(args.join(" "));
    if (args[0] === "eval" && args.includes("--raw")) {
      return "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system.drv";
    }
    if (args[0] === "eval") {
      return JSON.stringify(nativeReceipt().configuration.nginx);
    }
    return args[0] === "hash" ? configHash : "[]";
  };
  await (module.imageStages as unknown as (...args: unknown[]) => Promise<void>)(
    "git+https://example.org/site?rev=abc",
    "-",
    command,
    async (role: string) => {
      await Promise.resolve();
      if (stages.length !== 6) throw new Error("Image stage preceded complete preflight");
      images.push(role);
    },
    nativeReceipt(),
  );
  if (images.join() !== "storage,control,compute,ci") throw new Error("Missing image stages");
  for (const [index, role] of ["storage", "control", "compute", "ci"].entries()) {
    if (
      !stages[index]?.includes(`#nixosConfigurations.${role}.config.system.build.toplevel.drvPath`)
    ) {
      throw new Error("Missing or reordered role evaluation");
    }
  }
  if (!stages[5]?.startsWith("hash file ") || !stages[5]?.endsWith(configPath)) {
    throw new Error("Actual config was not bound to the receipt hash");
  }
});

Deno.test("rejected preflight prevents every image stage", async () => {
  const module = await import("../../tofu/build-images.ts");
  let images = 0;
  let failed = false;
  try {
    await module.imageStages(
      "/absolute/site",
      "-",
      () => Promise.resolve("invalid derivation"),
      async () => {
        await Promise.resolve();
        images++;
      },
    );
  } catch {
    failed = true;
  }
  if (!failed || images !== 0) throw new Error("Image build accepted failed preflight");
});

Deno.test("disabled validation and non-nginx targets prevent image builds", async () => {
  const { imageStages } = await import("../../tofu/build-images.ts");
  for (
    const config of [
      { enabled: true, validated: false, targets: [] },
      {
        enabled: true,
        validated: true,
        targets: ["/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-system.drv^out"],
      },
    ]
  ) {
    let builds = 0;
    let images = 0;
    let evaluations = 0;
    let failed = false;
    try {
      await imageStages("path:/absolute/site", "-", async (args) => {
        await Promise.resolve();
        if (args[0] === "eval") evaluations++;
        if (args[0] === "build") builds++;
        return args.includes("--raw")
          ? "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system.drv"
          : JSON.stringify(config);
      }, async () => {
        await Promise.resolve();
        images++;
      }, nativeReceipt());
    } catch {
      failed = true;
    }
    if (!failed || builds !== 0 || images !== 0 || evaluations !== 5) {
      throw new Error("Strict writer gate was bypassed or its configuration was never evaluated");
    }
  }
});

Deno.test("writer-only default image entry point refuses an absent native receipt", async () => {
  const { imageStages } = await import("../../tofu/build-images.ts");
  let images = 0;
  let failed = false;
  try {
    await imageStages("path:/site", "-", (args) =>
      Promise.resolve(
        args.includes("--raw")
          ? "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system.drv"
          : args[0] === "eval"
          ? JSON.stringify({
            enabled: true,
            validated: true,
            targets: ["/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nginx.conf.drv^out"],
          })
          : "[]",
      ), () => {
      images++;
      return Promise.resolve();
    });
  } catch {
    failed = true;
  }
  if (!failed || images !== 0) {
    throw new Error("Images accepted writer-only preflight without native evidence");
  }
});

for (const fault of ["role", "hash", "native-exit", "severity", "fake-native", "writer-output"]) {
  Deno.test(`native receipt ${fault} failure refuses every image`, async () => {
    const call = imageStages as unknown as (...args: unknown[]) => Promise<void>;
    const receipt = nativeReceipt();
    if (fault === "role") {
      receipt.configuration.roles.compute = "/nix/store/ffffffffffffffffffffffffffffffff-other.drv";
    }
    if (fault === "hash") receipt.nginx_actual_config.sha256 = "3".repeat(64);
    if (fault === "native-exit") receipt.nginx_test.exit_code = 1;
    if (fault === "severity") receipt.nginx_severity_counters.warn = 1;
    if (fault === "fake-native") receipt.nginx_test.stderr = "gixy passed";
    if (fault === "writer-output") receipt.nginx_build.stdout = "[]";
    let images = 0;
    let failed = false;
    try {
      await call("path:/site", "-", nativeCommand, () => {
        images++;
        return Promise.resolve();
      }, receipt);
    } catch {
      failed = true;
    }
    if (!failed || images !== 0) throw new Error(`Images accepted failed native receipt: ${fault}`);
  });
}

Deno.test("default CLI requires native receipt before any input read", async () => {
  let diagnostic = "";
  try {
    await main(["path:/site", "unread-base.json", "-", "output"]);
  } catch (error) {
    diagnostic = String(error);
  }
  if (!diagnostic.includes("--preflight-receipt")) {
    throw new Error("Default CLI bypassed explicit native receipt admission");
  }
});
