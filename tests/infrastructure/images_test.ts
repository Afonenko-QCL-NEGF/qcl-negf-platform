import { imageRoles, roles, validateBase } from "../../tofu/build-images.ts";
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
      return JSON.stringify({
        enabled: true,
        validated: true,
        targets: ["/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-nginx.conf.drv^out"],
      });
    }
    return "[]";
  };
  await module.imageStages("git+https://example.org/site?rev=abc", "-", command, async (role) => {
    await Promise.resolve();
    if (stages.length !== 6) throw new Error("Image stage preceded complete preflight");
    images.push(role);
  });
  if (images.join() !== "storage,control,compute,ci") throw new Error("Missing image stages");
  for (const [index, role] of ["storage", "control", "compute", "ci"].entries()) {
    if (
      !stages[index]?.includes(`#nixosConfigurations.${role}.config.system.build.toplevel.drvPath`)
    ) {
      throw new Error("Missing or reordered role evaluation");
    }
  }
  if (!stages[5]?.endsWith("-nginx.conf.drv^out")) throw new Error("Wrong strict writer target");
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
    let failed = false;
    try {
      await imageStages("path:/absolute/site", "-", async (args) => {
        await Promise.resolve();
        if (args[0] === "build") builds++;
        return args.includes("--raw")
          ? "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system.drv"
          : JSON.stringify(config);
      }, async () => {
        await Promise.resolve();
        images++;
      });
    } catch {
      failed = true;
    }
    if (!failed || builds !== 0 || images !== 0) throw new Error("Strict writer gate bypassed");
  }
});
