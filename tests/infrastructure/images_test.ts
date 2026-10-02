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
