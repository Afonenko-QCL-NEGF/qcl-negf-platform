{ pkgs }:
let
  basePython = pkgs.python314;
  engine = basePython.pkgs.ansible-core;
  python = basePython.withPackages (ps: [ ps.pytest ps.ansible-core ]);
  general = pkgs.fetchurl {
    url = "https://galaxy.ansible.com/download/community-general-13.4.0.tar.gz";
    hash = "sha256-79HAtdxviblmfkvXfyQmwwVFhhkQ26GIWThxCV7eGAQ=";
  };
  library = pkgs.fetchurl {
    url = "https://galaxy.ansible.com/download/community-library_inventory_filtering_v1-1.1.5.tar.gz";
    hash = "sha256-y7nobFsXIN8h6UDO3NLz4SJsOCYmI+CQqINxJhBzOFE=";
  };
  collections = pkgs.runCommand "qcl-operations-ansible-collections" {
    nativeBuildInputs = [ pkgs.gnutar pkgs.gzip ];
  } ''
    mkdir -p "$out/ansible_collections/community/general"
    mkdir -p "$out/ansible_collections/community/library_inventory_filtering_v1"
    tar -xzf ${general} -C "$out/ansible_collections/community/general"
    tar -xzf ${library} -C "$out/ansible_collections/community/library_inventory_filtering_v1"
  '';
in {
  inherit python collections;
  environment = {
    QCL_TEST_ANSIBLE_COLLECTIONS = "${collections}";
    ANSIBLE_COLLECTIONS_PATH = "${collections}";
    ANSIBLE_COLLECTIONS_SCAN_SYS_PATH = "false";
    QCL_TEST_PYTHON_BASE = basePython.interpreter;
    QCL_TEST_PYTHON_LAUNCHER = python.interpreter;
    QCL_TEST_ANSIBLE_ENGINE_OUTPUT = "${engine}";
    QCL_TEST_ANSIBLE_ENGINE_ROOT = "${engine}/${basePython.sitePackages}/ansible";
    QCL_TEST_ANSIBLE_ENGINE_VERSION = engine.version;
    PYTHONNOUSERSITE = "true";
  };
}
