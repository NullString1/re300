{
  description = "Rust Dev Env";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        pkgsCrossMipsel = pkgs.pkgsCross.mipsel-linux-gnu;
      in with pkgs; {
        devShells.default = mkShell rec {
          hardeningDisable = [ "all" ];
          buildInputs = [
            # Rust
            (rust-bin.stable.latest.default.override {
              extensions = ["rust-std" "rust-src"];
            })
            pkgsCrossMipsel.stdenv.cc
            pkgsCrossMipsel.openssl.dev
            rust-analyzer
            binwalk
            flashrom
            fontconfig.dev
            pkg-config
            squashfsTools
            ncurses
            ncurses.dev
            cmake
          ];
          PKG_CONFIG_PATH = "${fontconfig.dev}/bin";
          LD_LIBRARY_PATH = "${lib.makeLibraryPath buildInputs}";
          shellHook = ''
            alias openwrt-build='make defconfig download clean world -j8'
          '';
        };
      });
}
