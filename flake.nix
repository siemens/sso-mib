# SPDX-FileCopyrightText: (C) 2025 Siemens
# SPDX-License-Identifier: MIT
{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/release-25.11";

  outputs =
    {
      self,
      nixpkgs,
      systems,
      ...
    }@inputs:
    let
      inherit (nixpkgs) lib;
      eachSystem = lib.genAttrs (import systems);
      pkgsFor = eachSystem (
        system:
        import nixpkgs {
          localSystem.system = system;
          overlays = with self.overlays; [ default ];
        }
      );
    in
    {
      overlays = import ./nix/overlays.nix { inherit inputs lib self; };

      packages = eachSystem (system: {
        default = self.packages.${system}.sso-mib;
        inherit (pkgsFor.${system}) sso-mib;
      });

      devShells = eachSystem (
        system:
        let
          pkgs = pkgsFor.${system};
        in
        pkgs.mkShell {
          inherit (pkgs.sso-mib) buildInputs nativeBuildInputs;
        }
      );
    };
}
