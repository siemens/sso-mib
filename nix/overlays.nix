# SPDX-FileCopyrightText: (C) 2025 Siemens
# SPDX-License-Identifier: MIT
{
  lib,
  inputs,
  self,
}:

let
  mkDate =
    longDate:
    (lib.concatStringsSep "-" [
      (builtins.substring 0 4 longDate)
      (builtins.substring 4 2 longDate)
      (builtins.substring 6 2 longDate)
    ]);

  lines = lib.strings.splitString "\n" (builtins.readFile ../meson.build);
  matchVersion = lib.strings.match "[ ]*version[ ]*:.*([0-9]+\.[0-9]+\.[0-9]+).*";
  version = builtins.head (
    lib.lists.findFirst (x: !builtins.isNull x) "git" (lib.lists.map matchVersion lines)
  );
in

{
  default = inputs.self.overlays.sso-mib;
  sso-mib = final: prev: {
    sso-mib = prev.callPackage ./sso-mib.nix {
      version =
        version
        + "+date="
        + (mkDate (inputs.self.lastModifiedDate or "19700101"))
        + "_"
        + (inputs.self.shortRev or "dirty");
    };
  };
}
