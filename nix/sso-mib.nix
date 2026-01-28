# SPDX-FileCopyrightText: (C) 2025 Siemens
# SPDX-License-Identifier: MIT
{
  lib,
  stdenv,
  meson,
  ninja,
  pkg-config,
  libjwt,
  libuuid,
  glib,
  json-glib,
  version ? "git",
}:

stdenv.mkDerivation {
  pname = "sso-mib";
  inherit version;

  src = ../.;

  nativeBuildInputs = [
    pkg-config
    meson
    ninja
  ];

  buildInputs = [
    libjwt
    libuuid
    glib
    json-glib
  ];

  meta = with lib; {
    homepage = "https://github.com/siemens/sso-mib";
    description = "C library to interact with a locally running microsoft-identity-broker to get various authentication tokens via DBus.";
    maintainers = [ maintainers.michaeladler ];
    platforms = platforms.all;
    license = [
      licenses.gpl2Only
      licenses.lgpl21Only
    ];
  };
}
