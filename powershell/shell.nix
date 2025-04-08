let
  pkgs = import <nixpkgs> {};
in
  pkgs.mkShellNoCC {
    packages = [ pkgs.powershell ];
    POWERSHELL_UPDATECHECK = "Off";
    shellHook = ''
        exec pwsh -NoProfile -NoLogo
    '';
  }
