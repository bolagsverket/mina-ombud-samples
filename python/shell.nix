let
  pkgs = import <nixpkgs> {};
in
  pkgs.mkShellNoCC {
    packages = [ pkgs.python3 ];
  }
