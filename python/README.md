# Mina ombud - anslutningsexempel i Python

Denna kod är fristående förutom beroenden på
- [cryptography](https://pypi.org/project/cryptography/) för kryptografiska operationer
- [requests](https://pypi.org/project/requests/) för HTTP-requests.


Följande exempel finns:
- [samples/enduser_sample.py](src/minaombud/samples/enduser_sample.py) visar de steg som
  krävs för att göra API-anrop från början till slut i ett normalfall där
  slutanvändaren är en fullmaktshavare som agerar med en fullmakt
- [cli.py](src/minaombud/cli.py) är en kommandoradsapplikation som kan användas
  för att testa anrop till Mina ombud (söka behörigheter och fullmakter, hämta fullmakter)
- [server.py](src/minaombud/server.py) är en HTTP-server som publicerar ett JSON Web Key Set (JWKS).

## Development

### Create and activate virtual environment

#### Create virtual environment (un*x)
    $ python3 -m venv venv
    $ . venv/bin/activate

#### Create virtual environment (Windows cmd.exe)
    C:\> python3 -m venv venv
    C:\> . venv/Scripts/activate

#### Create virtual environment (Windows PowerShell)
    PS1> python3 -m venv venv
    PS1> ./venv/Scripts/activate.ps1

### Install dependencies
    (venv) $ pip install -e .

### Install dev extras
    (venv) $ pip install -e .[dev]

### Install extras for server
    (venv) $ pip install -e .[server]
