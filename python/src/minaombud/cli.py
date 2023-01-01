import argparse
from typing import Dict, Any, Optional

from minaombud.client import MinaOmbudClient
from minaombud.crypto.jwkset import JwkSet
from minaombud.defaults import (
    MINA_OMBUD_SAMPLE_ISSUER,
    MINA_OMBUD_API_CLIENT_ID,
    MINA_OMBUD_API_TOKEN_URL,
    MINA_OMBUD_API_URL,
    MINA_OMBUD_SAMPLE_USER_DB,
    MINA_OMBUD_SAMPLE_KEYS,
    MINA_OMBUD_SAMPLE_SERVICE,
    MINA_OMBUD_API_CLIENT_SECRET,
    MINA_OMBUD_SAMPLE_USER,
    MINA_OMBUD_SAMPLE_USER_SCOPE,
    MINA_OMBUD_SAMPLE_AUDIENCE,
    MINA_OMBUD_SAMPLE_CLIENT_ID,
)
from minaombud.model import Identitetsbeteckning, FullmaktsgivareRoll, FullmaktStatus
from minaombud.user import create_user_token, load_user_database


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token-url", default=MINA_OMBUD_API_TOKEN_URL, metavar="URL")
    parser.add_argument("--url", default=MINA_OMBUD_API_URL, help="API url")
    parser.add_argument(
        "--issuer",
        "--iss",
        default=MINA_OMBUD_SAMPLE_ISSUER,
        help="Issuer for signed JWT:s.",
    )
    parser.add_argument(
        "--audience", "--aud", action="append", help="Value(s) for JWT aud claim."
    )
    parser.add_argument(
        "--expiry-time",
        "--expiry",
        "--exp",
        default=300,
        type=int,
        help="User token expiry time",
    )
    parser.add_argument(
        "--user",
        "-u",
        default=MINA_OMBUD_SAMPLE_USER,
        help="Specify user details (token or claims)",
    )
    parser.add_argument(
        "--user-db",
        default=MINA_OMBUD_SAMPLE_USER_DB,
        help="Load users from file",
        metavar="FILE",
    )
    parser.add_argument(
        "--user-scope",
        default=MINA_OMBUD_SAMPLE_USER_SCOPE,
        choices=("self", "other", "any"),
    )
    parser.add_argument("--keys", "--key", "-k", metavar="PATH", action="append")
    parser.add_argument("--service", default=MINA_OMBUD_SAMPLE_SERVICE)
    parser.add_argument("--client-id", default=MINA_OMBUD_API_CLIENT_ID)
    parser.add_argument("--client-secret", default=MINA_OMBUD_API_CLIENT_SECRET)

    subparsers = parser.add_subparsers(dest="cmd", help="kommando")

    def behorigheter_args():
        p = subparsers.add_parser("behorighet", help="sök behörigheter")
        p.add_argument(
            "--fullmaktsgivare",
            metavar="ORGNR",
            help="Organisations-/personnummer för fullmaktsgivaren.",
        )
        p.add_argument(
            "tredjeman", metavar="TREDJEMAN", help="Organisationsnummer för tredje man."
        )
        p.add_argument(
            "fullmaktshavare", metavar="PNR", help="Personnummer för fullmaktskavaren."
        )
        p.add_argument(
            "behorigheter",
            nargs="*",
            metavar="KOD",
            help="Filtrera på behörighetskod(er).",
        )

    def fullmakter_args():
        p = subparsers.add_parser("fullmakt", help="sök fullmakter")
        p.add_argument("--tredjeman", metavar="ORGNR", action="append")
        p.add_argument(
            "--fullmaktsgivare",
            metavar="ORGNR",
        )
        p.add_argument(
            "--roll",
            choices=("privat", "organisation"),
            metavar="ROLL",
            action="append",
        )
        p.add_argument("--fullmaktshavare", metavar="PNR")
        p.add_argument("--status", choices=("aktuell", "giltig", "historisk"))
        p.add_argument("--aterkallad", dest="aterkallad", action="store_true")
        p.add_argument("--inte-aterkallad", dest="aterkallad", action="store_false")
        p.add_argument(
            "fullmakter", nargs="*", metavar="ID", help="Hämta fullmakter med ID."
        )

    behorigheter_args()
    fullmakter_args()

    args = parser.parse_args()
    if not args.keys:
        args.keys = MINA_OMBUD_SAMPLE_KEYS

    if not args.audience:
        args.audience = MINA_OMBUD_SAMPLE_AUDIENCE

    if args.keys:
        keys = JwkSet.load(args.keys)
    else:
        keys = JwkSet()

    users: Optional[Dict[str, Any]]
    if args.user_db:
        with open(args.user_db, "rb") as f:
            users = load_user_database(f)
    else:
        users = None

    if args.user:
        user_token = create_user_token(
            args.user,
            keys,
            users=users,
            issuer=args.issuer,
            audience=args.audience,
            client_id=MINA_OMBUD_SAMPLE_CLIENT_ID,
            expiry_time=args.expiry_time,
        )
    else:
        user_token = None

    client = MinaOmbudClient(
        service=args.service,
        scope=f"user:{args.user_scope}",
        client_id=args.client_id,
        client_secret=args.client_secret,
        token_url=args.token_url,
        url=args.url,
    )

    if args.cmd == "behorighet":
        fullmaktshavare = Identitetsbeteckning.from_id(args.fullmaktshavare)
        if args.fullmaktsgivare:
            fullmaktsgivare = Identitetsbeteckning.from_id(args.fullmaktsgivare)
        else:
            fullmaktsgivare = None

        response = client.sok_behorigheter(
            tredjeman=args.tredjeman,
            fullmaktshavare=fullmaktshavare,
            fullmaktsgivare=fullmaktsgivare,
            behorigheter=args.behorigheter if args.behorigheter else None,
            user_token=user_token,
        )

    elif args.cmd == "fullmakt":
        if args.fullmaktshavare:
            fullmaktshavare = Identitetsbeteckning.from_id(args.fullmaktshavare)
        else:
            fullmaktshavare = None

        if args.fullmaktsgivare:
            fullmaktsgivare = Identitetsbeteckning.from_id(args.fullmaktsgivare)
        else:
            fullmaktsgivare = None

        if args.roll:
            fullmaktsgivarroll = [FullmaktsgivareRoll[r.upper()] for r in args.roll]
        else:
            fullmaktsgivarroll = None

        if args.status:
            status = FullmaktStatus[args.status.upper()]
        else:
            status = None

        aterkallad = args.aterkallad
        if args.fullmakter:
            if fullmaktshavare or fullmaktsgivare or fullmaktsgivarroll or status or aterkallad is not None:
                parser.print_help()
                parser.error("Vid hämtning av specifika fullmakter används inte filter")
                parser.exit(1)

            if not args.tredjeman:
                parser.print_help()
                parser.error("Tredje man måste anges")
                parser.exit(1)

            tredjeman = args.tredjeman
            if len(args.tredjeman) == 1:
                tredjeman = tredjeman * len(args.fullmakter)
            elif len(tredjeman) != len(args.fullmakter):
                parser.print_help()
                parser.error(
                    "Antal tredje män matchar inte antal fullmakter som ska hämtas"
                )
                parser.exit(1)

            fullmakter = [
                client.hamta_fullmakt(tm, id, user_token=user_token)
                for id, tm in zip(args.fullmakter, tredjeman)
            ]
            response = fullmakter[0] if len(fullmakter) == 1 else fullmakter
        else:
            if not (fullmaktshavare or fullmaktsgivare):
                parser.print_help()
                parser.error("Ange fullmaktshavare och/eller fullmaktsgivare")
                parser.exit(1)

            response = client.sok_fullmakter(
                tredjeman=args.tredjeman,
                fullmaktshavare=fullmaktshavare,
                fullmaktsgivare=fullmaktsgivare,
                fullmaktsgivarroll=fullmaktsgivarroll,
                aterkallad=aterkallad,
                status=status,
                user_token=user_token,
            )
    else:
        parser.print_help()
        parser.exit(1)
        return

    print(response.to_json(indent=2))


if __name__ == "__main__":
    main()
