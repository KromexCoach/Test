"""Ligne de commande : `iam-ad serve` et `iam-ad generate-api-key`."""

from __future__ import annotations

import argparse
import json

from iam_ad.auth import new_api_key


def _serve(args: argparse.Namespace) -> None:
    import uvicorn

    uvicorn.run(
        "iam_ad.api:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        ssl_certfile=args.tls_cert,
        ssl_keyfile=args.tls_key,
        proxy_headers=args.behind_proxy,
        server_header=False,
        log_level="info",
    )


def _generate_api_key(args: argparse.Namespace) -> None:
    key, digest = new_api_key()
    print(f"Clé à remettre à « {args.name} » (affichée une seule fois) :\n  {key}\n")
    print("Empreinte à ajouter à IAM_API_KEYS :")
    print(f"  IAM_API_KEYS='{json.dumps({args.name: digest})}'")


def main() -> None:
    parser = argparse.ArgumentParser(prog="iam-ad", description=__doc__)
    commands = parser.add_subparsers(required=True)

    serve = commands.add_parser("serve", help="démarre l'API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8443)
    serve.add_argument("--tls-cert", help="certificat TLS du serveur (PEM)")
    serve.add_argument("--tls-key", help="clé privée TLS du serveur (PEM)")
    serve.add_argument(
        "--behind-proxy",
        action="store_true",
        help="fait confiance aux en-têtes X-Forwarded-* du reverse proxy",
    )
    serve.set_defaults(handler=_serve)

    generate = commands.add_parser("generate-api-key", help="génère une clé d'API et son empreinte")
    generate.add_argument("name", help="nom de l'application cliente (ex. : logiciel-rh)")
    generate.set_defaults(handler=_generate_api_key)

    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
