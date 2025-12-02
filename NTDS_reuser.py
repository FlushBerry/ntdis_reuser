#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from collections import defaultdict

# Hash NT "mot de passe vide" classique
EMPTY_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"


def parse_dump(path):
    """
    Parse un dump NTDS (format type secretsdump):
    user:RID:LMHASH:NTHASH:::
    Retourne un dict: nt_hash -> liste de (user, line_no)
    """
    hash_to_users = defaultdict(list)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(":")
            # Format attendu : user:RID:LM:NT:...
            if len(parts) < 4:
                continue

            user = parts[0]
            nt_hash = parts[3].lower()

            hash_to_users[nt_hash].append((user, lineno))

    return hash_to_users


def show_reused_hashes(hash_to_users):
    """
    Affiche les NT hash utilisés par au moins 2 comptes.
    """
    reused = {h: u for h, u in hash_to_users.items() if len(u) >= 2}

    if not reused:
        print("Aucun NT hash réutilisé trouvé.\n")
        return

    print("=== NT hash réutilisés (même hash pour plusieurs comptes) ===\n")

    for nt_hash, users in reused.items():
        print(f"NT hash {nt_hash} utilisé par {len(users)} comptes :")
        for user, lineno in users:
            print(f"  - {user} (ligne {lineno})")
        print()


def find_specific_hash(hash_to_users, target_hash):
    """
    Recherche d'un NT hash particulier et affiche UNIQUEMENT les comptes concernés.
    """
    target = target_hash.lower()
    print(f"=== Recherche du NT hash : {target} ===\n")

    if target not in hash_to_users:
        print("Aucun compte ne possède ce NT hash.")
        return

    users = hash_to_users[target]
    print(f"Ce NT hash est utilisé par {len(users)} compte(s) :")
    for user, lineno in users:
        print(f"  - {user} (ligne {lineno})")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Analyse un dump NTDS (format secretsdump) pour trouver les NT hash réutilisés ou un hash spécifique."
    )
    parser.add_argument(
        "dump_file",
        help="Chemin du fichier de dump NTDS (ex: ntds_dump.txt)"
    )
    parser.add_argument(
        "-f", "--find",
        dest="find_hash",
        help="NT hash spécifique à rechercher (32 caractères hex)."
    )
    parser.add_argument(
        "--ignore-empty",
        action="store_true",
        help=f"Ignorer le hash de mot de passe vide ({EMPTY_NT_HASH})."
    )

    args = parser.parse_args()

    hash_to_users = parse_dump(args.dump_file)

    # Optionnel : ignorer les mots de passe vides
    if args.ignore_empty and EMPTY_NT_HASH in hash_to_users:
        del hash_to_users[EMPTY_NT_HASH]

    print(f"Analyse du dump : {args.dump_file}\n")

    # Si un hash spécifique est demandé → on NE FAIT QUE ça
    if args.find_hash:
        find_specific_hash(hash_to_users, args.find_hash)
        return

    # Sinon → on affiche les hash réutilisés
    show_reused_hashes(hash_to_users)


if __name__ == "__main__":
    main()
