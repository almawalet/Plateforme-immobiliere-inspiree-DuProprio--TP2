"""
Ce module est responsable de la gestion des utilisateurs dans l'application IFT-1004 Solo Immo,
incluant l'enregistrement de nouveaux utilisateurs et la connexion des utilisateurs existants.
Il interagit avec le fichier des utilisateurs pour enregistrer et vérifier les informations des utilisateurs,
tels que les noms d'utilisateurs et les mots de passe (sous forme hachée).

Fonctions:
- `creer_compte()`: Crée un nouveau compte utilisateur.
- `se_connecter()`: Connecte un utilisateur existant en vérifiant son nom d'utilisateur et son mot de passe.
- `se_deconnecter()`: Déconnecte l'utilisateur actuel.
- `utilisateur_est_connecte()`: Vérifie si un utilisateur est connecté.
- `recuperer_utilisateur_courant()`: Récupère l'utilisateur actuellement connecté.
- `definir_utilisateur_courant(nom_utilisateur)`: Définit l'utilisateur actuellement connecté.
- `vider_session()`: Efface les informations de session de l'utilisateur actuellement connecté.

Dépendances:
- `secrets`: Pour comparer les hachages (https://docs.python.org/3/library/secrets.html#secrets.compare_digest).
- `gestionnaire_donnees`: Pour lire et écrire dans le fichier des utilisateurs.
- `utilitaires`: Pour hacher les mots de passe.
- `configuration`: Pour accéder au chemin du fichier de session.
"""

import secrets
from gestionnaire_donnees import charger_utilisateurs, sauvegarder_utilisateurs
from utilitaires import hacher_mot_de_passe
from configuration import FICHIER_SESSION


def recuperer_utilisateur_courant():
    """Récupère le nom de l'utilisateur actuellement connecté depuis le fichier de session.

    Cette fonction lit le fichier de session pour déterminer l'utilisateur actuellement connecté.
    Si le fichier contient un nom d'utilisateur, celui-ci est retourné sous forme de chaîne de caractères.
    Si le fichier est vide, la fonction retourne `None`.

    Returns:
        str or None: Le nom de l'utilisateur actuellement connecté (str)
                     ou `None` si aucun utilisateur n'est connecté.
    """
    with open(FICHIER_SESSION, "r") as fichier:
        utilisateur = fichier.readline()
        if utilisateur != "":
            return str(utilisateur)
        else:
            return None  #Juste pour etre plus specifique


def definir_utilisateur_courant(nom_utilisateur):
    """Définit l'utilisateur actuellement connecté en enregistrant son nom dans le fichier de session.

    Cette fonction marque l'utilisateur comme étant actuellement connecté en écrivant son nom
    dans le fichier de session. Toute connexion précédente est remplacée, car le fichier de session
    est écrasé à chaque appel.

    Args:
        nom_utilisateur (str): Le nom de l'utilisateur à enregistrer comme utilisateur connecté.
    """
    with open(FICHIER_SESSION, "w") as fichier:
        fichier.write(nom_utilisateur)


def vider_session():
    """Efface les informations de session pour déconnecter l'utilisateur actuellement connecté.

    Cette fonction vide le contenu du fichier de session, marquant ainsi l'utilisateur comme déconnecté.
    """
    with open(FICHIER_SESSION, "w") as fichier:
        fichier.write("")  #Les infos précédentes sont automatiquement effacées

def creer_compte():
    """Crée un nouveau compte utilisateur en demandant un nom d'utilisateur et un mot de passe.

    Cette fonction suit les étapes suivantes :
      1. Charge les utilisateurs existants depuis le fichier des utilisateurs.
      2. Demande un nom d'utilisateur unique. Si le nom d'utilisateur existe déjà, un message d'erreur est affiché et la fonction se termine.
      3. Demande un mot de passe, le hache pour plus de sécurité, puis ajoute les informations au dictionnaire des utilisateurs.
      4. Sauvegarde le dictionnaire mis à jour dans le fichier des utilisateurs.

    Le hachage du mot de passe est réalisé via la fonction `hacher_mot_de_passe`, garantissant la sécurité des informations d'authentification.

    Affiche un message de confirmation si le compte est créé avec succès, ou un message d'erreur si le nom d'utilisateur est déjà pris.
    """
    utilisateurs = charger_utilisateurs()

    nom_utilisateur = input("Nom d'utilisateur: ")
    if nom_utilisateur in utilisateurs:
        print("Nom d'utilisateur déjà prix.")
        return None

    mot_de_passe = input("Mot de passe: ")
    mot_de_passe = hacher_mot_de_passe(mot_de_passe)
    utilisateurs[nom_utilisateur] = mot_de_passe
    sauvegarder_utilisateurs(utilisateurs)
    print("Compte crée avec succès.")
    return None

def se_connecter():
    """Connecte un utilisateur existant en vérifiant ses informations d'identification.

    Cette fonction suit les étapes suivantes :
      1. Charge les utilisateurs existants depuis le fichier des utilisateurs.
      2. Demande à l'utilisateur de saisir son nom d'utilisateur et son mot de passe.
      3. Hache le mot de passe fourni et le compare au mot de passe haché stocké pour l'utilisateur.
      4. Si les informations sont correctes (nom d'utilisateur existant et mot de passe correspondant),
         l'utilisateur est marqué comme connecté en enregistrant son nom dans le fichier de session.
         Un message de confirmation est affiché.
      5. Si les informations sont incorrectes, un message d'erreur est affiché.

    La comparaison des hachages est effectuée via `secrets.compare_digest` pour éviter les attaques de timing.

    Affiche un message de réussite si la connexion est réussie, ou un message d'erreur en cas d'échec.
    """
    utilisateurs = charger_utilisateurs()
    utilisateurs = {utilisateur.strip(): mot_de_passe.strip() for utilisateur, mot_de_passe in charger_utilisateurs().items()} #Pour supprimer les espaces pour que la comparaison des mots de passes fonctionnent
    nom_utilisateur = input("Nom d'utilisateur: ")
    mot_de_passe = input("Mot de passe: ").strip()

    if nom_utilisateur in utilisateurs and hacher_mot_de_passe(mot_de_passe) == utilisateurs[nom_utilisateur]:
        print("Connexion réussie.")
        with open(FICHIER_SESSION, "w") as fichier:
            fichier.write(nom_utilisateur)
    else:
        print("Nom d'utilisateur ou mot de passe incorrecte.")

def se_deconnecter():
    """Déconnecte l'utilisateur actuel."""
    vider_session()
    print("Déconnexion réussie.")


def utilisateur_est_connecte():
    """Vérifie si un utilisateur est connecté.

    Returns:
        bool: True si un utilisateur est connecté, False sinon.
    """
    return recuperer_utilisateur_courant() is not None
