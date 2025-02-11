# IFT-1004 - Automne 2024 - Travail pratique #2

Bienvenue dans IFT-1004 Solo Immo, une application console permettant aux utilisateurs de gérer des annonces immobilières. Ce projet a été développé dans le cadre du cours IFT-1004 et vise à consolider les compétences en programmation Python, notamment en matière de programmation modulaire, de gestion des fichiers et de cryptographie pour le stockage sécurisé des mots de passe.

## Fonctionnalités

- **Inscription des utilisateurs** : Créez un nouveau compte utilisateur.
- **Connexion des utilisateurs** : Connectez-vous à votre compte utilisateur.
- **Déconnexion des utilisateurs** : Déconnectez-vous de votre compte utilisateur.
- **Ajout de propriétés** : Ajoutez une nouvelle propriété (réservé aux utilisateurs connectés).
- **Liste des propriétés** : Affichez toutes les propriétés disponibles.
- **Filtrage des propriétés** : Filtrez les propriétés par prix, ville, type de propriété, nombre de chambres et nombre de salles de bains.

## Structure du projet

Le projet est structuré en plusieurs modules pour assurer une organisation claire et une maintenance aisée.

- **ift1004_solo_immo.py** : Le point d'entrée principal de l'application.
- **configuration.py** : Définit les constantes globales utilisées à travers l'application.
- **gestionnaire_proprietes.py** : Gère les opérations sur les propriétés, telles que l'ajout, la liste et le filtrage des propriétés.
- **gestionnaire_utilisateurs.py** : Gère les opérations sur les utilisateurs, telles que l'inscription, la connexion et la déconnexion.
- **gestionnaire_donnees.py** : Gère la manipulation des fichiers de données (lecture et écriture des propriétés et des utilisateurs).
- **utilitaires.py** : Fournit un ensemble de fonctions utilitaires, couvrant diverses fonctionnalités telles que le hachage de mots de passe, le formatage de montants monétaires et l'affichage de données sous forme de tableaux.

## Utilisation

Pour exécuter ce projet, vous devez avoir Python 3 installé sur votre machine. 

