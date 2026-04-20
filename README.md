# SSH Honeypot Dashboard

Projet de honeypot SSH développé en Python permettant de capturer des tentatives de connexion, d’enregistrer les identifiants testés et les commandes envoyées, puis d’analyser ces événements via un dashboard web.

## Objectif du projet

L’objectif de ce projet est de simuler un service SSH exposé afin d’observer les comportements d’un utilisateur ou d’un attaquant, de journaliser les actions réalisées dans la session, puis de transformer ces données en informations exploitables grâce à un système de scoring et de classification.

Ce projet a été pensé dans une logique de démonstration technique et de valorisation de compétences en cybersécurité, backend Python, traitement de logs et visualisation de données.

## Fonctionnalités

- Simulation d’un faux service SSH
- Capture des tentatives de connexion
- Enregistrement des usernames et mots de passe testés
- Journalisation des commandes envoyées dans la session
- Stockage des événements dans une base SQLite
- Dashboard web avec statistiques
- Score de menace normalisé sur 100
- Classification automatique du comportement observé
- Génération d’un rapport TXT

## Technologies utilisées

- Python 3
- FastAPI
- Paramiko
- SQLite
- SQLAlchemy
- Jinja2

## Architecture du projet

```bash
honeypot-project/
├── app/
│   ├── main.py
│   ├── database.py
│   ├── models.py
│   ├── services/
│   │   └── scoring.py
│   └── templates/
│       └── dashboard.html
├── honeypot/
│   └── fake_ssh.py
├── requirements.txt
├── README.md
└── .gitignore
