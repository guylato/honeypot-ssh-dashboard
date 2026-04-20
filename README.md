SSH & Web Honeypot – Système de capture et d’analyse de comportements malveillants

Ce projet a pour objectif de concevoir un honeypot complet, combinant un service SSH simulé et un honeypot web, permettant de capturer des tentatives d’intrusion, d’analyser les comportements observés et de produire des indicateurs exploitables dans un contexte de cybersécurité défensive.

Le point de départ du projet repose sur un constat simple : les services exposés sur Internet, tels que SSH ou les interfaces web d’administration, sont constamment ciblés par des attaques automatisées (brute force, scans, injections, exécution de commandes, téléchargement de payloads). Ces interactions représentent une source précieuse d’information pour comprendre les stratégies utilisées par les attaquants.

L’objectif est donc de créer un système capable de simuler des services vulnérables, de collecter ces interactions, puis de les analyser afin d’identifier des comportements suspects et d’en mesurer la criticité.

Architecture du système

Le projet repose sur une architecture modulaire développée en Python, combinant des composants réseau et une plateforme d’analyse.

Le système est structuré autour de trois éléments principaux :

Un honeypot SSH, basé sur Paramiko, chargé de simuler un serveur et de capturer les interactions en ligne de commande

Un honeypot web, intégré à une API FastAPI, simulant des endpoints sensibles tels que /login, /admin ou /phpmyadmin

Une API backend, développée avec FastAPI, permettant de traiter, stocker et exposer les données collectées

Ces composants sont reliés à une base de données SQLite, utilisée pour enregistrer les sessions, les identifiants testés, les commandes exécutées et les événements web.

Un dashboard web, construit avec Jinja2, permet de visualiser ces informations de manière synthétique et exploitable.

Mécanisme de capture
Honeypot SSH

Le honeypot SSH simule un service accessible sur un port dédié. Lorsqu’un client se connecte, le système accepte volontairement l’authentification, indépendamment des identifiants fournis.

Les éléments suivants sont capturés :

L’adresse IP source
Le nom d’utilisateur
Le mot de passe utilisé
Les commandes envoyées dans la session

Une fois connecté, l’utilisateur interagit avec un faux shell reproduisant un environnement minimal. Les commandes sont interceptées et analysées sans être réellement exécutées, garantissant un contrôle total du système.

Honeypot Web

Le honeypot web simule plusieurs endpoints sensibles généralement ciblés par les attaquants.

Les interactions capturées incluent :

Les requêtes HTTP (GET / POST)
Les chemins demandés (/login, /admin, /wp-admin, etc.)
Les identifiants soumis via formulaires
Les payloads envoyés (tentatives d’injection)
Le user-agent du client

Ce module permet de détecter des comportements tels que :

Brute force sur formulaire
Tentatives d’injection SQL
Payloads XSS
Scans automatisés (sqlmap, curl, scripts)

Analyse des comportements

Contrairement à une simple journalisation, le projet intègre un mécanisme d’analyse des interactions.

Les actions observées sont examinées afin d’identifier des patterns typiques d’attaque, tels que :

Commandes de reconnaissance (ls, whoami, id, ps)
Tentatives de téléchargement (wget, curl)
Tentatives d’exécution (bash, sh, chmod)
Requêtes web suspectes (union select, <script>, ../)
Accès répétés à des endpoints sensibles

Cette analyse permet de qualifier le comportement observé et de le replacer dans un contexte d’attaque réaliste.

Scoring et évaluation du risque

Le projet intègre un système de scoring permettant d’évaluer la criticité de chaque interaction.

Ce score est basé sur plusieurs critères :

La nature des identifiants utilisés (ex : root, admin, mots de passe faibles)
Le nombre et le type de commandes exécutées
La présence de patterns suspects dans les requêtes web
Le comportement global de la session

Le score final est normalisé sur 100 et associé à un niveau de risque :

Faible
Moyen
Élevé
Critique

Cela permet d’obtenir une vision rapide et structurée du niveau de menace.

Classification des attaques

En complément du scoring, le système propose une classification automatique des comportements observés.

Chaque interaction peut être associée à un type d’activité, par exemple :

Reconnaissance
Brute force probable
Tentative de téléchargement
Tentative d’exécution
Tentative malware
Injection SQL
XSS
Scan automatisé
Activité suspecte

Cette classification repose sur des règles heuristiques basées sur les actions observées.

Visualisation et exploitation des données

Les données collectées sont exposées via une API REST et visualisées dans un dashboard web.

Ce dashboard permet de consulter :

Le nombre total de sessions capturées
Le score moyen de menace
La répartition des niveaux de risque
Les IP les plus actives
Les identifiants les plus utilisés
Les mots de passe les plus fréquents
Les commandes les plus observées
Les endpoints web les plus ciblés
Les types d’attaque identifiés
Le détail des dernières interactions

L’objectif est de transformer des logs bruts en informations lisibles et exploitables.

Génération de rapports

Le système intègre également un module de reporting permettant de générer un rapport d’analyse au format texte.

Ce rapport contient :

Un résumé global des activités observées
Les statistiques principales
Les types d’attaque identifiés
Le détail des sessions les plus récentes

Ce document est conçu pour être exploitable dans un contexte professionnel, proche des livrables attendus lors d’une analyse de sécurité.

Enjeux et apports du projet

Ce projet s’inscrit dans une démarche de cybersécurité défensive, centrée sur l’observation et l’analyse des comportements malveillants.

Il permet de mettre en œuvre plusieurs compétences clés :

Développement backend et conception d’API
Manipulation de protocoles réseau (SSH, HTTP)
Collecte et structuration de logs
Analyse comportementale
Scoring et évaluation de risque
Conception d’interfaces de visualisation

Au-delà de l’aspect technique, le projet illustre la capacité à concevoir un système complet, allant de la capture des données jusqu’à leur exploitation, dans une logique proche des outils utilisés en sécurité opérationnelle.
