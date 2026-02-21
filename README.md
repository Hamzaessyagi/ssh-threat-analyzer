🔐 SSH Threat Analyzer

Analyse avancée des attaques SSH à partir de logs Linux réels.

Projet développé par Hamza Es-Syagi, étudiant en cybersécurité à l’ESISA.

📌 Contexte

Ce projet analyse 4 fichiers auth.log réels provenant du serveur Linux de l’école exposé à Internet, représentant plus de :

1 447 249 lignes

492 192 tentatives SSH échouées

4 000+ adresses IP uniques

2 connexions réussies détectées

Objectif : transformer des logs bruts et illisibles en informations claires, exploitables et visualisées automatiquement.

🚀 Fonctionnalités

Parsing complet des logs SSH

Détection :

Tentatives échouées

Connexions réussies

Top IPs attaquantes

Usernames ciblés

Génération automatique :

📊 Dashboard PNG

📁 Rapport JSON

📝 Post LinkedIn auto-généré

Géolocalisation des IPs

Exécution native ou via Docker

Benchmark de performance intégré

🏗️ Architecture du projet
ssh-threat-analyzer/
│
├── scripts/
│   ├── analyze.py        # Analyse et parsing des logs
│   ├── visualize.py      # Génération dashboard
│   └── service.py        # Géolocalisation IP
│
├── output/               # Résultats générés automatiquement
│
├── run.sh                # Pipeline natif Ubuntu
├── docker-run.sh         # Pipeline containerisé
│
├── Dockerfile
├── .gitignore
└── README.md
🐧 Exécution (Ubuntu / WSL)
1️⃣ Mode natif
chmod +x run.sh
./run.sh auth.log.1

Résultats générés dans :

output/
2️⃣ Mode Docker
chmod +x docker-run.sh
./docker-run.sh auth.log.1

Aucune installation Python requise.

📊 Benchmark (hyperfine – 10 runs)

Exécution native :

7.00s ± 0.32s

Docker :

10.81s ± 1.13s

➡️ Exécution locale ≈ 1.54x plus rapide
➡️ Docker garantit portabilité et reproductibilité

📈 Exemple de Dashboard généré

Le dashboard inclut :

Top IPs attaquantes

Usernames les plus ciblés

Timeline des attaques heure par heure

Répartition des tentatives

🛠️ Technologies utilisées

Python 3

matplotlib

json / collections

Ubuntu (WSL)

Docker

Git & GitHub

hyperfine (benchmark)

🔒 Sécurité & bonnes pratiques

Les logs réels ne sont pas versionnés

.gitignore protège les fichiers sensibles

.dockerignore empêche l’inclusion des logs dans l’image Docker

🎯 Vision future

Automatisation quotidienne

Scoring des IPs dangereuses

Blocage automatique via fail2ban

Génération de rapports SOC automatisés

👨‍💻 Auteur

Hamza Es-Syagi
Projet académique basé sur des données réelles du serveur de l’école.
