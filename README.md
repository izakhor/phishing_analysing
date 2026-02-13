# 📧 Phishing Email Analyzer

Un outil Python d’analyse d’emails .eml permettant de détecter des indicateurs de phishing, calculer un score de risque et générer un rapport JSON structuré.

# 🎯 Objectif du projet

Ce projet simule un mini outil SOC capable de :

- Parser un email .eml

- Analyser les headers (SPF, DKIM, DMARC…)

- Inspecter le contenu (URLs, mots-clés suspects…)

- Analyser les pièces jointes

- Calculer un score de risque

- Générer un rapport JSON exploitable

# 🧠 Architecture du projet

```bash
phishing-analyzer/
│.
├── main.py
├── eml_parser.py
├── header_check.py
├── content_check.py
├── attachment.py
├── vt_scanner.py
├── risk.py
├── report.py
├── extra.py
└── phishing_report.json
```
## `🔹 main.py`

Orchestrateur principal :

- Demande le chemin du fichier .eml

- Lance l’analyse

- Calcule les scores

- Génère le rapport final

## `🔹 eml_parser.py`

Analyse technique de l’email :

- Headers

- Contenu

- Pièces jointes

## `🔹 risk.py`

Moteur de scoring :

- Score headers

- Score contenu

- Score pièces jointes

- Score total + niveau de risque

## `🔹 report.py`

Génère le rapport JSON final structuré.

# 🚀 Installation

## 1️⃣ Cloner le projet
```bash
git clone https://github.com/ton-utilisateur/phishing-analyzer.git
cd phishing-analyzer
```
## ▶️ Utilisation

Lancer le script :

```python
python main.py
```


Le programme demandera :

```python
Chemin complet du fichier .eml a analyser :
```


Entrer le chemin complet du fichier .eml.

# 📄 Rapport généré

Un fichier phishing_report.json sera créé automatiquement.

Exemple de sortie :
```json
{
    "metadata": {
        "tool": "Phishing Analyzer",
        "version": "1.0"
    },
    "summary": {
        "total_score": 72,
        "risk_level": "High"
    },
    "analysis": {
        "headers": {...},
        "content": {...},
        "attachments": [...]
    }
}
```

# 🧮 Système de scoring

Le score est calculé à partir de :

- 🔹 Headers (SPF, DKIM, DMARC)

- 🔹 Contenu (URLs, mots-clés suspects)

- 🔹 Pièces jointes (extensions suspectes, détections)

Le score total détermine un niveau de risque :

Score	Niveau
0–19	Informational
20–39	Low
40–59	Medium
60–79	High
80+	Critical

# 🛡️ Cas d’usage

- Projet portfolio cybersécurité

- Base pour un outil plus avancé (MITRE ATT&CK, VirusTotal API…)

# 🔮 Améliorations futures

- Mapping MITRE ATT&CK

# 👨‍💻 Auteur

Projet développé dans un objectif d’apprentissage et de montée en compétence en cybersécurité (analyse phishing & scoring de risque).
