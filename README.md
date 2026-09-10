# 🔷 Burp-Like Python - JATHNIEL EDITION

Proxy d'interception HTTP/HTTPS avec interface graphique, inspiré de Burp Suite.

---

## 📋 Description

**Burp-Like Python** est un outil d'interception et de modification de requêtes HTTP/HTTPS. Il permet de :

- Intercepter les requêtes en temps réel
- Modifier la méthode, l'URL, les headers et le body
- Décoder automatiquement les valeurs (URL, Base64, HTML, Hex, JSON, JWT)
- Historiser toutes les requêtes
- Rejouer des requêtes depuis le Repeater
- Encoder/décoder avec le Decoder

---

## 🚀 Installation

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Lancer l'application
python3 burp_like.py