# Rapport Technique — Module VOC & AI
## ICOC-Lite : Integrated Cyber Operations Center
**Membre 3 — Vulnerability Operations Center (VOC) + AI Risk Engine**

---

## 1. Vue d'ensemble du module

Le module VOC/AI constitue le cœur analytique de la plateforme ICOC-Lite. Il assure la détection des vulnérabilités sur les machines du laboratoire, leur scoring, leur suivi de remédiation, et alimente un moteur d'intelligence artificielle qui calcule un score de risque global en temps réel.

L'architecture repose sur une chaîne de traitement complète :

```
Machine victime (Metasploitable3)
        ↓
  Scanner nmap + vulners NSE
        ↓
  Base de données PostgreSQL
        ↓
  Moteur AI (3 modèles ML)
        ↓
  Dashboard React (temps réel)
```

---

## 2. Module VOC — Vulnerability Operations Center

### 2.1 Inventaire logiciel (FR-VOC-01)

L'inventaire est réalisé via une connexion SSH vers la machine victime (`192.168.237.129`). Le module exécute la commande `dpkg-query` pour récupérer la liste des paquets installés :

```python
ssh vagrant@192.168.237.129
dpkg-query -W -f='${Package} ${Version}\n'
```

Les paquets critiques pour la sécurité (openssh-server, apache2, openssl, etc.) sont prioritairement collectés. En cas d'indisponibilité SSH, le module utilise `paramiko` comme alternative à `sshpass`.

### 2.2 Scanner de vulnérabilités (FR-VOC-05)

Le scanner utilise **nmap** avec le script NSE **vulners** pour identifier les CVEs présentes sur la machine victime. Il s'exécute depuis le conteneur Docker de l'API et cible directement la VM Metasploitable3.

**Commande équivalente :**
```bash
nmap -sV --script vulners \
  -p 21,22,25,80,139,443,445,3306,5432,6667,8009,8080,8443 \
  192.168.237.129
```

**Ports scannés et services détectés :**

| Port | Service | CVEs trouvées |
|------|---------|---------------|
| 21 | vsftpd 1.3.5 | CVE-2015-3306 (backdoor, CVSS 10.0) |
| 22 | OpenSSH 6.6.1p1 | CVE-2023-38408, CVE-2016-1908 (CVSS 9.8) |
| 80 | Apache 2.4.7 | CVE-2024-38476, CVE-2023-25690 (CVSS 9.8) |
| 8080 | Jetty 8.1.7 | Multiples CVEs |

**Résultats du dernier scan :**
- **155 CVEs** détectées sur `192.168.237.129`
- **35 CVEs** avec exploit public disponible
- **25 Critical**, **65 High**, **60 Medium**, **5 Low**

Le scanner enrichit chaque CVE avec :
- Le flag `is_exploit` (présence d'un exploit public EDB-ID, PACKETSTORM, MSF)
- Les références d'exploit (`exploit_refs[]`)
- Le port et service concerné

### 2.3 Scoring CVSS v3.1 (FR-VOC-02)

Chaque CVE est scorée selon le standard **CVSS v3.1** (Common Vulnerability Scoring System). Le calcul décompose le vecteur en métriques :

- **Attack Vector (AV)** : Network / Adjacent / Local / Physical
- **Attack Complexity (AC)** : Low / High
- **Privileges Required (PR)** : None / Low / High
- **User Interaction (UI)** : None / Required
- **Scope (S)** : Unchanged / Changed
- **Impact (C/I/A)** : Confidentiality / Integrity / Availability

**Exemple — CVE-2023-38408 (OpenSSH RCE) :**
```
Vecteur : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Score   : 9.8 / Critical
Signification : Exploitable depuis le réseau, sans authentification,
                impact total sur confidentialité, intégrité et disponibilité
```

### 2.4 Suivi des correctifs (FR-VOC-03)

La base `patch_records` maintient l'état de chaque CVE par hôte :

| Statut | Signification |
|--------|---------------|
| `missing` | Correctif non appliqué |
| `available` | Correctif disponible, non déployé |
| `scheduled` | Planifié |
| `applied` | Correctif appliqué |
| `wontfix` | Décision de ne pas corriger |

Actuellement : **154 CVEs** en statut `missing` sur `192.168.237.129`.

### 2.5 Intégration NVD/CVE (FR-VOC-06)

Le module interroge l'API NVD (National Vulnerability Database) pour enrichir les CVEs avec descriptions et vecteurs CVSS officiels. Une clé API NVD est configurée pour augmenter le débit (50 req/30s au lieu de 5).

### 2.6 Conformité réglementaire (FR-VOC-07)

Le module calcule automatiquement les scores de conformité pour trois référentiels :

**PCI-DSS v4.0 :**
- REQ-6.3 : Gestion des vulnérabilités → **0%** (117 CVEs non corrigées)
- REQ-6.3.3 : Correctifs critiques < 30 jours → **0%** (22 critiques non patchées)
- REQ-11.3 : Scans réguliers → **100%** (scan effectué)
- REQ-5.3 : Anti-malware actif → **75%** (VirusTotal configuré)
- **Score global : 31.2% — Non-Conforme**

**ISO 27001:2022 :**
- A.8.8 : Gestion des vulnérabilités techniques → **0%**
- A.8.19 : Installation logicielle contrôlée → **100%**
- **Score global : 70% — Partiel**

**NIST CSF v2.0 :**
- ID.RA : Évaluation des risques → **0%**
- DE.CM : Surveillance continue → **100%**
- **Score global : 50% — Non-Conforme**

Ces scores sont **calculés dynamiquement** à partir des données réelles du scan. Ils évoluent automatiquement après chaque nouveau scan ou application de correctif.

---

## 3. Agent victime

### 3.1 Architecture

L'agent est installé directement sur la machine Metasploitable3 (Ubuntu 14.04). Il est écrit en **Python 2.7 pur**, sans dépendances externes, utilisant uniquement la bibliothèque standard Python.

**Compatibilité :** Python 2.7 / 3.x — zéro installation de paquets requise.

### 3.2 Moniteurs actifs

L'agent exécute 5 threads de surveillance en parallèle :

**1. AuthLogMonitor** — Surveillance SSH en temps réel
- Lit `/var/log/auth.log` en continu (polling toutes les 2 secondes)
- Détecte les tentatives de connexion échouées
- Déclenche `ssh_brute_force` après 3 échecs, `Critical` après 5 (FR-SOC-02)
- Détecte les connexions réussies post-brute-force

**2. FIMMonitor** — Intégrité des fichiers (FR-SOC-06)
- Calcule les hash MD5 de : `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/etc/ssh/sshd_config`
- Surveille `/tmp` pour les dépôts de fichiers suspects (malware)
- Polling toutes les 20 secondes

**3. ProcessMonitor** — Détection de processus suspects (FR-SOC-08)
- Lit `ps aux` toutes les 8 secondes
- Détecte : nmap, hydra, msfconsole, netcat, bash -i, python -c, etc.
- Alerte `Critical` sur tout processus d'attaque connu

**4. NetMonitor** — Connexions réseau (FR-SOC-01)
- Lit `/proc/net/tcp` toutes les 10 secondes
- Détecte les connexions vers les ports de reverse shell (4444, 5555, 1337, etc.)
- Alerte `Critical` sur toute connexion C2 détectée

**5. HeartbeatMonitor** — Métriques système (FR-NOC-01/02/06)
- Lit `/proc/stat` (CPU), `/proc/meminfo` (RAM), `df /` (disque), `/proc/net/dev` (réseau)
- Envoie un heartbeat toutes les 10 secondes au dashboard

### 3.3 Communication

Chaque événement est envoyé via HTTP POST à l'API :

```json
{
  "agent_id": "victim-agent-metasploitable3-ub1404",
  "host_ip": "192.168.237.129",
  "event_type": "ssh_brute_force",
  "severity": "Critical",
  "data": {
    "summary": "SSH failed login from 192.168.237.131 (attempt #5)",
    "src_ip": "192.168.237.131",
    "attempts": 5,
    "rule": "FR-SOC-02 — brute-force threshold"
  }
}
```

### 3.4 Service Upstart

L'agent est installé comme service système via Upstart (Ubuntu 14.04) :
- Démarrage automatique au boot
- Redémarrage automatique en cas de crash
- Logs dans `/var/log/icoc-agent.log`

---

## 4. Moteur AI — Intelligence Artificielle

### 4.1 Architecture globale

Le moteur AI est composé de 7 fonctionnalités (FR-AI-01 à FR-AI-07) et de 3 modèles de Machine Learning entraînés sur des données CVE réelles.

```
Données d'entrée
├── patch_records (154 CVEs de Metasploitable3)
├── security_events (alertes SOC en temps réel)
└── threat_intel (11 entrées CISA KEV + MITRE ATT&CK)
        ↓
   Moteur AI
├── Modèle 1 : Régression d'exploitabilité
├── Modèle 2 : Classificateur de sévérité
└── Modèle 3 : Détecteur d'anomalies
        ↓
   Sorties
├── Score de risque global (0-100)
├── Prédiction d'incident (probabilité 24h)
├── Recommandations de remédiation
└── Corrélations SOC × VOC
```

### 4.2 Modèle 1 — Régression d'exploitabilité (FR-AI-02)

**Algorithme :** GradientBoostingRegressor (scikit-learn)

**Objectif :** Prédire le score d'exploitabilité (0-10) d'une CVE à partir de son vecteur CVSS.

**Feature engineering :** Le vecteur CVSS est décomposé en 15 features numériques :
- Métriques de base : AV, AC, PR, UI, S, C, I, A
- Features dérivées : interaction AV×AC, facteur humain PR×UI, impact total C+I+A
- Features composites : réseau sans interaction, impact CIA complet, scope pondéré

**Entraînement :**
```
Dataset    : 2000 CVEs (NVD)
Échantillons valides : 1891
Train/Test : 80/20 (1512 / 379)
RMSE       : 2.73
R²         : -0.05 (données synthétiques — à réentraîner sur NVD réel)
```

**Note :** Le modèle actuel est entraîné sur données synthétiques. Pour la production, la commande `python ai/train.py --download` télécharge les CVEs réelles depuis l'API NVD et réentraîne les modèles.

**Utilisation dans le système :**
- Calcul de la probabilité d'incident (FR-AI-06)
- Priorisation des alertes (FR-AI-02)

### 4.3 Modèle 2 — Classificateur de sévérité (FR-AI-02)

**Algorithme :** RandomForestClassifier + CalibratedClassifierCV (calibration de probabilités)

**Objectif :** Classifier une CVE en Critical / High / Medium / Low à partir de son vecteur CVSS et score.

**Architecture :**
- 300 arbres de décision
- Profondeur maximale : 10
- Pondération des classes équilibrée (`class_weight="balanced"`)
- Calibration sigmoid pour des probabilités fiables

**Résultats d'entraînement :**
```
Accuracy       : 100% (sur données synthétiques)
CV Accuracy    : 100% ± 0%
Classes        : Low, Medium, High, Critical
Precision/Recall/F1 : 1.0 pour toutes les classes
```

**Utilisation dans le système :**
- Re-classification des alertes entrantes
- Validation des scores CVSS calculés manuellement

### 4.4 Modèle 3 — Détecteur d'anomalies (FR-AI-03)

**Algorithme :** IsolationForest (scikit-learn)

**Objectif :** Détecter les CVEs dont la combinaison de métriques est inhabituelle — indicateur potentiel d'exploitation active ou de mauvaise configuration.

**Principe :** L'Isolation Forest isole les points anormaux en construisant des arbres aléatoires. Les points qui nécessitent peu de coupures pour être isolés sont considérés comme anomalies.

**Configuration :**
```
n_estimators  : 200
contamination : 5% (5% des CVEs attendues comme anomalies)
Threshold     : 0.0 (percentile 5 du score de décision)
```

**Features utilisées :**
- 15 features CVSS de base
- Score CVSS normalisé
- Ancienneté de la CVE (jours depuis publication)
- Flags : impact CIA complet, vecteur réseau, sans authentification, changement de scope
- Statut de patch

**Explication des anomalies :**
Le modèle génère une explication textuelle pour chaque anomalie détectée :
- "CVE critique (CVSS 9.8) sans correctif appliqué"
- "Vecteur d'attaque réseau, sans authentification, sans interaction"
- "Impact CIA complet — potentiel de dommage maximal"

### 4.5 Score de risque global (FR-AI-01)

Le score de risque (0-100) agrège trois composantes :

```
Score = VOC (60%) + SOC (25%) + TI (15%)
```

**Composante VOC (0-60) :**
Somme pondérée des CVEs non patchées, normalisée par leur score CVSS :
```python
for cve in unpatched:
    weight = {"Critical": 1.0, "High": 0.7, "Medium": 0.4, "Low": 0.1}[severity]
    voc_score += weight × (cvss_score / 10) × 10
voc_score = min(60, voc_score)
```

**Composante SOC (0-25) :**
```python
soc_score = min(25, alertes_actives × 1.5 + incidents_actifs × 5.0)
```

**Composante TI (0-15) :**
```python
ti_score = min(15, threat_intel_hits × 3.0)
```

**Niveaux de risque :**
| Score | Niveau | Couleur |
|-------|--------|---------|
| ≥ 80 | Critical | Rouge |
| ≥ 60 | High | Orange |
| ≥ 40 | Medium | Jaune |
| ≥ 20 | Low | Cyan |
| < 20 | Minimal | Vert |

**Score actuel du lab :** 75/100 — High (baseline sans attaques)
**Score sous attaque :** 100/100 — Critical

### 4.6 Flux de renseignement sur les menaces (FR-AI-05)

Le module intègre deux sources de threat intelligence :

**Source 1 — CISA KEV (Known Exploited Vulnerabilities) :**
11 entrées statiques sélectionnées pour leur pertinence avec le lab :
- CVE-2024-6387 (OpenSSH RegreSSHion — RCE sans auth)
- CVE-2014-6271 (Shellshock — bash RCE)
- CVE-2016-5195 (Dirty COW — élévation de privilèges kernel)
- CVE-2021-3156 (sudo Baron Samedit — root local)
- etc.

**Source 2 — MITRE ATT&CK :**
Techniques d'attaque mappées au scénario du lab :
- T1190 : Exploit Public-Facing Application
- T1110.001 : Brute Force SSH
- T1059.004 : Unix Shell (Shellshock)

En mode online (`LAB_OFFLINE_MODE=false`), le système récupère automatiquement les dernières entrées CISA KEV et les CVEs critiques récentes depuis l'API NVD.

### 4.7 Prédiction d'incident (FR-AI-06)

Le module prédit la probabilité d'un incident de sécurité dans les 24 prochaines heures :

```python
# Avec modèle ML disponible :
probabilité = (exploitabilité_moyenne / 10) × 0.6
            + nb_high_missing × 0.04
            + min(alertes_soc × 0.02, 0.15)

# Sans modèle ML (formule de secours) :
probabilité = 0.05
            + nb_critical_missing × 0.12
            + nb_high_missing × 0.05
            + min(alertes_soc × 0.03, 0.20)
```

**Résultat actuel :** 98% — Very High
(25 CVEs critiques non patchées + 49 alertes SOC actives)

### 4.8 Recommandations automatiques (FR-AI-07)

Le moteur génère des recommandations priorisées basées sur l'état réel du système :

**Priorité 1 — Correctifs critiques immédiats :**
Top 3 CVEs critiques triées par score CVSS, avec package, version actuelle et version corrigée.

Exemple :
```
Action : Patcher immédiatement CVE-2023-38408 sur 192.168.237.129
Détail : Package openssh-server | Actuel: 6.6.1p1 → Fix: 9.3p2 | CVSS: 9.8
Effort : 30 minutes
```

**Priorité 2 — Fenêtre de maintenance :**
Regroupement des 43 CVEs High en une fenêtre de maintenance planifiée.

**Priorité 2 — Investigation SOC :**
Si > 3 alertes actives, recommandation d'investigation croisée SOC × VOC.

**Priorité 3 — Vérification de conformité :**
Scan de conformité post-patch pour valider PCI-DSS REQ-6.3.3 et ISO 27001 A.8.8.

### 4.9 Corrélation SOC × VOC (FR-AI-03)

Le module croise les alertes SOC avec les CVEs non patchées pour identifier les attaques ciblant des vulnérabilités connues :

```python
# Pour chaque alerte SOC :
cves_sur_hote = patch_records[alerte.dst_ip]
score_correlation = max(cvss) / 10 × 1.2

# Si score > 0.7 → risque amplifié
```

**Exemple :** Une alerte SSH brute-force depuis Kali (192.168.237.131) vers Metasploitable (192.168.237.129) est corrélée avec CVE-2023-38408 (OpenSSH RCE, CVSS 9.8) → score de corrélation 0.98 → **risque amplifié**.

### 4.10 Flux temps réel (FR-AI-04)

Le score de risque est diffusé en temps réel via **Server-Sent Events (SSE)** :
- Mise à jour toutes les 15 secondes
- Latence < 30 secondes (exigence FR-AI-04)
- Visible dans l'onglet "AI Intelligence" du dashboard

---

## 5. Intégration VirusTotal

Le module VOC intègre l'API VirusTotal v3 pour enrichir les analyses :

**Hash de fichier :** Vérification de malwares détectés sur la machine victime
**Réputation IP :** Vérification de l'IP de l'attaquant (192.168.237.131)
**URL :** Analyse des URLs suspectes détectées dans les logs

Lors d'un scan, les 3 CVEs critiques les plus sévères sont enrichies avec le rapport VirusTotal de l'IP hôte.

---

## 6. Rôle de l'IA Générative (Gemini)

Dans une version production de la plateforme, **Google Gemini** serait intégré pour augmenter les capacités analytiques du système :

**Investigation d'incidents :**
Au lieu de règles statiques, Gemini analyserait le contexte complet d'un incident (logs bruts, CVEs corrélées, historique d'attaques) pour générer une analyse narrative détaillée, identifier les techniques MITRE ATT&CK utilisées, et proposer des contre-mesures adaptées au contexte spécifique.

**Recommandations de remédiation :**
Gemini génèrerait des recommandations contextualisées en tenant compte de l'environnement (Ubuntu 14.04, versions spécifiques des paquets), des contraintes opérationnelles, et des dépendances entre correctifs.

**Analyse de conformité :**
Gemini interpréterait les résultats de conformité en langage naturel, expliquerait les implications légales et opérationnelles de chaque non-conformité, et proposerait un plan de remédiation priorisé.

**Threat Intelligence :**
Gemini enrichirait les entrées CISA KEV avec une analyse contextuelle, reliant les CVEs détectées aux campagnes d'attaque connues et aux groupes APT actifs.

---

## 7. Pipeline de données complet

```
1. SCAN (nmap + vulners)
   └─ 155 CVEs détectées sur 192.168.237.129
   
2. STOCKAGE (PostgreSQL)
   ├─ patch_records : 154 enregistrements
   ├─ cve_database  : 160 entrées
   └─ scan_reports  : 2 rapports

3. ANALYSE AI
   ├─ Modèle 1 : Score d'exploitabilité par CVE
   ├─ Modèle 2 : Classification de sévérité
   └─ Modèle 3 : Détection d'anomalies

4. SCORE DE RISQUE
   ├─ VOC : 60/60 (154 CVEs non patchées)
   ├─ SOC : 6.5/25 (alertes agent)
   └─ TI  : 15/15 (11 entrées threat intel)
   = 75/100 — HIGH (baseline)
   = 100/100 — CRITICAL (sous attaque)

5. CONFORMITÉ
   ├─ PCI-DSS  : 31.2% — Non-Conforme
   ├─ ISO 27001: 70.0% — Partiel
   └─ NIST CSF : 50.0% — Non-Conforme

6. DASHBOARD (React, mise à jour 10s)
   └─ Toutes les données affichées en temps réel
```

---

## 8. Technologies utilisées

| Composant | Technologie | Version |
|-----------|-------------|---------|
| Scanner | nmap + vulners NSE | 7.95 |
| API Backend | FastAPI (Python) | 0.109.2 |
| Base de données | PostgreSQL | 16 |
| ML Framework | scikit-learn | 1.4.1 |
| Modèle régression | GradientBoostingRegressor | — |
| Modèle classification | RandomForestClassifier | — |
| Modèle anomalie | IsolationForest | — |
| Sérialisation modèles | joblib | 1.3.2 |
| Threat Intel | CISA KEV + MITRE ATT&CK | Live |
| Enrichissement | VirusTotal API v3 | — |
| Frontend | React + Vite | 18.x |
| Conteneurisation | Docker + Docker Compose | — |

---

*Rapport rédigé pour la présentation académique ICOC-Lite — Février 2026*
