
import html
import json
import os
import urllib.request
import shutil
from datetime import datetime, timezone
from pathlib import Path

E = html.escape

OUT = Path("pipeline-report")
OUT.mkdir(exist_ok=True)

K = {"crit": 0, "high": 0}
API_ERROR = ""

BUILD_URL = os.getenv("BUILD_URL", "").rstrip("/") + "/"

STAGES = [
    ("Checkout GitHub", "📥", "Récupère le code depuis GitHub."),
    ("Install Dependencies", "📦", "Installe les dépendances npm."),
    ("Lint", "🧹", "Analyse la qualité du code."),
    ("Build", "🔨", "Build Angular en production."),
    ("Trivy FS Scan", "🛡️", "Analyse les vulnérabilités des dépendances."),
    ("SonarQube Analysis", "🔍", "Analyse les bugs et code smells."),
    ("Docker Build", "🐳", "Construit l'image Docker."),
    ("Trivy Image Scan", "🛡️", "Analyse les vulnérabilités de l'image."),
    ("Docker Login", "🔑", "Connexion à Docker Hub."),
    ("Docker Push", "🚀", "Publication de l'image Docker."),
    ("Deploy Frontend on Minikube", "☸️", "Déploiement via Ansible."),
]

ST = {
    "SUCCESS": ("Réussi", "ok"),
    "FAILED": ("Échoué", "ko"),
    "UNSTABLE": ("Instable", "warn"),
    "ABORTED": ("Annulé", "warn"),
    "NOT_EXECUTED": ("Ignoré", "mute"),
    "SKIPPED": ("Ignoré", "mute"),
    "IN_PROGRESS": ("En cours", "info"),
    "PAUSED_PENDING_INPUT": ("En attente", "info"),
}

def get_stages():
    global API_ERROR

    if not BUILD_URL:
        API_ERROR = "BUILD_URL indisponible."
        return {}

    url = BUILD_URL + "wfapi/describe"

    try:
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json"}
        )

        # Aucun utilisateur ni token Jenkins nécessaire.
        with urllib.request.urlopen(req, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8"))

        return {
            stage["name"]: stage
            for stage in data.get("stages", [])
        }

    except Exception as exc:
        API_ERROR = str(exc)
        print("Impossible de récupérer les stages Jenkins:", exc)
        return {}


def dur(ms):
    seconds = int((ms or 0) / 1000)
    minutes, seconds = divmod(seconds, 60)

    return (
        f"{minutes} min {seconds:02d} s"
        if minutes else f"{seconds} s"
    )


def trivy(path):
    def run():
        p = Path(path)

        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return "<p class='muted'>Rapport Trivy indisponible.</p>"

        shutil.copy2(p, OUT / p.name)

        vulns = [
            v
            for result in (data.get("Results") or [])
            for v in (result.get("Vulnerabilities") or [])
            if v.get("Severity") in ("CRITICAL", "HIGH")
        ]

        crit = sum(
            v.get("Severity") == "CRITICAL" for v in vulns
        )

        high = sum(
            v.get("Severity") == "HIGH" for v in vulns
        )

        K["crit"] += crit
        K["high"] += high

        vulns.sort(
            key=lambda v: (
                v.get("Severity") != "CRITICAL",
                v.get("PkgName", "")
            )
        )

        output = f"""
        <div class="security-summary">
            <div class="security-item critical">
                <b>{crit}</b>
                <span>Critiques</span>
            </div>
            <div class="security-item high">
                <b>{high}</b>
                <span>Élevées</span>
            </div>
        </div>
        """

        if vulns:
            rows = ""

            for v in vulns[:40]:
                severity = v.get("Severity", "")

                rows += f"""
                <tr>
                    <td><span class="severity {severity.lower()}">
                        {E(severity)}
                    </span></td>
                    <td>{E(v.get('VulnerabilityID', ''))}</td>
                    <td>{E(v.get('PkgName', ''))}</td>
                    <td>{E(v.get('InstalledVersion', ''))}</td>
                    <td>{E(v.get('FixedVersion') or '—')}</td>
                </tr>
                """

            output += f"""
            <div class="scroll">
                <table>
                    <thead>
                        <tr>
                            <th>Sévérité</th>
                            <th>CVE</th>
                            <th>Paquet</th>
                            <th>Version installée</th>
                            <th>Version corrigée</th>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
            """

        else:
            output += """
            <p class="good">✔ Aucune vulnérabilité détectée.</p>
            """

        artifact_url = (
            BUILD_URL + "artifact/" + p.name
            if BUILD_URL else p.name
        )

        output += f"""
        <p>
            <a class="btn" href="{E(artifact_url)}">
                Télécharger le rapport JSON
            </a>
        </p>
        """

        return output

    return run


def sonar():
    key = os.getenv("SONAR_PROJECT_KEY", "frontend")

    host = os.getenv(
        "SONAR_HOST_URL",
        "http://192.168.33.10:9000"
    ).rstrip("/")

    url = f"{host}/dashboard?id={key}"

    return f"""
    <p>
        <a class="btn" target="_blank" href="{E(url)}">
            Ouvrir SonarQube
        </a>
    </p>
    """


def build_info():
    image = (
        f"{os.getenv('IMAGE_NAME', 'medamine56987/frontend')}:"
        f"{os.getenv('IMAGE_TAG', os.getenv('BUILD_NUMBER', 'latest'))}"
    )

    return f"""
    <div class="image-info">
        <span>Image Docker</span>
        <code>{E(image)}</code>
    </div>
    """


DET = {
    "Trivy FS Scan": trivy("trivy-report.json"),
    "Trivy Image Scan": trivy("trivy-image-report.json"),
    "SonarQube Analysis": sonar,
    "Docker Build": build_info,
    "Docker Push": build_info,
}


# =========================
# DESIGN CSS
# =========================

CSS = """
* {
    box-sizing: border-box;
}

:root {
    color-scheme: light;
    --bg: #f1f5f9;
    --card: #ffffff;
    --text: #172033;
    --muted: #64748b;
    --line: #e2e8f0;
    --ok: #16a34a;
    --ko: #dc2626;
    --warn: #d97706;
    --info: #2563eb;
    --accent: #4f46e5;
}

body {
    margin: 0 !important;
    padding: 0 !important;
    background: var(--bg) !important;
    color: var(--text) !important;
    font-family: Inter, Arial, sans-serif !important;
    line-height: 1.6;
}

.wrap {
    max-width: 1150px;
    margin: auto;
    padding: 35px 20px 60px;
}

header {
    background: linear-gradient(135deg, #312e81, #4f46e5, #0284c7);
    color: white !important;
    padding: 35px;
    border-radius: 20px;
    margin-bottom: 25px;
    box-shadow: 0 10px 30px rgba(49,46,129,.18);
}

header h1 {
    margin: 0 0 8px;
    font-size: 28px;
    color: white !important;
}

header p {
    color: #e0e7ff !important;
    margin: 5px 0;
}

.meta {
    display: flex;
    flex-wrap: wrap;
    gap: 12px 25px;
    margin-top: 22px;
    font-size: 13px;
}

.meta a {
    color: white !important;
}

.global {
    display: inline-block;
    background: rgba(255,255,255,.17);
    padding: 8px 17px;
    border-radius: 30px;
    margin-top: 20px;
    font-weight: 700;
}

.cards {
    display: grid;
    grid-template-columns: repeat(auto-fit,minmax(170px,1fr));
    gap: 15px;
    margin-bottom: 28px;
}

.kpi {
    background: var(--card) !important;
    padding: 20px;
    border: 1px solid var(--line);
    border-radius: 15px;
    box-shadow: 0 3px 12px rgba(15,23,42,.04);
}

.kpi b {
    display: block;
    font-size: 32px;
    font-weight: 800;
}

.kpi span {
    color: var(--muted) !important;
    font-size: 13px;
}

.kpi.ok b { color: var(--ok) !important; }
.kpi.ko b { color: var(--ko) !important; }
.kpi.warn b { color: var(--warn) !important; }

.stage {
    background: var(--card) !important;
    border: 1px solid var(--line);
    border-left: 5px solid #94a3b8;
    border-radius: 15px;
    padding: 22px;
    margin-bottom: 16px;
    box-shadow: 0 3px 12px rgba(15,23,42,.035);
}

.stage.ok { border-left-color: var(--ok); }
.stage.ko { border-left-color: var(--ko); }
.stage.warn { border-left-color: var(--warn); }
.stage.info { border-left-color: var(--info); }

.head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
}

.head h2 {
    margin: 0;
    font-size: 18px;
    color: var(--text) !important;
}

.badge {
    padding: 5px 13px;
    border-radius: 30px;
    font-size: 12px;
    font-weight: 700;
    color: white !important;
    background: #94a3b8;
}

.badge.ok { background: var(--ok); }
.badge.ko { background: var(--ko); }
.badge.warn { background: var(--warn); }
.badge.info { background: var(--info); }

.desc {
    color: var(--muted) !important;
    margin: 8px 0;
}

.facts {
    font-size: 12px;
    color: var(--muted) !important;
    margin-top: 12px;
    padding-top: 10px;
    border-top: 1px solid var(--line);
}

.muted {
    color: var(--muted) !important;
}

.security-summary {
    display: flex;
    gap: 12px;
    margin: 15px 0;
}

.security-item {
    padding: 12px 20px;
    border-radius: 10px;
    background: var(--bg);
}

.security-item b {
    display: block;
    font-size: 24px;
}

.security-item span {
    font-size: 12px;
    color: var(--muted);
}

.critical b { color: var(--ko); }
.high b { color: var(--warn); }

.severity {
    font-weight: 800;
    font-size: 11px;
}

.severity.critical { color: var(--ko); }
.severity.high { color: var(--warn); }

.scroll {
    overflow-x: auto;
    border: 1px solid var(--line);
    border-radius: 10px;
    margin: 15px 0;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    min-width: 650px;
}

th, td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid var(--line);
}

th {
    background: var(--bg);
    color: var(--muted);
    font-weight: 700;
}

.btn {
    display: inline-block;
    padding: 9px 16px;
    border-radius: 9px;
    background: var(--accent) !important;
    color: white !important;
    text-decoration: none !important;
    font-size: 13px;
    font-weight: 700;
    margin-top: 8px;
}

.btn:hover {
    background: #3730a3 !important;
}

.good {
    color: var(--ok) !important;
    font-weight: 700;
}

.image-info {
    background: var(--bg);
    border-radius: 10px;
    padding: 13px;
    margin-top: 12px;
}

.image-info span {
    display: block;
    font-size: 12px;
    color: var(--muted);
}

.image-info code {
    display: block;
    margin-top: 5px;
    overflow-wrap: anywhere;
}

code {
    background: var(--bg);
    padding: 3px 6px;
    border-radius: 5px;
    font-size: 12px;
}

footer {
    text-align: center;
    color: var(--muted) !important;
    font-size: 12px;
    margin-top: 35px;
}

@media(max-width:600px) {
    .wrap { padding: 15px 10px 35px; }
    header { padding: 22px; }
    header h1 { font-size: 23px; }
    .stage { padding: 16px; }
    .cards { grid-template-columns: repeat(2,minmax(0,1fr)); }
}
"""


# =========================
# RECUPERATION DES STAGES
# =========================

jobs = get_stages()

total = {"ok": 0, "ko": 0, "other": 0}
sections = ""

for name, icon, desc in STAGES:

    job = jobs.get(name)

    if job:
        status = job.get("status", "UNKNOWN")
        label, cls = ST.get(status, ("Inconnu", "mute"))
    else:
        label, cls = (
            "Non trouvé",
            "mute"
        )

    if cls in ("ok", "ko"):
        total[cls] += 1
    else:
        total["other"] += 1

    facts = f"Stage : <code>{E(name)}</code>"

    if job:
        facts += f" — Durée : {dur(job.get('durationMillis'))}"

    try:
        details = DET.get(name, lambda: "")()
    except Exception as exc:
        details = f"<p class='muted'>Erreur : {E(str(exc))}</p>"

    sections += f"""
    <section class="stage {cls}">
        <div class="head">
            <h2>{icon} {E(name)}</h2>
            <span class="badge {cls}">{E(label)}</span>
        </div>

        <p class="desc">{E(desc)}</p>

        <div class="facts">{facts}</div>

        {details}
    </section>
    """


# =========================
# STATUT GLOBAL
# =========================

if total["ko"]:
    verdict = f"⚠️ {total['ko']} stage(s) en échec"

elif total["ok"] == len(STAGES):
    verdict = "✅ Tous les stages sont réussis"

elif jobs:
    verdict = "ℹ️ Pipeline partiellement exécutée"

else:
    verdict = "⚠️ Statuts des stages indisponibles"


now = datetime.now(timezone.utc).strftime(
    "%d/%m/%Y %H:%M UTC"
)

env = os.getenv

if API_ERROR:
    api_notice = f"""
    <p class="muted">
        Informations des stages indisponibles : {E(API_ERROR)}
    </p>
    """
else:
    api_notice = ""


# =========================
# GENERATION HTML
# =========================

page = f"""<!DOCTYPE html>
<html lang="fr">

<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Rapport Jenkins - {E(env('JOB_NAME', 'Frontend'))}</title>

<style>
{CSS}
</style>

</head>

<body>

<div class="wrap">

<header>

<h1>🚀 Rapport du pipeline Jenkins</h1>

<p>{E(env('JOB_NAME', 'Frontend'))} — Qualité, sécurité et déploiement</p>

<div class="meta">

<span>🔖 Commit : <b>{E(env('GIT_SHORT', 'N/A'))}</b></span>

<span>
🔗 <a href="{E(BUILD_URL)}">
Build #{E(env('BUILD_NUMBER', 'N/A'))}
</a>
</span>

<span>🕒 {now}</span>

</div>

<div class="global">{E(verdict)}</div>

</header>

{api_notice}

<div class="cards">

<div class="kpi ok">
<b>{total['ok']}</b>
<span>Stages réussis</span>
</div>

<div class="kpi ko">
<b>{total['ko']}</b>
<span>Stages échoués</span>
</div>

<div class="kpi warn">
<b>{total['other']}</b>
<span>Autres stages</span>
</div>

<div class="kpi ko">
<b>{K['crit']}</b>
<span>Vulnérabilités critiques</span>
</div>

<div class="kpi warn">
<b>{K['high']}</b>
<span>Vulnérabilités élevées</span>
</div>

</div>

<h2>📊 Détail de l'exécution</h2>

{sections}

<footer>
Rapport généré automatiquement par Jenkins<br>
{now}
</footer>

</div>

</body>
</html>
"""

(OUT / "index.html").write_text(
    page,
    encoding="utf-8"
)

print("======================================")
print("  RAPPORT JENKINS GENERE AVEC SUCCES")
print("======================================")
print(f"Stages réussis : {total['ok']}")
print(f"Stages échoués : {total['ko']}")
print(f"Autres stages  : {total['other']}")
print(f"Vulnérabilités critiques : {K['crit']}")
print(f"Vulnérabilités élevées   : {K['high']}")
print("Fichier : pipeline-report/index.html")
