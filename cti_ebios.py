"""
Chaîne d'intégration CTI -> EBIOS RM (mémoire Telco, NMS et accès tiers)
=======================================================================

Objectif
--------
Confronter les scénarios opérationnels (atelier 4 d'EBIOS RM) aux techniques
réellement observées chez les groupes d'attaquants qui ciblent le secteur des
télécommunications, puis réévaluer la vraisemblance de chaque scénario selon une
règle fixée AVANT l'exécution.

Source CTI
----------
Base MITRE ATT&CK Enterprise, au format STIX 2.1 (dépôt officiel
mitre-attack/attack-stix-data). Aucun autre flux n'est utilisé.

Règles méthodologiques (fixées avant exécution)
-----------------------------------------------
R1 - Groupe « télécom » : groupe ATT&CK (intrusion-set) non révoqué et non
     déprécié dont la description mentionne explicitement le secteur des
     télécommunications (motif « telecom », insensible à la casse).
R2 - Technique observée : une technique d'un scénario est « observée » si au
     moins un groupe télécom l'utilise (relation STIX « uses »), directement ou
     via l'une de ses sous-techniques (T1078 est observée si un groupe utilise
     T1078 ou T1078.xxx). Une sous-technique (ex. T1078.004) n'est observée que
     si elle est utilisée telle quelle.
R3 - Taux de couverture CTI d'un scénario = techniques observées / techniques
     du scénario.
R4 - Ajustement de la vraisemblance (échelle V1 à V4) :
       couverture >= 2/3  -> +1 niveau (plafonné à V4)
       couverture <= 1/3  -> -1 niveau (plancher V1)
       sinon              -> inchangée
R5 - Niveau de risque : grille 4x4 EBIOS RM de CISO Assistant
     (vraisemblance x gravité -> Faible / Moyen / Élevé).

Utilisation
-----------
    python3 cti_ebios.py data/enterprise-attack-19.2.json sorties/v19.2
"""

import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Données d'entrée : scénarios opérationnels (tableau 10 du mémoire)
# ---------------------------------------------------------------------------
SCENARIOS = {
    "SO1": {"nom": "Compromission d'un accès tiers et rançongiciel sur le NMS",
            "source": "SR4 Crime organisé", "gravite": 4, "vraisemblance": 2,
            "techniques": ["T1595", "T1566", "T1078", "T1133", "T1087", "T1548", "T1486"]},
    "SO2": {"nom": "Usurpation de session et injection de configurations malveillantes",
            "source": "SR4 Crime organisé", "gravite": 4, "vraisemblance": 2,
            "techniques": ["T1595", "T1566", "T1078", "T1133", "T1548", "T1087", "T1059.008", "T1565"]},
    "SO3": {"nom": "Compromission d'un compte cloud et collecte d'informations",
            "source": "SR5 Groupe étatique", "gravite": 4, "vraisemblance": 2,
            "techniques": ["T1595", "T1078.004", "T1087", "T1548", "T1005", "T1602.002"]},
    "SO4": {"nom": "Hameçonnage ciblé et vol de jetons de session d'administration",
            "source": "SR5 Groupe étatique", "gravite": 4, "vraisemblance": 2,
            "techniques": ["T1566", "T1539", "T1078", "T1087", "T1548", "T1602.002", "T1048", "T1567"]},
    "SO5": {"nom": "Altération interne des journaux et données de supervision",
            "source": "SR7 Collaborateur malveillant", "gravite": 4, "vraisemblance": 3,
            "techniques": ["T1078", "T1518.001", "T1018", "T1565", "T1070"]},
    "SO6": {"nom": "Divulgation et revente de données sensibles",
            "source": "SR8 Ancien employé", "gravite": 4, "vraisemblance": 2,
            "techniques": ["T1078", "T1087", "T1005", "T1602.002", "T1048", "T1567"]},
}

VRAISEMBLANCE = {1: "V1 Peu vraisemblable", 2: "V2 Vraisemblable",
                 3: "V3 Très vraisemblable", 4: "V4 Certain"}
GRAVITE = {1: "G1 Mineure", 2: "G2 Significative", 3: "G3 Importante", 4: "G4 Critique"}
# Grille EBIOS RM 4x4 de CISO Assistant : GRILLE[vraisemblance-1][gravite-1]
GRILLE = [[0, 0, 0, 1], [0, 0, 1, 1], [1, 1, 2, 2], [1, 2, 2, 2]]
NIVEAU_RISQUE = {0: "Faible", 1: "Moyen", 2: "Élevé"}

MOTIF_TELECOM = re.compile(r"telecom", re.IGNORECASE)   # règle R1
SEUIL_HAUT, SEUIL_BAS = 2 / 3, 1 / 3                     # règle R4


# ---------------------------------------------------------------------------
# Lecture du paquet STIX
# ---------------------------------------------------------------------------
def actif(o):
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def id_attack(o):
    for ref in o.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def charger(chemin):
    paquet = json.load(open(chemin, encoding="utf-8"))
    objets = {o["id"]: o for o in paquet["objects"]}
    version = next((o.get("x_mitre_version") for o in paquet["objects"]
                    if o["type"] == "x-mitre-collection"), "?")
    techniques = {o["id"]: o for o in paquet["objects"]
                  if o["type"] == "attack-pattern" and actif(o)}
    groupes = {o["id"]: o for o in paquet["objects"]
               if o["type"] == "intrusion-set" and actif(o)}
    mitigations = {o["id"]: o for o in paquet["objects"]
                   if o["type"] == "course-of-action" and actif(o)}
    campagnes = {o["id"] for o in paquet["objects"] if o["type"] == "campaign" and actif(o)}
    utilise = defaultdict(set)        # groupe -> identifiants ATT&CK des techniques
    attenue = defaultdict(set)        # technique -> mitigations (Mxxxx, nom)
    tech_campagne = defaultdict(set)  # campagne -> techniques
    attribution = defaultdict(set)    # campagne -> groupes auxquels elle est attribuée
    for r in paquet["objects"]:
        if r["type"] != "relationship" or not actif(r):
            continue
        src, cible = r["source_ref"], r["target_ref"]
        if r["relationship_type"] == "uses" and src in groupes and cible in techniques:
            utilise[src].add(id_attack(techniques[cible]))
        if r["relationship_type"] == "uses" and src in campagnes and cible in techniques:
            tech_campagne[src].add(id_attack(techniques[cible]))
        if r["relationship_type"] == "attributed-to" and src in campagnes and cible in groupes:
            attribution[src].add(cible)
        if r["relationship_type"] == "mitigates" and src in mitigations and cible in techniques:
            m = mitigations[src]
            attenue[id_attack(techniques[cible])].add((id_attack(m), m["name"]))
    # Comme sur les fiches ATT&CK : un groupe hérite des techniques des campagnes
    # qui lui sont attribuées (relation STIX « attributed-to »).
    for camp, grps in attribution.items():
        for g in grps:
            utilise[g] |= tech_campagne[camp]
    noms_tech = {id_attack(t): t["name"] for t in techniques.values()}
    return version, groupes, utilise, attenue, noms_tech


# ---------------------------------------------------------------------------
# Règles R1 à R5
# ---------------------------------------------------------------------------
def groupes_telecom(groupes):
    """R1 : groupes dont la description mentionne les télécommunications."""
    return {gid: g for gid, g in groupes.items()
            if MOTIF_TELECOM.search(g.get("description", ""))}


def observee(technique, techniques_groupe):
    """R2 : technique utilisée telle quelle ou via une sous-technique."""
    return technique in techniques_groupe or any(
        t.startswith(technique + ".") for t in techniques_groupe)


def ajuster(v, couverture):
    """R4 : ajustement de la vraisemblance selon la couverture CTI."""
    if couverture >= SEUIL_HAUT - 1e-9:
        return min(v + 1, 4)
    if couverture <= SEUIL_BAS + 1e-9:
        return max(v - 1, 1)
    return v


def risque(v, g):
    """R5 : niveau de risque selon la grille EBIOS RM de CISO Assistant."""
    return NIVEAU_RISQUE[GRILLE[v - 1][g - 1]]


def parent(t):
    return t.split(".")[0]


# ---------------------------------------------------------------------------
# Analyse
# ---------------------------------------------------------------------------
def analyser(chemin_stix, dossier_sortie):
    version, groupes, utilise, attenue, noms = charger(chemin_stix)
    tel = groupes_telecom(groupes)
    noms_groupes = {gid: f"{g['name']} ({id_attack(g)})" for gid, g in tel.items()}
    sortie = Path(dossier_sortie)
    sortie.mkdir(parents=True, exist_ok=True)

    # 1. Techniques des scénarios : quels groupes télécom les utilisent ?
    detail, synthese = [], []
    for so, s in SCENARIOS.items():
        obs = 0
        for t in s["techniques"]:
            qui = sorted(noms_groupes[gid] for gid in tel if observee(t, utilise[gid]))
            obs += bool(qui)
            detail.append({"scenario": so, "technique": t, "nom": noms.get(t, "?"),
                           "observee": "oui" if qui else "non", "nb_groupes": len(qui),
                           "groupes": "; ".join(qui)})
        n = len(s["techniques"])
        cov = obs / n
        v0, g = s["vraisemblance"], s["gravite"]
        v1 = ajuster(v0, cov)
        synthese.append({"scenario": so, "nom": s["nom"], "source_de_risque": s["source"],
                         "techniques": n, "observees": obs, "couverture": round(cov, 2),
                         "vraisemblance_initiale": VRAISEMBLANCE[v0],
                         "vraisemblance_cti": VRAISEMBLANCE[v1],
                         "evolution": {1: "+1", 0: "=", -1: "-1"}[v1 - v0],
                         "gravite": GRAVITE[g],
                         "risque_initial": risque(v0, g), "risque_cti": risque(v1, g)})

    # 2. Angles morts : techniques (niveau parent) fréquentes chez les groupes
    #    télécom mais absentes de tous les scénarios.
    freq = defaultdict(set)
    for gid in tel:
        for t in utilise[gid]:
            freq[parent(t)].add(noms_groupes[gid])
    dans_so = {parent(t) for s in SCENARIOS.values() for t in s["techniques"]}
    seuil_freq = max(2, round(len(tel) / 3))           # utilisée par >= 1/3 des groupes
    angles_morts = sorted(
        ({"technique": t, "nom": noms.get(t, "?"), "nb_groupes": len(g),
          "part_groupes": round(len(g) / len(tel), 2), "groupes": "; ".join(sorted(g))}
         for t, g in freq.items() if t not in dans_so and len(g) >= seuil_freq),
        key=lambda x: -x["nb_groupes"])

    # 3. Priorisation des mesures (atelier 5) : mitigations ATT&CK couvrant le
    #    plus de techniques OBSERVÉES dans les scénarios.
    couvre = defaultdict(set)
    scen = defaultdict(set)
    for row in detail:
        if row["observee"] != "oui":
            continue
        t = row["technique"]
        mits = set(attenue.get(t, set())) | set(attenue.get(parent(t), set()))
        for m in mits:
            couvre[m].add(t)
            scen[m].add(row["scenario"])
    mitig = sorted(
        ({"mitigation": m[0], "nom": m[1], "nb_techniques": len(couvre[m]),
          "nb_scenarios": len(scen[m]), "scenarios": ", ".join(sorted(scen[m])),
          "techniques": ", ".join(sorted(couvre[m]))} for m in couvre),
        key=lambda x: (-x["nb_scenarios"], -x["nb_techniques"], x["mitigation"]))

    # 4. Couche ATT&CK Navigator (score = nombre de groupes télécom)
    so_par_tech = defaultdict(list)
    for so, s in SCENARIOS.items():
        for t in s["techniques"]:
            so_par_tech[t].append(so)
    couche = {
        "name": f"Telco - groupes télécom vs scénarios EBIOS RM (ATT&CK v{version})",
        "versions": {"attack": str(version).split(".")[0], "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Score = nombre de groupes ATT&CK ciblant les télécoms utilisant la "
                       "technique. Contour = technique présente dans un scénario opérationnel.",
        "techniques": [],
        "gradient": {"colors": ["#ffffff", "#f4a261", "#c1121f"], "minValue": 0,
                     "maxValue": max(len(g) for g in freq.values())},
        "legendItems": [{"label": "Technique d'un scénario opérationnel", "color": "#1d3557"}],
        "showTacticRowBackground": False, "selectTechniquesAcrossTactics": True,
    }
    toutes = set(freq) | {t for gid in tel for t in utilise[gid]} | set(so_par_tech)
    for t in sorted(toutes):
        nb = len({noms_groupes[gid] for gid in tel if observee(t, utilise[gid])})
        entree = {"techniqueID": t, "score": nb}
        if t in so_par_tech:
            entree["comment"] = "Scénarios : " + ", ".join(so_par_tech[t])
            entree["metadata"] = [{"name": "EBIOS RM", "value": ", ".join(so_par_tech[t])}]
        entree["showSubtechniques"] = False
        couche["techniques"].append(entree)

    # Écriture des fichiers
    def ecrire(nom, lignes):
        with open(sortie / nom, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=list(lignes[0].keys()), delimiter=";")
            w.writeheader()
            w.writerows(lignes)
    ecrire("1_synthese_scenarios.csv", synthese)
    ecrire("2_detail_techniques.csv", detail)
    ecrire("3_angles_morts.csv", angles_morts)
    ecrire("4_mitigations_prioritaires.csv", mitig)
    ecrire("0_groupes_telecom.csv", [{"groupe": noms_groupes[g], "nb_techniques": len(utilise[g])}
                                     for g in sorted(tel, key=lambda x: noms_groupes[x])])
    json.dump(couche, open(sortie / "couche_navigator.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    meta = {"version_attack": version, "nb_groupes_total": len(groupes),
            "nb_groupes_telecom": len(tel), "seuil_angles_morts": seuil_freq}
    json.dump(meta, open(sortie / "meta.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    return meta, synthese, detail, angles_morts, mitig


if __name__ == "__main__":
    meta, synthese, *_ = analyser(sys.argv[1], sys.argv[2])
    print(f"ATT&CK v{meta['version_attack']} : {meta['nb_groupes_telecom']} groupes télécom "
          f"sur {meta['nb_groupes_total']}")
    for s in synthese:
        print(f"{s['scenario']}  {s['observees']}/{s['techniques']} ({s['couverture']:.2f})  "
              f"{s['vraisemblance_initiale']} -> {s['vraisemblance_cti']}  "
              f"risque {s['risque_initial']} -> {s['risque_cti']}")
