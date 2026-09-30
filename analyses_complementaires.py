"""
Analyses complémentaires (pour le chapitre Discussion)
=====================================================
Ces analyses ne modifient pas la cotation officielle (règles R1 à R5 de
cti_ebios.py). Elles servent à discuter la robustesse et les limites du résultat.

A. Sensibilité au seuil : une technique ne compte comme observée que si au
   moins 2 groupes télécom l'utilisent.
B. Correspondance source de risque / type de groupe : les scénarios du crime
   organisé (SR4) sont confrontés aux seuls groupes à motivation financière,
   ceux des groupes étatiques (SR5) aux seuls groupes d'espionnage.
   Classement manuel, à partir des fiches ATT&CK : Scattered Spider (G1015) et
   LAPSUS$ (G1004) sont à motivation financière ; les autres groupes télécom
   sont des groupes d'espionnage. APT41 (G0096), qui mène les deux types
   d'activité, est compté dans les deux catégories.
C. Veille continue : comparaison entre deux versions d'ATT&CK (15.1 et 19.2).
"""
import csv
import json
import sys
from pathlib import Path

from cti_ebios import (SCENARIOS, VRAISEMBLANCE, ajuster, charger, groupes_telecom,
                       id_attack, observee, risque)

FINANCIERS = {"G1015", "G1004", "G0096"}
ESPIONNAGE_EXCLUS = {"G1015", "G1004"}


def couverture(techniques, groupes_ids, utilise, seuil=1):
    obs = sum(1 for t in techniques
              if sum(observee(t, utilise[g]) for g in groupes_ids) >= seuil)
    return obs, len(techniques)


def analyse(chemin, sortie):
    version, groupes, utilise, _, _ = charger(chemin)
    tel = groupes_telecom(groupes)
    code = {gid: id_attack(g) for gid, g in tel.items()}
    fin = [g for g in tel if code[g] in FINANCIERS]
    esp = [g for g in tel if code[g] not in ESPIONNAGE_EXCLUS]
    lignes = []
    for so, s in SCENARIOS.items():
        v0 = s["vraisemblance"]
        o1, n = couverture(s["techniques"], tel, utilise, 1)
        o2, _ = couverture(s["techniques"], tel, utilise, 2)
        if s["source"].startswith("SR4"):
            cible, lib = fin, "groupes à motivation financière"
        elif s["source"].startswith("SR5"):
            cible, lib = esp, "groupes d'espionnage"
        else:
            cible, lib = None, "non applicable (source interne)"
        if cible is not None:
            o3, _ = couverture(s["techniques"], cible, utilise, 1)
            vb = VRAISEMBLANCE[ajuster(v0, o3 / n)]
            cb = f"{o3}/{n} ({o3 / n:.2f})"
        else:
            vb, cb = "—", "—"
        lignes.append({
            "scenario": so, "source": s["source"],
            "officiel_couverture": f"{o1}/{n} ({o1 / n:.2f})",
            "officiel_vraisemblance": VRAISEMBLANCE[ajuster(v0, o1 / n)],
            "A_seuil2_couverture": f"{o2}/{n} ({o2 / n:.2f})",
            "A_seuil2_vraisemblance": VRAISEMBLANCE[ajuster(v0, o2 / n)],
            "B_groupes_compares": lib, "B_couverture": cb, "B_vraisemblance": vb,
        })
    Path(sortie).mkdir(parents=True, exist_ok=True)
    with open(Path(sortie) / "5_analyses_sensibilite.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(lignes[0]), delimiter=";")
        w.writeheader()
        w.writerows(lignes)
    return version, {code[g]: tel[g]["name"] for g in tel}, lignes


def comparer_versions(ancien, recent, sortie):
    va, ga, ua, _, _ = charger(ancien)
    vr, gr, ur, _, _ = charger(recent)
    ta, trc = groupes_telecom(ga), groupes_telecom(gr)
    na = {id_attack(g): g["name"] for g in ta.values()}
    nr = {id_attack(g): g["name"] for g in trc.values()}
    lignes = []
    for so, s in SCENARIOS.items():
        for t in s["techniques"]:
            qa = sorted(id_attack(ta[g]) for g in ta if observee(t, ua[g]))
            qr = sorted(id_attack(trc[g]) for g in trc if observee(t, ur[g]))
            if qa != qr:
                lignes.append({"scenario": so, "technique": t,
                               f"groupes_v{va}": len(qa), f"groupes_v{vr}": len(qr),
                               "nouveaux_groupes": ", ".join(f"{nr[c]} ({c})" for c in qr if c not in qa)})
    with open(Path(sortie) / "6_evolution_versions.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(lignes[0]), delimiter=";")
        w.writeheader()
        w.writerows(lignes)
    ajoutes = {c: n for c, n in nr.items() if c not in na}
    retires = {c: n for c, n in na.items() if c not in nr}
    json.dump({"version_ancienne": va, "version_recente": vr,
               "groupes_telecom_ancienne": len(na), "groupes_telecom_recente": len(nr),
               "groupes_ajoutes": ajoutes, "groupes_retires": retires},
              open(Path(sortie) / "6_evolution_groupes.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    return ajoutes, retires, lignes


if __name__ == "__main__":
    v, groupes, lignes = analyse(sys.argv[2], sys.argv[3])
    for l in lignes:
        print(l)
    aj, ret, evo = comparer_versions(sys.argv[1], sys.argv[2], sys.argv[3])
    print("Ajoutés :", aj)
    print("Retirés :", ret)
    for e in evo:
        print(e)
