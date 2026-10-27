"""PDF reports built from observed results. No executable content is embedded."""
from datetime import datetime
import json
from pathlib import Path
from uuid import uuid4
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import reportlab
from utils.storage import safe_name, write_json

PDF_DIR = Path(__file__).resolve().parent / "pdf"


class PDFReportGenerator:
    PREVIEW_LIMIT = 20

    @staticmethod
    def scan_summary(result):
        findings = result.get("threats", [])
        matches = sum(1 for item in findings if item.get("type") == "KNOWN_MALWARE")
        return {"Type": result.get("type", "INCONNU"),
                "Duree (secondes)": result.get("duration_sec", 0),
                "Fichiers traites (tentatives)": result.get("files_scanned", 0),
                "Fichiers lus": result.get("files_read", "Non mesure dans cette ancienne version"),
                "Alertes totalisees": result.get("threats_found", len(findings)),
                "Correspondances de signatures": matches,
                "Indices non confirmes a examiner": len(findings) - matches,
                "Erreurs": result.get("errors", 0), "Fichiers ignores": result.get("skipped", 0),
                "Annule": result.get("cancelled", False),
                "Profondeur rapide": result.get("max_directory_depth", "Non limitee pour ce scan"),
                "Sous-dossiers hors portee": result.get("directories_excluded", 0)}

    def _scan_sections(self, result):
        def priority(item):
            return (item.get("type") == "KNOWN_MALWARE", item.get("score", 0))
        findings = sorted(result.get("threats", []), key=priority, reverse=True)
        preview = [{"path": str(item.get("path", ""))[:360], "type": item.get("type", "?"),
                    "score_indicatif": item.get("score", 0),
                    "preuve": "Correspondance de signature" if item.get("type") == "KNOWN_MALWARE"
                    else "Indice non confirme; examen requis",
                    "notes": [str(note)[:160] for note in item.get("notes", [])[:3]]}
                   for item in findings[:self.PREVIEW_LIMIT]]
        return [("Bilan du scan", self.scan_summary(result)),
                ("Portee et limites", "Seuls les fichiers accessibles dans la portee choisie sont examines. "
                 "Un indice statique, un score ou une extension ne prouvent pas une infection. "
                 "Les fichiers sans alerte ne sont pas certifies sains."),
                ("Apercu des alertes", f"{len(preview)} sur {len(findings)} alertes affichees. "
                 "Les autres resultats et chemins complets figurent dans le JSON joint."),
                ("Alertes prioritaires", preview or "Aucune alerte retenue."),
                ("Apercu des erreurs", result.get("error_details", [])[:5])]

    def _write(self, title, sections, filename, raw_data=None):
        PDF_DIR.mkdir(parents=True, exist_ok=True)
        target = PDF_DIR / f"{safe_name(filename)}_{uuid4().hex[:12]}.pdf"
        styles = getSampleStyleSheet()
        # Embed the fonts shipped with ReportLab; no system font installation is required.
        font_dir = Path(reportlab.__file__).resolve().parent / "fonts"
        for name, source in (("CyberSans", "Vera.ttf"), ("CyberBold", "VeraBd.ttf")):
            if name not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont(name, str(font_dir / source)))
        for name in ("Normal", "BodyText", "Title", "Heading2"):
            styles[name].fontName = "CyberBold" if name in ("Title", "Heading2") else "CyberSans"
        styles.add(ParagraphStyle(name="CyberBody", parent=styles["BodyText"], fontSize=9, leading=13))
        styles.add(ParagraphStyle(name="CyberCode", fontName="Courier", fontSize=7.5, leading=10))
        sidecar = target.with_suffix(".json")
        payload = raw_data if raw_data is not None else {"sections": sections}
        # Preserve full details without turning thousands of findings into thousands of pages.
        write_json(sidecar, json.loads(json.dumps(payload, ensure_ascii=False, default=str)))
        story = [Paragraph(escape(title), styles["Title"]),
                 Paragraph(escape(f"CyberOS Security 2026.2.1 | {datetime.now():%Y-%m-%d %H:%M:%S}"),
                           styles["Normal"]), Spacer(1, 18)]
        story.append(Paragraph(escape("Donnees detaillees : " + sidecar.name), styles["CyberBody"]))
        for heading, value in sections:
            story.append(Paragraph(escape(str(heading)), styles["Heading2"]))
            if isinstance(value, (dict, list)):
                value = json.dumps(value, ensure_ascii=False, indent=2, default=str)
            # Literal text, bounded preview. The sidecar retains all original values.
            value = str(value)
            if len(value) > 16000:
                value = value[:16000] + "\n[Apercu abrege; details complets dans le JSON joint.]"
            lines = [line[i:i+108] for line in value.splitlines() for i in range(0, max(1, len(line)), 108)]
            story.append(Preformatted("\n".join(lines), styles["CyberCode"]))
            story.append(Spacer(1, 10))
        doc = SimpleDocTemplate(str(target), pagesize=A4, rightMargin=42, leftMargin=42,
                                topMargin=42, bottomMargin=42, title=title, author="CyberOS Security")
        def footer(canvas, document):
            canvas.setFillColor(colors.grey)
            canvas.setFont("Helvetica", 8)
            canvas.drawString(42, 24, "Observations partielles : ce rapport ne certifie pas l'absence de menace.")
            canvas.drawRightString(A4[0]-42, 24, str(document.page))
        doc.build(story, onFirstPage=footer, onLaterPages=footer)
        return str(target)

    def generate_evening_report(self, controller=None, report_type="SUMMARY"):
        if controller is None:
            raise ValueError("Contrôleur requis pour collecter les observations")
        status = controller.get_system_status()
        modules = getattr(controller, "_modules", {})
        sections = [("Portée", "État local au moment de la génération. Aucun nouveau scan de fichiers n'est lancé."),
                    ("Statut", status)]
        for name, method in (("quarantine", "get_stats"), ("integrity", "get_status"),
                             ("scheduler", "get_tasks"), ("auto_response", "get_status")):
            module = modules.get(name)
            if module and hasattr(module, method):
                sections.append((name, getattr(module, method)()))
        logs = controller.log.get_recent(30 if report_type == "SUMMARY" else 200)
        raw_sections = list(sections) + [("Journal recent", logs)]
        sections.append(("Journal recent (20 derniers messages)", [
            {k: item.get(k) for k in ("ts", "level", "msg")} for item in logs[-20:]]))
        return self._write("Rapport de sécurité local", sections, "CyberOS_local", {"sections": raw_sections})

    def generate_url_report(self, result):
        if not isinstance(result, dict) or not result.get("url"):
            raise ValueError("Résultat URL requis")
        return self._write("Analyse indicative d'une URL", [
            ("URL", result["url"]), ("Verdict", result.get("verdict", "INCONNU")),
            ("Score indicatif", result.get("score", 0)), ("Contrôles", result.get("checks", {})),
            ("Détails", result.get("details", {})), ("Limites", "Les heuristiques ne prouvent pas qu'un site est sûr.")],
            "CyberOS_URL", {"url_analysis": result})

    def generate_scan_report(self, result):
        if not isinstance(result, dict) or "files_scanned" not in result:
            raise ValueError("Résultat de scan requis")
        return self._write("Rapport de scan de fichiers", self._scan_sections(result),
                           "CyberOS_scan", {"scan": result})

    def generate_full_report(self, controller=None, scan_result=None, url_result=None):
        if controller is None:
            raise ValueError("Contrôleur requis")
        status = controller.get_system_status()
        logs = controller.log.get_recent(200)
        sections = [("Statut local", status)]
        sections.extend(self._scan_sections(scan_result) if scan_result else [
            ("Dernier scan", "Aucun scan disponible dans cette session.")])
        sections.append(("Derniere analyse URL", url_result if url_result else "Aucune analyse URL disponible dans cette session."))
        sections.append(("Journal recent (20 derniers messages)", [
            {k: item.get(k) for k in ("ts", "level", "msg")} for item in logs[-20:]]))
        return self._write("Rapport local complet", sections, "CyberOS_complet",
                           {"status": status, "scan": scan_result, "url_analysis": url_result, "logs": logs})

    def generate_report(self, controller=None, report_type="SUMMARY"):
        return self.generate_evening_report(controller, report_type)
