import copy
import ipaddress
"""
ELPATI URL SCANNER - Analyse de sites web style VirusTotal
100% local + IA hybride (locale ou Claude)
Vérifie : réputation, SSL, contenu, redirections, phishing, malware, blacklists
"""
import urllib.request, urllib.parse, urllib.error
import ssl, socket, hashlib, re, json, time, threading
from datetime import datetime
from pathlib import Path

# ─── BLACKLISTS LOCALES EMBARQUÉES ──────────────────────────────────────────
# Domaines malveillants connus (liste partielle, enrichissable)
MALICIOUS_DOMAINS = {
    # Phishing connus
    "paypa1.com", "paypai.com", "paypal-secure.com", "paypal-login.net",
    "appleid-verify.com", "apple-id-login.com", "icloud-verify.com",
    "google-security-alert.com", "gmail-login-secure.com",
    "facebook-login-secure.com", "fb-login-verify.com",
    "amazon-secure-login.com", "amazon-account-verify.net",
    "microsoft-security-alert.com", "office365-login.net",
    "netflix-billing-update.com", "netflix-account-verify.net",
    "bankofamerica-secure.com", "chase-secure-login.com",
    # Malware/C2 connus
    "malware-traffic-analysis.net", "evil.corp",
    "ransomware-c2.com", "botnet-controller.net",
    # Faux sites antivirus
    "windows-defender-alert.com", "virus-detected-now.com",
    "your-pc-is-infected.com", "scan-your-pc-free.com",
}

# TLDs et patterns suspects
SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
                   ".top", ".click", ".link", ".online", ".site", ".icu"}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "secure", "verify", "update", "confirm",
    "account", "password", "credential", "banking", "paypal",
    "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "support", "helpdesk", "alert", "suspended",
    "free", "winner", "prize", "urgent", "click-here",
]

SAFE_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "linkedin.com", "github.com", "wikipedia.org",
    "amazon.com", "microsoft.com", "apple.com", "netflix.com",
    "stackoverflow.com", "reddit.com", "twitch.tv", "discord.com",
    "anthropic.com", "openai.com", "cloudflare.com", "akamai.com",
}

class ElpatiURLScanner:
    def __init__(self):
        from elpati.elpati_log import ElpatiLog
        self.log = ElpatiLog()
        self._scan_history = []
        self._cache = {}  # Cache des scans récents
        self._cache_ttl = 300  # 5 minutes

    # ════════════════════════════════════════════════════════════════════
    #  POINT D'ENTRÉE PRINCIPAL
    # ════════════════════════════════════════════════════════════════════
    def scan_url(self, url: str, use_ai: bool = True) -> dict:
        """
        Analyse complète d'une URL — style VirusTotal.
        Retourne un rapport détaillé avec score de dangerosité.
        """
        url = self._normalize_url(url)
        if not url:
            return {"error": "URL invalide", "url": url}

        # Cache
        cache_key = hashlib.md5(url.encode()).hexdigest()
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if time.time() - cached["_cached_at"] < self._cache_ttl:
                cached = copy.deepcopy(cached)
                cached["from_cache"] = True
                return cached

        self.log.info(f"URL Scanner: Analyse de {url}")
        start = time.time()

        report = {
            "url": url,
            "domain": self._extract_domain(url),
            "scanned_at": datetime.utcnow().isoformat(),
            "checks": {},
            "score": 0,
            "verdict": "INCONNU",
            "verdict_color": "warning",
            "summary": [],
            "details": {},
            "from_cache": False,
        }

        # Lancer tous les contrôles
        domain = report["domain"]
        checks = {}

        checks["blacklist"]      = self._check_blacklist(url, domain)
        checks["domain_age"]     = self._check_domain_patterns(domain)
        parsed = urllib.parse.urlsplit(url)
        checks["ssl"] = (self._check_ssl(domain, parsed.port or 443) if parsed.scheme == "https" else
                         {"has_ssl": False, "valid": False, "score": 15,
                          "findings": ["URL HTTP sans chiffrement"], "cert_info": {}})
        checks["dns"]            = self._check_dns(domain)
        checks["redirects"]      = self._check_redirects(url)
        checks["content"]        = self._check_content(url)
        checks["reputation"]     = self._check_reputation(domain)
        checks["ip_geolocation"] = self._check_ip_geo(domain)
        checks["tech_stack"]     = self._analyze_headers(url)

        report["checks"] = checks
        report["details"] = self._build_details(checks, domain, url)

        # Score global
        score, flags = self._calculate_score(checks, domain, url)
        report["score"] = score
        report["summary"] = flags
        report["verdict"], report["verdict_color"] = self._score_to_verdict(score)
        report["scan_duration_ms"] = int((time.time() - start) * 1000)

        if not checks["dns"].get("resolved") or not checks["content"].get("reachable"):
            report["incomplete"] = True
            if score < 60:
                report["verdict"], report["verdict_color"] = "INCONCLUSIF — contrôles réseau incomplets", "warning"
        else:
            report["incomplete"] = False

        # Analyse IA
        if use_ai:
            report["ai_analysis"] = self._ai_analyze(report)

        # Historique
        self._scan_history.insert(0, {
            "url": url, "score": score,
            "verdict": report["verdict"],
            "ts": report["scanned_at"]
        })
        self._scan_history = self._scan_history[:50]

        # Cache
        report["_cached_at"] = time.time()
        self._cache[cache_key] = copy.deepcopy(report)

        self.log.audit(f"URL Scanner: {url} → {report['verdict']} (score={score})")
        return report

    # ════════════════════════════════════════════════════════════════════
    #  CONTRÔLES INDIVIDUELS
    # ════════════════════════════════════════════════════════════════════

    def _check_blacklist(self, url: str, domain: str) -> dict:
        """Vérifie contre les blacklists locales."""
        result = {"passed": True, "score": 0, "findings": []}

        # Blacklist domaines malveillants
        if domain in MALICIOUS_DOMAINS:
            result["passed"] = False
            result["score"] = 100
            result["findings"].append(f"Domaine dans la blacklist locale: {domain}")
            return result

        # Vérifier sous-domaines
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in MALICIOUS_DOMAINS:
                result["passed"] = False
                result["score"] = 90
                result["findings"].append(f"Domaine parent dans la blacklist: {parent}")
                return result

        # Patterns d'URL malveillantes
        url_lower = url.lower()
        malicious_patterns = [
            r"\.exe\?",          # Executable déguisé
            r"invoice.*\.php",   # Fausse facture
            r"download.*free",   # Faux téléchargement
            r"\.php\?id=\d+&redirect=",  # Open redirect
            r"base64",           # Payload encodé
            r"%2f%2f",           # Double slash encodé
            r"javascript:",      # XSS
            r"data:text/html",   # Data URI
            r"\.\./\.\./",       # Path traversal
        ]
        for pattern in malicious_patterns:
            if re.search(pattern, url_lower):
                result["score"] = max(result["score"], 70)
                result["findings"].append(f"Pattern malveillant dans l'URL: {pattern}")

        if result["findings"]:
            result["passed"] = False
        return result

    def _check_domain_patterns(self, domain: str) -> dict:
        """Analyse les patterns suspects du domaine."""
        result = {"passed": True, "score": 0, "findings": [], "age_estimate": "inconnu"}

        # Domaine sûr connu
        if domain in SAFE_DOMAINS or any(domain.endswith("." + d) for d in SAFE_DOMAINS):
            result["score"] = 0
            result["findings"].append("Domaine de confiance vérifié")
            return result

        # TLD suspect
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                result["score"] += 25
                result["findings"].append(f"TLD suspect: {tld}")

        # Mots-clés suspects dans le domaine
        domain_lower = domain.lower()
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in domain_lower:
                result["score"] += 15
                result["findings"].append(f"Mot-clé suspect: '{kw}'")
                break  # Un seul warning par domaine

        # Domaine très long (souvent phishing)
        base = domain.split(".")[0] if "." in domain else domain
        if len(base) > 25:
            result["score"] += 20
            result["findings"].append(f"Nom de domaine anormalement long ({len(base)} chars)")

        # Trop de tirets (phishing classique)
        if domain.count("-") >= 3:
            result["score"] += 15
            result["findings"].append(f"Nombreux tirets dans le domaine ({domain.count('-')} tirets)")

        # Chiffres dans le domaine (souvent auto-générés)
        if sum(c.isdigit() for c in base) > 3:
            result["score"] += 10
            result["findings"].append("Beaucoup de chiffres dans le domaine")

        # Imitation de marque connue (typosquatting)
        brands = ["google", "facebook", "amazon", "apple", "microsoft",
                  "paypal", "netflix", "instagram", "twitter", "youtube"]
        for brand in brands:
            if brand in domain_lower and domain_lower != f"{brand}.com":
                result["score"] += 40
                result["findings"].append(f"Possible typosquatting de '{brand}'")
                break

        if result["score"] > 0:
            result["passed"] = False
        return result

    def _check_ssl(self, domain: str, port=443) -> dict:
        """Vérifie le certificat SSL."""
        result = {
            "has_ssl": False, "valid": False, "score": 0,
            "findings": [], "cert_info": {}
        }
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((domain, port), timeout=5),
                server_hostname=domain
            ) as sock:
                cert = sock.getpeercert()
                result["has_ssl"] = True
                result["valid"] = True

                # Extraire infos certificat
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))
                result["cert_info"] = {
                    "subject":    subject.get("commonName", "?"),
                    "issuer":     issuer.get("organizationName", "?"),
                    "expires":    cert.get("notAfter", "?"),
                    "san":        [v for _, v in cert.get("subjectAltName", [])],
                }
                result["findings"].append(f"SSL valide — Émetteur: {issuer.get('organizationName','?')}")

                # Certificat auto-signé (pas de CA reconnu)
                known_cas = ["Let's Encrypt", "DigiCert", "Sectigo", "GlobalSign",
                             "Comodo", "GeoTrust", "Thawte", "VeriSign", "Google"]
                issuer_name = issuer.get("organizationName", "")
                if not any(ca in issuer_name for ca in known_cas):
                    result["score"] += 20
                    result["findings"].append(f"CA peu connue: {issuer_name}")

        except ssl.SSLCertVerificationError as e:
            result["has_ssl"] = True
            result["valid"] = False
            result["score"] = 50
            result["findings"].append(f"Certificat SSL invalide: {str(e)[:80]}")
        except (socket.timeout, ConnectionRefusedError, OSError):
            # Pas de SSL sur port 443 — peut être HTTP seul
            result["score"] = 15
            result["findings"].append("Pas de SSL détecté (connexion HTTP non chiffrée)")
        except Exception as e:
            result["findings"].append(f"Vérification SSL impossible: {str(e)[:60]}")
        return result

    def _check_dns(self, domain: str) -> dict:
        """Résolution DNS et analyse."""
        result = {"resolved": False, "ips": [], "score": 0, "findings": []}
        try:
            ips = socket.getaddrinfo(domain, None)
            unique_ips = list(set(info[4][0] for info in ips))
            result["resolved"] = True
            result["ips"] = unique_ips[:5]

            # IPs privées dans un domaine public (suspect)
            for ip in unique_ips:
                if ipaddress.ip_address(ip).is_private:
                    result["score"] += 30
                    result["findings"].append(f"Résolution vers IP privée: {ip}")

            result["findings"].append(f"Résolu → {', '.join(unique_ips[:3])}")
        except socket.gaierror:
            result["score"] = 60
            result["findings"].append("DNS: domaine introuvable (NXDOMAIN)")
        except Exception as e:
            result["findings"].append(f"DNS: {str(e)[:60]}")
        return result

    def _check_redirects(self, url):
        result = {"redirect_count": 0, "chain": [], "score": 0, "findings": []}
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(NoRedirect())
        current = url
        for _ in range(10):
            if current in result["chain"]:
                result["score"] = max(25, result["score"])
                result["findings"].append("Boucle de redirection")
                break
            result["chain"].append(current)
            try:
                req = urllib.request.Request(current, method="HEAD",
                    headers={"User-Agent": "CyberOS-Scanner/2026.2.1"})
                with opener.open(req, timeout=5):
                    break
            except urllib.error.HTTPError as exc:
                if exc.code not in (301, 302, 303, 307, 308):
                    result["findings"].append(f"HTTP {exc.code}")
                    break
                location = exc.headers.get("Location")
                if not location:
                    break
                target = self._normalize_url(urllib.parse.urljoin(current, location))
                if not target:
                    result["score"] = 80
                    result["findings"].append("Destination de redirection invalide")
                    break
                if self._extract_domain(target) in MALICIOUS_DOMAINS:
                    result["score"] = 100
                    result["findings"].append("Redirection vers la liste noire locale")
                current = target
            except Exception as exc:
                result["error"] = str(exc)[:100]
                break
        result["redirect_count"] = max(0, len(result["chain"]) - 1)
        if result["redirect_count"] >= 4:
            result["score"] = max(result["score"], 25)
            result["findings"].append("Chaîne de redirections longue")
        return result

    def _check_content(self, url: str) -> dict:
        """Analyse le contenu HTML de la page."""
        result = {"reachable": False, "score": 0, "findings": [],
                  "page_title": "", "forms": 0, "external_resources": []}
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 CyberOS-Scanner/2026",
                         "Accept": "text/html,application/xhtml+xml"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                result["reachable"] = True
                result["http_status"] = resp.status
                content = resp.read(100 * 1024).decode("utf-8", errors="replace")

                # Titre de la page
                title_m = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
                if title_m:
                    result["page_title"] = title_m.group(1).strip()[:100]

                # Formulaires (potentiel phishing)
                forms = re.findall(r"<form[^>]*>", content, re.IGNORECASE)
                result["forms"] = len(forms)
                if len(forms) > 0:
                    # Formulaire avec champ password = potentiel vol de mdp
                    if re.search(r'type=["\']password["\']', content, re.IGNORECASE):
                        result["score"] += 20
                        result["findings"].append("Formulaire avec champ mot de passe détecté")

                # Scripts externes suspects
                ext_scripts = re.findall(r'src=["\']https?://([^/"\'>]+)', content, re.IGNORECASE)
                result["external_resources"] = list(set(ext_scripts))[:10]

                # Mots-clés phishing dans le contenu
                phishing_kw = ["enter your password", "verify your account",
                               "your account has been suspended", "confirm your identity",
                               "entrez votre mot de passe", "vérifiez votre compte",
                               "compte suspendu", "confirmez votre identité",
                               "credit card", "carte bancaire", "numéro de carte"]
                for kw in phishing_kw:
                    if kw.lower() in content.lower():
                        result["score"] += 25
                        result["findings"].append(f"Contenu phishing: '{kw}'")
                        break

                # Obfuscation JavaScript
                if content.count("eval(") > 2 or content.count("unescape(") > 2:
                    result["score"] += 35
                    result["findings"].append("JavaScript obfusqué détecté (eval/unescape excessif)")

                # Iframes cachées
                hidden_iframes = re.findall(
                    r'<iframe[^>]*(width=["\']0["\']|height=["\']0["\']|display:none)[^>]*>',
                    content, re.IGNORECASE)
                if hidden_iframes:
                    result["score"] += 40
                    result["findings"].append(f"Iframe(s) cachée(s) détectée(s): {len(hidden_iframes)}")

                # Auto-download
                if re.search(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*url=.*\.(exe|zip|rar|bat)',
                             content, re.IGNORECASE):
                    result["score"] += 60
                    result["findings"].append("Téléchargement automatique de fichier exécutable")

                if not result["findings"]:
                    result["findings"].append(f"Contenu analysé ({len(content):,} chars) — aucun pattern suspect")

        except urllib.error.URLError as e:
            result["findings"].append(f"Site inaccessible: {str(e.reason)[:80]}")
            result["score"] += 10
        except Exception as e:
            result["findings"].append(f"Erreur contenu: {str(e)[:80]}")
        return result

    def _check_reputation(self, domain: str) -> dict:
        """Évalue la réputation globale du domaine."""
        result = {"score": 0, "findings": [], "category": "inconnu"}

        if domain in SAFE_DOMAINS or any(domain.endswith("." + d) for d in SAFE_DOMAINS):
            result["category"] = "Domaine de confiance"
            result["findings"].append("Domaine reconnu comme fiable")
            return result

        # Âge estimé du domaine via pattern
        parts = domain.split(".")
        base = parts[0] if parts else domain

        # Domaines récemment enregistrés ont souvent des noms courts aléatoires
        if len(base) <= 4 and base.isalpha():
            result["score"] += 5
            result["findings"].append("Nom de domaine très court (potentiellement DGA)")

        # Vérifier les sous-domaines profonds (phishing souvent utilise sub.sub.domaine.com)
        if len(parts) > 4:
            result["score"] += 20
            result["findings"].append(f"Beaucoup de sous-domaines imbriqués ({len(parts)} niveaux)")

        # Catégorisation basique par mots-clés
        categories = {
            "banking":    ["bank", "banque", "credit", "loan", "finance", "invest"],
            "shopping":   ["shop", "store", "buy", "deal", "discount", "promo"],
            "adult":      ["xxx", "porn", "adult", "sex", "cam"],
            "gambling":   ["casino", "bet", "poker", "gambling", "slot"],
            "crypto":     ["crypto", "bitcoin", "ethereum", "nft", "token", "wallet"],
        }
        for cat, keywords in categories.items():
            if any(kw in domain.lower() for kw in keywords):
                result["category"] = cat
                result["findings"].append(f"Catégorie détectée: {cat}")
                if cat in ("adult", "gambling"):
                    result["score"] += 10
                break

        if not result["findings"]:
            result["findings"].append("Réputation neutre — domaine non répertorié")
        return result

    def _check_ip_geo(self, domain: str) -> dict:
        """Géolocalisation approximative de l'IP."""
        result = {"ip": "", "country": "inconnu", "findings": []}
        try:
            ip = socket.gethostbyname(domain)
            result["ip"] = ip

            # Détection basique par plage IP (quelques pays à haut risque connus)
            high_risk_ranges = [
                ("185.220.", "Réseau Tor/anonymiseur"),
                ("194.165.", "Hébergement bulletproof"),
                ("45.142.",  "Réseau suspect connu"),
            ]
            for prefix, note in high_risk_ranges:
                if ip.startswith(prefix):
                    result["findings"].append(f"IP dans plage à risque: {note}")
                    result["score"] = 40
                    break
            if not result["findings"]:
                result["findings"].append(f"IP résolue: {ip}")
        except Exception as e:
            result["findings"].append(f"Géoloc impossible: {str(e)[:60]}")
        return result

    def _analyze_headers(self, url: str) -> dict:
        """Analyse les en-têtes HTTP de sécurité."""
        result = {"score": 0, "findings": [], "headers": {}, "missing_security_headers": []}
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 CyberOS-Scanner/2026"},
                method="HEAD"
            )
            with urllib.request.urlopen(req, timeout=6) as resp:
                headers = dict(resp.headers)
                result["headers"] = {k: v[:100] for k, v in headers.items()}
                result["http_status"] = resp.status

                # En-têtes de sécurité importants
                security_headers = {
                    "Strict-Transport-Security": "HSTS (force HTTPS)",
                    "Content-Security-Policy":   "CSP (anti-XSS)",
                    "X-Frame-Options":           "Anti-clickjacking",
                    "X-Content-Type-Options":    "Anti-MIME sniffing",
                    "X-XSS-Protection":          "Protection XSS navigateur",
                    "Referrer-Policy":           "Contrôle référent",
                }
                missing = []
                for hdr, desc in security_headers.items():
                    if not any(hdr.lower() == k.lower() for k in headers):
                        missing.append(f"{hdr} ({desc})")
                result["missing_security_headers"] = missing
                if len(missing) >= 4:
                    result["score"] += 15
                    result["findings"].append(f"{len(missing)} en-têtes de sécurité manquants")
                elif len(missing) == 0:
                    result["findings"].append("Tous les en-têtes de sécurité présents ✓")

                # Détection technologie (Server header)
                server = headers.get("Server", headers.get("server", ""))
                if server:
                    result["findings"].append(f"Serveur: {server[:50]}")
                powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
                if powered:
                    result["findings"].append(f"Technologie: {powered[:50]}")
        except Exception as e:
            result["findings"].append(f"Analyse headers: {str(e)[:80]}")
        return result

    # ════════════════════════════════════════════════════════════════════
    #  CALCUL DU SCORE GLOBAL
    # ════════════════════════════════════════════════════════════════════

    def _calculate_score(self, checks: dict, domain: str, url: str) -> tuple:
        """Agrège tous les scores en un score global 0-100."""
        total = 0
        flags = []

        weights = {
            "blacklist":      2.0,
            "domain_age":     1.5,
            "ssl":            1.0,
            "dns":            1.2,
            "redirects":      1.0,
            "content":        1.8,
            "reputation":     1.0,
            "ip_geolocation": 0.8,
            "tech_stack":     0.5,
        }

        for check_name, weight in weights.items():
            check = checks.get(check_name, {})
            s = check.get("score", 0)
            if s > 0:
                total += s * weight
                for finding in check.get("findings", []):
                    if s > 20 and finding not in flags:
                        flags.append(finding)

        # Known malicious indicators must never be diluted by unrelated clean checks.
        blacklist = checks.get("blacklist", {}).get("score", 0)
        if blacklist >= 90:
            return 100, checks["blacklist"].get("findings", [])[:10]
        final = min(max(int(total / sum(weights.values())), int(blacklist)), 100)
        if checks.get("content", {}).get("score", 0) >= 50:
            final = max(final, 60)
        return final, flags[:10]

    def _score_to_verdict(self, score: int) -> tuple:
        if score == 0:   return "AUCUN INDICATEUR RELEVE",          "success"
        if score <= 20:  return "RISQUE INDICATIF FAIBLE", "success"
        if score <= 40:  return "🟡 À SURVEILLER",  "warning"
        if score <= 60:  return "🟠 SUSPECT",        "warning"
        if score <= 80:  return "🔴 DANGEREUX",      "danger"
        return               "💀 MALVEILLANT",       "danger"

    # ════════════════════════════════════════════════════════════════════
    #  ANALYSE IA
    # ════════════════════════════════════════════════════════════════════

    def _ai_analyze(self, report: dict) -> dict:
        """Analyse IA du rapport — locale ou Claude."""
        try:
            from core.ai_core import AICore
            ai = AICore()

            context = {
                "type": "url_scan",
                "url": report["url"],
                "domain": report["domain"],
                "local_score": report["score"],
                "indicators": {
                    "in_blacklist":     report["checks"].get("blacklist", {}).get("score", 0) > 50,
                    "suspicious_domain":report["checks"].get("domain_age", {}).get("score", 0) > 30,
                    "invalid_ssl":      not report["checks"].get("ssl", {}).get("valid", True),
                    "phishing_content": report["checks"].get("content", {}).get("score", 0) > 30,
                    "suspicious_redirects": report["checks"].get("redirects", {}).get("redirect_count", 0) > 3,
                    "known_malicious":  report["checks"].get("blacklist", {}).get("score", 0) >= 90,
                },
                "behavior": {
                    "has_password_form": "mot de passe" in str(report["checks"].get("content", {}).get("findings", [])).lower(),
                    "many_redirects": report["checks"].get("redirects", {}).get("redirect_count", 0) > 3,
                }
            }
            return ai.analyze_threat(context)
        except Exception as e:
            return {"source": "LOCAL_AI", "score": report["score"],
                    "verdict": report["verdict"], "explanation": str(e)[:100]}

    # ════════════════════════════════════════════════════════════════════
    #  UTILITAIRES
    # ════════════════════════════════════════════════════════════════════

    def _normalize_url(self, url):
        url = str(url).strip()
        if not url or any(ord(c) < 32 or c.isspace() for c in url):
            return ""
        if "://" not in url:
            if ":" in url and not url.rsplit(":", 1)[-1].split("/", 1)[0].isdigit():
                return ""
            url = "https://" + url
        try:
            parts = urllib.parse.urlsplit(url)
            if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
                return ""
            if parts.port is not None and not 1 <= parts.port <= 65535:
                return ""
            host = parts.hostname.encode("idna").decode("ascii")
            if ":" in host:
                host = "[" + host + "]"
            if parts.port:
                host += ":" + str(parts.port)
            return urllib.parse.urlunsplit((parts.scheme, host, parts.path or "/", parts.query, ""))
        except (ValueError, UnicodeError):
            return ""

    def _extract_domain(self, url):
        try:
            host = urllib.parse.urlsplit(url).hostname or ""
            host = host.lower().rstrip(".")
            return host[4:] if host.startswith("www.") else host
        except ValueError:
            return ""

    def _build_details(self, checks: dict, domain: str, url: str) -> dict:
        """Construit le dictionnaire de détails pour l'affichage."""
        return {
            "domain":           domain,
            "url_length":       len(url),
            "has_ssl":          checks.get("ssl", {}).get("valid", False),
            "ssl_issuer":       checks.get("ssl", {}).get("cert_info", {}).get("issuer", "?"),
            "dns_ips":          checks.get("dns", {}).get("ips", []),
            "dns_resolved":     checks.get("dns", {}).get("resolved", False),
            "redirect_chain":   checks.get("redirects", {}).get("chain", []),
            "redirect_count":   checks.get("redirects", {}).get("redirect_count", 0),
            "page_title":       checks.get("content", {}).get("page_title", ""),
            "http_status":      checks.get("content", {}).get("http_status", 0),
            "forms_count":      checks.get("content", {}).get("forms", 0),
            "external_res":     checks.get("content", {}).get("external_resources", []),
            "missing_headers":  checks.get("tech_stack", {}).get("missing_security_headers", []),
            "server":           checks.get("tech_stack", {}).get("headers", {}).get("Server", "?"),
            "ip":               checks.get("ip_geolocation", {}).get("ip", "?"),
            "category":         checks.get("reputation", {}).get("category", "inconnu"),
        }

    def get_history(self, n: int = 20) -> list:
        return self._scan_history[:n]

    def clear_cache(self):
        self._cache.clear()
