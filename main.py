#!/usr/bin/env python3
"""
    python cyber_parser.py collect [--full] [--sources cert telegram]
    python cyber_parser.py calibrate      # авто-поріг за еталонним джерелом
    python cyber_parser.py rescore        # перерахунок score без повторного збору
    python cyber_parser.py cluster        # дедуплікація між джерелами
    python cyber_parser.py export         # docs.jsonl + events.jsonl
"""
import argparse
import hashlib
import json
import logging
import re
import sqlite3
import time
import unicodedata
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
from bs4 import BeautifulSoup
from dateutil import parser as dtparser
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Конфігурація
DB_PATH = "cyber.db"
RAW_DIR = Path("raw")
SINCE = datetime(2022, 2, 24, tzinfo=timezone.utc)
SINCE_ISO = SINCE.isoformat(timespec="seconds")
MAX_PAGES = 2000
SLEEP = 1.0
DEFAULT_THRESHOLD = 10
KYIV = ZoneInfo("Europe/Kyiv")
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36 (academic-research)"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler("parser.log", encoding="utf-8"), logging.StreamHandler()],
)
log = logging.getLogger("cyber")


def to_utc_iso(value):
    if value is None or value == "":
        return None
    try:
        s = str(value).strip()
        if s.isdigit() and len(s) >= 10:
            n = int(s)
            dt = datetime.fromtimestamp(n / 1000 if len(s) >= 13 else n, tz=timezone.utc)
        else:
            dt = dtparser.parse(s)
    except (ValueError, OverflowError, OSError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=KYIV)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def normalize(text):
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text).replace("\xa0", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


URL_RE = re.compile(r"https?://\S+|hxxps?://\S+")


def fingerprint(text):
    # Хеш нормалізованого тексту (нижній регістр, без посилань і пунктуації)
    t = URL_RE.sub(" ", text.lower())
    t = re.sub(r"[^\w]+", " ", t).strip()
    return hashlib.md5(t.encode("utf-8")).hexdigest()


def url_id(url):
    return hashlib.md5(url.encode("utf-8")).hexdigest()[:16]


def detect_lang(text):
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return "unknown"
    cyr = sum("\u0400" <= c <= "\u04ff" for c in letters) / len(letters)
    if cyr > 0.5:
        return "uk/ru"
    return "en" if cyr < 0.1 else "mixed"


def make_session():
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    retry = Retry(total=5, backoff_factor=1.5, status_forcelist=[429, 500, 502, 503, 504],
                  allowed_methods=["GET"], respect_retry_after_header=True)
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def save_raw(category, doc_id, content, ext):
    if content is None:
        return None
    d = RAW_DIR / category
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{doc_id}.{ext}"
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content, encoding="utf-8")
    return str(p)


# Словники
def compile_term(t):
    return re.compile(rf"\b{t[:-1]}\b" if t.endswith("$") else rf"\b{t}", re.I)


CYBER_THREATS = [
    "кібератак", "кіберінцидент", "кіберзагроз", "кібершпигун", r"кібер\w*(?:операц|злочин)",
    "malware", r"шкідлив\w+\s+(?:програм|код|файл|по$)", "хакер", "злам", "експлойт", "exploit$",
    "вразливіст", "бекдор", "backdoor", "ботнет", "троян", "wiper", "stealer", "rootkit",
    "rat$", "c2$", r"командн\w+\s+сервер", r"сервер\w*\s+управлін", "кібербезпек",
]
ATTACK_TYPES = [
    "фішинг", "phishing", "спуфінг", "ddos", "dos$", "ransomware", r"програм\w*-?вимагач",
    "шифрувальник", "брутфорс", r"sql.?injection", "xss$", r"zero.?day", r"0-?day",
    "дефейс", "defacement", r"ланцюг\w*\s+постачан", r"supply.?chain", r"man.in.the.middle",
    "mitm$", r"перехоплен\w+\s+(?:трафік|даних|сесі)",
]
ATTACK_ACTIONS = [
    "проникнен", "несанкціонован", "компрометац", r"отримал\w*\s+доступ", "закріпленн",
    "ексфільтрац", r"викрад\w+\s+(?:дан|інформац|облікових|баз)", "шифруванн",
    r"знищенн\w+\s+(?:дан|інформац)", r"ескалаці\w+\s+привілей", r"латеральн", "зловмисник",
]
THREAT_ACTORS = [
    r"apt\s?\d*$", r"хакерськ\w+\s+угруповань", "кіберугрупован", "кіберзлочин",
    r"спонсован\w+\s+держав", r"російськ\w+\s+хакер", r"китайськ\w+\s+хакер",
    "sandworm", "gamaredon", "turla", r"fancy\s+bear", r"cozy\s+bear", r"uac-\d", r"unc\d{3,4}",
    "killnet", "noname057", "lockbit", "xaknet", "cyberarmy",
]
IMPACTS = [
    r"витік\w*\s+(?:даних|інформац|персональн|баз|документ)", r"злив\w*\s+(?:даних|баз|інформац)",
    "знеструмлен", "блекаут", "збій", "недоступн", "паралізува",
    r"зупинк\w+\s+(?:робот|систем|виробництв)", "відключен", r"порушен\w+\s+робот",
    r"втрат\w+\s+(?:даних|доступ)", r"розкритт\w+\s+(?:даних|інформац)", r"оприлюдн\w+\s+(?:дан|документ)",
]
INFO_OPS = [
    "іпсо", "ботоферм", "дезінформац", "фейк", "пропаганд", "наратив", "маніпуляц", "вкид",
    r"психологічн\w+\s+(?:операц|вплив)", "fimi", r"інформаційн\w+\s+(?:операц|вплив|війн|атак)",
]
TECHNOLOGY = [
    "scada", "асутп", "ics$", "plc$", "плк$", "hmi$", "vpn$", "rdp$", "ssh$", r"active\s+directory",
    r"domain\s+controller", "exchange$", "zimbra", "firewall", "маршрутизатор", "router$",
    "mikrotik", "мікротік", "cisco", "fortinet", "fortigate", "ivanti", "citrix", "хмарн", "cloud$",
    "windows", "linux", r"баз\w+\s+даних", "сервер",
]
LEAK_TERMS = [
    r"витік\w*\s+(?:даних|інформац|персональн|баз|документ)", r"злив\w*\s+(?:даних|баз|інформац)",
    "дамп", r"data.?leak", r"data.?breach", r"викрад\w+\s+(?:дан|баз|документ)",
    r"оприлюдн\w+\s+(?:дан|документ)",
]
PHYSICAL_TERMS = [
    "знеструмлен", "блекаут", r"відключен\w+\s+(?:електро|світл|опален|вод)",
    r"зупинк\w+\s+(?:виробництв|підстанц|турбін)", "аварі", r"пошкодженн\w+\s+обладнан",
    "scada", "асутп", "plc$", "плк$",
]
KINETIC_NOISE = [
    "мобілізац", "тцк", "ухилянт", "вбивств", "дтп", "хабар", "корупці", "нарко", "кол-центр",
    "крадіжк", "ґвалтуван", "держзрад", "колаборант", "митниц", "контрабанд", "тендер", "податк",
    "олігарх", "вибор", "голосуван", "депутат", "гуманітар", "біженц", "пенсі", "пільг",
    "шахед", "ракетн", "обстріл", "снаряд", "артилері", "штурм", "загинул", "поранен",
    "кіберпес", "кіберкіт", "шахрайгудбай", "форум", "вебінар", "тренінг", "онлайн-курс",
    "курсу", "сніданок", "день науки", "подкаст"
]
SECTORS = {
    "energy": ["обленерго", "укренерго", "енергосектор", "енергетичн", "енергокомпан", "дтек", "нафтогаз",
               "укргазвидобут", "аес$", "тец$", "тес$", "гес$", "підстанці", "електромереж", "енергосистем"],
    "telecom": ["телеком", "провайдер", "київстар", "vodafone", "lifecell", "укртелеком",
                r"оператор\w*\s+(?:зв.язку|мобільн)", r"базов\w+\s+станці"],
    "finance": [r"банк(?!рут)", "ощадбанк", "приватбанк", "монобанк", "нбу$", "платіжн", "фінансов"],
    "transport": ["залізниц", "укрзалізниц", "аеропорт", "логістик", "метро$", "нова\\s+пошта", "укрпошт"],
    "government": ["міністерств", "кабмін", r"кабінет\w*\s+міністрів", r"державн\w+\s+реєстр",
                   r"(?:додаток|портал|застосунок)\s+«?дія", "міськрад", "обладміністрац", "міноборони",
                   r"органи\s+державн", "держспецзв"],
    "healthcare": ["лікарн", "медичн", r"охорон\w+\s+здоров", "госпітал"],
    "water": ["водоканал", "водопостач", "водовідвед", "водогін"],
    "industry_ics": ["scada", "асутп", "плк$", "plc$", "hmi$", "ics$", "промислов", "виробництв"],
}
CRITICAL_INFRA_GENERIC = [r"критичн\w+\s+інфраструктур", "об.єкт\\w*\\s+критичн"]

CREDENTIAL_RE = re.compile(r"парол|логін|облікові\s+дані|credentials|токен|ключ\w*\s+доступ", re.I)
PERSONAL_RE = re.compile(r"персональн\w+\s+дан|паспорт|\bіпн\b|номер\w*\s+телефон|прізвищ", re.I)
TOPOLOGY_RE = re.compile(r"схем\w+\s+мереж|топологі|hostname|ip-?адрес|внутрішн\w+\s+(?:мереж|ip)", re.I)
DUMP_RE = re.compile(r"дамп|баз\w+\s+даних|злив", re.I)


def extract_iocs(text):
    t = text.replace("[.]", ".").replace("(.)", ".").replace("hxxp", "http")
    ips = [ip for ip in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", t))
           if all(int(o) <= 255 for o in ip.split("."))]
    return {
        "cve": sorted({m.upper() for m in re.findall(r"cve-\d{4}-\d{4,7}", t, re.I)}),
        "ipv4": sorted(ips),
        "hash": sorted({m.lower() for m in re.findall(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", t, re.I)}),
        "uac_groups": sorted({m.upper() for m in re.findall(r"\buac-\d{4}\b", t, re.I)}),
        "cert_refs": sorted(set(re.findall(r"CERT-UA#\d+", t, re.I))),
        "attack_ttp": sorted(set(re.findall(r"\bT[01]\d{3}(?:\.\d{3})?\b", t))),
    }


class Analyzer:
    CAP = 3

    def __init__(self):
        c = lambda lst: [(t, compile_term(t)) for t in lst]
        self.cats = {
            "threats": (4, c(CYBER_THREATS)), "attacks": (5, c(ATTACK_TYPES)),
            "actions": (3, c(ATTACK_ACTIONS)), "actors": (4, c(THREAT_ACTORS)),
            "tech": (3, c(TECHNOLOGY)), "impacts": (4, c(IMPACTS)), "info_ops": (4, c(INFO_OPS)),
        }
        self.leak = c(LEAK_TERMS)
        self.physical = c(PHYSICAL_TERMS)
        self.noise = c(KINETIC_NOISE)
        self.sectors = {k: c(v) for k, v in SECTORS.items()}
        self.infra_generic = c(CRITICAL_INFRA_GENERIC)

    @staticmethod
    def _hits(text, comp):
        return [t for t, rx in comp if rx.search(text)]

    def analyze(self, text):
        low = text.lower()
        h = {name: self._hits(low, comp) for name, (_, comp) in self.cats.items()}
        leak = self._hits(low, self.leak)
        physical = self._hits(low, self.physical)
        noise = self._hits(low, self.noise)
        sectors = {k: hs for k, comp in self.sectors.items() if (hs := self._hits(low, comp))}
        infra_generic = self._hits(low, self.infra_generic)
        iocs = extract_iocs(text)
        n_ioc = sum(len(v) for k, v in iocs.items() if k in ("cve", "ipv4", "hash"))

        core = bool(h["threats"] or h["attacks"] or h["actors"] or n_ioc or iocs["uac_groups"])
        ipso = bool(h["info_ops"] and (core or h["tech"] or (sectors and h["impacts"])))
        gate = core or ipso or bool(leak)

        score = sum(min(len(h[n]), self.CAP) * w for n, (w, _) in self.cats.items())
        n_infra = sum(len(v) for v in sectors.values()) + len(infra_generic)
        score += min(n_infra, self.CAP) * 3
        if "cert-ua" in low or "нкцк" in low:
            score += 10
        if core and (sectors or infra_generic):
            score += 10
        if ipso:
            score += 10
        score += min(n_ioc + len(iocs["uac_groups"]), 5) * 4
        score -= min(len(noise), 3) * 5

        event_hints = []
        if h["attacks"] or h["actions"] or h["threats"]:
            event_hints.append("cyber_incident")
        if leak:
            event_hints.append("data_leak")
        if ipso or h["info_ops"]:
            event_hints.append("info_operation")
        if re.search(r"cve-\d|вразливіст|zero.?day|0-?day", low):
            event_hints.append("vulnerability")
        if re.search(r"ddos", low):
            event_hints.append("ddos")

        if n_ioc or iocs["uac_groups"]:
            detail = 3
        elif iocs["attack_ttp"] or len(h["tech"]) >= 2 or (h["attacks"] and h["tech"]):
            detail = 2
        elif core:
            detail = 1
        else:
            detail = 0
        sens_flags = {
            "iocs": bool(n_ioc), "credentials": bool(CREDENTIAL_RE.search(text)),
            "personal_data": bool(PERSONAL_RE.search(text)), "topology": bool(TOPOLOGY_RE.search(text)),
            "dump": bool(DUMP_RE.search(text)),
        }
        prefeatures = {
            "sectors": sorted(sectors), "event_type_hints": event_hints,
            "technical_detail_hint": detail,
            "sensitivity_flags": sens_flags,
            "sensitivity_hint": min(sum(sens_flags.values()), 3),
            "physical_effect_hint": bool(physical), "physical_terms": physical,
        }
        return {
            "score": score, "gate": gate, "iocs": iocs, "sectors": sorted(sectors),
            "indicators": {**h, "leak": leak, "infra": {**sectors}, "noise": noise, "gate": gate},
            "prefeatures": prefeatures,
        }


class Store:
    def __init__(self, path=DB_PATH):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS docs(
                id TEXT PRIMARY KEY, source_category TEXT, source_name TEXT, url TEXT,
                published_at TEXT, collected_at TEXT, title TEXT, text TEXT, text_hash TEXT,
                lang TEXT, trusted INTEGER, score INTEGER, is_candidate INTEGER,
                event_id TEXT, meta TEXT);
            CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY, value TEXT);
            CREATE INDEX IF NOT EXISTS ix_pub ON docs(published_at);
            CREATE INDEX IF NOT EXISTS ix_event ON docs(event_id);
        """)

    def seen(self, doc_id):
        return self.db.execute("SELECT 1 FROM docs WHERE id=?", (doc_id,)).fetchone() is not None

    def upsert(self, r):
        cols = ["id", "source_category", "source_name", "url", "published_at", "collected_at", "title",
                "text", "text_hash", "lang", "trusted", "score", "is_candidate", "event_id", "meta"]
        self.db.execute(f"INSERT OR REPLACE INTO docs({','.join(cols)}) VALUES({','.join(':' + c for c in cols)})", r)
        self.db.commit()

    def threshold(self):
        row = self.db.execute("SELECT value FROM kv WHERE key='threshold'").fetchone()
        return int(row["value"]) if row else DEFAULT_THRESHOLD

    def set_threshold(self, v):
        self.db.execute("INSERT OR REPLACE INTO kv VALUES('threshold',?)", (str(v),))
        self.db.commit()

    def stats(self):
        q = lambda s: self.db.execute(s).fetchone()[0]
        return {"total": q("SELECT COUNT(*) FROM docs"),
                "candidates": q("SELECT COUNT(*) FROM docs WHERE is_candidate=1")}


class Collector:
    def __init__(self, store, analyzer, full=False):
        self.store, self.analyzer, self.full = store, analyzer, full
        self.session = make_session()

    def fetch(self, url, **kw):
        try:
            r = self.session.get(url, timeout=50, **kw)
        except requests.RequestException as e:
            log.error("Запит не вдався %s: %s", url, e)
            return None
        time.sleep(SLEEP)
        return r

    def ingest(self, category, source, url, published, title, text, trusted=False,
               extra=None, raw=None, raw_ext="html"):
        title, text = normalize(title), normalize(text)
        if len(text) < 30:
            return False
        doc_id = url_id(url)
        a = self.analyzer.analyze(f"{title}\n\n{text}")
        cand = bool(trusted or (a["gate"] and a["score"] >= self.store.threshold()))
        meta = {"indicators": a["indicators"], "iocs": a["iocs"], "sectors": a["sectors"],
                "prefeatures": a["prefeatures"], "raw_path": save_raw(category, doc_id, raw, raw_ext),
                **(extra or {})}
        self.store.upsert({
            "id": doc_id, "source_category": category, "source_name": source, "url": url,
            "published_at": published, "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "title": title, "text": text, "text_hash": fingerprint(text), "lang": detect_lang(text),
            "trusted": int(trusted), "score": a["score"], "is_candidate": int(cand),
            "event_id": None, "meta": json.dumps(meta, ensure_ascii=False)})
        return cand


class CertUA(Collector):
    LIST = "https://cert.gov.ua/api/articles/all?page={page}&lang=uk"
    DETAIL = "https://cert.gov.ua/api/articles/byId?id={id}&lang=uk"
    PAGE = "https://cert.gov.ua/article/{id}"
    HDR = {"Accept": "application/xml, text/xml, */*"}

    def collect(self):
        log.info("CERT-UA: старт (full=%s)", self.full)
        added = 0
        for page in range(20):
            r = self.fetch(self.LIST.format(page=page), headers=self.HDR)
            if r is None or r.status_code != 200:
                log.warning("CERT-UA список: недоступно (стор. %s)", page)
                break
            try:
                root = ET.fromstring(r.content)
            except ET.ParseError as e:
                log.error("CERT-UA XML стор. %s: %s", page, e)
                continue
            items = root.findall("./items/items")
            if not items:
                break
            if page == 0:
                log.info("CERT-UA: статей в архіві: %s", root.findtext("count"))
            n_old = n_seen = 0
            for item in items:
                aid = (item.findtext("id") or "").strip()
                if not aid:
                    continue
                pub = to_utc_iso(item.findtext("date"))
                if pub and pub < SINCE_ISO:
                    n_old += 1
                    continue
                front = self.PAGE.format(id=aid)
                if not self.full and self.store.seen(url_id(front)):
                    n_seen += 1
                    continue
                title = (item.findtext("title") or "").strip()
                text = BeautifulSoup(item.findtext("description") or "", "html.parser").get_text("\n", strip=True)
                raw = None
                d = self.fetch(self.DETAIL.format(id=aid), headers=self.HDR)


                if d is not None and d.status_code == 200:
                    try:
                        body = ""
                        content_type = d.headers.get("Content-Type", "").lower()


                        if "application/json" in content_type or d.text.strip().startswith("{"):
                            d_json = d.json()
                            if "data" in d_json and isinstance(d_json["data"], dict):
                                body = d_json["data"].get("body") or d_json["data"].get("content") or ""
                            else:
                                body = d_json.get("body") or d_json.get("content") or d_json.get("text") or ""


                        else:
                            droot = ET.fromstring(d.content)
                            body = droot.findtext(".//body") or droot.findtext(".//content") or droot.findtext(
                                ".//text") or ""

                        if body:
                            text = BeautifulSoup(body, "html.parser").get_text("\n", strip=True)
                        raw = d.content
                    except Exception as e:
                        log.warning("CERT-UA деталь %s: помилка розбору %s (беремо description)", aid, e)
                else:
                    log.warning("CERT-UA деталь %s недоступна", aid)

                tags = [t.findtext("name") for t in item.findall("./tags/tags") if t.findtext("name")]
                self.ingest("Gov_CERT", "CERT-UA", front, pub, title, f"{title}\n\n{text}",
                            trusted=True, extra={"cert_tags": tags}, raw=raw, raw_ext="xml")
                added += 1
            log.info("CERT-UA стор. %s: нових %s, старих %s, вже було %s", page,
                     len(items) - n_old - n_seen, n_old, n_seen)
            if n_old == len(items):
                break
            if not self.full and n_seen == len(items):
                break
        log.info("CERT-UA: додано %s", added)


class TelegramGov(Collector):
    CHANNELS = {"Держспецзв'язку": "dsszzi_official", "СБУ": "SBUkr", "Кіберполіція": "CyberpolUA"}
    DAYS_BACK = 100

    def collect(self):
        for name, channel in self.CHANNELS.items():
            self.collect_channel(name, channel)

    def collect_channel(self, name, channel):
        since_dt = datetime.now(timezone.utc) - timedelta(days=self.DAYS_BACK)
        since_iso = since_dt.isoformat(timespec="seconds")
        log.info("Telegram: %s (@%s) — ліміт збору від %s", name, channel, since_iso[:10])

        url, visited, added = f"https://t.me/s/{channel}", set(), 0
        for page in range(MAX_PAGES):
            r = self.fetch(url)
            if r is None or r.status_code != 200:
                log.warning("Telegram %s: статус %s", channel, getattr(r, "status_code", None))
                break
            soup = BeautifulSoup(r.text, "html.parser")
            msgs = soup.select("div.tgme_widget_message")
            if not msgs:
                break
            unseen = 0
            for msg in msgs:
                date_a = msg.select_one("a.tgme_widget_message_date")
                time_tag = date_a.select_one("time") if date_a else None
                pub = to_utc_iso(time_tag.get("datetime")) if time_tag else None

                if pub and pub < since_iso:
                    continue
                text_div = msg.select_one("div.tgme_widget_message_text")
                if not text_div:
                    continue
                post_url = date_a["href"] if date_a and date_a.get("href") else f"https://t.me/{channel}"
                if not self.full and self.store.seen(url_id(post_url)):
                    continue
                unseen += 1
                text = text_div.get_text("\n", strip=True)
                title = normalize(text).split("\n")[0][:120]
                if self.ingest("Gov_Security", name, post_url, pub, title, text, raw=str(msg)):
                    added += 1
            first = msgs[0].get("data-post", "")
            first_date = msgs[0].select_one("a.tgme_widget_message_date time")
            oldest_pub = to_utc_iso(first_date.get("datetime")) if first_date else None
            if "/" not in first:
                break
            oldest_id = first.split("/")[-1]
            if oldest_id in visited or oldest_id == "1":
                break
            visited.add(oldest_id)

            if oldest_pub and oldest_pub < since_iso:
                log.info("Telegram %s: досягнуто межу  (%s). Зупинка пагінації.", channel, oldest_pub[:10])
                break
            if not self.full and unseen == 0:
                break
            if page % 5 == 0:
                log.info("Telegram %s: стор. %s, найстаріший пост %s", channel, page + 1, oldest_pub)
            url = f"https://t.me/s/{channel}?before={oldest_id}"
        log.info("Telegram %s: кандидатів додано %s", channel, added)


def cmd_calibrate(store):
    rows = store.db.execute("SELECT score FROM docs WHERE trusted=1").fetchall()
    scores = sorted(r["score"] for r in rows)
    if len(scores) < 20:
        log.warning("Замало довірених документів (%s) для калібрування", len(scores))
        return
    p10 = scores[int(0.10 * (len(scores) - 1))]
    thr = max(6, min(15, p10))
    store.set_threshold(thr)
    untrusted = store.db.execute("SELECT score FROM docs WHERE trusted=0").fetchall()
    share = sum(r["score"] >= thr for r in untrusted) / max(len(untrusted), 1)
    log.info("Поріг=%s (p10 довірених=%s, медіана=%s). Частка решти документів вище порога: %.1f%%",
             thr, p10, scores[len(scores) // 2], share * 100)
    cmd_rescore(store)


def cmd_rescore(store):
    an, thr = Analyzer(), store.threshold()
    rows = store.db.execute("SELECT id, title, text, trusted, meta FROM docs").fetchall()
    for r in rows:
        a = an.analyze(f"{r['title']}\n\n{r['text']}")
        meta = json.loads(r["meta"] or "{}")
        meta.update({"indicators": a["indicators"], "iocs": a["iocs"], "sectors": a["sectors"],
                     "prefeatures": a["prefeatures"]})
        cand = int(bool(r["trusted"] or (a["gate"] and a["score"] >= thr)))
        store.db.execute("UPDATE docs SET score=?, is_candidate=?, meta=? WHERE id=?",
                         (a["score"], cand, json.dumps(meta, ensure_ascii=False), r["id"]))
    store.db.commit()
    log.info("Перераховано %s документів, поріг=%s. %s", len(rows), thr, store.stats())


# дедуплікація між джерелами
def cmd_cluster(store, threshold=0.5, window_days=7):
    from sklearn.feature_extraction.text import TfidfVectorizer
    rows = store.db.execute(
        "SELECT id, title, text, text_hash, published_at FROM docs WHERE is_candidate=1").fetchall()
    n = len(rows)
    if n == 0:
        log.warning("Немає кандидатів для кластеризації")
        return
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    def ts(i):
        p = rows[i]["published_at"]
        return datetime.fromisoformat(p) if p else None

    times = [ts(i) for i in range(n)]
    win = timedelta(days=window_days)

    by_hash = {}
    for i, r in enumerate(rows):
        if r["text_hash"] in by_hash:
            union(by_hash[r["text_hash"]], i)
        else:
            by_hash[r["text_hash"]] = i

    docs = [f"{r['title']}\n{URL_RE.sub(' ', r['text'])[:4000]}" for r in rows]
    X = TfidfVectorizer(sublinear_tf=True, ngram_range=(1, 2), max_df=0.8).fit_transform(docs)
    B = 500
    for s in range(0, n, B):
        sim = (X[s:s + B] @ X.T).tocoo()
        for a, b, v in zip(sim.row, sim.col, sim.data):
            a += s
            if a >= b or v < threshold:
                continue
            if times[a] and times[b] and abs(times[a] - times[b]) > win:
                continue
            union(a, b)

    groups = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)
    for members in groups.values():
        first = min(members, key=lambda i: rows[i]["published_at"] or "9999")
        ev = "EV-" + hashlib.md5(rows[first]["id"].encode()).hexdigest()[:10]
        for i in members:
            store.db.execute("UPDATE docs SET event_id=? WHERE id=?", (ev, rows[i]["id"]))
    store.db.commit()
    log.info("Кластеризація: %s публікацій -> %s подій (поріг схожості %.2f, вікно ±%s дн.)",
             n, len(groups), threshold, window_days)


def cmd_export(store, docs_path="docs.jsonl", events_path="events.jsonl"):
    rows = store.db.execute("SELECT * FROM docs WHERE is_candidate=1 ORDER BY published_at").fetchall()
    events = {}
    with open(docs_path, "w", encoding="utf-8") as f:
        for r in rows:
            d = dict(r)
            d["meta"] = json.loads(d["meta"] or "{}")
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
            e = events.setdefault(d["event_id"] or f"SINGLE-{d['id']}", [])
            e.append(d)
    with open(events_path, "w", encoding="utf-8") as f:
        for ev, ds in events.items():
            ds.sort(key=lambda x: x["published_at"] or "")
            rep = max(ds, key=lambda x: len(x["text"]))
            union = lambda key: sorted({v for x in ds for v in x["meta"]["iocs"].get(key, [])})
            pre = [x["meta"]["prefeatures"] for x in ds]
            f.write(json.dumps({
                "event_id": ev,
                "first_published": ds[0]["published_at"], "last_published": ds[-1]["published_at"],
                "n_publications": len(ds), "sources": sorted({x["source_name"] for x in ds}),
                "n_sources": len({x["source_name"] for x in ds}),
                "urls": [x["url"] for x in ds],
                "iocs": {k: union(k) for k in ("cve", "ipv4", "hash", "uac_groups", "cert_refs", "attack_ttp")},
                "sectors_hint": sorted({s for p in pre for s in p["sectors"]}),
                "event_type_hints": sorted({t for p in pre for t in p["event_type_hints"]}),
                "technical_detail_hint": max(p["technical_detail_hint"] for p in pre),
                "sensitivity_hint": max(p["sensitivity_hint"] for p in pre),
                "physical_effect_hint": any(p["physical_effect_hint"] for p in pre),
                "title": rep["title"], "text": rep["text"],
            }, ensure_ascii=False) + "\n")
    log.info("Експорт: %s публікацій -> %s, %s подій -> %s", len(rows), docs_path, len(events), events_path)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--full", action="store_true", help="ігнорувати seen і збирати все заново")
    c.add_argument("--sources", nargs="+", default=["cert", "telegram"],
                   choices=["cert", "telegram"])
    sub.add_parser("calibrate")
    sub.add_parser("rescore")
    cl = sub.add_parser("cluster")
    cl.add_argument("--threshold", type=float, default=0.5)
    cl.add_argument("--window", type=int, default=7)
    sub.add_parser("export")
    args = ap.parse_args()

    store = Store()
    if args.cmd == "collect":
        an = Analyzer()
        classes = {"cert": CertUA, "telegram": TelegramGov}
        for s in args.sources:
            classes[s](store, an, full=args.full).collect()
        log.info("Підсумок: %s", store.stats())
    elif args.cmd == "calibrate":
        cmd_calibrate(store)
    elif args.cmd == "rescore":
        cmd_rescore(store)
    elif args.cmd == "cluster":
        cmd_cluster(store, args.threshold, args.window)
    elif args.cmd == "export":
        cmd_export(store)


if __name__ == "__main__":
    main()