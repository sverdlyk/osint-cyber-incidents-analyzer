#!/usr/bin/env python3
import json
import logging
import time
import requests
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("llm_extractor")

MODEL_NAME = "qwen2.5:7b"
OLLAMA_URL = "http://127.0.0.1:11434/api/chat"


MAX_NUM_CTX = 6144


ENGLISH_TAXONOMY_MAP = {
    "event_type": {
        "фішинг": "phishing",
        "шкідливе ПЗ": "malware",
        "програмне вимагання": "ransomware",
        "деструктивна діяльність": "data_destruction",
        "несанкціонований доступ": "unauthorized_access",
        "поширення шкідливого ПЗ": "malware_distribution",
        "витік даних": "data_exfiltration",
        "DDoS": "ddos",
        "дефейсмент": "defacement",
        "інформаційна операція": "information_operation",
        "фізичний вплив": "physical_impact",
        "інше": "other"
    },
    "attack_vector": {
        "фішинг": "phishing",
        "експлуатація вразливості": "vulnerability_exploitation",
        "шкідливе ПЗ": "malware",
        "викрадення облікових даних": "credential_theft",
        "компрометація облікового запису": "account_compromise",
        "підбір паролів": "brute_force",
        "постачальник": "supply_chain",
        "фізичний доступ": "physical_access",
        "інформаційна операція": "information_operation",
        "невідомо": "unknown",
        "інше": "other"
    },
    "sector": {
        "енергетика": "energy",
        "телеком": "telecom",
        "фінанси": "finance",
        "транспорт": "transport",
        "державний сектор": "government",
        "оборона та військові": "defense",
        "юстиція та суди": "justice",
        "охорона здоров'я": "healthcare",
        "водопостачання": "water_supply",
        "промисловість": "industrial",
        "медіа": "media",
        "невідомо": "unknown"
    }
}

ALLOWED_EVENT_TYPES = set(ENGLISH_TAXONOMY_MAP["event_type"].keys())
ALLOWED_ATTACK_VECTORS = set(ENGLISH_TAXONOMY_MAP["attack_vector"].keys())
ALLOWED_SECTORS = set(ENGLISH_TAXONOMY_MAP["sector"].keys())

TYPE_TO_SECTOR_MAPPING = {
    "телеком": ["телеком", "провайдер", "оператор", "мобільний", "інтернет", "зв'язок"],
    "енергетика": ["енергетич", "електростанц", "аес", "тец", "обленерго", "підстанц"],
    "фінанси": ["банк", "фінансов", "платіжн", "страхов"],
    "транспорт": ["транспорт", "залізниц", "аеропорт", "пошт", "логістик", "метро"],
    "оборона та військові": ["міноборони", "зсу", "військ", "генштаб", "delta", "розвідк"],
    "юстиція та суди": ["суд", "нотаріат", "юстиці", "прокуратур"],
    "державний сектор": ["державн", "міністерств", "орган влади", "реєстр", "урядов"],
    "охорона здоров'я": ["лікарн", "медичн", "госпітал", "клінік", "поліклінік", "оздоров"],
    "водопостачання": ["водоканал", "водопостач", "водовідвед"],
    "промисловість": ["scada", "асутп", "плк", "завод", "фабрик", "виробництв", "ics"],
    "медіа": ["медіа", "новин", "агентств", "телеканал", "радіо", "прес"]
}

SECTOR_KEYWORDS = {
    "енергетика": ["укренерго", "дтек", "обленерго", "аес", "тец", "підстанц", "енергосистем"],
    "телеком": ["ukr.net", "київстар", "vodafone", "lifecell", "укртелеком"],
    "фінанси": ["приватбанк", "ощадбанк", "нбу", "monobank", "монобанк"],
    "транспорт": ["укрзалізниц", "укрпошт", "нова пошта", "аеропорт"],
    "оборона та військові": ["міноборони", "зсу", "генштаб", "delta"],
    "юстиція та суди": ["печерський", "нотаріат"],
    "державний сектор": ["кабмін", "дія", "рада"],
    "охорона здоров'я": ["лікарн", "медичн", "госпітал"],
    "медіа": ["укрінформ", "тсн", "телеканал", "радіо"]
}


SECTOR_HINT_MAP = {
    "government": "державний сектор",
    "finance": "фінанси",
    "telecom": "телеком",
    "industry_ics": "промисловість",
    "healthcare": "охорона здоров'я",
    "energy": "енергетика",
    "transport": "транспорт",
    "water": "водопостачання",
    "defense": "оборона та військові",
    "justice": "юстиція та суди",
    "media": "медіа",
}


EVENT_TYPE_HINT_MAP = {
    "ddos": "DDoS",
    "data_leak": "витік даних",
    "info_operation": "інформаційна операція",
}


TRUSTED_SOURCE_KEYWORDS = ["cert", "сбу", "дссззі", "кіберполіція", "держспецзв'язку", "держспецзв'язок"]

SYSTEM_PROMPT = """Ти — професійний аналітик з кібербезпеки (Threat Intelligence). Твоє завдання — екстрагувати факти з технічного звіту CERT-UA.
Формат відповіді: СТРОГО валідний JSON. 
Мова відповідей (окрім назв ПЗ та хакерських угруповань): ВИКЛЮЧНО УКРАЇНСЬКА. АБСОЛЮТНО ЗАБОРОНЕНО використовувати англійські слова (напр., "Unknown", "User", "System", "Government", "Software") у полях target_entity, target_type та confirmed_impact.

КРОК 1: ВИЗНАЧ РЕЛЕВАНТНІСТЬ
is_relevant_cyber_incident = true, якщо текст містить опис КОНКРЕТНОЇ хакерської атаки, кампанії шкідливого ПЗ, несанкціонованого доступу або експлуатації вразливості проти українських чи іноземних цілей.
is_relevant_cyber_incident = false, якщо це організаційне повідомлення, загальні рекомендації, правила кіберзахисту або загальний огляд діяльності угруповання без опису конкретної нової атаки.

КРОК 2: ЕКСТРАКЦІЯ ФАКТІВ
1. target_entity (Конкретна назва цілі/жертви):
   - ТІЛЬКИ унікальна назва організації-ЖЕРТВИ (напр. "ПриватБанк", "Укрінформ").
   - ЗВЕРНИ УВАГУ: Організації, ВІД ІМЕНІ яких розсилається фішинг (наприклад, "від імені Держспецзв'язку", "імітує сайт UKR.NET", "від імені Печерського суду") — це ПРИМАНКИ (spoofing), а НЕ жертви. Їх ЗАБОРОНЕНО вказувати сюди!
   - ЗАБОРОНЕНО писати абстракції: "System", "Computer", "Unknown", "Infrastructure".
   - Якщо назва реальної жертви прихована або не вказана явно → пиши СТРОГО "невідомо".

2. target_type (Категорія жертви):
   - Ширша категорія ВИКЛЮЧНО УКРАЇНСЬКОЮ (напр. "державна установа", "телекомунікаційний оператор", "військове формування", "судова установа").
   - ЖОДНОЇ англійської мови. Якщо незрозуміло → "невідомо".

3. sector (Сектор критичної інфраструктури):
   - Обери ОДНЕ: енергетика, телеком, фінанси, транспорт, державний сектор, оборона та військові, юстиція та суди, охорона здоров'я, водопостачання, промисловість, медіа, невідомо.

4. attack_vector (Вектор атаки):
   - Обери ОДНЕ: фішинг, експлуатація вразливості, шкідливе ПЗ, викрадення облікових даних, підбір паролів, компрометація облікового запису, постачальник, фізичний доступ, інформаційна операція, невідомо, інше.

5. event_type (Тип кіберподії):
   - Обери ОДНЕ найголовніше:
     1. фішинг (тільки масова розсилка без зараження)
     2. шкідливе ПЗ (інфікування бекдорами, стілерами, троянами)
     3. програмне вимагання (шифрувальники, ransomware)
     4. деструктивна діяльність (wiper, знищення/затирання файлів: CaddyWiper, RoarBat, Somnia)
     5. несанкціонований доступ (злам мережі, RDP, VPN)
     6. поширення шкідливого ПЗ
     7. витік даних
     8. DDoS
     9. дефейсмент
     10. інформаційна операція
     11. фізичний вплив
     12. інше

6. threat_actor (Атакуюче угруповання):
   - ТІЛЬКИ назва групи (напр. "UAC-0056", "APT28", "Sandworm"). Якщо не вказано → пиши "невідомо".

7. technical_detail_level: 1 (загальний опис), 2 (назви ПЗ/методів), 3 (наявність IOC, хешів, IP-адрес).
8. confirmed_impact: ТЕКСТОВИЙ опис ПІДТВЕРДЖЕНИХ НАСЛІДКІВ виключно українською (напр. "компрометація систем та мережі", "знищення даних"). ЗАБОРОНЕНО використовувати англійські слова.
9. is_impact_confirmed: true якщо успішний збій/компрометація/знищення відбулися; false якщо це лише спроба або попередження.

Текст для аналізу:
{text}
"""

JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "is_relevant_cyber_incident": {"type": "boolean"},
        "rejection_reason": {"type": "string"},
        "target_entity": {"type": "string"},
        "target_type": {"type": "string"},
        "sector": {"type": "string"},
        "attack_vector": {"type": "string"},
        "event_type": {"type": "string"},
        "threat_actor": {"type": "string"},
        "technical_detail_level": {"type": "integer"},
        "confirmed_impact": {"type": "string"},
        "is_impact_confirmed": {"type": "boolean"}
    },
    "required": [
        "is_relevant_cyber_incident", "rejection_reason", "target_entity", "target_type",
        "sector", "attack_vector", "event_type", "threat_actor", "technical_detail_level",
        "confirmed_impact", "is_impact_confirmed"
    ]
}


def sanitize_extracted_data(extracted: dict) -> dict:
    actor = str(extracted.get("threat_actor", "невідомо")).strip()
    actor_lower = actor.lower()

    import re
    actor = re.sub(r'\s*\[\d+\]', '', actor)
    if any(w in actor_lower for w in
           ["unknown", "unspecified", "not specified", "apt group", "advanced persistent threat",
            "cyber threat group"]):
        extracted["threat_actor"] = "невідомо"
    else:
        extracted["threat_actor"] = actor

    t_type = str(extracted.get("target_type", "невідомо")).strip()
    bad_entities = ["unknown", "system", "computer", "user", "device", "organization", "infrastructure", "software",
                    "victim", "neither"]
    if any(w in t_type.lower() for w in bad_entities):
        extracted["target_type"] = "невідомо"

    impact = str(extracted.get("confirmed_impact", "")).strip()
    if any(w in impact.lower() for w in
           ["exfiltration", "compromise", "potential", "data loss", "high", "severe", "prevented", "remote access"]):
        if "exfiltration" in impact.lower() or "витік" in impact.lower():
            extracted["confirmed_impact"] = "витік або несанкціонований доступ до даних"
        else:
            extracted["confirmed_impact"] = "компрометація систем та мережі"

    return extracted


def normalize_confirmed_impact(impact_text: str, event_type: str, is_confirmed: bool) -> str:
    lower = impact_text.lower()

    if lower in ["false", "true", "none", "невідомо", "", "робочих станцій", "high"]:
        if not is_confirmed:
            return "невідомо"
        if event_type == "шкідливе ПЗ":
            return "ураження систем шкідливим ПЗ"
        if event_type == "програмне вимагання":
            return "шифрування даних та вимагання викупу"
        if event_type == "деструктивна діяльність":
            return "деструктивне знищення файлів та даних"
        if event_type == "несанкціонований доступ":
            return "несанкціонований віддалений доступ до систем"
        if event_type == "дефейсмент":
            return "несанкціонована зміна вмісту веб-ресурсу"
        if event_type == "фішинг":
            return "фішингова розсилка"
        if event_type == "DDoS":
            return "порушення доступності сервісів"
        return "компрометація інфраструктури"

    if any(w in lower for w in ["знищ", "затер", "деструктив", "wipe", "пошкодженн"]):
        return "деструктивне знищення файлів та даних"
    if any(w in lower for w in ["витік", "крадіж", "злит", "оприлюднен", "exfiltration"]):
        return "витік або несанкціонований доступ до даних"
    if any(w in lower for w in ["ddos", "доступність", "відмова", "навантаж"]):
        return "порушення доступності / DDoS-атака"
    if any(w in lower for w in ["компрометаці", "уражен", "заражен", "інфікуван", "compromise"]):
        return "компрометація систем та мережі"
    if any(w in lower for w in ["розсил", "фішинг", "лист"]):
        return "розповсюдження фішингових повідомлень"

    return impact_text.strip()


def determine_sector(target_entity: str, target_type: str, llm_sector_guess: str, sectors_hint=None) -> str:
    type_lower = str(target_type).lower()
    entity_lower = str(target_entity).lower()

    for sector, keywords in TYPE_TO_SECTOR_MAPPING.items():
        if any(kw in type_lower for kw in keywords):
            return sector

    for sector, keywords in SECTOR_KEYWORDS.items():
        if any(kw in entity_lower for kw in keywords):
            return sector

    if sectors_hint:
        for hint in sectors_hint:
            mapped = SECTOR_HINT_MAP.get(str(hint).lower())
            if mapped:
                return mapped

    if entity_lower in ("", "невідомо", "unknown", "none", "не визначено"):
        return "невідомо"

    return llm_sector_guess if llm_sector_guess in ALLOWED_SECTORS else "невідомо"


def calculate_preliminary_impact(event_type: str, is_confirmed: bool, impact_text: str) -> int:
    impact_lower = str(impact_text).lower()
    event_lower = str(event_type).lower()
    score = 0

    if event_lower == "фізичний вплив":
        score = 8
    elif event_lower == "деструктивна діяльність":
        score = 7 if is_confirmed else 4
    elif event_lower == "програмне вимагання":
        score = 6 if is_confirmed else 3
    elif event_lower == "несанкціонований доступ":
        score = 5 if is_confirmed else 2
    elif event_lower == "витік даних":
        score = 4 if is_confirmed else 2
    elif event_lower == "шкідливе пз":
        score = 3 if is_confirmed else 1
    elif event_lower == "дефейсмент":
        score = 2 if is_confirmed else 1
    elif event_lower == "ddos":
        score = 2 if is_confirmed else 1
    elif event_lower in ["фішинг", "поширення шкідливого пз"]:
        score = 1
    else:
        score = 1

    if is_confirmed:
        physical_keywords = ["scada", "асутп", "плк", "обладнан", "зупинк", "блекаут", "знеструмлен", "технологічн", "виробництв"]
        if any(word in impact_lower for word in physical_keywords):
            score = max(score, 8)

    return max(0, min(10, score))


def clean_model_artifacts(text: str) -> str:
    if not isinstance(text, str):
        return text
    text = text.replace("шкідлива програма", "шкідливе ПЗ").replace("инше", "інше")
    text = text.replace("кибератака", "кібератака").replace("шкірлив", "шкідлив")
    return text.strip()


def clean_markdown(response_text: str) -> str:
    clean = response_text.strip()
    if clean.startswith("```json"):
        clean = clean[7:]
    if clean.endswith("```"):
        clean = clean[:-3]
    return clean.strip()


def format_ioc_list(items, limit=15):
    items = [str(x) for x in items] if items else []
    if not items:
        return "невідомо"
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" ... (ще {len(items) - limit})"


def estimate_prompt_tokens(text: str) -> int:

    return int(len(text) / 2.3)


def pick_num_ctx(prompt_text: str, num_predict: int = 600) -> int:
    needed = estimate_prompt_tokens(prompt_text) + num_predict + 256
    for bucket in (2048, 4096, MAX_NUM_CTX):
        if needed <= bucket:
            return bucket
    return MAX_NUM_CTX


def process_events(input_file: str = "events.jsonl",
                   output_file: str = "enriched_events.jsonl",
                   rejected_file: str = "rejected_events.jsonl",
                   failed_file: str = "failed_events.jsonl"):
    input_path = Path(input_file)
    if not input_path.exists():
        log.error("Файл %s не знайдено.", input_file)
        return

    try:
        requests.post(OLLAMA_URL,
                      json={"model": MODEL_NAME, "messages": [{"role": "user", "content": "test"}], "stream": False},
                      timeout=60)
        log.info(f"Модель {MODEL_NAME} підключена.")
    except Exception as e:
        log.error(f"Помилка підключення до Ollama: {e}")
        return

    processed_ids = set()
    for filepath in [output_file, rejected_file]:
        fpath = Path(filepath)
        if fpath.exists():
            with open(fpath, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        if "event_id" in data:
                            processed_ids.add(data["event_id"])
                    except (json.JSONDecodeError, KeyError):
                        pass
    log.info(f"Пропущено вже оброблених: {len(processed_ids)}")

    stats = {"accepted": 0, "rejected": 0, "failed": 0, "skipped": 0}

    with open(input_path, "r", encoding="utf-8") as fin, \
            open(output_file, "a", encoding="utf-8") as fout_enriched, \
            open(rejected_file, "a", encoding="utf-8") as fout_rejected, \
            open(failed_file, "a", encoding="utf-8") as fout_failed:

        for line_num, line in enumerate(fin, 1):
            event = json.loads(line)
            event_id = event.get('event_id', 'UNKNOWN')
            if event_id in processed_ids:
                stats["skipped"] += 1
                continue

            source_raw = event.get('sources') or event.get('source_name', 'Невідоме джерело')
            source_name = source_raw[0] if isinstance(source_raw, list) and source_raw else str(source_raw)
            is_trusted = 1 if any(x in source_name.lower() for x in TRUSTED_SOURCE_KEYWORDS) else 0

            raw_text = event.get('text', '')
            title = event.get('title', '')


            title_lower = title.lower()
            administrative_patterns = [
                "щодо обміну інформацією", "щодо невідкладних заходів",
                "рекомендації", "зведена інформація", "щодо кіберзахисту",
                "як бути відповідальним", "дайджест", "огляд кіберзагроз"
            ]
            if any(p in title_lower for p in administrative_patterns) and "атака" not in title_lower and "кампанія" not in title_lower:
                rejected_record = {
                    "event_id": event_id, "title": title, "source": source_name,
                    "rejection_reason": "general_guideline_or_administrative_notice"
                }
                fout_rejected.write(json.dumps(rejected_record, ensure_ascii=False) + "\n")
                fout_rejected.flush()
                stats["rejected"] += 1
                print(f"\n {line_num}: {event_id} ({source_name})...")
                print(f"НЕ ІНЦИДЕНТ (авто-фільтр) — відкинуто")
                continue

            iocs = event.get("iocs", {})
            if not isinstance(iocs, dict):
                iocs = {}

            uac_groups = iocs.get("uac_groups", [])
            cert_refs = iocs.get("cert_refs", [])
            cve = iocs.get("cve", [])
            ipv4 = iocs.get("ipv4", [])
            hashes = iocs.get("hash", [])
            attack_ttp = iocs.get("attack_ttp", [])
            tech_hint = event.get("technical_detail_hint", "невідомо")
            phys_hint = event.get("physical_effect_hint", False)
            event_type_hints = event.get("event_type_hints", [])
            sectors_hint = event.get("sectors_hint", [])


            metadata_context = f"""
ДЖЕРЕЛО: {source_name}
UAC GROUPS: {', '.join(map(str, uac_groups)) if uac_groups else 'невідомо'}
CERT REFERENCES: {', '.join(map(str, cert_refs)) if cert_refs else 'невідомо'}
CVE: {', '.join(map(str, cve)) if cve else 'невідомо'}
IPv4: {format_ioc_list(ipv4)}
HASH: {format_ioc_list(hashes)}
ATTACK TTP: {', '.join(map(str, attack_ttp)) if attack_ttp else 'невідомо'}
ПОПЕРЕДНЯ ПІДКАЗКА ТИПУ ПОДІЇ: {', '.join(map(str, event_type_hints)) if event_type_hints else 'невідомо'}
ПОПЕРЕДНЯ ПІДКАЗКА СЕКТОРУ: {', '.join(map(str, sectors_hint)) if sectors_hint else 'невідомо'}
ПОПЕРЕДНЯ ТЕХНІЧНА ДЕТАЛІЗАЦІЯ: {tech_hint}
ОЗНАКА ФІЗИЧНОГО ВПЛИВУ: {phys_hint}
"""

            if len(raw_text) > 7000:
                text_to_analyze = raw_text[:4000] + "\n...[ПРОПУСК СЕРЕДИНИ]...\n" + raw_text[-2000:]
            else:
                text_to_analyze = raw_text

            prompt = SYSTEM_PROMPT.format(text=f"""
ЗАГОЛОВОК:
{title}

ПОПЕРЕДНІ МЕТАДАНІ:
{metadata_context}

ТЕКСТ:
{text_to_analyze}
""")
            print(f"\n {line_num}: {event_id} ({source_name})...")

            num_ctx = pick_num_ctx(prompt)

            success = False
            response_text = ""
            for attempt in range(3):
                try:
                    payload = {
                        "model": MODEL_NAME, "format": JSON_SCHEMA, "stream": False,
                        "messages": [
                            {"role": "system", "content": "Тільки факти. Виключно українська мова. Тільки JSON."},
                            {"role": "user", "content": prompt}],
                        "options": {"temperature": 0.1, "repeat_penalty": 1.1, "num_ctx": num_ctx, "num_predict": 600,
                                    "top_p": 0.9}
                    }
                    resp = requests.post(OLLAMA_URL, json=payload, timeout=180)
                    resp.raise_for_status()
                    response_text = resp.json()["message"]["content"]
                    success = True
                    break
                except Exception as e:
                    if attempt < 2:
                        time.sleep(5)
                    else:
                        log.error(f"Збій для {event_id}: {e}")

            if not success:
                fout_failed.write(json.dumps({"event_id": event_id, "title": title, "error": "request_failed"},
                                              ensure_ascii=False) + "\n")
                fout_failed.flush()
                stats["failed"] += 1
                continue

            try:
                clean_content = clean_markdown(response_text)
                extracted = json.loads(clean_content)


                extracted = sanitize_extracted_data(extracted)

                if not bool(extracted.get("is_relevant_cyber_incident", False)):
                    rejected_record = {
                        "event_id": event_id, "title": title, "source": source_name,
                        "rejection_reason": clean_model_artifacts(
                            extracted.get("rejection_reason", "not_specific_cyber_incident"))
                    }
                    fout_rejected.write(json.dumps(rejected_record, ensure_ascii=False) + "\n")
                    fout_rejected.flush()
                    stats["rejected"] += 1
                    print(f"НЕ ІНЦИДЕНТ — відкинуто ({rejected_record['rejection_reason']})")
                    continue


                target_entity = extracted.get("target_entity", "невідомо")
                bad_entities_strict = ["cert-ua", "cert", "сбу", "дссззі", "government", "organization", "victim", "system", "user", "unknown", "infrastructure", "software"]
                if any(b in target_entity.lower() for b in bad_entities_strict) or len(target_entity) > 40:
                    target_entity = "невідомо"


                threat_actor = clean_model_artifacts(extracted.get("threat_actor", "невідомо"))
                if threat_actor.lower() in ["невідомо", "unknown", "other", "інше", "кіберзлочинці"]:
                    if uac_groups:
                        threat_actor = uac_groups[0]


                raw_event_type = clean_model_artifacts(extracted.get("event_type", "інше"))
                text_lower = (title + " " + raw_text).lower()
                if raw_event_type not in ALLOWED_EVENT_TYPES:
                    hinted_type = None
                    for hint in event_type_hints or []:
                        if hint in EVENT_TYPE_HINT_MAP:
                            hinted_type = EVENT_TYPE_HINT_MAP[hint]
                            break
                    if hinted_type:
                        raw_event_type = hinted_type
                    elif any(w in text_lower for w in ["wiper", "wipe", "знищення даних", "затирання", "деструктивн"]):
                        raw_event_type = "деструктивна діяльність"
                    elif any(w in text_lower for w in ["шкідлив", "malware", "бекдор", "вірус", "троян", "rat", "stealer", "стілер"]):
                        raw_event_type = "шкідливе ПЗ"
                    elif "фішинг" in text_lower or "phish" in text_lower:
                        raw_event_type = "фішинг"
                    elif "ddos" in text_lower:
                        raw_event_type = "DDoS"

                if raw_event_type not in ALLOWED_EVENT_TYPES:
                    raw_event_type = "інше"
                event_type_en = ENGLISH_TAXONOMY_MAP["event_type"].get(raw_event_type, "other")


                raw_attack_vector = clean_model_artifacts(extracted.get("attack_vector", "невідомо"))
                if raw_attack_vector not in ALLOWED_ATTACK_VECTORS:
                    if raw_event_type == "деструктивна діяльність" or raw_event_type == "шкідливе ПЗ":
                        raw_attack_vector = "шкідливе ПЗ"
                    elif raw_event_type == "фішинг":
                        raw_attack_vector = "фішинг"

                if raw_attack_vector not in ALLOWED_ATTACK_VECTORS:
                    raw_attack_vector = "інше"
                attack_vector_en = ENGLISH_TAXONOMY_MAP["attack_vector"].get(raw_attack_vector, "unknown")


                detail_level = max(1, min(3, int(extracted.get("technical_detail_level", 1))))
                target_type = extracted.get("target_type", "невідомо")


                raw_sector = determine_sector(target_entity, target_type, extracted.get("sector", "невідомо"),
                                               sectors_hint)
                sector_en = ENGLISH_TAXONOMY_MAP["sector"].get(raw_sector, "unknown")

                raw_impact_text = clean_model_artifacts(extracted.get("confirmed_impact", "невідомо"))
                is_confirmed = bool(extracted.get("is_impact_confirmed", False))

                impact_text = normalize_confirmed_impact(raw_impact_text, raw_event_type, is_confirmed)

                impact_lower = impact_text.lower()
                if impact_lower != "невідомо" and impact_lower.strip():
                    if any(word in impact_lower for word in [
                        "можлив", "спроб", "загроз", "ризик",
                        "потенційн", "намагалися", "ймовірн"
                    ]):
                        is_confirmed = False

                preliminary_impact = calculate_preliminary_impact(raw_event_type, is_confirmed, impact_text)

                clean_extracted = {
                    "is_relevant_cyber_incident": True,
                    "target_entity": target_entity,
                    "target_type": target_type,
                    "sector": sector_en,
                    "attack_vector": attack_vector_en,
                    "event_type": event_type_en,
                    "threat_actor": threat_actor,
                    "source_reliability_score": 5 if is_trusted else 3,
                    "technical_detail_level": detail_level,
                    "confirmed_impact": impact_text,
                    "is_impact_confirmed": is_confirmed,
                    "preliminary_impact_score": preliminary_impact,
                    "impact_calculation_logic": f"Тип інциденту: {raw_event_type} ({event_type_en}); підтверджений вплив: {is_confirmed}"
                }

                event["llm_extraction"] = clean_extracted
                fout_enriched.write(json.dumps(event, ensure_ascii=False) + "\n")
                fout_enriched.flush()
                stats["accepted"] += 1

                print("ДОДАНО:")
                print(json.dumps(clean_extracted, indent=2, ensure_ascii=False))
                print("-" * 60)

            except json.JSONDecodeError:
                log.warning(f"Помилка парсингу JSON: {event_id}")
                fout_failed.write(json.dumps({"event_id": event_id, "title": title,
                                               "error": "json_decode_error", "raw_response": response_text},
                                              ensure_ascii=False) + "\n")
                fout_failed.flush()
                stats["failed"] += 1

    log.info(f"Готово! Прийнято: {stats['accepted']}, відхилено: {stats['rejected']}, "
             f"провалено: {stats['failed']}, пропущено (вже оброблені): {stats['skipped']}")
    log.info(f"Файли: {output_file} / {rejected_file} / {failed_file}")

if __name__ == "__main__":
    log.info(f"Запуск з {MODEL_NAME}...")
    process_events()