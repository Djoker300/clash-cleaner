import sys
import urllib.request
import urllib.error
import yaml
import re
import socket
from concurrent.futures import ThreadPoolExecutor

# ==================================================
# НАСТРОЙКА СТРАН (1 - включено, 0 - выключено)
# ==================================================
COUNTRIES_CONFIG = {
    "AU": 0,  # Australia
    "BG": 0,  # Bulgaria
    "CA": 0,  # Canada
    "FI": 0,  # Finland
    "FR": 1,  # France
    "DE": 1,  # Germany
    "HK": 0,  # Hong Kong
    "IN": 0,  # India
    "IE": 0,  # Ireland
    "IT": 1,  # Italy
    "JP": 0,  # Japan
    "KR": 0,  # Korea
    "LV": 0,  # Latvia
    "NL": 1,  # Netherlands
    "PK": 0,  # Pakistan
    "PL": 1,  # Poland
    "PT": 0,  # Portugal
    "RO": 0,  # Romania
    "RU": 0,  # Russia
    "SG": 0,  # Singapore
    "ES": 0,  # Spain
    "SE": 0,  # Sweden
    "CH": 0,  # Switzerland
    "TW": 0,  # Taiwan
    "TH": 0,  # Thailand
    "TR": 0,  # Turkey
    "GB": 0,  # United Kingdom
    "US": 0,  # United States
}

BASE_URL = "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/by-country/clash-{country_code}.yaml"
PING_TIMEOUT = 3.0

def get_flag_emoji(country_code: str) -> str:
    code = country_code.upper()
    if len(code) != 2:
        return "🌐"
    return chr(127397 + ord(code[0])) + chr(127397 + ord(code[1]))

def download_country_yaml(country_code: str) -> dict | None:
    code_upper = country_code.upper()
    url = BASE_URL.format(country_code=code_upper)
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8')
            return yaml.safe_load(content)
    except Exception as e:
        print(f"[-] Ошибка загрузки {code_upper}: {e}")
    return None

def is_node_alive(proxy: dict) -> bool:
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return False
    try:
        with socket.create_connection((server, int(port)), timeout=PING_TIMEOUT):
            return True
    except Exception:
        return False

def check_proxy_worker(proxy: dict) -> dict | None:
    if is_node_alive(proxy):
        return proxy
    return None

def main():
    # Фильтруем только включенные страны
    active_countries = [code for code, status in COUNTRIES_CONFIG.items() if status == 1]

    if not active_countries:
        print(" ОШИБКА: Ни одна страна не включена в COUNTRIES_CONFIG!")
        sys.exit(1)

    raw_proxies = []

    print("=" * 50)
    print(" 1. ЗАГРУЗКА ИСТОЧНИКОВ")
    print(f" Активные страны: {', '.join(active_countries)}")
    print("=" * 50)

    for code in active_countries:
        data = download_country_yaml(code)
        if not data or "proxies" not in data or not data["proxies"]:
            print(f"[-] [{code}]: Не удалось получить узлы.")
            continue

        count = len(data["proxies"])
        print(f"[+] [{code}]: Загружено {count} узлов.")

        flag = get_flag_emoji(code)
        for p in data["proxies"]:
            p["_country_code"] = code
            p["_flag"] = flag
            raw_proxies.append(p)

    total_downloaded = len(raw_proxies)
    if total_downloaded == 0:
        print("\n ОШИБКА: Не удалось получить ни одного прокси!")
        sys.exit(1)

    # 2. Удаление дубликатов
    unique_proxies = []
    seen_endpoints = set()
    for p in raw_proxies:
        endpoint = (p.get("server"), p.get("port"), p.get("type"))
        if endpoint not in seen_endpoints:
            seen_endpoints.add(endpoint)
            unique_proxies.append(p)

    duplicates_removed = total_downloaded - len(unique_proxies)

    print("\n" + "=" * 50)
    print(" 2. ПРОВЕРКА И ФИЛЬТРАЦИЯ")
    print("=" * 50)
    print(f"• Всего скачано:          {total_downloaded}")
    print(f"• Найдено дубликатов:      {duplicates_removed}")
    print(f"• Уникальных для проверки: {len(unique_proxies)}")
    print(f"• Проверка доступности (таймаут {PING_TIMEOUT}сек)...")

    # 3. Проверка пинга
    alive_proxies = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_proxy_worker, unique_proxies)
        for res in results:
            if res:
                alive_proxies.append(res)

    dead_nodes = len(unique_proxies) - len(alive_proxies)

    if not alive_proxies:
        print("\n ВНИМАНИЕ: Ни один узел не ответил. Берём первые 20 без отсева.")
        alive_proxies = unique_proxies[:20]

    # 4. Формирование конфига
    final_proxies = []
    proxy_names = []

    for idx, p in enumerate(alive_proxies, 1):
        code = p.pop("_country_code", "")
        flag = p.pop("_flag", "🌐")
        node_type = p.get("type", "node")

        new_name = f"{flag} {code} - {node_type} {idx}"
        p["name"] = new_name

        final_proxies.append(p)
        proxy_names.append(new_name)

    final_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": final_proxies,
        "proxy-groups": [
            {
                "name": "PROXIES",
                "type": "select",
                "proxies": ["AUTO"] + proxy_names
            },
            {
                "name": "AUTO",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": proxy_names
            }
        ],
        "rules": [
            "GEOIP,LAN,DIRECT",
            "MATCH,PROXIES"
        ]
    }

    output_filename = "config.yaml"
    with open(output_filename, "w", encoding="utf-8") as f:
        yaml.dump(final_config, f, allow_unicode=True, sort_keys=False)

    print("\n" + "=" * 50)
    print(" 3. ИТОГОВАЯ СТАТИСТИКА")
    print("=" * 50)
    print(f"• Исходно узлов:           {total_downloaded}")
    print(f"• Отсеяно дублей:          {duplicates_removed}")
    print(f"• Не ответили на TCP:      {dead_nodes}")
    print(f"• Сохранено в config.yaml: {len(final_proxies)} узлов")
    print(f"\n[УСПЕХ] Файл '{output_filename}' обновлен!")

if __name__ == "__main__":
    main()
