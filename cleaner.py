import urllib.request
import urllib.error
import yaml
import re
import socket
from concurrent.futures import ThreadPoolExecutor

TARGET_COUNTRIES = ["nl", "de", "us"]
BASE_URL = "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/countries/{country_code}.yaml"
PING_TIMEOUT = 3.0

def get_flag_emoji(country_code: str) -> str:
    code = country_code.upper()
    if len(code) != 2:
        return "🌐"
    return chr(127397 + ord(code[0])) + chr(127397 + ord(code[1]))

def download_country_yaml(country_code: str) -> dict | None:
    url = BASE_URL.format(country_code=country_code.lower())
    print(f"Скачивание [{country_code.upper()}]...")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Clash/1.0.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            return yaml.safe_load(response.read().decode('utf-8'))
    except Exception as e:
        print(f"[-] Не удалось загрузить {country_code.upper()}: {e}")
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
    raw_proxies = []

    for code in TARGET_COUNTRIES:
        data = download_country_yaml(code)
        if not data or "proxies" not in data or not data["proxies"]:
            continue
        
        flag = get_flag_emoji(code)
        for p in data["proxies"]:
            p["_country_code"] = code.upper()
            p["_flag"] = flag
            raw_proxies.append(p)

    if not raw_proxies:
        print(" Ошибка: Не удалось загрузить прокси из источника!")
        return

    # Удаление дубликатов
    unique_proxies = []
    seen_endpoints = set()
    for p in raw_proxies:
        endpoint = (p.get("server"), p.get("port"), p.get("type"))
        if endpoint not in seen_endpoints:
            seen_endpoints.add(endpoint)
            unique_proxies.append(p)

    print(f"Скачано уникальных узлов: {len(unique_proxies)}. Проверяем доступность...")

    # Проверка пинга
    alive_proxies = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(check_proxy_worker, unique_proxies)
        for res in results:
            if res:
                alive_proxies.append(res)

    # Защита: если по TCP никто не ответил, берем первые 20 узлов
    if not alive_proxies:
        print(" Ни один узел не ответил на TCP-чек. Берем список без отсева.")
        alive_proxies = unique_proxies[:20]

    print(f"Формируем файл из {len(alive_proxies)} узлов...")

    final_proxies = []
    proxy_names = []

    for idx, p in enumerate(alive_proxies, 1):
        code = p.pop("_country_code", "")
        flag = p.pop("_flag", "🌐")
        
        original_name = p.get("name", "")
        clean_name = re.sub(r'^[\U0001F1E6-\U0001F1FF]{2}\s*', '', original_name)
        
        new_name = f"{flag} {code} - Node {idx}"
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
            "FINAL,PROXIES"
        ]
    }

    output_filename = "config.yaml"
    with open(output_filename, "w", encoding="utf-8") as f:
        yaml.dump(final_config, f, allow_unicode=True, sort_keys=False)

    print(f"[УСПЕХ] Файл '{output_filename}' успешно сохранен!")

if __name__ == "__main__":
    main()
