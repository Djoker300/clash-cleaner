import urllib.request
import urllib.error
import yaml
import re
import socket
from concurrent.futures import ThreadPoolExecutor

# --- НАСТРОЙКИ ---
# ISO-коды стран, которые скачиваем (в нижнем регистре)
TARGET_COUNTRIES = ["nl", "de", "us"]

# Шаблон URL источника
BASE_URL = "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/countries/{country_code}.yaml"

# Таймаут проверки порта в секундах (1.5 сек достаточно, чтобы отсеять "мертвые" сервера)
PING_TIMEOUT = 1.5

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
    """Быстрая проверка доступности TCP-порта сервера."""
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return False
    try:
        port = int(port)
        with socket.create_connection((server, port), timeout=PING_TIMEOUT):
            return True
    except Exception:
        return False

def check_proxy_worker(proxy: dict) -> dict | None:
    """Воркер для параллельной проверки."""
    if is_node_alive(proxy):
        return proxy
    return None

def main():
    raw_proxies = []

    # 1. Скачиваем конфиги нужных стран
    for code in TARGET_COUNTRIES:
        data = download_country_yaml(code)
        if not data or "proxies" not in data or not data["proxies"]:
            continue
        
        flag = get_flag_emoji(code)
        for p in data["proxies"]:
            # Сохраняем метку страны для формирования красивого имени
            p["_country_code"] = code.upper()
            p["_flag"] = flag
            raw_proxies.append(p)

    if not raw_proxies:
        print("Ошибка: Не удалось загрузить ни одного прокси!")
        return

    print(f"\nВсего скачано узлов: {len(raw_proxies)}. Удаляем дубликаты и проверяем доступность...")

    # 2. Удаление дубликатов по комбинации (server + port + cipher/type)
    unique_proxies = []
    seen_endpoints = set()

    for p in raw_proxies:
        endpoint = (p.get("server"), p.get("port"), p.get("type"))
        if endpoint in seen_endpoints:
            continue
        seen_endpoints.add(endpoint)
        unique_proxies.append(p)

    print(f"После удаления дубликатов осталось: {len(unique_proxies)}")
    print("Проверка пинга (TCP connect)... Это займет пару секунд.")

    # 3. Параллельная проверка доступности портов
    alive_proxies = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        results = executor.map(check_proxy_worker, unique_proxies)
        for res in results:
            if res:
                alive_proxies.append(res)

    print(f" Живых узлов (порт открыт): {len(alive_proxies)} из {len(unique_proxies)}")

    if not alive_proxies:
        print("Ошибка: Все узлы оказались неактивны.")
        return

    # 4. Формирование чистых и уникальных имен
    final_proxies = []
    proxy_names = []

    for idx, p in enumerate(alive_proxies, 1):
        code = p.pop("_country_code", "")
        flag = p.pop("_flag", "🌐")
        
        original_name = p.get("name", "")
        clean_name = re.sub(r'^[\U0001F1E6-\U0001F1FF]{2}\s*', '', original_name)
        
        # Нумеруем узлы для гарантированной уникальности имен в Clash
        new_name = f"{flag} {code} - Node {idx}"
        p["name"] = new_name
        
        final_proxies.append(p)
        proxy_names.append(new_name)

    # 5. Сборка итогового файла
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

    print(f"\n[УСПЕХ] Готово! Сохранен чистый файл '{output_filename}' ({len(final_proxies)} рабочих узлов).")

if __name__ == "__main__":
    main()
