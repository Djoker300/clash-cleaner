import urllib.request
import urllib.error
import yaml
import re

# --- НАСТРОЙКИ ---
# Список стран (в нижнем регистре), которые нужно скачать и объединить.
# Добавляй или удаляй коды нужных стран (например: "nl", "de", "us", "tr", "fr", "gb", "kz", "fi")
TARGET_COUNTRIES = ["nl", "de", "us"]

# Базовый URL шаблона хранения файлов стран в репозитории-источнике
BASE_URL = "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/countries/{country_code}.yaml"

def get_flag_emoji(country_code: str) -> str:
    """Генерирует эмодзи флага по ISO-коду страны (например, 'nl' -> '🇳🇱')."""
    code = country_code.upper()
    if len(code) != 2:
        return "🌐"
    return chr(127397 + ord(code[0])) + chr(127397 + ord(code[1]))

def download_country_yaml(country_code: str) -> dict | None:
    """Скачивает YAML-файл конкретной страны."""
    url = BASE_URL.format(country_code=country_code.lower())
    print(f"Скачивание [{country_code.upper()}] по ссылке: {url}")
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Clash/1.0.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content = response.read().decode('utf-8')
            return yaml.safe_load(content)
    except urllib.error.HTTPError as e:
        print(f"[-] Ошибка HTTP {e.code} при скачивании {country_code.upper()}")
    except Exception as e:
        print(f"[-] Не удалось загрузить {country_code.upper()}: {e}")
    return None

def main():
    all_proxies = []
    proxy_names = []

    for code in TARGET_COUNTRIES:
        flag = get_flag_emoji(code)
        data = download_country_yaml(code)
        
        if not data or "proxies" not in data or not data["proxies"]:
            print(f"[-] В файле для страны {code.upper()} прокси не найдены.")
            continue

        count = 0
        for p in data["proxies"]:
            original_name = p.get("name", "")
            
            # Удаляем уже имеющиеся флаги из начала названия, если они там есть
            clean_name = re.sub(r'^[\U0001F1E6-\U0001F1FF]{2}\s*', '', original_name)
            
            # Формируем красивое название вида: "🇳🇱 NL - NodeName"
            new_name = f"{flag} {code.upper()} - {clean_name}".strip()
            
            # Убедимся, что имена уникальные (если есть дубликаты)
            idx = 1
            unique_name = new_name
            while unique_name in proxy_names:
                unique_name = f"{new_name} ({idx})"
                idx += 1

            p["name"] = unique_name
            all_proxies.append(p)
            proxy_names.append(unique_name)
            count += 1

        print(f"[+] Добавлено узлов из {code.upper()}: {count}")

    if not all_proxies:
        print("Ошибка: Не удалось загрузить ни одного прокси!")
        return

    # Формируем стандартную структуру конфига Clash
    final_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "proxies": all_proxies,
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

    print(f"\n[УСПЕХ] Сформирован конфиг {output_filename}. Всего прокси: {len(all_proxies)}")

if __name__ == "__main__":
    main()
