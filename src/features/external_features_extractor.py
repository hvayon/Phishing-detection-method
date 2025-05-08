import os
import re
import time
from datetime import datetime

import socket
import requests
import whois
import pycountry

from dotenv import load_dotenv

# Загрузить переменные из .env
load_dotenv()

# Извлекаем внешние признаки сайта

# Функция проверяет, зарегистрирован ли домен сайта в WHOIS
def whois_registered_domain(domain):
    try:
        hostname = whois.whois(domain).domain_name
        if type(hostname) == list:
            for host in hostname:
                if re.search(host.lower(), domain):
                    return 0
            return 1
        else:
            if re.search(hostname.lower(), domain):
                return 0
            else:
                return 1
    except:
        return 1


# вычисляем количество дней до истечения срока регистрации
def domain_registration_length(domain):
    try:
        res = whois.whois(domain)
        expiration_date = res.expiration_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        # Some domains do not have expiration dates. The application should not raise an error if this is the case.
        if expiration_date:
            if type(expiration_date) == list:
                expiration_date = min(expiration_date)
            return abs((expiration_date - today).days)
        else:
            return 0
    except:
        return -1


# возраст домена
# возвращает возраст домена в днях
# если нет результата, то -2
# в случае ошибки -1
# не работает с .com (поправить)
def domain_age(domain: str) -> int:
    try:
        # Получаем WHOIS-информацию
        domain_info = whois.whois(domain)
        # Извлекаем дату создания
        creation_date = domain_info.creation_date

        # Если дата не найдена
        if not creation_date:
            return -2

        # Обрабатываем разные форматы даты
        if isinstance(creation_date, list):
            creation_date = min(creation_date)

        if isinstance(creation_date, str):
            try:
                # Пробуем разные форматы даты
                for fmt in ("%Y-%m-%d %H:%M:%S", "%Y.%m.%d", "%d-%b-%Y"):
                    try:
                        creation_date = datetime.strptime(creation_date.split(".")[0], fmt)
                        break
                    except ValueError:
                        continue
                else:
                    return -2
            except:
                return -2

        # Рассчитываем возраст
        delta = datetime.now() - creation_date
        return delta.days

    except:
        return -1


# получаем ранк сайта
def page_rank(domain):
    try:
        # Пример API SimilarWeb (нужен API-ключ)
        api_key = os.getenv("API_KEY")  # Безопасный способ
        url = f"https://api.similarweb.com/v1/similar-rank/{domain}/rank?api_key={api_key}"
        response = requests.get(url).json()
        return int(response['similar_rank']['rank'])
    except:
        return 0


# Проверка наличия NS-записей в домен
import dns.resolver

def dns_record(domain):
    try:
        answer = dns.resolver.resolve(domain, 'NS')
        # for server in answer: # возвращает имена серверов
        #     print(server.target)
        if len(answer) > 0:
            return 0
        else:
            return 1
    except dns.resolver.NXDOMAIN:  # Домен не существует
        return 1
    except dns.resolver.NoAnswer:  # Нет NS-записей
        return 1
    except:
        return 1

def get_domain_ip(domain):
    """Получает IPv4-адрес домена."""
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, socket.herror):
        return None
    except:
        return None


def get_ip_country(ip):
    """Определяет страну по IP с помощью API ip-api.com."""
    if not ip:
        return None
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=15)
        if response.status_code == 200:
            data = response.json()
            # print(data)
            return data.get('countryCode', '').upper() if data.get('status') == 'success' else None
        return None
    except:
        return None


def get_whois_country(domain):
    """Извлекает страну регистрации домена из WHOIS-данных."""
    try:
        domain_info = whois.whois(domain)
        country = domain_info.country

        # Обработка списка стран
        if isinstance(country, list):
            country = country[0] if country else None

        if not country:
            return None

        # Проверка на двухбуквенный код
        if len(str(country)) == 2 and str(country).isalpha():
            return str(country).upper()

        # Конвертация названия в код
        try:
            match = pycountry.countries.search_fuzzy(str(country))
            print(match)
            return match[0].alpha_2.upper() if match else None
        except LookupError:
            return None
    except:
        return None


def ip_country_match(domain):
    """Проверяет соответствие страны IP-адреса и WHOIS-регистрации.
       Возвращает 1 при несоответствии или ошибке, 0 при совпадении."""
    ip = get_domain_ip(domain)
    if not ip:
        return 1

    ip_country = get_ip_country(ip)
    if not ip_country:
        return 1

    whois_country = get_whois_country(domain)
    if not whois_country:
        return 1

    return 0 if ip_country == whois_country else 1


# тесты
# удалить web_traffic из dataset
if __name__ == "__main__":
    domain = "google.com"  # Замените на нужный домен
    res = get_whois_country(domain)
    result = ip_country_match(domain)
    #
    print(res)
    print(result)
