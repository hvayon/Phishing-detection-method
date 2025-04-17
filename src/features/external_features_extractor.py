import re
import time
from datetime import datetime
import os

import requests
import whois
from dotenv import load_dotenv

# Загрузить переменные из .env
load_dotenv()

######################################################
#           Извлекаем внешние признаки сайта          #
######################################################

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
        print(api_key)
        url = f"https://api.similarweb.com/v1/similar-rank/{domain}/rank?api_key={api_key}"
        response = requests.get(url).json()
        print(response)
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

# def page_rank(short_url):
#     try:
#         # Кодирование URL и формирование безопасного запроса
#         encoded_url = quote(short_url)
#         url = f"http://data.alexa.com/data?cli=10&dat=s&url={encoded_url}"
#
#         # Создание запроса с заголовками (некоторые сайты требуют User-Agent)
#         request = urllib.request.Request(
#             url,
#             headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
#         )
#
#         # Выполнение запроса с таймаутом
#         with urllib.request.urlopen(request, timeout=10) as response:
#             soup = BeautifulSoup(response.read(), 'xml')
#
#         # Поиск данных с проверкой наличия тега и атрибута
#         if (reach_tag := soup.find('REACH')) and reach_tag.has_attr('RANK'):
#             return int(reach_tag['RANK'])
#         return 0
#
#     except (URLError, HTTPError, ValueError, TypeError, AttributeError):
#         # Обработка основных ошибок:
#         # - Сетевые проблемы
#         # - Проблемы конвертации данных
#         # - Отсутствие атрибутов/тегов
#         return 0
#     except Exception as e:
#         # Общая обработка для непредвиденных исключений (можно добавить логирование)
#         return 0

# тесты
# удалить web_traffic из dataset
if __name__ == "__main__":
    domain = "google.ru"  # Замените на нужный домен
    # result = whois_registered_domain(domain)
    # result = domain_registration_length(domain)
    # result = domain_age(domain)
    result = page_rank(domain) # тут rank
    # result = dns_record(domain)

    print(result)
