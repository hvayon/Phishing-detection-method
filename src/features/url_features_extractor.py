# 0 - легитимный URL
# 1 - фишинговый URL

import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

import certifi  # Сертификаты для проверки SSL
from tldextract import extract  # Парсинг доменных частей URL

# Импорт модуля для анализа случайности домена
from src.features.nlp_class import DomainRandomnessChecker

# Набор подстрок, характерных для фишинговых URL (в нижнем регистре)
HINTS = {
    'wp', 'login', 'admin', 'secure', 'verify', 'oauth',
    'account', 'update', 'confirm', 'ebay', 'paypal', 'signin'
}

# Загрузка списка брендов для проверки подделок
BRAND_KEYWORDS = set()
try:
    with open('brands.txt', 'r') as file:
        BRAND_KEYWORDS = {line.strip().lower() for line in file if line.strip()}
except FileNotFoundError:
    pass  # Файл не найден - список брендов останется пустым

# Предварительно скомпилированные регулярные выражения для оптимизации
IPV4_PATTERN = re.compile(
    r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
    r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
    r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
    r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    r')\b')

IPV4_HEX_PATTERN = re.compile(r'\b(0x[0-9a-fA-F]{1,2}\.){3}0x[0-9a-fA-F]{1,2}\b')
IPV6_PATTERN = re.compile(r'\b(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})\b')

# Паттерн для сервисов сокращения ссылок
SHORTENERS_PATTERN = re.compile(
    r'(?:https?://)?(?:www\.)?'
    r'(?:'
    r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
    r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
    r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
    r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|'
    r'db\.tt|qr\.ae|adf\.ly|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|'
    r'buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|scrnch\.me|filoops\.info|'
    r'vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net|buff\.ly|cutt\.ly|'
    r'clck\.ru|qps\.ru|shrturi\.com|rebrand\.ly|trim\.im|p\.tk\.ru|soo\.gd|shorturl\.at|'
    r'n9\.cl|click\.ru|lnk\.su|0x0\.st|zws\.im|s2r\.lnk|alturl\.com|tiny\.one|short\.io'
    r')'
    r'(?:/.*)?$',
    re.IGNORECASE
)

# Список подозрительных доменов верхнего уровня
SUSPICIOUS_TLDS = {
    'fit', 'tk', 'gp', 'ga', 'work', 'ml', 'date', 'wang', 'men', 'icu',
    'online', 'click', 'country', 'stream', 'download', 'xin', 'racing',
    'jetzt', 'ren', 'mom', 'party', 'review', 'trade', 'accountants',
    'science', 'ninja', 'xyz', 'faith', 'zip', 'cricket', 'win', 'accountant',
    'realtor', 'top', 'christmas', 'gdn', 'link', 'asia', 'club', 'la', 'ae',
    'exposed', 'pe', 'go.id', 'rs', 'k12.pa.us', 'or.kr', 'ce.ke', 'audio',
    'gob.pe', 'gov.az', 'website', 'bj', 'mx', 'media', 'sa.gov.au'
}

# Инициализация NLP-модели один раз при загрузке модуля
nlp_manager = DomainRandomnessChecker()


def has_ip_address(url: str) -> int:
    """
    Обнаружение IP-адресов в URL.
    Возвращает 1, если найден IPv4/IPv6 адрес или hex-формат IPv4.
    """
    return int(bool(
        IPV4_PATTERN.search(url) or
        IPV4_HEX_PATTERN.search(url) or
        IPV6_PATTERN.search(url)
    ))


def url_length(url: str) -> int:
    """Вычисление общей длины URL-адреса."""
    return len(url)


def is_shortened_url(url: str) -> int:
    """Проверка использования сервисов сокращения ссылок."""
    return int(bool(SHORTENERS_PATTERN.search(url)))

def count_redirection(page):
    """Количество редиректов"""
    return len(page.history)

def count_external_redirection(page, domain):
    """Количество внешних перенаправлений"""
    count = 0
    if len(page.history) == 0:
        return 0
    else:
        for i, response in enumerate(page.history,1):
            if domain.lower() not in response.url.lower():
                count+=1
            return count

def count_special_chars(s: str, chars: str) -> int:
    """Вспомогательная функция для подсчёта специальных символов."""
    return sum(s.count(c) for c in chars)


# Функции подсчёта конкретных символов
def count_at(base_url: str) -> int:
    """Подсчёт символов '@' в URL."""
    return base_url.count('@')


def count_comma(base_url: str) -> int:
    """Подсчёт символов ',' в URL."""
    return base_url.count(',')


def count_dollar(base_url: str) -> int:
    """Подсчёт символов '$' в URL."""
    return base_url.count('$')


def count_semicolumn(url: str) -> int:
    """Подсчёт символов ';' в URL."""
    return url.count(';')


def count_space(base_url: str) -> int:
    """Подсчёт пробелов и URL-кодированных пробелов (%20)."""
    return base_url.count(' ') + base_url.count('%20')


def count_and(base_url: str) -> int:
    """Подсчёт символов '&' в URL."""
    return base_url.count('&')


def count_double_slash(full_url: str) -> int:
    """Подсчёт не относящихся к протоколу вхождений '//'."""
    positions = [m.start() for m in re.finditer(r'//', full_url)]
    return int(any(pos > 7 for pos in positions))  # Игнорируем слэши протокола


def count_slash(full_url: str) -> int:
    """Подсчёт символов '/' в URL."""
    return full_url.count('/')


def count_equal(base_url: str) -> int:
    """Подсчёт символов '=' в URL."""
    return base_url.count('=')


def count_percentage(base_url: str) -> int:
    """Подсчёт символов '%' в URL."""
    return base_url.count('%')


def count_exclamation(base_url: str) -> int:
    """Подсчёт символов '?' в URL."""
    return base_url.count('?')


def count_underscore(base_url: str) -> int:
    """Подсчёт символов '_' в URL."""
    return base_url.count('_')


def count_hyphens(base_url: str) -> int:
    """Подсчёт символов '-' в URL."""
    return base_url.count('-')


def count_dots(hostname: str) -> int:
    """Подсчёт точек в имени хоста."""
    return hostname.count('.')


def count_colon(url: str) -> int:
    """Подсчёт символов ':' в URL."""
    return url.count(':')


def count_star(url: str) -> int:
    """Подсчёт символов '*' в URL."""
    return url.count('*')


def count_or(url: str) -> int:
    """Подсчёт символов '|' в URL."""
    return url.count('|')


def path_extension(url_path: str) -> int:
    """Проверка расширения .txt в конце пути URL."""
    return int(url_path.lower().endswith('.txt'))


def count_http_token(url_path: str) -> int:
    """Подсчёт вхождений 'http' в пути URL."""
    return url_path.lower().count('http')

def port(url):
    """ Регулярное выражение с учетом IPv4, IPv6 и валидных портов (1-65535) """
    pattern = r"""
        ^(?:[a-zA-Z][a-zA-Z0-9+.-]*://)?  # Схема (опционально)
        (?:[^/@:]+@)?                      # Логин/пароль (опционально)
        (?:                                
          (?:\[[a-fA-F0-9:.]+\]) |        # IPv6 в квадратных скобках
          ([a-zA-Z0-9\-._~%]+)            # Домен или IPv4
        )
        :(?!\d+/)                          # Исключить двоеточия в пути
        ([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])  # Порт 1-65535
        (?:/|$)                            # Конец URL или путь
    """
    if re.search(pattern, url, re.VERBOSE | re.IGNORECASE):
        return 1
    return 0

def check_ssl_certificate(domain: str) -> tuple[bool, str]:
    """
    Проверка SSL-сертификата домена.
    Возвращает кортеж (валидность, сообщение об ошибке).
    """
    context = ssl.create_default_context(cafile=certifi.where())

    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as conn:
                cert = conn.getpeercert()
                cert_dict = {key: value for key, value in cert.items()}

                # Проверка временных рамок сертификата
                now = datetime.now(timezone.utc)
                not_after = datetime.strptime(
                    cert_dict['notAfter'], '%b %d %H:%M:%S %Y %Z'
                ).replace(tzinfo=timezone.utc)

                not_before = datetime.strptime(
                    cert_dict['notBefore'], '%b %d %H:%M:%S %Y %Z'
                ).replace(tzinfo=timezone.utc)

                if now < not_before:
                    return False, "Сертификат ещё не действителен"
                if now > not_after:
                    return False, "Сертификат просрочен"

                # Проверка соответствия домена
                if not cert_matches_domain(cert_dict, domain):
                    return False, "Несоответствие домена"

                return True, "Валидный сертификат"

    except (ssl.SSLError, socket.timeout, ConnectionRefusedError) as e:
        return False, f"Ошибка SSL: {str(e)}"
    except Exception as e:
        return False, f"Общая ошибка: {str(e)}"


def cert_matches_domain(cert: dict, domain: str) -> bool:
    """Проверка соответствия домена в сертификате (SAN/CN)."""
    names = []
    domain = domain.lower()

    # Извлечение Common Name
    for sub in cert.get('subject', []):
        for key, value in sub:
            if key[0] == 'commonName':
                names.append(value.lower())

    # Извлечение SAN (Subject Alternative Names)
    for san_type, san_value in cert.get('subjectAltName', []):
        if san_type == 'DNS':
            names.append(san_value.lower())

    # Проверка совпадений
    for name in names:
        if name == domain:
            return True
        if name.startswith('*'):
            base_domain = domain.split('.', 1)[-1]
            if f".{base_domain}" == name[1:]:
                return True
    return False


def https_token(url: str) -> int:
    """Проверка валидности HTTPS соединения."""
    parsed = urlparse(url)
    if parsed.scheme != 'https':
        return 1  # Используется HTTP или другой протокол

    domain = parsed.netloc.split(':', 1)[0]
    valid, _ = check_ssl_certificate(domain)
    return 0 if valid else 1  # 1 если сертификат невалидный


def ratio_digits(hostname: str) -> float:
    """Расчёт соотношения цифр в имени хоста."""
    digits = sum(c.isdigit() for c in hostname)
    return digits / len(hostname) if hostname else 0.0


def count_digits(line: str) -> int:
    """Подсчёт цифр в строке."""
    return sum(c.isdigit() for c in line)


def count_tilde(full_url: str) -> int:
    """Обнаружение символа '~' в URL."""
    return int('~' in full_url)


def phish_hints(url_path: str) -> int:
    """Подсчёт фишинговых ключевых слов в пути URL."""
    lower_path = url_path.lower()
    return sum(lower_path.count(hint) for hint in HINTS)


def tld_in_path(tld: str, path: str) -> int:
    """Проверка наличия TLD в пути URL."""
    tld_lower = tld.lower()
    path_lower = path.lower()
    escaped_tld = re.escape(tld_lower)
    return int(bool(re.search(rf'\b{escaped_tld}\b', path_lower)))


def tld_in_subdomain(tld: str, subdomain: str) -> int:
    """Проверка наличия TLD в поддомене."""
    tld_lower = tld.lower()
    subdomain_lower = subdomain.lower()
    subdomain_parts = subdomain_lower.split('.')
    return int(tld_lower in subdomain_parts)


def count_redirection(page) -> int:
    """Подсчёт количества редиректов в истории страницы."""
    return len(getattr(page, 'history', []))


def count_external_redirection(page, domain: str) -> int:
    """Подсчёт редиректов на другие домены."""
    if not hasattr(page, 'history'):
        return 0

    target_domain = domain.lower().replace("www.", "")
    return sum(
        1 for resp in page.history
        if urlparse(resp.url).netloc.lower().replace("www.", "") != target_domain
    )


def random_domain(domain: str) -> int:
    """Проверка домена на случайность с использованием NLP."""
    return int(nlp_manager.is_random_domain(domain))


def char_repeat(
        words: List[str],
        min_length: int = 2,
        max_length: int = 5,
        weights: Optional[Dict[int, float]] = None,
        ignore_chars: str = "."
) -> Dict:
    """
    Обнаружение повторяющихся последовательностей символов.
    Возвращает словарь с:
    - total_score: взвешенная сумма повторений
    - counts: количество повторений по длинам
    - details: примеры подозрительных подстрок
    """
    counts = {length: 0 for length in range(min_length, max_length + 1)}
    details = {length: [] for length in range(min_length, max_length + 1)}
    weights = weights or {2: 1.0, 3: 1.5, 4: 2.0, 5: 3.0}

    for word in words:
        clean_word = word.translate({ord(c): None for c in ignore_chars})
        for length in range(min_length, max_length + 1):
            for i in range(len(clean_word) - length + 1):
                substr = clean_word[i:i + length]
                if len(set(substr)) == 1:  # Все символы в подстроке одинаковые
                    counts[length] += 1
                    if substr not in details[length]:
                        details[length].append(substr)

    total_score = sum(counts[length] * weights.get(length, 1.0)
                      for length in counts)

    return {
        'total_score': round(total_score, 2),
        'counts': counts,
        'details': details
    }


def punycode(url: str) -> int:
    """Обнаружение Punycode в URL."""
    return int(url.lower().startswith(('http://xn--', 'https://xn--')))


def brand_imitation(domain: str, path: str) -> int:
    """Проверка на имитацию известных брендов."""
    domain_lower = domain.lower()
    path_lower = path.lower()
    for brand in BRAND_KEYWORDS:
        brand_lower = brand.lower()
        if brand_lower in domain_lower or brand_lower in path_lower:
            return int(domain_lower != brand_lower)
    return 0

def count_subdomain(url: str) -> int:
    """Подсчёт количества поддоменов."""
    return len(extract(url).subdomain.split('.'))


def suspicious_tld(tld: str) -> int:
    """Проверка TLD на наличие в списке подозрительных."""
    return int(tld.lower() in SUSPICIOUS_TLDS)