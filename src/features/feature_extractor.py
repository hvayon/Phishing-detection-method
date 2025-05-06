import requests

import src.features.external_features_extractor as efe
import src.features.url_features_extractor as ufe
import tldextract
import urllib.parse
import re
from requests.exceptions import RequestException, Timeout
import logging
from functools import wraps

from bs4 import BeautifulSoup
from urllib.parse import urlparse

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def deadline(timeout):
    """Декоратор для ограничения времени выполнения функции"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Timeout:
                logger.warning(f"Timeout exceeded for {func.__name__}")
                return False, None, None
            except Exception as e:
                logger.error(f"Unexpected error in {func.__name__}: {str(e)}")
                return False, None, None
        return wrapper
    return decorator

@deadline(5)
def is_url_accessible(url: str) -> tuple:
    """
    Проверяет доступность URL с обработкой ошибок и повторами
    Возвращает кортеж: (success: bool, final_url: str, response: requests.Response)
    """
    from urllib.parse import urlparse
    import requests

    def try_get(url_to_try: str) -> requests.Response | None:
        """Пытается получить URL с таймаутом"""
        try:
            res = requests.get(url_to_try, timeout=5, allow_redirects=True)
            # Проверка на пустой контент (некоторые сайты возвращают 200 с пустой страницей)
            if len(res.content) < 10:
                logger.warning(f"Empty content for {url_to_try}")
                return None
            return res
        except (RequestException, Timeout) as e:
            logger.info(f"Connection failed for {url_to_try}: {str(e)}")
            return None

    parsed = urlparse(url)
    original_scheme = parsed.scheme or 'http'  # Если схема не указана
    netloc = parsed.netloc or parsed.path  # Для URL без схемы

    # Варианты URL для попыток подключения
    attempts = [
        f"{original_scheme}://{netloc}",
        f"{original_scheme}://www.{netloc}"
    ]

    # Если основной домен начинается с www, пробуем без www
    if netloc.startswith('www.'):
        attempts.insert(0, f"{original_scheme}://{netloc[4:]}")

    for attempt_url in attempts:
        logger.info(f"Trying: {attempt_url}")
        response = try_get(attempt_url)
        if response and response.status_code == 200:
            logger.info(f"Successfully accessed: {attempt_url}")
            return True, attempt_url, response

    logger.warning(f"All access attempts failed for {url}")
    return False, None, None


# процесс извлечения данных
def extract_data_from_url(hostname, content, domain, Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title,
                          Text):
    Null_format = ["", "#", "#nothing", "#doesnotexist", "#null", "#void", "#whatever",
                   "#content", "javascript::void(0)", "javascript::void(0);", "javascript::;", "javascript"]

    soup = BeautifulSoup(content, 'html.parser', from_encoding='iso-8859-1')

    # collect all external and internal hrefs from url
    for href in soup.find_all('a', href=True):
        dots = [x.start(0) for x in re.finditer('\.', href['href'])]
        if hostname in href['href'] or domain in href['href'] or len(dots) == 1 or not href['href'].startswith('http'):
            if "#" in href['href'] or "javascript" in href['href'].lower() or "mailto" in href['href'].lower():
                Anchor['unsafe'].append(href['href'])
            if not href['href'].startswith('http'):
                if not href['href'].startswith('/'):
                    Href['internals'].append(hostname + '/' + href['href'])
                elif href['href'] in Null_format:
                    Href['null'].append(href['href'])
                else:
                    Href['internals'].append(hostname + href['href'])
        else:
            Href['externals'].append(href['href'])
            Anchor['safe'].append(href['href'])

    # collect all media src tags
    for img in soup.find_all('img', src=True):
        dots = [x.start(0) for x in re.finditer('\.', img['src'])]
        if hostname in img['src'] or domain in img['src'] or len(dots) == 1 or not img['src'].startswith('http'):
            if not img['src'].startswith('http'):
                if not img['src'].startswith('/'):
                    Media['internals'].append(hostname + '/' + img['src'])
                elif img['src'] in Null_format:
                    Media['null'].append(img['src'])
                else:
                    Media['internals'].append(hostname + img['src'])
        else:
            Media['externals'].append(img['src'])

    for audio in soup.find_all('audio', src=True):
        dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
        if hostname in audio['src'] or domain in audio['src'] or len(dots) == 1 or not audio['src'].startswith('http'):
            if not audio['src'].startswith('http'):
                if not audio['src'].startswith('/'):
                    Media['internals'].append(hostname + '/' + audio['src'])
                elif audio['src'] in Null_format:
                    Media['null'].append(audio['src'])
                else:
                    Media['internals'].append(hostname + audio['src'])
        else:
            Media['externals'].append(audio['src'])

    for embed in soup.find_all('embed', src=True):
        dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
        if hostname in embed['src'] or domain in embed['src'] or len(dots) == 1 or not embed['src'].startswith('http'):
            if not embed['src'].startswith('http'):
                if not embed['src'].startswith('/'):
                    Media['internals'].append(hostname + '/' + embed['src'])
                elif embed['src'] in Null_format:
                    Media['null'].append(embed['src'])
                else:
                    Media['internals'].append(hostname + embed['src'])
        else:
            Media['externals'].append(embed['src'])

    for i_frame in soup.find_all('iframe', src=True):
        dots = [x.start(0) for x in re.finditer('\.', i_frame['src'])]
        if hostname in i_frame['src'] or domain in i_frame['src'] or len(dots) == 1 or not i_frame['src'].startswith(
                'http'):
            if not i_frame['src'].startswith('http'):
                if not i_frame['src'].startswith('/'):
                    Media['internals'].append(hostname + '/' + i_frame['src'])
                elif i_frame['src'] in Null_format:
                    Media['null'].append(i_frame['src'])
                else:
                    Media['internals'].append(hostname + i_frame['src'])
        else:
            Media['externals'].append(i_frame['src'])

    # collect all link tags
    for link in soup.findAll('link', href=True):
        dots = [x.start(0) for x in re.finditer('\.', link['href'])]
        if hostname in link['href'] or domain in link['href'] or len(dots) == 1 or not link['href'].startswith('http'):
            if not link['href'].startswith('http'):
                if not link['href'].startswith('/'):
                    Link['internals'].append(hostname + '/' + link['href'])
                elif link['href'] in Null_format:
                    Link['null'].append(link['href'])
                else:
                    Link['internals'].append(hostname + link['href'])
        else:
            Link['externals'].append(link['href'])

    for script in soup.find_all('script', src=True):
        dots = [x.start(0) for x in re.finditer('\.', script['src'])]
        if hostname in script['src'] or domain in script['src'] or len(dots) == 1 or not script['src'].startswith(
                'http'):
            if not script['src'].startswith('http'):
                if not script['src'].startswith('/'):
                    Link['internals'].append(hostname + '/' + script['src'])
                elif script['src'] in Null_format:
                    Link['null'].append(script['src'])
                else:
                    Link['internals'].append(hostname + script['src'])
        else:
            Link['externals'].append(link['href'])

    # collect all css
    for link in soup.find_all('link', rel='stylesheet'):
        dots = [x.start(0) for x in re.finditer('\.', link['href'])]
        if hostname in link['href'] or domain in link['href'] or len(dots) == 1 or not link['href'].startswith('http'):
            if not link['href'].startswith('http'):
                if not link['href'].startswith('/'):
                    CSS['internals'].append(hostname + '/' + link['href'])
                elif link['href'] in Null_format:
                    CSS['null'].append(link['href'])
                else:
                    CSS['internals'].append(hostname + link['href'])
        else:
            CSS['externals'].append(link['href'])

    for style in soup.find_all('style', type='text/css'):
        try:
            start = str(style[0]).index('@import url(')
            end = str(style[0]).index(')')
            css = str(style[0])[start + 12:end]
            dots = [x.start(0) for x in re.finditer('\.', css)]
            if hostname in css or domain in css or len(dots) == 1 or not css.startswith('http'):
                if not css.startswith('http'):
                    if not css.startswith('/'):
                        CSS['internals'].append(hostname + '/' + css)
                    elif css in Null_format:
                        CSS['null'].append(css)
                    else:
                        CSS['internals'].append(hostname + css)
            else:
                CSS['externals'].append(css)
        except:
            continue

    # collect all form actions
    for form in soup.findAll('form', action=True):
        dots = [x.start(0) for x in re.finditer('\.', form['action'])]
        if hostname in form['action'] or domain in form['action'] or len(dots) == 1 or not form['action'].startswith(
                'http'):
            if not form['action'].startswith('http'):
                if not form['action'].startswith('/'):
                    Form['internals'].append(hostname + '/' + form['action'])
                elif form['action'] in Null_format or form['action'] == 'about:blank':
                    Form['null'].append(form['action'])
                else:
                    Form['internals'].append(hostname + form['action'])
        else:
            Form['externals'].append(form['action'])

    # collect all link tags
    for head in soup.find_all('head'):
        for head.link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
            if hostname in head.link['href'] or len(dots) == 1 or domain in head.link['href'] or not head.link[
                'href'].startswith('http'):
                if not head.link['href'].startswith('http'):
                    if not head.link['href'].startswith('/'):
                        Favicon['internals'].append(hostname + '/' + head.link['href'])
                    elif head.link['href'] in Null_format:
                        Favicon['null'].append(head.link['href'])
                    else:
                        Favicon['internals'].append(hostname + head.link['href'])
            else:
                Favicon['externals'].append(head.link['href'])

        for head.link in soup.findAll('link', {'href': True, 'rel': True}):
            isicon = False
            if isinstance(head.link['rel'], list):
                for e_rel in head.link['rel']:
                    if (e_rel.endswith('icon')):
                        isicon = True
            else:
                if (head.link['rel'].endswith('icon')):
                    isicon = True

            if isicon:
                dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                if hostname in head.link['href'] or len(dots) == 1 or domain in head.link['href'] or not head.link[
                    'href'].startswith('http'):
                    if not head.link['href'].startswith('http'):
                        if not head.link['href'].startswith('/'):
                            Favicon['internals'].append(hostname + '/' + head.link['href'])
                        elif head.link['href'] in Null_format:
                            Favicon['null'].append(head.link['href'])
                        else:
                            Favicon['internals'].append(hostname + head.link['href'])
                else:
                    Favicon['externals'].append(head.link['href'])

    # collect i_frame
    for i_frame in soup.find_all('iframe', width=True, height=True, frameborder=True):
        if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['frameborder'] == "0":
            IFrame['invisible'].append(i_frame)
        else:
            IFrame['visible'].append(i_frame)
    for i_frame in soup.find_all('iframe', width=True, height=True, border=True):
        if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['border'] == "0":
            IFrame['invisible'].append(i_frame)
        else:
            IFrame['visible'].append(i_frame)
    for i_frame in soup.find_all('iframe', width=True, height=True, style=True):
        if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['style'] == "border:none;":
            IFrame['invisible'].append(i_frame)
        else:
            IFrame['visible'].append(i_frame)

    # get page title
    try:
        Title = soup.title.string
    except:
        pass

    # get content text
    Text = soup.get_text()

    return Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text


def extract_features(url, status):
    def words_raw_extraction(domain, subdomain, path):
        w_domain = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", domain.lower())
        w_subdomain = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", subdomain.lower())
        w_path = re.split("\-|\.|\/|\?|\=|\@|\&|\%|\:|\_", path.lower())
        raw_words = w_domain + w_path + w_subdomain
        w_host = w_domain + w_subdomain
        raw_words = list(filter(None, raw_words))
        return raw_words, list(filter(None, w_host)), list(filter(None, w_path))

    Href = {'internals': [], 'externals': [], 'null': []}
    Link = {'internals': [], 'externals': [], 'null': []}
    Anchor = {'safe': [], 'unsafe': [], 'null': []}
    Media = {'internals': [], 'externals': [], 'null': []}
    Form = {'internals': [], 'externals': [], 'null': []}
    CSS = {'internals': [], 'externals': [], 'null': []}
    Favicon = {'internals': [], 'externals': [], 'null': []}
    IFrame = {'visible': [], 'invisible': [], 'null': []}
    Title = ''
    Text = ''
    state, iurl, page = is_url_accessible(url)
    if state:
        content = page.content
        hostname, domain, path = get_domain(url)
        extracted_domain = tldextract.extract(url)
        domain = extracted_domain.domain + '.' + extracted_domain.suffix
        subdomain = extracted_domain.subdomain
        tmp = url[url.find(extracted_domain.suffix):len(url)]
        pth = tmp.partition("/")
        path = pth[1] + pth[2]
        words_raw, words_raw_host, words_raw_path = words_raw_extraction(extracted_domain.domain, subdomain, pth[2])
        tld = extracted_domain.suffix
        parsed = urlparse(url)
        scheme = parsed.scheme

        #Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text = extract_data_from_url(hostname, content,
                                                                                                   # domain, Href, Link,
                                                                                                   # Anchor, Media, Form,
                                                                                                   # CSS, Favicon, IFrame,
                                                                                                   # Title, Text)

        features = {
            # URL-based features
            'url': url,  # Временное поле, будет удалено
            'length_url': ufe.url_length(url),
            'length_hostname': ufe.url_length(hostname),
            'ip': ufe.has_ip_address(url),
            'url_dots': ufe.count_dots(url),
            'url_hyphens': ufe.count_hyphens(url),
            'url_at': ufe.count_at(url),
            'url_qm': ufe.count_exclamation(url),
            'url_and': ufe.count_and(url),
            'url_or': ufe.count_or(url),  # Заглушка
            'url_eq': ufe.count_equal(url),
            'url_underscore': ufe.count_underscore(url),
            'url_tilde': ufe.count_tilde(url),  # Заглушка
            'url_percent': ufe.count_percentage(url),
            'url_slash': ufe.count_slash(url),
            'url_star': ufe.count_star(url),
            'url_colon': ufe.count_colon(url),
            'url_comma': ufe.count_comma(url),
            'url_semicolumn': ufe.count_semicolumn(url),
            'url_dollar': ufe.count_dollar(url),
            'url_space': ufe.count_space(url),
            # 'nb_www': 1 if 'www' in url else 0,
            # 'nb_com': 1 if '.com' in url else 0,
            'url_dslash': ufe.count_double_slash(url),
            'http_in_path': ufe.count_http_token(path),
            'https_token': ufe.https_token(scheme),
            'ratio_digits_url': ufe.ratio_digits(url),
            'ratio_digits_host': ufe.ratio_digits(hostname),
            'punycode': ufe.punycode(url),
            'port': ufe.port(url),
            'tld_in_path': ufe.tld_in_path(tld, path),
            'tld_in_subdomain': ufe.tld_in_subdomain(tld, subdomain),
            # 'abnormal_subdomain': 0,  # Заглушка
            'url_subdomains': ufe.count_subdomain(url),
            # 'prefix_suffix': 0,  # Заглушка (требует re)
            'random_domain': ufe.random_domain(domain),
            'shortening_service': ufe.is_shortened_url(url),
            'path_extension': ufe.path_extension(url),
            'url_redirection': ufe.count_redirection(page),  # требуется requests
            'url_external_redirection': ufe.count_external_redirection(page, domain),  # требуется requests
            # 'length_words_raw': ufe.length_word_raw(words_raw),  # Заглушка
            # 'char_repeat': 0,  # Заглушка
            # 'shortest_words_raw': 0,  # Заглушка
            # 'shortest_word_host': 0,  # Заглушка
            # 'shortest_word_path': 0,  # Заглушка
            # 'longest_words_raw': 0,  # Заглушка
            # 'longest_word_host': 0,  # Заглушка
            # 'longest_word_path': 0,  # Заглушка
            # 'avg_words_raw': 0.0,  # Заглушка
            # 'avg_word_host': 0.0,  # Заглушка
            # 'avg_word_path': 0.0,  # Заглушка
            'phish_hints': ufe.phish_hints(url),  # Заглушка
            # 'domain_in_brand': 0,  # Заглушка Доделать???
            'brand_in_subdomain': ufe.brand_imitation(extracted_domain.domain,subdomain),  # Заглушка
            'brand_in_path': ufe.brand_imitation(extracted_domain.domain,path),  # Заглушка
            'suspicious_tld': ufe.suspicious_tld(tld),  # Заглушка (требует urlparse)
            # 'statistical_report': 0,  # Заглушка
            'nb_hyperlinks': 0,  # Заглушка
            'ratio_intHyperlinks': 0.0,  # Заглушка
            'ratio_extHyperlinks': 0.0,  # Заглушка
            'ratio_nullHyperlinks': 0.0,  # Заглушка
            'nb_extCSS': 0,  # Заглушка
            'ratio_intRedirection': 0.0,  # Заглушка
            'ratio_extRedirection': 0.0,  # Заглушка
            'ratio_intErrors': 0.0,  # Заглушка
            'ratio_extErrors': 0.0,  # Заглушка
            'login_form': 0,  # Заглушка
            'external_favicon': 0,  # Заглушка
            'links_in_tags': 0,  # Заглушка
            'submit_email': 0,  # Заглушка
            'ratio_intMedia': 0.0,  # Заглушка
            'ratio_extMedia': 0.0,  # Заглушка
            'sfh': 0,  # Заглушка
            'iframe': 0,  # Заглушка
            'popup_window': 0,  # Заглушка
            'safe_anchor': 0,  # Заглушка
            'onmouseover': 0,  # Заглушка
            'right_clic': 0,  # Заглушка
            'empty_title': 0,  # Заглушка
            'domain_in_title': 0,  # Заглушка
            'domain_with_copyright': 0,  # Заглушка
            'whois_registered_domain': efe.whois_registered_domain(url),
            'domain_registration_length': efe.domain_registration_length(url),
            'domain_age': efe.domain_age(url),
            # 'web_traffic': 0,  # Заглушка
            'dns_record': efe.dns_record(url),
            # 'google_index': 0,  # Заглушка (требует check_google_index)
            'page_rank': efe.page_rank(url),
            'status': 0  # УДАЛИТЬ
        }

        # Удаляем служебные поля
        del features['url']
        del features['status']

        return features
    return None

def get_domain(url):
    o = urllib.parse.urlsplit(url)
    return o.hostname, tldextract.extract(url).domain, o.path

# def extract_features(url):
#     features = {
#         # URL-based features
#         'url': url,  # Временное поле, будет удалено
#         'length_url': ufe.url_length(url),
#         # 'length_hostname': 0,  # Заглушка (требует urlparse)
#         'ip': 0,  # Заглушка (требует re)
#         'nb_dots': url.count('.'),
#         'nb_hyphens': url.count('-'),
#         'nb_at': url.count('@'),
#         'nb_qm': url.count('?'),
#         'nb_and': url.count('&'),
#         'nb_or': 0,  # Заглушка
#         'nb_eq': url.count('='),
#         'nb_underscore': url.count('_'),
#         'nb_tilde': 0,  # Заглушка
#         'nb_percent': url.count('%'),
#         'nb_slash': url.count('/'),
#         'nb_star': 0,  # Заглушка
#         'nb_colon': url.count(':'),
#         'nb_comma': 0,  # Заглушка
#         'nb_semicolumn': 0,  # Заглушка
#         'nb_dollar': 0,  # Заглушка
#         'nb_space': 0,  # Заглушка
#         'nb_www': 1 if 'www' in url else 0,
#         'nb_com': 1 if '.com' in url else 0,
#         'nb_dslash': 0,  # Заглушка
#         'http_in_path': 0,  # Заглушка (требует urlparse)
#         'https_token': 1 if url.startswith('https') else 0,
#         'ratio_digits_url': url.count('0') / len(url) if len(url) > 0 else 0.0,
#         'ratio_digits_host': 0.0,  # Заглушка (требует urlparse)
#         'punycode': 1 if 'xn--' in url else 0,
#         'port': 0,  # Заглушка (требует urlparse)
#         'tld_in_path': 0,  # Заглушка (требует urlparse)
#         'tld_in_subdomain': 0,  # Заглушка
#         'abnormal_subdomain': 0,  # Заглушка
#         'nb_subdomains': 0,  # Заглушка (требует urlparse)
#         'prefix_suffix': 0,  # Заглушка (требует re)
#         'random_domain': 0,  # Заглушка
#         'shortening_service': 1 if any(s in url for s in ['bit.ly', 'goo.gl']) else 0,
#         'path_extension': 0,  # Заглушка (требует urlparse)
#         'nb_redirection': 0,  # Заглушка
#         'nb_external_redirection': 0,  # Заглушка
#         'length_words_raw': 0,  # Заглушка
#         'char_repeat': 0,  # Заглушка
#         'shortest_words_raw': 0,  # Заглушка
#         'shortest_word_host': 0,  # Заглушка
#         'shortest_word_path': 0,  # Заглушка
#         'longest_words_raw': 0,  # Заглушка
#         'longest_word_host': 0,  # Заглушка
#         'longest_word_path': 0,  # Заглушка
#         'avg_words_raw': 0.0,  # Заглушка
#         'avg_word_host': 0.0,  # Заглушка
#         'avg_word_path': 0.0,  # Заглушка
#         'phish_hints': 0,  # Заглушка
#         'domain_in_brand': 0,  # Заглушка
#         'brand_in_subdomain': 0,  # Заглушка
#         'brand_in_path': 0,  # Заглушка
#         'suspecious_tld': 0,  # Заглушка (требует urlparse)
#         'statistical_report': 0,  # Заглушка
#         'nb_hyperlinks': 0,  # Заглушка
#         'ratio_intHyperlinks': 0.0,  # Заглушка
#         'ratio_extHyperlinks': 0.0,  # Заглушка
#         'ratio_nullHyperlinks': 0.0,  # Заглушка
#         'nb_extCSS': 0,  # Заглушка
#         'ratio_intRedirection': 0.0,  # Заглушка
#         'ratio_extRedirection': 0.0,  # Заглушка
#         'ratio_intErrors': 0.0,  # Заглушка
#         'ratio_extErrors': 0.0,  # Заглушка
#         'login_form': 0,  # Заглушка
#         'external_favicon': 0,  # Заглушка
#         'links_in_tags': 0,  # Заглушка
#         'submit_email': 0,  # Заглушка
#         'ratio_intMedia': 0.0,  # Заглушка
#         'ratio_extMedia': 0.0,  # Заглушка
#         'sfh': 0,  # Заглушка
#         'iframe': 0,  # Заглушка
#         'popup_window': 0,  # Заглушка
#         'safe_anchor': 0,  # Заглушка
#         'onmouseover': 0,  # Заглушка
#         'right_clic': 0,  # Заглушка
#         'empty_title': 0,  # Заглушка
#         'domain_in_title': 0,  # Заглушка
#         'domain_with_copyright': 0,  # Заглушка
#         'whois_registered_domain': efe.whois_registered_domain(url),
#         'domain_registration_length': efe.domain_registration_length(url),
#         'domain_age': efe.domain_age(url),
#         'web_traffic': 0,  # Заглушка
#         'dns_record': efe.dns_record(url),
#         'google_index': 0,  # Заглушка (требует check_google_index)
#         'page_rank': efe.page_rank(url),
#         'status': 0  # УДАЛИТЬ
#     }
#
#     # Удаляем служебные поля
#     del features['url']
#     del features['status']
#
#     return features

if __name__ == "__main__":
    url = "https://nikulya.ru"  # Замените на нужный домен
    all_features = extract_features(url, "legitimate")
    print(all_features)