import csv
import logging
import os
import re
import urllib.parse
import urllib.parse
from functools import wraps
from urllib.parse import urlparse
import pandas as pd
import time
from tqdm import tqdm
import pickle
import pandas as pd
import tldextract
from bs4 import BeautifulSoup
from requests.exceptions import RequestException, Timeout

import src.features.content_features_extractor as confe
import src.features.external_features_extractor as extfe
import src.features.url_features_extractor as urlfe

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


def process_dataset(input_file, output_file, max_urls=None, checkpoint_interval=2):
    """
    Обрабатывает датасет URL, извлекает характеристики и сохраняет результат

    Параметры:
        input_file (str): путь к входному CSV файлу с URL
        output_file (str): путь для сохранения результата
        max_urls (int): максимальное количество URL для обработки (None для всех)
        checkpoint_interval (int): частота сохранения промежуточных результатов
    """
    # Загружаем исходный датасет
    df = pd.read_csv(input_file, sep=';')

    # Ограничиваем количество URL, если нужно
    if max_urls is not None and max_urls < len(df):
        df = df.sample(max_urls, random_state=42)

    # Создаем список для хранения результатов
    results = []
    failed_urls = []

    # Обрабатываем каждый URL с прогресс-баром
    for idx, row in tqdm(df.iterrows(), total=len(df), desc="Processing URLs"):
        url = row['url']
        status = row['status']

        try:
            # Извлекаем характеристики
            features = extract_features(url, status)

            if features is not None:
                # Создаем новую запись с url в начале и status в конце
                new_entry = {'url': url}
                new_entry.update(features)
                new_entry['status'] = status
                results.append(new_entry)
            else:
                failed_urls.append(url)

            # Сохраняем промежуточные результаты
            if (idx + 1) % checkpoint_interval == 0:
                save_checkpoint(results, failed_urls, output_file)

            # Небольшая задержка для избежания блокировки
            time.sleep(0.5)

        except Exception as e:
            print(f"Error processing {url}: {str(e)}")
            failed_urls.append(url)
            continue

    # Сохраняем финальные результаты
    save_final_results(results, failed_urls, output_file)

    return results, failed_urls


def save_checkpoint(results, failed_urls, output_file):
    """Сохраняет промежуточные результаты"""
    if len(results) > 0:
        checkpoint_file = output_file.replace('.csv', f'_checkpoint_{len(results)}.pkl')
        with open(checkpoint_file, 'wb') as f:
            pickle.dump({'results': results, 'failed_urls': failed_urls}, f)


def save_final_results(results, failed_urls, output_file):
    """Сохраняет финальные результаты в CSV и информацию о неудачных URL"""
    if len(results) > 0:
        # Создаем DataFrame из результатов
        result_df = pd.DataFrame(results)

        # Сохраняем основной датасет
        result_df.to_csv(output_file, index=False)
        print(f"Successfully processed {len(result_df)} URLs. Saved to {output_file}")

    if len(failed_urls) > 0:
        # Сохраняем список неудачных URL
        failed_df = pd.DataFrame({'failed_urls': failed_urls})
        failed_file = output_file.replace('.csv', '_failed.csv')
        failed_df.to_csv(failed_file, index=False)
        print(f"Failed to process {len(failed_urls)} URLs. List saved to {failed_file}")


def load_checkpoint(checkpoint_file):
    """Загружает промежуточные результаты из checkpoint файла"""
    with open(checkpoint_file, 'rb') as f:
        data = pickle.load(f)
    return data['results'], data['failed_urls']

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
    for link in soup.find_all('link', href=True):
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
    for form in soup.find_all('form', action=True):
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

        for head.link in soup.find_all('link', {'href': True, 'rel': True}):
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

        Href, Link, Anchor, Media, Form, CSS, Favicon, IFrame, Title, Text = extract_data_from_url(hostname, content,
                                                                                                   domain, Href, Link,
                                                                                                   Anchor, Media, Form,
                                                                                                   CSS, Favicon, IFrame,
                                                                                                   Title, Text)

        features = {
            # # # URL-based features
            'url': url,  # Временное поле, будет удалено
            'length_url': urlfe.url_length(url),
            'length_hostname': urlfe.url_length(hostname),
            'ip': urlfe.has_ip_address(url),
            'url_dots': urlfe.count_dots(url),
            'url_hyphens': urlfe.count_hyphens(url),
            'url_at': urlfe.count_at(url),
            'url_qm': urlfe.count_exclamation(url),
            'url_and': urlfe.count_and(url),
            'url_or': urlfe.count_or(url),  # Заглушка
            'url_eq': urlfe.count_equal(url),
            'url_underscore': urlfe.count_underscore(url),
            'url_tilde': urlfe.count_tilde(url),  # Заглушка
            'url_percent': urlfe.count_percentage(url),
            'url_slash': urlfe.count_slash(url),
            'url_star': urlfe.count_star(url),
            'url_colon': urlfe.count_colon(url),
            'url_comma': urlfe.count_comma(url),
            'url_semicolumn': urlfe.count_semicolumn(url),
            'url_dollar': urlfe.count_dollar(url),
            'url_space': urlfe.count_space(url),
            'url_www': urlfe.check_www(url),
            'url_com': urlfe.check_com(url),
            'url_dslash': urlfe.count_double_slash(url),
            'http_in_path': urlfe.count_http_token(path),
            'https_token': urlfe.https_token(scheme),
            'ratio_digits_url': urlfe.ratio_digits(url),
            'ratio_digits_host': urlfe.ratio_digits(hostname),
            'punycode': urlfe.punycode(url),
            'port': urlfe.port(url),
            'tld_in_path': urlfe.tld_in_path(tld, path),
            'tld_in_subdomain': urlfe.tld_in_subdomain(tld, subdomain),
            # 'abnormal_subdomain': 0,  # Заглушка
            'url_subdomains': urlfe.count_subdomain(url),
            # 'prefix_suffix': 0,  # Заглушка (требует re)
            'random_domain': urlfe.random_domain(domain),
            'shortening_service': urlfe.is_shortened_url(url),
            'path_extension': urlfe.path_extension(url),
            'url_redirection': urlfe.count_redirection(page),  # требуется requests
            'url_external_redirection': urlfe.count_external_redirection(page, domain),  # требуется requests
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
            'phish_hints': urlfe.phish_hints(url),  # Заглушка
            'domain_in_brand': urlfe.domain_in_brand(extracted_domain.domain),  # Заглушка Доделать???
            'brand_in_subdomain': urlfe.brand_imitation(extracted_domain.domain, subdomain),  # Заглушка
            'brand_in_path': urlfe.brand_imitation(extracted_domain.domain, path),  # Заглушка
            'suspicious_tld': urlfe.suspicious_tld(tld),  # Заглушка (требует urlparse)
            # 'statistical_report': 0,  # Заглушка
            # # # content-based features
            'url_hyperlinks': confe.url_hyperlinks(Href, Link, Media, Form, CSS, Favicon),  # Заглушка
            'ratio_intHyperlinks': confe.internal_hyperlinks(Href, Link, Media, Form, CSS, Favicon),  # Заглушка
            'ratio_extHyperlinks': confe.external_hyperlinks(Href, Link, Media, Form, CSS, Favicon),  # Заглушка
            'ratio_nullHyperlinks': confe.null_hyperlinks(hostname, Href, Link, Media, Form, CSS, Favicon),  # Заглушка
            'url_extCSS': confe.external_css(CSS),  # Заглушка
            'ratio_intRedirection': confe.internal_redirection(Href, Link, Media, Form, CSS, Favicon),  # Заглушка
            'ratio_extRedirection': confe.external_redirection(Href, Link, Media, Form, CSS, Favicon),  # Заглушка
            'ratio_intErrors': confe.internal_errors(Href, Link, Media, Form, CSS, Favicon),  # Заглушка
            'ratio_extErrors': confe.external_errors(Href, Link, Media, Form, CSS, Favicon),  # Заглушка
            'login_form': confe.login_form(Form),  # Заглушка
            'external_favicon': confe.external_favicon(Favicon),  # Заглушка
            'links_in_tags': confe.links_in_tags(Link),  # Заглушка
            'submit_email': confe.submitting_to_email(Form),  # Заглушка
            'ratio_intMedia': confe.internal_media(Media),  # Заглушка
            'ratio_extMedia': confe.external_media(Media),  # Заглушка
            #  # additional content-based features
            # 'sfh': 0,  # Заглушка
            # 'iframe': 0,  # Заглушка
            'popup_window': confe.popup_window(Text),  # Заглушка
            # 'safe_anchor': 0,  # Заглушка
            'onmouseover': confe.onmouseover(Text),  # Заглушка
            'right_clic': confe.right_clic(Text),  # Заглушка
            'empty_title': confe.empty_title(Title),  # Заглушка
            'domain_in_title': confe.domain_in_title(extracted_domain.domain, Title),  # Заглушка
            # 'domain_with_copyright': 0,  # Заглушка
            # # # внешние признаки
            'whois_registered_domain': extfe.whois_registered_domain(url),
            'domain_registration_length': extfe.domain_registration_length(url),
            'domain_age': extfe.domain_age(url),
            # 'web_traffic': 0,  # Заглушка
            'dns_record': extfe.dns_record(url),
            # 'google_index': 0,  # Заглушка (требует check_google_index)
            'page_rank': extfe.page_rank(url),
            'ip_country_match': extfe.ip_country_match(domain),
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


if __name__ == "__main__":
    # url = "https://vk.ru"  # Замените на нужный домен
    # all_features = extract_features(url, "legitimate")
    # print(all_features)

    # Пример использования
    input_csv = "../../phish-collector/data/test.csv"
    output_csv = "../../phish-collector/data/dataset_with_features.csv"

    # Обрабатываем датасет
    results, failed_urls = process_dataset(input_csv, output_csv)
