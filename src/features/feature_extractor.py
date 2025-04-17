import src.features.external_features_extractor as efe


def extract_features(url):
    features = {
        # URL-based features
        'url': url,  # Временное поле, будет удалено
        'length_url': len(url),
        'length_hostname': 0,  # Заглушка (требует urlparse)
        'ip': 0,  # Заглушка (требует re)
        'nb_dots': url.count('.'),
        'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'),
        'nb_qm': url.count('?'),
        'nb_and': url.count('&'),
        'nb_or': 0,  # Заглушка
        'nb_eq': url.count('='),
        'nb_underscore': url.count('_'),
        'nb_tilde': 0,  # Заглушка
        'nb_percent': url.count('%'),
        'nb_slash': url.count('/'),
        'nb_star': 0,  # Заглушка
        'nb_colon': url.count(':'),
        'nb_comma': 0,  # Заглушка
        'nb_semicolumn': 0,  # Заглушка
        'nb_dollar': 0,  # Заглушка
        'nb_space': 0,  # Заглушка
        'nb_www': 1 if 'www' in url else 0,
        'nb_com': 1 if '.com' in url else 0,
        'nb_dslash': 0,  # Заглушка
        'http_in_path': 0,  # Заглушка (требует urlparse)
        'https_token': 1 if url.startswith('https') else 0,
        'ratio_digits_url': url.count('0') / len(url) if len(url) > 0 else 0.0,
        'ratio_digits_host': 0.0,  # Заглушка (требует urlparse)
        'punycode': 1 if 'xn--' in url else 0,
        'port': 0,  # Заглушка (требует urlparse)
        'tld_in_path': 0,  # Заглушка (требует urlparse)
        'tld_in_subdomain': 0,  # Заглушка
        'abnormal_subdomain': 0,  # Заглушка
        'nb_subdomains': 0,  # Заглушка (требует urlparse)
        'prefix_suffix': 0,  # Заглушка (требует re)
        'random_domain': 0,  # Заглушка
        'shortening_service': 1 if any(s in url for s in ['bit.ly', 'goo.gl']) else 0,
        'path_extension': 0,  # Заглушка (требует urlparse)
        'nb_redirection': 0,  # Заглушка
        'nb_external_redirection': 0,  # Заглушка
        'length_words_raw': 0,  # Заглушка
        'char_repeat': 0,  # Заглушка
        'shortest_words_raw': 0,  # Заглушка
        'shortest_word_host': 0,  # Заглушка
        'shortest_word_path': 0,  # Заглушка
        'longest_words_raw': 0,  # Заглушка
        'longest_word_host': 0,  # Заглушка
        'longest_word_path': 0,  # Заглушка
        'avg_words_raw': 0.0,  # Заглушка
        'avg_word_host': 0.0,  # Заглушка
        'avg_word_path': 0.0,  # Заглушка
        'phish_hints': 0,  # Заглушка
        'domain_in_brand': 0,  # Заглушка
        'brand_in_subdomain': 0,  # Заглушка
        'brand_in_path': 0,  # Заглушка
        'suspecious_tld': 0,  # Заглушка (требует urlparse)
        'statistical_report': 0,  # Заглушка
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
        'web_traffic': 0,  # Заглушка
        'dns_record': efe.dns_record(url),
        'google_index': 0,  # Заглушка (требует check_google_index)
        'page_rank': efe.page_rank(url),
        'status': 0  # УДАЛИТЬ
    }

    # Удаляем служебные поля
    del features['url']
    del features['status']

    return features

if __name__ == "__main__":
    domain = "vk.ru"  # Замените на нужный домен
    all_features = extract_features(domain)
    print(all_features)