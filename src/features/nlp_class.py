import ssl

import certifi
import nltk
from nltk.corpus import words, brown
from nltk import bigrams
from nltk.probability import FreqDist
import tldextract

nltk.download('words', quiet=True)
nltk.download('brown', quiet=True)

# Фикс для SSL
ssl._create_default_https_context = lambda: ssl.create_default_context(cafile=certifi.where())

class DomainRandomnessChecker:
    def __init__(self):
        # Загрузка английского словаря
        self.english_words = set(words.words())

        # Подготовка данных о частоте биграмм
        brown_bigrams = []
        for word in brown.words():
            word_lower = word.lower()
            if len(word_lower) >= 2:
                brown_bigrams.extend(bigrams(word_lower))

        self.bigram_freq = FreqDist(brown_bigrams)
        total = sum(self.bigram_freq.values()) or 1
        self.bigram_prob = {bg: count / total for bg, count in self.bigram_freq.items()}

        # Инициализация парсера доменов
        self.extract = tldextract.TLDExtract()

    def preprocess_domain(self, domain):
        """Извлечение основной части домена"""
        extracted = self.extract(domain)
        return extracted.domain

    def contains_english_words(self, text):
        """Проверка наличия английских слов в тексте"""
        text_lower = text.lower()
        max_len = min(15, len(text_lower))

        for length in range(3, max_len + 1):
            for i in range(len(text_lower) - length + 1):
                if text_lower[i:i + length] in self.english_words:
                    return True
        return False

    def calculate_bigram_score(self, text):
        """Вычисление среднего значения вероятностей биграмм"""
        text_bigrams = list(bigrams(text.lower()))
        if not text_bigrams:
            return 0.0

        total = 0.0
        for bg in text_bigrams:
            total += self.bigram_prob.get(bg, 0.0)
        return total / len(text_bigrams)

    def analyze_domain(self, domain):
        """Полный анализ домена"""
        main_part = self.preprocess_domain(domain)
        if not main_part:
            return {}

        return {
            'length': len(main_part),
            'has_digits': any(c.isdigit() for c in main_part),
            'contains_words': self.contains_english_words(main_part),
            'bigram_score': self.calculate_bigram_score(main_part)
        }

    def is_random_domain(self, domain, threshold=0.5):
        """Определение случайности домена"""
        analysis = self.analyze_domain(domain)
        if not analysis:
            return False

        # Эвристические правила
        score = 0

        if not analysis['contains_words']:
            score += 2

        if analysis['bigram_score'] < 0.0001:
            score += 1

        if analysis['length'] >= 15:
            score += 1

        if analysis['has_digits']:
            score += 1

        return score >= 3


# Пример использования
if __name__ == "__main__":
    checker = DomainRandomnessChecker()

    test_domains = [
        "example.com",
        "google.com",
        "xkjfhsd83h4.net",
        "random123generator.org",
        "a1b2c3d4e5f6g7.com",
        "facebook.com",
        "trv8s2pq.xyz"
    ]

    for domain in test_domains:
        result = checker.is_random_domain(domain)
        # analysis = checker.analyze_domain(domain)
        print(f"Домен: {domain}")
        print(f"Результат анализа: {'Случайный' if result else 'Не случайный'}")
        # print(f"Детали: {analysis}\n")