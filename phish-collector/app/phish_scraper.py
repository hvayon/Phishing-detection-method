import requests

response = requests.get("https://data.phishtank.com/data/online-valid.json")
data = response.json()

with open("/data/phishtank_urls.txt", "w", encoding="utf-8") as file:
    for entry in data:
        file.write(entry["url"] + "\n")
print(f"Сохранено {len(data)} URL")