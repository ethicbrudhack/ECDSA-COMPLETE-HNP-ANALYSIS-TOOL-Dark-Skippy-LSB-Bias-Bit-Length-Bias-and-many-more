import requests
import time
import random
import os

dzialajace_api = None
failed_blocks = 0

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36"
]

api_urls = [
    'https://api.blockchair.com/bitcoin/raw/block/{block_height}',
    'https://blockchain.info/rawblock/{block_height}',
    'https://blockstream.info/api/block-height/{block_height}',
    'https://mempool.space/api/block-height/{block_height}'
]

LAST_BLOCK_FILE = "last_block.txt"
TXID_FILE = "txids.txt"

def zapisz_do_pliku(nazwa, linia):
    with open(nazwa, "a") as f:
        f.write(linia + "\n")

def zapisz_ostatni_blok(block_height):
    with open(LAST_BLOCK_FILE, "w") as f:
        f.write(str(block_height))

def odczytaj_ostatni_blok(start_fallback):
    if os.path.exists(LAST_BLOCK_FILE):
        try:
            with open(LAST_BLOCK_FILE, "r") as f:
                return int(f.read().strip())
        except:
            return start_fallback
    return start_fallback

def znajdz_dzialajace_api(block_height):
    global dzialajace_api
    for api_url in api_urls:
        print(f"Testuję API: {api_url}")
        test_url = api_url.format(block_height=block_height)
        headers = {'User-Agent': random.choice(user_agents)}

        try:
            response = requests.get(test_url, headers=headers, timeout=10)
            if response.status_code == 200:
                print(f"Wybrano działające API: {api_url}")
                dzialajace_api = api_url
                return
        except Exception as e:
            print(f"API {api_url} nie działa: {e}")
    print("Nie znaleziono działającego API.")
    dzialajace_api = None

def get_txids_from_block(block_height):
    global dzialajace_api, failed_blocks

    if not dzialajace_api:
        znajdz_dzialajace_api(block_height)
        if not dzialajace_api:
            return []

    url = dzialajace_api.format(block_height=block_height)
    headers = {'User-Agent': random.choice(user_agents)}

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 429:
            print(f"API zablokowane (429) dla bloku {block_height}, spróbuję później.")
            failed_blocks += 1
            return []

        elif response.status_code != 200:
            print(f"Błąd API {dzialajace_api} dla bloku {block_height}: {response.status_code}")
            failed_blocks += 1
            return []

        failed_blocks = 0

        # Obsługa Blockchair
        if "blockchair" in dzialajace_api:
            block_data = response.json()
            data = block_data['data'].get(str(block_height))
            txids = data['decoded_raw_block']['tx']

        # Obsługa Blockchain.info
        elif "blockchain.info" in dzialajace_api:
            block_data = response.json()
            txids = [tx['hash'] for tx in block_data.get('tx', [])]

        # Obsługa Blockstream / Mempool.space
        elif "blockstream.info" in dzialajace_api or "mempool.space" in dzialajace_api:
            block_hash = response.text.strip()
            tx_response = requests.get(f"https://{dzialajace_api.split('/')[2]}/api/block/{block_hash}/txids",
                                       headers={'User-Agent': random.choice(user_agents)}, timeout=15)
            if tx_response.status_code == 200:
                try:
                    txids = tx_response.json()
                except ValueError:
                    print(f"⚠️ Błąd JSON dla bloku {block_height}, odpowiedź: {tx_response.text[:100]}...")
                    failed_blocks += 1
                    return []
            else:
                print(f"Błąd podczas pobierania txids dla hash: {block_hash}")
                failed_blocks += 1
                return []

        else:
            print("Nieznane API.")
            return []

        # Zapis txidów do pliku
        for txid in txids:
            zapisz_do_pliku(TXID_FILE, txid)

        return txids

    except Exception as e:
        print(f"Błąd przy pobieraniu bloku {block_height}: {e}")
        failed_blocks += 1
        return []

def fetch_txids_for_blocks(start_block, end_block):
    global failed_blocks, dzialajace_api
    all_txids = []

    for block_height in range(start_block, end_block + 1):
        print(f"\n📦 Pobieram transakcje dla bloku {block_height}...")
        txids = get_txids_from_block(block_height)

        if txids:
            print(f"✅ Znaleziono {len(txids)} transakcji w bloku {block_height}.")
            all_txids.extend(txids)
        else:
            print(f"⚠️ Brak transakcji lub błąd w bloku {block_height}.")

        zapisz_ostatni_blok(block_height)

        if failed_blocks >= 3:
            print(f"🔁 Zbyt wiele błędów – zmieniam API...")
            dzialajace_api = None
            failed_blocks = 0

        time.sleep(1)  # opóźnienie, żeby nie przeciążyć API

    return all_txids

if __name__ == "__main__":
    DEFAULT_START_BLOCK = 1
    END_BLOCK = 1000000

    start_block = odczytaj_ostatni_blok(DEFAULT_START_BLOCK)
    print(f"▶️ Start pobierania od bloku {start_block} do {END_BLOCK}.")

    txids = fetch_txids_for_blocks(start_block, END_BLOCK)

    if txids:
        print(f"\n🎯 Znaleziono {len(txids)} transakcji w sumie.")
    else:
        print("\n❌ Nie znaleziono żadnych transakcji.")
