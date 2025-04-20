import requests
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from collections import Counter
from pymongo import MongoClient

load_dotenv(".env")

# Konfigurasi MongoDB
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")
COLLECTION_NAME = os.getenv("COLLECTION_NAME")

# Ganti dengan Bearer Token dan Zone ID Anda
CLOUDFLARE_API_URL = os.getenv("CLOUDFLARE_API_URL")
CLOUDFLARE_BEARER_TOKEN = os.getenv("CLOUDFLARE_BEARER_TOKEN")
ZONE_ID = os.getenv("ZONE_ID")

# Waktu mulai dan akhir (UTC) untuk 24 jam terakhir
# WIB ke UTC: Kurangi 7 jam
now_utc = datetime.utcnow()
today_wib = now_utc + timedelta(hours=7)

# Ambil tanggal WIB saat ini
date_wib = today_wib.date()

# Tentukan rentang waktu dalam UTC untuk hari yang sama di WIB
start_time_utc = datetime(date_wib.year, date_wib.month, date_wib.day, 0, 0, 0) - timedelta(hours=7)
end_time_utc = datetime(date_wib.year, date_wib.month, date_wib.day, 23, 59, 59) - timedelta(hours=7)

# Format output dalam format ISO 8601
start_time = start_time_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
end_time = end_time_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

print(f"Waktu pengambilan log dari {start_time} sampai {end_time}")

# Query GraphQL
GRAPHQL_QUERY = """
{
  viewer {
    zones(filter: {zoneTag: \"%s\"}) {
      firewallEventsAdaptiveGroups(
        filter: {AND: [ {datetime_geq: \"%s\", datetime_leq: \"%s\"}]} limit: 10000
      ) {
        count
        dimensions {
          action
          clientRequestHTTPHost
          clientCountryName
          clientASNDescription
          clientAsn
          ruleId
          clientIP
          kind
          edgeResponseStatus
          userAgent
          clientRequestHTTPProtocol
          clientRequestHTTPMethodName
          clientRefererHost
        }
      }
    }
  }
}
""" % (ZONE_ID, start_time, end_time)

def get_firewall_events():
    headers = {
        "Authorization": f"Bearer {CLOUDFLARE_BEARER_TOKEN}",
        "Content-Type": "application/json"
    }

    response = requests.post(CLOUDFLARE_API_URL, headers=headers, json={"query": GRAPHQL_QUERY})

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}, {response.text}")
        return None

def summarize_events(events):
    actions = Counter()
    hosts = Counter()
    countries = Counter()
    asns = Counter()
    rules = Counter()
    clientIP = Counter()
    kind = Counter()
    edgeResponseStatus = Counter()
    userAgent = Counter()
    clientRequestHTTPProtocol = Counter()
    clientRequestHTTPMethodName = Counter()
    clientRefererHost = Counter()

    if not events or "data" not in events or "viewer" not in events["data"]:
        print("No valid data received.")
        return None

    groups = events["data"]["viewer"]["zones"][0]["firewallEventsAdaptiveGroups"]
    for group in groups:
        count = group["count"]
        dimensions = group["dimensions"]

        actions[dimensions["action"]] += count
        hosts[dimensions["clientRequestHTTPHost"]] += count
        countries[dimensions["clientCountryName"]] += count
        asns[dimensions["clientASNDescription"]] += count
        rules[dimensions['ruleId']] += count
        clientIP[dimensions['clientIP']] += count
        kind[dimensions['kind']] += count
        edgeResponseStatus[str(dimensions['edgeResponseStatus'])] += count
        userAgent[dimensions['userAgent']] += count
        clientRequestHTTPProtocol[dimensions['clientRequestHTTPProtocol']] += count
        clientRequestHTTPMethodName[dimensions['clientRequestHTTPMethodName']] += count
        clientRefererHost[dimensions['clientRefererHost']] += count

    return {
        "timestamp": today_wib,
        "action_counts": dict(actions),
        "host_counts": dict(hosts),
        "country_counts": dict(countries),
        "asn_counts": dict(asns),
        "rule_counts": dict(rules),
        "clientIP": dict(clientIP),
        "kind": dict(kind),
        "edgeResponseStatus": dict(edgeResponseStatus),
        "userAgent": dict(userAgent),
        "clientRequestHTTPProtocol": dict(clientRequestHTTPProtocol),
        "clientRequestHTTPMethodName": dict(clientRequestHTTPMethodName),
        "clientRefererHost": dict(clientRefererHost)
    }

def save_to_mongo(data):
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]

    if data:
        collection.insert_one(data)
        print("Data saved to MongoDB\n")

def main():
    events = get_firewall_events()
    summary = summarize_events(events)
    if summary:
        save_to_mongo(summary)

if __name__ == "__main__":
    main()