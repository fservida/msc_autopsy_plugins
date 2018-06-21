import sqlite3
import json
from pprint import pprint

from datetime import datetime

db = "data/dfrws_wink_persistenceDB"

connection = sqlite3.connect(db)

cursor = connection.cursor()

activities = {}

for result in cursor.execute("SELECT json FROM Elements WHERE Type == 'activity'"):
    data = json.loads(result[0])
    device = data["object"]["object_name"]
    device_type = data["object"]["object_type"]
    action = data["action"]["reading"]
    date = datetime.fromtimestamp(int(data["created_at"]))

    activity = {
        "device": device,
        "device_type": device_type,
        "action": action,
        "date": date
    }

    activities[date] = activity

for date in sorted(activities.keys()):
    activity = activities[date]
    print(activity["date"].isoformat(), activity["device"], activity["device_type"], activity["action"])

