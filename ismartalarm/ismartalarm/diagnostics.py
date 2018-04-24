# ismartalarm.py
# Project: pentesting
#
# Created by "Francesco Servida"
# Created on 18.04.18

from pprint import pprint
import re
import urllib
from datetime import datetime
import json
import base64


def post_parse(post_dict):
    post_content = post_dict['post_content']
    post_dict['post_content'] = {post_key: post_value for post_key, post_value in
                                 [post_tuple.split("=") for post_tuple in post_content.split("&") if
                                  len(post_tuple.split("=")) == 2]}

    post_dict['timestamp'] = datetime.fromtimestamp(int(str(int(post_dict['timestamp'], 16))[:10])).isoformat()
    try:
        post_dict['timestamp_post'] = datetime.fromtimestamp(int(str(post_dict['post_content']['TS'])[:10])).isoformat()
    except KeyError:
        # Timestamp not found in post content
        pass

    try:
        post_dict['BaseMessage_Decoded'] = base64.b64decode(
            urllib.unquote(post_dict['post_content']['BaseMessage'].encode("utf8")))
    except KeyError:
        # Post Params do not contain a Base Message
        pass

    return post_dict


def parse_post_events(events):
    post_re = re.compile(
        "@(?P<timestamp>.*)::.*?::POST (?P<path>.*) HTTP/1\.1\r\nHost:(?P<host>.*)(?:\r\n.*){5}\r\n(?P<post_content>.*)")

    post_events = [event for event in events if "::POST" in event]

    post_events = map(post_parse, [post_re.match(event).groupdict() for event in post_events])

    http_posts_by_path = {}
    for event in post_events:
        if event['path'] in http_posts_by_path:
            http_posts_by_path[event['path']].append(event)
        else:
            http_posts_by_path[event['path']] = [event]

    return http_posts_by_path


def parse_door_events(events):
    door_events = [event for event in events if "::ALARMDOOR::{" in event]
    door_re = re.compile(".*::ALARMDOOR::(?P<json_message>{.*})")

    door_events = [json.loads(door_re.match(event).groupdict()['json_message']) for event in door_events]

    for event in door_events:
        event["timestamp"] = datetime.fromtimestamp(int(event['TS'][:10])).isoformat()
        event["event"] = "Door Closed" if int(event['MessageType']) else "Door Open"

    return door_events


def parse_mode_events(events):
    actions = {
        0: "ARM",
        1: "HOME",
        2: "DISARM",
        3: "PANIC"
    }

    mode_events = [events for events in events if "MODEID" in events]

    mode_re = re.compile("@(?P<timestamp>.*)::MODEID::.*")

    mode_events = [(str(int(mode_re.match(event).groupdict()['timestamp'], 16))[:10], event) for event in mode_events]

    mode_event_dict = {}
    for event in mode_events:
        if event[0] in mode_event_dict:
            mode_event_dict[event[0]].append(event[1])
        else:
            mode_event_dict[event[0]] = [event[1]]

    mode_event_dict = {timestamp: events for timestamp, events in mode_event_dict.items() if len(events) == 2 and not (
    "Mqtt add or mofidy modeid" in events[0] or "Mqtt add or mofidy modeid" in events[1])}

    mode_events = []
    for events in mode_event_dict.values():
        for event in events:
            if "change modeid" not in event:
                mode_events.append(event)

    mode_re = re.compile("@(?P<timestamp>.*)::MODEID::(?P<mode_id>\d)")
    mode_events = [mode_re.match(event).groupdict() for event in mode_events]

    for event in mode_events:
        event["action"] = actions[int(event['mode_id'])]
        event["timestamp_iso"] = datetime.fromtimestamp(int(str(int(event["timestamp"], 16))[:10])).isoformat()

    return sorted(mode_events, key=lambda x: x['timestamp'])

if __name__ == '__main__':
    with open("../data/server_stream", "rb") as file:
        stream = file.read()

    diag = stream.decode('utf-8', 'ignore')
    diag = diag.encode('ascii', 'ignore')
    events = diag.split("$")

    http_posts_by_path = parse_post_events(events)
    with open('../data/server_stream_extracted.json', 'w') as file:
        json.dump(http_posts_by_path, file, indent=4)

    door_events = parse_door_events(events)
    with open('../data/server_stream_door_events.json', 'w') as file:
        json.dump(door_events, file, indent=4)

    mode_events = parse_mode_events(events)
    with open('../data/server_stream_mode_events.json', 'w') as file:
        json.dump(mode_events, file, indent=4)

    with open('../data/server_stream.json', 'w') as file:
        json.dump(events, file, indent=4)
