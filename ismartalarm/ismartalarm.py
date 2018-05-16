# ismart_alarm.py
# Project: autopsy_plugins
# 
# Created by "Francesco Servida"
# Created on 16.05.18

import os, errno
import argparse
import sys
import json
from ipaddress import ip_address
from datetime import datetime
from ismartalarm.diagnostics import *

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Dump iSmartAlarm diagnostics log & parses data")
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    parser.add_argument('-v', '--verbose', help="Enable debugging output", action='store_true')
    parser.add_argument('-p', '--path', help="Output path, default is ./YYYY-MM-DDThh_mm_ss", type=str,
                        default=datetime.now().isoformat().replace(":", "_")[:-7])

    subparsers = parser.add_subparsers(dest='command')
    subparsers.required = True

    #  subparser for dump & parse
    parser_dump = subparsers.add_parser('dump')
    # add a required argument
    parser_dump.add_argument('ip', help='IP Address of the iSmartAlarm Device.', type=ip_address)

    #  subparser for parse only action
    parser_parse = subparsers.add_parser('parse')
    # add a required argument
    parser_parse.add_argument('input', help='File to be analyzed (default: std input)', nargs='?',
                              type=argparse.FileType('rb'), default=sys.stdin)

    args = parser.parse_args()

    # Create output directory
    try:
        os.makedirs(args.path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    # Dump log if needed
    if args.command == 'dump':
        log = dump_log(args.ip, args.verbose)
        with open(os.path.join(args.path, 'server_stream'), 'wb')as file:
            file.write(log)

    # Read the log if needed
    if args.command == 'parse':
        log = args.input.read()

    # Finally parse the log

    diag = log.decode('utf-8', 'ignore')
    events = diag.split("$")

    http_posts_by_path = parse_post_events(events)
    with open(os.path.join(args.path, 'server_stream_post_requests.json'), 'w') as file:
        json.dump(http_posts_by_path, file, indent=4)

    door_events = parse_door_events(events)
    with open(os.path.join(args.path, 'server_stream_door_events.json'), 'w') as file:
        json.dump(door_events, file, indent=4)

    mode_events = parse_mode_events(events)
    with open(os.path.join(args.path, 'server_stream_mode_events.json'), 'w') as file:
        json.dump(mode_events, file, indent=4)

    with open(os.path.join(args.path, 'server_stream.json'), 'w') as file:
        json.dump(events, file, indent=4)
