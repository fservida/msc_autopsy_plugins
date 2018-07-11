# network_collect.py
# Project: autopsy_plugins
# 
# Created by "Francesco Servida"
# Created on 24.04.18

import sys
import socket

TCP_PORT_AUTH = 12345
BUFFER_SIZE = 32
GET_AUTH_KEY = bytes.fromhex("495341544a0000000100000000000000")  # ISATJ

TCP_PORT_LOGS = 22306
BUFFER_AUTH_REPONSE = 18
BUFFER_FLOW_REPONSE = 1024
ASK_LOGS_AUTH_NOKEY = bytes.fromhex("4c4f4754480000000100000010000000")  # LOGTH
ASK_LOGS_FLOW = bytes.fromhex("4c4f4754460000000100000000000000")


def dump_log(ip, verbose=False):
    """
    Dumps the log from the ismartalarm
    :param ip: ip address of the ismartalarm device
    :param verbose: whether or not to print debug info to the stderr
    :return: collected log as a binary string
    """
    # Force ip to str (if eg. ip == ipaddress class)
    ip = str(ip)

    # Getting Auth Key
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, TCP_PORT_AUTH))
    s.send(GET_AUTH_KEY)
    data = s.recv(BUFFER_SIZE)
    s.close()

    auth_key = data[16:32]
    if verbose:
        print("Received data: {} - KEY: {}".format(data, auth_key), file=sys.stderr)


    # Asking for logs
    ask_logs_auth = ASK_LOGS_AUTH_NOKEY + auth_key

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, TCP_PORT_LOGS))

    s.send(ask_logs_auth)
    # Waiting for response and discard it, it's only a confirmation
    data = s.recv(BUFFER_AUTH_REPONSE)
    if verbose:
        print("Response: ", data, file=sys.stderr)

    # Socket Connection will time out after 10 seconds of inactivity (The Cube finished sending the logs)
    s.settimeout(10)
    s.send(ASK_LOGS_FLOW)
    # Waiting for response
    ismart_log = b""
    i = 0
    while 1:
        if i % 4 == 0 and verbose:
            print("Receiving logs...", file=sys.stderr)
        try:
            data = s.recv(BUFFER_FLOW_REPONSE)
            ismart_log += data
        except socket.timeout:
            if verbose:
                print("Connection timed out after 10 seconds of inactivity from the cube", file=sys.stderr)
            break
        i += 1

    s.close()
    return ismart_log


if __name__ == '__main__':
    from datetime import datetime

    log = dump_log("10.20.30.18", verbose=True)
    with open("data/log_stream_{}.txt".format(datetime.now().isoformat().replace(":", "_")[:-7]), "wb") as file:
        file.write(log)
