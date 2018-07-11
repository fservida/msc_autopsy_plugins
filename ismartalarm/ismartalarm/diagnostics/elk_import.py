# elk_import.py
# Project: autopsy_plugins
# 
# Created by "Francesco Servida"
# Created on 29.06.18

from datetime import datetime
import json
from elasticsearch import Elasticsearch
es = Elasticsearch('elk.hogwarts.servida.ch:9200')

with open("../../2018-05-17T10_54_28/server_stream_post_requests.json") as file:
    requests = json.load(file)

# es.indices.create(index='ismartalarm-dfrws', body={
#    'settings': {
#          'index': {
#               'number_of_shards': 1,
#               'number_of_replicas': 0
#          }
#    }
# })

i = 0
for path in requests:
    for request in requests[path]:
        print(request)
        es.index(index='ismartalarm-dfrws', doc_type='post_requests', id=i, body=request)
        i += 1
print(i)