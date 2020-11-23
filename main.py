from typing import Optional, Union
from fastapi import Depends, FastAPI, WebSocket, HTTPException, Security, Request, Response, BackgroundTasks, Cookie, Query, WebSocketDisconnect
from fastapi import status, Header
from fastapi.security.api_key import APIKeyQuery, APIKeyHeader, APIKey
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.responses import RedirectResponse, JSONResponse
#from pygate_grpc.client import PowerGateClient
#from pygate_grpc.ffs import get_file_bytes, bytes_to_chunks, chunks_to_bytes
#from google.protobuf.json_format import MessageToDict
#from pygate_grpc.ffs import bytes_to_chunks
from eth_utils import keccak
from io import BytesIO
from maticvigil.EVCore import EVCore
from uuid import uuid4
import sqlite3
import logging
import sys
import json
import aioredis
import redis
import time
import requests
import hashlib
from skydb import SkydbTable
from config import settings
import os

formatter = logging.Formatter(u"%(levelname)-8s %(name)-4s %(asctime)s,%(msecs)d %(module)s-%(funcName)s: %(message)s")

stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
# stdout_handler.setFormatter(formatter)

stderr_handler = logging.StreamHandler(sys.stderr)
stderr_handler.setLevel(logging.ERROR)
# stderr_handler.setFormatter(formatter)
rest_logger = logging.getLogger(__name__)
rest_logger.setLevel(logging.DEBUG)
rest_logger.addHandler(stdout_handler)
rest_logger.addHandler(stderr_handler)

r = redis.Redis()
r.set('my_lock',0)

# Setup skydb
api_keys_table = SkydbTable(
			table_name=settings.table_names.api_keys,
			columns=["api_key","token"],
			seed=settings.seed,
			verbose=1
		)

accounting_records_table = SkydbTable(
			table_name=settings.table_names.accounting_records,
			columns=['token','cid','localCID','txHash','confirmed','timestamp'],
			seed=settings.seed,
			verbose=1
		)

#retreivals_single_table = SkydbTable(
#			table_name=settings.table_names.retreivals_single,
#			columns=['requestID','cid','localCID','retreived_file','completed'],
#			seed=settings.seed,
#			verbose=1
#		)
#
#retreivals_bulk_table = SkydbTable(
#			table_name=settings.table_names.retreivals_bulk,
#			columns=['requestID','api_key','token','retreived_file','completed'],
#			seed=settings.seed,
#			verbose=1
#		)
#
#skynet_table = SkydbTable(
#			table_name = settings.table_name.skynet_table,
#			columns=['api_key','file_id'],
#			seed=settings.seed,
#			verbose=1
#		)
#

# setup CORS origins stuff
origins = ["*"]

redis_lock = redis.Redis()

app = FastAPI(docs_url=None, openapi_url=None, redoc_url=None)
app.add_middleware(
	CORSMiddleware,
	allow_origins=origins,
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"]
)
app.mount('/static', StaticFiles(directory='static'), name='static')

evc = EVCore(verbose=True)
contract = evc.generate_contract_sdk(
	contract_address=settings.audit_contract,
	app_name='auditrecords'
)


REDIS_CONN_CONF = {
	"host": settings['REDIS']['HOST'],
	"port": settings['REDIS']['PORT'],
	"password": settings['REDIS']['PASSWORD'],
	"db": settings['REDIS']['DB']
}
#
STORAGE_CONFIG = {
  "hot": {
	"enabled": True,
	"allowUnfreeze": True,
	"ipfs": {
	  "addTimeout": 30
	}
  },
  "cold": {
	"enabled": True,
	"filecoin": {
	  "repFactor": 1,
	  "dealMinDuration": 518400,
	  "renew": {
	  },
	  "addr": "placeholderstring"
	}
  }
}


@app.on_event('startup')
async def startup_boilerplate():
	app.redis_pool: aioredis.Redis = await aioredis.create_redis_pool(
		address=(REDIS_CONN_CONF['host'], REDIS_CONN_CONF['port']),
		db=REDIS_CONN_CONF['db'],
		password=REDIS_CONN_CONF['password'],
		maxsize=5
	)
	app.sqlite_conn = sqlite3.connect('auditprotocol_1.db')
	app.sqlite_cursor = app.sqlite_conn.cursor()


async def load_user_from_auth(
		request: Request = None
) -> Union[dict, None]:
	api_key_in_header = request.headers['Auth-Token'] if 'Auth-Token' in request.headers else None
	if not api_key_in_header:
		return None
	rest_logger.debug(api_key_in_header)
	row = None
	while True:
		rest_logger.debug("Waiting for Lock")
		v = redis_lock.incr('my_lock')
		if v == 1:
			row = api_keys_table.fetch(condition={'api_key':api_key_in_header}, 
					start_index=api_keys_table.index-1,
					n_rows=1)
			v = redis_lock.decr('my_lock')
			break
		v = redis_lock.decr('my_lock')
		time.sleep(0.01)
	print(row)
	ffs_token = row[next(iter(row.keys()))]['token']
	return {'token': ffs_token, 'api_key': api_key_in_header}


#:@app.post('/create')
#:async def create_filecoin_filesystem(
#:		request: Request
#:):
#:	req_json = await request.json()
#:	hot_enabled = req_json.get('hotEnabled', True)
#:	pow_client = PowerGateClient(settings.powergate_url, False)
#:	new_ffs = pow_client.ffs.create()
#:	rest_logger.info('Created new FFS')
#:	rest_logger.info(new_ffs)
#:	if not hot_enabled:
#:		default_config = pow_client.ffs.default_config(new_ffs.token)
#:		rest_logger.debug(default_config)
#:		new_storage_config = STORAGE_CONFIG
#:		new_storage_config['cold']['filecoin']['addr'] = default_config.default_storage_config.cold.filecoin.addr
#:		new_storage_config['hot']['enabled'] = False
#:		new_storage_config['hot']['allowUnfreeze'] = False
#:		pow_client.ffs.set_default_config(json.dumps(new_storage_config), new_ffs.token)
#:		rest_logger.debug('Set hot storage to False')
#:		rest_logger.debug(new_storage_config)
#:	# rest_logger.debug(type(default_config))
#:	api_key = str(uuid4())
#:	api_keys_table.add_row({'token':new_ffs.token,'api_key':api_key})
#:
#:	# Add row to skydb
#:	
#:	api_keys_table.add_row({'api_key':api_key, 'token':new_ffs.token})
#:	rest_logger.debug("Added a row to api_keys_table")
#:	return {'apiKey': api_key}

@app.post('/create')
async def get_create_api_key(
		request: Request
	):
	api_key = str(uuid4())
	token = str(uuid4())
	api_keys_table.add_row({'token':token, 'api_key':api_key})
	return {'apiKey':api_key}

@app.get('/payloads')
async def all_payloads(
	request: Request,
	response: Response,
	api_key_extraction=Depends(load_user_from_auth),
	start_index:Optional[int]=-1
):
	rest_logger.debug('Api key extraction')
	rest_logger.debug(api_key_extraction)
	rest_logger.debug(start_index)
	if not api_key_extraction:
		response.status_code = status.HTTP_403_FORBIDDEN
		return {'error': 'Forbidden'}
	if not api_key_extraction['token']:
		response.status_code = status.HTTP_403_FORBIDDEN
		return {'error': 'Forbidden'}
	ffs_token = api_key_extraction['token']
	return_json = dict()
	payload_list = list()
	records_rows = None
	if start_index == -1:
		start_index = accounting_records_table.index-1
	while True:
		rest_logger.debug("Waiting for Lock")
		v = redis_lock.incr('my_lock')
		if v == 1:
			records_rows = accounting_records_table.fetch(condition={'token':ffs_token}, 
								start_index=start_index,
								n_rows=3)

			v = redis_lock.decr('my_lock')
			break
		v = redis_lock.decr('my_lock')
		time.sleep(0.01)
	print(records_rows)
	for row_index in records_rows:
		file_,payload = sia_get(records_rows[row_index]['cid'])
		payload_obj = {
			'recordCid': records_rows[row_index]['localCID'],
			'txHash': records_rows[row_index]['txHash'],
			'timestamp': records_rows[row_index]['timestamp'],
			'file_download': file_,
		}
		payload_list.append(payload_obj)
	return_json.update({'payloads': payload_list})
	return return_json


def upload_to_sia(file_hash, file_content):
	headers = {'user-agent': 'Sia-Agent', 'content-type': 'application/octet-stream'}	
	r = requests.post(
			url=f"http://localhost:9980/renter/uploadstream/{file_hash}?datapieces=10&paritypieces=20",
			headers=headers,
			data=file_content
		)
	print(r.text)
	
def sia_get(file_hash):
	files_ = os.listdir('static/')
	if file_hash in files_:
		data = open(f'static/{file_hash}','r').read()
		return f'/static/{file_hash}', data
	try:
		r = requests.get(
					url=f"http://localhost:9980/renter/stream/{file_hash}",
					headers={'user-agent': 'Sia-Agent'},
					stream=True
				)
	except Exception as e:
		print(e)
		return None

	f = open(f"static/{file_hash}", 'w')
	data = r.text
	f.write(data)
	f.flush()
	return (f"/static/{file_hash}", data)

@app.get('/payload/{recordCid:str}')
async def record(request: Request, response:Response, recordCid: str):
	row = None
	while True:
		rest_logger.debug("Waiting for Lock")
		v = redis_lock.incr('my_lock')
		if v == 1:
			row = accounting_records_table.fetch(condition={'localCID':recordCid}, start_index=accounting_records_table.index-1, n_rows=1)
			v = redis_lock.decr('my_lock')
			break
		v = redis_lock.decr('my_lock')
		time.sleep(0.01)
	assert len(row) >= 1, "No row found"
	index = list(row.keys())[0]
	row = row[index]
	real_cid = row['cid']
	ffs_token = row['token']
	file_, payload = sia_get(row['cid'])
	return {'fileLink': file_, 'payload':payload}




# This function is responsible for committing payload
@app.post('/')
# @app.post('/jsonrpc/v1/{appID:str}')
async def root(
		request: Request,
		response: Response,
		api_key_extraction=Depends(load_user_from_auth)
):
	if not api_key_extraction:
		response.status_code = status.HTTP_403_FORBIDDEN
		return {'error': 'Forbidden'}
	if not api_key_extraction['token']:
		response.status_code = status.HTTP_403_FORBIDDEN
		return {'error': 'Forbidden'}
	#pow_client = PowerGateClient(fast_settings.config.powergate_url, False)
	# if request.method == 'POST':
	req_args = await request.json()
	payload = req_args['payload']
	token = api_key_extraction['token']
	h = hashlib.sha256()
	h.update(payload.encode())
	sha_payload_hash = h.hexdigest()
	upload_to_sia(sha_payload_hash, payload)
	#payload_bytes = BytesIO(payload.encode('utf-8'))
	#payload_iter = bytes_to_chunks(payload_bytes)
	## adds to hot tier, IPFS
	#stage_res = pow_client.ffs.stage(payload_iter, token=token)
	#rest_logger.debug('Staging level results:')
	#rest_logger.debug(stage_res)
	## uploads to filecoin
	#push_res = pow_client.ffs.push(stage_res.cid, token=token)
	#rest_logger.debug('Cold tier finalization results:')
	#rest_logger.debug(push_res)
	#await request.app.redis_pool.publish_json('new_deals', {'cid': stage_res.cid, 'jid': push_res.job_id, 'token': token})
	payload_hash = '0x' + keccak(text=payload).hex()
	token_hash = '0x' + keccak(text=token).hex()
	tx_hash_obj = contract.commitRecordHash(**dict(
		payloadHash=payload_hash,
		apiKeyHash=token_hash
	))
	tx_hash = tx_hash_obj[0]['txHash']
	rest_logger.debug('Committed record append to contract..')
	rest_logger.debug(tx_hash_obj)
	local_id = str(uuid4())
	timestamp = int(time.time())
	rest_logger.debug("Adding row to accounting_records_table")
	# Add row to skydb
	#print(f"Adding cid: {stage_res.cid}")
	accounting_records_table.add_row({
				'token':token,
				'cid':sha_payload_hash,
				'localCID':local_id,
				'txHash':tx_hash,
				'timestamp':timestamp,
				'confirmed':-1,

			})

	return {'commitTx': tx_hash, 'recordCid': local_id}
