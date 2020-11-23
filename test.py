import requests

def upload_to_sia(file_hash, file_content):
	headers = {'user-agent': 'Sia-Agent', 'content-type': 'application/octet-stream'}	
	r = requests.post(
			url=f"http://localhost:9980/renter/uploadstream/{file_hash}?datapieces=10&paritypieces=20",
			headers=headers,
			data=file_content
		)
	print(r.text)
	
def get(file_hash):
	try:
		r = requests.get(
					url=f"http://localhpst:9980/renter/stream/{file_hash}",
					headers={'user-agent': 'Sia-Agent'},
					stream=True
				)
	except Exception as e:
		return None

	f = open(f"files/{file_hash}")
	for chunk in r.iter_content(chunk_size=1024 * 50):  # 50 kB chunks
		# tornado_logger.debug('Writing chunk to bytes stream')
		f.write(chunk)
	f.flush()
