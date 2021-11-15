import pytest
import requests
import json

class LogAnonymization:
	def __init__(self,delimiter=" "):
		self.delimiter = delimiter
	
	def read_log_file(self,filename):
		with open(filename) as f:
			line = f.readline()

			while line:
				line = line.rstrip()

				if line.strip() == "":
					print("Found empty line.")
					yield line
					line = f.readline()
					continue

				yield self.process_log_file_by_line(line)

	def process_log_file_by_line(self,line):
		log_data = line.split(self.delimiter)
		if log_data[0].count('.') == 3:
			ip = log_data[0]

	def process_ip(self,ip):
		url='https://geolocation-db.com/jsonp/'+ip
		res=requests.get(url)
		res.content.decode()