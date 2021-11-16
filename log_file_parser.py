# -*- coding: utf-8 -*-

import pytest
import requests
import json

class LogAnonymization:	
	def read_log_file(self,filename):
		out_file = filename.split(filename[filename.rfind('.')])[0] + "_out.csv"
		f = open(filename,'r')
		line = f.readlines()

		for l in line:
			l = l.rstrip()
			an_ip,country_code=self.process_log_file_by_line(l)
			self.write_to_file(out_file,an_ip,country_code)
		f.close()

	def process_log_file_by_line(self,line):
		log_data = line.split()
		# print(log_data)
		if log_data[0].count('.') == 3:
			ip = log_data[0]
			# print(ip)
			an_ip,country_code = self.process_ip(ip)
			# print(an_ip,country_code)
			return an_ip,country_code

	def process_ip(self,ip):
		url='https://geolocation-db.com/jsonp/'+ip
		res=requests.get(url)
		q=res.content.decode()
		q=q.replace('callback(','')
		q=q[:len(q)-1]

		conv_q = json.loads(q)
		country_code = conv_q["country_code"]
		for ch in conv_q["country_code"]:
			country_code += str(ord(ch))

		ip_numbers = ip.split('.')
		anonymized_ip = []
		for item in ip_numbers:
			anonymized_ip.append(str(255-int(item)))

		an_ip='.'.join(anonymized_ip)
		return an_ip,country_code

	def write_to_file(self,out_file,an_ip,country_code):
		file1 = open(out_file,"a")
		file1.write(an_ip+" "+country_code+"\n")
		file1.close()

logAnonymization = LogAnonymization()
logAnonymization.read_log_file('access_1.log')

