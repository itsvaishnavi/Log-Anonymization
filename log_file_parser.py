# -*- coding: utf-8 -*-

# Import libraries
import requests
import json
import time

class LogAnonymization:	
	def read_log_file(self,filename):
		f = open(filename,'r') #Opens the input file 'filename'
		line = f.readlines() #list of all lines in the 'filename'

		# Creating the output filename with suffix '_out.csv'
		out_file = filename.split(filename[filename.rfind('.')])[0] + "_out.txt"

		for l in line:
			l = l.rstrip()
			# Get the original ip address, anonymized ip address and country code
			ip,an_ip,country_code,log_data=self.process_log_file_by_line(l)
			# Write the anonymized ip address and country code to the output file
			self.write_to_file(out_file,an_ip,country_code,log_data)
		f.close()
		return out_file

	def process_log_file_by_line(self,line):
		log_data = line.split()
		# print(log_data)
		if log_data[0].count('.') == 3:
			ip = log_data[0]
			# print(ip)
			an_ip,country_code = self.process_ip(ip)
			# print(an_ip,country_code)
			return ip,an_ip,country_code,log_data[1:]

	def process_ip(self,ip):
		try:
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
		except Exception as e:
			return '255.255.255.255','RN9999'

	def write_to_file(self,out_file,an_ip,country_code,log_data):
		file1 = open(out_file,"a+")
		d = " ".join(log_data)
		out_data = an_ip+" "+country_code+d+"\n"
		print(an_ip+" "+country_code+d+"\n")
		file1.write(out_data)
		file1.close()

# Write unit test cases

# Check if IP is extracted correctly for known usecase
def process_log_file_by_line_test_func(logAnonymization:LogAnonymization):
	ip,an_ip,country_code,log_data = logAnonymization.process_log_file_by_line('54.36.149.41 - - [22/Jan/2019:03:56:14 +0330] "GET /filter/27|13%20%D9%85%DA%AF%D8%A7%D9%BE%DB%8C%DA%A9%D8%B3%D9%84,27|%DA%A9%D9%85%D8%AA%D8%B1%20%D8%A7%D8%B2%205%20%D9%85%DA%AF%D8%A7%D9%BE%DB%8C%DA%A9%D8%B3%D9%84,p53 HTTP/1.1" 200 30577 "-" "Mozilla/5.0 (compatible; AhrefsBot/6.1; +http://ahrefs.com/robot/)" "-"')
	assert ip == "54.36.149.41","Check the process_log_file_by_line module once again"

# Check if IP is anonymized correctly for known usecase
def process_ip_test_func(logAnonymization:LogAnonymization):
	an_ip,country_code = logAnonymization.process_ip('54.36.149.41')
	assert an_ip=="201.219.106.214","Check the process_ip module once again"

def main():
	logAnonymization = LogAnonymization()

	process_log_file_by_line_test_func(logAnonymization)
	process_ip_test_func(logAnonymization)
	print("All test_funcs executed successfully!")

	out_file = logAnonymization.read_log_file('access.log')
	print("Output file ready with the filename::",out_file)

if __name__ == "__main__":
	start = time.time()
	main()
	end = time.time()
	print("Total time required to execute the script::",str(end-start),"ms")