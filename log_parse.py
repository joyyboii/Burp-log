from rawweb import RawWeb
from xml.etree import ElementTree as ET
import urllib.parse
import base64
import csv
log_path='burp.log'
output_log_csv='httplog.csv'
def parse_log(log_path):
	'''
	This fucntion accepts burp log file path.
	and returns a dict. of request and response
	result = {'GET /page.php...':'200 OK HTTP / 1.1....','':'',.....}
	'''
	result = {}
	try:
		with open(log_path): pass
	except IOError:
		print ("[+] Error!!! ",log_path,"doesn't exist..")
		exit()
	try:
		tree = ET.parse(log_path)
	except Exception:
		print ('[+] Opps..!Please make sure binary data is not present in Log, Like raw image dump,flash(.swf files) dump etc')
		exit()
	root = tree.getroot()
	for reqs in root.findall('item'):
		raw_req = reqs.find('request').text
		raw_req = urllib.parse.unquote(raw_req).decode('utf8')
		raw_resp = reqs.find('response').text
		result[raw_req] = raw_resp
	return result

def parseRawHttpReq(rawreq):
    try:
        raw = rawreq.decode('utf8')
    except (Exception):
        raw = rawreq
    global headers, method, body, path
    headers = {}
    sp = raw.split('\n\n',1)
    if len(sp) > 1:
        head = sp[0]
        body = sp[1]
    else:
        head = sp[0]
        body = ""
    c1 = head.split('\n',head.count('\n'))
    method = c1[0].split(' ',2)[0]
    path = c1[0].split(' ',2)[1]
    for i in range(1, head.count('\n')+1):
        slice1 = c1[i].split(': ',1)
        if slice1[0] != "":
            try:
                headers[slice1[0]] = slice1[1]  
            except:
                pass
    return headers, method, body, path

f = open(output_log_csv, "w")
c = csv.writer(f)
c.writerow(["method","body","path","headers"])
f.close()
result= parse_log(log_path)
for items in result:
    data=[]
    raaw= base64.b64decode(items)
    headers,method,body,path=parseRawHttpReq(raaw)
    data.append(method)
    data.append(body)
    data.append(path)
    data.append(headers)
    f = open(output_log_csv, "ab")
    c = csv.writer(f)
    c.writerow(data)
    f.close()