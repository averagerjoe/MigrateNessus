import sys
import requests
import json

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

port = ":8834"

def download(historicalScan, scanDetailURL, exportHeadersToken):

	exportFormat2 = json.dumps({'history_id':historicalScan["history_id"],'format': 'nessus'})

	#export scan
	exportUrl = scanDetailURL + "/export"
	try:
		fileNum = requests.post(exportUrl, headers=exportHeadersToken, data=exportFormat2, verify=False)
	except:
		print "Error getting export file number."
		sys.exit(0)

	parsedFileNum = json.loads(fileNum.text)

	#check scan is ready for download
	statusUrl = exportUrl + "/" + str(parsedFileNum["file"]) + "/status"

	while True:		
		status = requests.get(statusUrl, headers=exportHeadersToken, verify=False)

		parsedStatus = json.loads(status.text)

		if(parsedStatus["status"] == "ready"):
			break;

	#when ready download
	downloadUrl = exportUrl + "/" + str(parsedFileNum["file"]) + "/download"

	try:
		scanContent = requests.get(downloadUrl, headers=exportHeadersToken, verify=False)
	except:
		print "Error downloading scan content!"
		sys.exit(0)

	print ""
	print "Downloading complete for: " + fileNum.text
	print ""

	fileNum = str(parsedFileNum["file"])

	return scanContent.content, fileNum


def uploadScan(filename, scanContent, uploadURL, uploadHeadersToken, importURL, importHeadersToken):
	print ""
	print "Uploading {0} ...".format(filename)
	print ""

	parameters = {'no_enc': 0}

	uploadData = {'Filename':(filename,filename), 'Filedata':(filename,scanContent)}

	try: 
		uploadResponse = requests.post(uploadURL, headers=uploadHeadersToken, params=parameters, files=uploadData, verify=False)
	except:
		print "Error uploading file: {0}}.".format(filename)
		sys.exit(0)

	print ""
	print uploadResponse.text
	print ""

	importScan(filename, importURL, importHeadersToken)





def importScan(filename, importURL, importHeadersToken):
	print ""
	print "Importing {0} ...".format(filename)
	print ""

	filePayload2 = json.dumps({'file':filename})

	try:
		importResponse = requests.post(importURL, headers=importHeadersToken, data=filePayload2, verify=False)
	except:
		print "Error importing file: {0}}.".format(filename)
		sys.exit(0)

	print ""
	print importResponse.text
	print ""


def saveScan(filename, content):
	with open(filename,'w') as f:
	#f = open(filename, 'w')
		f.write(content)
		f.close()

def login(hostType):

	if(hostType == "export"):
		nessusHost = raw_input("Please enter the Nessus scanner's IP address/hostname to export scans from:")
	else:
		nessusHost = raw_input("Please enter the Nessus scanner's IP address/hostname to import scans to:")

	nessusHost = "https://" + nessusHost + port

	loginUrl = nessusHost + "/session"

	username = raw_input("Please enter your Nessus username:")
	password = raw_input("Please enter your Nessus password:")

	dataCreds = {'username':username,'password':password}

	try:
		token = requests.post(loginUrl, data=dataCreds, verify=False)
	except:
		if(hostype == "export"):
			print "Error connecting to export Nessus host. Exiting"
		else: 
			print "Error connecting to import Nessus host. Exiting"
		sys.exit(0)

	print ""
	print('Token: {0}.'.format(token.text))
	print ""

	tokens = json.loads(token.text)

	try: 
		if(tokens["error"] != ""):
			print tokens["error"]
			sys.exit(0)		
	except KeyError:
		print "Login Successful!"

	
	return tokens, nessusHost


exportToken, exportNessusHost = login("export")

importToken, importNessusHost = login("import")

#export headers and URL
exportHeadersToken = {'X-Cookie':'token='+exportToken["token"],'content-type': 'application/json'}
scanURL = exportNessusHost + "/scans"

#import headers and URL
importHeadersToken = {'X-Cookie':'token='+importToken["token"],'content-type': 'application/json'}
importURL = importNessusHost + "/scans/import"

uploadHeadersToken = {'X-Cookie':'token='+importToken["token"]}
uploadURL = importNessusHost + "/file/upload"

#gets the current scans
try:
	scans = requests.get(scanURL,headers=exportHeadersToken, verify=False)
except:
	print "Error getting scans!"
	sys.exit(0)

parsedScans = json.loads(scans.text)

#loop through the scans
for scan in parsedScans["scans"]:
	print('Scan ID: {0}.'.format(scan["id"])) 

	scanDetailURL = exportNessusHost + "/scans/" + str(scan["id"])

	#get scan detail to work with historical scans
	try:
		scanDetails = requests.get(scanDetailURL, headers=exportHeadersToken, verify=False)
	except:
		print "Error getting scan details!"
		sys.exit(0)

	parsedScanDetails = json.loads(scanDetails.text)

	print "scan history: " + str(parsedScanDetails["history"])

	#check if there are any scan results
	if(str(parsedScanDetails["history"]) != 'None'):

		#loop through scans/historical scans
		for historicalScan in parsedScanDetails["history"]: 

			scanContent, fileNum = download(historicalScan, scanDetailURL, exportHeadersToken)

			filename = scan["name"] + "_" + fileNum + ".nessus"		

			uploadScan(filename, scanContent, uploadURL, uploadHeadersToken, importURL, importHeadersToken)

	else:
		print "No scan results available for this scan."

	





