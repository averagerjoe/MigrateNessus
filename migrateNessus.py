# Joe McGrath
# 7/25/2016
#

import sys
import requests
import json

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

port = ":8834"

#Used to download a scan or policy
#takes in a type which is either "scan" or "policy"
#scanPol which has the ID of item to download
#then scanPolURL and exportHeadersToken to build the download request
#returns the content of the scan/policy (and additional fileNum info)
def download(type, scanPol, scanPolURL, exportHeadersToken):

	if(type == "scan"):

		exportFormat2 = json.dumps({'history_id':scanPol["history_id"],'format': 'nessus'})

		#export scan
		exportUrl = scanPolURL + "/export"
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
	else:
		#export policy
		exportUrl = scanPolURL + "/" + str(scanPol["id"]) + "/export?token=" + exportHeadersToken
	
		#print exportUrl

		try:
			policyContent = requests.get(exportUrl, verify=False)
		except:
			print "Error exporting policy."
			sys.exit(0)

	
		print ""
		print "Downloading complete for policy: " + str(scanPol["id"])
		print ""

		return policyContent.content

#Upload is use to transfer the scan/policy to the server 
#so it can be imported into the application
#have type (scan/policy)
#filename to import
#upload url and headers info to build the upload request
#import url and headers info to build and call the import function
# returns nothing
def upload(type, filename, content, uploadURL, uploadHeadersToken, importURL, importHeadersToken):

	print ""
	print "Uploading {0} ...".format(filename)
	print ""

	parameters = {'no_enc': 0}

	uploadData = {'Filename':(filename,filename), 'Filedata':(filename,content)}

	if(type == "scan"):

		try: 
			uploadResponse = requests.post(uploadURL, headers=uploadHeadersToken, params=parameters, files=uploadData, verify=False)
		except:
			print "Error uploading file: {0}}.".format(filename)
			sys.exit(0)

		#print ""
		#print uploadResponse.text
		#print ""

		importFile(filename, importURL, importHeadersToken)
	else:

		try: 
			uploadResponse = requests.post(uploadURL, headers=uploadHeadersToken, params=parameters, files=uploadData, verify=False)
		except:
			print "Error uploading file: {0}}.".format(filename)
			sys.exit(0)

		response = json.loads(uploadResponse.text)

		#print ""
		#print uploadResponse.text
		#print ""

		importFile(response["fileuploaded"], importURL, importHeadersToken)


# importFile function to add uploaded file to application
# takes in a filename to import 
# has the import URL and headers info to build import request
# returns nothing
def importFile(filename, importURL, importHeadersToken):
	print ""
	print "Importing {0} ...".format(filename)
	print ""

	filePayload2 = json.dumps({'file':filename})

	try:
		importResponse = requests.post(importURL, headers=importHeadersToken, data=filePayload2, verify=False)
	except:
		print "Error importing file: {0}}.".format(filename)
		sys.exit(0)

	#print ""
	#print importResponse.text
	#print ""

# save is used to write downloaded information to a local file
# takes in the filename to save info under
# and the content to save to the file
# returns nothing
def save(filename, content):
	with open(filename,'w') as f:
	#f = open(filename, 'w')
		f.write(content)
		f.close()

#login function used to authenticate to the various applications
# takes in the hostType to differentiate between export and import hosts
# returns the authentication tokens and the Nessus URL
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
			print "Exiting..."
			sys.exit(0)	
	except KeyError:
		print "Login Successful!"
		print ""

	
	return tokens, nessusHost

# scan() this function is where the export/import of scans happen
# takes in no parameters 
# returns nothing
def scan():
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
		#print('Scan ID: {0}.'.format(scan["id"])) 

		scanDetailURL = exportNessusHost + "/scans/" + str(scan["id"])

		#get scan detail to work with historical scans
		try:
			scanDetails = requests.get(scanDetailURL, headers=exportHeadersToken, verify=False)
		except:
			print "Error getting scan details!"
			sys.exit(0)

		parsedScanDetails = json.loads(scanDetails.text)

		#print "scan history: " + str(parsedScanDetails["history"])

		#check if there are any scan results
		if(str(parsedScanDetails["history"]) != 'None'):

			#loop through scans/historical scans
			for historicalScan in parsedScanDetails["history"]: 

				scanContent, fileNum = download("scan", historicalScan, scanDetailURL, exportHeadersToken)

				filename = scan["name"] + "_" + fileNum + ".nessus"		

				upload("scan", filename, scanContent, uploadURL, uploadHeadersToken, importURL, importHeadersToken)

		else:
			print "No scan results available for this scan."

# policy() this is where the export/import of policies happen
# takes in no parameters
# returns nothing
def policy():
	exportToken, exportNessusHost = login("export")

	importToken, importNessusHost = login("import")

	#export headers and URL
	exportHeadersToken = {'X-Cookie':'token='+exportToken["token"],'content-type': 'application/json'}
	policyURL = exportNessusHost + "/policies"

	#import headers and URL
	importHeadersToken = {'X-Cookie':'token='+importToken["token"],'content-type': 'application/json'}
	importURL = importNessusHost + "/policies/import"

	uploadHeadersToken = {'X-Cookie':'token='+importToken["token"]}
	uploadURL = importNessusHost + "/file/upload"

	#gets the current policies
	try:
		policies = requests.get(policyURL,headers=exportHeadersToken, verify=False)
	except:
		print "Error getting policies!"
		sys.exit(0)

	parsedPolicies = json.loads(policies.text)

	#print parsedPolicies

	#loop through the policies
	for policy in parsedPolicies["policies"]:
		#print 'Policy ID: ' + str(policy["id"]) 

		policyContent = download("policy", policy, policyURL, exportToken["token"])

		filename = policy["name"] + ".nessus"	

		upload("policy", filename, policyContent, uploadURL, uploadHeadersToken, importURL, importHeadersToken)

		#save(filename, policyContent)

loop = True

# try used to gracefully exit due to other errors/ keyboard interrupts
try:
	while(loop):
		print ""
		print "-----------------------------------------------"
		print "This script is used to migrate Nessus scans and"
		print "Policies to a separate Nessus scanner."
		print ""
		print "1. Migrate Scans"
		print "2. Migrate Policies"
		print "0. Exit"
		print ""
		print "-----------------------------------------------"

		choice = raw_input("Please select from the menu:")
		print ""

		#try used to catch errors due to entering in non numbers
		try:
			if(int(choice) == 0):
				print "Exiting..."
				sys.exit(0)
			elif(int(choice) == 1):
				scan()
			elif(int(choice) == 2):
				policy()
			else:
				print ""
				print "Please enter a proper value."
				print ""
		except ValueError:
			print ""
			print "Please enter a proper value."
			print ""
except:
	sys.exit(0)







	





