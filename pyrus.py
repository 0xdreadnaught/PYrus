import re
import sys
import time
import requests

#define some constants
file = sys.argv[1]
apikey = "YOUR API KEY HERE"
#setup our upload request
params = {'apikey': apikey}
files = {'file': (sys.argv[1], open(sys.argv[1], 'rb'))}

#send our file for scanning
response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
#we need to make sure the response is cast to str so it plays nice with regex
json_response = str(response.json())

#find the scan ID in the initial json response and trim the junk
pattern = "u'scan_id': u'(.*)', u'verbose_msg':"
x = re.search(pattern, json_response)
scanID = x.string[x.start():x.end()]
scanID = scanID[14:-18]

#get our response from the server
#need to create  headers and redefine params
headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  YOURUSERNAMEHERE"}
params = {'apikey': apikey, 'resource': scanID}

#now we nest the new json response in a loop until it's complete
complete = False
while not complete:
	response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)

	try:
		json_response = str(response.json())
	except:
		print "Did you exceed 4 queries per minute?"
		sys.exit()

	if("u'Scan finished," in json_response):
		complete = True
	else:
		time.sleep(20)

#now that we have our scan results we need to get some info before cleaning up the rest of the data
pattern = "'positives':(.*), u'total'"
x = re.search(pattern, json_response)
positives = x.string[x.start():x.end()]
positives = positives[13:-10]
pattern = "'total':(.*), u'md5':"
x = re.search(pattern, json_response)
total = x.string[x.start():x.end()]
total = total[9:-9]

#now we need to pull the individual AV results
pattern = "scan_id':(.*)u'scans': {"
x = re.search(pattern, json_response)
junk = x.string[x.start():x.end()]
raw_results = json_response.replace(junk, "")
raw_results = raw_results[3:-3]

#altering the data so we can split it easily later
raw_results += "},"
raw_results = raw_results.replace(" ", "")
raw_results = raw_results.replace("'},u'", "'},")
raw_results = raw_results[2:]
raw_results = raw_results.replace("u'", "")
raw_results = raw_results.replace("'", "")

#now we need to use regex to remove the update dates since they are dynamic
x = re.compile(",update:\d{8}")
raw_results = re.sub(x, '', raw_results)

#now remove detected status since it is redundant, there is another field for the detection result that we'll keep
raw_results = raw_results.replace("detected:False", "")
raw_results = raw_results.replace("detected:True", "")

#back to cleaning things up again
raw_results = raw_results.replace(":{,version:", " (")
raw_results = raw_results.replace(",result:", "): ")
raw_results = raw_results.replace("): None",  "): CLEAN")
# ^  this should be  set to white in the end

#results data is finally cleaned up and ready to split
list_results = raw_results.split("},")
list_results = sorted(list_results, key=str.lower)

for item in list_results:
	print item

print "\033[0;37;40mDetections: " + positives + "/" + total

