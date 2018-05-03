# Written by: Bailey Yee
# May 2, 2018
#
#
# helper function to extract the relevant data from the command line curl call
def extractRelevantData(data):
    splitArr = data[1].split("\n")
    return splitArr[len(splitArr) - 1]

# helper function to print scan details in the correct format
def formatScanDetails(data, file):
    print ('')
    print ('filename: ' + file)
    print ('overall_status: ' + (data['scan_results']['scan_all_result_a'] if data['scan_results']['scan_all_result_a'] != 'No threat detected' else 'Clean'))

    scan_details = data['scan_results']['scan_details']
    for key, value in scan_details.items():
        scan_detail = scan_details[key]
        print ('')
        print ('engine: ' + key)
        print ('threat_found: ' + (scan_detail['threat_found'] if scan_detail['threat_found'] else 'Clean'))
        print ('scan_result: {0}'.format(scan_detail['scan_result_i']))
        print ('def_time: ' + scan_detail['def_time'])


import commands
import hashlib
import sys
import json

md5 = hashlib.md5() # used to calculate md5 hash


# check if a file was passed in as argument
# program terminates if no file was passed
if len(sys.argv) <= 2:
    print ("Please pass in an apikey and a file ex: \n     python test.py apikey1234567890 someFile.txt")
    sys.exit()

apikey = sys.argv[1] # apiKey from argument passed in

# open file passed as an argument and calculate hash
with open(sys.argv[2], 'r') as f:
    while True:
        data = f.read()
        if not data:
            break
        md5.update(data)

md5 = md5.hexdigest().upper() #convert hash to hexidecimal and upper case the letters

# format the curl command to look up against metadefender.opswat.com
curlLookup = "curl -X GET https://api.metadefender.com/v2/hash/" + md5 + " -H 'apikey: " + apikey + "'"
s = commands.getstatusoutput(curlLookup) # call in terminal

# grab relevant data from output from terminal call
temp = extractRelevantData(s)
j = json.loads(temp) # format json data to be usable

if j.get(md5, "") != "":
    # result was not found
    # upload file
    curlPost = "curl -X POST --data-binary " + "'@" + sys.argv[1] + "'" + " https://api.metadefender.com/v2/file -H 'apikey: " + apikey + "'"
    post = commands.getstatusoutput(curlPost) # call curl in terminal and grab the output
    tempPost = extractRelevantData(post)
    postJson = json.loads(tempPost) # format json data to be usable

    getJson = "" # variable to store json when retreiving results
    finished = False # flag to stop pulling when data is retreived
    while finished == False:
        # format curl call to retreive results via data_id
        curlGet = "curl -X GET https://api.metadefender.com/v2/file/" + postJson['data_id'] + " -H 'apikey: " + apikey + "'"
        sget = commands.getstatusoutput(curlGet) # grab output from curl call
        tempGet = extractRelevantData(sget)
        getJson = json.loads(tempGet) # format json data to be usable
        if getJson.get('file_id', "") != "": # sets finished flag to True when data is retreived
            finished = True

    # print out the scan results
    formatScanDetails(getJson, sys.argv[2])
else:
    # result was found
    # print out the scan results
    formatScanDetails(j, sys.argv[2])

print ("")
print ('End')
