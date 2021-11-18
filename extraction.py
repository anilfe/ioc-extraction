import requests
import re
import urllib.request
import json

sumJson = {}
sumJson["indicators"] = []

# Gathering logs - url should be filled with txt or similar file
url = "https://.txt"
data = urllib.request.urlopen(url)

# Finding unique IP addresses on file
pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
ipList = []
for line in data:
    ip = re.findall(pattern,str(line))
    ipList.append(ip)
flatList = list(set([item for sublist in [x for x in ipList if x != []] for item in sublist]))


## There are 2 functions - First one is for single IP, and the second one is for whole IP addresses ##
## You need IP key

def singleIP(ipAdd = ' '):
    #VirusTotal has changed their API policy, therefore I could not send all ip adresses because of the limitations. Instead to demostrate I have developed code with single IP.
    #I have choosed the IP above, because it has been observed malicious.
    #There is also another function works with whole IP's, if you have pro API key.

    #VirusTotal API Request
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

    #IP info, APIkey should not be inside code directly.
    params = {'apikey':' ','ip':ipAdd}
    response = requests.get(url, params=params)

    #Check if there is malicious
    if response.json()['detected_urls'] != []:
        positives = response.json()['detected_urls'][0]['positives']
        total = response.json()['detected_urls'][0]['total']

        virusTotalJson = json.dumps({"value": params['ip'],
                                    "type":"ip",
                                    "providers":[
                                        {
                                        "provider":"VirusTotal",
                                        "verdict":"malicious",
                                        "score": str(positives)+'/'+str(total)
                                        }
                                        ]
                                    })
        sumJson["indicators"].append(virusTotalJson)
    return(sumJson)


def wholeIP(flatList):
    #VirusTotal API Request
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

    for ipAdd in flatList:
        #IP info, APIkey should not be inside code directly.
        params = {'apikey':' ','ip':ipAdd}
        response = requests.get(url, params=params)

        #Check if there is malicious. If 'detected_urls' exists, there should be at least 1 malicious condition.
        if response.json()['detected_urls'] != []:
            positives = response.json()['detected_urls'][0]['positives']
            total = response.json()['detected_urls'][0]['total']

            virusTotalJson = json.dumps({"value": params['ip'],
                                        "type":"ip",
                                        "providers":[
                                            {
                                            "provider":"VirusTotal",
                                            "verdict":"malicious",
                                            "score": str(positives)+'/'+str(total)
                                            }
                                            ]
                                        })
            sumJson["indicators"].append(virusTotalJson)
    return(sumJson)

