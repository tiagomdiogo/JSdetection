import sys
import json


def vuln_parser(vuln):
    f = open(vuln, 'r')
    text = f.read()
    f.close()
    return json.loads(text)
    

def js_parser(jsCode):
    f = open(jsCode, 'r')
    text = f.read()
    f.close()
    return json.loads(text)
    

def analyse(jsCode, vuln):
    vuln_dict = vuln_parser(vuln)
    js_to_analyse = js_parser(jsCode)





if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("Please insert the following args <JSCODE> <VULN_PATTERN>")
    result = analyse(sys.argv[1], sys.argv[2])
    #todo output the result in a json file

