import sys
import json
    
class VulnDetection:
    
    def __init__(self):
        self.vuln = {}
        self.tainted = []
        self.vuln_detected = {}

    def memberexpression(self, expr):
        result = self.analyse_statement(expr["object"])
        result += "." + self.analyse_statement(expr["property"])
        return result

    def assignmentexpression(self, expr):
        var_name = self.analyse_statement(expr["left"])
        right_side = self.analyse_statement(expr["right"]) 
        for i in range(len(self.vuln)): 
            if right_side.lower() in self.vuln[i]["sources"]:
                self.tainted.append(var_name)
                self.vuln_detected[var_name] = {"Vulnerability": self.vuln[i]["vulnerability"], "source": [right_side], "sanitizers":[], "sinks": []}
                
        if right_side in self.tainted:
            self.tainted.append(var_name)
            self.vuln_detected[var_name] = {"Vulnerability": self.vuln_detected[right_side]["Vulnerability"], "source": self.vuln_detected[right_side]["source"], "sanitizers":[], "sinks": []}

        

    def expressionstatement(self, expr):
        self.analyse_statement(expr["expression"])

    def identifier(self, expr):
        return expr["name"]

    def analyse_statement(self,node):
        node_type = node["type"]

        if node_type == "ExpressionStatement":
            return self.expressionstatement(node)     
        elif node_type == "AssignmentExpression":
            return self.assignmentexpression(node)
        elif node_type == "Identifier":
            return self.identifier(node)
        elif node_type == "MemberExpression":
            return self.memberexpression(node)
       # elif node_type == "CallExpression":
            #return self.callexpression(node)

    def json_parser(self, json_text):
        f = open(json_text, 'r')
        text = json.loads(f.read())
        f.close()
        return text        

    def analyse(self,jsCode, vuln):
        self.vuln = self.json_parser(vuln)
        js_to_analyse = self.json_parser(jsCode)

        for i in range(len(js_to_analyse["body"])):
            self.analyse_statement(js_to_analyse["body"][i])

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("Please insert the following args <JSCODE> <VULN_PATTERN>")
    vuln = VulnDetection()    
    result = vuln.analyse(sys.argv[1], sys.argv[2])
    #todo output the result in a json file

