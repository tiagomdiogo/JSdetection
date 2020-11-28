import sys
import json
    
class VulnDetection:
    
    def __init__(self):
        self.vuln = {}
        self.tainted = []
        self.vuln_detected = {}

    def memberexpression(self, expr):
        result = self.analyse_statement(expr["object"], 0)
        result += "." + self.analyse_statement(expr["property"], 0)
        return result

    def ifstatement(self, expr):
        pass

    def assignmentexpression(self, expr):
        var_name = self.analyse_statement(expr["left"], 1)
        right_side = self.analyse_statement(expr["right"], 1).split(" ")  
        for x in right_side:
            if x in self.tainted:
                self.tainted.append(var_name)
                self.vuln_detected[var_name] = {"Vulnerability": self.vuln_detected[x]["Vulnerability"], "sources": self.vuln_detected[x]["sources"], "sanitizers":[], "sinks": []}            
            else: 
                for i in range(len(self.vuln)):
                    if x.lower() in self.vuln[i]["sources"]:    
                        self.tainted.append(var_name)
                        self.vuln_detected[var_name] = {"Vulnerability": self.vuln[i]["vulnerability"], "sources": [x], "sanitizers":[], "sinks": []}
             

    def callexpression(self, expr, fromAssigmnemt):
        callee = self.analyse_statement(expr["callee"],0 )

        args = expr["arguments"]
        args_list = []              
        for z in range(len(args)):
            a = self.analyse_statement(args[z], 0)
            args_list.append(a)

        for i in range(len(self.vuln)):   
            if callee.lower() in self.vuln[i]["sinks"]:    
                for arg_name in args_list:
                    for arg in arg_name.split(" "):
                        if arg in self.tainted:
                            if self.vuln_detected[arg]["Vulnerability"] == self.vuln[i]["vulnerability"]:
                                self.vuln_detected[arg]["sinks"].append(callee.lower())
                        elif self.vuln[i]["vulnerability"] in self.vuln_detected:
                            self.vuln_detected[self.vuln[i]["vulnerability"]]["sinks"].append(callee.lower())
            if fromAssigmnemt == 0:                    
                if callee.lower() in self.vuln[i]["sources"]:
                        self.vuln_detected[self.vuln[i]["vulnerability"]] = {"Vulnerability": self.vuln[i]["vulnerability"], "sources": [callee.lower()], "sanitizers":[], "sinks": []}                                   
                if callee.lower() in self.vuln[i]["sanitizers"]:
                        if self.vuln[i]["vulnerability"] in self.vuln_detected:
                            self.vuln_detected[self.vuln[i]["vulnerability"]]["sanitizers"].append(callee.lower())

        if fromAssigmnemt == 0:
            return callee
        else:
            return callee + " " + " ".join(args_list)    

    def expressionstatement(self, expr):
        self.analyse_statement(expr["expression"], 0)

    def identifier(self, expr):
        return expr["name"]

    def literal(self,expr):
        return ""

    def binaryexpression(self, expr):
        left = self.analyse_statement(expr["left"],0 )
        left +=  " " + self.analyse_statement(expr["right"], 0)
        return left


    def analyse_statement(self,node, fromAssigmnemt):
        node_type = node["type"]

        if node_type == "ExpressionStatement":
            return self.expressionstatement(node)     
        elif node_type == "AssignmentExpression":
            return self.assignmentexpression(node)
        elif node_type == "Identifier":
            return self.identifier(node)
        elif node_type == "BinaryExpression":
            return self.binaryexpression(node)    
        elif node_type == "MemberExpression":
            return self.memberexpression(node)
        elif node_type == "CallExpression":
            return self.callexpression(node, fromAssigmnemt)
        elif node_type == "IfStatement":
            return self.ifstatement(node)    
        elif node_type == "Literal":
            return self.literal(node)

    def json_parser(self, json_text):
        f = open(json_text, 'r')
        text = json.loads(f.read())
        f.close()
        return text        

    def analyse(self,jsCode, vuln):
        self.vuln = self.json_parser(vuln)
        js_to_analyse = self.json_parser(jsCode)

        for i in range(len(js_to_analyse["body"])):
            self.analyse_statement(js_to_analyse["body"][i], 0)

        return self.vuln_detected    

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("Please insert the following args <JSCODE> <VULN_PATTERN>")
    vuln = VulnDetection()    
    result = vuln.analyse(sys.argv[1], sys.argv[2])
    #print(result)
    for key in result:
        if len(result[key]["sources"]) > 0 and len(result[key]["sinks"]):
            print(result[key])

    #todo output the result in a json file

