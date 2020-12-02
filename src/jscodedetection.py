import sys
import json
    
class VulnDetection:
    
    def __init__(self):
        self.vuln = {}
        self.tainted = []
        self.vuln_detected = {}

    def memberexpression(self, expr):
        result = self.analyse_statement(expr["object"], 0, [])
        result += "." + self.analyse_statement(expr["property"], 0, [])
        return result

    def whilestatement(self, expr):
        test = self.analyse_statement(expr["test"], 0, []).split(" ")
        implicit =[]
        for arg in test:
            if arg in self.tainted:
                implicit.append(arg)
        for i in range(len(expr["body"]) + 2):
            self.analyse_statement(expr["body"], 0, implicit)

    def ifstatement(self, expr):
        test = self.analyse_statement(expr["test"], 0, []).split(" ")
        implicit =[]
        for arg in test:
            if arg in self.tainted:
                implicit.append(arg)

        self.analyse_statement(expr["consequent"], 0, implicit)
        if expr["alternate"] is not None:
            self.analyse_statement(expr["alternate"],0, implicit)
    
    def blockstatement(self, expr, implicit):
        for stmt in expr["body"]:
            self.analyse_statement(stmt, 0, implicit)

    def assignmentexpression(self, expr, implicitFlow):
        var_name = self.analyse_statement(expr["left"], 1, [])
        right_side = self.analyse_statement(expr["right"], 1, []).split(" ")

        if len(implicitFlow) > 0:
            if var_name not in self.tainted and var_name not in self.vuln_detected:
                self.tainted.append(var_name)
                self.vuln_detected[var_name] = {"vulnerability": self.vuln_detected[implicitFlow[0]]["vulnerability"], "sources": self.vuln_detected[implicitFlow[0]]["sources"], "sanitizers":self.vuln_detected[implicitFlow[0]]["sanitizers"], "sinks": []}

        for x in right_side:
            if x in self.tainted:
                if var_name not in self.tainted:
                    self.tainted.append(var_name)
                    if var_name not in self.vuln_detected:
                        self.vuln_detected[var_name] = {"vulnerability": self.vuln_detected[x]["vulnerability"], "sources": self.vuln_detected[x]["sources"], "sanitizers":self.vuln_detected[x]["sanitizers"], "sinks": []}            
            else: 
                for i in range(len(self.vuln)):
                    if x.lower() in self.vuln[i]["sources"]:
                        if var_name not in self.tainted:  
                            self.tainted.append(var_name)
                            if var_name not in self.vuln_detected:  
                                self.vuln_detected[var_name] = {"vulnerability": self.vuln[i]["vulnerability"], "sources": [x], "sanitizers":[], "sinks": []}
                        else:
                            if x not in self.vuln_detected[var_name]["sources"]:
                                self.vuln_detected[var_name]["sources"].append(x)        
             

    def callexpression(self, expr, fromAssigmnemt):
        callee = self.analyse_statement(expr["callee"],0, [])

        args = expr["arguments"]
        args_list = []              
        for z in range(len(args)):
            a = self.analyse_statement(args[z], 0, [])
            args_list.append(a)

        for i in range(len(self.vuln)):  
            for arg_name in args_list:
                for arg in arg_name.split(" "):
                    if arg in self.tainted:
                        if self.vuln_detected[arg]["vulnerability"] == self.vuln[i]["vulnerability"]:
                            if callee.lower() not in self.vuln_detected[arg]["sinks"] and callee.lower() in self.vuln[i]["sinks"]:                                
                                self.vuln_detected[arg]["sinks"].append(callee.lower())
                            elif callee.lower() not in self.vuln_detected[arg]["sanitizers"] and callee.lower() in self.vuln[i]["sanitizers"]:                                
                                    self.vuln_detected[arg]["sanitizers"].append(callee.lower())
                    else:
                        if self.vuln[i]["vulnerability"] in self.vuln_detected:
                            if callee.lower() not in self.vuln_detected[self.vuln[i]["vulnerability"]]["sinks"] and callee.lower() in self.vuln[i]["sinks"]:
                                self.vuln_detected[self.vuln[i]["vulnerability"]]["sinks"].append(callee.lower())
            if fromAssigmnemt == 0:                  
                if callee.lower() in self.vuln[i]["sources"] and self.vuln[i]["vulnerability"] not in self.vuln_detected:
                    self.vuln_detected[self.vuln[i]["vulnerability"]] = {"vulnerability": self.vuln[i]["vulnerability"], "sources": [callee.lower()], "sanitizers":[], "sinks": []}                                                
                else:
                    if callee.lower() in self.vuln[i]["sanitizers"]:
                        if self.vuln[i]["vulnerability"] in self.vuln_detected:
                            self.vuln_detected[self.vuln[i]["vulnerability"]]["sanitizers"].append(callee.lower())
            
        if fromAssigmnemt == 0:
            return callee
        else:
            return callee + " " + " ".join(args_list)    

    def expressionstatement(self, expr, implicit):
        self.analyse_statement(expr["expression"], 0, implicit)

    def identifier(self, expr):
        return expr["name"]

    def literal(self,expr):
        return ""

    def binaryexpression(self, expr):
        left = self.analyse_statement(expr["left"],0, [])
        left +=  " " + self.analyse_statement(expr["right"], 0 ,[])
        return left


    def analyse_statement(self,node, fromAssigmnemt, implicitFlow):
        node_type = node["type"]

        if node_type == "ExpressionStatement":
            return self.expressionstatement(node , implicitFlow)     
        elif node_type == "AssignmentExpression":
            return self.assignmentexpression(node, implicitFlow)
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
        elif node_type == "BlockStatement":
            return self.blockstatement(node, implicitFlow)
        elif node_type == "WhileStatement":
            return self.whilestatement(node)           
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
            self.analyse_statement(js_to_analyse["body"][i], 0, [])

        return self.vuln_detected    

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("Please insert the following args <JSCODE> <VULN_PATTERN>")
    vuln = VulnDetection()    
    result = vuln.analyse(sys.argv[1], sys.argv[2])
    result_array = []
    for key in result:
        if len(result[key]["sources"]) > 0 and len(result[key]["sinks"]):
            result_array.append(result[key])

    output = sys.argv[1].split(".json")[0] + ".output.json"  
    f = open(output, 'w')
    print(result_array)
    json.dump(result_array, f)
    f.close()      

