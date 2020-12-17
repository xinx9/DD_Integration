import base64
import datetime
import requests
import json
from urllib.parse import urlencode
from datetime import date
from requests_toolbelt import MultipartEncoder

import curlify

class DefectDojo:
    api_url = "http://192.168.1.200:8080/api/v2"
    auth_token = None
    
#------------------------------------------------------------------#
#   Authorize Methods
#------------------------------------------------------------------#
    
    user = "eGlueA=="
    key = "WW1OaU0yeHVlQT09"

    def __TWO_PASS_THROUGH__(self):
        return base64.b64decode(
            base64.b64decode(self.key.encode()).decode().encode()).decode()

    def __AUTH_TOKEN__(self):
        user = self.user
        key = self.key
        TOKEN_URL = f'{self.api_url}/api-token-auth/'
        data = {
                base64.b64decode("dXNlcm5hbWU=".encode()).decode(): 
                    f"{base64.b64decode(user.encode()).decode()}",
                base64.b64decode("cGFzc3dvcmQ=".encode()).decode(): 
                    f"{self.__TWO_PASS_THROUGH__()}" 
                }
        r = requests.post(TOKEN_URL, data=data, verify=True)
        auth_token = r.json()["token"]
        self.auth_token = auth_token

    def get_auth(self):
        if(self.auth_token == None):
            self.__AUTH_TOKEN__()
        return self.auth_token

#------------------------------------------------------------------#
#   Utility Methods
#------------------------------------------------------------------#
    def get_Header(self):
        headers = {'content-type': 'application/json',
                   'Authorization': f'token {self.auth_token}'}
        return headers

    def printoutput(self, func):
        print(json.dumps(func.json(), indent=2))
        
    def request_data(self, endpoint):
        r = requests.get(f"{self.api_url}/{endpoint}/", 
                         headers=self.get_Header())
        return r.json()
    
#------------------------------------------------------------------#
#   Get Methods
#------------------------------------------------------------------#
    
    def get_products(self, id=None):
        if(id is None):
            resp = self.request_data('products')
        else:
            resp = self.request_data(f'products/{id}/')
        return resp
    
    def get_engagements(self, id=None):
        if(id is None):
            resp = self.request_data('engagements')
        else:
            resp = self.request_data(f'engagements/{id}/')
        return resp
    
    def get_findings(self, id=None):
        if(id is None):
            resp = self.request_data('findings')
        else:
            resp = self.request_data(f'findings/{id}/')
        return resp

#------------------------------------------------------------------#
#   Create Methods
#------------------------------------------------------------------#
    
    def removeNull(self,data):
        jdata = {}
        for (key,value) in data.items(): #removes all key,value from the dictonary if it equals a null value
            if (value != None):
                jdata[key] = value
        return jdata
        
    def create_product(self, tags=None, name=None, description=None,
                        prod_numeric_grade=None, business_criticality=None,
                        platform=None, lifecycle=None, origin=None,
                        user_records=None, revenue=None, external_audience=None,
                        internet_accessible=None, product_manager=None,
                        technical_contact=None, team_manager=None, prod_type=None,
                        authorized_user=None, regulation=None):
        data = {
            "name": name,                                      #string array
            "description":description,                         #string
            "prod_type":prod_type,                             #integer
            "tags":tags,                                       #list of strings
            "prod_numeric_grade":prod_numeric_grade,           #integer
            "business_criticality":business_criticality,       #string
            "platform":platform,                               #string     [ very high, high, medium, low, very low, none ]
            "lifecycle":lifecycle,                             #string     [ web service, desktop, iot, mobile, web ]
            "origin":origin,                                   #string     [ construction, production, retirement ]
            "user_records":user_records,                       #integer    [ third party library, purchased, contractor, internal, open source, outsourced ]
            "revenue":revenue,                                 #string($decimal)
            "external_audience":external_audience,             #boolean
            "internet_accessible":internet_accessible,         #boolean
            "product_manager":product_manager,                 #integer
            "technical_contact":technical_contact,             #integer
            "team_manager":team_manager,                       #integer
            "authorized_user":authorized_user,                 #integer array
            "regulation":regulation                            #integer array
        }
        flag = False
        data = self.removeNull(data)
        if name is None or description is None or prod_type is None:
            print(f"\nRequired Field Empty\n\nCheck:\n\tName: {name}\n\tDescription: {description}\n\tProd_type: {prod_type}\n")
        else:
            r = requests.post(f'{self.api_url}/products/', headers=self.get_Header(), data=data)
            if(r.status_code in range(200,299)):
                flag = True
            print(r,"\n",json.dumps(r.json(), indent=2))
        return flag

    def create_engagement(self, name=None, description=None, version=None, eng_type=None, first_contacted=None,
                          target_start=None, target_end=None, lead=None, requester=None, preset=None, reason=None, 
                          report_type=None, product=None, updated=None, created=None, active=None, tracker=None,
                          test_strategy=None, threat_model=None, api_test=None, pen_test=None, check_list=None, 
                          status=None, progress=None, tmodel_path=None, risk_path=None, done_testing=None, 
                          engagement_type=None, build_id=None, commit_hash=None, branch_tag=None, 
                          build_server=None, source_code_management_server=None, source_code_management_uri=None, 
                          orchestration_engine=None, deduplication_on_engagement=None):
        data = {
            "name":name, 
            "description":description, 
            "version":version, 
            "eng_type":eng_type, 
            "first_contacted":first_contacted, 
            "target_start":target_start, 
            "target_end":target_end,
            "lead":lead,
            "requester":requester,
            "preset":preset,
            "reason":reason,
            "report_type":report_type,
            "product":product,
            "updated":updated,
            "created":created,
            "active":active,
            "tracker":tracker,
            "test_strategy":test_strategy,
            "threat_model":threat_model,
            "api_test":api_test,
            "pen_test":pen_test,
            "check_list":check_list,
            "status":status,
            "progress":progress,
            "tmodel_path":tmodel_path,
            "risk_path":risk_path,
            "done_testing":done_testing,
            "engagement_type":engagement_type,
            "build_id":build_id,
            "commit_hash":commit_hash,
            "branch_tag":branch_tag,
            "build_server":build_server,
            "source_code_management_server":source_code_management_server,
            "source_code_management_uri":source_code_management_uri,
            "orchestration_engine":orchestration_engine,
            "deduplication_on_engagement":deduplication_on_engagement
        }
        flag = False
        data = self.removeNull(data)
        if(target_end == None or target_start == None or product == None):
            print(f"\nRequired Field Empty\n\nCheck:\n\ttarget_end: {target_end}\n\ttarget_start: {target_start}\n\tproduct: {product}\n\n")
        else:
            r = requests.post(f'{self.api_url}/engagements/', headers=self.get_Header(), data=data)
            if(r.status_code in range(200,299)):
                flag = True
            print(r,"\n",json.dumps(r.json(), indent=2))
        return flag

    def create_finding(self, title=None, date=None, cwe=None, cve=None, cvssv3=None, url=None,
                       severity=None, description=None, mitigation=None, impact=None, 
                       steps_to_reproduce=None, severity_justification=None, references=None, 
                       test=None, is_template=None, active=None, verified=None, false_p=None,
                       duplicate=None, duplicate_finding=None, out_of_scope=None, payload=None, 
                       under_review=None, review_requested_by=None, under_defect_review=None, 
                       defect_review_requested_by=None, is_Mitigated=None, thread_id=None, 
                       mitigated=None, mitigated_by=None, reporter=None, numerical_severity=None, 
                       last_reviewed=None, last_reviewed_by=None, line_number=None, 
                       sourcefilepath=None, sourcefile=None, param=None, nb_occurences=None,
                       hash_code=None, line=None, file_path=None, component_name=None, 
                       component_version=None, static_finding=None, dynamic_finding=None, 
                       created=None, scanner_confidence=None, sonarqube_issue=None, found_by=None,
                       unique_id_from_tool=None, vuln_id_from_tool=None, sast_source_object=None,
                       sast_sink_object=None, sast_source_line=None, sast_source_file_path=None,):
        data = {
            "title": title,
            "date": date,
            "cwe": cwe,
            "cve": cve,
            "cvssv3": cvssv3,
            "url": url,
            "severity": severity,
            "description": description,
            "mitigation": mitigation,
            "impact": impact,
            "steps_to_reproduce": steps_to_reproduce,
            "severity_justification": severity_justification,
            "references": references,
            "test": test,
            "is_template": is_template,
            "active": active,
            "verified": verified,
            "false_p": false_p,
            "duplicate": duplicate,
            "duplicate_finding": duplicate_finding,
            "out_of_scope": out_of_scope,
            "under_review": under_review,
            "review_requested_by": review_requested_by,
            "under_defect_review": under_defect_review,
            "defect_review_requested_by": defect_review_requested_by,
            "is_Mitigated": is_Mitigated,
            "thread_id": thread_id,
            "mitigated": mitigated,
            "mitigated_by": mitigated_by,
            "reporter": reporter,
            "numerical_severity": numerical_severity,
            "last_reviewed": last_reviewed,
            "last_reviewed_by": last_reviewed_by,
            "line_number": line_number,
            "sourcefilepath": sourcefilepath,
            "sourcefile": sourcefile,
            "param": param,
            "payload": payload,
            "hash_code": hash_code,
            "line": line,
            "file_path": file_path,
            "component_name": component_name,
            "component_version": component_version,
            "static_finding": static_finding,
            "dynamic_finding": dynamic_finding,
            "created": created,
            "scanner_confidence": scanner_confidence,
            "sonarqube_issue": sonarqube_issue,
            "unique_id_from_tool": unique_id_from_tool,
            "vuln_id_from_tool": vuln_id_from_tool,
            "sast_source_object": sast_sink_object,
            "sast_sink_object": sast_sink_object,
            "sast_source_line": sast_source_line,
            "sast_source_file_path": sast_source_file_path,
            "nb_occurences": nb_occurences,
            "found_by": found_by
        }
        flag = False
        data = self.removeNull(data)
        if(test == None or found_by == None or title == None or severity == None
           or description == None or mitigation == None or impact == None or numerical_severity == None):
            print(f"\nRequired Field Empty\n\nCheck:\n\t \
                test: {test}\n\t \
                found_by: {found_by}\n\t \
                title: {title}\n\t \
                severity: {severity}\n\t \
                description: {description}\n\t \
                mitigation: {mitigation}\n\t \
                impact: {impact}\n\t \
                numerical_severity: {numerical_severity}\n\n")
        else:
            r = requests.post(f'{self.api_url}/findings/', headers=self.get_Header(), data=data)
            if(r.status_code in range(200,299)):
                flag = True
            print(r,"\n",json.dumps(r.json(), indent=2))
        return flag

    #------------------------------------------------------------------#
    #   Search Methods
    #------------------------------------------------------------------#

    def searchProduct(self, name=None):
        productListing = self.get_products()
        prodID = None
        for i in productListing["results"]:
            if(i["name"] == name):
                 prodID = i["id"]
        return prodID

    def searchEngagements(self,prodID=None):
        engagementListing = self.get_engagements()
        engagementID = []
        for i in engagementListing["results"]:
            if(i["product"] == prodID):
                engagementID.append(i["id"])
        return engagementID

    def searchEngagements(self,prodID=None, name=None):
        engagementListing = self.get_engagements()
        engagementID = []
        for i in engagementListing["results"]:
            if(i["product"] == prodID and i["name"] == name):
                engagementID.append(i["id"])
        return engagementID

    def searchFindings(self, engagementID=None):
        findingListing = self.get_findings()
        findingID = None
        for i in findingListing["results"]:
            if(i["test"] == engagementID):
                findingID = i["id"]
        return findingID

    #------------------------------------------------------------------#
    #   import scan
    #------------------------------------------------------------------#
    
    def importScan(self, scan_date=None, minimum_severity="Info", active=True, verified=True,
                   endpoint_to_add=None, test_type=None, file=None, lead=None, tags=None,
                   close_old_finding=False, push_to_jira=False, engagement=None, scan_type=None):
        '''
        Available scan types: 
        Netsparker Scan
        Burp Scan
        Nessus Scan
        Nmap Scan
        Nexpose Scan
        AppSpider Scan
        Veracode Scan
        Checkmarx Scan
        Checkmarx Scan detailed
        Crashtest Security JSON File
        Crashtest Security XML File
        ZAP Scan
        Arachni Scan
        VCG Scan
        Dependency Check Scan
        Dependency Track Finding Packaging Format (FPF) Export
        Retire.js Scan
        Node Security Platform Scan
        '''
        data = {
            "scan_date": scan_date,
            "minimum_severity": minimum_severity,
            "active": active,
            "verified": verified,
            "endpoint_to_add": endpoint_to_add,
            "test_type": test_type,
            "lead": lead,
            "tags": tags,
            "close_old_finding": close_old_finding,
            "push_to_jira": push_to_jira,
            "engagement": engagement,
            "scan_type": scan_type
        }
        
        data = self.removeNull(data)
        file = open(file, 'rb')
        
        payload = MultipartEncoder(
            [
            ('json', (None, json.dumps(data), 'text/plain')),
            ('file', ((file.name, file), 'text/plain'))
            ],
            None, 
            encoding='utf-8')
        
        flag = False
        
        header = {
            'Authorization': f'token {self.auth_token}',
            'Content-type': payload.content_type}
        
        
        files = {'file', (file, open(file, 'rb') , 'text/xml')}
        params={'title':'file'}
     #   if( engagement==None or scan_type==None):
      #      print(f"\nRequired Field Empty\n\nCheck:\n\t Engagement: {engagement}\n\t scan_type: {scan_type}\n\n")
      #  else:
        print(requests.post(f'{self.api_url}/import-scan/',  data=payload, headers=header))
            
           # print(curlify.to_curl(r.request))
            
           # if(r.status_code in range(200,299)):
           #     flag = True
           # print(r,"\n",json.dumps(r.json(), indent=2))
        return flag


curDate = date.today()
today = curDate.strftime("%Y-%m-%d")
dd = DefectDojo()
dd.get_auth()
#dd.printoutput(dd.get_products())
#dd.get_products()
#dd.printoutput(dd.get_engagements())
#dd.printoutput(dd.get_findings())
#dd.create_product(name="skeet", description="fubar, code red, delete everything!!!", prod_type=1)
#dd.create_engagement(name="test", time_end="2020-12-07" )
#prodid = dd.searchProduct(dd.get_products().json()["results"][0]["name"])
#print(json.dumps(dd.searchFindings(), indent=2))
#d = dd.searchFindings(engagementID=11)
#for i in d:
#    print(json.dumps(dd.get_findings(i), indent=2))

prodid = dd.searchProduct(name="skeet")
engagementid = dd.searchEngagements(prodID=prodid, name="test")[0]
print(engagementid)
dd.importScan(engagement=engagementid, scan_type="Nmap Scan", file=r'C:\Users\Xinx\Desktop\test.xml')