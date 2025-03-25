import argparse
import json

checkMalware = False
checkSuspect = False
vulnExists = True
vulnThreshold=0
behaviors=[]
vulns = []
findings={}

def process_config(json_file):
    global checkMalware, checkSuspect, vulnExists, vulnThreshold, behaviors, findings
    try:
        data = json.load(json_file)
        findings["config"]=data
        findings["findings"]=[]
        print(f"Successfully loaded Config data")
        
        checkMalware = data["malware"]
        checkSuspect = data["suspect"]
        vulnExists=data["vulnExists"]
        vulnThreshold=data["vulnThreshold"]
        behaviors=data["behaviors"]

    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in the Config file")
    except Exception as e:
        print(f"An error occurred while processing Config JSON: {str(e)}")



def process_vulns(report_file, vuln_file):
    global findings
    try:
        data = json.load(report_file)
        vuln = json.load(vuln_file)
        print(f"Successfully loaded the Vulns data")

        numVuln=data["report"]["metadata"]["assessments"]["vulnerabilities"]["count"]
        if numVuln == 0:
            print("No vulnerabilities detected!")
        else:
            print("Vulnerabilities detected!")
            for item in vuln:
                temp = {}
                if item["cve_score"] > vulnThreshold and item["detections"]:
                    temp["type"]="vulnerability"
                    temp["name"]=item["cve_name"]
                    temp["severity"] = item["cve_score"]
                    temp["description"] = item["description"]
                    temp["location"]=item["detections"]
                    findings["findings"].append(temp)
                elif vulnExists and "YES" in item["exploitable"] and item["detections"]:
                    temp["type"]="vulnerability"
                    temp["name"]=item["cve_name"]
                    temp["severity"] = item["cve_score"]
                    temp["description"] = item["description"]
                    temp["location"]=item["detections"]
                    findings["findings"].append(temp)

        print("Done processing vulns!")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in the Report file")
    except Exception as e:
        print(f"An error occurred while processing Report JSON: {str(e)}")



def process_malware(report_file, malware_file):
    global findings

    try:
        data = json.load(report_file)
        mal = json.load(malware_file)
        print(f"Successfully loaded the Report data")
    
        ##Check for Malware
        if checkMalware:
            print("Checking for Malware....")
            numMal=data["report"]["metadata"]["assessments"]["malware"]["count"]
            if numMal == 0:
                print("No malware detected!")
            else:
                print("Malware Detected!")
                
                for item in mal:
                    temp = {}
                    if item["malware"]: ## Check if malware is TRUE
                        temp["type"]="malware"
                        temp["name"]=item["malwareName"]
                        temp["location"]=item["detections"]
                        findings["findings"].append(temp)
                    elif  checkSuspect and  item["suspect"]: ## Check if config has suspect set to TRUE
                        temp["type"]="suspected malware"
                        temp["name"]=item["malwareName"]
                        temp["location"]=item["detections"]
                        findings["findings"].append(temp)
        else:
            print("Not checking for malware...")

    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in the Report file")
    except Exception as e:
        print(f"An error occurred while processing Report JSON: {str(e)}")



def main():
    parser = argparse.ArgumentParser(description="Process needed files")
    parser.add_argument('-r', '--report', type=argparse.FileType('r'), required=True, help="Input Report JSON file")
    parser.add_argument('-c', '--config', type=argparse.FileType('r'), required=True, help="Input Config JSON file")
    parser.add_argument('-v', '--vulns', type=argparse.FileType('r'), required=True, help="Input CVE JSON file")
    parser.add_argument('-m', '--malware', type=argparse.FileType('r'), required=True, help="Input Malware JSON file")
    args = parser.parse_args()

        
    ## Process the config file
    process_config(args.config)

    ## Process the CVEs
    process_vulns(args.report,args.vulns)
    
    ## Process the report file
    process_malware(args.report, args.malware)


    args.report.close()
    args.config.close()
    args.vulns.close()
    args.malware.close()

    outfile = open("findings.json", "w")
    outfile.write(json.dumps(findings))
    outfile.close()

if __name__ == "__main__":
    main()
