import argparse
import json
import csv
import re

checkMalware = False
vulnExists = True
vulnThreshold=0
behaviors=[]
vulns = []
findings=[]

def process_config(json_file):
    global checkMalware, vulnExists, vulnThreshold, behaviors
    try:
        data = json.load(json_file)
        print(f"Successfully loaded Config data")
        checkMalware = data["malware"]
        vulnExists=data["vulnExists"]
        vulnThreshold=data["vulnThreshold"]
        behaviors=data["behaviors"]

    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in the Config file")
    except Exception as e:
        print(f"An error occurred while processing Config JSON: {str(e)}")



def process_vulns(vuln_file):
    try:
        data = json.load(vuln_file)
        print(f"Successfully loaded the Vulns data")

        ##for x in data:



    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in the Report file")
    except Exception as e:
        print(f"An error occurred while processing Report JSON: {str(e)}")



def process_malware(json_file):
    try:
        data = json.load(json_file)
        print(f"Successfully loaded the Report data")
    
        ##Check for Malware
        if checkMalware:
            print("Checking for Malware....")
            numMal=data["report"]["metadata"]["assessments"]["malware"]["count"]
            if numMal == 0:
                print("No malware detected!")
            else:
                print("Malware Detected!")
        else:
            print("Not checking for malware...")


    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in the Report file")
    except Exception as e:
        print(f"An error occurred while processing Report JSON: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Process needed files")
    parser.add_argument('-f', '--file', type=argparse.FileType('r'), required=True, help="Input JSON file")
    parser.add_argument('-c', '--config', type=argparse.FileType('r'), required=True, help="Config JSON file")
    parser.add_argument('-v', '--vulns', type=argparse.FileType('r'), required=True, help="CVE JSON file")
    args = parser.parse_args()

        
    ## Process the config file
    process_config(args.config)

    ## Process the CVEs
    process_vulns(args.vulns)
    
    ## Process the report file
    process_malware(args.file)


    args.file.close()
    args.config.close()

if __name__ == "__main__":
    main()
