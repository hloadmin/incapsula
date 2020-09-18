#!/usr/bin/python3.8

import requests
import json
import boto3
import sys
import re
import time
import pprint

def addsite(api_url, api_id, api_key, domain):

    try:
        
        uri = "/add"
        paramstring = "?api_id=" + api_id + "&api_key=" + api_key + "&domain=" + domain

        url = api_url + uri + paramstring

        payload = {}
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        response = requests.request("POST", url, headers=headers, data=payload)

        siteData = json.dumps(response.json())
        if 'site_id' not in siteData:
            raise ValueError("Site add error. No site_id in response -- Aborting,  please check portal for manual cleanup")
		
        site_id = response.json()['site_id']
        status = response.json()['status']	

        return(site_id, status)

    except Exception as e:
        print(e)


def validatesite(api_url, api_id, api_key, site_id):
    try:
        print("entering validate")
        uri = "/configure"
        paramstring = "?api_id=" + api_id + "&api_key=" + api_key + \
            "&site_id=" + str(site_id) + "&param=domain_validation&value=dns"

        url = api_url + uri + paramstring
        response = requests.request("POST", url)
        
        if response.json()['res'] > 0:
            raise ValueError("Internal error with WAF\t" + str(response.json()['debug_info']))               
		        
        validation_string = response.json()['debug_info']['domain_dns'][domain][0]
        print("Configure TXT record for the domain this validation record\n" + validation_string + "\n")
        return(validation_string)

    except Exception as e:
        print(e)


def getDNSValidationRecords(api_url, api_id, api_key, site_id, key):
    try:        
        uri = "/status"
        paramstring = "?api_id=" + api_id + "&api_key=" + api_key + "&site_id=" + str(site_id)
        url = api_url + uri + paramstring
        dns = {}
        response = requests.request("POST", url)
        if key == "pending-certificate":            
            validation_string = response.json()['ssl']['generated_certificate']['validation_data'][0]['set_data_to'][0]
        elif key == "pending-dns-changes":            
            dns = response.json()['dns']
        return(validation_string, dns)

    except Exception as e:
        print("setvalidationTest" + str(e))


def setDNSValiadtionRecords(zone,validation_string):
    
    client = boto3.client('route53')
    hostedZoneResponse = client.list_hosted_zones_by_name(
        DNSName=zone,        
        MaxItems='1'
    )    
    
    hostedzoneID = (hostedZoneResponse['HostedZones'][0]['Id']).replace('/hostedzone/', '')	    
    print("Will be adding TXT record in Hostedzone " + zone + "--- " + hostedzoneID + "\n")

    getTXTResponse = client.list_resource_record_sets(
        HostedZoneId=str(hostedzoneID),
        StartRecordName=zone,
        StartRecordType='TXT',        
        MaxItems='1'
    )
    
    currentTxT = getTXTResponse['ResourceRecordSets'][0]['ResourceRecords']
    
    checkString = [{'Value': '"_globalsign-domain-verification=oJPj8tUeH-OfLpvb3GslKtgt4OynByvr23dkrbs2pJ"'}]
    
    flag = 0
    
    if(all(x in currentTxT for x in checkString)): 
        flag = 1
    
    if (flag) : 
        print ("TXT record already added, wait for propogation if required\n")
        pprint.pprint(currentTxT)
        return 1   
    else : 
        currentTxT.append({'Value': '"_globalsign-domain-verification=oJPj8tUeH-OfLpvb3GslKtgt4OynByvr23dkrbs2pJ"'})
        
        response = client.change_resource_record_sets(
            HostedZoneId= str(hostedzoneID),
            ChangeBatch={
                'Comment': 'test TXT validation',
                'Changes': [
                    {
                        'Action': 'UPSERT',
                        'ResourceRecordSet': {
                            'Name': zone,
                            'Type': 'TXT',
                            'TTL': 60,
                            'ResourceRecords': currentTxT
                        }
                    },
                ]
            }
        )
    print(response)

def modifySiteSecurity(api_url, api_id, api_key, site_id):

    try:
        uri = "/configure/security"

        waf_ruleid = ['api.threats.sql_injection', 'api.threats.cross_site_scripting','api.threats.illegal_resource_access', 'api.threats.remote_file_inclusion']
                
        for ruleid in waf_ruleid:
            
            paramstring = "?api_id=" + api_id + "&api_key=" + api_key + "&site_id=" + str(site_id) + "&rule_id=" + ruleid + "&security_rule_action=api.threats.action.block_request"
            url = api_url + uri + paramstring           
           
            response = requests.request(
                "POST", url)
            rtr = response.json()['security']['waf']['rules']
        return rtr
    except Exception as e:
        print(e)

def setCacheing(api_url, api_id, api_key, site_id):
    try:
        uri = "/performance/cache-mode"	
        paramstring = "?api_id=" + api_id + "&api_key=" + api_key + \
            "&site_id=" + str(site_id) + "&cache_mode=aggressive&aggressive_cache_duration=15_min"
 
        url = api_url + uri + paramstring
        response = requests.request("POST", url)    
        return(response.json())
    except Exception as e:
        print(e)


def advancedSettings(api_url, api_id, api_key, site_id):
    
    try:
        advanced_params = ['redirect_http_to_https', 'redirect_naked_domain_to_full']
        uri = "/performance/advanced"	
        
        for params in advanced_params:
            paramstring = "?api_id=" + api_id + "&api_key=" + api_key + \
                "&site_id=" + str(site_id) + "&param=" + params + "&value=true"
            url = api_url + uri + paramstring            
            response = requests.request("POST", url)
            if response.json()['res'] == 0:
                print("\nParameter" + params + " is enabled")    
            else:
                print("Error setting value -- " + params)        

    except Exception as e:
        print(e)

def getArgs():
    try:
        if len(sys.argv) != 3:
            print('\n     Usage: \n\n     %s  fqdn zone\n' % sys.argv[0])
            print('\n     example: \n\n     %s  www.readyrooms.com.au readyrooms.com.au\n' % sys.argv[0])
            sys.exit(1)
        else:
            fqdn = re.sub('https://|http://|www.', '', sys.argv[1])
            fqdn = fqdn.split('/')
            zone = sys.argv[2]
            print("fqdn: %s" % fqdn[0])
            print("zone: %s" % zone)
            return fqdn[0], zone
    except Exception as e:
        print(e)

'''
  Add site to incapsula
'''
##GET User input. Only param count validation is done, not value validation. 
domain, zone = getArgs()

##Declare connection strings.
##TODO - Move this to ENV variables, similar to AWS credentials.
api_key = "xxxxxxxxxxxxxxxxxxxx"
api_id = "xxxxxxxx"
api_url = "https://my.incapsula.com/api/prov/v1/sites"

try:
    ##ADD Site. If successful, returns the Site_ID and the progress status of the WAF. 
    ##IF side already exist, it returns the Site_ID without any further changes. 
    ##Possible values for Progress status are,
    ## ['pending-select-approver', 'pending-certificate', 'pending-dns-change', 'fully configured']
    site_id, status = addsite(api_url, api_id, api_key, domain)
    print("Site ID for the URL -- " + str(site_id) + "and WAF status is " + status + "\n")
	
    ##Based on various progress status, we kick start relevanat process. 
    ##if status is pending-select-approver, domain owenership validation process via DNS started. 
    if status == "pending-select-approver":
        validation_string = validatesite(api_url, api_id, api_key, site_id)
        print("Set DNS validation TXT record\n" + str(validation_string) + "\n")
    ##if status is pending-certificates or pending-dns-changes, we need to add DNS records. 
    elif status == "pending-certificate" or status == "pending-dns-changes":
        validation_string, dns = getDNSValidationRecords(api_url, api_id, api_key, site_id, status)
        print("Pending Validation - *** if empty, domain already validated ***: \n" + str(validation_string) + "\t\n")
        print("Ready for cutover - *** If empty, check validation *** \n" + str(dns) +"\n" )
    else: print("Site is already configured correctly")        
        
    ##Set DNS validation records to provde domain ownership and Issue certificate. 
	##Note: If another URL with same domain exists, with wildcard cert, then this validation might not be required.
    dns_validation_status = setDNSValiadtionRecords(zone, validation_string)
    
	##Enable default WAF rules (change action to block request)
    waf_rulesstatus = modifySiteSecurity(api_url, api_id, api_key, site_id)
    #print("\n\nEnabled WAF security settings")
    #print(json.dumps(waf_rulesstatus, indent=4, sort_keys=True) +"\n\n")

    # Enabled this module if additional caching module if requred.
    # setCacheing(api_url, api_id, api_key, site_id)

	# advanced settings for HTTP to HTTPS redirection is performed here.
    advancedSettings(api_url, api_id, api_key, site_id)
	
except Exception as e:
    print("main\t" ,str(e))
