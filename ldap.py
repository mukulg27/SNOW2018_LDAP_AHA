#! /usr/bin/env python

# Enter the following in terminal to run: 
#./ldap.py -inc INT3852254 -inst fisindia

import argparse
import requests
import json
import getpass




def run(args):
	inc = args.inc # these match the "dest": dest="input"
	inst = args.inst # from dest="output"
	urls(inst,inc)

# FIRST STEP: Getting Information from HI.
user_hi = raw_input("Insert HI Username: ")
pwd_hi = getpass.getpass('Insert HI Password:')

# Fetching Primar & Seconday Node

def urls(inst,inc):



	hi_node_url ='https://hi.service-now.com/api/now/table/u_cmdb_aha_node_summary'

	hi_node_headers = {"Content-Type":"application/json","Accept":"application/json"}

	hi_node_query = 'u_operational_status=operational^u_instance_name='+inst

	hi_node_parameters = {'sysparm_query':hi_node_query, 'sysparm_fields':'u_node_name,u_discovered_node_port,u_host_server,u_primary_dc,u_standby_dc','sysparm_limit':'1'}

	hi_node_response = requests.get(hi_node_url, auth=(user_hi, pwd_hi), params=hi_node_parameters, headers=hi_node_headers )

	# Check for HTTP codes other than 200
	if hi_node_response.status_code != 200: 
	    print('Status:', hi_node_response.status_code, 'Headers:', hi_node_response.headers, 'Error Response:',hi_node_response.json())
	    exit()

	# Decode the JSON response into a dictionary and use the data
	hi_node_data = hi_node_response.json()


	hi_node_u_primary_dc = hi_node_data['result'][0]['u_primary_dc'].lower()
	hi_node_u_standby_dc = hi_node_data['result'][0]['u_standby_dc'].lower()

	#Fetching Primary URL
	print("##########################################################")
	print("################## PRIMARY LDAP TEST #####################")
	print("##########################################################")

	hi_node_query_primary = 'u_operational_status=operational^u_instance_name='+inst+'^u_host_serverLIKE'+hi_node_u_primary_dc

	hi_node_parameters_primary = {'sysparm_query':hi_node_query_primary, 'sysparm_fields':'u_node_name,u_discovered_node_port,u_host_server','sysparm_limit':'1'}

	hi_node_response_primary = requests.get(hi_node_url, auth=(user_hi, pwd_hi), params=hi_node_parameters_primary, headers=hi_node_headers )
	# Check for HTTP codes other than 200
	if hi_node_response_primary.status_code != 200: 
		print('Status:', hi_node_response_primary.status_code, 'Headers:', hi_node_response_primary.headers, 'Error Response:',hi_node_response_primary.json())
		exit()

	# Decode the JSON response into a dictionary and use the data
	hi_node_data_primary = hi_node_response_primary.json()
	# print(data2a)

	u_host_server_primary = hi_node_data_primary['result'][0]['u_host_server']
	u_discovered_node_port_primary = hi_node_data_primary['result'][0]['u_discovered_node_port']
	u_node_name_primary = hi_node_data_primary['result'][0]['u_node_name']
	url_primary = 'http://' +u_host_server_primary + ':'+u_discovered_node_port_primary+'/security_status.do?name=LDAPAuthStatus&action=testconnection'
	print("primary url : "+ url_primary)
	ldaptest(url_primary,inc,"Primary")


	#Fetching Seconday URL

	print("##########################################################")
	print("################# SECONDARY LDAP TEST ####################")
	print("##########################################################")

	hi_node_query_secondary = 'u_operational_status=operational^u_instance_name='+inst+'^u_host_serverLIKE'+hi_node_u_standby_dc
	hi_node_parameters_secondary = {'sysparm_query':hi_node_query_secondary, 'sysparm_fields':'u_node_name,u_discovered_node_port,u_host_server','sysparm_limit':'1'}

	hi_node_response_secondary = requests.get(hi_node_url, auth=(user_hi, pwd_hi), params=hi_node_parameters_secondary, headers=hi_node_headers )
	# Check for HTTP codes other than 200
	if hi_node_response_secondary.status_code != 200: 
		print('Status:', hi_node_response_secondary.status_code, 'Headers:', hi_node_response_secondary.headers, 'Error Response:',hi_node_response_secondary.json())
		exit()

	# Decode the JSON response into a dictionary and use the data
	hi_node_data_secondary = hi_node_response_secondary.json()
	# print(data2b)

	u_host_server_secondary = hi_node_data_secondary['result'][0]['u_host_server']
	u_discovered_node_port_secondary = hi_node_data_secondary['result'][0]['u_discovered_node_port']
	u_node_name_secondary= hi_node_data_secondary['result'][0]['u_node_name']
	url_secondary = 'http://' +u_host_server_secondary + ':'+u_discovered_node_port_secondary+'/security_status.do?name=LDAPAuthStatus&action=testconnection'
	print("secondary url : "+ url_secondary)
	ldaptest(url_secondary,inc,"Secondary")




#LDAP Connectivity Test

def ldaptest(url_ldap,inc,node):
	print(url_ldap)

	headers_ldap = {"Content-Type":"application/json","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"}

	response_ldap = requests.get(url_ldap, headers=headers_ldap )
	# Check for HTTP codes other than 200
	if response_ldap.status_code != 200: 
	    print('Status:', response_ldap.status_code, 'Headers:', response_ldap.headers, 'Error Response:',response_ldap.json())
	    exit()


	data_ldap = response_ldap.json()
	#print(data_ldap)
	#formated_json =json.dumps(data_ldap, indent=4)
	
	formated_json =json.dumps(data_ldap)
	formated_json = formated_json.replace('"','\\"')
	formated_json = formated_json.replace('{','{<br/>')
	formated_json = formated_json.replace('}, {','<br/>}')
	formated_json = formated_json.replace(', ',', <br/>')
	formated_json = formated_json.replace('}],','}],<br/>')

	
	formated_json = "[code]<pre><code>"+node +" URL : "+ url_ldap+"<br/><br/>"+formated_json+"</code></pre>[/code]"
	hiupdate(inc,formated_json)



#Updating HI Incident

def hiupdate(inc,formated_json):
	print(formated_json)
	print(inc)
	# Set the request parameters
	# Need to change the instance to hi.service-now.com after testing
	url_hi1 = 'https://hi.service-now.com/api/now/table/incident'

	# Set Query
	hi_inc_query='number='+inc

	# Set proper headers
	headers = {"Content-Type":"application/json","Accept":"application/json"}

	# Set parameters
	parameters1 = {'sysparm_query':hi_inc_query, 'sysparm_fields':'sys_id,number'}


	# Do the HTTP request
	response1 = requests.get(url_hi1, auth=(user_hi, pwd_hi), params=parameters1, headers=headers)

	# Check for HTTP codes other than 200
	if response1.status_code != 200: 
	    print('Status:', response1.status_code, 'Headers:', response1.headers, 'Error Response:',response1.json())
	    exit()

	# # Decode the JSON response into a dictionary and use the data
	data1 = response1.json()
	print(data1)
	sys_id_inc = data1['result'][0]['sys_id']
	print(sys_id_inc)

	# Update ther Record

	url_hi2 = 'https://hi.service-now.com/api/now/table/incident/'+sys_id_inc
	headers2 = {"Content-Type":"application/json","Accept":"application/json"}

	data_post = "{\"work_notes\":\"" + formated_json +"\"}"
	
	print(url_hi2)
	print(data_post)

	response2 = requests.put(url_hi2, auth=(user_hi, pwd_hi), headers=headers2,data=data_post)
	#response2 = requests.put(url_hi2, auth=(user_hi, pwd_hi), headers=headers2,data="{\"work_notes\":\"{u'HCC Ldap Service': [{<br/>u'url': u'ldap://ldap.hccs.edu:636/', u'test_success': True, u'operational_status': True, u'test_error_message': u'Connected successfully', u'test_error_code': 0}]}\"}")


	# Check for HTTP codes other than 200
	if response2.status_code != 200: 
	    print('Status:', response2.status_code, 'Headers:', response2.headers, 'Error Response:',response2.json())
	    exit()





def main():
	parser=argparse.ArgumentParser(description="LDAP Connectivity test for Primary & Secondary DC")
	parser.add_argument("-inc",help="HI Incident number" ,dest="inc", type=str, required=True)
	parser.add_argument("-inst",help="Instance to run LDAP Test on" ,dest="inst", type=str, required=True)
	parser.set_defaults(func=run)
	args=parser.parse_args()
	args.func(args)

if __name__=="__main__":
	main()