
# Developed by : Behzad Kianbakht (2023/12/05)
# ---------------------------------------------------------------------------------------

import requests
import urllib3
import logging
import logging.handlers
import sys
import json
import time
from pyzabbix import ZabbixMetric , ZabbixSender


script_type = sys.argv[1]
# List of unity storage Name and IP ; This Name should be same as Host Name in Zabbix
storage_list = [["Unity1","192.0.0.0"],["Unity2","192.0.0.20"]]


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#-----------------------------------------------------------------------
unity_api_user = "UserName"
unity_api_pass = "PassWord"
unity_api_port = "443"
list_resources = ['battery','ssd','ethernetPort','fcPort','sasPort','fan','powerSupply','storageProcessor','lun','pool','dae','dpe','ioModule','lcc','memoryModule','ssc','uncommittedPort','disk']
#-----------------------------------------------------------------------

Zabbix_Interface_IP = "127.0.0.1"

#-----------------------------------------------------------------------
LOG_FILENAME = "/var/log/zabbix/storage_device_log/unity.log"
#print(LOG_FILENAME)
unity_logger = logging.getLogger("unity_logger")
unity_logger.setLevel(logging.INFO)

unity_handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=1024*1024, backupCount=5)
unity_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
unity_handler.setFormatter(unity_formatter)
unity_logger.addHandler(unity_handler)
#-----------------------------------------------------------------------

def api_connect(api_user,api_password,api_ip,api_port):
	api_login_url = "https://{0}:{1}/api/types/loginSessionInfo".format(api_ip,api_port)
	session_unity = requests.Session()
	session_unity.auth = (api_user, api_password)
	session_unity.headers = {'X-EMC-REST-CLIENT': 'true', 'Content-type': 'application/json', 'Accept': 'application/json'}

	try:
		login = session_unity.get(api_login_url, verify=False)
	except Exception as oops:
		unity_logger.error("Connection Error Occurs: {0}".format(oops))
		sys.exit("50")

	if login.status_code != 200:
		unity_logger.error("Connection Return Code = {0}".format(login.status_code))
		sys.exit("60")
	elif login.text.find("isPasswordChangeRequired") >= 0: # If i can find string "isPasswordChangeRequired" therefore login is successful
		unity_logger.info("Connection established")
		return session_unity
	else:
		unity_logger.error("Login Something went wrong")
		sys.exit("70")


def api_logout(api_ip, session_unity):
	api_logout_url = "https://{0}/api/types/loginSessionInfo/action/logout".format(api_ip) 
	session_unity.headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

	try:
		logout = session_unity.post(api_logout_url, verify=False)
	except Exception as oops:
		unity_logger.error("Logout Error Occurs: {0}".format(oops))
		sys.exit("150")

	if logout.status_code != 200:
		unity_logger.error("Logout status = {0}".format(logout.status_code))
		sys.exit("160")
	elif logout.text.find("Logout successful") >= 0:
		unity_logger.info("Logout successful")
	else:
		unity_logger.error("Logout Something went wrong")
		sys.exit("170")


def convert_to_zabbix_json(data,storage_name,resource,timestampnow,):
        if script_type == "discovery":
            output = {}
            output = {
				"data" : data,
				"Host_Name" : storage_name,
				"key" : resource,
				"time" : timestampnow
			}
            return output
        elif script_type == "status":
            pass


def discovering_resources(api_user, api_password, api_ip, api_port, storage_name, list_resources):
	api_session = api_connect(api_user, api_password, api_ip, api_port)
	try:
		zbx = ZabbixSender(Zabbix_Interface_IP,chunk_size=1000)
	except:
		print("zabbix connection can not establish")
	xer = []
	packet = []
	try:
		for resource in list_resources:
			resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name".format(api_ip, api_port, resource)
			resource_info = api_session.get(resource_url, verify=False)
			resource_info = json.loads(resource_info.content.decode('utf8'))

			discovered_resource = []
			for one_object in resource_info['entries']:
				if ['lun', 'pool'].count(resource) == 1:
					one_object_list = {}
					one_object_list["{#ID}"] = one_object['content']['id']
					one_object_list["{#NAME}"] = one_object['content']['name'].replace(' ', '_')
					discovered_resource.append(one_object_list)
				else:
					one_object_list = {}
					one_object_list["{#ID}"] = one_object['content']['id']
					discovered_resource.append(one_object_list)
			timestampnow = int(time.time())
			xer.append(discovered_resource)
			converted_resource = convert_to_zabbix_json(discovered_resource,storage_name,resource,timestampnow)
			packet = [ZabbixMetric(host=converted_resource["Host_Name"],key=converted_resource["key"],value=json.dumps(converted_resource["data"]))]
			zbx.send(packet)
		print("send data to zabbix DONE!")
	except Exception as e:
		unity_logger.error("Error occurs in discovering")
		sys.exit("1000")
	api_logout(api_ip,api_session) 


def get_status_resources(api_user, api_password, api_ip, api_port, storage_name, list_resources):
	api_session = api_connect(api_user, api_password, api_ip, api_port)
	try:
		zbx = ZabbixSender(Zabbix_Interface_IP,chunk_size=1000)
	except:
		print("zabbix connection can not establish")
	state_resources = [] # This list will persist state of resources (pool, lun, fcPort, battery, diks, ...) on zabbix format
	try:
		for resource in list_resources:
			# Create different URI for different resources
			if ['pool'].count(resource) == 1:
				resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health,sizeTotal,sizeUsed,sizeSubscribed".format(api_ip, api_port, resource)
			elif ['lun'].count(resource) == 1:
				resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health,sizeTotal,sizeAllocated".format(api_ip, api_port, resource)
			else:
				resource_url = "https://{0}:{1}/api/types/{2}/instances?fields=name,health,needsReplacement".format(api_ip, api_port, resource)

			# Get info about one resource
			resource_info = api_session.get(resource_url, verify=False)
			resource_info = json.loads(resource_info.content.decode('utf8'))
			timestampnow = int(time.time())

			if ['ethernetPort', 'fcPort', 'sasPort'].count(resource) == 1:
				for one_object in resource_info['entries']:
					key_health = "health.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
					key_status = "link.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
					state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))

					# Get state of interfaces from description
					descriptionIds = str(one_object['content']['health']['descriptionIds'][0]) # Convert description to string
					if descriptionIds.find("LINK_UP") >= 0: # From description i can known, link is up or link is down
						link_status = 10
					elif descriptionIds.find("LINK_DOWN") >=0:
						link_status = 11

					state_resources.append("%s %s %s %s" % (storage_name, key_status, timestampnow, link_status))

			elif ['lun'].count(resource) == 1:
				for one_object in resource_info['entries']:
					key_health = "health.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_')) # Use lun name instead lun id on zabbix key
					key_sizeTotal = "sizeTotal.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))
					key_sizeAllocated = "sizeAllocated.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))

					state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))
					state_resources.append("%s %s %s %s" % (storage_name, key_sizeTotal, timestampnow, one_object['content']['sizeTotal']))
					state_resources.append("%s %s %s %s" % (storage_name, key_sizeAllocated, timestampnow, one_object['content']['sizeAllocated']))
			elif ['pool'].count(resource) == 1:
				for one_object in resource_info['entries']:
					key_health = "health.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_')) # Use pull name instead lun id on zabbix key
					key_sizeUsedBytes = "sizeUsedBytes.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))
					key_sizeTotalBytes = "sizeTotalBytes.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))
					key_sizeSubscribedBytes = "sizeSubscribedBytes.{0}.[{1}]".format(resource, one_object['content']['name'].replace(' ', '_'))

					state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))
					state_resources.append("%s %s %s %s" % (storage_name, key_sizeUsedBytes, timestampnow, one_object['content']['sizeUsed']))
					state_resources.append("%s %s %s %s" % (storage_name, key_sizeTotalBytes, timestampnow, one_object['content']['sizeTotal']))
					state_resources.append("%s %s %s %s" % (storage_name, key_sizeSubscribedBytes, timestampnow, one_object['content']['sizeSubscribed']))
			else:
				for one_object in resource_info['entries']:
					# Get state of resources from description
					descriptionIds = str(one_object['content']['health']['descriptionIds'][0]) # Convert description to string
					if descriptionIds.find("ALRT_COMPONENT_OK") >= 0:
						running_status = 8
					elif descriptionIds.find("ALRT_DISK_SLOT_EMPTY") >= 0:
						running_status = 6
					else:
						running_status = 5

					key_health = "health.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
					key_status = "running.{0}.[{1}]".format(resource, one_object['content']['id'].replace(' ', '_'))
					state_resources.append("%s %s %s %s" % (storage_name, key_health, timestampnow, one_object['content']['health']['value']))
					state_resources.append("%s %s %s %s" % (storage_name, key_status, timestampnow, running_status))

		for status_details in state_resources:
			status_details_list = status_details.split(" ")
			#print(status_details_list)
			packet = [ZabbixMetric(host=status_details_list[0],key=status_details_list[1],value=int(status_details_list[3]))]
			#print(packet)
			zbx.send(packet)
		print("send data to zabbix DONE!")

	except Exception as oops:
		# print("failed Status")
		# print(oops)
		unity_logger.error("Error occured in get state")
		sys.exit("1000")
	api_logout(api_ip, api_session)


#---------------------------------------------------------------------------
for i in range(0,len(storage_list)):
	if script_type == "discovery":
		try:
			result_discovery = discovering_resources(api_user=unity_api_user,api_password=unity_api_pass,api_ip=storage_list[i][1],api_port=unity_api_port,storage_name=storage_list[i][0],list_resources=list_resources)
		except Exception as e:
			print(f"Discovery Error: {e}")
	elif script_type == "status":
		try:
			result_status = get_status_resources(api_user=unity_api_user,api_password=unity_api_pass,api_ip=storage_list[i][1],api_port=unity_api_port,storage_name=storage_list[i][0],list_resources=list_resources)
		except Exception as e:
			print(f"Status Error: {e}")
	else:
		print("Input arg not define - ( discovery or status )")
