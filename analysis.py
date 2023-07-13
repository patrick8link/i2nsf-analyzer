import os
from ncclient import manager
from xml.dom import minidom
from datetime import datetime, timezone
import xmltodict
import json
import csv
import pandas as pd
import pickle
import time

confd = {'address': '10.0.0.5',
           'netconf_port': 2022,
           'username': 'admin',
           'password': 'admin'}

confd_analytics = {'address': '10.0.0.44',
           'netconf_port': 2022,
           'username': 'admin',
           'password': 'admin'}

confd_manager = manager.connect(
        host = confd["address"],
        port = confd["netconf_port"],
        username = confd["username"],
        password = confd["password"],
        hostkey_verify = False)



filename = 'final_model.pkl'
with open(filename, 'rb') as file:  
	loaded_model = pickle.load(file)
	file.close()


confd_manager.create_subscription(stream_name="I2NSF-Monitoring")
data = {}
while True:
	#print('Waiting for next notification')

	# This will block until a notification is received because
	# we didn't pass a timeout or block=False
	n = confd_manager.take_notification()
	
	
	local_time = datetime.now(timezone.utc).astimezone()
	#print("Current Time: {} ".format(local_time.isoformat()))
	with open('log/monitor.xml','w+') as f:
	#with open('logs.xml','w+') as f:
		f.write(n.notification_xml)
	#print(n.notification_ele.tag)
	d = xmltodict.parse(n.notification_xml)
	
	data = d["notification"]["i2nsf-event"]["i2nsf-traffic-flows"]
	data["eventTime"] = d["notification"]["eventTime"]    
	mydata = data['arrival-rate'],data['arrival-throughput']


	mydf = pd.DataFrame([mydata],columns = ['arrival-rate','arrival-throughput'])
	#print(mydf)
	result = loaded_model.predict(mydf)
	print(result)
	endTime = time.time()
	print(endTime)
	

	if result[0] == 1:
		confd_analytics_manager = manager.connect(
			host = confd_analytics["address"],
			port = confd_analytics["netconf_port"],
			username = confd_analytics["username"],
			password = confd_analytics["password"],
			hostkey_verify = False)
		reconfiguration= f"""
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <i2nsfnfi:i2nsf-security-policy xmlns="urn:ietf:params:xml:ns:yang:ietf-i2nsf-analytics-interface"
        xmlns:i2nsfnfi="urn:ietf:params:xml:ns:yang:ietf-i2nsf-nsf-facing-interface"
        xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <i2nsfnfi:name>block_attack</i2nsfnfi:name>
    <i2nsfnfi:rules>
        <i2nsfnfi:name>block_attack</i2nsfnfi:name>
        <i2nsfnfi:condition>
        <i2nsfnfi:ipv4>
            <i2nsfnfi:source-ipv4-range>
				<i2nsfnfi:start>{data["src-ip"]}</i2nsfnfi:start>
				<i2nsfnfi:end>{data["src-ip"]}</i2nsfnfi:end>
            </i2nsfnfi:source-ipv4-range>
        </i2nsfnfi:ipv4>
        </i2nsfnfi:condition>
        <i2nsfnfi:action>
        <i2nsfnfi:packet-action>
            <i2nsfnfi:ingress-action>drop</i2nsfnfi:ingress-action>
        </i2nsfnfi:packet-action>
        </i2nsfnfi:action>
    </i2nsfnfi:rules>
    <nsf-name>firewall</nsf-name>
    <problem>
        <ddos-detected>
        <attack-src-ip>{data["src-ip"]}</attack-src-ip>
        <attack-dst-ip>{data["dst-ip"]}</attack-dst-ip>
        <attack-dst-port>{data["dst-port"]}</attack-dst-port>
        </ddos-detected>
    </problem>
    </i2nsfnfi:i2nsf-security-policy>
</nc:config>
"""
		print (f"{data['eventTime']} - Possible attack from {data['src-ip']}")
		confd_reconfiguration = confd_analytics_manager.edit_config(target="running",config = reconfiguration)
		confd_analytics_manager.close_session()
