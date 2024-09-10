#!/usr/bin/python3

import base64
import json
import pandas as pd
import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

user = input('Username: ')
password = input('Password: ')

#url = "https://nsxmgr.example.net"
url = input('Address for the NSX Manager (https://nsxmsg.example.net): ')

if not url.startswith("https://"):
    url = f'https://{url}'

headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
          }

policies = requests.get(f'{url}/policy/api/v1/infra/domains/default/security-policies', headers=headers, verify=False, auth=(user, password))

with pd.ExcelWriter("firewall-out.xlsx", mode="w", engine="openpyxl") as writer:
  for policy in policies.json()['results']:
    rule_names = []
    rule_ids = []
    rule_sequences = []
    rule_source_group_ips_list = []
    rule_source_group_vms_list = []
    rule_destination_group_ips_list = []
    rule_destination_group_vms_list = []
    rule_port_infos = []

    rules = requests.get(f"{url}/policy/api/v1/infra/domains/default/security-policies/{policy['id']}/rules", headers=headers, verify=False, auth=(user, password))
    for rule in rules.json()['results']:
      rule_name = rule['display_name']
      rule_id = rule['id']
      rule_id = rule['rule_id']
      rule_sequence = rule['sequence_number']
      rule_source_groups = rule['source_groups']
      rule_dest_groups = rule['destination_groups']
      rule_services = rule['services']

      if rule['source_groups']:
        source_group_ips = ""
        source_group_vms = ""
        for group in rule['source_groups']:
          if group != "ANY":
            group_id = requests.get(f"{url}/policy/api/v1{group}", headers=headers, verify=False, auth=(user, password))
            sgroups = requests.get(f"{url}/policy/api/v1{group}/members/ip-addresses", headers=headers, verify=False, auth=(user, password))
            if "results" in sgroups.json():
              for sip in sgroups.json()['results']:
                source_group_ips += f"{sip}\r\n"
            sgroups = requests.get(f"{url}/policy/api/v1{group}/members/virtual-machines", headers=headers, verify=False, auth=(user, password))
            if "results" in sgroups.json():
              for vm in sgroups.json()['results']:
                source_group_vms += f"{vm['display_name']}\r\n"
          else:
            source_group_ips = "ANY"
            source_group_vms = "None"

      if rule['destination_groups']:
        destination_group_ips = ""
        destination_group_vms = ""
        for group in rule['destination_groups']:
          if group != "ANY":
            group_id = requests.get(f"{url}/policy/api/v1{group}", headers=headers, verify=False, auth=(user, password))
            dgroups = requests.get(f"{url}/policy/api/v1{group}/members/ip-addresses", headers=headers, verify=False, auth=(user, password))
            if "results" in dgroups.json():
              for dip in dgroups.json()['results']:
                destination_group_ips += f"{dip}\r\n"
            dgroups = requests.get(f"{url}/policy/api/v1{group}/members/virtual-machines", headers=headers, verify=False, auth=(user, password))
            if "results" in dgroups.json():
              for vm in dgroups.json()['results']:
                destination_group_vms += f"{vm['display_name']}\r\n"
          else:
            destination_group_ips = "ANY"
            destination_group_vms = "None"

      if rule['services']:
        dest_service = []
        portinfo = ""
        for rule in rule['services']:
          if rule != "ANY":
            rservices = requests.get(f"{url}/policy/api/v1{rule}", headers=headers, verify=False, auth=(user, password))
            rservices = rservices.json()
            print(rservices)
            for rservice in rservices['service_entries']:
              if "destination_ports" in rservice:
                portinfo += f"Ports: {rservice['destination_ports']} - "
              if "l4_protocol" in rservice:
                portinfo += f"Protocol: {rservice['l4_protocol']} - "
              if "protocol" in rservice:
                portinfo += f"Protocol: {rservice['protocol']} - "
              if "alg" in rservice:
                portinfo += f"Algorithm: {rservice['alg']} - "
              if "display_name" in rservice:
                portinfo += f"Name: {rservice['display_name']}"
              else:
                print("\r\n Error:")
                print(rservice)
              portinfo += "\r\n"
          else:
            portinfo += "ANY\r\n"

      rule_names.append(rule_name)
      rule_ids.append(rule_id)
      rule_sequences.append(rule_sequence)
      rule_source_group_ips_list.append(source_group_ips)
      rule_source_group_vms_list.append(source_group_vms)
      rule_destination_group_ips_list.append(destination_group_ips)
      rule_destination_group_vms_list.append(destination_group_vms)
      rule_port_infos.append(portinfo)



      print(f"Rule Name: {rule_name}")
      print(f"Rule ID: {rule_id}")
      print(f"Rule Sequence: {rule_sequence}")
      print(f"Rule Source IPs: {source_group_ips}")
      print(f"Rule Source Names: {source_group_vms}")
      print(f"Rule Destination IPs: {destination_group_ips}")
      print(f"Rule Destination Namess: {destination_group_vms}")
      print(f"Ports/Services: {portinfo}")

    df = pd.DataFrame({'Rule Name': rule_names, 'Rule ID': rule_ids, 'Rule Sequence': rule_sequences, 'Sources IPs': rule_source_group_ips_list, 'Source VMs': rule_source_group_vms_list,
                       'Destination IPs': rule_destination_group_ips_list, 'Destination VMs': rule_destination_group_vms_list, 'Port / Service(s)': rule_port_infos})
    df.to_excel(writer, sheet_name=policy['display_name'][:30])
