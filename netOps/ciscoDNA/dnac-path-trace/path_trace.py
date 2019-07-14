#!/usr/bin/env python
# -*- coding: utf-8 -*-

from env_lab import apicem
import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    'content-type': "application/json",
    'x-auth-token': ""
    }

def apic_login(host, username, password):
    """
    Use the REST API to log into an APIC-EM and retrieve ticket
    """
    url = "https://{}/api/system/v1/auth/token".format(host)

    # Make Login request and return the response body
    response = requests.request("POST", url, auth=HTTPBasicAuth(username, password),headers=headers, verify=False)

    return response.json()["Token"]

def host_list(apic, ticket, ip=None, mac=None, name=None):

    url = "https://{}/api/v1/host".format(apic)
    headers["x-auth-token"] = ticket
    filters = []

    if ip:
        filters.append("hostIp={}".format(ip))
    if mac:
        filters.append("hostMac={}".format(mac))
    if name:
        filters.append("hostName={}".format(name))
    if len(filters) > 0:
        url += "?" + "&".join(filters)

    response = requests.request("GET", url, headers=headers, verify=False)
    print(response.text)
    return response.json()["response"]

def network_device_list(apic, ticket, id=None):
    url = "https://{}/api/v1/network-device".format(apic)
    headers["x-auth-token"] = ticket

    if id:
        url += "/{}".format(id)

    response = requests.request("GET", url, headers=headers, verify=False)

    if id:
        return [response.json()["response"]]

    return response.json()["response"]

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument("source_ip", help = "Source IP Address")
    parser.add_argument("destination_ip", help = "Destination IP Address")
    args = parser.parse_args()

    source_ip = args.source_ip
    destination_ip = args.destination_ip

    print("Running Troubleshooting Script for ")
    print("     Source IP:      {} ".format(source_ip))
    print("     Destination IP: {} ".format(destination_ip))
    print("")

    login = apic_login(apicem['host'], apicem['username'], apicem['password'])

    source_host = host_list(apicem['host'], login, ip=source_ip)
    destination_host = host_list(apicem['host'], login, ip=destination_ip)

    print(source_host, destination_host)
    #source_host_net_device = network_device_list(apicem['host'], login, id=source_host[0]["connectedNetworkDeviceId"])
    print("Source Host Network Connection Details:")
    print("-" * 45)
    #print_network_device_details(source_host_net_device[0])
    #if source_host[0]["hostType"] == "wired":
    #    source_host_interface = interface_details(apicem['host'], login, id=source_host[0]["connectedInterfaceId"])
    #    print("Attached Interface:")
    #    print("-" * 20)
    #    print_interface_details(source_host_interface)

    #destination_host_net_device = network_device_list(apicem["host"], login, id=destination_host[0]["connectedNetworkDeviceId"])
    print("Destination Host Network Connection Details:")
    print("-" * 45)
    #print_network_device_details(destination_host_net_device[0])
    #if destination_host[0]["hostType"] == "wired":
    #    destination_host_interface = interface_details(apicem["host"], login, id=destination_host[0]["connectedNetworkDeviceId"])
    #    print("Attached Interface:")
    #    print("-" * 20)
    #    print_interface_details(destination_host_interface)

