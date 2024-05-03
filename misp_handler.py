#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert, misp_fgt_tag, fgt_url, fgt_key
import requests as rq
import argparse
import json


class LatimerMISP2FGT():
    """
    Init device instance.
    """

    def __init__(self, misp_url, misp_key, misp_verifycert, misp_fgt_tag, fgt_url, fgt_key):
        self._misp_url = misp_url
        self._misp_key = misp_key
        self._misp_verifycert = misp_verifycert
        self._misp_fgt_tag = misp_fgt_tag
        self._fgt_url = fgt_url
        self._fgt_key = 'Bearer ' + fgt_key
        try:
            misp_connection = PyMISP(self._misp_url, self._misp_key, self._misp_verifycert, 'json')
        except:
            misp_connection = False

        if misp_connection:
            self._misp_connection = misp_connection
            self._connected = True
        else:
            self._misp_connection = None
            self._connected = False

    def get_misp_iocs(self):
        if not self._connected:
            raise self.exceptions(AttributeError, 'No MISP connection. Please recreate the object.')
        else:
            iocs_to_fw = self._misp_connection.search(controller='attributes', tags=self._misp_fgt_tag)
            iocs_to_fw = iocs_to_fw['Attribute']

            iocs = []
            d = {}
            for attribute in iocs_to_fw:
                d['event_id'] = attribute['event_id']

                for k, v in attribute.items():
                    if k == 'Event':
                        d['event_info'] = str(v['info'])

                d['attr_id'] = attribute['id']
                d['type'] = attribute['type']
                d['value'] = str(attribute['value'])
                iocs.append(d)
        return iocs

    def exceptions(exception, message):
        return exception(message)

    def push_iocs_to_fgt(self, iocs: list):

        base_grp_name = 'misp-ioc-'
        address_group_ip = base_grp_name + 'ip'
        address_group_domain = base_grp_name + 'domain'

        addr_objs = []

        for ioc in iocs:
            d = {
                'name': ioc['value'],
                'color': ioc['6'],
                'comment': ioc['event_info']
            }

            if 'ip' in ioc['type']:
                d['subnet'] = ioc['value']

            elif ioc['type'] == 'domain':
                d['type'] = 'fqdn'
                d['fqdn'] = ioc['value']

            else:
                continue

            addr_objs.append(d)

        addr_objs = json.dumps(addr_objs)
        self.create_addr_batch(addr_objs)

        addrgrp_names = self.get_addrgrp_names()

        if addrgrp_names[0] == 'Error':
            print('Error')
        else:
            ip_group_created = False
            domain_group_created = False
            for i in addrgrp_names:
                if address_group_ip == i:
                    ip_group_created = True
                elif address_group_domain == i:
                    domain_group_created = True

            # Create fortigate group addresses
            if not ip_group_created:
                # Testing with random members
                ip_list = ['ip1', 'ip2', 'ip3']
                try:
                    self.create_adrgrp(address_group_ip, ip_list)
                except:
                    print('Error')

            if not domain_group_created:
                # Testing with random members
                domain_list = ['domain1', 'domain2', 'domain3']
                try:
                    self.create_adrgrp(address_group_ip, domain_list)
                except:
                    print('Error')

        return None

    def get_addrgrp_names(self) -> list:

        fgt_url_addrgrp = self._fgt_url + '/api/v2/cmdb/firewall/addrgrp'

        headers = {
            'Authorization': str(self._fgt_key)
        }

        try:
            response = rq.get(fgt_url_addrgrp, headers=headers, verify=False)
        except:
            print('Error')
        finally:
            if response.status_code == 200:
                response = response.json()['results']
            else:
                response =['Error']

        if response[0] == 'Error':
            return response
        else:
            all_group_names = []
            for addrgrp in response:
                all_group_names.append(addrgrp['name'])

            return all_group_names

    def create_addrgrp(self, group_name: str, member_list: list) -> bool:

        fgt_url_addrgrp = self._fgt_url + '/api/v2/cmdb/firewall/addrgrp'

        group_name = 'misp-ioc-' + group_name

        headers = {
            'Authorization': str(self._fgt_key)
        }

        payload = {}

        try:
            payload['name'] = group_name
            payload['color'] = '6'
            payload['member'] = member_list
            payload = json.dumps(payload)
            create_response = rq.post(fgt_url_addrgrp, headers=headers, data=payload, verify=False)
        except:
            create_response = False
            return create_response

        create_response = True

        return create_response

    def create_addr_batch(self, addresses_objects: str) -> bool:

        fgt_url_addr = self._fgt_url + '/api/v2/cmdb/firewall/address'

        headers = {
            'Authorization': str(self._fgt_key)
        }

        try:
            response = rq.post(fgt_url_addr, headers=headers, data=addresses_objects, verify=False)
        except:
            response = False
        finally:
            if response.status_code == 200:
                response = True

        return response
