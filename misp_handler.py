#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import ExpandedPyMISP, PyMISP
from keys import misp_url, misp_key, misp_verifycert
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


    def get_misp_fw_tag_index(self):
        response = self._misp_connection.search_index(tag = self._misp_fgt_tag)
        test = self._misp_connection.assertEqual(response['response'], self.search_index_result)
        return test

    def init(url, key):
        return PyMISP(url, key, misp_verifycert, 'json')


    def search_events(m, quiet, url, controller, out=None, **kwargs):
        result = m.search(controller, **kwargs)
        if quiet:
            for e in result['response']:
                print('{}{}{}\n'.format(url, '/events/view/', e['Event']['id']))
        elif out is None:
            print(json.dumps(result['response']))
        else:
            with open(out, 'w') as f:
                f.write(json.dumps(result['response']))


    def search_attrs(m, quiet, url, out=None, custom_type_attribute="yara"):
        controller = 'attributes'
        result = m.search(controller, type_attribute=custom_type_attribute)
        if quiet:
            for e in result['response']:
                print('{}{}{}\n'.format(url, '/events/view/', e['Event']['id']))
        elif out is None:
            print(json.dumps(result['response']))
        else:
            with open(out, 'w') as f:
                f.write(json.dumps(result['response']))


    def get_tags(m):
        result = m.get_all_tags(True)
        r = result
        print(json.dumps(r) + '\n')

