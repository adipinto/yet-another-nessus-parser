#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Copyright notice
================

Copyright (C) 2012
     Alessandro Di Pinto             <alessandro.dipinto@security.dico.unimi.it>

 This program is free software: you can redistribute it and/or modify it under
 the terms of the GNU General Public License as published by the Free Software
 Foundation, either version 3 of the License, or (at your option) any later
 version.

 Yet Another Nessus Parser (YANP) is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

 You should have received a copy of the GNU General Public License along with
 this program. If not, see <http://www.gnu.org/licenses/>.
"""

from argparse import ArgumentParser
from xml.dom.minidom import parse
from xml.dom import Node
from pprint import pprint
from os.path import isdir, exists, basename
from os import walk
from netaddr import IPSet
import csv


# Software version
PROG_VER    =    "1.0"
PROG_NAME   =    "Yet Another Nessus Parser (YANP)"

class nessus_parser:
    """
    Parser to perform information extraction from .nessus files format.
    """
    
    """
    Data structure to store parsed information (IP):

    _results = {
       IP_1: [ info, vuln_1, ... , vuln_N ]
       ...
       IP_N: ...
    }

    info = {
        scan_start:        'start time of specific scan'
        scan_stop:         'end time of specific scan'
        os:                'operating system version detected'
        hostname:          'hostname'
        netbios_name:      'netbios name'
        mac_address:       'MAC address'
    }

    vuln = {
        plugin_name:       'nessus plugin name'
        plugin_id:         'nessus plugin ID'
        plugin_type:       'local, remote, combined'
        port:              'port'
        protocol:          'protocol'
        description:       'description'
        solution:          'suggested solution'
        service_name       'generic service name'
        cvss_base_score:   'CVSS score to format X.Y'
        cvss_vector:       'CVSS vector'
        exploit_available: 'true o false'
        metasploit:        'true o false'
        cve:               'CVE, if it exists'
    }
    """
    _results         =    None
    _statistics      =    None
    _DEBUG           =    False
    _filter_cvss     =    ''
    _filter_ip       =    ''
    _xml_source      =    ''
    # Max CVSS score for low vulns
    _CVSS_LOW        =    3.9
    # Min CVSS score for high vulns
    _CVSS_HIGH       =    7.0
    # Plugin Types
    _LOCAL           =    'local'
    _REMOTE          =    'remote'
    _COMBINED        =    'combined'

    # Blacklist Nessus Plugin ID
    _blacklist = [
        "11154", # Unknown Service Detection
        "19506", # Nessus Scan Information
        "45590", # Common Platform Enumeration
        "56468", # Time of Last System Startup
        "57033", # Microsoft Patch Bulletin Feasibility Check
    ]
    # Vulnerabilities filtered by blacklist
    _blacklist_hit = 0
    
    def __init__(self, filename_xml):
        if filename_xml == None or filename_xml == "":
            print "[!] No filename specified!"
            exit(1)
 
        # Parse input values in order to find valid .nessus files
        self._xml_source = []
        if isdir(filename_xml):
            if not filename_xml.endswith("/"):
                filename_xml += "/"
            # Automatic searching of files into specified directory
            for path, dirs, files in walk(filename_xml):
                for f in files:
                    if f.endswith(".nessus"):
                        self._xml_source.append(filename_xml + f)
                break
        elif filename_xml.endswith(".nessus"):
            if not exists(filename_xml):
                print "[!] File specified '%s' not exist!" % filename_xml
                exit(3)
            self._xml_source.append(filename_xml)

        if not self._xml_source:
            print "[!] No file .nessus to parse was found!"
            exit(3)

        # Dictionary to store information
        self._results = {}
        
        # For each .nessus file found...
        for report in self._xml_source:
            # Parse and extract information
            self._parse_results(report)


    def _parse_results(self, file_report):
        
        # Automatic parse of .nessus file
        dom = parse(file_report)
        
        # For each host in report file, it extracts information
        for host in dom.getElementsByTagName('ReportHost'):
            # Get IP address
            ip = host.getAttribute('name')
            if ip == "":
                continue # Error getting IP address, skip!
            else:
                self._results[ip] = []
                
            # Parse information of selected node
            for item in host.childNodes:        
                if item.nodeName == 'HostProperties':
                    item_info = {
                        'scan_start':   '',
                        'scan_stop':    '',
                        'os':           '',
                        'hostname':     '',
                        'netbios_name': '',
                        'mac_address':  '',
                    }
                    for properties in item.childNodes:
                        if properties.attributes is None: continue
                        
                        # Extract generic information
                        if properties.getAttribute('name') == 'HOST_START':
                            item_info['scan_start'] = properties.childNodes[0].nodeValue
                            
                        if properties.getAttribute('name') == 'HOST_END':
                            item_info['scan_stop'] = properties.childNodes[0].nodeValue
                            
                        if properties.getAttribute('name') == 'operating-system':
                            item_info['os'] = properties.childNodes[0].nodeValue
                            
                        if properties.getAttribute('name') == 'host-fqdn':
                            item_info['hostname'] = properties.childNodes[0].nodeValue
                            
                        if properties.getAttribute('name') == 'netbios-name':
                            item_info['netbios_name'] = properties.childNodes[0].nodeValue
                            
                        if properties.getAttribute('name') == 'mac-address':
                            item_info['mac_address'] = properties.childNodes[0].nodeValue
                            
                    # Add information extracted to data structure
                    self._results[ip].append(item_info)
                                                      
                # Information extraction
                if item.nodeName == 'ReportItem':
                    if item.attributes is None: continue
                    
                    # Skip specific vulnerability if it is into a blacklist
                    if item.getAttribute('pluginID') in self._blacklist:
                        self._blacklist_hit += 1
                        continue
                    
                    vuln = {
                        'plugin_name':       '',
                        'plugin_id':         '',
                        'plugin_type':       '',
                        'port':              '',
                        'protocol':          '',
                        'description':       '',
                        'solution':          '',
                        'service_name':      '',
                        'cvss_base_score':   '0.0',
                        'cvss_vector':       '',
                        'exploit_available': '',
                        'metasploit':        '',
                        'cve':               '',
                        }

                    # Extract generic vulnerability information
                    vuln['plugin_name'] = item.getAttribute('pluginName')
                    vuln['plugin_id'] = item.getAttribute('pluginID')
                    vuln['port'] = item.getAttribute('port')
                    vuln['protocol'] = item.getAttribute('protocol')
                    vuln['description'] = item.getAttribute('description')
                    vuln['service_name'] = item.getAttribute('svc_name')

                    # No another information about vulnerability, continue!
                    if len(item.childNodes) == 0: continue
                    
                    # Extract detailed vulnerability information
                    for details in item.childNodes:
                        if details.nodeName == 'description':
                            vuln['description'] = details.childNodes[0].nodeValue
                            
                        if details.nodeName == 'solution':
                            vuln['solution'] = details.childNodes[0].nodeValue

                        if details.nodeName == 'plugin_type':
                            vuln['plugin_type'] = details.childNodes[0].nodeValue
                            
                        if details.nodeName == 'cvss_base_score':
                            vuln['cvss_base_score'] = details.childNodes[0].nodeValue
                            
                        if details.nodeName == 'cvss_vector':
                            vuln['cvss_vector'] = details.childNodes[0].nodeValue

                        if details.nodeName == 'exploitability_ease' or details.nodeName == 'exploit_available':
                            if details.childNodes[0].nodeValue.find('true') >= 0 or details.childNodes[0].nodeValue.find('Exploits are available') >= 0:
                                vuln['exploit_available'] = 'true'
                            else:
                                vuln['exploit_available'] = 'false'

                        if details.nodeName == 'exploit_framework_metasploit':
                            if details.childNodes[0].nodeValue.find('true') >= 0:
                                vuln['metasploit'] = 'true'
                                vuln['exploit_available'] = 'true'
                            else:
                                vuln['metasploit'] = 'false'
                            
                        if details.nodeName == 'cve':
                            vuln['cve'] = details.childNodes[0].nodeValue

                    # Store information extracted
                    self._results[ip].append(vuln)
                    
                # End 'ReportItem'
            # End node parsing
            
        # Release open resource
        self._close(dom)
            
    def _close(self, dom):
        if dom:
            dom.unlink()
            
    def print_raw(self):
        """
        Print information extracted in raw format to standard output
        """
        if self._results:
            pprint(self._results)
        else:
            print "[!] No information available."

    def find_by_pluginid(self, pluginid):
        """
        Search information by Nessus Plugin ID
        """
        if len(pluginid) != 5 or not pluginid.isdigit():
            print "[!] PluginID format error."
            exit(4)
        
        for host in IPSet(self._results.keys()):
            host = str(host) # From IPAddress to string
            for vuln in self._results[host][1:]:
                
                if vuln['plugin_id'] == pluginid:
                    print "%s:%s %s" % (host, vuln['port'], self._results[host][0]['hostname'])

    def find_by_plugin_name(self, plugin_descr):
        """
        Search information by Nessus Plugin name
        """
        plugin_descr = plugin_descr.lower()
        for host in IPSet(self._results.keys()):
            host = str(host) # From IPAddress to string
            for vuln in self._results[host][1:]:
                if vuln['plugin_name'].lower().find(plugin_descr) >= 0:
                    print "%s:%s [ID %s] %s" % (host, vuln['port'], vuln['plugin_id'], vuln['plugin_name'])

    def print_statistics(self):
        """
        Print statistics about parsed reports
        """
        vuln_low        =   0
        vuln_med        =   0
        vuln_high       =   0
        vuln_info       =   0
        vuln_local      =   0
        vuln_local_uniq =   []
        vuln_low_uniq   =   []
        vuln_med_uniq   =   []
        vuln_high_uniq  =   []
        vuln_info_uniq  =   []
        exploits        =   0
        exploits_uniq   =   []

        targets = {}

        for host in self._results.keys():
            targets[host] = {
                'vuln_low'          : 0,
                'vuln_med'          : 0,
                'vuln_high'         : 0,
                'vuln_info'         : 0,
                'vuln_local'        : 0,
                'vuln_local_uniq'   : [],
                'vuln_low_uniq'     : [],
                'vuln_med_uniq'     : [],
                'vuln_high_uniq'    : [],
                'vuln_info_uniq'    : [],
                'exploits'          : 0,
                'exploits_uniq'     : [],
                }
            for vuln in self._results[host][1:]:
                # Check for CVSS score
                cvss = float(vuln['cvss_base_score'])
                if cvss <= 3.9:
                    if cvss == 0:
                        vuln_info += 1
                        targets[host]['vuln_info'] += 1
                        # Add uniq vuln (global)
                        if vuln['plugin_id'] not in vuln_info_uniq:
                            vuln_info_uniq.append(vuln['plugin_id'])
                        # Add uniq vuln (host)
                        if vuln['plugin_id'] not in targets[host]['vuln_info_uniq']:
                            targets[host]['vuln_info_uniq'].append(vuln['plugin_id'])
                    else:
                        vuln_low += 1
                        targets[host]['vuln_low'] += 1
                        # Add uniq vuln (global)
                        if vuln['plugin_id'] not in vuln_low_uniq:
                            vuln_low_uniq.append(vuln['plugin_id'])
                        # Add uniq vuln (host)
                        if vuln['plugin_id'] not in targets[host]['vuln_low_uniq']:
                            targets[host]['vuln_low_uniq'].append(vuln['plugin_id'])
                elif cvss >= 7.0:
                    vuln_high += 1
                    targets[host]['vuln_high'] += 1
                    # Add uniq vuln (global)
                    if vuln['plugin_id'] not in vuln_high_uniq:
                        vuln_high_uniq.append(vuln['plugin_id'])
                    # Add uniq vuln (host)
                    if vuln['plugin_id'] not in targets[host]['vuln_high_uniq']:
                        targets[host]['vuln_high_uniq'].append(vuln['plugin_id'])
                else:
                    vuln_med += 1
                    targets[host]['vuln_med'] += 1
                    # Add uniq vuln (global)
                    if vuln['plugin_id'] not in vuln_med_uniq:
                        vuln_med_uniq.append(vuln['plugin_id'])
                    # Add uniq vuln (host)
                    if vuln['plugin_id'] not in targets[host]['vuln_med_uniq']:
                        targets[host]['vuln_med_uniq'].append(vuln['plugin_id'])
                # Check local assessment vulnerabilities
                if vuln['plugin_type'] == self._LOCAL:
                    vuln_local += 1
                    # Add uniq local vulnerability (global)
                    if vuln['plugin_id'] not in vuln_local_uniq:
                        vuln_local_uniq.append(vuln['plugin_id'])
                    # Add uniq local vulnerability (host)
                    targets[host]['vuln_local'] += 1
                    if vuln['plugin_id'] not in targets[host]['vuln_local_uniq']:
                        targets[host]['vuln_local_uniq'].append(vuln['plugin_id'])
                # Check for public exploit availability
                if vuln['exploit_available'].find("true") >= 0 or vuln['metasploit'].find("true") >=0:
                    exploits += 1
                    # Add uniq exploit (global)
                    if vuln['plugin_id'] not in exploits_uniq:
                        exploits_uniq.append(vuln['plugin_id'])
                    # Add uniq exploit (host)
                    targets[host]['exploits'] += 1
                    if vuln['plugin_id'] not in targets[host]['exploits_uniq']:
                        targets[host]['exploits_uniq'].append(vuln['plugin_id'])
        
        print ""
        print "#" * 8 + "  STATISTICS  " + "#" * 8
        print ""
        print "Total targets:\t\t%d" % len(self._results.keys())
        print "Total vulns:\t\t%d\t[  unique:   %4d  ]" % ((vuln_high + vuln_med + vuln_low + vuln_info), len(vuln_high_uniq) \
                                                     + len(vuln_med_uniq) + len(vuln_low_uniq) + len(vuln_info_uniq))
        print "High vulns: \t\t%d\t[  unique: %6d  ]" % (vuln_high, len(vuln_high_uniq))
        print "Medium vulns\t\t%d\t[  unique: %6d  ]" % (vuln_med, len(vuln_med_uniq))
        print "Low vulns:\t\t%d\t[  unique: %6d  ]" % (vuln_low, len(vuln_low_uniq))
        print "Info vulns:\t\t%d\t[  unique: %6d  ]" % (vuln_info, len(vuln_info_uniq))
        print "Local vulns:\t\t%d\t[  unique: %6d  ]" % (vuln_local, len(vuln_local_uniq))
        print "Available exploits:\t%d\t[  unique: %6d  ]" % (exploits, len(exploits_uniq))
        print "Blacklist's size:\t%d\t[  filtered: %4d  ]" % (len(self._blacklist), self._blacklist_hit)
        
        print ""
        print "#" * 8 + "    TARGETS   " + "#" * 8
        print ""
        for host in targets.keys():
            print "[*] %s" % host
            total_vulns = targets[host]['vuln_high'] + targets[host]['vuln_med'] + targets[host]['vuln_low'] + targets[host]['vuln_info']
            total_vulns_uniq = len(targets[host]['vuln_high_uniq']) + len(targets[host]['vuln_med_uniq']) + len(targets[host]['vuln_low_uniq']) \
                                                                + len(targets[host]['vuln_info_uniq'])
            print "\tTotal vulns: \t\t%d\t[  unique: %6d  ]" % (total_vulns, total_vulns_uniq)
            print "\t  [+] Local vulns:\t%d\t[  unique: %6d  ]" % (targets[host]['vuln_local'], len(targets[host]['vuln_local_uniq']))
            print "\t  [+] Remote vulns:\t%d\t[  unique: %6d  ]" % (total_vulns - targets[host]['vuln_local'], \
                                                                    total_vulns_uniq - len(targets[host]['vuln_local_uniq']))
            print "\tHigh vulns: \t\t%d\t[  unique: %6d  ]" % (targets[host]['vuln_high'], len(targets[host]['vuln_high_uniq']))
            print "\tMedium vulns\t\t%d\t[  unique: %6d  ]" % (targets[host]['vuln_med'], len(targets[host]['vuln_med_uniq']))
            print "\tLow vulns:\t\t%d\t[  unique: %6d  ]" % (targets[host]['vuln_low'], len(targets[host]['vuln_low_uniq']))
            print "\tInfo vulns:\t\t%d\t[  unique: %6d  ]" % (targets[host]['vuln_info'], len(targets[host]['vuln_info_uniq']))
            print "\tAvailable exploits:\t%d\t[  unique: %6d  ]" % (targets[host]['exploits'], len(targets[host]['exploits_uniq']))

            
    def print_targets(self, fullinfo=False, delim='|'):
        """
        Print targets present into parsed reports
        """
        for host in IPSet(self._results.keys()):
            host = str(host) # From IPAddress to string
            if fullinfo:
                print "%s%s%s%s%s%s%s%s%s%s%s%s%s" % (host, delim,
                                             self._results[host][0]['hostname'], delim,
                                             self._results[host][0]['netbios_name'], delim,
                                             self._results[host][0]['os'], delim,
                                             self._results[host][0]['scan_start'], delim,
                                             self._results[host][0]['scan_stop'], delim,
                                             self._results[host][0]['mac_address']
                                             )
            else:
                print "%s %s" % (host, self._results[host][0]['hostname'])

    def print_org_format(self, cvss_min='4.0', cvss_max='10.0'):
        """
        Print to standard output extracted information in '.org' format (Emacs)
        """
        
        # Print reports parsed
        print "* Nessus files parsed"
        for report in self._xml_source:
            print "\t%s" % report

        # Print scan's information
        print "* Parsing info"
        print "\tResults filtered by: %s" % cvss_min
        print "\tTotal targets analized: %s" % len(self._results.keys())
        
        # Print targets
        print "* Targets"
        for host in IPSet(self._results.keys()):
            print "\t%s" % str(host)
            
        print "* Results"
        for host in self._results.keys():
            print "** %s" % host
            # Print specific system's information
            print "\tScan started at: %s" % self._results[host][0]['scan_start']
            print "\tScan stopped at: %s" % self._results[host][0]['scan_stop']
            hostname = self._results[host][0]['hostname']
            if hostname is not '':
                print "\tHostname: %s" % hostname
            netbios = self._results[host][0]['netbios_name']
            if netbios is not '':
                print "\tNetbios Name: %s" % netbios
            os = self._results[host][0]['os']
            if os is not '':
                print "\tOperating System: %s" % os
            mac = self._results[host][0]['mac_address']
            if mac is not '':
                print "\tMAC: %s" % mac
            
            
            # Sort vulnerabilities by CVSS score
            for vuln in sorted(self._results[host][1:], key=lambda cvss: float(cvss['cvss_base_score']), reverse=True) :
                cvss = vuln['cvss_base_score']
                if cvss is not "":
                    # Apply CVSS filter
                    if float(cvss) >= float(cvss_min) and float(cvss) <= float(cvss_max):
                        # CVSS - Plugin name - Plugin ID
                        print "*** TODO [CVSS %04s][%s] %s [ID: %s]" % (cvss, vuln['service_name'], vuln['plugin_name'], vuln['plugin_id'])
                        # Port , Protocol
                        print "\tPort: %s/%s" % (vuln['port'], vuln['protocol'])

                        # Service name
                        # service = vuln['service_name']
                        # if service is not '':
                        #     print "\tService: %s" % service
                        
                        # Description
                        # print "\tDescription: %s" % vuln['description']

                        # Public exploits available
                        exploit = vuln['exploit_available']
                        metasploit = vuln['metasploit']
                        if exploit is 'true':
                            print "\tExploit available!"
                        if metasploit is 'true':
                            print "\tMetasploit module available!"

                        # CVSS Vector
                        cvss_vector = vuln['cvss_vector']
                        if cvss_vector is not '':
                            print "\tCVSS Vector %s" % cvss_vector.split("#")[1]

                        # CVE
                        cve = vuln['cve']
                        if cve is not '':
                            print "\tCVE %s" % cve
                            
    def save_csv_report(self, filename, cvss_min='4.0', cvss_max='10.0', only_local=False, delim=','):
        """
        Save extracted information into csv file format
        """
        counter_id = 1
        counter_vulns = 0
        counter_local = 0
        counter_remote = 0
        
        if not filename.endswith('.csv'):
            filename += '.csv'
        writer = csv.writer(open(filename, 'wb'), delimiter=delim)
        # Print CVS header
        writer.writerow([
            "ID",
            "IP",
            "HOSTNAME",
            "OPERATING SYSTEM",
            "PORT", "PROTOCOL",
            "VULNERABILITY NAME",
            "VULNERABILITY DESCRIPTION",
            "REMEDIATION",
            "CVSS SCORE",
            "CVSS VECTOR",
            "CVE"
        ])
        
        # Loop hosts
        for host in self._results.keys():
            info = []
            # ID
            info.append(counter_id)
            # IP
            info.append(host)
            # HOSTNAME
            info.append(self._results[host][0]['hostname'])
            # OS
            info.append(self._results[host][0]['os'])
            
            # Sort vulnerabilities by CVSS score
            for vuln in sorted(self._results[host][1:], key=lambda cvss: float(cvss['cvss_base_score']), reverse=True):
                info = info[0:4]
                cvss = vuln['cvss_base_score']
                if cvss is not "":
                    # Apply ONLY_LOCAL filter
                    if only_local == True and vuln['plugin_type'] != self._LOCAL:
                        continue
                    # Apply CVSS filter
                    if float(cvss) >= float(cvss_min) and float(cvss) <= float(cvss_max):
                        # Statistics
                        if vuln['plugin_type'] == self._LOCAL:
                            counter_local += 1
                        else:
                            counter_remote += 1
                        
                        # PORT
                        port = vuln['port']
                        if port == "0":
                            port = "---"
                        info.append(port)
                        # PROTOCOL
                        info.append(vuln['protocol'])
                        # VULN NAME
                        info.append(vuln['plugin_name'])
                        # VULN DESC
                        info.append(vuln['description'])
                        # REMEDIATION
                        info.append(vuln['solution'])
                        # CVSS SCORE
                        info.append(cvss)
                        # CVSS VECTOR (Remove 'CVSS#' preamble)
                        vector = vuln['cvss_vector']
                        if vector.find("#") != -1:
                            vector = vector.split("#")
                            if len(vector) > 1:
                                vector = vector[1]
                            else:
                                vector = vuln['cvss_vector']
                        info.append(vector)
                        # CVE
                        info.append(vuln['cve'])

                        writer.writerow([item.encode("utf-8") if isinstance(item, basestring) else item for item in info])
                        counter_vulns += 1
                        counter_id += 1
                        info[0] = counter_id

        # Print reports parsed
        print "[*] Information extracted from:"
        for report in self._xml_source:
            print "\t[+] %s" % basename(report)
            
        # Prints total vulns wrote
        print "[*] CSV delimiter used: \t\t'%s'" % delim
        print "[*] Total targets parsed: \t\t%d" % len(self._results.keys())
        print "[*] Min CVSS filter applied: \t\t%.1f" % float(cvss_min)
        print "[*] Max CVSS filter applied: \t\t%.1f" % float(cvss_max)
        print "[*] Local vulnerabilities: \t\t%d" % counter_local
        print "[*] Remote vulnerabilities:\t\t%d" % counter_remote
        print "[*] Total considered vulnerabilities: \t%d" % counter_vulns
        
# Entry point
if __name__ == "__main__":

    # Arguments parser
    cmdline = ArgumentParser(description="%s performs information extraction from .nessus files and creates a customized output. (Compatible with Nessus v5 release)" % PROG_NAME,
                             version=PROG_VER,
                             epilog="Developed by Alessandro Di Pinto  (alessandro.dipinto@security.dico.unimi.it)"
                             )
    cmdline.add_argument("-i",
                         metavar="[dir|.nessus]",
                         help="Report exported in .nessus format. If directory is specified, will be parsed all .nessus files found. (not recursive)",
                         required=True,
                         )
    cmdline.add_argument("--org",
                         action="store_true",
                         default=False,
                         help="Print results in .org format. CVSS filter will be applied.",
                         )
    cmdline.add_argument("--csv",
                         metavar="[filename]",
                         help="Save results into csv report. CVSS filter will be applied.",
                         )
    cmdline.add_argument("--delim",
                         metavar="[delim]",
                         help="Use custom delimiter value to split CSV information.",
                         default=',',
                         )
    cmdline.add_argument("--local",
                         action="store_true",
                         default=False,
                         help="Filter vulnerabilities only from local assessment. (applied in CSV report)",
                         )
    cmdline.add_argument("--min-cvss",
                         metavar="[min]",
                         default="4.0",
                         help="Filter vulnerabilities from minimum CVSS.",
                         )
    cmdline.add_argument("--max-cvss",
                         metavar="[max]",
                         default="10.0",
                         help="Filter vulnerabilities up to maximum CVSS.",
                         )
    cmdline.add_argument("-t",
                         action="store_true",
                         default=False,
                         help="Print a list of targets parsed.",
                         )
    cmdline.add_argument("-s",
                         action="store_true",
                         default=False,
                         help="Print statistics about parsed reports.",
                         )
    cmdline.add_argument("-p",
                         metavar="[PluginID]",
                         help="Print a list of targets vulnerable at specified Nessus PluginID",
                         )
    cmdline.add_argument("-d",
                         metavar="[PluginName]",
                         help="Print a list of targets vulnerable at specified Nessus Plugin name (case-insensitive)",
                         )
    cmdline.add_argument("--raw",
                         action="store_true",
                         default=False,
                         help="Print parsed information in raw mode (debug).",
                         )

    # Parse arguments provided
    args = cmdline.parse_args()
    
    # If not operation required, exit.
    if not args.org and not args.t and not args.raw and not args.p and not args.d and not args.s and not args.csv:
        print "[!] No operation specified!"
        print ""
        # Show help
        cmdline.print_help()
        exit(2)

    # Process command line
    parser = nessus_parser(args.i)

    # Search by Plugin ID
    if args.p:
        parser.find_by_pluginid(args.p)
    # Search by Plugin name
    if args.d:
        parser.find_by_plugin_name(args.d)
    # Print in .org format
    if args.org:
        parser.print_org_format(cvss_min=args.min_cvss, cvss_max=args.max_cvss)
    # Save into csv file
    if args.csv:
        parser.save_csv_report(args.csv, cvss_min=args.min_cvss, cvss_max=args.max_cvss, only_local=args.local, delim=args.delim)
    # Print targets
    if args.t:
        parser.print_targets()
    # Print statistics
    if args.s:
        parser.print_statistics()
    # Print in raw format
    if args.raw:
        parser.print_raw()

    # Exit successfully
    exit(0)
