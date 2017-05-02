<h3>Project description</h3>

Yet Another Nessus Parser (YANP) is a parser ables to extract information from Tenable Nessus's .nessus file format. The main tool's objective is to export vulnerability assessment reports in a parsable way. The user is able to choose an appropriate  output format in order to save the Nessus' reports following various advanced needs.

YANP supports all latest features introduced by Nessus v5 release.

<h3>Features</h3>

In order to help penetration testers, the following features are supported:

Parse multiple .nessus file and output a single report.
Print results in .org format. (for Emacs enthusiasts)
Save results into csv report using a custom delimiter string.
Filter vulnerabilities based on local assessment.
Filter vulnerabilities from minimum CVSS.
Filter vulnerabilities up to maximum CVSS.
Print only a list of targets parsed (IPs and hostnames).
Print advanced statistics about parsed reports.
Print a list of targets vulnerable at specified Nessus PluginID.
Print a list of targets vulnerable at specified Nessus Plugin name.
Print parsed information in raw mode (for advanced purposes).

<h3>Dependencies</h3>

Python netaddr

Python ArgumentParser

Python Minidom

<h3>About</h3>

Developed by Alessandro Di Pinto
