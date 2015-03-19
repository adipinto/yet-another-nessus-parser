# Project description #
Yet Another Nessus Parser (YANP) is a parser to extract information from .nessus file format, used by Tenable Nessus, in order to export vulnerability assessment reports. This kind of file format is simply a custom XML that encloses information about one or more scan's results. Main purpose of YANP is to allow a penetration testers to transform XML reports into many customized output formats.
In fact, after an automatic XML parsing stage, it's possible to choose an appropriate supported output in order to save reports following various advanced needs.

_YANP supports all latest features introduced by Nessus v5 release._

# Features #
In order to help penetration testers, following main features are supported:
  * Parse multiple .nessus file and output a single report.
  * Print results in .org format. (for Emacs enthusiast)
  * Save results into csv report using a custom delimiter string.
  * Filter vulnerabilities based on local assessment.
  * Filter vulnerabilities from minimum CVSS.
  * Filter vulnerabilities up to maximum CVSS.
  * Print only a list of targets parsed (IPs and hostnames).
  * Print advanced statistics about parsed reports.
  * Print a list of targets vulnerable at specified Nessus PluginID.
  * Print a list of targets vulnerable at specified Nessus Plugin name.
  * Print parsed information in raw mode (for advanced purposes).

# Dependencies #
YANP is written in pure Python language and it's optimized to parse XML files through xml.minidom library. In order to manage command line, parse data structures and parse XML files, application needs following library:
  * Python netaddr
  * Python ArgumentParser
  * Python Minidom

# About #
Developed by Alessandro Di Pinto