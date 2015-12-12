#!/usr/bin/python
# -*- coding: UTF-8 -*-
#
# Script for checking global health of host running VMware ESX/ESXi
#
# Licence : GNU General Public Licence (GPL) http://www.gnu.org/
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#
# Pre-req : pywbem3
#
# Copyright (c) 2008 David Ligeret
# Copyright (c) 2009 Joshua Daniel Franklin
# Copyright (c) 2010 Branden Schneider
# Copyright (c) 2010-2015 Claudio Kuenzler
# Copyright (c) 2010 Samir Ibradzic
# Copyright (c) 2010 Aaron Rogers
# Copyright (c) 2011 Ludovic Hutin
# Copyright (c) 2011 Carsten Schoene
# Copyright (c) 2011-2012 Phil Randal
# Copyright (c) 2011 Fredrik Aslund
# Copyright (c) 2011 Bertrand Jomin
# Copyright (c) 2011 Ian Chard
# Copyright (c) 2012 Craig Hart
# Copyright (c) 2013 Carl R. Friend
# Copyright (c) 2015 Andreas Gottwald
# Copyright (c) 2015 Stanislav German-Evtushenko
#
# The VMware 4.1 CIM API is documented here:
#   http://www.vmware.com/support/developer/cim-sdk/4.1/smash/cim_smash_410_prog.pdf
#   http://www.vmware.com/support/developer/cim-sdk/smash/u2/ga/apirefdoc/
#
# The VMware 5.x CIM API is documented here:
#   http://pubs.vmware.com/vsphere-50/index.jsp?nav=/5_1_1
#
# This Nagios plugin is maintained here:
#   http://www.claudiokuenzler.com/nagios-plugins/check_esxi_hardware.php
#

import sys
import time
import pywbem3
import re
import string
import pkg_resources
from optparse import OptionParser,OptionGroup

version = '20150710'

NS = 'root/cimv2'

# define classes to check 'OperationStatus' instance
ClassesToCheck = [
  'OMC_SMASHFirmwareIdentity',
  'CIM_Chassis',
  'CIM_Card',
  'CIM_ComputerSystem',
  'CIM_NumericSensor',
  'CIM_Memory',
  'CIM_Processor',
  'CIM_RecordLog',
  'OMC_DiscreteSensor',
  'OMC_Fan',
  'OMC_PowerSupply',
  'VMware_StorageExtent',
  'VMware_Controller',
  'VMware_StorageVolume',
  'VMware_Battery',
  'VMware_SASSATAPort'
]

sensor_Type = {
  0:'unknown',
  1:'Other',
  2:'Temperature',
  3:'Voltage',
  4:'Current',
  5:'Tachometer',
  6:'Counter',
  7:'Switch',
  8:'Lock',
  9:'Humidity',
  10:'Smoke Detection',
  11:'Presence',
  12:'Air Flow',
  13:'Power Consumption',
  14:'Power Production',
  15:'Pressure',
  16:'Intrusion',
  32768:'DMTF Reserved',
  65535:'Vendor Reserved'
}

data = []

perf_Prefix = {
  1:'Pow',
  2:'Vol',
  3:'Cur',
  4:'Tem',
  5:'Fan',
  6:'FanP'
}


# parameters

# host name
hostname=''

# user
user=''

# password
password=''

# vendor - possible values are 'unknown', 'auto', 'dell', 'hp', 'ibm', 'intel'
vendor='unknown'

# verbose
verbose=False

# Produce performance data output for nagios
perfdata=False

# timeout
timeout = 0

# elements to ignore (full SEL, broken BIOS, etc)
ignore_list=[]

# urlise model and tag numbers (currently only Dell supported, but the code does the right thing for other vendors)
urlise_country=''

# collect perfdata for each category
get_power   = True
get_volts   = True
get_current = True
get_temp    = True
get_fan     = True

# define exit codes
ExitOK = 0
ExitWarning = 1
ExitCritical = 2
ExitUnknown = 3

# Special handling for blade servers
isblade = "no"

def dell_country(country):
  if country == 'at':  # Austria
    return 'at/de/'
  if country == 'be':  # Belgium
    return 'be/nl/'
  if country == 'cz':  # Czech Republic
    return 'cz/cs/'
  if country == 'de':  # Germany
    return 'de/de/'
  if country == 'dk':  # Denmark
    return 'dk/da/'
  if country == 'es':  # Spain
    return 'es/es/'
  if country == 'fi':  # Finland
    return 'fi/fi/'
  if country == 'fr':  # France
    return 'fr/fr/'
  if country == 'gr':  # Greece
    return 'gr/en/'
  if country == 'it':  # Italy
    return 'it/it/'
  if country == 'il':  # Israel
    return 'il/en/'
  if country == 'me':  # Middle East
    return 'me/en/'
  if country == 'no':  # Norway
    return 'no/no/'
  if country == 'nl':  # The Netherlands
    return 'nl/nl/'
  if country == 'pl':  # Poland
    return 'pl/pl/'
  if country == 'pt':  # Portugal
    return 'pt/en/'
  if country == 'ru':  # Russia
    return 'ru/ru/'
  if country == 'se':  # Sweden
    return 'se/sv/'
  if country == 'uk':  # United Kingdom
    return 'uk/en/'
  if country == 'za':  # South Africa
    return 'za/en/'
  if country == 'br':  # Brazil
    return 'br/pt/'
  if country == 'ca':  # Canada
    return 'ca/en/'
  if country == 'mx':  # Mexico
    return 'mx/es/'
  if country == 'us':  # United States
    return 'us/en/'
  if country == 'au':  # Australia
    return 'au/en/'
  if country == 'cn':  # China
    return 'cn/zh/'
  if country == 'in':  # India
    return 'in/en/'
  # default
  return 'en/us/'

def urlised_server_info(vendor, country, server_info):
  #server_inf = server_info
  if vendor == 'dell' :
    # Dell support URLs (idea and tables borrowed from check_openmanage)
    du = 'http://www.dell.com/support/troubleshooting/' + dell_country(country) + '19/Product/poweredge-'
    if (server_info is not None) :
      p=re.match('(.*)PowerEdge (.*) (.*)',server_info)
      if (p is not None) :
        md=p.group(2)
        if md == 'R210 II':
          md='r210-2'
        md=md.lower()
        server_info = p.group(1) + '<a href="' + du + md + '#ui-tabs-4">PowerEdge ' + p.group(2)+'</a> ' + p.group(3)
  elif vendor == 'hp':
    return server_info
  elif vendor == 'ibm':
    return server_info
  elif vendor == 'intel':
    return server_info

  return server_info

# ----------------------------------------------------------------------

def system_tag_url(vendor,country):
  if vendor == 'dell':
    # Dell support sites
    supportsite = 'http://www.dell.com/support/troubleshooting/'
    dellsuffix = 'nodhs1/Index?t=warranty&servicetag='

    # warranty URLs for different country codes
    return supportsite + dell_country(country) + dellsuffix
  # elif vendor == 'hp':
  # elif vendor == 'ibm':
  # elif vendor == 'intel':

  return ''

# ----------------------------------------------------------------------

def urlised_serialnumber(vendor,country,SerialNumber):
  if SerialNumber is not None :
    tu = system_tag_url(vendor,country)
    if tu != '' :
      SerialNumber = '<a href="' + tu + SerialNumber + '">' + SerialNumber + '</a>'
  return SerialNumber

# ----------------------------------------------------------------------

def verboseoutput(message) :
  if verbose:
    print("%s %s" % (time.strftime("%Y%m%d %H:%M:%S"), message))

# ----------------------------------------------------------------------

def getopts() :
  global hosturl,user,password,vendor,verbose,perfdata,urlise_country,timeout,ignore_list,get_power,get_volts,get_current,get_temp,get_fan
  usage = "usage: %prog  https://hostname user password system [verbose]\n" \
    "example: %prog https://my-shiny-new-vmware-server root fakepassword dell\n\n" \
    "or, using new style options:\n\n" \
    "usage: %prog -H hostname -U username -P password [-V system -v -p -I XX]\n" \
    "example: %prog -H my-shiny-new-vmware-server -U root -P fakepassword -V auto -I uk\n\n" \
    "or, verbosely:\n\n" \
    "usage: %prog --host=hostname --user=username --pass=password [--vendor=system --verbose --perfdata --html=XX]\n"

  parser = OptionParser(usage=usage, version="%prog "+version)
  group1 = OptionGroup(parser, 'Mandatory parameters')
  group2 = OptionGroup(parser, 'Optional parameters')

  group1.add_option("-H", "--host", dest="host", help="report on HOST", metavar="HOST")
  group1.add_option("-U", "--user", dest="user", help="user to connect as", metavar="USER")
  group1.add_option("-P", "--pass", dest="password", \
      help="password, if password matches file:<path>, first line of given file will be used as password", metavar="PASS")

  group2.add_option("-V", "--vendor", dest="vendor", help="Vendor code: auto, dell, hp, ibm, intel, or unknown (default)", \
      metavar="VENDOR", type='choice', choices=['auto','dell','hp','ibm','intel','unknown'],default="unknown")
  group2.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, \
      help="print status messages to stdout (default is to be quiet)")
  group2.add_option("-p", "--perfdata", action="store_true", dest="perfdata", default=False, \
      help="collect performance data for pnp4nagios (default is not to)")
  group2.add_option("-I", "--html", dest="urlise_country", default="", \
      help="generate html links for country XX (default is not to)", metavar="XX")
  group2.add_option("-t", "--timeout", action="store", type="int", dest="timeout", default=0, \
      help="timeout in seconds - no effect on Windows (default = no timeout)")
  group2.add_option("-i", "--ignore", action="store", type="string", dest="ignore", default="", \
      help="comma-separated list of elements to ignore")
  group2.add_option("--no-power", action="store_false", dest="get_power", default=True, \
      help="don't collect power performance data")
  group2.add_option("--no-volts", action="store_false", dest="get_volts", default=True, \
      help="don't collect voltage performance data")
  group2.add_option("--no-current", action="store_false", dest="get_current", default=True, \
      help="don't collect current performance data")
  group2.add_option("--no-temp", action="store_false", dest="get_temp", default=True, \
      help="don't collect temperature performance data")
  group2.add_option("--no-fan", action="store_false", dest="get_fan", default=True, \
      help="don't collect fan performance data")

  parser.add_option_group(group1)
  parser.add_option_group(group2)

  # check input arguments
  if len(sys.argv) < 2:
    print("no parameters specified\n")
    parser.print_help()
    sys.exit(-1)
  # if first argument starts with 'https://' we have old-style parameters, so handle in old way
  if re.match("https://",sys.argv[1]):
    # check input arguments
    if len(sys.argv) < 5:
      print("too few parameters\n")
      parser.print_help()
      sys.exit(-1)
    if len(sys.argv) > 5 :
      if sys.argv[5] == "verbose" :
        verbose = True
    hosturl = sys.argv[1]
    user = sys.argv[2]
    password = sys.argv[3]
    vendor = sys.argv[4]
  else:
    # we're dealing with new-style parameters, so go get them!
    (options, args) = parser.parse_args()

    # Making sure all mandatory options appeared.
    mandatories = ['host', 'user', 'password']
    for m in mandatories:
      if not options.__dict__[m]:
        print("mandatory parameter '--" + m + "' is missing\n")
        parser.print_help()
        sys.exit(-1)

    hostname=options.host.lower()
    # if user has put "https://" in front of hostname out of habit, do the right thing
    # hosturl will end up as https://hostname
    if re.match('^https://',hostname):
      hosturl = hostname
    else:
      hosturl = 'https://' + hostname

    user=options.user
    password=options.password
    vendor=options.vendor.lower()
    verbose=options.verbose
    perfdata=options.perfdata
    urlise_country=options.urlise_country.lower()
    timeout=options.timeout
    ignore_list=options.ignore.split(',')
    get_power=options.get_power
    get_volts=options.get_volts
    get_current=options.get_current
    get_temp=options.get_temp
    get_fan=options.get_fan

  # if user or password starts with 'file:', use the first string in file as user, second as password
  if (re.match('^file:', user) or re.match('^file:', password)):
        if re.match('^file:', user):
          filextract = re.sub('^file:', '', user)
          filename = open(filextract, 'r')
          filetext = filename.readline().split()
          user = filetext[0]
          password = filetext[1]
          filename.close()
        elif re.match('^file:', password):
          filextract = re.sub('^file:', '', password)
          filename = open(filextract, 'r')
          filetext = filename.readline().split()
          password = filetext[0]
          filename.close()

# ----------------------------------------------------------------------

getopts()

# if running on Windows, don't use timeouts and signal.alarm
on_windows = True
os_platform = sys.platform
if os_platform != "win32":
  on_windows = False
  import signal
  def handler(signum, frame):
    print('UNKNOWN: Execution time too long!')
    sys.exit(ExitUnknown)

# connection to host
verboseoutput("Connection to "+hosturl)
wbemclient = pywbem3.WBEMConnection(hosturl, (user,password), NS, no_verification=True)

# Add a timeout for the script. When using with Nagios, the Nagios timeout cannot be < than plugin timeout.
if on_windows == False and timeout > 0:
  signal.signal(signal.SIGALRM, handler)
  signal.alarm(timeout)

# run the check for each defined class
GlobalStatus = ExitUnknown
server_info = ""
bios_info = ""
SerialNumber = ""
ExitMsg = ""

# if vendor is specified as 'auto', try to get vendor from CIM
# note: the default vendor is 'unknown'
if vendor=='auto':
  try:
    c=wbemclient.EnumerateInstances('CIM_Chassis')
  except pywbem3.cim_operations.CIMError as args:
    if ( args[1].find('Socket error') >= 0 ):
      print("UNKNOWN: %s" %args)
      sys.exit (ExitUnknown)
    else:
      verboseoutput("Unknown CIM Error: %s" % args)
  except pywbem3.cim_http.AuthError as arg:
    verboseoutput("Global exit set to UNKNOWN")
    GlobalStatus = ExitUnknown
    print("UNKNOWN: Authentication Error")
    sys.exit (GlobalStatus)
  else:
    man=c[0]['Manufacturer']
    if re.match("Dell",man):
      vendor="dell"
    elif re.match("HP",man):
      vendor="hp"
    elif re.match("IBM",man):
      vendor="ibm"
    elif re.match("Intel",man):
      vendor="intel"
    else:
      vendor='unknown'

for classe in ClassesToCheck :
  verboseoutput("Check classe "+classe)
  try:
    instance_list = wbemclient.EnumerateInstances(classe)
  except pywbem3.cim_operations.CIMError as args:
    if ( args[1].find('Socket error') >= 0 ):
      print("UNKNOWN: %s" %args)
      sys.exit (ExitUnknown)
    else:
      verboseoutput("Unknown CIM Error: %s" % args)
  except pywbem3.cim_http.AuthError as arg:
    verboseoutput("Global exit set to UNKNOWN")
    GlobalStatus = ExitUnknown
    print("UNKNOWN: Authentication Error")
    sys.exit (GlobalStatus)
  else:
    # GlobalStatus = ExitOK #ARR
    for instance in instance_list :
      sensor_value = ""
      elementName = instance['ElementName']
      if elementName is None :
        elementName = 'Unknown'
      elementNameValue = elementName
      verboseoutput("  Element Name = "+elementName)

      # Ignore element if we don't want it
      if elementName in ignore_list :
        verboseoutput("    (ignored)")
        continue

      # BIOS & Server info
      if elementName == 'System BIOS' :
        bios_info =     instance['Name'] + ': ' \
            + instance['VersionString'] + ' ' \
            + str(instance['ReleaseDate'].datetime.date())
        verboseoutput("    VersionString = "+instance['VersionString'])

      elif elementName == 'Chassis' :
        man = instance['Manufacturer']
        if man is None :
          man = 'Unknown Manufacturer'
        verboseoutput("    Manufacturer = "+man)
        SerialNumber = instance['SerialNumber']
        SerialChassis = instance['SerialNumber']
        if SerialNumber:
          verboseoutput("    SerialNumber = "+SerialNumber)
        server_info = man + ' '
        if vendor != 'intel':
          model = instance['Model']
          if model:
            verboseoutput("    Model = "+model)
            server_info +=  model + ' s/n:'

      elif elementName == 'Server Blade' :
        SerialNumber = instance['SerialNumber']
        if SerialNumber:
          verboseoutput("    SerialNumber = "+SerialNumber)
          isblade = "yes"

      # Report detail of Numeric Sensors and generate nagios perfdata

      if classe == "CIM_NumericSensor" :
        sensorType = instance['sensorType']
        sensStr = sensor_Type.get(sensorType,"Unknown")
        if sensorType:
          verboseoutput("    sensorType = %d - %s" % (sensorType,sensStr))
        units = instance['BaseUnits']
        if units:
          verboseoutput("    BaseUnits = %d" % units)
        # grab some of these values for Nagios performance data
        scale = 10**instance['UnitModifier']
        verboseoutput("    Scaled by = %f " % scale)
        cr = int(instance['CurrentReading'])*scale
        verboseoutput("    Current Reading = %f" % cr)
        elementNameValue = "%s: %g" % (elementName,cr)
        ltnc = 0
        utnc = 0
        ltc  = 0
        utc  = 0
        if instance['LowerThresholdNonCritical'] is not None:
          ltnc = instance['LowerThresholdNonCritical']*scale
          verboseoutput("    Lower Threshold Non Critical = %f" % ltnc)
        if instance['UpperThresholdNonCritical'] is not None:
          utnc = instance['UpperThresholdNonCritical']*scale
          verboseoutput("    Upper Threshold Non Critical = %f" % utnc)
        if instance['LowerThresholdCritical'] is not None:
          ltc = instance['LowerThresholdCritical']*scale
          verboseoutput("    Lower Threshold Critical = %f" % ltc)
        if instance['UpperThresholdCritical'] is not None:
          utc = instance['UpperThresholdCritical']*scale
          verboseoutput("    Upper Threshold Critical = %f" % utc)
        #
        if perfdata:
          perf_el = elementName.replace(' ','_')

          # Power and Current
          if sensorType == 4:               # Current or Power Consumption
            if units == 7:            # Watts
              if get_power:
                data.append( ("%s=%g;%g;%g " % (perf_el, cr, utnc, utc),1) )
            elif units == 6:          # Current
              if get_current:
                data.append( ("%s=%g;%g;%g " % (perf_el, cr, utnc, utc),3) )

          # PSU Voltage
          elif sensorType == 3:               # Voltage
            if get_volts:
              data.append( ("%s=%g;%g;%g " % (perf_el, cr, utnc, utc),2) )

          # Temperatures
          elif sensorType == 2:               # Temperature
            if get_temp:
              data.append( ("%s=%g;%g;%g " % (perf_el, cr, utnc, utc),4) )

          # Fan speeds
          elif sensorType == 5:               # Tachometer
            if get_fan:
              if units == 65:           # percentage
                data.append( ("%s=%g%%;%g;%g " % (perf_el, cr, utnc, utc),6) )
              else:
                data.append( ("%s=%g;%g;%g " % (perf_el, cr, utnc, utc),5) )

      elif classe == "CIM_Processor" :
        verboseoutput("    Family = %d" % instance['Family'])
        verboseoutput("    CurrentClockSpeed = %dMHz" % instance['CurrentClockSpeed'])


      # HP Check
      if vendor == "hp" :
        if instance['HealthState'] is not None :
          elementStatus = instance['HealthState']
          verboseoutput("    Element HealthState = %d" % elementStatus)
          interpretStatus = {
            0  : ExitOK,    # Unknown
            5  : ExitOK,    # OK
            10 : ExitWarning,  # Degraded
            15 : ExitWarning,  # Minor
            20 : ExitCritical,  # Major
            25 : ExitCritical,  # Critical
            30 : ExitCritical,  # Non-recoverable Error
          }[elementStatus]
          if (interpretStatus == ExitCritical) :
            verboseoutput("GLobal exit set to CRITICAL")
            GlobalStatus = ExitCritical
            ExitMsg += " CRITICAL : %s " % elementNameValue
          if (interpretStatus == ExitWarning and GlobalStatus != ExitCritical) :
            verboseoutput("GLobal exit set to WARNING")
            GlobalStatus = ExitWarning
            ExitMsg += " WARNING : %s " % elementNameValue
          # Added the following for when GlobalStatus is ExitCritical and a warning is detected
          # This way the ExitMsg gets added but GlobalStatus isn't changed
          if (interpretStatus == ExitWarning and GlobalStatus == ExitCritical) : # ARR
            ExitMsg += " WARNING : %s " % elementNameValue #ARR
          # Added the following so that GlobalStatus gets set to OK if there's no warning or critical
          if (interpretStatus == ExitOK and GlobalStatus != ExitWarning and GlobalStatus != ExitCritical) : #ARR
            GlobalStatus = ExitOK #ARR



      # Dell, Intel, IBM and unknown hardware check
      elif (vendor == "dell" or vendor == "intel" or vendor == "ibm" or vendor=="unknown") :
        # Added 20121027 As long as Dell doesnt correct these CIM elements return code we have to ignore it
        ignore_list.append("System Board 1 Riser Config Err 0: Connected")
        ignore_list.append("System Board 1 LCD Cable Pres 0: Connected")
        ignore_list.append("System Board 1 VGA Cable Pres 0: Connected")
        ignore_list.append("Add-in Card 4 PEM Presence 0: Connected")
        if instance['OperationalStatus'] is not None :
          elementStatus = instance['OperationalStatus'][0]
          verboseoutput("    Element Op Status = %d" % elementStatus)
          interpretStatus = {
            0  : ExitOK,            # Unknown
            1  : ExitCritical,      # Other
            2  : ExitOK,            # OK
            3  : ExitWarning,       # Degraded
            4  : ExitWarning,       # Stressed
            5  : ExitWarning,       # Predictive Failure
            6  : ExitCritical,      # Error
            7  : ExitCritical,      # Non-Recoverable Error
            8  : ExitWarning,       # Starting
            9  : ExitWarning,       # Stopping
            10 : ExitCritical,      # Stopped
            11 : ExitOK,            # In Service
            12 : ExitWarning,       # No Contact
            13 : ExitCritical,      # Lost Communication
            14 : ExitCritical,      # Aborted
            15 : ExitOK,            # Dormant
            16 : ExitCritical,      # Supporting Entity in Error
            17 : ExitOK,            # Completed
            18 : ExitOK,            # Power Mode
            19 : ExitOK,            # DMTF Reserved
            20 : ExitOK             # Vendor Reserved
          }[elementStatus]
          if (interpretStatus == ExitCritical) :
            verboseoutput("Global exit set to CRITICAL")
            GlobalStatus = ExitCritical
            ExitMsg += " CRITICAL : %s " % elementNameValue
          if (interpretStatus == ExitWarning and GlobalStatus != ExitCritical) :
            verboseoutput("GLobal exit set to WARNING")
            GlobalStatus = ExitWarning
            ExitMsg += " WARNING : %s " % elementNameValue
          # Added same logic as in 20100702 here, otherwise Dell servers would return UNKNOWN instead of OK
          if (interpretStatus == ExitWarning and GlobalStatus == ExitCritical) : # ARR
            ExitMsg += " WARNING : %s " % elementNameValue #ARR
          if (interpretStatus == ExitOK and GlobalStatus != ExitWarning and GlobalStatus != ExitCritical) : #ARR
            GlobalStatus = ExitOK #ARR
        if elementName == 'Server Blade' :
                if SerialNumber :
                        if SerialNumber.find(".") != -1 :
                                SerialNumber = SerialNumber.split('.')[1]


# Munge the ouptput to give links to documentation and warranty info
if (urlise_country != '') :
  SerialNumber = urlised_serialnumber(vendor,urlise_country,SerialNumber)
  server_info = urlised_server_info(vendor,urlise_country,server_info)

# If this is a blade server, also output chassis serial number as additional info
if (isblade == "yes") :
  SerialNumber += " Chassis S/N: %s " % (SerialChassis)

# Output performance data
perf = '|'
if perfdata:
  sdata=[]
  ctr=[0,0,0,0,0,0,0]
  # sort the data so we always get perfdata in the right order
  # we make no assumptions about the order in which CIM returns data
  # first sort by element name (effectively) and insert sequence numbers
  for p in sorted(data):
    p1 = p[1]
    sdata.append( ("P%d%s_%d_%s") % (p1,perf_Prefix[p1], ctr[p1], p[0]) )
    ctr[p1] += 1
  # then sort perfdata into groups and output perfdata string
  for p in sorted(sdata):
    perf += p

# sanitise perfdata - don't output "|" if nothing to report
if perf == '|':
  perf = ''

if GlobalStatus == ExitOK :
  print("OK - Server: %s %s %s%s" % (server_info, SerialNumber, bios_info, perf))

elif GlobalStatus == ExitUnknown :
  print("UNKNOWN: %s" % (ExitMsg)) #ARR

else:
  print("%s- Server: %s %s %s%s" % (ExitMsg, server_info, SerialNumber, bios_info, perf))

sys.exit (GlobalStatus)

