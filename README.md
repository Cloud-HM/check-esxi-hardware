check_esxi_hardware
=========

Monitoring plugin to check the hardware on VMware ESX/ESXi servers. It only works with Python 3.5+.

This is the public git repository for development of the plugin. 

Installation
-------------
Since this repo makes use of `git submodule`, when you check out with Git 1.6.5+, you will need to do a recursive clone like this:

`git clone --recursive https://github.com/cloud-hm/check_esxi_hardware`


How to run
-------------
It's a simple Python 3 script. Assuming that your ESXi: 

* Has a CIM-able user called `cimuser` 
* with a password of `temp123` 
* and your server's brand is `dell`
* and that the server's IP address is `10.0.1.82`

then you can just run:

`python check_esxi_hardware.py https://10.0.1.82 cimuser temp123 dell`


Documentation + Production Ready Plugin
-------------
Please refer to http://www.claudiokuenzler.com/nagios-plugins/check_esxi_hardware.php 
