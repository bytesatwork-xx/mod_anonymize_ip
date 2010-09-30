================
mod_anonymize_ip
================

:Author: `Benedikt Böhm <bb@xnull.de>`_
:Version: 0.3.1
:Web: http://github.com/hollow/mod_anonymize_ip
:Git: ``git clone https://github.com/hollow/mod_anonymize_ip.git``
:Download: http://github.com/hollow/mod_anonymize_ip/downloads

mod_anonymize_ip is a simple apache module that implements bit masking for
anonymizing the client IP address.

Installation
============

To compile and install this module, use ``apxs`` provided by the apache
webserver:
::

  apxs -i -a -c mod_anonymize_ip.c

Configuration
=============

In your virtual host and/or directory configuration add ithe following
directive:

AnonymizeIP <length>
  Mask <length> bits of the client IP address

AnonymizeIPException <uri>
  Add an exception (i.e. do not anonymize IP) for the given URI. can be used
  multiple times.

Bugs
====

Currently there is no possibility to exclude certain IPs from anonymization,
which will render mod_authz_host useless in most cases.
