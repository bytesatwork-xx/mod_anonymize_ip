================
mod_anonymize_ip
================

:Author: `Benedikt Böhm <bb@xnull.de>`_
:Version: 0.2
:Web: http://bb.xnull.de/projects/mod_anonymize_ip/
:Source: http://git.xnull.de/gitweb/?p=mod_anonymize_ip.git
:Download: http://bb.xnull.de/projects/mod_anonymize_ip/dist/

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

Bugs
====

Currently there is no possibility to exclude certain IPs from anonymization,
which will render mod_authz_host useless in most cases.
