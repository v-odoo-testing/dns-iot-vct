"""
The `~certbot_dns_dnsiot.dns_dnsioy` plugin automates the process of
completing a ``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and
subsequently removing, TXT records using dnsiot Dynamic Updates.

.. note::
   The plugin is not installed by default. It can be installed by heading to
   `certbot.eff.org <https://certbot.eff.org/instructions#wildcard>`_, choosing your system and
   selecting the Wildcard tab.

Named Arguments
---------------

===================================== =====================================
``--config <file>``                   The config File
===================================== =====================================


Credentials
-----------

=> disabled, not needed, access is limited for 127.0.0.1
"""

from dns_iot import *
