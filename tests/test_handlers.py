import unittest

import dns_iot.dns_iot
from dns_iot.dns_iot import ZMQHandler

# pylint: disable=logging-fstring-interpolation,broad-exception-caught


class TestHandleModifiers(unittest.TestCase):
    """
    Test Class handle modifiers
    """

    @classmethod
    def setUpClass(cls):
        """
        Setup class, init globals and class
        """
        cls.zmq_server = ZMQHandler()
        dns_iot.dns_iot.BASE_DOMAIN = "my.test.comain"
        dns_iot.dns_iot.CONFIG_SUBDOMAINS = []
        dns_iot.dns_iot.CONFIG_TXT_RECORDS = []

    def test_modify_subdomain(self):
        """
        Test adding and removing sub domains
        """
        my_list = []
        subdomain1 = "xxx"
        nxdomain = f"{subdomain1}.{dns_iot.dns_iot.BASE_DOMAIN}"
        self.zmq_server.handle_a_modif(f"{nxdomain}:+:")
        self.assertEqual(f"{dns_iot.dns_iot.CONFIG_SUBDOMAINS[0]}", subdomain1)
        my_list.append(subdomain1)
        subdomain2 = "yyy"
        nxdomain = f"{subdomain2}.{dns_iot.dns_iot.BASE_DOMAIN}"
        self.zmq_server.handle_a_modif(f"{nxdomain}:+:")
        my_list.append(subdomain2)
        self.assertListEqual(my_list, dns_iot.dns_iot.CONFIG_SUBDOMAINS)
        # remove subdomain2
        self.zmq_server.handle_a_modif(f"{nxdomain}:-:")
        my_list.remove(subdomain2)
        self.assertListEqual(my_list, dns_iot.dns_iot.CONFIG_SUBDOMAINS)
        # add subdomain 2 again
        self.zmq_server.handle_a_modif(f"{nxdomain}:+:")
        my_list.append(subdomain2)
        self.assertListEqual(my_list, dns_iot.dns_iot.CONFIG_SUBDOMAINS)
        # delete *
        nxdomain = f"*.{dns_iot.dns_iot.BASE_DOMAIN}"
        self.zmq_server.handle_a_modif(f"{nxdomain}:-:")
        self.assertListEqual([], dns_iot.dns_iot.CONFIG_SUBDOMAINS)

    def test_modify_txt_records(self):
        """
        Test adding and removing txt records
        """


if __name__ == "__main__":
    unittest.main(verbosity=1)
