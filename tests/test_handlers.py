import unittest
import dns_iot.dns_iot
from dns_iot.dns_iot import ZMQHandler


class TestHandleMethods(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.zmq_server = ZMQHandler()
        dns_iot.dns_iot.BASE_DOMAIN = (
            "my.test.comain"  # .globals()["BASE_DOMAIN"]='my.test.comain'
        )
        dns_iot.dns_iot.CONFIG_SUBDOMAINS = []

    def test_add_subdomain(self):
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
        self.zmq_server.handle_a_modif(f"{nxdomain}:-:")
        my_list.remove(subdomain2)
        self.assertListEqual(my_list, dns_iot.dns_iot.CONFIG_SUBDOMAINS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
