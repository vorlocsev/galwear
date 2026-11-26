"""Strict non-executing configuration syntax candidates."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_tzlite_config_review import nsswitch, hosts, resolv, sensor_xml


class ConfigReviewTests(unittest.TestCase):
    def test_nss(self):
        self.assertEqual(nsswitch(b"passwd: files\ngroup: files\nhosts: files dns\n")["provider_candidates"],["dns","files"])

    def test_nss_unknown_and_duplicate(self):
        for raw in (b"passwd: files\ngroup: files\nhosts: mdns\n",
                    b"passwd: files\ngroup: files\nhosts: files [NOTFOUND=return] dns\n",
                    b"passwd: files\npasswd: files\ngroup: files\nhosts: files\n"):
            with self.assertRaises(ValueError):
                nsswitch(raw)

    def test_hosts(self):
        self.assertEqual(hosts(b"127.0.0.1 localhost\n::1 localhost\n")["record_count"],2)

    def test_hosts_invalid(self):
        for raw in (b"noip localhost",b"127.0.0.1 bad..name",b"127.0.0.1 bad\0name"):
            with self.assertRaises(ValueError):
                hosts(raw)

    def test_resolv(self):
        self.assertEqual(resolv(b"nameserver 192.0.2.1\nsearch example.test\n")["nameserver_count"],1)

    def test_resolv_unknown(self):
        for raw in (b"nameserver 192.0.2.1\ninclude /etc/other",
                    b"nameserver 192.0.2.1\nsearch example.test\ndomain example.test",
                    b"nameserver invalid"):
            with self.assertRaises(ValueError):
                resolv(raw)

    def test_xml(self):
        self.assertEqual(sensor_xml(b"<sensor><fixture/></sensor>")["element_count"],2)

    def test_xml_entities(self):
        with self.assertRaises(ValueError):
            sensor_xml(b'<!DOCTYPE x [<!ENTITY e "fixture">]><x>&e;</x>')

    def test_xml_depth(self):
        with self.assertRaises(ValueError):
            sensor_xml(b"<x>"*34+b"</x>"*34)


if __name__=="__main__":
    unittest.main()
