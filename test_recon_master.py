"""Basic tests for ReconMaster. Run with: python -m unittest -v"""

import unittest

from recon_master import ReconMaster, parse_ports


class ParsePortsTests(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(parse_ports("443"), [443])

    def test_port_range(self):
        self.assertEqual(parse_ports("80-83"), [80, 81, 82, 83])

    def test_rejects_zero(self):
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_rejects_too_high(self):
        with self.assertRaises(ValueError):
            parse_ports("70000")

    def test_rejects_reversed_range(self):
        with self.assertRaises(ValueError):
            parse_ports("100-10")


class TargetTypeTests(unittest.TestCase):
    def test_detects_ipv4(self):
        self.assertTrue(ReconMaster("1.1.1.1")._is_ip_target())

    def test_detects_ipv6(self):
        self.assertTrue(ReconMaster("::1")._is_ip_target())

    def test_domain_is_not_ip(self):
        self.assertFalse(ReconMaster("example.com")._is_ip_target())

    def test_target_trailing_dot_stripped(self):
        self.assertEqual(ReconMaster("example.com.").target, "example.com")


class HeaderCandidateTests(unittest.TestCase):
    def test_falls_back_to_bare_host(self):
        recon = ReconMaster("example.com")
        self.assertEqual(
            recon._header_candidate_urls(),
            ["https://example.com", "http://example.com"],
        )

    def test_includes_non_standard_open_port(self):
        recon = ReconMaster("example.com")
        recon.results['open_ports'] = [{'port': 8099, 'service': 'unknown'}]
        urls = recon._header_candidate_urls()
        self.assertIn("https://example.com:8099", urls)
        self.assertIn("http://example.com:8099", urls)


class VulnerabilityTests(unittest.TestCase):
    def test_flags_sensitive_port(self):
        recon = ReconMaster("example.com")
        recon.results['open_ports'] = [{'port': 23, 'service': 'telnet'}]
        recon.check_vulnerabilities()
        types = [item['type'] for item in recon.results['vulnerabilities']]
        self.assertIn('Potentially Sensitive Service Exposed', types)

    def test_no_issue_for_common_web_port(self):
        recon = ReconMaster("example.com")
        recon.results['open_ports'] = [{'port': 443, 'service': 'https'}]
        recon.check_vulnerabilities()
        self.assertEqual(recon.results['vulnerabilities'], [])


if __name__ == "__main__":
    unittest.main()
