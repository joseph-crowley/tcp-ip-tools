import unittest
from unittest.mock import patch, Mock
from tools import IPDNSDetailTool, PingTool, NsLookupTool

class TestIPDNSDetailTool(unittest.TestCase):
    @patch('socket.gethostbyname')
    @patch('socket.getfqdn')
    def test_execute(self, mock_getfqdn, mock_gethostbyname):
        mock_getfqdn.return_value = 'test.com'
        mock_gethostbyname.return_value = '1.1.1.1'
        tool = IPDNSDetailTool('test.com')
        result = tool.execute()
        self.assertEqual(result, 'IP: 1.1.1.1, Host: test.com')

class TestPingTool(unittest.TestCase):
    @patch('subprocess.Popen')
    def test_execute(self, mock_popen):
        process_mock = Mock()
        attrs = {'communicate.return_value': (b'PING output', b'')}
        process_mock.configure_mock(**attrs)
        mock_popen.return_value = process_mock
        tool = PingTool('test.com')
        result = tool.execute()
        self.assertEqual(result, 'PING output')

class TestNsLookupTool(unittest.TestCase):
    @patch('subprocess.Popen')
    def test_execute(self, mock_popen):
        process_mock = Mock()
        attrs = {'communicate.return_value': (b'nslookup output', b'')}
        process_mock.configure_mock(**attrs)
        mock_popen.return_value = process_mock
        tool = NsLookupTool('test.com')
        result = tool.execute()
        self.assertEqual(result, 'nslookup output')

if __name__ == '__main__':
    unittest.main()
