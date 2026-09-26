
import unittest

import subprocess

import json

import os



class TestMCPParser(unittest.TestCase):

    @classmethod

    def setUpClass(cls):

        cls.parser_path = os.path.join(os.path.dirname(__file__), "parser.py")



    def run_parser_with_events(self, events):

        proc = subprocess.Popen(

            ['python3', self.parser_path],

            stdin=subprocess.PIPE,

            stdout=subprocess.PIPE,

            stderr=subprocess.PIPE,

            text=True

        )

        raw_input = "\n".join([json.dumps(e) for e in events]) + "\n"

        stdout, stderr = proc.communicate(input=raw_input, timeout=5)

        lines = [line.strip() for line in stdout.strip().split('\n') if line.strip()]

        return lines, stderr



    def test_01_valid_single_call(self):

        """Verify normal HTTP POST wrapping a single MCP tool call."""

        http_payload = (

            "POST /mcp HTTP/1.1\r\n"

            "Host: 127.0.0.1\r\n"
            "Content-Length: 95\r\n\r\n"
            '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test"}}}'
        )
        event = {"conn_id": 101, "dir": "write", "data": http_payload, "ts_ns": 1000}
        lines, _ = self.run_parser_with_events([event])
        
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertEqual(parsed.get("tool_name"), "read_file")
        self.assertEqual(parsed.get("msg_type"), "request")
        self.assertEqual(parsed.get("conn_id"), 101)

    def test_02_fragmented_split_across_writes(self):
        """Verify stream reassembly when a payload is split across two SSL_write calls."""
        part1 = 'POST /mcp HTTP/1.1\r\n\r\n{"jsonrpc":"2.0","id":2,"method":"tools/'
        part2 = 'call","params":{"name":"split_tool","arguments":{"flag":true}}}'
        
        event1 = {"conn_id": 202, "dir": "write", "data": part1, "ts_ns": 2000}
        event2 = {"conn_id": 202,"dir": "write", "data": part2, "ts_ns": 2001}
        
        lines, _ = self.run_parser_with_events([event1, event2])
        self.assertEqual(len(lines), 1)
        parsed = json.loads(lines[0])
        self.assertEqual(parsed.get("tool_name"), "split_tool")
        self.assertEqual(parsed.get("msg_type"), "request")

    def test_03_batched_messages_in_single_packet(self):
        """Verify extraction of multiple back-to-back JSON-RPC objects in one packet."""
        mcp1 = '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"tool_one"}}'
        mcp2 = '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"tool_two"}}'
        batched_data = f"POST /mcp HTTP/1.1\r\n\r\n{mcp1}{mcp2}"
        
        event = {"conn_id": 303, "dir": "write", "data": batched_data, "ts_ns": 3000}
        lines, _ = self.run_parser_with_events([event])
        
        self.assertEqual(len(lines), 2)
        tools = [json.loads(line).get("tool_name") for line in lines]
        self.assertIn("tool_one", tools)
        self.assertIn("tool_two", tools)

    def test_04_malformed_and_non_mcp_traffic(self):
        """Verify truncated JSON and plain non-JSON traffic are skipped without crashing."""
        malformed = {"conn_id": 404, "dir": "write", "data": 'POST /mcp\r\n\r\n{"jsonrpc": "broken', "ts_ns": 4000}
        plain_http = {"conn_id": 505, "dir": "write", "data": "GET /health HTTP/1.1\r\n\r\n", "ts_ns": 5000}
        
        lines, _ = self.run_parser_with_events([malformed, plain_http])
        self.assertEqual(len(lines), 0)

if __name__ == '__main__':
    unittest.main(verbosity=2)
