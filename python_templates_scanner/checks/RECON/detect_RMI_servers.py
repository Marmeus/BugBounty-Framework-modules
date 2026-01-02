import os
import json
import base64

from odin import OdinCheck, CheckResult, CheckTarget

import socket
import sys

from enum import Enum

class Check(OdinCheck):
    # Check metadata
    name = "detect_RMI_servers"
    severity = "High"
    description = "Detection of exposed Java RMI servers with class loader enabled"
    poc = None
    
    NOT_EXPOSED     = 0
    NOT_NEGOTIATION = 1
    NOT_VULN        = 2
    VULN            = 3
    
    def __init__(self, mode: str, target: CheckTarget):
        # keep this line
        super().__init__(mode, target)

        # put your additional initialization code here

    def check(self):        
        results = []
        
        vuln = self.do_check(self.target.ip, self.target.port)
        if vuln == self.VULN:
            results.append(self.create_result())
        
        return results
    
    def do_check(self, host, port) -> int:
        if not self.init_connection():
            return self.NOT_EXPOSED

        if not self.negotiate():
            return self.NOT_NEGOTIATION

        vuln = self.send_call()
        try:
            self.conn.close()
        except:
            pass

        if vuln:
            return self.VULN
        
        return self.NOT_VULN
    
    def init_connection(self) -> bool:
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            self.conn.connect((self.host, self.port))
        except:
            return False
        return True
    
    def negotiate(self) -> bool:
        msg = bytearray([
            0x4a, 0x52, 0x4d, 0x49,             # magic
            0x00, 0x02,                         # version
            0x4b,                               # protocol=StreamProtocol
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00  # pad?
        ])

        self.conn.sendall(msg, 0)

        _response = self.conn.recv(1024)
        response = bytearray(_response)

        if response[0] != 0x4e:                 # ProtocolAck
            return False
        
        hostname_len = response[1] * 255 + response[2]
        hostname = response[3 : 3 + hostname_len]
        _port = response[3 + hostname_len + 2 : 3 + hostname_len + 2 + 2]
        port = _port[0] * 256 + _port[1]

        return True
    
    def send_call(self) -> bool:
        msg = bytearray([
            0x50, # call
            # now comes a serialized java class, taken from metasploit's rmi check
            0xac, 0xed, 0x00, 0x05, 0x77, 0x22, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xf6, 0xb6, 0x89, 0x8d, 0x8b, 0xf2, 0x86, 0x43,
            0x75, 0x72, 0x00, 0x18, 0x5b, 0x4c, 0x6a, 0x61,
            0x76, 0x61, 0x2e, 0x72, 0x6d, 0x69, 0x2e, 0x73,
            0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x4f, 0x62,
            0x6a, 0x49, 0x44, 0x3b, 0x87, 0x13, 0x00, 0xb8,
            0xd0, 0x2c, 0x64, 0x7e, 0x02, 0x00, 0x00, 0x70,
            0x78, 0x70, 0x00, 0x00, 0x00, 0x00, 0x77, 0x08,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x73, 0x72, 0x00, 0x14, 0x6d, 0x65, 0x74, 0x61,
            0x73, 0x70, 0x6c, 0x6f, 0x69, 0x74, 0x2e, 0x52,
            0x4d, 0x49, 0x4c, 0x6f, 0x61, 0x64, 0x65, 0x72,
            0xa1, 0x65, 0x44, 0xba, 0x26, 0xf9, 0xc2, 0xf4,
            0x02, 0x00, 0x00, 0x74, 0x00, 0x28, 0x66, 0x69,
            0x6c, 0x65, 0x3a, 0x52, 0x4d, 0x49, 0x43, 0x6c,
            0x61, 0x73, 0x73, 0x4c, 0x6f, 0x61, 0x64, 0x65,
            0x72, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74,
            0x79, 0x54, 0x65, 0x73, 0x74, 0x2f, 0x69, 0x71,
            0x6e, 0x44, 0x2e, 0x6a, 0x61, 0x72, 0x78, 0x70,
            0x77, 0x01, 0x00
        ])

        self.conn.sendall(msg, 0)

        response = b''

        while True:
            try:
                _response = self.conn.recv(1024)
                if len(_response) == 0:
                    break
                response += _response
            except:
                break

        # this is probably oversimplified, but worked against the 2 vuln/not vuln hosts I tested
        if b'RMI class loader disabled' not in response and b'ClassNotFound' in response:
            return True
        
        return False

# code below this line WILL NOT be executed by odin. it is only useful for you
# to debug your code locally

if __name__ == '__main__':
    import argparse
    from odin import test_check
    
    parser = argparse.ArgumentParser('odin check tester')
    parser.add_argument('--ip', required=True)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--ssl', required=True, type=bool)
    parser.add_argument('--fqdn', required=True)
    args = parser.parse_args()

    test_check(Check, args.ip, args.port, args.fqdn, args.ssl)
