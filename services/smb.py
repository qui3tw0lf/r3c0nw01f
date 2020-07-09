#!/usr/bin/env python3
import os
import sys
import logging
import threading
from lib import basic


class Smb:

    SERVICE_NAME = "Smb"
    SERVICE_PORTS = [139, 445]
    SERVICE_PROTOCOLS = ["smb", "netbios-ssn"]
    SERVICE_REQ_DIRS = ["scans"]
    SERVICE_MODULES = ["SmbClient", "SmbMap", "Enum4Linux"]
    SERVICE_REQ_COMMANDS = ["smbclient", "smbmap", "enum4linux"]
    CLIENT_IP = ""
    CLIENT_PORT = 0
    CLIENT_PROTOCOL = ""
    CLIENT_MODULES = []

    @classmethod
    def GetDetails(_cls):
        _out = {"name": _cls.__dict__['SERVICE_NAME'],
                "ports": _cls.__dict__['SERVICE_PORTS'],
                "protocols": _cls.__dict__['SERVICE_PROTOCOLS'],
                "functions": _cls.__dict__['SERVICE_MODULES']}
        return _out

    def __init__(self, _ip, _port, _protocol, _modules):
        logging.debug("-- Service Info --")
        logging.debug("%-10s : %s" % ("Name", self.SERVICE_NAME))
        logging.debug("%-10s : %s" % ("Ports", str(self.SERVICE_PORTS)))
        logging.debug("%-10s : %s" % ("Protocols", str(self.SERVICE_PROTOCOLS)))
        self.CommandCheck()
        self.DirectoryCheck()
        self.CLIENT_IP = _ip
        self.CLIENT_PORT = _port
        self.CLIENT_PROTOCOL = _protocol
        self.CLIENT_MODULES = _modules
        _dict = globals()[self.SERVICE_NAME]
        _threading_list = []
        for _mod in _modules:
            _thread = threading.Thread(target=_dict.__dict__[_mod], args=(self,))
            _threading_list.append(_thread)
        for _t in _threading_list:
            _t.start()
        for _t in _threading_list:
            _t.join()
        logging.debug("%s module finished!" % self.SERVICE_NAME)

    def CommandCheck(self):
        logging.debug("---- Checking commands")
        for _cmd in self.SERVICE_REQ_COMMANDS:
            _out, _err = basic.RunCommand("which " + _cmd)
            if _err != "":
                logging.error(_cmd + " : Command not found!")
                sys.exit(0)

    def DirectoryCheck(self):
        logging.debug("---- Checking directories")
        for _dir in self.SERVICE_REQ_DIRS:
            if not os.path.exists(_dir) or not os.path.isdir(_dir):
                os.mkdir(_dir)
                logging.debug("%s directory doesn't exists! Created." % _dir)

    def SmbClient(self):
        try:
            _cmd = "smbclient -L //%s &> scans/smbclient.txt" % (self.CLIENT_IP)
            basic.RunCommand(_cmd)
        except Exception as _except:
            logging.error(_except)

    def SmbMap(self):
        try:
            _cmd = "smbmap -H %s &> scans/smbmap.txt" % (self.CLIENT_IP)
            basic.RunCommand(_cmd)
        except Exception as _except:
            logging.error(_except)

    def Enum4Linux(self):
        try:
            _cmd = "enum4linux -a %s &> scans/enum4linux.txt" % (self.CLIENT_IP)
            basic.RunCommand(_cmd)
        except Exception as _except:
            logging.error(_except)


if __name__ == "__main__":
    Smb()
