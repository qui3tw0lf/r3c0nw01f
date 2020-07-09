#!/usr/bin/env python3
import os
import sys
import logging
import threading
from lib import basic


class Web:

    SERVICE_NAME = "Web"
    SERVICE_PORTS = [80, 443]
    SERVICE_PROTOCOLS = ["http", "https"]
    SERVICE_REQ_DIRS = ["scans"]
    SERVICE_MODULES = ["WebHeaders", "RobotsTxt", "Gobuster", "Nikto"]
    SERVICE_REQ_COMMANDS = ["curl", "gobuster", "nikto"]
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

    def WebHeaders(self):
        try:
            _cmd = "curl %s://%s:%s/ -I 2>/dev/null 1> scans/web_headers.txt" % (self.CLIENT_PROTOCOL, self.CLIENT_IP, self.CLIENT_PORT)
            basic.RunCommand(_cmd)
            _cmd = "curl -X OPTIONS %s://%s:%s/ -I 2>/dev/null 1> scans/web_headers_options.txt" % (self.CLIENT_PROTOCOL, self.CLIENT_IP, self.CLIENT_PORT)
            basic.RunCommand(_cmd)
        except Exception as _except:
            logging.error(_except)

    def RobotsTxt(self):
        try:
            _cmd = "curl %s://%s:%s/robots.txt 2>/dev/null 1> scans/robots.txt" % (self.CLIENT_PROTOCOL, self.CLIENT_IP, self.CLIENT_PORT)
            basic.RunCommand(_cmd)
        except Exception as _except:
            logging.error(_except)

    def Gobuster(self):
        try:
            _cmd = "gobuster dir -u %s://%s:%s/ -w /tmp/list.lst -t 50 &> scans/gobuster.txt" % (self.CLIENT_PROTOCOL, self.CLIENT_IP, self.CLIENT_PORT)
            basic.RunCommand(_cmd)
        except Exception as _except:
            logging.error(_except)

    def Nikto(self):
        try:
            _cmd = "nikto -h %s://%s:%s/ &> scans/nikto.txt" % (self.CLIENT_PROTOCOL, self.CLIENT_IP, self.CLIENT_PORT)
            basic.RunCommand(_cmd)
        except Exception as _except:
            logging.error(_except)


if __name__ == "__main__":
    Web()
