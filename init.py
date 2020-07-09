#!/usr/bin/env python3

import nmap
import logging
import argparse
import threading
import coloredlogs
from websock import WebSocketServer
from services.web import Web as SERVICE_WEB
from services.smb import Smb as SERVICE_SMB


class W0lf:

    MODULES_LIST = []
    SERVICE_MODE = 'all'
    MODULE_INFO = {}
    SCAN_RESULTS = {}
    ARGS = {}

    def __init__(self):
        self.GetModulesInfo()
        _argparse = argparse.ArgumentParser(description='Automatic Recon')
        _argparse.add_argument('ip', action='store', help='Target IP address')
        _argparse.add_argument('ports', action='store', help='Target Ports')
        _argparse.add_argument('--all', default='all', action='store_const', const='all', dest='scan_mode', help='Run all modules (Default : Enabled)')
        _argparse.add_argument('--nmap', default='nmap', action='store_const', const='nmap', dest='scan_mode', help='Run nmap module')
        for _mod in self.MODULES_LIST:
            _argparse.add_argument('--%s' % _mod, action='store_const', const='%s' % _mod, dest='scan_mode', help='Run %s module' % _mod)
        _args = vars(_argparse.parse_args())
        logging.debug(_args)
        self.ARGS = _args
        self.SERVICE_MODE = _args['scan_mode']
        self.RunNmapScan()
        _thread1 = threading.Thread(target=self.RunNmapScan, args=(1,))
        _thread1.start()
        _thread1 = threading.Thread(target=self.RunNmapScan, args=(2,))
        _thread1.start()
        self.RunModules()

    def GetModulesInfo(self):
        _globals = globals()
        _keys = dict(_globals).keys()
        _list_of_modules = [x for x in _keys if x.find("SERVICE_") == 0]
        logging.debug("Module List    : %s " % str(_list_of_modules))
        for _mod in _list_of_modules:
            _tmp_json = _globals[_mod].GetDetails()
            self.MODULE_INFO[_mod] = _tmp_json
            self.MODULES_LIST.append(_tmp_json['name'].lower())
            logging.debug("Loading module : %s %s %s" % (_tmp_json['name'], str(_tmp_json['ports']), str(_tmp_json['protocols'])))

    def RunNmapScan(self, _detailed=0):
        _scan_type = ["-sS", "basic"]
        if _detailed == 1:
            _scan_type = ["-sV", "version"]
        elif _detailed == 2:
            _scan_type = ["-sVC", "combined"]
        _nmap = nmap.PortScanner()
        _nmap.scan(self.ARGS['ip'], self.ARGS['ports'], arguments='--min-rate 2000 -Pn -n %s' % (_scan_type[0]))
        logging.debug(_nmap.command_line())
        for _host in _nmap.all_hosts():
            _tmp_tcp = _nmap[_host]['tcp']
            for _port in _tmp_tcp.keys():
                _tmp_port = _tmp_tcp[_port]
                if _tmp_port['state'] == 'open':
                    self.SCAN_RESULTS[_port] = _tmp_port
                logging.debug("Port : %d | Protocol : %s | Status : %s" % (_port, _tmp_port['name'], _tmp_port['state']))

    def FindModule(self, _key, _type="ports"):
        if _type == "ports":
            _results = [x for x in self.MODULE_INFO if _key in self.MODULE_INFO[x]['ports']]
        else:
            _results = [x for x in self.MODULE_INFO if _key in self.MODULE_INFO[x]['protocols']]
        return _results

    def RunModules(self):
        if self.SERVICE_MODE == 'all':
            for _port in self.SCAN_RESULTS:
                _tmp_proto = self.SCAN_RESULTS[_port]['name']
                _tmp_mod = self.FindModule(_tmp_proto, "proto")
                for _mod in _tmp_mod:
                    _tmp_funcs = self.MODULE_INFO[_mod]['functions']
                    logging.debug(_mod)
                    globals()[_mod](self.ARGS['ip'], _port, _tmp_proto, _tmp_funcs)
        elif self.SERVICE_MODE == "nmap":
            self.RunNmapScan(_detailed=1)
            self.RunNmapScan(_detailed=2)
        else:
            _tmp_mod_name = "SERVICE_%s" % self.SERVICE_MODE.upper()
            for _port in self.SCAN_RESULTS:
                _tmp_proto = self.SCAN_RESULTS[_port]['name']
                _tmp_mod = self.FindModule(_tmp_proto, "proto")
                for _mod in _tmp_mod:
                    if _mod == _tmp_mod_name:
                        _tmp_funcs = self.MODULE_INFO[_mod]['functions']
                        globals()[_mod](self.ARGS['ip'], _port, _tmp_proto, _tmp_funcs)


class WSServer:

    def on_data_receive(self, client, data):
        '''Called by the WebSocket server when data is received.'''
        # Your implementation here.
        print(__doc__)

    def on_connection_open(self, client):
        '''Called by the WebSocket server when a new connection is opened.'''
        # Your implementation here.
        print(__doc__)

    def on_error(self, exception):
        '''Called by the WebSocket server whenever an Exception is thrown.'''
        # Your implementation here.
        print(__doc__)

    def on_connection_close(self, client):
        '''Called by the WebSocket server when a connection is closed.'''
        # Your implementation here.
        print(__doc__)

    def on_server_destruct(self):
        '''Called immediately prior to the WebSocket server shutting down.'''
        # Your implementation here.
        print(__doc__)

    def __init__(self):
        _my_server = WebSocketServer(
            "127.0.0.1",
            8467,
            on_data_receive=self.on_data_receive,
            on_connection_open=self.on_connection_open,
            on_error=self.on_error,
            on_connection_close=self.on_connection_close,
            on_server_destruct=self.on_server_destruct
        )
        _my_server.serve_forever()


if __name__ == "__main__":
    coloredlogs.install(level=logging.DEBUG, fmt="%(asctime)s %(levelname)s %(message)s")
    # _w0lf = W0lf()
    _server = WSServer()
