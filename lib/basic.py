import logging
import subprocess
import coloredlogs


def RunCommand(_command, _show_output=False):
    try:
        logging.debug("Running : %s" % _command)
        _proc = subprocess.Popen(_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _out, _err = _proc.communicate()
        _out = _out.decode().strip()
        _err = _err.decode().strip()
        if _show_output:
            logging.debug("Output  : " + _out)
            logging.debug("Error   : " +  _err)
        return _out, _err
    except Exception as _except:
        logging.error(_except)
