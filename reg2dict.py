'''
rv.reg2dict: Module to read windows registry as a dictionary.  Supports shallow or deep (recursive) walks.
Version: 1.1
Author: Ram Varra
'''
import logging
import win32api, win32con, pywintypes
import platform

import rv.misc
#===========================================================================================================
def _reg2dict_for_key(key_hdl, deep):
    d = {}     
    i = 0
    while True:
        logging.debug("i = {}".format(i))
        try:
            k, v, t = win32api.RegEnumValue(key_hdl, i)
        except pywintypes.error as ex:
            if ex.strerror == 'No more data is available.':
                break
            else:
                logging.error ("_reg2dict_for_key: Failed to get Value at index {}: Exception: {}".format (i, ex))
                raise ex
        else:
            logging.debug("Value at {} = '{}'".format(i, v))
            d[k] = v
            i += 1
    if deep:
        for t in win32api.RegEnumKeyEx(key_hdl):
            sub_key_hdl = win32api.RegOpenKeyEx(key_hdl, t[0])
            d[t[0]] = _reg2dict_for_key(sub_key_hdl, deep)
    return d

#------------------------------------------------------------------------------------------------------------------
def reg2dict (key, computer=None, hive=win32con.HKEY_LOCAL_MACHINE, deep=True):
    '''
    Extract contents of a registry key into a dictionary tree. 
    key - registry key (e.g r"SOFTWARE\Microsoft\Windows NT"). Should not include hive prefix like HKEY_LOCAL_MACHINE
    computer = HOSTNAME or IPADDRESS of the remote computer. Defaults to current computer.
    hive - defaults to win32con.HKEY_LOCAL_MACHINE
    deep - If true, registry is walked recursively to generate dictionary tree. False - returns values from top level key only. Default is True.
    '''
    if not computer:
        computer = platform.node ()
    hive_hdl = win32api.RegConnectRegistry ("\\\\" + computer, hive)
    key_hdl = win32api.RegOpenKeyEx(hive_hdl, key)
    return _reg2dict_for_key(key_hdl, deep)
    
#------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    import pprint

    rv.misc.set_logging ()
    
    for key, deep in [(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", False), (r"SOFTWARE\Python", True)]:
        logging.info ('\n{} - Deep {}\n'.format (key, deep))
        r = reg2dict (key, deep=deep)
        logging.info (pprint.pformat(r))
