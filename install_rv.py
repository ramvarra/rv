"""
    Install rv package on local system C:\TOOLS\PythonLib
    Check and sets PYTHONPATH to include C:\TOOLS\PythonLib
    Python3 compatible
"""

import os
import sys
import logging
import shutil
import misc

_WIN_RV_FILES = ['dpapi.py', 'windows_tz.py',  'reg2dict.py']

_RV_FILES = ['__init__.py', 'misc.py', 'ESUtil.py', 'crypt.py', 'zillow.py', 'CachedDns.py', 'geoip.py']
if os.name == 'nt':
    _RV_FILES += _WIN_RV_FILES
    INSTALL_DIR = r'C:\TOOLS\PythonLib'
else:
    INSTALL_DIR = r'/usr/local/lib/PythonLib'

#----------------------------------------------------------------------------------------------------------------------
def install_rv(install_dir=INSTALL_DIR):
    if os.name == 'nt':
        misc.update_windows_tz()

    if not os.path.isdir(install_dir):
        logging.info("Install Dir {} not present. Creating it now...".format(install_dir))
        os.makedirs (install_dir)

    dir_list = [install_dir]

    for dst_dir in dir_list:
        rv_dir = os.path.join (dst_dir, 'rv')
        if not os.path.isdir(rv_dir):
            logging.info("Creating RV DIR {} ...".format(rv_dir))
            os.mkdir(rv_dir)
        for rv_file in _RV_FILES:
            if not os.path.exists(rv_file):
                misc.fatal("Source RV FILE: {} does to exist".format (rv_file))
            destination_file = os.path.join(rv_dir, rv_file)
            logging.info("Copying {} -> {}".format (rv_file, destination_file))
            shutil.copyfile(rv_file, destination_file)
        logging.info("Successfully copied all files to RVI DIR: {}".format(rv_dir))

    logging.info("Setting PYTHONPATH")
    misc.add_path(install_dir, path_var='PYTHONPATH')
#----------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    misc.set_logging(r'C:\TEMP\install_rv.log')

    install_rv()
