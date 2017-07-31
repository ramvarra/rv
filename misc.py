import os, sys, shlex
import re
import subprocess
import datetime
import tempfile
import logging
import xml.etree.ElementTree as etree
import logging.handlers
import subprocess
if os.name == 'nt':
    import win32api, win32con, winreg
    import win32wnet
    import win32netcon
    if __package__:
        from . import windows_tz
    else:
        import windows_tz

import traceback
import platform
import smtplib
import time
from email.mime.text import MIMEText
import csv
import socket
import pytz


import IPython.display

#=================================================================================================
g_mail_config = None
g_indent = 0
g_dns_cache = {}
g_reverse_dns_cache = {}

_re_rfc3339 = re.compile(r'(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(\.(?P<f>\d+))?(?P<sign>[+-])(?P<oh>\d\d):(?P<om>\d\d)$')
_re_ip_address = re.compile(r'(\d+\.){3}\d+$')

# -- This is used to conform older timezone names used in Windows Systems to new standard used in the windows_tz module.
_custom_wintz_map = {
    'Jerusalem Standard Time': 'Israel Standard Time',
    'E. Europe Standard Time': 'GTB Standard Time',
    '(UTC-08:00) Pacific Time (US & Canada)': 'Pacific Standard Time',
    '(UTC-07:00) Mountain Time (US & Canada)': 'US Mountain Standard Time',
    '(UTC) Dublin, Edinburgh, Lisbon, London': 'UTC',
    '(UTC+02:00) Beirut': 'Middle East Standard Time',
    '(UTC+08:00) Beijing, Chongqing, Hong Kong, Urumqi': 'China Standard Time',
    '(UTC+02:00) Jerusalem': 'Israel Standard Time',
    '(UTC+05:30) Chennai, Kolkata, Mumbai, New Delhi': 'India Standard Time',
    '(UTC+08:00) Taipei': 'Taipei Standard Time',
    '(UTC-04:00) Atlantic Time (Canada)': 'Atlantic Standard Time',
    '(UTC-07:00) Arizona': 'US Mountain Standard Time',
    'Malay Peninsula Standard Time': 'Singapore Standard Time',
    'Russia TZ 1 Standard Time': 'Kaliningrad Standard Time',
    'Russia TZ 2 Standard Time': 'Russian Standard Time',
    'Russia TZ 3 Standard Time': 'Russia Time Zone 3',
    'Russia TZ 4 Standard Time': 'Ekaterinburg Standard Time',
    'Russia TZ 5 Standard Time': 'N. Central Asia Standard Time',
    'Russia TZ 6 Standard Time': 'North Asia Standard Time',
    'Russia TZ 7 Standard Time': 'North Asia East Standard Time',
    'Russia TZ 8 Standard Time':  'Yakutsk Standard Time',
    'Russia TZ 9 Standard Time': 'Russia Time Zone 9',
    'Russia TZ 10 Standard Time': 'Russia Time Zone 10',
    'Russia TZ 11 Standard Time': 'Russia Time Zone 11',
    'Pacific Standard Time (Mexico)': 'Pacific Standard Time',
    'Easter Island Standard Time': 'SA Pacific Standard Time',
}
#=================================================================================================
#------------------------------------------------------------------------------------------
def dns_lookup(host):
    if not host:
        return ''
    if host not in g_dns_cache:
        ip = ''
        # if dns fails to find ip, we will keep in cache as ip
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as ex:
            pass #logging.warn ("DNS Lookup for '{}' failed: {}".format (host, str(ex)))
        g_dns_cache[host] = ip

    return g_dns_cache[host]

#------------------------------------------------------------------------------------------
def dns_reverse_lookup(ip):
    if not ip:
        return ''
    if ip not in g_reverse_dns_cache:
        # if dns fails to find ip, we will keep in cache as ip
        host_name = ip
        if re.match (_re_ip_address, ip):
            try:
                host_name = socket.gethostbyaddr(ip)[0]
            except socket.error as ex:
                logging.debug("Reverse DNS Lookup for '{}' failed: {}".format (ip, str(ex)))
                pass
        g_reverse_dns_cache[ip] = host_name

    return g_reverse_dns_cache[ip]


#-----------------------------------------------------------------------------------------------------------------
def humanize_bytes(bytes, precision=1):
    """Return a humanized string representation of a number of bytes.
    """
    abbrevs = (
        (1<<50, 'PB'),
        (1<<40, 'TB'),
        (1<<30, 'GB'),
        (1<<20, 'MB'),
        (1<<10, 'kB'),
        (1, 'bytes')
    )
    if bytes == 1:
        return '1 byte'
    for factor, suffix in abbrevs:
        if bytes >= factor:
            break
    #print ("bytes = '{}' type: {}".format (bytes, type(bytes)))
    return '%.*f %s' % (precision, 1.0 * bytes / factor, suffix)

#=================================================================================================
def is_windows ():
    '''
    Check if we are on Windows OS
    :return: True - if running on windows else False
    '''
    return (os.name == 'nt')

#=================================================================================================        
def in_path (p, path_var='PATH'):
    """
    Check if p exists in Path, if not already present.
    :return - True if p present in path_var
    """
    if path_var in os.environ:
        os_path = os.environ[path_var].rstrip (os.pathsep)
        abs_norm_p = os.path.normcase (os.path.abspath(p))
        return any([1 for x in os_path.split (os.pathsep) if os.path.normcase(os.path.abspath(x)) == abs_norm_p])
    return False

#----------------------------------------------------------------------------------------------------------------------
def add_path (p, path_var='PATH'):
    """
    Add p to System Path Variable path_var, if not already present. Windows only function.
    """
    abs_norm_p = os.path.normcase(os.path.abspath(p))
    logging.info("Normalized dir: {}".format (abs_norm_p))

    if path_var in os.environ:
        if in_path(p, path_var=path_var):
            logging.info('Dir {} Already in {}'.format(p, path_var))
            return
        logging.info('Adding {} to {}'.format(abs_norm_p, path_var))
        os_path = os.environ[path_var].rstrip(os.pathsep) + os.pathsep + abs_norm_p
    else:
        os_path = abs_norm_p

    logging.info('Setting {} to {}'.format(path_var, os_path))
    if os.name == 'nt':
        ret = subprocess.check_output('SETX /M "{}" "{}"'.format(path_var, os_path), shell=True)
        if b'SUCCESS: Specified value was saved.' not in ret:
            fatal('Setx of {} failed with Error: Output: {}'.format(path_var, ret))
        logging.info('Successfully updated {}'.format(path_var))
    else:
        logging.error("ADDPATH not implmented - edit /etc/environment to add/update {}")

#----------------------------------------------------------------------------------------------------------------------
def send_mail (subject, content, email_to):
    global g_mail_config

    if g_mail_config is None:
        logging.error ("Mail Settings not configured with set_logging () initialization. Can not send mail.")
        return False


    smtp_connection = smtplib.SMTP (g_mail_config['SMTP_SERVER'])


    msg = MIMEText (content)
    msg['From'] = g_mail_config['EMAIL_FROM']
    msg['To'] = ', '.join (email_to)
    msg['Subject'] = subject 
    logging.info ('Sending email to: "%s" Subject: "%s"', email_to, subject)
    try:
        smtp_connection.sendmail (g_mail_config['EMAIL_FROM'], email_to, msg.as_string ())
    except Exception as e:
        logging.error ('SMTP EMAIL Send failed with exception: %s' % e)
    finally:
        smtp_connection.quit ()

#-----------------------------------------------------------------------------------------------------------------------------    
def _set_formatter (mp=False):
    global g_indent
    prefix = platform.node ().split('.', 1)[0]
    if mp:
        prefix += ":" + str(os.getpid())
    fmtr = logging.Formatter (prefix + ":" + '%(asctime)s %(levelname)s' +
                              ': ' + ' ' * g_indent + '%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    for handler in logging.getLogger ().handlers:
        handler.setFormatter (fmtr)


#-----------------------------------------------------------------------------------------------------------------------------
class _IPythonLoggingHandler(logging.Handler):
    #-----------------------------------------------------------------------------------------------------------------
    def __init__(self):
        logging.Handler.__init__(self)
    #-----------------------------------------------------------------------------------------------------------------
    def flush(self):
        pass
    #-----------------------------------------------------------------------------------------------------------------
    def emit(self, record):
        try:
            msg = self.format(record)
            fs = "<span class='test'>{msg}</span>".format(cls=record.levelname, msg=msg)
            IPython.display.display(IPython.display.HTML(fs))
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)
#-----------------------------------------------------------------------------------------------------------------------------    
def set_logging (log_file=None, level=logging.INFO, mail_config=None, max_bytes=4*1024*1024, backup_count=5,
                 mp=False):
    '''
    Setup the logging configuration. Must be called before any logging output is produced.
    :param log_file: Full path to the log_file (None - to not to log to file). If this is dir, creates scriptname.log
    :param level: logging level
    :param mail_config: Configuration used to send emails - used by rv.misc.fatal ()
    :param max_bytes: Configuration for rotating log - max file size
    :param backup_count: Configuration for rotating log - max number of log files (suffixed .log.1, .log.2, ...)
    :param log_threadname: Add name of thread to logging header - useful for Multi-threaded programs.
    :return: root logger
    '''
    global g_mail_config
    if mail_config:
        assert isinstance(mail_config, dict), "mail_config must be a dictionary."
        g_mail_config = {}
        for k in ('EMAIL_FROM', 'FATAL_TO', 'SMTP_SERVER'):
            assert k in mail_config, "mail_config dict missing {} key".format (k)
            g_mail_config[k] = mail_config[k]

    logger = logging.getLogger()
    if len(logger.handlers):
        logger.handlers = []

        
    logger.setLevel (level)

    # add stream or ipython notebook handler
    handler_list = []
    if r'IPython\kernel\__main__.py' in sys.argv[0]:
        if not logger.handlers:
            handler_list.append(_IPythonLoggingHandler())
    else:
        handler_list.append(logging.StreamHandler())

    if log_file is not None:
        if os.path.isdir(log_file):
            # use default scriptname.log
            log_file = os.path.join(log_file, os.path.splitext(os.path.basename(sys.argv[0]))[0]) + '.log'

        # setup rotating file handler
        print('Logging to: ', log_file)
        handler_list.append(logging.handlers.RotatingFileHandler (log_file, 'a',
                                                                  maxBytes=max_bytes, backupCount=backup_count))
    for ch in handler_list:
        ch.setLevel(level)
        logger.addHandler(ch)

    _set_formatter (mp=mp)
    
    return logger
#-----------------------------------------------------------------------------------------------------------------------------
def is_admin ():
    """
    Check if current logged in user running with elevated admin privs
    """
    try:
        _ = os.listdir (os.path.join(os.environ['SYSTEMROOT'], 'TEMP'))
    except WindowsError as ex:
        if ex.strerror == 'Access is denied':
            return False
        else:
            raise
    else:
        return True
#==================================================================================================
def is_vmware():
    ''' Determine if we are on a VMware Linux CentOS Guest'''
    
    # check if we already have cached result
    if hasattr(is_vmware, "return_value"):
        return is_vmware.return_value
        
    # use a function attribute as cache
    is_vmware.return_value = False     
       
    uname_list = os.uname ()
    if not (uname_list[0] == 'Linux' and uname_list[2].startswith ('2.6') and uname_list[4] == 'x86_64'):
        fatal ("uname does not match Linux 2.6 x86_64 - not a CentOs!!!'")
        
    try:
        dmesg = subprocess.check_output ('/bin/dmesg')
    except Exception as ex:
        fatal ("Failed to run dmesg command: %s" % (ex,))
        
    #validate dmesg is not rolled over and still contains Hypervisor message.
    #The Hypervisor line will appear between these two patterns
    for pat in (r'^CPU0:\s+', r'^Linux version 2'):
        if not re.search (pat, dmesg, re.MULTILINE):
            fatal ("dmesg does not have required pattern: '%s'. Can not determine if this is VMware guest!" % (pat,))
    m = re.search (r'^Hypervisor detected: (\S+)', dmesg, re.MULTILINE)
    if m:
        if m.group (1) == 'VMware':
            is_vmware.return_value = True
        else:
            fatal ("Unsupported Hypervisor detected in dmesg: %s" % (m.group (1),))
    return is_vmware.return_value
#--------------------------------------------------------------------------------------------------------
def fatal(msg):
    node = platform.node ().split('.', 1)[0]
    email_subject = "{}:{} Fatal Error: {}".format (node, sys.argv[0], msg)

    ex_type, ex_value, ex_traceback = sys.exc_info()
    if ex_type:
        msg += "\nException Stack Trace\n {}".format (traceback.format_exc())

    logging.error(msg)
    if g_mail_config:
        fatal_to_list = g_mail_config.get('FATAL_TO')
        if fatal_to_list:
            send_mail (email_subject, msg, fatal_to_list)
        else:
            logging.error("No FATAL_TO configured in mail config")
    sys.exit(1)

#--------------------------------------------------------------------------------------------------------
def safe_open (file_name, safety_window_seconds=5, max_wait_seconds=None):
    return open (file_name)

    if max_wait_seconds and max_wait_seconds < safety_window_seconds:
        fatal ("Invalid params safe_open: file_name {}: max_wait_seconds {}"
                           "must be > safety_window_seconds {}".format (file_name, max_wait_seconds, safety_window_seconds))

    begin_ts = time.time ()
    mt = os.path.getmtime (file_name)
    while True:
        logging.info ("safe_open: file: {} waiting {} seconds to check mtime {} again".format (file_name, safety_window_seconds, mt))
        time.sleep (safety_window_seconds)
        new_mt = os.path.getmtime (file_name)
        if  new_mt == mt:
            logging.info ("file {} not modified in {} seconds - opening it now".format (file_name, safety_window_seconds))
            return open (file_name)
        else:
            logging.debug ("file {} changed in last {} seconds - old modtime {} new_modtime {}".format (file_name, safety_window_seconds, mt, new_mt))
            mt = new_mt
            if max_wait_seconds:
                if (begin_ts + max_wait_seconds) > time.time ():
                    fatal ("safe_open: file {} max_wait_seconds exceeded {}".format(file_name, max_wait_seconds))


#--------------------------------------------------------------------------------------------------------------------
def get_command_output (cmd_list, ignore_error=None):
    # split the cmd_list into list, if it is a string 
    if isinstance (cmd_list, str):
        cmd_list = shlex.split (cmd_list)
    
    with tempfile.TemporaryFile (suffix='.cmd_out', prefix='autohdp_') as fd_out: 
        with tempfile.TemporaryFile (suffix='.cmd_err', prefix='autohdp_') as fd_err:
            logging.info ("Running: '%s'", cmd_list)
            try:
                ret = subprocess.call (cmd_list, stdout=fd_out, stderr=fd_err)            
            except Exception as ex:
                fatal ("Failed to run cmd '%s': Exception: %s" %(cmd_list[0], ex))
            fd_out.seek (0)            
            out = fd_out.read ()
            fd_err.seek (0)
            err = fd_err.read ()
            
            if ret != 0:
                fatal ("CMD failed with return code: %d. STDOUT='%s'\nSTDERR='%s'" % (ret, out, err))
                
            if err:
                if not ignore_error or ignore_error not in err:
                    logging.error ("'%s' finished with return code 0, but has errors on STDERR. STDOUT='%s'\nSTDERR='%s'", ' '.join(cmd_list), out, err)
                    if ignore_error:
                        logging.error ("ignore_error: '%s' not found in STDERR", ignore_error)
                    fatal ("Non Ignorable Fatal error while running: %s. \nSTDERR:%s" % (' '.join (cmd_list), err))
                    
    logging.info("'%s' finished successfully." % (cmd_list,))
    return out
#=====================================================================================================================
def wrap (message, func, *args, **kwargs):
    global g_indent
    logging.info ("START: %s" % message)
    g_indent += 4
    _set_formatter ()
    try:
        ret = func (*args, **kwargs)
    finally:
        g_indent -= 4
        _set_formatter ()
    logging.info ("END: %s" % message)
    return (ret)

#=====================================================================================================================
def load_config (file_name, required_params=[], optional_params=None):
    ''' Load configuration containing name/value (hadoop style) from XML file into a dictionary and return the dict
        checks for all required_params exists.  If optional_params specied, validates that only (required+optional) exists in the file. 
    '''
    d = {}
    
    logging.info ("Loading config file '%s'", file_name)
 
    try:
        xml = etree.parse (file_name)
    except Exception as ex:
        fatal ("Failed to load config file: '%s' Error: %s" % (file_name, ex))
    
    doc = xml.getroot ()
    if doc.tag != 'configuration':
        fatal ("Missing root tag configuration in config file '%s'. Instead found '%s'" % (file_name, doc.getroot().tag))

    #----------------------------------------------------
    def get_node_text (prop, node_name):
        v = prop.find (node_name)
        if v is None:
            fatal ("Invalid config file '%s'. Missing node '%s' in property in: %s" % (file_name, node_name, etree.tostring (prop)))
        txt = v.text
        if txt is None:
            fatal ("Invalid config file '%s'. Missing node text '%s' in property in: %s" % (file_name, node_name, etree.tostring (prop)))
        return txt.strip ()
    #----------------------------------------------------
                        
    for prop in doc.findall ('property'):
        name = get_node_text (prop, 'name')
        if not name:
            fatal ("Invalid config file '%s'. Empty name in property: %s" % (file_name, etree.tostring (prop)))
        value = get_node_text (prop, 'value')
        d[name] = value
    
    missing_params = set(required_params) - set(d) 
    if missing_params:
        fatal ("Invalid config file '%s'. Missing these required parameters: %s" % (file_name, ','.join (missing_params)))
    
    if optional_params:
        extra_params = set(d) - set(required_params + optional_params)
        if extra_params:
            fatal ("Invalid config file '%s'. Contains unexpected parameters: %s" % (file_name, ','.join (extra_params)))
    
    logging.info ("Configuration from file '%s' = %s", file_name, d)
    return (d)

#=========================================================================================================================
def csv_to_sqllite (filepath_or_fileobj, dbpath, table='data'):
    import sqlite3
    if isinstance(filepath_or_fileobj, str):
        fo = open(filepath_or_fileobj)
    else:
        fo = filepath_or_fileobj
    reader = csv.reader(fo)
 
    types = guess_csv_types (fo)
    fo.seek(0)
    headers = reader.next()
 
    _columns = ','.join(
        ['"%s" %s' % (header, _type) for (header,_type) in zip(headers, types)]
        )
 
    conn = sqlite3.connect(dbpath)
    c = conn.cursor()
    c.execute('CREATE table %s (%s)' % (table, _columns))
 
    _insert_tmpl = 'insert into %s values (%s)' % (table,
        ','.join(['?']*len(headers)))
    for row in reader:
        # we need to take out commas from int and floats for sqlite to
        # recognize them properly ...
        row = [ x.replace(',', '') if y in ['real', 'integer'] else x
                for (x,y) in zip(row, types) ]
        c.execute(_insert_tmpl, row)
 
    conn.commit()
    c.close()    
    #------------------------------------------------------------------------------------------------------------------
def guess_csv_types (fileobj, max_sample_size=100):
    '''
    Guess column types (as for SQLite) of CSV.
    '''
    reader = csv.reader(fileobj)
    # skip header
    _headers = reader.next()
    # we default to text for each field
    types = ['text'] * len(_headers)
    # order matters
    # (order in form of type you want used in case of tie to be last)
    options = [
        ('text', str),
        ('real', float),
        ('integer', int)
        # 'date',
        ]
    # for each column a set of bins for each type counting successful casts
    perresult = {
        'integer': 0,
        'real': 0,
        'text': 0
        }
    results = [ dict(perresult) for x in range(len(_headers)) ]
    for count,row in enumerate(reader):
        for idx,cell in enumerate(row):
            cell = cell.strip()
            # replace ',' with '' to improve cast accuracy for ints and floats
            cell = cell.replace(',', '')
            for key,cast in options:
                try:
                    # for null cells we can assume success
                    if cell:
                        cast(cell)
                    results[idx][key] = (results[idx][key]*count + 1) / float(count+1)
                except ValueError as ex:
                    pass
        if count >= max_sample_size:
            break
    for idx,colresult in enumerate(results):
        for _type, dontcare in options:
            if colresult[_type] == 1.0:
                types[idx] = _type
    return types

#-----------------------------------------------------------------------------------------------------------------------
def robocopy (src_dir, dst_dir, retries=5):

    cmd = r'robocopy /S /R:{} "{}" "{}"'.format(retries, src_dir, dst_dir)
    logging.info ("Running Robcopy cmd: {}".format(cmd))

    with tempfile.NamedTemporaryFile (suffix='.log', prefix='rv-misc-robocopy-') as tmp_file:
        ret = subprocess.call (cmd, shell=True, stdout=tmp_file, stderr=tmp_file)
        logging.info ("Robcopy Completed with return code {}. Checking for errors".format(ret))
        tmp_file.file.seek(0)
        for line in tmp_file.readlines ():
            m = re.match(r'\s*Files\s*:\s+(?P<total>[0-9]+)\s+(?P<copied>[0-9]+)\s+(?P<skipped>[0-9]+)\s+'
                          r'(?P<mismatch>[0-9]+)\s+(?P<failed>[0-9]+)', line)
            if m:
                if int(m.group('failed')) == 0:
                    logging.info ("Robcopy successful total = {} copied = {}".format (m.group('total'), m.group('copied')))
                    return True
                logging.error ('Robycopy Failed:  Total = {} Copied = {} Failed = {}'.format (m.group('total'), m.group ('copied'), m.group('failed')))
                return False

        # no break in for loop - no line matched regex
        logging.error ('Robocopy output has no File information. Output:')
        tmp_file.file.seek(0)
        logging.info(tmp_file.read())
        return False

#-----------------------------------------------------------------------------------------------------------------------
def pprint_ordered_dict (d, indent=''):
    '''
    pretty print ordered dictionary
    :param d:  ordered dictionary
    :param indent: initial indent
    :return: None
    '''
    for k, v in d.iteritems():
        if isinstance (v, str):
            print ("{}{}='{}'".format(indent, k, v))
        elif isinstance(v, list):
            print ('{}{}=[({})'.format(indent, k, len(v)))
            for li in v:
                print (indent + '  {')
                pprint_ordered_dict (li, indent=indent+ '      ')
                print (indent + '  }')
            print (indent + ']')
        else:
            print ('{}{}={{'.format(indent, k))
            pprint_ordered_dict (v, indent=indent+'  ')
            print (indent + '}')
#----------------------------------------------------------------------------------------------------------
def dir_compare (dir1, dir2):
    '''
    Compare 2 directories dir1 with dir2. Return True if all files in dir1 tree match with dir2 (file names and contents).
    Note that this does not do reverse check - i.e dir2 could have more files than dir1.
    :param dir1: First dir
    :param dir2: Second dir
    :return: True if all files in dir1 match with dir2 in name and content.
    '''
    import filecmp
    dl = len (dir1)
    file_count = 0
    for src_root, subdirs, files in os.walk (dir1):
        dst_root = dir2 + src_root[dl:]
        for file in files:
            dst_file = os.path.join (dst_root, file)
            src_file = os.path.join (src_root, file)
            if not filecmp.cmp (src_file, dst_file, shallow=False):
                logging.error ("SRC {} DST {} different. Compared failed after {} files".format (src_file, dst_file, file_count))
                return False
            file_count += 1
    logging.info ("{} files compared between SRC {} and DST {}".format (file_count, dir1, dir2))
    return True

#------------------------------------------------------------------------------------------------------------
class _callable_dict(dict):
    """
    Class used with Timer - for returning elapsed time
    """
    def __call__(self):
        return self.get('T')
#------------------------------------------------------------------------------------------------------------
class Timer(object):
    """
    Timer: Context Manager class to track elapsed time.
    e.g.:
        with Timer() as t:
            do_some_work()
        print ('Took {} secs'.format(t())
    """
    def __init__(self):
        self._t = _callable_dict()

    def __enter__(self):
        self._begin_ts = time.time()
        return self._t

    def __exit__(self, type, value, traceback):
        self._t['T'] = time.time() - self._begin_ts

#------------------------------------------------------------------------------------------------------------

#=====================================================================================================================
def map_drive(drive, networkPath, user, password, force=False):
    logging.info("Checking the path: {}".format(networkPath))
    if (os.path.exists(drive)):
        logging.info("{} Drive is already mounted.".format(drive))

        if force:
            logging.info("trying to unmap drive {}...".format(drive))
            try:
                win32wnet.WNetCancelConnection2(drive, 1, 1)
                logging.info("Successfully unmapped {}...".format(drive))
            except:
                logging.error("Drive Unmap failed for {}, This might not be a network drive...".format(drive))
                return False
        else:
            logging.info("Non-forcing call. Will not unmap...")
            return False
    else:
        logging.info("Drive {} is free to map...".format(drive))

    logging.info("Trying to map {} to drive {}".format(networkPath, drive))
    try:
        win32wnet.WNetAddConnection2(win32netcon.RESOURCETYPE_DISK, drive, networkPath, None, user, password)
    except Exception as ex:
        logging.error("Unexpected error while mapping {} to drive {}: {}".format(networkPath, drive, ex))
        return False
    logging.info("Successfully mapped {} to drive {}".format(networkPath, drive))
    return True
#=====================================================================================================================
def unmap_drive(drive, force=False):
    #Check if the drive is in use
    if (os.path.exists(drive)):
        logging.info ("drive in use, trying to unmap...")
        if not force:
            logging.info("Executing un-forced call...")
        try:
            win32wnet.WNetCancelConnection2(drive, 1, force)
            logging.info("{} successfully unmapped...".format(drive))
            return True
        except:
            logging.info("Unmap failed, try again...")
            return False
    else:
        logging.info("{} Drive is already free...".format(drive))
        return True
        
#----------------------------------------------------------------------------------------------------------------
def intel_date_to_ww (ts=None):
    '''
        return intel workweek as integer of the format YYYYWW for date input ts.
        ts has to be either datetime or date type
    '''
    #-------------------------------------------------------------------------------------------------------------
    def _next_day (ts, weekday):
        ''' return  date corresponding to next weekday after ts: 0 - Mon, 1 - Tue, ... 5 - Sat, 6 - Sun '''
        remaining_days = weekday - ts.weekday ()
        if remaining_days <= 0:
            remaining_days += 7
        return ts + datetime.timedelta (days = remaining_days)
    #-------------------------------------------------------------------------------------------------------------
    if ts is None:
        ts = datetime.date.today()
    if not isinstance (ts, datetime.date):
        raise Exception ("Invalid argument type to calculate_ww)) -  expected datetime.date got %s" % type(ts))

    # saturday in the  WW of ts - 1 day
    last_day_in_the_week  = _next_day (ts - datetime.timedelta (days = 1), 5)
    # saturday in first WW of year
    last_day_in_the_first_week = _next_day (datetime.date (last_day_in_the_week.year - 1, 12, 31), 5)
    number_of_weeks_in_between = (last_day_in_the_week.timetuple ().tm_yday - last_day_in_the_first_week.timetuple ().tm_yday) // 7

    return last_day_in_the_week.year * 100 + number_of_weeks_in_between + 1

#----------------------------------------------------------------------------------------------------------------------------
def intel_ww_to_date(target_ww):
    '''
        param target_ww: Integer of format YYYYWW.
        returns first day (Sunday) of the target_ww.  Return value is datetime.date object.
    '''
    assert isinstance(target_ww, int), "target_ww must be integer.  Invalid type {} for {}".format(target_ww, type(target_ww))
    assert target_ww > 1000
    ww = target_ww % 100
    assert ww > 0 and ww <= 52, "Invalid target_ww {} - weekpart must be between 01 and 52".format(target_ww)
    year = int(target_ww/100)
    x = [(d, intel_date_to_ww(d)) for d in [datetime.date(year, 1, 1) + datetime.timedelta(i) for i in range(8)]]
    first_dt, first_ww = x[0]
    for ref_dt, ref_ww in x[1:]:
        if ref_ww != first_ww:
            break
    else:
        raise Exception("No ww transition in year {} - list {}".format(year, x))
    ww_delta = target_ww - ref_ww
    return ref_dt + datetime.timedelta(days=7*ww_delta)


#----------------------------------------------------------------------------------------------------------------------------
def rfc_3339_to_utc(s):
    '''
        convert RFC 3339 Time to UTC datetime.
        e.g: '2015-11-25T15:06:05.230-07:00', '2015-11-25T15:06:05.228388+07:00', '2015-11-25T15:06:05.228388+17:00'
    '''
    m = re.match(_re_rfc3339, s)
    if not m:
        raise ValueError # Invalid RFC_3389
    microsecond = 0
    if m.group('f'):
        microsecond = int(m.group('f'))
        if len(m.group('f')) <= 3:
            microsecond *= 1000
        elif len(m.group('f')) > 6:
            raise ValueError # Microsecs longer than 6 digits

    sign = -1 if m.group('sign') == '-' else 1
    offset = sign * int(m.group('oh')) * 60 + int(m.group('om'))
    if abs(offset) >= 24*60:
        raise ValueError #"Bad Offset in time string: {}".format(s)
    ts = datetime.datetime(*(int(m.group(i)) for i in range(1,7)), microsecond=microsecond, tzinfo=pytz.UTC) - datetime.timedelta(minutes=offset)
    return ts
#----------------------------------------------------------------------------------------------------------------------------
def read_registry_value(key, value_name, computer=None):
    hive = win32con.HKEY_LOCAL_MACHINE

    if key[0] == '\\':
        key = key[1:]
    if key[:5].upper() == 'HKEY_':
        parts = key.split('\\')
        hive_name, key = parts[0].upper(), '\\'.join(parts[1:])
        hive = getattr(win32con, hive_name)
        assert hive is not None, "Invalid Registry hive '{}' in '{}'".format(hive_name, key)


    reg = winreg.ConnectRegistry(computer, hive) if computer else hive

    hk = win32api.RegOpenKey (reg, key)
    v, t = win32api.RegQueryValueEx (hk, value_name)
    if t in (winreg.REG_EXPAND_SZ, winreg.REG_SZ):
        zs_index = v.find('\x00')
        if zs_index >= 0:
            v = v[:zs_index]

    return (v, t)
#----------------------------------------------------------------------------------------------------------------------------
def update_windows_tz():
    # originally from tzlocal/get_widows_info.py
    XML_SOURCE = 'http://unicode.org/cldr/data/common/supplemental/windowsZones.xml'
    import urllib.request
    import xml.dom.minidom
    import pprint
    logging.info("Loading CLDR {}".format(XML_SOURCE))
    if socket.getfqdn().lower().endswith('intel.com'):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': 'http://proxy-us.intel.com:911'}))
    else:
        opener = urllib.request.build_opener()
    source = opener.open(XML_SOURCE).read()

    dom = xml.dom.minidom.parseString(source)

    for element in dom.getElementsByTagName('mapTimezones'):
        if element.getAttribute('type') == 'windows':
            break

    win_tz = {}
    tz_win = {}
    for mapping in element.getElementsByTagName('mapZone'):
        if mapping.getAttribute('territory') == '001':
            win_tz[mapping.getAttribute('other')] = mapping.getAttribute('type').split(' ')[0]

        for tz_name in mapping.getAttribute('type').split(' '):
            tz_win[tz_name] = mapping.getAttribute('other')

    win_tz['Chatham Island Standard Time'] = 'Pacific/Chatham'
    tz_win['Pacific/Chatham'] = 'Chatham Island Standard Time'

    # Etc/UTC is a common alias for Etc/GMT:
    tz_win['Etc/UTC'] = 'UTC'
    logging.info("Writing windows_tz.py")
    with open('windows_tz.py', "wt") as out:
        out.write("# This file is autogenerated by the get_windows_info.py script (now in rv.misc.update_windows_tz())\n"
                  "# Do not edit.\nwin_tz = ")
        pprint.pprint(win_tz, out)
        out.write("\n# Old name for the win_tz variable:\ntz_names = win_tz\n\ntz_win = ")
        pprint.pprint(tz_win, out)
#----------------------------------------------------------------------------------------------------------------------------
def get_host_tz(host=None):
    key = r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation'
    win_tz, _ = read_registry_value(key, 'TimeZoneKeyName', computer=host)
    return get_pytz_from_wintz(win_tz)

#----------------------------------------------------------------------------------------------------------------------------
def get_pytz_from_wintz(win_tz):
    win_tz = _custom_wintz_map.get(win_tz, win_tz)
    return pytz.timezone(windows_tz.win_tz[win_tz])



#----------------------------------------------------------------------------------------------------------------------------
# credit to: https://gist.github.com/mnordhoff/2213179
# Python regular expressions for IPv4 and IPv6 addresses and URI-references,
# based on RFC 3986's ABNF.
#
# IPV4_RE and IPV6_RE are self-explanatory.
# IPV6Z_RE requires a zone ID (RFC 6874) follow the IPv6 address.
# IPV6_OR_Z_RE allows an IPv6 address with optional zone ID.
# URI_RE is what you think of as a URI. (It uses ipv6_address_or_addrz.)

IPV4_RE = re.compile('\\b(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\b')
IPV6_RE = re.compile('\\b(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)\\b')
IPV6Z_RE = re.compile('\\b(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)%25(?:[A-Za-z0-9\\-._~]|%[0-9A-Fa-f]{2})+\\b')
IPV6_OR_Z_RE = re.compile('\\b(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)(?:%25(?:[A-Za-z0-9\\-._~]|%[0-9A-Fa-f]{2})+)?\\b')
URI_RE = re.compile("\\b(?:([A-Za-z][A-Za-z0-9+\\-.]*):(?://((?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|:)*@)?(?:\\[(?:(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)(?:%25(?:[A-Za-z0-9\\-._~]|%[0-9A-Fa-f]{2})+)?|[Vv][0-9A-Fa-f]+\\.(?:[!$&'()*+,;=A-Za-z0-9\\-._~]|:)+)\\]|(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])*)(?::[0-9]*)?)((?:/(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])*)*)|(/(?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])+(?:/(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])*)*)?)|((?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])+(?:/(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])*)*)|())(?:\\?((?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])|[/?])*))?(?:#((?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])|[/?])*))?|(?://((?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|:)*@)?(?:\\[(?:(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)(?:%25(?:[A-Za-z0-9\\-._~]|%[0-9A-Fa-f]{2})+)?|[Vv][0-9A-Fa-f]+\\.(?:[!$&'()*+,;=A-Za-z0-9\\-._~]|:)+)\\]|(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])*)(?::[0-9]*)?)((?:/(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])*)*)|(/(?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])+(?:/(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])*)*)?)|((?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|@)+(?:/(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])*)*)|())(?:\\?((?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])|[/?])*))?(?:#((?:(?:(?:%[0-9A-Fa-f]{2}|[!$&'()*+,;=A-Za-z0-9\\-._~])|[:@])|[/?])*))?)\\b")

# MAC address - by RAM
MAC_RE = re.compile(r'\b(?:[0-9A-F]{4}\.[0-9A-F]{4}\.[0-9A-F]{4})|(?:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})\b', re.IGNORECASE)
#----------------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    print ("Testing intel ww functions")
    for year in range(1990, 2050):
        for w in range(year*100+1, year*100+53):
            d = intel_ww_to_date(w)
            #print (w, d, rv.misc.intel_date_to_ww(d))
            assert intel_date_to_ww(d) == w
        print (year, 'OK')
