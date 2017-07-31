import socket, time
import logging
import memcache
import collections

# ----------------------------------------------------------------------------------------------------------------------
class CachedDns:
    # -------------------------------------------------------------------------------------
    def __init__(self, memcache_server=["127.0.0.1:11211"], ttl_hours=24):
        logging.info("Using Memcached: {}".format(memcache_server))
        self._mc = memcache.Client(memcache_server)
        self._ttl_hours = 24
        self._stats = collections.defaultdict(int)

    # ------------------------------------------------------------------------------------------------------------------
    def lookup(self, host):
        '''
        looks up cache, if not found or older than ttl_hours, queries dns and cache
        '''
        if not host:
            return ''
        key = 'f:' + host.lower()  # memcache key for forward lookup
        self._stats['F_TOTAL'] += 1
        host_info = self._mc.get(key)
        #logging.info("From MEMCACHE: {}".format(host_info))
        if (not host_info) or (host_info[1] < time.time() - self._ttl_hours * 3600):
            if not host_info:
                self._stats['F_MISSES'] += 1
            else:
                self._stats['F_AGES'] += 1

            ip = ''
            try:
                #logging.info("DNS Lookup - {}".format(host))
                ip = socket.gethostbyname(host)
            except socket.gaierror as ex:
                logging.warning("DNS Lookup for '{}' failed: {}".format(host, str(ex)))

            host_info = (ip, time.time())
            ret = self._mc.set(key, host_info)
            if ret == 0:
                raise Exception("Memcache failure")
            if ip:
                r_host_info = (host, time.time())
                r_key = "r:" + ip
                ret = self._mc.set(r_key, r_host_info)
                if ret == 0:
                    raise Exception("Memcache failure for r_key: {} r_host_info: {}".format(r_key, r_host_info))
        return host_info[0]

    # ------------------------------------------------------------------------------------------------------------------
    def rlookup(self, ip):
        '''
        reverse looks up cache, if not found or older than ttl_hours, queries dns and cache
        '''
        if not ip:
            return ''
        r_key = 'r:' + ip.lower()  # memcache key for reverse lookup
        self._stats['R_TOTAL'] += 1
        r_host_info = self._mc.get(r_key)
        #logging.info("From MEMCACHE: {}".format(r_host_info))
        host_name = ip
        if (not r_host_info) or (r_host_info[1] < time.time() - self._ttl_hours * 3600):
            if not r_host_info:
                self._stats['R_MISSES'] += 1
            else:
                self._stats['R_AGES'] += 1

            try:
                #logging.info("DNS RLookup - {}".format(ip))
                host_name = socket.gethostbyaddr(ip)[0]
            except socket.error as ex:
                logging.debug("Reverse DNS Lookup for '{}' failed: {}".format(ip, str(ex)))
                pass
            r_host_info = (host_name.lower(), time.time())
            key = "f:" + host_name.lower()
            host_info = (ip, time.time())
            ret = self._mc.set_multi({key: host_info, r_key: r_host_info})
            if ret == 0:
                raise Exception("Memcache failure")
        return r_host_info[0]
    # ------------------------------------------------------------------------------------------------------------------
    def log_stats(self):
        logging.info("DnsCache Stats:")
        for n in ('ForwardLookup', 'ReverseLookup'):
            t = n[0]
            total, misses, ages = self._stats[t+"_TOTAL"], self._stats[t+'_MISSES'], self._stats[t+'_AGES']
            if total == 0:
                total = 1
            logging.info("{}: TOTAL = {} MISSES = {} ({:.1f}%) AGES = {}".format(n, total, misses, misses/total, ages))



#-----------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    import rv.misc

    rv.misc.set_logging()
    cdns = CachedDns()
    cdns.rlookup(cdns.lookup('fmscsfe101'))
    cdns.log_stats()