'''
Module to lookup ip address to Geo IP
'''
import os
import geoip2.database
import logging
import ipaddress

class GeoIP:
    # Download GeoLite2 City and GeoLite2 ASN from: https://dev.maxmind.com/geoip/geoip2/geolite2/
    # place .mmdb fies in _DIR location
    _DIR = r'C:\TOOLS\DATA' if os.name == 'nt' else r'/DATA/MAXMIND.GEOIP2'
    _CITY_DB = os.path.join(_DIR, 'GeoLite2-City.mmdb')
    _ASN_DB = os.path.join(_DIR, 'GeoLite2-ASN.mmdb')

    #--------------------------------------------------------------------------------------
    def __init__(self):
        for f in [self._CITY_DB, self._ASN_DB]:
            if not os.path.exists(f):
                msg = "Can not find {} - install it from https://dev.maxmind.com/geoip/geoip2/geolite2/".format(f)
                logging.error(msg)
                raise Exception(msg)

        self.city_reader = geoip2.database.Reader(self._CITY_DB)
        self.asn_reader = geoip2.database.Reader(self._ASN_DB)
    # --------------------------------------------------------------------------------------
    def lookup(self, ip):
        r = {}
        if ip.startswith('192.168.') or ip.startswith('10.') or ipaddress.ip_address(ip).is_private:
            return r
        try:
            asn = self.asn_reader.asn(ip)
            r['org'] = asn.autonomous_system_organization
        except geoip2.errors.AddressNotFoundError:
            pass

        try:
            city = self.city_reader.city(ip)
            r['city'] = city.city.name
            r['country'] = city.country.name
            r['loc'] = {'lat': city.location.latitude, 'lon': city.location.longitude}
        except geoip2.errors.AddressNotFoundError:
            pass
        return r

#----------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    import rv.misc
    rv.misc.set_logging()
    geoip = GeoIP()
    for ip in ['172.217.4.132', '192.168.1.10']:
        print('{} = {}'.format(ip, geoip.lookup(ip)))

