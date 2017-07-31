import requests
import pprint
from xml.etree import ElementTree as etree
#------------------------------------------------------------------------------------------------------------------
def _node_to_dict(n):
    return {sub_n.tag: (_node_to_dict(sub_n) if len(sub_n) else sub_n.text) for sub_n in n}
#------------------------------------------------------------------------------------------------------------------
def _get_errors(xml):
    errs = []
    for msg in xml.findall('message'):
        text  = msg.find('text').text
        code = msg.find('code').text
        if code != '0':
            errs.append("Code {}: {}".format(code, text))
    return errs
#------------------------------------------------------------------------------------------------------------------
def search(ZWSID, address, citystatezip):
    url = 'http://www.zillow.com/webservice/GetSearchResults.htm'
    params = {
                'address': address,
                'citystatezip': citystatezip,
                'zws-id': ZWSID,
            }
    resp = requests.get(url, params=params)
    resp.raise_for_status()
    xml = etree.fromstring(resp.text)
    errs = _get_errors(xml)
    if errs:
        raise Exception("ZillowRequest to URL {} with Params: {} Failed\n{}".format(url, params, '\n'.join(errs)))

    results = [_node_to_dict(res) for res in xml.findall('response/results/result')]
    if not results:
        raise Exception("ZillowRequest to URL {} with Params: {} Returned no results: XML Resp: {}".format(url, params, etree.tostring(xml)))
    assert len(results) == 1, "ZillowRequest to URL {} with Params: {} Returned > 1 result: XML Resp: {}".format(url, params, etree.tostring(xml))
    return results[0]
#------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    address = '4204 W Shannon St'
    zipcode = '85226'
    ZWSID = '<YOUR_ZWSID>'
    print("Searching '{} {}".format(address, zipcode))
    res = search(ZWSID, address, zipcode)
    pprint.pprint(res)
    print('Estimated Price: {}'.format(res['zestimate']['amount']))
