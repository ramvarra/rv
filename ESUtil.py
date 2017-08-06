import os, sys, re, pprint
import logging
import elasticsearch
import elasticsearch.helpers
import pandas as pd
import math
import datetime
import json
import time


import rv.misc

__author__ = 'Ram Varra'

#---------------------------------------------------------------------------------------
class ESUtil(object):
    # Max number of records allowed to returned from search
    _MAX_SIZE = 250 * 1000

    #---------------------------------------------------------------------------------------
    @staticmethod
    def SetMaxSize(max_size):
        ESUtil._MAX_SIZE = max_size

    #---------------------------------------------------------------------------------------
    def __init__(self, hosts='localhost:9200', **kwargs):
        self._es = elasticsearch.Elasticsearch(hosts=hosts, **kwargs)
        es_logger = logging.getLogger('elasticsearch')
        es_logger.setLevel(logging.ERROR)

    #---------------------------------------------------------------------------------------
    def _get_params(self, *args, **kwargs):
        p = {}
        p['convert_numeric'] = kwargs.pop('convert_numeric', True)
        p['convert_dates'] = kwargs.pop('convert_dates', 'coerce')
        p['_id'] = kwargs.pop('_id', False)
        if 'search_type' in kwargs:
            raise Exception("ESUtil.Exception: search_type should not be specified")

        return p
    #---------------------------------------------------------------------------------------
    def _make_df_from_recs(self, recs):
        df = pd.DataFrame(recs)
        df.fillna('')
        return df

    #---------------------------------------------------------------------------------------
    def _get_data_key(self, response_hit):
        if "_source" in response_hit:
            return "_source"
        if "fields" in response_hit:
            return 'fields'
        raise Exception ("returned hits do not contain either _source or fields")

    #---------------------------------------------------------------------------------------
    def _get_rec(self, x, data_key, include_id=True, include_index=False):
        if data_key == '_source':
            rec = x.get('_source', None)
        else:
            rec =  {k:v[0] for k,v in x.get('fields', {}).items()}
        if include_id:
            rec['_id'] = x['_id']
        if include_index:
            rec['_index'] = x['_index']
        return rec

    #---------------------------------------------------------------------------------------
    def _get_recs_from_es_response(self, es_response, include_id=True, include_index=False):
        failed_count = es_response.get('_shards', {}).get('failed', 0)
        if failed_count > 0:
            logging.error ("Query Failed with {} failed_count: {}".format(failed_count, pprint.pformat(es_response)))
            raise Exception("ESUtil: Query Failed")

        response_hits = es_response['hits']['hits']
        recs = []
        if len(response_hits) > 0:
            data_key = self._get_data_key(response_hits[0])
            recs.extend(self._get_rec(x, data_key, include_id=include_id, include_index=include_index) for x in response_hits)
        return recs
    #---------------------------------------------------------------------------------------
    def recs_search(self, include_id=True, include_index=False, *args, **kwargs):
        if kwargs.get('size', None) is None:
            kwargs['size'] = 1
            t = self._es.search(*args, **kwargs)
            kwargs['size'] = t['hits']['total']
            if kwargs['size'] > ESUtil._MAX_SIZE:
                raise Exception ("ESUtilError: Too large of size: {} - max allowed is {}".format(kwargs['size'], ESUtil._MAX_SIZE))

        es_response = self._es.search(*args, **kwargs)
        recs = self._get_recs_from_es_response(es_response, include_id=include_id, include_index=include_index)
        return (recs)
    #---------------------------------------------------------------------------------------
    def df_search(self, include_id=True, include_index=False, *args, **kwargs):
        recs = self.recs_search(*args, include_id=include_id, include_index=include_index, **kwargs)
        return self._make_df_from_recs(recs)

    #===============================================================================================================
    def _fetch_docs_chunk(self, index, doc_type, chunk_size, body=None, include_id=True, include_index=False):
        if body is None:
            body = {"query": {"match_all" : {}}}

        kwargs = dict(index=index, doc_type = doc_type, body = body, size = chunk_size)
        scroll = "5m"

        scroll_ret = self._es.search(search_type='scan', scroll=scroll, **kwargs)
        scroll_id = scroll_ret['_scroll_id']

        total_docs = scroll_ret['hits']['total']
        logging.info ("Expecting total: {}".format(total_docs))
        current_total_docs = 0
        while True:
            try:
                #logging.info("ScrollRet: {}".format(pprint.pformat(scroll_ret)))
                es_response = self._es.scroll(scroll_id=scroll_id, scroll=scroll)
                #logging.info("Resp: {}".format(pprint.pformat(es_response)))
            except elasticsearch.exceptions.NotFoundError as ex:
                break
            doc_count = len(es_response['hits']['hits'])

            if doc_count == 0:
                break

            current_total_docs += doc_count
            logging.info("Got {} recs - remaining {} {:.1f}% Completed".format(doc_count,
                                                            (total_docs - current_total_docs), (100.0 * current_total_docs)/total_docs))
            scroll_id = es_response['_scroll_id']

            yield self._get_recs_from_es_response(es_response, include_id=include_id, include_index=include_index) # _mkrecs(es_response)
    #--------------------------------------------------------------------------------------
    def recs_scan (self, index, doc_type, body=None, chunk_size=4*1024, include_id=True, include_index=False):
        """
        Extract records from ES.
        :param index: Name of index
        :param doc_type: Doc Type
        :param body: Search Query
        :param chunk_size: Scan scroll size. Actual size will be #SHARDS * chunk_size
        :return: Returns list of dicts with documents.
        """
        all_recs = []
        total_docs = 0
        with rv.misc.Timer() as total_time:
            for chunk in self._fetch_docs_chunk(index, doc_type, body=body, chunk_size=chunk_size, include_id=include_id, include_index=include_index):
                all_recs.extend(chunk)
                total_docs += len(chunk)
        rate = total_docs/total_time() if total_time() > 0 else -1
        logging.info("Scanned {} recs from index {} doc_type {}  - @{:.1f} recs/sec".format(total_docs, index, doc_type, rate))
        return all_recs
        
    #--------------------------------------------------------------------------------------
    def export_index_to_file(self, index, doc_type, out_file, include_id=True, include_index=True, chunk_size=4*1024,
                             sleep_time=10):
        """
        Export all documents from an index into file as JSON records. One document per line.
        :param index: Index name to export from.
        :param doc_type: DocType of docs to export.
        :param out_file: Name of the file to write to.
        :param chunk_size: Size used in the scroll. The number of records fetched for scroll/scan will the #SHARDS x chunk_size.
        :param include_id: Include _id field in the records.
        :param include_index: Include _index field in the records.
        :return: Total count of records expoorted.
        """
        logging.info("Fetching all docs from index {} doc_type {}".format(index, doc_type))
        total_docs = 0
        with rv.misc.Timer() as total_time:
            with open(out_file, "w") as fd:
                for chunk in self._fetch_docs_chunk(index=index, doc_type=doc_type, include_index=include_index,
                                                    include_id=include_id, chunk_size=chunk_size):
                    for rec in chunk:
                        json.dump(rec, fd)
                        fd.write('\n')
                    total_docs += len(chunk)
                    if sleep_time > 0 and len(chunk) == chunk_size:
                        logging.info("Sleeping for {} secs".format(sleep_time))
                        time.sleep(sleep_time)

        rate = total_docs/total_time() if total_time() > 0 else -1
        logging.info("Exported {} recs from index {} doc_type {} to file {} - @{:.1f} recs/sec".format(total_docs,
                                                                                index, doc_type, out_file, rate))
        return total_docs

    #---------------------------------------------------------------------------------------------------------------------------
    def load_recs_into_es(self, recs_to_load):
        ret = elasticsearch.helpers.bulk (self._es, recs_to_load)
        if ret:
            if ret[0] < len(recs_to_load):
                logging.error ("ERROR while Loading recs expected {} actual {}".format (len(recs_to_load), ret[0]))
                logging.error ('bulk  return: {}'.format (pprint.pformat(ret)))
                failed_recs = ret[1]
                logging.error ("{} records failed to load".format (len(failed_recs)))
                logging.info("Orignal records to load: {}".format(pprint.pformat(recs_to_load)))
                raise Exception("Failed")

            if ret[1]:
                raise Exception("ERRORS in bulk loading: {}".format (ret[1]))
            return ret[0]
    #---------------------------------------------------------------------------------------------------------------------------
    def _read_docs_from_file(self, in_file, chunk_size):
        recs = []
        file_size = float(os.path.getsize(in_file))
        with open(in_file, "r") as fd:
            while True:
                l = fd.readline ()
                if not l:
                    if recs:
                        yield (recs, 100*fd.tell()/file_size)
                    break

                recs.append(json.loads(l))
                if len(recs) == chunk_size:
                    yield (recs, 100*fd.tell()/file_size)
                    recs = []

    #---------------------------------------------------------------------------------------------------------------------------
    def _update_docs(self, docs, index, doc_type=None, ts_field=None, transform=None, prune_cols=False):
        if index or doc_type or transform or prune_cols:
            for doc in docs:
                if index:
                    doc['_index'] = doc[ts_field].strftime(index) if ts_field else index
                if doc_type:
                    doc['_type'] = doc_type
                if prune_cols:
                    to_drop = [k for k,v in doc.items() if v is None or pd.isnull(v) or
                               (isinstance(v, float) and math.isnan(v))]
                    for k in to_drop:
                        del doc[k]
                if transform:
                    transform(doc)

    #---------------------------------------------------------------------------------------------------------------------------
    def update_recs(self, recs, doc_type, chunk_size=10*1024, sleep_time=30):
        """
        Update records into ES using bulk api. Recs must contain '_id' and '_index' fields
        :param recs:  recs to load
        :param chunk_size: chunk size (#of records) used in bulk loading - default - 10K
        :param sleep_time: time between bulk load calls - grace time to avoid overloading ES (default = 30secs)
        :return: Total number of records loaded.
        """
        #---------------------------------------------------------------------------------------------------------------
        loaded_rec_count = 0
        with rv.misc.Timer() as total_time:
            for cur in range(0, len(recs), chunk_size):
                chunk = recs[cur:cur+chunk_size]
                if not len(chunk) > 0:
                    break

                if loaded_rec_count > 0 and sleep_time > 0:
                    logging.info("Sleeping {} secs".format(sleep_time))
                    time.sleep (sleep_time)
                urecs = []
                for r in chunk:
                    assert '_id' in r and '_index' in r, "_id or _index not found in rec: {}".format(r)
                    ur = {'_id': r['_id'], '_type': doc_type, '_index': r['_index'], '_op_type': 'update'}
                    ur['doc'] = {k: v for k,v in r.items() if not k[0] == '_'}
                    urecs.append(ur)

                logging.info("Sending: {} recs for update".format(len(urecs)))
                with rv.misc.Timer() as t:
                    l = self.load_recs_into_es(urecs)
                assert l == len(chunk)
                loaded_rec_count += l
                rate = l / t() if t() > 0 else -1
                pct_complete = loaded_rec_count * 100.0/len(recs)
                logging.info("Updated: {} @{:.1f} recs/sec - Total {}/{} {:.1f}% ".format(l, rate, loaded_rec_count,
                                                                                         len(recs), pct_complete))

        logging.info("Successfully updated - total recs: {}/{} Total time: {}".format(loaded_rec_count,
                                                                                          len(recs), total_time()))
        return loaded_rec_count

    #---------------------------------------------------------------------------------------------------------------------------
    def import_recs(self, recs, index=None, doc_type=None, ts_field=None, chunk_size=10*1024, sleep_time=30, transform=None):
        """
        Load Pandas data frame to specified index.
        :param recs:  recs to load
        :param index: document will be loaded into the index. It can be simple or strftime pattern (e.g log-%Y-%m-%d) in
                    which case, ts_field will be used to generate the value. If not specified, must be in recs
        :param doc_type: doc_type of the loaded records. If not specified, must be in recs
        :param chunk_size: chunk size (#of records) used in bulk loading - default - 10K
        :param sleep_time: time between bulk load calls - grace time to avoid overloading ES (default = 30secs)
        :param ts_field: ts_field in the doc for generating the index name (index name must be strftime pattern)
        :return: Total number of records loaded.
        """
        #---------------------------------------------------------------------------------------------------------------
        loaded_rec_count = 0
        with rv.misc.Timer() as total_time:
            for cur in range(0, len(recs), chunk_size):
                chunk = recs[cur:cur+chunk_size]
                if not len(chunk) > 0:
                    break

                if loaded_rec_count > 0 and sleep_time > 0:
                    logging.info("Sleeping {} secs".format(sleep_time))
                    time.sleep (sleep_time)

                self._update_docs(chunk, index=index, doc_type=doc_type, ts_field=ts_field, transform=transform)

                logging.info("Loading: {} recs into es index: {} type: {}".format(len(chunk), index, doc_type))
                with rv.misc.Timer() as t:
                    l = self.load_recs_into_es(chunk)
                assert l == len(chunk)
                loaded_rec_count += l
                rate = l / t() if t() > 0 else -1
                pct_complete = loaded_rec_count * 100.0/len(recs)
                logging.info("Loaded: {} @{:.1f} recs/sec - Total {}/{} {:.1f}% ".format(l, rate, loaded_rec_count,
                                                                                         len(recs), pct_complete))

        logging.info("Successfully imported - total recs: {}/{} Total time: {}".format(loaded_rec_count,
                                                                                          len(recs), total_time()))
        return loaded_rec_count
    #---------------------------------------------------------------------------------------------------------------------------
    def import_docs_from_df(self, df, index=None, doc_type=None, ts_field=None, chunk_size=10*1024, sleep_time=30, transform=None, prune_cols=False):
        """
        Load Pandas data frame to specified index.
        :param df:  data frame to load
        :param index: document will be loaded into the index. It can be simple or strftime pattern (e.g log-%Y-%m-%d) in
                    which case, ts_field will be used to generate the value. If not specified, must be in df
        :param doc_type: doc_type of the loaded records. if not specified, must be in df.
        :param chunk_size: chunk size (#of records) used in bulk loading - default - 10K
        :param sleep_time: time between bulk load calls - grace time to avoid overloading ES (default = 30secs)
        :param ts_field: ts_field in the doc for generating the index name (index name must be strftime pattern)
        :param prune_cols:  Remove the fields that are None or Null values from the records loaded.
        :return: Total number of records loaded.
        """
        #---------------------------------------------------------------------------------------------------------------
        loaded_rec_count = 0
        with rv.misc.Timer() as total_time:
            for cur in range(0, len(df), chunk_size):
                chunk = df[cur:cur+chunk_size].to_dict('records')
                if not len(chunk) > 0:
                    break

                if loaded_rec_count > 0 and sleep_time > 0:
                    logging.info("Sleeping {} secs".format(sleep_time))
                    time.sleep (sleep_time)

                self._update_docs(chunk, index=index, doc_type=doc_type, ts_field=ts_field, transform=transform, prune_cols=prune_cols)
                logging.info("Loading: {} recs into es index: {} type: {}".format(len(chunk), index, doc_type))
                with rv.misc.Timer() as t:
                    l = self.load_recs_into_es(chunk)
                assert l == len(chunk)
                loaded_rec_count += l
                rate = l / t() if t() > 0 else -1
                pct_complete = loaded_rec_count * 100.0/len(df)
                logging.info("Loaded: {} @{:.1f} recs/sec - Total {}/{} {:.1f}% ".format(l, rate, loaded_rec_count,
                                                                                         len(df), pct_complete))

        logging.info("Successfully imported df - total recs: {}/{} Total time: {}".format(loaded_rec_count,
                                                                                          len(df), total_time()))
        return loaded_rec_count

    #---------------------------------------------------------------------------------------------------------------------------
    def import_docs_from_file(self, in_file, chunk_size=10*1024, sleep_time=30, index=None, doc_type=None,
                              transform=None):
        """
        Load JSON documents from a file to specified index.
        :param in_file:  in_file should contain one record per line (produced by esu.export_index_to_file)
        :param chunk_size: chunk size (#of records) used in bulk loading - default - 10K
        :param sleep_time: time between bulk load calls - grace time to avoid overloading ES (default = 30secs)
        :param index: If specified - document will be loaded into the index. If not specified documents in the file must contain the _index field.
        :param doc_type: If not specified documents in the file must contain the _type field.
        :param transformer: function used to transform the source docs. Default is None
        :return: Total number of records loaded.
        """
        loaded_rec_count = 0
        with rv.misc.Timer() as total_time:
            for chunk, pct_complete in self._read_docs_from_file(in_file, chunk_size):
                if loaded_rec_count > 0 and sleep_time > 0:
                    logging.info("Sleeping {} secs".format(sleep_time))
                    time.sleep (sleep_time)

                self._update_docs(chunk, index=index, doc_type=doc_type, transform=transform)
                ix = chunk[0]['_index']
                tp = chunk[0]['_type']
                logging.info("Loading: {} recs into es index: {} type: {}".format(len(chunk), ix, tp))
                with rv.misc.Timer() as t:
                    l = self.load_recs_into_es(chunk)
                assert l == len(chunk)
                loaded_rec_count += l
                rate = l / t() if t() > 0 else -1
                logging.info("Loaded: {} @{:.1f} recs/sec - Total {} {:.1f}% ".format(l, rate, loaded_rec_count,
                                                                                      pct_complete))

        logging.info("Successfully imported file {} - total recs: {} total time: {} secs".format(in_file,
                                                                                    loaded_rec_count, total_time()))
        return loaded_rec_count

    #-------------------------------------------------------------------------------------------
    def _make_map(self, doc_type, props):
            mapping = {
                doc_type: {
                    "_all": {
                        "enabled": False
                    },
                    "dynamic_templates": [
                        {
                            "strings": {
                                "match_mapping_type": "string",
                                "mapping": {
                                    "type": "keyword"
                                }
                            }
                        }
                    ],
                    "properties": props
                }
            }

            return mapping


    #-------------------------------------------------------------------------------------------
    def get_props_from_recs(self, recs, analyzed_fields=None):

        if isinstance(recs, dict):
            recs = [recs]

        str_props = {'type': 'keyword'}
        date_props = {'type': 'date'}
        type_map = {
            str: str_props,
            datetime.datetime: date_props,
            datetime.date: date_props,
            pd.Timestamp: date_props,
            int: {'type': 'integer'},
            bool: {'type': 'boolean'},
            float: {'type': 'double'},
            dict: {'type': 'nested', "include_in_root": True},
            'geo_point': {'type': 'geo_point'},
        }

        props = {}
        for r in recs:
            for k, v in r.items():
                if k.startswith('_'):
                    continue

                if isinstance(v, list) or isinstance(v, tuple):
                    if len(v) == 0:
                        continue
                    type_v = type(v[0])
                elif v is None:
                    continue
                elif isinstance(v, dict) and set(v.keys()) == {'lat', 'lon'}:
                    type_v = 'geo_point'
                else:
                    type_v = type(v)

                if type_v not in type_map:
                    raise Exception("Invalid type '{}' for field '{}' in rec:\n{}".format(type_v, k,
                                                                                          pprint.pformat(r)))
                if k in props:
                    old_type, current_type  = props[k], type_map[type_v]
                    if old_type != current_type:
                        raise Exception("Type of field '{}' was {} - now {} - incompatible change".format(k,
                                                                                    old_type, current_type))
                else:
                    props[k] = type_map[type_v]

        if analyzed_fields:
            for f in analyzed_fields:
                assert props[f]['type'] == 'keyword'
                props[f]['type'] = 'text'
        return props

    # ------------------------------------------------------------------------------------------------------------------
    def get_mappings_from_props(self, props):
        return {
            "_default_": {
                "_all": {
                    "enabled": False
                },
                "dynamic_templates": [
                    {
                        "strings": {
                            "match_mapping_type": "string",
                            "mapping": {"type": "keyword"}
                        }
                    }
                ],
                "properties": props
            }
        }


    #-------------------------------------------------------------------------------------------------------------------
    def get_mappings_from_recs(self, recs, analyzed_fields=None):
        props = self.get_props_from_recs(recs, analyzed_fields)
        return self.get_mappings_from_props(props)

    #-------------------------------------------------------------------------------------------------------------------
    def create_template(self, template_name, index_pattern, mappings, settings=None):
        if settings is None:
            settings = {
                "number_of_shards": 2,
                "number_of_replicas": 0
            }

        template_body = {
            "template": index_pattern,
            "settings": settings,
            "mappings": mappings,
        }
        logging.info ("Creating Template {}".format (template_name))
        if self._es.indices.exists_template (template_name):
            logging.info ("Template {} already exist. Deleting it to recreate...".format (template_name))
            try:
                logging.info (self._es.indices.delete_template (template_name))
            except elasticsearch.exceptions.NotFoundError:
                logging.info ("Template {} was not present...".format (template_name))

        logging.info ("Creating the template: {}".format (template_name))
        logging.info ('Template body: {}'.format (pprint.pformat (template_body)))
        try:
            ret = self._es.indices.put_template (name=template_name, body=template_body, order=0)
        except elasticsearch.ElasticsearchException as ex:
            raise Exception("Failed to create template: {} - Exc: {}".format(template_name, pprint.pformat(ex.args)))

        logging.info('Result of create template: {}'.format(ret))

    #-------------------------------------------------------------------------------------------------------------------
    def create_index(self, index, props, settings=None, force=False):
        if self._es.indices.exists(index):
            if not force:
                raise Exception("Index {} already exists and Force is false".format(index))
            logging.info("Deleting existing index '%s'...", index)
            res = self._es.indices.delete(index=index)
            assert res['acknowledged'], "Failed to delete index {}: {}".format(index, res)
        logging.info("Creating index '{}' ...".format(index))
        body = {'mappings': self._get_mappings_from_props(props)}
        if settings:
            body['settings'] = settings
        res = self._es.indices.create(index=index, body=body)
        assert res['acknowledged'], "Failed to create index {}: {}".format(index, res)
        return True
    #--------------------------------------------------------------------------------------------------
    def get_max(self, index, doc_type, field, **kwargs):
        ''' this one seem to return millisec resolution
            queries time from ts_field, kwargs should specify additional fields to filter the records.
            e.g self._get_max_timestamp ('host_ts', host='DEVBOX', log_dir_src='AdapterLogs')
            Usage: t = esu.get_max(index='cdr_erv-*', doc_type='cdr_erv', field='SessionIdTime')
        '''

        max_ts_query = {
            "query" : { "match_all" : {}},
            "fields" : [ field ],
            "sort": [{ field: {"order": "desc", "ignore_unmapped" : True} }],
            "size": 1
        }

        list_of_terms = []
        for k, v in kwargs.items():
            if v is not None:
                list_of_terms.append({"term": {k: v}})

        if list_of_terms:
            max_ts_query['filter'] = {
                "bool": {
                    "must": list_of_terms
                }
            }

        #logging.info ("Running es.search query on {}: {}".format(self._get_index_wild (), pprint.pformat(max_ts_query)))
        try:
            result = self._es.search(index=index, doc_type=doc_type, body=max_ts_query)
        except elasticsearch.exceptions.NotFoundError as ex:
            logging.info ("NotFound Exception: {} in query:\n{}".format (ex, pprint.pformat(max_ts_query)))
            return None

        if len(result['hits']['hits']):
            ts = result['hits']['hits'][0]['fields'][field][0]
            return ts
        #logging.info ("max_ts_query '{}' returned no hits: \nresult = {}".format(pprint.pformat(max_ts_query), pprint.pformat(result)))
        return None
    #-------------------------------------------------------------------------------------------------------------------
    def re_index(self, index_wild, doc_type, transform, temp_folder=r'D:\TEMP'):
        index_file_list = []

        logging.info("Reindex Index Pattern - {}".format(index_wild))

        for index in sorted(self._es.indices.get(index_wild).keys()):
            f = os.path.join(temp_folder, "{}.json".format(index))
            assert not os.path.exists(f), "File {} already exist".format(f)
            index_file_list.append((index, f))

        for index,f  in index_file_list:
            logging.info('Reindexing: index {} - using Temp file {}'.format(index, f))
            self.export_index_to_file(index=index, doc_type=doc_type, out_file=f, include_id=True, sleep_time=1)
            logging.info("Deleting index: {}".format(index))
            self._es.indices.delete(index=index)
            assert not self._es.indices.exists(index=index)
            self.import_docs_from_file(index=index, doc_type=doc_type, in_file=f, transform=transform, sleep_time=1)

    # -------------------------------------------------------------------------------------------------------------------
    def pruned(self, rec):
        return {k: v for k, v in rec.items() if not(v is None or pd.isnull(v) or
                                                    (isinstance(v, float) and math.isnan(v)))}