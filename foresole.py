#!/usr/bin/env python
# encoding: utf-8
"""
foresole.py

"""

import sys
import os
import uuid
import subprocess
from datetime import datetime

import sunburnt
import fiwalk

SOLR = sunburnt.SolrInterface("http://localhost:8983/solr", "../gumshoe/jetty/solr/conf/schema.xml")
IMAGE = sys.argv[1]

def epoch_to_dt(epoch):
    """Convert Unix epoch times into datetime.datetime objects."""
    if type(epoch) in (str, unicode):
        epoch = float(epoch)
    return datetime.fromtimestamp(epoch)

def fileobject_to_dict(fo):
    """Convert a fiwalk fileobject into a dict. Ignores unallocated fileobjects."""
    if fo.allocated():
        #proc = subprocess.Popen(['./extract_strings', fo.inode()], stdout=subprocess.PIPE)
        return {
            'atime_dt': epoch_to_dt(fo.atime()),
            'compressed_b': fo.compressed(),
            #'contents': proc.stdout.read(),
            'crtime_dt': epoch_to_dt(fo.crtime()),
            'ctime_dt': epoch_to_dt(fo.ctime()),
            'dtime_dt': epoch_to_dt(fo.dtime()),
            'encrypted_b': fo.encrypted(),
            'extension_facet': fo.ext(),
            'fileid_i': int(fo._tags['id']),
            'filename_display': fo.filename(),
            'filename_t': fo.filename(),
            'filesize_l': long(fo.filesize()),
            'fragments_i': int(fo.fragments()),
            'gid_i': int(fo._tags['gid']),
            'id': uuid.uuid4(),
            #'imagefile': fo._tags['imagefile'],
            'inode_i': int(fo.inode()),
            'libmagic_display': fo.libmagic(),
            'libmagic_facet': fo.libmagic(),
            'md5_s': fo.md5(),
            'meta_type_i': fo._tags['meta_type'],
            'mode_facet': int(fo._tags['mode']),
            'mode_i': int(fo._tags['mode']),
            'mtime_dt': epoch_to_dt(fo.mtime()),
            'nlink_i': fo._tags['nlink'],
            'name_type_s': fo.name_type(),
            'partition_i': int(fo.partition()),
            'sha1_s': fo.sha1(),
            'uid_i': int(fo._tags['uid']),
            'volume_display': IMAGE,
            'volume_facet': IMAGE
        }
    else:
        return None


def index_fobj(fobj):
    """Callback function to post a fileobject-dict to Solr."""
    doc = fileobject_to_dict(fobj)
    if doc is not None:
        #print doc
        SOLR.add(doc)
    else:
        pass
    
def main():
	fiwalk.fiwalk_using_sax(imagefile=file(IMAGE), callback=index_fobj)
	SOLR.commit()

if __name__ == '__main__':
	main()

