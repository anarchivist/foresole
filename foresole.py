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

SOLR = sunburnt.SolrInterface("http://localhost:8983/solr", "solr/conf/schema.xml")

def epoch_to_dt(epoch):
    """Convert Unix epoch times into datetime.datetime objects."""
    if type(epoch) in (str, unicode):
        epoch = float(epoch)
    return datetime.fromtimestamp(epoch)

def fileobject_to_dict(fo):
    """Convert a fiwalk fileobject into a dict. Ignores unallocated fileobjects."""
    if fo.allocated():
        proc = subprocess.Popen(['./extract_strings', fo.inode()], stdout=subprocess.PIPE)
        return {
            'atime': epoch_to_dt(fo.atime()),
            'compressed': fo.compressed(),
            'contents': proc.stdout.read(),
            'crtime': epoch_to_dt(fo.crtime()),
            'ctime': epoch_to_dt(fo.ctime()),
            'dtime': epoch_to_dt(fo.dtime()),
            'encrypted': fo.encrypted(),
            'extension': fo.ext(),
            'fileid': int(fo._tags['id']),
            'filename': fo.filename(),
            'filesize': long(fo.filesize()),
            'fragments': int(fo.fragments()),
            'gid': int(fo._tags['gid']),
            'id': uuid.uuid4(),
            #'imagefile': fo._tags['imagefile'],
            'inode': int(fo.inode()),
            'libmagic': fo.libmagic(),
            'md5': fo.md5(),
            'meta_type': fo._tags['meta_type'],
            'mode': int(fo._tags['mode']),
            'mtime': epoch_to_dt(fo.mtime()),
            'nlink': fo._tags['nlink'],
            'name_type': fo.name_type(),
            'partition': int(fo.partition()),
            'sha1': fo.sha1(),
            'uid': int(fo._tags['uid']),
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
	xml = sys.argv[1]
	fiwalk.fiwalk_using_sax(xmlfile=file(xml), callback=index_fobj)
	SOLR.commit()

if __name__ == '__main__':
	main()

