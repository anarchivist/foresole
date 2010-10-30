#!/usr/bin/env python
# encoding: utf-8
"""
foresole.py

"""

import sys
import os

import sunburnt
from fiwalk import fileobjects_using_sax

solr = sunburnt.SolrInterface("http://localhost:8983", "schema.xml")

def fileobject_to_dict(fo):
    return {
        'atime': fo.atime(),
        'compressed': fobj.compressed(),
        'crtime': fo.crtime(),
        'ctime': fo.ctime(),
        'dtime': fo.dtime(),
        'encrypted': fo.encrypted(),
        'extension': fo.ext(),
        'filename': fo.filename(),
        'filesize': fo.filesize(),
        'fragments': fo.fragments(),
        'gid': fo._tags['gid'],
        'fileid': fo._tags['id'],
        'imagefile': fo._tags['imagefile'],
        'inode': fo.inode(),
        'libmagic': fo.libmagic(),
        'md5': fo.md5(),
        'meta_type': fo._tags['meta_type'],
        'mode': fo._tags['mode'],
        'mtime': fo.mtime(),
        'nlink': fo._tags['nlink'],
        'name_type': fo.name_type(),
        'partition': fo.partition(),
        'sha1': fo.sha1(),
        'uid': fo._tags['uid'],
    }
    
def main():
	xml = sys.argv[1]
	for fobj in fileobjects_using_sax(file(xml)):
	    if not fobj.allocated():
	        pass
	    else:
	        fod = fileobject_to_dict(fo)
	        solr.add(fod)
	solr.commit()


if __name__ == '__main__':
	main()

