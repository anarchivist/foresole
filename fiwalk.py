#!/usr/bin/env python
#
# %%% BEGIN NO FILL
"""fiwalk module
This module contains a number of classes for dealing with fiwalk objects, both using
the XML DOM model and using the EXPAT model.

byteruns() is function that returns an array of byterun objects.
Each object has the attributes:
  file_offset - offset from the beginning of the file
  img_offset  - offset from the beginning of the image
  bytes       - the number of bytes
  fs_offset   - offset from the beginning of the file system

where encoding, if present, is 0 for raw, 1 for NTFS compressed.

"""
from sys import stderr
from subprocess import Popen,PIPE

"Flags"
ALLOC_ONLY = 1

def isone(x):
    """Return true if something is one (number or string)"""
    try:
        return int(x)==1;
    except TypeError:
        return False

class byterun:
    """The internal representation for a byte run. Originally this was an array,
    which is faster than an attributed object. But this approach is more expandable,
    and it's only 70% the speed of an array under Python3.0.
    """
    __slots__ = ["file_offset","img_offset","bytes","fill","sector_size"]
    def __init__(self,img_offset=None,bytes=None):
        if img_offset!=None: self.img_offset = img_offset
        if bytes!=None: self.bytes = bytes
        self.sector_size = 512          # default

    def __cmp__(self,other):
        return cmp(self.img_offset,other.img_offset)

    def __str__(self):
        try:
            return "byterun[img_offset=%d; file_offset=%d bytes=%d] " % (self.img_offset,self.file_offset,self.bytes)
        except AttributeError:
            pass
        try:
            return "byterun[file_offset=%d; fill=%d; bytes=%d]" % (self.file_offset,self.fill,self.bytes)
        except AttributeError:
            return "byterun[<unknown>]"
    
    def start_sector(self):
        return self.img_offset // self.sector_size

    def sector_count(self):
        return self.bytes // self.sector_size

    def has_sector(self,s):
        if self.sector_size==0: raise ValueError,"%s: sector_size cannot be 0" % (self)
        try:
            return self.img_offset <= s * self.sector_size < self.img_offset+self.bytes
        except AttributeError:
            # Doesn't have necessary attributes to answer true.
            # Usually this happens with runs of a constant value
            return False       

    def extra_bytes(self):
        return self.bytes % self.sector_size

    def decode_xml_attributes(self,attr):
        self.fill=None
        if attr.has_key('file_offset'):
            self.file_offset = int(attr['file_offset'].value)
        if attr.has_key('start') :
            self.img_offset  = int(attr['start'].value)
        if attr.has_key('img_offset'):
            self.img_offset  = int(attr['img_offset'].value)
        if attr.has_key('len'):
            self.bytes       = int(attr['len'].value)
        if attr.has_key('fs_offset'):
            self.fs_offset   = int(attr['fs_offset'].value)
        if attr.has_key('fill') :
            self.fill = int(attr['fill'].value)
        
    def decode_sax_attributes(self,attr):
        self.fill=None
        if attr.has_key('file_offset'):
            self.file_offset = int(attr['file_offset'])
        if attr.has_key('start') :
            self.img_offset  = int(attr['start'])
        if attr.has_key('img_offset'):
            self.img_offset  = int(attr['img_offset'])
        if attr.has_key('len'):
            self.bytes       = int(attr['len'])
        if attr.has_key('fs_offset'):
            self.fs_offset   = int(attr['fs_offset'])
        if attr.has_key('fill') :
            self.fill = int(attr['fill'])
        

def safeInt(x):
    if x: return int(x)
    return False
#    return int(x) if x else False

class fileobject:
    """The base class for file objects created either through XML DOM or EXPAT"""
    TIMETAGLIST=['atime','mtime','ctime','dtime','crtime']

    def __init__(self,imagefile=None):
        self.imagefile = imagefile
        
    def __str__(self):
        try:
            fn = self.filename()
        except KeyError:
            fn = "???"
        return "fileobject %s byte_runs: %s" % (fn, " ".join([str(x) for x in self.byteruns()]))

    def partition(self):
        """Partion number of the file"""
        return self.tag("partition")

    def filename(self):
        """Name of the file"""
        return self.tag("filename")

    def ext(self):
        """Extension, as a lowercase string without the leading '.'"""
        import os, string
        (base,ext) = os.path.splitext(self.filename())
        if ext == '':
            return None
        else:
            return string.lstrip(ext, '\.')

    def filesize(self):
        """Size of the file, in bytes"""
        return safeInt(self.tag("filesize"))

    def uid(self):
        """UID of the file"""
        return safeInt(self.tag("uid"))

    def gid(self):
        """GID of the file"""
        return safeInt(self.tag("gid"))

    def ctime(self):
        """Metadata Change Time (sometimes Creation Time), as number of seconds
        since January 1, 1970 (Unix time)"""
        return safeInt(self.tag("ctime"))   
        
    def atime(self):
        """Access time, as number of seconds since January 1, 1970 (Unix time)"""
        return safeInt(self.tag("atime"))   
        
    def crtime(self):
        """CR time, as number of seconds since January 1, 1970 (Unix time)"""
        return safeInt(self.tag("crtime"))  
        
    def mtime(self):
        """Modify time, as number of seconds since January 1, 1970 (Unix time)"""
        return safeInt(self.tag("mtime"))  
        
    def dtime(self):
        """ext2 dtime"""
        return safeInt(self.tag("dtime"))

    def times(self):
        """Return a dictionary of all times that the system has"""
        ret = {}
        for tag in self.TIMETAGLIST:
            if self.has_tag(tag):
                try:
                    ret[tag] = safeInt(self.tag(tag))
                except TypeError:
                    pass
        return ret

    def sha1(self):
        """Returns the SHA1 in hex"""
        return self.tag("sha1")

    def md5(self):
        """Returns the MD5 in hex"""
        return self.tag("md5")

    def fragments(self):
        """Returns number of file fragments"""
        return len(self.byteruns())

    def name_type(self):
        """Return the contents of the name_type tag"""
        return self.tag("name_type")

    def inode(self):
        """Inode; may be a number or SleuthKit x-y-z formatr"""
        return self.tag("inode")

    def allocated(self):
        """Returns True if the file is allocated, False if it was not
        (that is, if it was deleted or is an orphan).
        Note that we need to be tolerant of mixed case, as it was changed.
        """
        if self.filename()=="$OrphanFiles": return False
        return isone(self.tag("alloc")) or isone(self.tag("ALLOC"))

    def compressed(self):
        if not self.has_tag("compressed") and not self.has_tag("compressed") : return False
        return isone(self.tag("compressed")) or isone(self.tag("COMPRESSED"))

    def encrypted(self):
        if not self.has_tag("encrypted") and not self.has_tag("encrypted") : return False
        return isone(self.tag("encrypted")) or isone(self.tag("ENCRYPTED"))

    def file_present(self,imagefile=None):
        """Returns true if the file is present in the disk image"""
        import hashlib
        if self.filesize()==0:
            return False               # empty files are never present
        if imagefile==None:
            imagefile=self.imagefile # use this one
        for hashname in ['md5','sha1']:
            oldhash = self.tag(hashname)
            if oldhash:
                newhash = hashlib.new(hashname,self.contents(imagefile=imagefile)).hexdigest()
                return oldhash==newhash
        raise ValueError,"Cannot process file "+self.filename()+": no hash in "+str(self)

    def has_contents(self):
        """True if the file has one or more bytes"""
        return len(self.byteruns())>0

    def has_sector(self,s):
        """True if sector s is contained in one of the byteruns."""
        for run in self.byteruns():
            if run.has_sector(s): return True
        return False

    def libmagic(self):
        """Returns libmagic string if the string is specified
           in the xml, or None otherwise"""
        return self.tag("libmagic")
    def content_for_run(self,run=None,imagefile=None):
        """ Returns the content for a specific run. This is a convenience feature
        which does not touch the file object if an imagefile is provided."""
        if imagefile==None: imagefile=self.imagefile
        if run.bytes== -1:
            return chr(0) * run.bytes
        elif run.fill is not None : 
            return chr(run.fill) * run.bytes
        else:
            imagefile.seek(run.img_offset)
            return imagefile.read(run.bytes)

    def contents(self,imagefile=None,icat_fallback=True):
        """ Returns the contents of all the runs concatenated together. For allocated files
        this should be the original file contents. """
        if imagefile is None     : imagefile=self.imagefile
        if imagefile is None     : raise ValueError,"imagefile is unknown"
        if self.encrypted()      : raise ValueError,"Cannot generate content for encrypted files"
        if self.compressed() or imagefile.name.endswith(".aff") or imagefile.name.endswith(".E01"):
            if icat_fallback:
                # 
                # For now, compressed files rely on icat rather than python interface
                #
                offset     = safeInt(self.volume.offset)
                block_size = safeInt(self.volume.block_size)
                if block_size==0: block_size = 512
                inode = self.inode()
                if inode :
                    block_size = 512
                    cmd = ['icat','-b',str(block_size),'-o',str(offset/block_size),imagefile.name,str(inode)] 
                    (data,err) = Popen(cmd, stdout=PIPE,stderr=PIPE).communicate()
                    # Check for an error
                    if len(err) > 0 :  
                        raise ValueError, "icat error: "+" ".join(cmd)
                    return data
                else :
                    raise ValueError, "Inode missing from file in compressed format."
            raise ValueError,"Cannot read raw bytes in compressed disk image"
        res = []
        for run in self.byteruns():
            res.append(self.content_for_run(run=run,imagefile=imagefile))
        return "".join(res)

    def tempfile(self,calcMD5=False,calcSHA1=False):
        """Return the contents of imagefile in a named temporary file. If
        calcMD5 or calcSHA1 are set TRUE, then the object returned has a
        haslib object as self.md5 or self.sha1 with the requested hash."""
        import tempfile,hashlib
        tf = tempfile.NamedTemporaryFile()
        if calcMD5: tf.md5 = hashlib.md5()
        if calcSHA1: tf.sha1 = hashlib.sha1()
        for run in self.byteruns():
            self.imagefile.seek(run.img_start)
            count = run.bytes
            while count>0:
                xfer_bytes = min(count,1024*1024)        # transfer up to a megabyte at a time
                buf = self.imagefile.read(xfer_bytes)
                tf.write(buf)
                if calcMD5: tf.md5.update(buf)
                if calcSHA1: tf.sha1.update(buf)
                count -= xfer_bytes
        tf.flush()
        return tf
        
    def frag_start_sector(self,fragment):
        return self.byteruns()[fragment].img_offset / 512

    def name_type(self):
        return self.tag("name_type")

class fileobject_dom(fileobject):
    """file objects created through the DOM. Each object has the XML document
    stored in the .doc attribute."""    
    def __init__(self,xmldoc,imagefile=None):
        fileobject.__init__(self,imagefile=imagefile)
        self.doc = xmldoc

    def tag(self,name):
        """Returns the wholeText for any given NAME. Raises KeyError
        if the NAME does not exist."""
        try:
            return self.doc.getElementsByTagName(name)[0].firstChild.wholeText
        except IndexError:
            # Check for a hash tag with legacy API
            if name in ['md5','sha1','sha256']:
                for e in self.doc.getElementsByTagName('hashdigest'):
                    if e.getAttribute('type').lower()==name:
                        return e.firstChild.wholeText
            raise KeyError,name+" not in XML"

    def has_tag(self,name) :
        try:
            temp=self.doc.getElementsByTagName(name)[0].firstChild.wholeText
            return True
        except IndexError:
            # Check for a hash tag with legacy API
            if name in ['md5','sha1','sha256']:
                for e in self.doc.getElementsByTagName('hashdigest'):
                    if e.getAttribute('type').lower()==name:
                        return True
            return False
    
    def byteruns(self):
        """Returns a sorted array of byterun objects.
        """
        ret = []
        try:
            for run in self.doc.getElementsByTagName("byte_runs")[0].childNodes:
                b = byterun()
                if run.nodeType==run.ELEMENT_NODE:
                    b.decode_xml_attributes(run.attributes)
                    ret.append(b)
        except IndexError:
            pass
        ret.sort(key=lambda r:r.file_offset)
        return ret



class saxobject:
    # saxobject is a mix-in that makes it easy to turn XML tags into functions.
    # If the sax tag is registered, then a function with the tag's name is created.
    # Calling the function returns the value for the tag that is stored in the _tags{}
    # dictionary. The _tags{} dictionary is filled by the _end_element() method that is defined.
    # For fileobjects all tags are remembered.
    def __init__(self):
        self._tags     = {}
    def tag(self,name):
        """Returns the XML text for a given NAME."""
        return self._tags.get(name,None)
    def has_tag(self,name) : return name in self._tags

def register_sax_tag(tagclass,name):
    setattr(tagclass,name,lambda self:self.tag(name))

class fileobject_sax(fileobject,saxobject):
    """file objects created through expat. This class is created with a tags array and a set of byte runs."""
    def __init__(self,imagefile=None,xml=None):
        fileobject.__init__(self,imagefile=imagefile)
        saxobject.__init__(self)
        self._byteruns = []
    def byteruns(self):
        """Returns an array of byterun objects."""
        return self._byteruns


class volumeobject_sax(saxobject):
    """A class that represents the volume."""
    def __init__(self):
        self.offset = 0
        self.block_size = 0

    def __str__(self):
        return "volume "+(str(self._tags))

    def partition_offset(self):
        try:
            return self.tag('partition_offset')
        except KeyError:
            return self.tag('Partition_Offset')

register_sax_tag(volumeobject_sax,'ftype')
register_sax_tag(volumeobject_sax,'ftype_str')
register_sax_tag(volumeobject_sax,'block_count')
register_sax_tag(volumeobject_sax,'first_block')
register_sax_tag(volumeobject_sax,'last_block')
    
class imageobject_sax(saxobject):
    """A class that represents the disk image"""
register_sax_tag(imageobject_sax,'imagesize')
register_sax_tag(imageobject_sax,'image_filename')


################################################################

################################################################

def fiwalk_installed_version(fiwalk='fiwalk'):
    """Return the current version of fiwalk that is installed"""
    from subprocess import Popen,PIPE
    import re
    for line in Popen([fiwalk,'-V'],stdout=PIPE).stdout.read().split("\n"):
        g = re.search("^FIWalk Version:\s+(.*)$",line)
        if g:
            return g.group(1)
    return None

class XMLDone(Exception):
    def __init__(self,value):
        self.value = value

def fiwalk_xml_version(filename=None):
    """Returns the fiwalk version that was used to create an XML file.
    Uses the "quick and dirt" approach to getting to getting out the XML version."""

    in_element = set()
    cdata = ""
    version = None
    def start_element(name,attrs):
        global cdata
        in_element.add(name)
        cdata = ""
    def end_element(name):
        global cdata
        if ("fiwalk" in in_element) and ("creator" in in_element) and ("version" in in_element):
            raise XMLDone(cdata)
        if ("fiwalk" in in_element) and ("fiwalk_version" in in_element):
            raise XMLDone(cdata)
        in_element.remove(name)
        cdata = ""
    def char_data(data):
        global cdata
        cdata += data

    import xml.parsers.expat
    p = xml.parsers.expat.ParserCreate()
    p.StartElementHandler  = start_element
    p.EndElementHandler    = end_element
    p.CharacterDataHandler = char_data
    try:
        p.ParseFile(open(filename))
    except XMLDone, e:
        return e.value
    except xml.parsers.expat.ExpatError:
        return None             # XML error
    return None
    

class xml_reader:
    def __init__(self):
        self.data = None
        self.tagstack = ['xml']
    
    def _char_data(self, data):
        """Handles XML data"""
        if self.data != None: self.data += data

    def process_xml_stream(self,xml_stream,callback):
        "Run the reader on a given XML input stream"
        self.callback = callback
        import xml.parsers.expat
        p = xml.parsers.expat.ParserCreate()
        p.StartElementHandler  = self._start_element
        p.EndElementHandler    = self._end_element
        p.CharacterDataHandler = self._char_data
        p.ParseFile(xml_stream)    

class fileobject_reader(xml_reader):
    """Class which uses the SAX expat-based XML reader.
    Reads an FIWALK XML input file and automatically creates
    volumeobject_sax and fileobject_sax objects, but just returns the filoeobject
    objects.."""
    def __init__(self,flags):
        self.volumeobject = False
        self.fileobject   = False
        self.imageobject  = imageobject_sax()
        self.imagefile    = None
        self.flags        = flags
        xml_reader.__init__(self)
        
    def set_imagefile(self,imagefile):
        """Sets the fiwalk_xml_readers imagefile to be IMAGEFILE, so that fiwalk objects
        know how to get their contents."""
        self.imagefile = imagefile


    def set_imagefilename(self,imagefilename):
        """Opens the requested imagefile"""
        self.imagefile = open(imagefilename,'r+')

    def _start_element(self, name, attrs):
        """ Handles the start of an element for the XPAT scanner"""
        self.tagstack.append(name)
        if name=="volume":
            self.volumeobject            = volumeobject_sax()
            self.volumeobject.block_size = 512 # reasonable default
            self.volumeobject.image      = self.imageobject
            self.data                    = u""
            if "offset" in attrs: self.volumeobject.offset = int(attrs["offset"]) 
            return
        if name=="block_size":
            self.data = u""
        
        if name=="fileobject":
            self.fileobject = fileobject_sax(imagefile=self.imagefile)
            self.fileobject.volume = self.volumeobject
            return
        if name=='hashdigest':
            self.hashdigest_type = attrs['type'] # remember the type
        if not self.fileobject: return
        if name=="run":
            b = byterun()
            b.decode_sax_attributes(attrs)
            self.fileobject._byteruns.append(b)
            return
        self.data = u""                 # new element; otherwise data is ignored

    def _end_element(self, name):
        """Handles the end of an eleement for the XPAT scanner"""
        assert(self.tagstack.pop()==name)
        if name=="volume":
            self.volumeobject = None
            return
        if name=="block_size" and len(self.tagstack) > 1 : 
            if self.tagstack[-1] == "volume" : 
                self.volumeobject.block_size = int(self.data)
                self.data=None
            return
        if name=="fileobject":
            if (self.flags & ALLOC_ONLY)==0 or self.fileobject.allocated():
                self.callback(self.fileobject)
            self.fileobject = None
            return
        if name=='hashdigest':
            self.fileobject._tags[self.hashdigest_type.lower()] = self.data
            self.data = None
            return
        if self.fileobject:             # in a file object, all tags are remembered
            self.fileobject._tags[name] = self.data
            self.data = None
            return
        # Special case: <source><image_filename>fn</image_filename></source>
        # gets put in <imagfile>fn</imagefile>
        if name=='image_filename' and self.tagstack==['xml','fiwalk','source']:
            self.imageobject._tags[name] = self.data
        # Handle lots of XML that was generated wrong
        # This can be removed when XML version 0.3 is gone
        if name=='imagefile' and self.tagstack==['xml','fiwalk','source']:
            self.imageobject._tags['image_filename'] = self.data

class volumeobject_reader(xml_reader):
    def __init__(self):
        self.volumeobject = False
        xml_reader.__init__(self)
        self.imageobject  = imageobject_sax()

    def _start_element(self, name, attrs):
        """ Handles the start of an element for the XPAT scanner"""
        self.tagstack.append(name)
        if name=="volume":
            self.volumeobject = volumeobject_sax()
            self.volumeobject.image = self.imageobject
            return
        if name=='fileobject':
            self.data = None            # don't record this
            return
        self.data = u""                 # new element; otherwise data is ignored

    def _end_element(self, name):
        """Handles the end of an eleement for the XPAT scanner"""
        assert(self.tagstack.pop()==name)
        if name=="volume":
            self.callback(self.volumeobject)
            self.volumeobject = None
            return
        if self.tagstack[-1]=='volume' and self.volumeobject:             # in the volume
            self.volumeobject._tags[name] = self.data
            self.data = None
            return
        if self.tagstack[-1]=='fiwalk':
            self.imageobject._tags[name] = self.data
            return

        # Special case: <source><image_filename>fn</image_filename></source> gets put in <imagfile>fn</imagefile>
        if name=='image_filename' and self.tagstack==['xml','fiwalk','source']:
            self.imageobject._tags[name] = self.data
        # Handle lots of XML that was generated wrong
        # This can be removed when XML version 0.3 is gone
        if name=='imagefile' and self.tagstack==['xml','fiwalk','source']:
            self.imageobject._tags['image_filename'] = self.data
        return


################################################################
def fiwalk_xml_stream(imagefile=None,flags=0,fiwalk="fiwalk"):
    """ Returns an fiwalk XML stream given a disk image by running fiwalk."""
    fiwalk_args = "-x"
    if flags & ALLOC_ONLY: fiwalk_args += "O"
    from subprocess import Popen,PIPE
    return Popen([fiwalk,fiwalk_args,imagefile.name],stdout=PIPE).stdout

def fiwalk_using_sax(imagefile=None,xmlfile=None,fiwalk="fiwalk",flags=0,callback=None):
    """Processes an image using expat, calling a callback for every file object encountered.
    If xmlfile is provided, use that as the xmlfile, otherwise runs fiwalk."""
    if xmlfile==None:
        xmlfile = fiwalk_xml_stream(imagefile=imagefile,flags=flags,fiwalk=fiwalk)
    r = fileobject_reader(flags=flags)
    r.imagefile = imagefile
    r.process_xml_stream(xmlfile,callback)

def fileobjects_using_sax(imagefile=None,xmlfile=None,fiwalk="fiwalk",flags=0):
    """Returns a LIST of fileobjects extracted from the given
    imagefile. If XMLFILE is provided, read the objects are read
    directly from the XML, otherwise this method runs fiwalk with the
    specified FLAGS."""
    ret = []
    fiwalk_using_sax(imagefile=imagefile,xmlfile=xmlfile,fiwalk=fiwalk,flags=flags,
                     callback=lambda fi:ret.append(fi))
    return ret

def fileobjects_iter(imagefile=None,xmlfile=None,fiwalk="fiwalk",flags=0):
    """Returns an iterator that returns fileobjects extracted from the given
    imagefile. If XMLFILE is provided, read the objects are read
    directly from the XML, otherwise this method runs fiwalk with the
    specified FLAGS."""
    def local_iter(fi):
        yield fi
    fiwalk_using_sax(imagefile=imagefile,xmlfile=xmlfile,fiwalk=fiwalk,flags=flags,
                     callback=local_iter)

def fileobjects_using_dom(imagefile=None,xmlfile=None,fiwalk="fiwalk",flags=0):
    """Returns a tuple consisting of (XML,LIST) where XML is the
    document of the imagefile's fiwalk and LIST is a list of file
    objects extracted from that document.  If XMLFILE is provided, the
    objects are read directly from the XML, otherwise this method runs
    fiwalk with the specified FLAGS."""

    if xmlfile==None:
        xmlfile = fiwalk_xml_stream(imagefile=imagefile,fiwalk=fiwalk,flags=flags)

    import xml.dom.minidom
    doc =  xml.dom.minidom.parseString(xmlfile.read())
    ret = []
    for xmlfi in doc.getElementsByTagName("fileobject"):
        fi = fileobject_dom(xmlfi,imagefile=imagefile)
        if (flags & ALLOC_ONLY)==0 or fi.allocated():
            ret.append(fi)
    return (doc,ret)
    
def volumeobjects_using_sax(imagefile=None,xmlfile=None,fiwalk="fiwalk",flags=0):
    if xmlfile==None:
        xmlfile = fiwalk_xml_stream(imagefile=imagefile,fiwalk=fiwalk,flags=flags)
    ret = []
    r = volumeobject_reader()
    r.process_xml_stream(xmlfile,callback=lambda vo:ret.append(vo))
    return ret
    

################################################################
def combine_runs(runs):
    """Given an array of bytrun elements, combine the runs and return a new array."""
    if runs==[]: return []
    ret = [runs[0]]
    for run in runs[1:]:
        # if the last one ends where this run begins, just extend
        # otherwise append
        last = ret[-1]
        if last.img_offset+last.bytes == run.img_offset:
            ret[-1] = byterun(img_offset = last.img_offset,
                              bytes = last.bytes + run.bytes)
            continue
        else:
            ret.append(run)
    return ret
            


class extentdb:
    """A class to a database of extents and report if they collide.
    Currently this is not an efficient implementation, but it could become
    more efficient in the future. When it does, every program that uses
    this implementation will get faster too!  Each extent is represented
    as a byterun object"""
    def __init__(self,sectorsize=512):
        self.db = []                    # the database of runs
        self.sectorsize = 512
        pass
    
    def report(self,f):
        """Print information about the database"""
        f.write("sectorsize: %d\n" % self.sectorsize)
        for run in sorted(self.db):
            f.write("   [@%8d ; %8d]\n" % (run.img_offset,run.bytes))
        f.write("total entries in database: %d\n\n" % len(r))
    
    def sectors_for_bytes(self,count):
        """Returns the number of sectors necessary to hold COUNT bytes"""
        return (count+self.sectorsize-1)//self.sectorsize
    
    def sectors_for_run(self,run):
        """Returns an array of the sectors for a given run"""
        start_sector = run.img_offset/self.sectorsize
        sector_count = self.sectors_for_bytes(run.bytes)
        return range(start_sector,start_sector+sector_count)

    def run_for_sector(self,sector_number,count=1):
        """Returns the run for a specified sector, and optionally a count of sectors"""
        return byterun(bytes=count*self.sectorsize,img_offset=sector_number * self.sectorsize)

    def intersects(self,extent):
        """Returns the intersecting extent, or None if there is none"""
        if extent.bytes==0: return True    # 0 length intersects with everything
        if extent.bytes<0: raise ValueError,"Length cannot be negative:"+str(extent)
        start = extent.img_offset
        stop  = extent.img_offset+extent.bytes
        for d in self.db:
            if d.img_offset <= start < d.img_offset+d.bytes: return d
            if d.img_offset < stop  < d.img_offset+d.bytes: return d
            if start<d.img_offset and d.img_offset+d.bytes <= stop: return d
        return None

    def intersects_runs(self,runs):
        """Returns the intersecting extent for a set of runs, or None
        if there is none."""
        for r in runs:
            v = self.intersects(r)
            if v: return v
        return None

    def intersects_sector(self,sector):
        """Returns the intersecting extent for a specified sector, None otherwise.
        Sector numbers start at 0."""
        return self.intersects(self.run_for_sector(sector))

    def add(self,extent):
        """Adds an EXTENT (start,length) to the database.
        Raises ValueError if there is an intersection."""
        v = self.intersects(extent)
        if v:
            raise ValueError,"Cannot add "+str(extent)+": it intersects "+str(v)
        self.db.append(extent)

    def add_runs(self,runs):
        """Adds all of the runs to the extent database"""
        for r in runs:
            self.add(r)

    #def extent_for_sector(self,sector):
    #    """Returns an extent for a given sector"""
    #    return (0,self.sectorsize,self.sectorsize*sector)

    def runs_for_sectors(self,sectors):
        """Given a list of SECTORS, return a list of RUNS.
        Automatically combines adjacent runs."""

        runs = [byterun(bytes=self.sectorsize,img_offset=x*self.sectorsize) for x in sectors]
        return combine_runs(runs)

    def add_sectors(self,sectors):
        """Adds the sectors in the list to the database."""
        self.add_runs(self.runs_for_sectors(sectors))

    def sectors_not_in_db(self,run):
        """For a given run, return a list of sectors not in the extent db"""
        return filter(lambda x:not self.intersects_sector(x),self.sectors_for_run(run))
        
        
################################################################
if __name__=="__main__":
    imagefilename = "/corp/drives/nps/nps-2009-canon2/nps-2009-canon2-gen6.raw"

    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-a","--all",help="print all file contents",action="store_true")
    parser.add_option("-r","--regress",help="Perform regression with "+imagefilename,action="store_true")
    parser.add_option("--compress",help="Test the extraction of a compressed file",action="store_true")
    (options,args) = parser.parse_args()

    if options.compress:
        cfn = "/corp/drives/nps/nps-2009-ntfs1/ntfs1-gen2.aff"
        fobjs = fileobjects_using_sax(open(cfn))
        for fi in fobjs:
            if fi.compressed():
                print fi.filename()," is compressed",fi.compressed()
                f = open("output.pdf","w")
                f.write(fi.contents())
                f.close()
                exit(0)
        exit(0)

    if options.regress:
        def process(fi):
            present = ""
            if fi.file_present() :
                present = "(present)"
            num_frags = fi.fragments()
            print "%s : %d fragments; first one at sector %s %s" % \
                  (fi.filename(),num_frags,str(num_frags))
            if fi.filename()=="Compressed/logfile1.txt" or options.all:
                print "contents:",fi.contents()

        print "==TESTING SAX INTERFACE=="
        fiwalk = "../src/fiwalk"
        f = open(imagefilename,"r")
        for fi in fileobjects_using_sax  (imagefile=f, fiwalk=fiwalk):
            process(fi)
        print "\n"
        print "Run with dom:"
        (doc,fis) = fileobjects_using_dom(imagefile=f, fiwalk=fiwalk)
        for fi in fis :
            process(fi)

    print "testing overlap engine:"
    db = extentdb()
    a = byterun(img_offset=0,bytes=5)
    db.add(a)
    b = byterun(5,5)
    db.add(b)
    assert db.intersects(byterun(0,5))==byterun(0,5)
    assert db.intersects(byterun(0,1))
    assert db.intersects(byterun(2,3))
    assert db.intersects(byterun(4,1))
    assert db.intersects(byterun(5,1))
    assert db.intersects(byterun(6,1))
    assert db.intersects(byterun(9,1))
    assert db.intersects(byterun(-1,5))
    assert db.intersects(byterun(-1,10))
    assert db.intersects(byterun(-1,11))
    assert db.intersects(byterun(-1,1))==None
    assert db.intersects(byterun(10,1))==None
    

