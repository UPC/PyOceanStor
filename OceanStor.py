# -*- coding: utf-8 -*-
"""Connect to OceanStor device and get information."""
#
# There are implemented just a few functions for our monitoring needs, but
# the capabilitites are huge. EVERYTHING on an OceanStor can be done using
# the API. If not convinced, connect the browser to the device and fire up
# developer tools. You will see the browser is using the API for doing the
# job.
# Google "Huawei OceanStor REST API" for the documentation
#
# Toni Comerma
# Octubre 2017
#
# Modifications
#   
#   Jan 2020: Adapt to python for centos /
#   June 2024: Python3 compatible.
#       Added some user, share and quota management functions
# TODO:
#
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse
import ssl
import json
import datetime
from http.cookiejar import CookieJar
from enum import Enum, IntEnum
import logging


class OceanStorError(Exception):
    """Class for OceanStor derived errors."""

    def __init__(self, msg=None):
        if msg is None:
            # Set some default useful error message
            msg = "An error occured connecting to OceanStor"
        super(OceanStorError, self).__init__(msg)

class OceanStorSecurityStyle( Enum ):
    NATIVE = 1
    NTFS = 2
    UNIX = 3
    MIXED = 4

class OceanStorShareDomainType( Enum ):
    # AD Domain user or group
    AD = 0
    LOCAL = 2

class OceanStorSharePermission( Enum ):
    READ = 0
    FULL_CONTROL = 1
    FORBIDDEN = 2
    READ_WRITE = 5
class OceanStorParentType( IntEnum ):
    FILESYSTEM = 40,
    DTREE = 16445

class OceanStor(object):
    """Class that connects to OceanStor device and gets information."""

    def __init__(self, host, system_id, username, password, timeout):
        self.host = host
        self.system_id = system_id
        self.username = username
        self.password = password
        self.timeout = timeout
        # Create reusable http components
        self.cookies = CookieJar()
        self.ctx = ssl._create_unverified_context()
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.ctx),
                                           urllib.request.HTTPCookieProcessor(self.cookies))
        self.opener.addheaders = [('Content-Type', 'application/json; charset=utf-8')]
        self.logger = logging.getLogger(__name__)

    def alarm_level_text(self, level):
        if level == 3:
            return "warning"
        elif level == 4:
            return "major"
        elif level == 5:
            return "critical"
        else:
            return "unknown"

    def healthstatus_text(self, level):
        if level == "1":
            return "normal"
        elif level == "2":
            return "fault"
        elif level == "5":
            return "degradated"
        else:
            return "unknown"

    def runningstatus_text(self, level):
        if level == "14":
            return "pre-copy"
        elif level == "16":
            return "reconstruction"
        elif level == "27":
            return "online"
        elif level == "28":
            return "offline"
        elif level == "32":
            return "balancing"
        elif level == "53":
            return "initializing"
        else:
            return "unknown"

    def date_to_human(self, timestamp):
        return datetime.datetime.fromtimestamp(
                        int(timestamp)).strftime('%Y-%m-%d %H:%M:%S')


    def query(self, url, data = None):
        try:
            if data:
                response = self.opener.open( url, json.dumps(data).encode("utf-8") )
            else:
                response = self.opener.open( url )
            content = response.read().decode( 'utf-8' )
            response_json = json.loads(content)
            # Comprovar si request ok
            if response_json['error']['code'] != 0:
                raise OceanStorError(
                        "ERROR: Got an error response from system ({0}): {1}".
                        format(response_json['error']['code'], response_json['error']['description']))
        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))
        return response_json
    
    # This method will be used instead of query for PUT or DELTE operations
    # Modify operations use PUT instead of POST
    # Delete operations use DELETE
    def request(self, url, method : str, data = None):
        try:
            req = urllib.request.Request( url, data= json.dumps(data).encode("utf-8"), method = method )
            response = self.opener.open( req )

            content = response.read().decode( 'utf-8' )
            response_json = json.loads(content)

            # Comprovar si request ok
            if response_json['error']['code'] != 0:
                raise OceanStorError(
                        "ERROR: Got an error response from system ({0}): {1}".
                        format(response_json['error']['code'], response_json['error']['description']))
        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))
        return response_json


    def login(self):
        try:
            formdata = {"username": self.username,
                        "password": self.password, "scope": "0"}
            url = "https://{0}:8088/deviceManager/rest/{1}/sessions".\
                  format(self.host, self.system_id)
            
            response = self.opener.open(url, json.dumps(formdata).encode("utf-8"))
            content = response.read().decode('utf-8')
            
            response_json = json.loads(content)
            # Comprvar login ok
            if response_json['error']['code'] != 0:
                raise OceanStorError(
                        "ERROR: Got an error response from system ({0})".
                        format(response_json['error']['code']))
            self.iBaseToken = response_json['data']['iBaseToken']
            self.opener.addheaders = [('iBaseToken', self.iBaseToken)]
        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))
        return True

    def logout(self):
        try:
            url = "https://{0}:8088/deviceManager/rest/{1}/sessions".\
                  format(self.host, self.system_id)
            request = urllib.request.Request(url)
            request.get_method = lambda: 'DELETE'
            f = self.opener.open(request)
            content = f.read()
        except:
            # No error control. We are quitting anyway
            return


    def system(self):
        try:
            url = "https://{0}:8088/deviceManager/rest/{1}/system/".\
                  format(self.host, self.system_id)
            response_json = self.query(url)
            self.sectorsize = float(response_json['data']['SECTORSIZE'])
        except Exception as e:
            pass
        return True

    def alarms(self):
        a = list()
        try:
            url = "https://{0}:8088/deviceManager/rest/{1}/alarm/currentalarm".\
                  format(self.host, self.system_id)
            response_json = self.query(url)
            for i in response_json["data"]:
                a.append([self.alarm_level_text(i["level"]),
                          self.date_to_human(i["startTime"]),
                          i["description"]])
        except Exception as e:
            pass
        return a

    # Returns a list of lists (one for each matching, non clone, fs) containing
    # the name the capacity, available capacity, % used, reserved, used reserve
    # and finally the id.
    # This method has been extended to return the id of the file system.
    def filesystems(self, pattern):
        a = list()
        try:
            self.system()
            if "*" in pattern:
                wildcard = True
                pattern = pattern.replace('*', '')
            else:
                wildcard = False
            url = "https://{0}:8088/deviceManager/rest/{1}/filesystem?".\
                  format(self.host, self.system_id)
            url = url + urllib.parse.urlencode({'filter': 'NAME:{0}'.
                                          format(pattern).encode("utf-8")})
            response_json = self.query(url)
            # Get interesting data into list
            for i in response_json["data"]:
                if (
                    (wildcard and i["NAME"].startswith(pattern)) or
                    (not wildcard and i["NAME"] == pattern)
                   ):
                    if i["ISCLONEFS"] == "false":
                        size = float(i["CAPACITY"])/1024 / \
                            1024*(self.sectorsize/1024)  # To GB
                        free = float(i["AVAILABLECAPCITY"]) / \
                            1024/1024*(self.sectorsize/1024)  # To GB
                        reserved = float(i["SNAPSHOTRESERVECAPACITY"]) / \
                            1024/1024*(self.sectorsize/1024)  # To GB
                        usedreserved = float(i["SNAPSHOTUSECAPACITY"]) / \
                            1024/1024*(self.sectorsize/1024)  # To GB
                        pctused = (1-((free+reserved)/size))*100
                        pctusedreserved = (usedreserved/(reserved+1))*100
                        a.append([i["NAME"],
                                  size,
                                  size-free-reserved,
                                  pctused,
                                  reserved,
                                  usedreserved,
                                  pctusedreserved,
				  i["ID"]])
        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))
        return a
 
    # Either parentId or parentName must be supplied
    def dtree( self, name: str, parentId: str = None, parentName: str = None ):

        try:
            url = "https://{0}:8088/deviceManager/rest/{1}/QUOTATREE?".\
                format(self.host, self.system_id)
            
            parentKey = ""
            parentValue = ""
            if parentName:
               parentKey = "PARENTNAME"
               parentValue = parentName
            elif parentId:
               parentKey = "PARENTID"
               parentValue = parentId
            else:
                raise OceanStorError( "Either parentid or parentname must be supplied" )
             
            url = url + urllib.parse.urlencode({'NAME': name.encode("utf-8"),
                parentKey : parentValue.encode("utf-8")})
            
            response_json = self.query(url)
            return response_json["data"]

        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))

        return None

    def cifsshare( self, pattern: str ):

        try:
            url = "https://{0}:8088/deviceManager/rest/{1}/CIFSSHARE?".\
                format(self.host, self.system_id)
            
            if "*" in pattern:
                wildcard = True
                pattern = pattern.replace('*', '')
            else:
                wildcard = False
            
                         
            
            url += urllib.parse.urlencode({'filter': 'NAME:{0}'.
                                          format(pattern).encode("utf-8")})
            
            response_json = self.query(url)

            return response_json["data"]

        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))

        return None

    def diskdomains(self, pattern):
        a = list()
        try:
            self.system()
            if "*" in pattern:
                wildcard = True
                pattern = pattern.replace('*', '')
            else:
                wildcard = False
            url = "https://{0}:8088/deviceManager/rest/{1}/diskpool".\
                   format(self.host, self.system_id)
            response_json = self.query(url)
            # Get interesting data into list
            for i in response_json["data"]:
                if (
                    (wildcard and i["NAME"].startswith(pattern)) or
                    (not wildcard and i["NAME"] == pattern)
                   ):
                    size = float(i["TOTALCAPACITY"])/1024/1024*(self.sectorsize/1024)  # To GB
                    free = float(i["FREECAPACITY"])/1024/1024*(self.sectorsize/1024)   # To GB
                    pctused = (1-(free/size))*100
                    a.append([i["NAME"],
                              size,
                              size-free,
                              pctused,
                              self.healthstatus_text(i["HEALTHSTATUS"]),
                              self.runningstatus_text(i["RUNNINGSTATUS"])])
        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))
        return a


    def storagepools(self, pattern):
        a = list()
        try:
            self.system()
            if "*" in pattern:
                wildcard = True
                pattern = pattern.replace('*', '')
            else:
                wildcard = False
            url = "https://{0}:8088/deviceManager/rest/{1}/storagepool".\
                   format(self.host, self.system_id)
            response_json = self.query(url)
            # Get interesting data into list
            for i in response_json["data"]:
                if (
                    (wildcard and i["NAME"].startswith(pattern)) or
                    (not wildcard and i["NAME"] == pattern)
                   ):
                    size = float(i["USERTOTALCAPACITY"])/1024/1024*(self.sectorsize/1024)  # To GB
                    free = float(i["USERFREECAPACITY"])/1024/1024*(self.sectorsize/1024)  # To GB
                    pctused = (1-(free/size))*100
                    a.append([i["NAME"],
                              size,
                              size-free,
                              pctused,
                              self.healthstatus_text(i["HEALTHSTATUS"]),
                              self.runningstatus_text(i["RUNNINGSTATUS"])])
        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))
        return a

    def createuser( self, name: str, uid: int, group: int, description: str = "") -> bool:
        try:
            self.system()
            formdata = {
                "name": name,
                "primary_group_id": group,
                "description": description,
                "id": uid
            }
            url = "https://{0}:8088/deviceManager/rest/{1}/UNIX_USER".\
                   format(self.host, self.system_id)
            
            response_json = self.query(url, formdata)
            
            return True
            
        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))
        
        return False
    
    def createdtree( self, name: str, securityStyle : OceanStorSecurityStyle = None, parentId: str = None, parentName: str = None ):
        if parentName:
            parentKey = "PARENTNAME"
            parentValue = parentName
        elif parentId:
            parentKey = "PARENTID"
            parentValue = parentId
        else:
            raise OceanStorError( "Either parentid or parentname must be supplied" )
        
        try:
            self.system()
            formdata = {
                "NAME": name,
                parentKey: parentValue
            }
            if securityStyle is not None:
                formdata[ "securityStyle" ] = "{}".format( securityStyle.value )
            
            url = "https://{0}:8088/deviceManager/rest/{1}/QUOTATREE".\
                   format(self.host, self.system_id)            

            response_json = self.query( url, formdata )
            
            return True
            
        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))
        
        return False

    def createcifsshare( self, name: str, sharePath: str ):
        try:
            self.system()
            formdata = {
                "NAME": name,
                "SHAREPATH": "/{}/{}".format( sharePath, name )
            }
            
            url = "https://{0}:8088/deviceManager/rest/{1}/CIFSSHARE".\
                   format(self.host, self.system_id)
            

            response_json = self.query( url, formdata )
            
            return response_json[ "data" ]
            
        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))
        
        return None

    def addusertocifsshare( self, username: str, shareId: int, permission: OceanStorSharePermission, domainType: OceanStorShareDomainType = None ):
        try:
            self.system()
            formdata = {
                "NAME": username,
                "PARENTID": str( shareId ),
                "PERMISSION": str( permission.value )
            }
            if domainType:
                formdata[ "DOMAINTYPE" ] = str( domainType.value )
            
            url = "https://{0}:8088/deviceManager/rest/{1}/CIFS_SHARE_AUTH_CLIENT".\
                   format(self.host, self.system_id)

            response_json = self.query( url, formdata )
            
            return response_json[ "data" ]
            
        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))
        return None

    # Returns the number of quotas of a certain filesystem or dtree
    def quotas(self, parentId : str, parentType : OceanStorParentType, vStoreId = None ) -> int:
        try:
            self.system()
            url = "https://{0}:8088/deviceManager/rest/{1}/FS_QUOTA/count?".\
                  format(self.host, self.system_id)
            params = {
                'PARENTTYPE': parentType.value,
                'PARENTID': parentId,
                'QUERYTYPE': 0
            }
            if vStoreId is not None:
                params[ 'vstoreId' ] = vStoreId.encode("utf-8")
        
            url = url + urllib.parse.urlencode( params )
            response_json = self.query(url)
            # Get interesting data into list
            return int( response_json["data"]["COUNT"] )
        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))
        return 0
 
    # Returns all the information on a single quota id
    # Sizes will be given in bytes
    def quota( self, quotaId : str, vStoreId = None ):
        res = dict()
        try:
            self.system()
            url = "https://{0}:8088/deviceManager/rest/{1}/FS_QUOTA/{2}?".\
                  format( self.host, self.system_id, quotaId )
            params = {
		        'SPACEUNITTYPE': 0,
            }
            if vStoreId is not None:
                params[ 'vstoreId' ] = vStoreId.encode("utf-8")
        
            url = url + urllib.parse.urlencode( params )
            response_json = self.query(url)
            res = response_json["data"]
        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))
        return res

    # Queries quota for a user and file system/dtree using the batch query
    # It will return either a single entry or an empty dict
    def quotauser( self, user : str, parentId : str, parentType : OceanStorParentType, vStoreId = None ):
        # First query the number of quotas
        nQuotas = self.quotas( parentId, parentType, vStoreId )
        pageSize = 1000

        # We will be using "Interface for Batch Querying Quota Information"
        # It is similar to the web ui for Quota Reports and thus it should only
        # return one entry per user.
        # The algorithm here is to look through pages until we find one entry
        # for the user we're looking for.


        res = dict()

        for i in range( 0, nQuotas, pageSize ):
            rangeMax = min( i + pageSize , nQuotas )
            try:
                self.system()
                url = "https://{0}:8088/deviceManager/rest/{1}/FS_QUOTA?".\
                    format( self.host, self.system_id)
                params = {
                    'PARENTTYPE': parentType.value,
                    'PARENTID': parentId,
                    'QUERYTYPE': 0,
                    'SPACEUNITTYPE': 0,
                    'range': "[{}-{}]".format( i, rangeMax )
                }
                if vStoreId is not None:
                    params[ 'vstoreId' ] = vStoreId.encode("utf-8")
            
                url = url + urllib.parse.urlencode( params )
                self.logger.debug( "URL: {}".format( url ) )
                response_json = self.query(url)

            except Exception as e:
                raise OceanStorError("HTTP Exception: {0}".format(e))
            
            # For each entry in the current page
            for quotaInfo in response_json["data"]:
                # Check if USRGRPOWNERNAME is defined
                if "USRGRPOWNERNAME" in quotaInfo and quotaInfo[ "USRGRPOWNERNAME" ] == user:
                    res = quotaInfo
                    return res

        return res

    def modifyquota( self, user : str, quotaId : str, spaceSoftQuota: int, spaceHardQuota: int, vStoreId = None ):
        try:
            self.system()
            url = "https://{0}:8088/deviceManager/rest/{1}/FS_QUOTA/{2}".\
                  format( self.host, self.system_id, quotaId )
            
            formdata = {
                # Is the ID required here?
		        'SPACEUNITTYPE': 0,
                'SPACESOFTQUOTA': str( spaceSoftQuota ),
                'SPACEHARDQUOTA': str( spaceHardQuota )
            }
            if vStoreId is not None:
                formdata[ 'vstoreId' ] = vStoreId.encode( "utf-8" )
           
            self.logger.debug( "URL: {}, formdata: {}".format( url, formdata ) )
            response_json = self.request( url, 'PUT', formdata )
        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))

    # Deletes a CIFS share by its identifier
    def deletecifsshare( self, shareId: int,  vStoreId = None ):
        try:
            self.system()
            url = "https://{0}:8088/deviceManager/rest/{1}/CIFSSHARE/{2}".\
                  format( self.host, self.system_id, shareId )
            params = {}
            if vStoreId is not None:
                params[ 'vstoreId' ] = vStoreId.encode( "utf-8" )
        
            url = url + urllib.parse.urlencode( params )
           
            response_json = self.request( url, 'DELETE' )
        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))
    
    # Deletes a dtree by its id
    def deletedtree( self, dtreeId: str, vStoreId = None):
        try:
            self.system()
            url = "https://{0}:8088/deviceManager/rest/{1}/QUOTATREE/{2}".\
                  format( self.host, self.system_id, dtreeId )
            params = {}
            if vStoreId is not None:
                params[ 'vstoreId' ] = vStoreId.encode( "utf-8" )
        
            url = url + urllib.parse.urlencode( params )
           
            response_json = self.request( url, 'DELETE' )
        except Exception as e:
            raise OceanStorError("HTTP Exception: {0}".format(e))