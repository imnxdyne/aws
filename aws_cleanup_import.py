# aws_cleanup_import.py
#   Consolidated location for "global vars" that may be modified by end-user.
#   2.5: baseline
from collections import deque,defaultdict,namedtuple  

#  aws_cleanup_import_ver needs to match version number in aws_cleanup.py
aws_cleanup_import_ver = 2.5

#  Can enabled multiple "keep" tags.
constantKeepTag = ['keep']

componentDef = namedtuple("componentDef", ['compName', 'compDelete', 'compKeep'])
componentDef.__new__.__defaults__ = (None, None, ())
class awsComponentClass:
  def __init__(self):
    #  compName - utilized for the following:
    #    1) Unique dictionary index for termTrackClass attribute "x"
    #    2) Title / display name
    #  compDelete: flag to disable AWS component from being deleted, but will still
    #       display inventory. Used for testing or keeping AWS components
    #  compKeep: for aws items that don't have tags, compKeep list names
    #       of AWS items to block from being deleted. NOTE: this a tuple value -
    #       if there's ony one value, have a trailing comma (ex: compKeep=('EC2 Key Value',) )
    self.EC2 = componentDef(compName = 'EC2 instances', compDelete = True)
    self.SecGroup = componentDef(compName = 'Security Groups', compDelete = True)
    self.Volume = componentDef(compName = 'Volumes', compDelete = True)
    self.KeyPairs = componentDef(compName = 'Key Pairs', compDelete = True, compKeep=('EC2 Keep',))
    self.S3 = componentDef(compName = 'S3 Buckets', compDelete = True)
    self.VPC = componentDef(compName = 'VPC', compDelete = True)
    self.Subnet = componentDef(compName = 'Subnets', compDelete = True)
    self.InternetGateway = componentDef(compName = 'Internet Gateways', compDelete = True)
    self.RouteTable = componentDef(compName = 'Route Tables', compDelete = True)
    #  User compKeep is a list of users not to delete. If only one value, a trailing comma is
    #    required - compKeep('scott',). Case-insensitive.
    #  Same applies to Group, Poilicy, and Role.
    self.User = componentDef(compName = 'User', compDelete = True, compKeep=())
    self.Group = componentDef(compName = 'Group', compDelete = True, compKeep=())
    self.Policy = componentDef(compName = 'Policy', compDelete = True, compKeep=())
    self.Role = componentDef(compName = 'Role', compDelete = True, compKeep=())
